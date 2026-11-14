"""Pre-flight config validation orchestrator.

Loads TOML, applies env overrides, validates against Pydantic models,
and returns a structured result with errors and warnings.
"""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

import os

from .env_overlay import EnvFileReadError, apply_env_overrides, env_or_file
from .models import ENV_MAP, IDENTITY_ENV_VARS, SECRET_ENV_VARS, IbctlConfig


@dataclass
class PreflightError:
    """A single validation error."""

    field: str
    message: str
    env_var: str | None = None
    actual_value: str | None = None


@dataclass
class PreflightResult:
    """Result of pre-flight validation."""

    ok: bool
    errors: list[PreflightError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _env_var_for_field(field_path: str) -> str | None:
    """Look up the env var name for a TOML field path."""
    return ENV_MAP.get(field_path)


def _is_secret_field(field_path: str) -> bool:
    """Check if a field's value should be redacted: a secret or an IB login name."""
    env_var = ENV_MAP.get(field_path)
    return env_var in SECRET_ENV_VARS | IDENTITY_ENV_VARS if env_var else False


def _format_pydantic_errors(exc: ValidationError) -> list[PreflightError]:
    """Convert Pydantic ValidationError into PreflightError list."""
    errors = []
    for err in exc.errors():
        # Build dotted field path from Pydantic's location tuple
        loc_parts = [str(p) for p in err["loc"]]
        field_path = ".".join(loc_parts)

        env_var = _env_var_for_field(field_path)

        # For model-level validators (cross-field rules), the "input" is the
        # entire config dict — never show that (noisy, may contain usernames).
        # Only show actual values for field-level errors.
        if err["type"] == "value_error":
            actual = None
        else:
            actual = err.get("input")

        # Redact secret values
        if _is_secret_field(field_path) and actual is not None:
            actual = "[REDACTED]"
        elif actual is not None:
            actual = str(actual)

        errors.append(
            PreflightError(
                field=field_path,
                message=err["msg"],
                env_var=env_var,
                actual_value=actual,
            )
        )
    return errors


def _check_credentials(model: IbctlConfig) -> list[PreflightError]:
    """Check that required env-only credentials are set.

    tws_userid presence is a domain invariant enforced in
    models.IbctlConfig._trading_mode_requires_userid so it fires in both
    check_env=True and --no-env paths. This function stays focused on
    env-only secrets: passwords and the TOTP secret env var pointed to by
    twofa.secret_env.
    """
    errors = []
    mode = model.auth.trading_mode

    # Primary password (required for all modes)
    if not env_or_file("TWS_PASSWORD"):
        errors.append(PreflightError(
            field="<env>",
            message="required — set TWS_PASSWORD or TWS_PASSWORD_FILE",
            env_var="TWS_PASSWORD",
        ))

    # Paper password (required for dual mode)
    if mode == "both":
        if not env_or_file("TWS_PASSWORD_PAPER"):
            errors.append(PreflightError(
                field="<env>",
                message="required for trading_mode=both — set TWS_PASSWORD_PAPER or TWS_PASSWORD_PAPER_FILE",
                env_var="TWS_PASSWORD_PAPER",
            ))

    # TOTP secret env var must exist when its name is set AND the operational
    # 2FA strategy actually needs a TOTP code. Under ntfy_callback (HITL-only),
    # no shared secret is used — the operator approves via a signed URL — so
    # requiring the env var there would false-positive a legitimate deployment.
    # This still catches the env-name rename foot-gun for TOTP-using
    # strategies (default 'periodic' and 'both'), just not for ntfy_callback.
    strategy = model.twofa.backoff.strategy
    totp_needed = strategy not in ("ntfy_callback", "disabled")
    secret_env = model.twofa.secret_env
    if totp_needed and secret_env and not env_or_file(secret_env):
        errors.append(PreflightError(
            field="twofa.secret_env",
            message=(
                f"required — the env var named by twofa.secret_env ({secret_env}) is not set. "
                f"Either export {secret_env}=<TOTP shared secret> or set twofa.secret_env to a var you have populated. "
                f"(Under twofa.backoff.strategy='{strategy}', TOTP codes are minted from this env var.)"
            ),
            env_var=secret_env,
        ))

    return errors


def _check_ntfy_callback_env(model: IbctlConfig) -> list[PreflightError]:
    """Hard-error when ntfy_callback (or both) HITL strategy is picked but
    its env-only wiring is missing. Escalated from warn to error because
    the strategy cannot function at runtime — callbacks are unsignable /
    URLs unreachable from the operator's phone.

    Called from validate_config only under check_env=True — pure --no-env
    calls (used by tests and tooling) skip these env-only invariants.
    """
    errors = []
    strategy = model.twofa.backoff.strategy
    if strategy not in ("ntfy_callback", "both"):
        return errors

    if not env_or_file("IBCTL_NTFY_ACTION_SIGNING_KEY"):
        errors.append(PreflightError(
            field="twofa.backoff.strategy",
            message=(
                f"twofa.backoff.strategy='{strategy}' requires IBCTL_NTFY_ACTION_SIGNING_KEY "
                "— callback URLs cannot be signed and every callback will be rejected. "
                "Set IBCTL_NTFY_ACTION_SIGNING_KEY (32+ random bytes) or pick strategy='periodic'."
            ),
            env_var="IBCTL_NTFY_ACTION_SIGNING_KEY",
        ))

    if not model.dashboard.external_url and not os.environ.get("IBCTL_DASHBOARD_EXTERNAL_URL"):
        errors.append(PreflightError(
            field="dashboard.external_url",
            message=(
                f"twofa.backoff.strategy='{strategy}' requires dashboard.external_url or "
                "IBCTL_DASHBOARD_EXTERNAL_URL — ntfy action-button URLs point at an internal "
                "address unreachable from a phone. Set the external URL or pick strategy='periodic'."
            ),
            env_var="IBCTL_DASHBOARD_EXTERNAL_URL",
        ))

    return errors


def _is_loopback_bind(bind: str) -> bool:
    """Whether a published-port bind address is reachable from this host only.

    Empty means compose's own default, which is loopback. A hostname other than
    ``localhost`` is treated as a network address.
    """
    host = bind.strip().lower().strip("[]")
    if not host or host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _check_vnc_exposure() -> list[PreflightError]:
    """Refuse a VNC port that is reachable from the network with no password.

    Compose publishes the VNC port on IBCTL_VNC_BIND, loopback unless the
    operator opts in. Bound to anything else with no VNC_SERVER_PASSWORD, anyone
    who can reach the port gets the Gateway's desktop, so the container must not
    start. Env-only, like the ntfy check: called from validate_config under
    check_env=True.
    """
    bind = os.environ.get("IBCTL_VNC_BIND", "")
    if _is_loopback_bind(bind):
        return []
    if (env_or_file("VNC_SERVER_PASSWORD") or "").strip():
        return []
    return [PreflightError(
        field="vnc.bind",
        message=(
            f"IBCTL_VNC_BIND={bind.strip()!r} publishes the VNC port to the network but "
            "VNC_SERVER_PASSWORD is not set. Set VNC_SERVER_PASSWORD (or VNC_SERVER_PASSWORD_FILE), "
            "or bind VNC to loopback only: IBCTL_VNC_BIND=127.0.0.1 (or leave it unset)."
        ),
        env_var="IBCTL_VNC_BIND",
    )]


def validate_config(
    toml_path: str = "/opt/ibctl/ibctl.toml",
    check_env: bool = True,
) -> PreflightResult:
    """Load TOML config, apply env overrides, validate via Pydantic.

    Args:
        toml_path: Path to the TOML config file. If it doesn't exist,
            validation proceeds with defaults + env overrides only.
        check_env: Whether to apply environment variable overrides.

    Returns:
        PreflightResult with ok=True if valid, or ok=False with errors.
    """
    # Step 1: Load TOML
    config_data: dict = {}
    toml_file = Path(toml_path)
    if toml_file.exists():
        try:
            config_data = tomllib.loads(toml_file.read_text())
        except tomllib.TOMLDecodeError as e:
            return PreflightResult(
                ok=False,
                errors=[
                    PreflightError(
                        field="<file>",
                        message=f"Invalid TOML syntax: {e}",
                    )
                ],
            )

    # Step 2: Apply env var overrides
    if check_env:
        try:
            config_data = apply_env_overrides(config_data)
        except EnvFileReadError as exc:
            return PreflightResult(
                ok=False,
                errors=[PreflightError(
                    field="<env>",
                    message=str(exc),
                    env_var=exc.env_var,
                )],
            )

    # Step 3: Validate against Pydantic model
    try:
        model = IbctlConfig(**config_data)
    except ValidationError as exc:
        return PreflightResult(
            ok=False,
            errors=_format_pydantic_errors(exc),
        )

    # Step 4: Check env-only credentials + ntfy_callback env wiring
    errors: list[PreflightError] = []
    if check_env:
        try:
            errors.extend(_check_credentials(model))
            errors.extend(_check_ntfy_callback_env(model))
            errors.extend(_check_vnc_exposure())
        except EnvFileReadError as exc:
            return PreflightResult(
                ok=False,
                errors=[PreflightError(
                    field="<env>",
                    message=str(exc),
                    env_var=exc.env_var,
                )],
            )

    if errors:
        return PreflightResult(ok=False, errors=errors)

    # Step 5: Collect warnings from model validators
    warnings = model.get_warnings()

    return PreflightResult(ok=True, warnings=warnings)
