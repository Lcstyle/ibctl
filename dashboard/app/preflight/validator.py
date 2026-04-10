"""Pre-flight config validation orchestrator.

Loads TOML, applies env overrides, validates against Pydantic models,
and returns a structured result with errors and warnings.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

import os

from .env_overlay import apply_env_overrides, env_or_file
from .models import ENV_MAP, SECRET_ENV_VARS, IbctlConfig


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
    """Check if a field's env var holds a secret (value should be redacted)."""
    env_var = ENV_MAP.get(field_path)
    return env_var in SECRET_ENV_VARS if env_var else False


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
    """Check that required credentials are set in the environment.

    Passwords are env-only (never in TOML). Which credentials are required
    depends on the trading mode:
    - live: TWS_USERID + TWS_PASSWORD
    - paper: TWS_USERID + TWS_PASSWORD
    - both: above + TWS_USERID_PAPER + TWS_PASSWORD_PAPER
    """
    errors = []
    mode = model.auth.trading_mode

    # Primary credentials (required for all modes)
    if not model.auth.tws_userid and not env_or_file("TWS_USERID"):
        errors.append(PreflightError(
            field="auth.tws_userid",
            message="required — set TWS_USERID or tws_userid in TOML",
            env_var="TWS_USERID",
        ))
    if not env_or_file("TWS_PASSWORD"):
        errors.append(PreflightError(
            field="<env>",
            message="required — set TWS_PASSWORD or TWS_PASSWORD_FILE",
            env_var="TWS_PASSWORD",
        ))

    # Paper credentials (required for dual mode)
    if mode == "both":
        if not model.auth.paper.tws_userid and not env_or_file("TWS_USERID_PAPER"):
            errors.append(PreflightError(
                field="auth.paper.tws_userid",
                message="required for trading_mode=both — set TWS_USERID_PAPER",
                env_var="TWS_USERID_PAPER",
            ))
        if not env_or_file("TWS_PASSWORD_PAPER"):
            errors.append(PreflightError(
                field="<env>",
                message="required for trading_mode=both — set TWS_PASSWORD_PAPER or TWS_PASSWORD_PAPER_FILE",
                env_var="TWS_PASSWORD_PAPER",
            ))

    return errors


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
        config_data = apply_env_overrides(config_data)

    # Step 3: Validate against Pydantic model
    try:
        model = IbctlConfig(**config_data)
    except ValidationError as exc:
        return PreflightResult(
            ok=False,
            errors=_format_pydantic_errors(exc),
        )

    # Step 4: Check credentials (env-only, not in TOML)
    errors = []
    if check_env:
        errors = _check_credentials(model)

    if errors:
        return PreflightResult(ok=False, errors=errors)

    # Step 5: Collect warnings from model validators
    warnings = model.get_warnings()

    return PreflightResult(ok=True, warnings=warnings)
