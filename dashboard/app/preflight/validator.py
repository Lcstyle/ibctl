"""Pre-flight config validation orchestrator.

Loads TOML, applies env overrides, validates against Pydantic models,
and returns a structured result with errors and warnings.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from .env_overlay import apply_env_overrides
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

    # Step 4: Collect warnings from model validators
    warnings = model.get_warnings()

    return PreflightResult(ok=True, warnings=warnings)
