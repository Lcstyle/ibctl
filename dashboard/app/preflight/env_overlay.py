"""Apply environment variable overrides on top of TOML-loaded config.

Replicates the behavior of config.rs::apply_env_overrides() so the
pre-flight validator checks the same effective config that Rust loads.

All env var names come from models.ENV_MAP — no hardcoded names here.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .models import ENV_MAP


def env_or_file(var: str) -> str | None:
    """Read an env var with Docker secrets _FILE support.

    VAR_FILE takes precedence (Docker secrets pattern).
    Returns trimmed contents, or None if neither is set.
    """
    file_var = f"{var}_FILE"
    file_path = os.environ.get(file_var)
    if file_path:
        try:
            return Path(file_path).read_text().strip()
        except OSError:
            pass

    val = os.environ.get(var)
    return val if val is not None else None


def coerce_bool(value: str) -> bool:
    """Coerce a string to bool, matching Rust's matches! behavior."""
    return value.lower() in ("yes", "true", "1")


def _set_nested(data: dict, dotted_path: str, value: Any) -> None:
    """Set a value in a nested dict using a dotted path like 'auth.paper.tws_userid'."""
    keys = dotted_path.split(".")
    current = data
    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value


def _get_nested(data: dict, dotted_path: str) -> Any:
    """Get a value from a nested dict using a dotted path. Returns None if missing."""
    keys = dotted_path.split(".")
    current = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


# Fields where env var values need special coercion before inserting into the dict.
# Maps TOML path -> coercion type.
_BOOL_FIELDS = {
    "twofa.relogin_after_timeout",
    "command_server.enabled",
    "dashboard.enabled",
    "dashboard.github_oauth_enabled",
    "dashboard.oidc_enabled",
    "dashboard.notifications_enabled",
    "logging.futures_session_logging",
    "site.auto_launch",
}

_INT_FIELDS = {
    "twofa.exit_interval",
    "gateway.java_heap_size",
    "command_server.port",
    "logging.session_reopen_hour",
    "timing.login_dialog_timeout_secs",
    "timing.restart_delay_secs",
    "timing.relogin_max_attempts",
}

_COMMA_LIST_FIELDS = {
    "command_server.control_from",
}


def apply_env_overrides(config: dict) -> dict:
    """Apply environment variable overrides to a TOML-loaded config dict.

    Modifies and returns the dict. Follows the same precedence and coercion
    rules as Rust's apply_env_overrides().
    """
    for toml_path, env_var in ENV_MAP.items():
        raw = env_or_file(env_var)
        if raw is None:
            continue

        # Apply type-appropriate coercion
        if toml_path in _BOOL_FIELDS:
            _set_nested(config, toml_path, coerce_bool(raw))
        elif toml_path in _INT_FIELDS:
            try:
                _set_nested(config, toml_path, int(raw))
            except ValueError:
                pass  # Silent fallback, matches Rust behavior
        elif toml_path in _COMMA_LIST_FIELDS:
            _set_nested(config, toml_path, [s.strip() for s in raw.split(",")])
        else:
            # String or enum — pass through as-is, Pydantic validates
            _set_nested(config, toml_path, raw)

    return config
