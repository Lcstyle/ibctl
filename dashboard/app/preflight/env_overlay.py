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
    """Coerce a string to bool, matching Rust's env_bool `matches!` vocabulary.

    Must stay in lock-step with the Rust closure in
    ``config.rs::RecoveryTimingConfig::to_runtime``:
        matches!(low.as_str(), "1" | "true" | "yes" | "on")
    Any drift lets an operator disable a subsystem in Rust while preflight
    still sees it enabled (or vice-versa).
    """
    return value.lower() in ("yes", "true", "1", "on")


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
    "dashboard.debug_mode",
    "dashboard.github_oauth_enabled",
    "dashboard.oidc_enabled",
    "dashboard.notifications_enabled",
    "dashboard.zmq_enabled",
    "ib_system_status.enabled",
    "logging.futures_session_logging",
    "site.auto_launch",
}

_INT_FIELDS = {
    "twofa.exit_interval",
    "gateway.java_heap_size",
    "command_server.port",
    "dashboard.port",
    "dashboard.zmq_port",
    "session.tws_cold_restart_day",
    "ib_system_status.check_interval_seconds",
    "logging.session_reopen_hour",
    "timing.login_dialog_timeout_secs",
    "timing.restart_delay_secs",
    "timing.relogin_max_attempts",
    # Recovery coordinator (PR-C stage 3): five int knobs that mirror Rust
    # RecoveryTimingConfig. Non-numeric values are silently ignored (see the
    # ValueError branch below) to match Rust env_u64/env_u32 behavior.
    "timing.recovery.aggressive_phase_max_secs",
    "timing.recovery.backoff_phase_max_secs",
    "timing.recovery.backoff_interval_secs",
    "timing.recovery.min_success_dwell_secs",
    "timing.recovery.fingerprint_streak_forcing_hitl",
}

_COMMA_LIST_FIELDS = {
    "command_server.control_from",
}

# Env vars that hold booleans but have NO TOML mapping. Only the Rust
# recovery coordinator reads them at boot (wired in a subsequent stage of
# PR-C — the read-site is currently in `config.rs::to_runtime()` which is
# not yet called from `main.rs`; see the `#[allow(dead_code)]` on
# `RecoveryTimingConfig`).
#   IBCTL_RECOVERY_DISABLED   — inverted from timing.recovery.enabled;
#     Rust's to_runtime() does the inversion, so leaving unmapped keeps
#     Python out of the picture (option (b) from the audit spec).
#   IBCTL_RECOVERY_FORCE_RESET — one-shot marker wipe trigger; consumed
#     by the coordinator and never persisted anywhere.
# `apply_env_overrides()` reads this set to reject typo values (anything
# that isn't in the Rust `env_bool` vocabulary) so they don't propagate
# downstream as raw strings. Membership alone is not enough — the read
# site below is what enforces the contract; tests must exercise the read
# site, not the set.
_BOOL_ENV_VARS: set[str] = {
    "IBCTL_RECOVERY_DISABLED",
    "IBCTL_RECOVERY_FORCE_RESET",
}

# Valid Rust `env_bool` vocabulary. Must match `coerce_bool` above and the
# `matches!` closure in Rust's `to_runtime`. Kept as a module-level constant
# so tests can import it directly.
_BOOL_STRICT_ACCEPT: frozenset[str] = frozenset({"1", "true", "yes", "on"})


def apply_env_overrides(config: dict) -> dict:
    """Apply environment variable overrides to a TOML-loaded config dict.

    Modifies and returns the dict. Follows the same precedence and coercion
    rules as Rust's apply_env_overrides().
    """
    for toml_path, env_var in ENV_MAP.items():
        raw = env_or_file(env_var)
        if raw is None or raw == "":
            continue  # Unset or empty = use TOML default for ALL types

        # Apply type-appropriate coercion
        if toml_path in _BOOL_FIELDS:
            _set_nested(config, toml_path, coerce_bool(raw))
        elif toml_path in _INT_FIELDS:
            try:
                parsed = int(raw)
            except ValueError:
                continue  # Silent fallback, matches Rust behavior
            if parsed < 0:
                # Rust `u64/u32` parse rejects negatives with the same
                # silent-warn semantics as non-numeric; mirror that so a
                # typo like `IBCTL_RECOVERY_BACKOFF_INTERVAL_SECS=-1`
                # doesn't turn Rust's soft-fall-back into a preflight
                # hard-error (Pydantic `ge=0` would otherwise fire).
                continue
            _set_nested(config, toml_path, parsed)
        elif toml_path in _COMMA_LIST_FIELDS:
            _set_nested(config, toml_path, [s.strip() for s in raw.split(",")])
        else:
            _set_nested(config, toml_path, raw)

    # Registered-but-unmapped bool env vars (Rust-only, no TOML round-trip).
    # We don't inject into `config` — there's no landing zone — but we
    # actively assert the value is in the Rust vocabulary so a downstream
    # audit / a typo like `IBCTL_RECOVERY_FORCE_RESET=maybe` is caught
    # BEFORE Rust silently maps unknown-string to `false`.
    for env_var in _BOOL_ENV_VARS:
        raw = env_or_file(env_var)
        if raw is None or raw == "":
            continue
        if raw.lower() not in _BOOL_STRICT_ACCEPT:
            # Match `_INT_FIELDS` silent-drop semantics: unknown -> ignored,
            # Rust falls back to its default. No error, no dict mutation.
            # A future PR that adds an on-disk log/warn sink should hook
            # here; a hard error would regress every deploy with a typo.
            continue

    return config
