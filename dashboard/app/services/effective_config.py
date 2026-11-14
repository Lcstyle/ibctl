"""The settings in effect: ibctl.toml with the env overrides applied.

This is the view preflight validates and the Config page shows. Dashboard code
that reads a setting goes through here instead of os.environ, so a value set in
ibctl.toml and the same value set by its env var (models.ENV_MAP) behave alike.
The file is read on every call: it is small, and nothing can go stale.
"""

from __future__ import annotations

import logging
import os
import tomllib
from typing import Any

from app.preflight.env_overlay import apply_env_overrides

logger = logging.getLogger("dashboard.config")

CONFIG_PATH = "/opt/ibctl/ibctl.toml"


def config_path() -> str:
    return os.environ.get("IBCTL_CONFIG", CONFIG_PATH)


def load() -> dict:
    """ibctl.toml (empty when there is none) with the env overrides applied.

    Raises OSError or tomllib.TOMLDecodeError when the file can't be read.
    """
    try:
        with open(config_path(), "rb") as f:
            config = tomllib.load(f)
    except FileNotFoundError:
        config = {}
    return apply_env_overrides(config)


def setting(path: str, default: Any) -> Any:
    """One setting by dotted path (``"dashboard.session_down_alert_minutes"``).

    ``default`` when it isn't set, or when the config can't be read (that is
    logged; preflight reports a broken config at startup).
    """
    try:
        node: Any = load()
    except (OSError, tomllib.TOMLDecodeError) as exc:
        logger.warning("cannot read %s (%s); using the default for %s", config_path(), exc, path)
        return default
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def int_setting(path: str, default: int) -> int:
    """A whole-number setting; ``default`` unless it's a non-negative int."""
    value = setting(path, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return default
    return value
