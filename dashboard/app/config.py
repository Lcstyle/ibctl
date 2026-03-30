"""Dashboard configuration from environment variables and ibctl.toml.

Env vars take precedence over TOML. The dashboard reads the [dashboard]
section from the same ibctl.toml that the Rust binary uses.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger("dashboard.config")


class DashboardSettings:
    """Immutable settings for the dashboard."""

    def __init__(
        self,
        port: int = 8080,
        token: str = "",
        debug_mode: bool = False,
        ibctl_host: str = "127.0.0.1",
        ibctl_port: int = 7462,
        log_level: str = "INFO",
    ):
        self.port = port
        self.token = token
        self.debug_mode = debug_mode
        self.ibctl_host = ibctl_host
        self.ibctl_port = ibctl_port
        self.log_level = log_level

    @classmethod
    def from_env(cls) -> DashboardSettings:
        """Load settings from environment variables."""
        return cls(
            port=int(os.environ.get("IBCTL_DASHBOARD_PORT", "8080")),
            token=os.environ.get("IBCTL_DASHBOARD_TOKEN", ""),
            debug_mode=os.environ.get("IBCTL_DEBUG_MODE", "").lower() in ("true", "yes", "1"),
            ibctl_host=os.environ.get("IBCTL_COMMAND_HOST", "127.0.0.1"),
            ibctl_port=int(os.environ.get("IBCTL_COMMAND_PORT", "7462")),
            log_level=os.environ.get("IBCTL_LOG_LEVEL", "INFO").upper(),
        )
