"""Pydantic v2 models for ibctl config validation.

Field names match IBC conventions (the canonical env var names).
These models mirror config/pkl/types.pkl and ibctl/src/config.rs.

ENV_MAP maps TOML dotted paths to their canonical environment variable names.
"""

from __future__ import annotations

import re
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# --- Enum types (match Pkl typealiases and Rust enums) ---

TradingMode = Literal["live", "paper", "both"]
TotpProvider = Literal["oathtool", "builtin"]
TwoFaTimeoutAction = Literal["restart", "exit"]
GatewayProgram = Literal["gateway", "tws"]
SessionAction = Literal["primary", "secondary", "primaryoverride"]
AcceptIncoming = Literal["accept", "reject", "manual"]
SiteRole = Literal["primary", "standby"]
LogLevel = Literal["debug", "info", "warn", "error"]

# --- Config section models ---


class PaperAuthConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tws_userid: str = ""


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tws_userid: str = ""
    trading_mode: TradingMode = "live"
    paper: PaperAuthConfig = PaperAuthConfig()


class TwoFaConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    secret_env: str = "TWOFACTOR_CODE"
    provider: TotpProvider = "oathtool"
    timeout_action: TwoFaTimeoutAction = "restart"
    exit_interval: int = Field(default=180, ge=0)
    device: str = ""
    relogin_after_timeout: bool = False


class GatewayConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tws_path: str = "/home/ibgateway/Jts"
    tws_settings_path: str = ""
    tws_major_vrsn: str = ""
    java_heap_size: int = Field(default=768, ge=64)
    gateway_or_tws: GatewayProgram = "gateway"
    live_api_port: int = Field(default=4001, ge=1, le=65535)
    paper_api_port: int = Field(default=4002, ge=1, le=65535)
    live_socat_port: int = Field(default=4003, ge=1, le=65535)
    paper_socat_port: int = Field(default=4004, ge=1, le=65535)


class SessionConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action: SessionAction = "primary"
    accept_incoming: AcceptIncoming = "accept"
    tws_cold_restart: str = ""

    @model_validator(mode="after")
    def validate_cold_restart_format(self) -> "SessionConfig":
        v = self.tws_cold_restart
        if v and not re.match(r"^\d{2}:\d{2}$", v):
            raise ValueError(
                f"tws_cold_restart must be HH:MM 24h format or empty, got '{v}'"
            )
        return self


class CommandServerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: bool = True
    port: int = Field(default=7462, ge=1, le=65535)
    paper_port: int = Field(default=7463, ge=1, le=65535)
    bind_address: str = "0.0.0.0"
    control_from: list[str] = ["127.0.0.1"]


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    socket_path: str = "/run/ibctl/agent.sock"


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    level: LogLevel = "info"
    log_dir: str = ""
    futures_session_logging: bool = False
    session_reopen_hour: int = Field(default=18, ge=0, le=23)


class TimingConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ui_tick_ms: int = Field(default=100, ge=0)
    agent_tick_ms: int = Field(default=50, ge=0)
    post_login_delay_ms: int = Field(default=1000, ge=0)
    popup_quiet_secs: int = Field(default=5, ge=0)
    popup_max_wait_secs: int = Field(default=30, ge=0)
    login_radio_delay_ms: int = Field(default=100, ge=0)
    jvm_shutdown_timeout_secs: int = Field(default=5, ge=0)
    login_dialog_timeout_secs: int = Field(default=120, ge=0)
    restart_delay_secs: int = Field(default=90, ge=0)
    relogin_max_attempts: int = Field(default=1, ge=0)


class SiteConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    role: SiteRole = "primary"
    auto_launch: bool = True


# --- Top-level config ---


class IbctlConfig(BaseModel):
    """Complete ibctl config model. Validates TOML structure + cross-field rules."""

    model_config = ConfigDict(extra="ignore")

    auth: AuthConfig = AuthConfig()
    twofa: TwoFaConfig = TwoFaConfig()
    gateway: GatewayConfig = GatewayConfig()
    session: SessionConfig = SessionConfig()
    command_server: CommandServerConfig = CommandServerConfig()
    agent: AgentConfig = AgentConfig()
    logging: LoggingConfig = LoggingConfig()
    timing: TimingConfig = TimingConfig()
    site: SiteConfig = SiteConfig()

    @model_validator(mode="after")
    def validate_cross_field_rules(self) -> "IbctlConfig":
        warnings: list[str] = []

        # Port conflict detection
        ports = {
            "gateway.live_api_port": self.gateway.live_api_port,
            "gateway.paper_api_port": self.gateway.paper_api_port,
            "gateway.live_socat_port": self.gateway.live_socat_port,
            "gateway.paper_socat_port": self.gateway.paper_socat_port,
            "command_server.port": self.command_server.port,
            "command_server.paper_port": self.command_server.paper_port,
        }
        seen: dict[int, str] = {}
        for name, port in ports.items():
            if port in seen:
                raise ValueError(
                    f"Port conflict: {name} ({port}) collides with {seen[port]}"
                )
            seen[port] = name

        # Dual mode credential check
        if (
            self.auth.trading_mode == "both"
            and not self.auth.paper.tws_userid
        ):
            warnings.append(
                "trading_mode=both but no paper tws_userid set; "
                "will use main credentials (set TWS_USERID_PAPER)"
            )

        # Store warnings for retrieval by validator
        self.__dict__["_warnings"] = warnings
        return self

    def get_warnings(self) -> list[str]:
        return self.__dict__.get("_warnings", [])


# --- Environment variable mapping ---
# Maps TOML dotted path -> canonical env var name.
# Used by env_overlay.py to apply env overrides before validation.

ENV_MAP: dict[str, str] = {
    # Auth
    "auth.tws_userid": "TWS_USERID",
    "auth.trading_mode": "TRADING_MODE",
    "auth.paper.tws_userid": "TWS_USERID_PAPER",
    # 2FA
    "twofa.provider": "TOTP_PROVIDER",
    "twofa.timeout_action": "TWOFA_TIMEOUT_ACTION",
    "twofa.exit_interval": "TWOFA_EXIT_INTERVAL",
    "twofa.device": "TWOFA_DEVICE",
    "twofa.relogin_after_timeout": "RELOGIN_AFTER_TWOFA_TIMEOUT",
    # Gateway
    "gateway.tws_path": "TWS_PATH",
    "gateway.tws_settings_path": "TWS_SETTINGS_PATH",
    "gateway.tws_major_vrsn": "TWS_MAJOR_VRSN",
    "gateway.java_heap_size": "JAVA_HEAP_SIZE",
    "gateway.gateway_or_tws": "GATEWAY_OR_TWS",
    # Session
    "session.action": "IBCTL_SESSION_ACTION",
    "session.accept_incoming": "IBCTL_ACCEPT_INCOMING",
    "session.tws_cold_restart": "TWS_COLD_RESTART",
    # Command server
    "command_server.enabled": "IBCTL_COMMAND_SERVER_ENABLED",
    "command_server.port": "IBCTL_COMMAND_PORT",
    "command_server.control_from": "IBCTL_CONTROL_FROM",
    # Agent
    "agent.socket_path": "IBCTL_AGENT_SOCKET",
    # Logging
    "logging.level": "IBCTL_LOG_LEVEL",
    "logging.log_dir": "IBCTL_LOG_DIR",
    "logging.futures_session_logging": "IBCTL_FUTURES_SESSION_LOGGING",
    "logging.session_reopen_hour": "IBCTL_SESSION_REOPEN_HOUR",
    # Timing
    "timing.login_dialog_timeout_secs": "IBCTL_LOGIN_TIMEOUT",
    "timing.restart_delay_secs": "IBCTL_RESTART_DELAY",
    "timing.relogin_max_attempts": "IBCTL_RELOGIN_ATTEMPTS",
    # Site
    "site.role": "IBCTL_SITE_ROLE",
    "site.auto_launch": "IBCTL_AUTO_LAUNCH",
}

# Reverse mapping for error messages: env var -> TOML path
ENV_MAP_REVERSE: dict[str, str] = {v: k for k, v in ENV_MAP.items()}

# Env vars that hold secrets (never log their values)
SECRET_ENV_VARS: set[str] = {
    "TWS_PASSWORD",
    "TWS_PASSWORD_PAPER",
}
