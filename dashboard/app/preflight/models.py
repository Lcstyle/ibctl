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
    model_config = ConfigDict(extra="forbid")

    tws_userid: str = ""


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tws_userid: str = ""
    trading_mode: TradingMode = "paper"
    paper: PaperAuthConfig = PaperAuthConfig()


TwoFaOnTimeout = Literal["restart_then_hitl", "restart_forever", "hitl_immediately"]
HitlStrategy = Literal["disabled", "periodic", "ntfy_callback", "both"]
CounterResetScope = Literal["any_reach", "stable"]


class TwoFaBackoffConfig(BaseModel):
    """Human-in-the-loop 2FA backoff policy."""

    model_config = ConfigDict(extra="forbid")

    max_immediate_attempts: int = Field(default=3, ge=0)
    on_timeout: TwoFaOnTimeout = "restart_then_hitl"
    strategy: HitlStrategy = "periodic"
    intervals_minutes: list[int] = [60]
    callback_valid_hours: int = Field(default=12, ge=1, le=168)
    counter_reset: CounterResetScope = "any_reach"
    stable_secs: int = Field(default=300, ge=0)
    cold_restart_preempts_hitl: bool = True
    ntfy_send_retries: int = Field(default=1, ge=0)

    @model_validator(mode="after")
    def validate_backoff(self) -> "TwoFaBackoffConfig":
        # on_timeout = restart_then_hitl requires >= 1 attempt (otherwise
        # nothing to count).
        if self.on_timeout == "restart_then_hitl" and self.max_immediate_attempts < 1:
            raise ValueError(
                "on_timeout='restart_then_hitl' requires max_immediate_attempts >= 1; "
                "use on_timeout='hitl_immediately' for zero-attempt behavior."
            )

        # hitl_immediately requires a non-disabled strategy (or we'd enter a
        # dead-end state with no retry path).
        if self.on_timeout == "hitl_immediately" and self.strategy == "disabled":
            raise ValueError(
                "on_timeout='hitl_immediately' with strategy='disabled' leaves no "
                "recovery path. Choose strategy='periodic' or 'ntfy_callback' or 'both'."
            )

        # Periodic-involving strategies need at least one interval.
        if self.strategy in {"periodic", "both"} and not self.intervals_minutes:
            raise ValueError(
                f"strategy='{self.strategy}' requires at least one entry in intervals_minutes."
            )

        # All intervals must be positive.
        if any(m <= 0 for m in self.intervals_minutes):
            raise ValueError("intervals_minutes entries must all be > 0.")

        # Stable reset requires a non-zero window.
        if self.counter_reset == "stable" and self.stable_secs <= 0:
            raise ValueError("counter_reset='stable' requires stable_secs > 0.")

        # ntfy_send_retries without an ntfy-involving strategy is harmless
        # dead config — don't error. At runtime the retry logic never runs.

        return self


class TwoFaConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    secret_env: str = "TWOFACTOR_CODE"
    provider: TotpProvider = "oathtool"
    timeout_action: TwoFaTimeoutAction = "restart"
    exit_interval: int = Field(default=180, ge=0)
    device: str = ""
    relogin_after_timeout: bool = False
    backoff: TwoFaBackoffConfig = TwoFaBackoffConfig()


class GatewayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
    model_config = ConfigDict(extra="forbid")

    action: SessionAction = "primary"
    accept_incoming: AcceptIncoming = "accept"
    tws_cold_restart: str = ""
    tws_cold_restart_day: int = Field(default=0, ge=0, le=6)

    @model_validator(mode="after")
    def validate_cold_restart_format(self) -> "SessionConfig":
        v = self.tws_cold_restart
        if v and not re.match(r"^\d{2}:\d{2}$", v):
            raise ValueError(
                f"tws_cold_restart must be HH:MM 24h format or empty, got '{v}'"
            )
        return self


class CommandServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    port: int = Field(default=7462, ge=1, le=65535)
    paper_port: int = Field(default=7463, ge=1, le=65535)
    bind_address: str = "0.0.0.0"
    control_from: list[str] = ["127.0.0.1", "172.0.0.0/8"]


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    socket_path: str = "/run/ibctl/agent.sock"


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: LogLevel = "info"
    log_dir: str = ""
    futures_session_logging: bool = False
    session_reopen_hour: int = Field(default=18, ge=0, le=23)


class RecoveryConfig(BaseModel):
    """[timing.recovery] — reconnect coordinator (Aggressive/Backoff/GivenUp).

    Mirrors ibctl/src/config.rs::RecoveryTimingConfig. Env overrides
    (IBCTL_RECOVERY_*) layer on top — see env_overlay.py.

    Bounds asymmetry note: `giveup_callback_valid_hours` enforces
    ge=1, le=168 only here — Rust `u32` and Pkl `UInt` accept the full
    range. Matches the pre-existing `twofa.backoff.callback_valid_hours`
    pattern: preflight is the stricter gate, so a hand-edited TOML with
    `giveup_callback_valid_hours=0` is blocked at boot instead of
    silently disabling the retry link.

    TODO(PR-C stage 3.5, audit MED): add soft-warns for dead-config
    states — `backoff_interval_secs=0` (no cadence), `fingerprint_streak_
    forcing_hitl * backoff_interval_secs > backoff_phase_max_secs`
    (streak never fires), `min_success_dwell_secs > aggressive_phase_
    max_secs` (dwell exceeds phase budget). Deferred out of the initial
    audit-fix to keep the surface small.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    aggressive_phase_max_secs: int = Field(default=3600, ge=0)
    backoff_phase_max_secs: int = Field(default=10800, ge=0)
    backoff_interval_secs: int = Field(default=900, ge=0)
    min_success_dwell_secs: int = Field(default=60, ge=0)
    fingerprint_streak_forcing_hitl: int = Field(default=8, ge=0)
    giveup_ntfy_kind: str = "reconnect_gave_up"
    giveup_callback_valid_hours: int = Field(default=12, ge=1, le=168)
    giveup_alert_resend_interval_hours: int = Field(default=6, ge=0)


class TimingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
    relogin_failure_action: Literal["reauth", "restart"] = "reauth"
    api_port_probe_interval_secs: int = Field(default=5, ge=0, le=3600)
    api_port_probe_fails_before_revoke: int = Field(default=3, ge=1, le=10)
    recovery: RecoveryConfig = RecoveryConfig()


class SiteConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: SiteRole = "primary"
    auto_launch: bool = True


class DashboardConfig(BaseModel):
    """Dashboard section — consumed by entrypoint + FastAPI, not by Rust.

    Auth secrets (OAuth client secrets, tokens) are env-only — never in TOML.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    port: int = Field(default=8080, ge=1, le=65535)
    token: str = ""
    debug_mode: bool = False
    github_oauth_enabled: bool = False
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_scopes: str = "openid profile email"
    notifications_enabled: bool = False
    notification_channel: Literal["ntfy", "slack", "telegram"] = "ntfy"
    zmq_enabled: bool = True
    zmq_port: int = Field(default=5556, ge=1, le=65535)
    # Description lives in config/pkl/types.pkl::DashboardConfig.externalUrl
    # (Pkl `///` is the single source of truth — descriptions.json ships to
    # the dashboard config-page tooltip and `docker/ibctl.toml` gets the
    # rendered comment above the field).
    external_url: str = ""


class IbSystemStatusConfig(BaseModel):
    """IB system status scraper — consumed by dashboard daemon."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    ttl_seconds: int = Field(default=600, ge=0)
    check_interval_seconds: int = Field(default=300, ge=0)
    url: str = "https://www.interactivebrokers.com/en/software/systemStatus.php"
    region: str = "NA"
    backend_hosts: list[str] = ["cdc1-hb1.ibllc.com", "cdc1-hb2.ibllc.com"]
    fallback_host: str = "interactivebrokers.com"
    extra_exchange_keywords: list[str] = []
    extra_benign_phrases: list[str] = []
    extra_blocking_keywords: list[str] = []


class IbStatusConfig(BaseModel):
    """ibctl-side policy for IBSTATUS pushes — consumed by ibctl state machine.

    Separate from IbSystemStatusConfig which is the dashboard-side scraper.
    """

    model_config = ConfigDict(extra="forbid")

    # When IBSTATUS=unavailable arrives, should ibctl kick a Connected session?
    # Default false — IBSTATUS gates login retry, not active sessions.
    # The scraper can be wrong (CDN blips); Gateway's own UI label is the
    # authoritative signal via the revocation bus.
    kick_active_session: bool = False


# --- Top-level config ---


class IbctlConfig(BaseModel):
    """Complete ibctl config model. Validates TOML structure + cross-field rules.

    All sections are validated — unknown top-level sections are rejected.
    """

    model_config = ConfigDict(extra="forbid")

    auth: AuthConfig = AuthConfig()
    twofa: TwoFaConfig = TwoFaConfig()
    gateway: GatewayConfig = GatewayConfig()
    session: SessionConfig = SessionConfig()
    command_server: CommandServerConfig = CommandServerConfig()
    agent: AgentConfig = AgentConfig()
    dashboard: DashboardConfig = DashboardConfig()
    ib_system_status: IbSystemStatusConfig = IbSystemStatusConfig()
    ib_status: IbStatusConfig = IbStatusConfig()
    logging: LoggingConfig = LoggingConfig()
    timing: TimingConfig = TimingConfig()
    site: SiteConfig = SiteConfig()

    @model_validator(mode="after")
    def validate_cross_field_rules(self) -> "IbctlConfig":
        from pathlib import Path as _Path

        warnings: list[str] = []

        # Settings dir must exist for the recovery-marker persistence layer.
        # If gateway.tws_settings_path is set but not a directory, marker I/O
        # fails silently and the GivenUp latch regresses on every restart.
        # Empty string is valid — means "use IBC default derived from tws_path".
        # Soft-warn only (operator may deploy the volume later); never a hard error.
        _tsp = self.gateway.tws_settings_path
        if _tsp and not _Path(_tsp).is_dir():
            warnings.append(
                f"gateway.tws_settings_path={_tsp!r} is not an existing directory. "
                "The recovery marker persistence layer writes here; if the path "
                "resolves to an ephemeral or missing volume the GivenUp latch will "
                "regress on every container restart. Ensure the two settings-dir "
                "prefixes (Jts_live, Jts_paper) are on a persistent volume."
            )

        # Port conflict detection
        ports = {
            "gateway.live_api_port": self.gateway.live_api_port,
            "gateway.paper_api_port": self.gateway.paper_api_port,
            "gateway.live_socat_port": self.gateway.live_socat_port,
            "gateway.paper_socat_port": self.gateway.paper_socat_port,
            "command_server.port": self.command_server.port,
            "command_server.paper_port": self.command_server.paper_port,
            "dashboard.port": self.dashboard.port,
            "dashboard.zmq_port": self.dashboard.zmq_port,
        }
        seen: dict[int, str] = {}
        for name, port in ports.items():
            if port in seen:
                raise ValueError(
                    f"Port conflict: {name} ({port}) collides with {seen[port]}"
                )
            seen[port] = name

        # Dashboard requires command server
        if self.dashboard.enabled and not self.command_server.enabled:
            raise ValueError(
                "dashboard.enabled=true requires command_server.enabled=true — "
                "the dashboard connects to ibctl via the command server"
            )

        # IB system status scraper requires dashboard
        if self.ib_system_status.enabled and not self.dashboard.enabled:
            raise ValueError(
                "ib_system_status.enabled=true requires dashboard.enabled=true — "
                "the status scraper runs inside the dashboard daemon"
            )

        # GitHub OAuth requires dashboard
        if self.dashboard.github_oauth_enabled and not self.dashboard.enabled:
            raise ValueError(
                "dashboard.github_oauth_enabled=true requires dashboard.enabled=true — "
                "GitHub OAuth is a dashboard login method"
            )

        # OIDC/SSO requires dashboard
        if self.dashboard.oidc_enabled and not self.dashboard.enabled:
            raise ValueError(
                "dashboard.oidc_enabled=true requires dashboard.enabled=true — "
                "OIDC/SSO is a dashboard login method"
            )

        # OIDC requires an issuer URL
        if self.dashboard.oidc_enabled and not self.dashboard.oidc_issuer:
            raise ValueError(
                "dashboard.oidc_enabled=true requires dashboard.oidc_issuer to be set "
                "(e.g. https://auth.example.com/application/o/ibctl/)"
            )

        # Notifications require dashboard
        if self.dashboard.notifications_enabled and not self.dashboard.enabled:
            raise ValueError(
                "dashboard.notifications_enabled=true requires dashboard.enabled=true — "
                "the notification service runs inside the dashboard daemon"
            )

        # Notification channel credential warnings
        if self.dashboard.notifications_enabled:
            import os
            ch = self.dashboard.notification_channel
            if ch == "slack" and not os.environ.get("IBCTL_SLACK_WEBHOOK_URL"):
                warnings.append(
                    "notification_channel=slack but IBCTL_SLACK_WEBHOOK_URL is not set — "
                    "Slack notifications will fail until a webhook URL is configured"
                )
            if ch == "telegram":
                if not os.environ.get("IBCTL_TELEGRAM_BOT_TOKEN"):
                    warnings.append(
                        "notification_channel=telegram but IBCTL_TELEGRAM_BOT_TOKEN is not set"
                    )
                if not os.environ.get("IBCTL_TELEGRAM_CHAT_ID"):
                    warnings.append(
                        "notification_channel=telegram but IBCTL_TELEGRAM_CHAT_ID is not set"
                    )

        # HITL 2FA ntfy_callback strategy requires ntfy notifications enabled
        # AND the signing key. Signing key check happens at validator.py level
        # (env-only secret, not in TOML).
        backoff = self.twofa.backoff
        if backoff.strategy in {"ntfy_callback", "both"}:
            if not self.dashboard.notifications_enabled:
                raise ValueError(
                    f"twofa.backoff.strategy='{backoff.strategy}' requires "
                    "dashboard.notifications_enabled=true — the callback URL is "
                    "delivered via the notification channel"
                )
            if self.dashboard.notification_channel != "ntfy":
                raise ValueError(
                    f"twofa.backoff.strategy='{backoff.strategy}' requires "
                    "dashboard.notification_channel='ntfy' — only ntfy supports the "
                    "action-button callback URL"
                )
            import os as _os
            if not _os.environ.get("IBCTL_NTFY_ACTION_SIGNING_KEY"):
                warnings.append(
                    f"twofa.backoff.strategy='{backoff.strategy}' but "
                    "IBCTL_NTFY_ACTION_SIGNING_KEY is not set — callback URLs "
                    "cannot be signed and the strategy will fail at runtime"
                )
            if (
                not self.dashboard.external_url
                and not _os.environ.get("IBCTL_DASHBOARD_EXTERNAL_URL")
            ):
                warnings.append(
                    f"twofa.backoff.strategy='{backoff.strategy}' but "
                    "neither dashboard.external_url nor IBCTL_DASHBOARD_EXTERNAL_URL "
                    "is set — ntfy action-button URLs will point at an internal "
                    "address unreachable from a phone"
                )

        # TCP probe disabled: noteworthy but not an error. Some operators
        # prefer label-probe-only for debugging. Warn so the reduced
        # detection footprint is explicit.
        if self.timing.api_port_probe_interval_secs == 0:
            warnings.append(
                "timing.api_port_probe_interval_secs=0 disables the TCP probe "
                "of Gateway's API port. The active label probe is then the "
                "only in-ibctl session-loss detector (dashboard's external "
                "FalseConnectedMonitor still runs independently)."
            )

        # HITL dead-end: strategy=disabled with on_timeout=restart_then_hitl
        # means ibctl will enter WaitingForHitl2fa after max_immediate_attempts
        # and sit there forever. Valid (operator uses dashboard HITL_RESUME
        # to recover) but easy to misconfigure accidentally.
        if (
            backoff.strategy == "disabled"
            and backoff.on_timeout == "restart_then_hitl"
            and backoff.max_immediate_attempts > 0
        ):
            warnings.append(
                "twofa.backoff.strategy='disabled' combined with "
                "on_timeout='restart_then_hitl' means HITL has no automatic "
                "recovery path. After "
                f"{backoff.max_immediate_attempts} failed 2FA attempts, ibctl "
                "will sit in WaitingForHitl2fa indefinitely until an operator "
                "sends HITL_RESUME manually via the dashboard. If that's not "
                "intended, set strategy to 'periodic', 'ntfy_callback', or 'both'."
            )

        # ZMQ PUB socket: on by default, runs automatically when dashboard runs.
        # No validation needed — silently inactive when dashboard is off.

        # Dual mode credential warning (env check happens in validator.py)
        # This only warns about TOML-level — env overrides are checked separately
        if (
            self.auth.trading_mode == "both"
            and not self.auth.paper.tws_userid
        ):
            warnings.append(
                "trading_mode=both but no paper tws_userid in TOML; "
                "ensure TWS_USERID_PAPER is set via env var"
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
    # 2FA backoff (HITL)
    "twofa.backoff.max_immediate_attempts": "IBCTL_TWOFA_MAX_IMMEDIATE_ATTEMPTS",
    "twofa.backoff.on_timeout": "IBCTL_TWOFA_ON_TIMEOUT",
    "twofa.backoff.strategy": "IBCTL_TWOFA_STRATEGY",
    "twofa.backoff.intervals_minutes": "IBCTL_TWOFA_INTERVALS_MINUTES",
    "twofa.backoff.callback_valid_hours": "IBCTL_TWOFA_CALLBACK_VALID_HOURS",
    "twofa.backoff.counter_reset": "IBCTL_TWOFA_COUNTER_RESET",
    "twofa.backoff.stable_secs": "IBCTL_TWOFA_STABLE_SECS",
    "twofa.backoff.cold_restart_preempts_hitl": "IBCTL_TWOFA_COLD_RESTART_PREEMPTS_HITL",
    "twofa.backoff.ntfy_send_retries": "IBCTL_TWOFA_NTFY_SEND_RETRIES",
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
    "session.tws_cold_restart_day": "TWS_COLD_RESTART_DAY",
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
    "timing.relogin_failure_action": "IBCTL_RELOGIN_FAILURE_ACTION",
    "timing.api_port_probe_interval_secs": "IBCTL_API_PORT_PROBE_INTERVAL_SECS",
    "timing.api_port_probe_fails_before_revoke": "IBCTL_API_PORT_PROBE_FAILS_BEFORE_REVOKE",
    # Timing — recovery coordinator ([timing.recovery])
    # DISABLED and FORCE_RESET are Rust-only env vars (not mapped to TOML);
    # see env_overlay._BOOL_ENV_VARS for their acceptance surface. The five
    # int vars below round-trip through TOML so the effective config Rust
    # loads matches what preflight validates.
    "timing.recovery.aggressive_phase_max_secs": "IBCTL_RECOVERY_AGGRESSIVE_MAX_SECS",
    "timing.recovery.backoff_phase_max_secs": "IBCTL_RECOVERY_BACKOFF_MAX_SECS",
    "timing.recovery.backoff_interval_secs": "IBCTL_RECOVERY_BACKOFF_INTERVAL_SECS",
    "timing.recovery.min_success_dwell_secs": "IBCTL_RECOVERY_MIN_SUCCESS_DWELL_SECS",
    "timing.recovery.fingerprint_streak_forcing_hitl": "IBCTL_RECOVERY_FINGERPRINT_STREAK",
    # Dashboard
    "dashboard.enabled": "IBCTL_DASHBOARD_ENABLED",
    "dashboard.port": "IBCTL_DASHBOARD_PORT",
    "dashboard.debug_mode": "IBCTL_DEBUG_MODE",
    "dashboard.github_oauth_enabled": "IBCTL_GITHUB_OAUTH_ENABLED",
    "dashboard.oidc_enabled": "IBCTL_OIDC_ENABLED",
    "dashboard.oidc_issuer": "IBCTL_OIDC_ISSUER",
    "dashboard.oidc_scopes": "IBCTL_OIDC_SCOPES",
    "dashboard.notifications_enabled": "IBCTL_NOTIFICATIONS_ENABLED",
    "dashboard.notification_channel": "IBCTL_NOTIFICATION_CHANNEL",
    "dashboard.zmq_enabled": "IBCTL_ZMQ_ENABLED",
    "dashboard.zmq_port": "IBCTL_ZMQ_PORT",
    "dashboard.external_url": "IBCTL_DASHBOARD_EXTERNAL_URL",
    # IB System Status
    "ib_system_status.enabled": "IBCTL_IB_STATUS_ENABLED",
    "ib_system_status.check_interval_seconds": "IB_STATUS_CHECK_INTERVAL",
    "ib_system_status.region": "IB_STATUS_REGION",
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
    "IBCTL_DASHBOARD_TOKEN",
    "IBCTL_DASHBOARD_AUTH_SECRET",
    "IBCTL_GITHUB_OAUTH_CLIENT_SECRET",
    "IBCTL_OIDC_CLIENT_SECRET",
    "IBCTL_NTFY_TOKEN",
    "IBCTL_NTFY_ACTION_SIGNING_KEY",
    "IBCTL_TELEGRAM_BOT_TOKEN",
    "IBCTL_SLACK_WEBHOOK_URL",
}
