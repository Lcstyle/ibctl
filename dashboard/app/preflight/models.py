"""Pydantic v2 models for ibctl config validation.

Field names match IBC conventions (the canonical env var names).
These models mirror config/pkl/types.pkl and ibctl/src/config.rs.

ENV_MAP maps TOML dotted paths to their canonical environment variable names.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path as _Path
from typing import Annotated, ClassVar, Literal
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
)

# --- Enum types (match Pkl typealiases and Rust enums) ---
#
# 'builtin' dropped from TotpProvider — Rust returns TotpError::BuiltinNotImplemented
# at runtime, and the schema must not advertise a value that is broken at
# runtime.
TradingMode = Literal["live", "paper", "both"]
TotpProvider = Literal["oathtool"]
TwoFaTimeoutAction = Literal["restart", "exit"]
GatewayProgram = Literal["gateway", "tws"]
SessionAction = Literal["primary", "secondary", "primaryoverride"]
AcceptIncoming = Literal["accept", "reject", "manual"]
SiteRole = Literal["primary", "standby"]
LogLevel = Literal["debug", "info", "warn", "error"]
IbStatusRegion = Literal["NA", "EU", "APAC"]

# --- Reusable annotated type aliases ---
#
# PortNumber consolidates the ge=1, le=65535 constraint that was duplicated
# across 8 port fields — refactor slips re-open port=0 acceptance.
PortNumber = Annotated[int, Field(ge=1, le=65535)]

# Shape of an IANA time zone name; same pattern as Pkl's OptionalTimeZone.
_TIME_ZONE_SHAPE = re.compile(r"UTC|GMT|[A-Za-z]+(/[A-Za-z0-9][A-Za-z0-9_+-]*){1,2}")

# --- Config section models ---


class PaperAuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tws_userid: str = Field(default="", pattern=r"^[a-zA-Z0-9_]*$")


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tws_userid: str = Field(default="", pattern=r"^[a-zA-Z0-9_]*$")
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
    # "HH:MM-HH:MM" (container TZ), "" or "off" = none.
    unattended_hours: str = Field(
        default="",
        pattern=r"^(|off|([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d)$",
    )

    @model_validator(mode="after")
    def validate_backoff(self) -> "TwoFaBackoffConfig":
        """Cross-field guards for HITL 2FA backoff.

        The four invariants encoded here mirror the Pkl `hidden ok` chain.
        """
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

        # An empty window can't be told from a 24 h one; Rust rejects it too.
        start, _, end = self.unattended_hours.partition("-")
        if end and start == end:
            raise ValueError(
                f"unattended_hours='{self.unattended_hours}' starts and ends at the "
                "same time. Use '' or 'off' for none — env: IBCTL_TWOFA_UNATTENDED_HOURS."
            )

        # ntfy_send_retries without an ntfy-involving strategy is harmless
        # dead config — don't error. At runtime the retry logic never runs.

        return self


class TwoFaConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    secret_env: str = Field(default="TWOFACTOR_CODE", pattern=r"^[A-Z][A-Z0-9_]*$")
    provider: TotpProvider = "oathtool"
    timeout_action: TwoFaTimeoutAction = "restart"
    exit_interval: int = Field(default=180, ge=1)
    device: str = ""
    relogin_after_timeout: bool = False
    backoff: TwoFaBackoffConfig = TwoFaBackoffConfig()

    @model_validator(mode="after")
    def validate_twofa(self) -> "TwoFaConfig":
        """Cross-field guards for 2FA policy.

        `relogin_after_timeout=true` combined with `timeout_action='exit'`
        is a mutually contradictory pair — the process would shut down
        before any relogin could run. Also rejects dead-config
        `exit_interval=0` (defensive; ge=1 catches it first, kept for
        symmetry with the Pkl `hidden ok` invariant).
        """
        if self.timeout_action == "exit" and self.exit_interval == 0:
            raise ValueError(
                "twofa.timeout_action='exit' with exit_interval=0 shuts down ibctl "
                "the instant the 2FA prompt appears. Set exit_interval to a positive "
                "value (default 180) or use timeout_action='restart' — env: TWOFA_EXIT_INTERVAL."
            )
        if self.relogin_after_timeout and self.timeout_action == "exit":
            raise ValueError(
                "twofa.relogin_after_timeout=true is incompatible with "
                "twofa.timeout_action='exit'. Pick one: relogin (set "
                "timeout_action='restart' via TWOFA_TIMEOUT_ACTION) or exit "
                "(clear RELOGIN_AFTER_TWOFA_TIMEOUT / set relogin_after_timeout=false)."
            )
        return self


class GatewayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tws_path: str = "/home/ibgateway/Jts"
    tws_settings_path: str = ""
    tws_major_vrsn: str = ""
    # IB Gateway's session time zone: an IANA name, or "" to leave jts.ini alone.
    time_zone: str = ""
    time_zone_live: str = ""
    time_zone_paper: str = ""
    java_heap_size: int = Field(default=768, ge=64)
    gateway_or_tws: GatewayProgram = "gateway"
    live_api_port: PortNumber = 4001
    paper_api_port: PortNumber = 4002
    live_socat_port: PortNumber = 4003
    paper_socat_port: PortNumber = 4004

    @field_validator("tws_path")
    @classmethod
    def _tws_path_absolute(cls, v: str) -> str:
        """Absolute-path check.

        A relative `tws_path` silently misbehaves at Rust launch time (the
        Jts directory is resolved against CWD, not the container root), and
        an empty one finds no Gateway launcher at all.
        """
        if not _Path(v).is_absolute():
            raise ValueError(
                f"gateway.tws_path must be an absolute path, got {v!r}. "
                "Set TWS_PATH to an absolute filesystem path (e.g. /home/ibgateway/Jts)."
            )
        return v

    @field_validator("tws_settings_path")
    @classmethod
    def _tws_settings_path_absolute(cls, v: str) -> str:
        """Absolute-path check.

        Empty string is the sentinel for "derive from tws_path"; any
        non-empty value must be absolute or the recovery marker persistence
        layer writes into a CWD-relative ghost directory.
        """
        if v and not _Path(v).is_absolute():
            raise ValueError(
                f"gateway.tws_settings_path must be empty (use TWS_PATH) or absolute, got {v!r}. "
                "Set TWS_SETTINGS_PATH to an absolute filesystem path."
            )
        return v

    @field_validator("time_zone", "time_zone_live", "time_zone_paper")
    @classmethod
    def _time_zone_known(cls, v: str, info) -> str:
        """Empty, or an IANA zone name the tz database knows.

        Empty means ibctl leaves the Gateway's jts.ini alone. The shape check
        is the one config/pkl/types.pkl::OptionalTimeZone applies (Pkl cannot
        read the tz database); the lookup then rejects names that fit the
        shape but name no zone.
        """
        if not v:
            return v
        env = ENV_MAP[f"gateway.{info.field_name}"]
        if not _TIME_ZONE_SHAPE.fullmatch(v):
            raise ValueError(
                f"gateway.{info.field_name} must be empty or an IANA time zone name "
                f"such as America/New_York, got {v!r}. Set {env} accordingly."
            )
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            raise ValueError(
                f"gateway.{info.field_name}={v!r} is not a time zone the tz database "
                f"knows. Use an IANA name such as America/New_York — env: {env}."
            ) from None
        return v


class SessionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: SessionAction = "primary"
    accept_incoming: AcceptIncoming = "accept"
    tws_cold_restart: str = ""
    tws_cold_restart_day: int = Field(default=0, ge=0, le=6)

    @model_validator(mode="after")
    def validate_cold_restart_format(self) -> "SessionConfig":
        """Format check on twsColdRestart (tighter regex).

        The previous `^\\d{2}:\\d{2}$` regex accepted '99:99' and '25:00'.
        Constrain to a proper 24h HH:MM range or empty.
        """
        v = self.tws_cold_restart
        if v and not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", v):
            raise ValueError(
                f"tws_cold_restart must be HH:MM 24h format or empty, got '{v}'. "
                "Set TWS_COLD_RESTART to a valid 24h time (e.g. '09:00') or leave empty to disable."
            )
        return self


# Action commands ibctl's TCP command server can refuse, by wire name. Mirrors
# ACTION_COMMANDS in ibctl/src/command_access.rs (a test keeps them in step).
ACTION_COMMANDS: tuple[str, ...] = (
    "STOP", "START", "RESTART", "RECONNECTDATA", "RECONNECTACCOUNT", "ENABLEAPI",
    "EXIT", "RESTARTSOCAT", "PAUSE", "RESUME", "HITL_RESUME", "RESUME_RECONNECT",
    "MAINT_HOLD", "MAINT_RELEASE", "SETSTATE", "IBSTATUS", "SETRESTART",
)


class CommandServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    port: PortNumber = 7462
    paper_port: PortNumber = 7463
    bind_address: str = "0.0.0.0"
    # ibctl refuses every peer when the list is empty (command_server.rs is_allowed).
    control_from: list[str] = Field(default=["127.0.0.1", "172.0.0.0/8"], min_length=1)
    # Action commands ibctl accepts. Empty means the default (all of them); the
    # names mirror ACTION_COMMANDS in ibctl/src/command_access.rs.
    allowed_commands: list[str] = Field(default_factory=lambda: list(ACTION_COMMANDS))

    @field_validator("bind_address")
    @classmethod
    def _bind_address_valid(cls, v: str) -> str:
        """IP address check.

        A malformed `bind_address` surfaces as an opaque Rust startup
        crash — reject at preflight with an actionable message.
        """
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(
                f"command_server.bind_address must be a valid IP (e.g. '0.0.0.0' or '127.0.0.1'), got {v!r}: {exc}. "
                "Set IBCTL_COMMAND_BIND_ADDRESS to a valid IP address."
            ) from exc
        return v

    @field_validator("control_from")
    @classmethod
    def _control_from_valid(cls, v: list[str]) -> list[str]:
        """IP / CIDR check.

        Each entry must parse as an IP or CIDR; a malformed entry silently
        fails the Rust allow-list check and locks out every client.
        """
        for entry in v:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"command_server.control_from entry {entry!r} is not a valid IP or CIDR: {exc}. "
                    "Set IBCTL_CONTROL_FROM to a comma-separated list of IPs/CIDRs "
                    "(e.g. '127.0.0.1,172.0.0.0/8')."
                ) from exc
        return v

    @field_validator("allowed_commands")
    @classmethod
    def _allowed_commands_valid(cls, v: list[str]) -> list[str]:
        """Names are trimmed, upper-cased and de-duplicated; blanks are dropped.

        An unknown name would silently match nothing and leave the caller
        locked out of a command it expects, so reject it with the valid set.
        Queries are always allowed and are not names for this list.
        """
        names: list[str] = []
        for entry in v:
            name = entry.strip().upper()
            if not name:
                continue
            if name not in ACTION_COMMANDS:
                raise ValueError(
                    f"command_server.allowed_commands entry {entry!r} is not an action command. "
                    f"Valid names: {', '.join(ACTION_COMMANDS)}. "
                    "Queries (STATUS, STATE, CONFIG, LOGS, WINDOWS, SUBSCRIBE) are always allowed. "
                    "Set IBCTL_ALLOWED_COMMANDS to a comma-separated list of those names, or leave it empty for all."
                )
            if name not in names:
                names.append(name)
        return names


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    socket_path: str = "/run/ibctl/agent.sock"

    @field_validator("socket_path")
    @classmethod
    def _socket_path_absolute(cls, v: str) -> str:
        """Absolute-path check.

        A relative `socket_path` silently misbehaves at Rust connect time —
        the Unix domain socket is created / opened against CWD.
        """
        if not _Path(v).is_absolute():
            raise ValueError(
                f"agent.socket_path must be an absolute path, got {v!r}. "
                "Set IBCTL_AGENT_SOCKET to an absolute filesystem path (e.g. /run/ibctl/agent.sock)."
            )
        return v


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: LogLevel = "info"
    log_dir: str = ""
    futures_session_logging: bool = False
    session_reopen_hour: int = Field(default=18, ge=0, le=23)
    retention_days: int = Field(default=0, ge=0)

    _warnings: list[str] = PrivateAttr(default_factory=list)

    @field_validator("log_dir")
    @classmethod
    def _log_dir_absolute_or_empty(cls, v: str) -> str:
        """Absolute-path check.

        Empty string means "log to stdout"; any non-empty value must be
        absolute so the log rotation surface is deterministic.
        """
        if v and not _Path(v).is_absolute():
            raise ValueError(
                f"logging.log_dir must be empty (stdout) or an absolute path, got {v!r}. "
                "Set IBCTL_LOG_DIR to an absolute filesystem path or leave unset for stdout."
            )
        return v

    @model_validator(mode="after")
    def _warn_futures_no_log_dir(self) -> "LoggingConfig":
        """Dead config: futures rotation without log_dir.

        `futures_session_logging=true` with an empty `log_dir` cannot rotate —
        stdout has no rotation surface — so the flag is silently dead.
        Surfaces as a warning (not error) so operators aren't locked out
        during transitional deploys.
        """
        if self.futures_session_logging and not self.log_dir:
            self._warnings.append(
                "logging.futures_session_logging=true with an empty log_dir has no effect — "
                "stdout has no rotation surface. Set IBCTL_LOG_DIR to enable per-session log files."
            )
        return self


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
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    aggressive_phase_max_secs: int = Field(default=3600, ge=1)
    backoff_phase_max_secs: int = Field(default=10800, ge=1)
    backoff_interval_secs: int = Field(default=900, ge=0)
    min_success_dwell_secs: int = Field(default=60, ge=1)
    fingerprint_streak_forcing_hitl: int = Field(default=8, ge=1)
    giveup_ntfy_kind: str = Field(default="reconnect_gave_up", min_length=1)
    giveup_callback_valid_hours: int = Field(default=12, ge=1, le=168)
    giveup_alert_resend_interval_hours: int = Field(default=6, ge=1)

    _warnings: list[str] = PrivateAttr(default_factory=list)

    @model_validator(mode="after")
    def validate_recovery(self) -> "RecoveryConfig":
        """RecoveryConfig cross-field invariants.

        Encodes the four invariants the coordinator was written to defend:

        - `min_success_dwell_secs > aggressive_phase_max_secs` → dwell can
          never accumulate; the 3-second-flap pathology sneaks back in.
        - `backoff_interval_secs == 0` with enabled → busy loop.
        - `backoff_phase_max_secs <= aggressive_phase_max_secs` → inverted
          phase ordering (escalation is Aggressive → Backoff → GivenUp).
        - `fingerprint_streak * backoff_interval > backoff_phase_max_secs`
          → same-error streak tripwire never fires (soft warn).
        """
        if not self.enabled:
            return self
        if self.min_success_dwell_secs > self.aggressive_phase_max_secs:
            raise ValueError(
                f"recovery.min_success_dwell_secs ({self.min_success_dwell_secs}) exceeds "
                f"aggressive_phase_max_secs ({self.aggressive_phase_max_secs}) — "
                "success dwell can never accumulate inside the aggressive phase. "
                "Lower IBCTL_RECOVERY_MIN_SUCCESS_DWELL_SECS below "
                "IBCTL_RECOVERY_AGGRESSIVE_MAX_SECS (default 60 vs 3600) or disable "
                "the coordinator with IBCTL_RECOVERY_DISABLED=1."
            )
        if self.backoff_interval_secs == 0:
            raise ValueError(
                "recovery.backoff_interval_secs=0 with recovery.enabled=true is a busy loop. "
                "Set IBCTL_RECOVERY_BACKOFF_INTERVAL_SECS>=60 or disable the coordinator "
                "with IBCTL_RECOVERY_DISABLED=1."
            )
        if self.backoff_phase_max_secs <= self.aggressive_phase_max_secs:
            raise ValueError(
                f"recovery.backoff_phase_max_secs ({self.backoff_phase_max_secs}) must be greater "
                f"than aggressive_phase_max_secs ({self.aggressive_phase_max_secs}) — "
                "phases escalate Aggressive -> Backoff -> GivenUp; inverted ordering is nonsense. "
                "Raise IBCTL_RECOVERY_BACKOFF_MAX_SECS above IBCTL_RECOVERY_AGGRESSIVE_MAX_SECS."
            )
        streak_time = self.fingerprint_streak_forcing_hitl * self.backoff_interval_secs
        if streak_time > self.backoff_phase_max_secs:
            self._warnings.append(
                f"recovery.fingerprint_streak_forcing_hitl ({self.fingerprint_streak_forcing_hitl}) "
                f"x backoff_interval_secs ({self.backoff_interval_secs}) = {streak_time}s exceeds "
                f"backoff_phase_max_secs ({self.backoff_phase_max_secs}) — the same-error streak "
                "tripwire will never fire; time-based GivenUp wins first. Either shorten "
                "IBCTL_RECOVERY_FINGERPRINT_STREAK or IBCTL_RECOVERY_BACKOFF_INTERVAL_SECS."
            )
        return self


class TimingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ui_tick_ms: int = Field(default=100, gt=0)
    agent_tick_ms: int = Field(default=50, gt=0)
    post_login_delay_ms: int = Field(default=1000, gt=0)
    popup_quiet_secs: int = Field(default=5, gt=0)
    popup_max_wait_secs: int = Field(default=30, gt=0)
    login_radio_delay_ms: int = Field(default=100, gt=0)
    jvm_shutdown_timeout_secs: int = Field(default=5, gt=0)
    login_dialog_timeout_secs: int = Field(default=120, ge=0)
    restart_delay_secs: int = Field(default=90, gt=0)
    relogin_max_attempts: int = Field(default=1, ge=0)
    relogin_failure_action: Literal["reauth", "restart"] = "reauth"
    api_port_probe_interval_secs: int = Field(default=5, ge=0, le=3600)
    api_port_probe_fails_before_revoke: int = Field(default=3, ge=1, le=10)
    recovery: RecoveryConfig = RecoveryConfig()


class SiteConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: SiteRole = "primary"
    auto_launch: bool = True

    @model_validator(mode="after")
    def _no_standby_split_brain(self) -> "SiteConfig":
        """Reject site.role='standby' + auto_launch=true (HA split-brain).

        A standby node that auto-launches Gateway on boot races the primary
        for the IB session — two nodes fight for the same authenticated
        socket. Escape hatch `IBCTL_STANDBY_AUTO_LAUNCH_OK=1` for niche
        hot-standby setups where the operator explicitly wants both nodes
        pre-warmed and coordinates externally.
        """
        if self.role == "standby" and self.auto_launch:
            if os.environ.get("IBCTL_STANDBY_AUTO_LAUNCH_OK") not in (
                "1",
                "true",
                "yes",
                "on",
            ):
                raise ValueError(
                    "site.role='standby' with site.auto_launch=true is an HA split-brain: "
                    "the standby node auto-launches Gateway on boot and fights the primary "
                    "for the IB session. Set site.auto_launch=false (env: IBCTL_AUTO_LAUNCH=false), "
                    "or set IBCTL_STANDBY_AUTO_LAUNCH_OK=1 for a niche hot-standby setup."
                )
        return self


class DashboardConfig(BaseModel):
    """Dashboard section — consumed by entrypoint + FastAPI, not by Rust.

    Auth secrets (OAuth client secrets, tokens) are env-only — never in TOML.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    port: PortNumber = 8080
    # token: env-only invariant enforced by _token_must_be_env_only field_validator
    # (a bare `max_length=0` Field constraint fires with an opaque
    # "String should have at most 0 characters" error, hiding the actionable
    # IBCTL_DASHBOARD_TOKEN fix — hence a field_validator, not the constraint).
    token: str = ""
    debug_mode: bool = False
    github_oauth_enabled: bool = False
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_scopes: str = "openid profile email"
    notifications_enabled: bool = False
    notification_channel: Literal["ntfy", "slack", "telegram"] = "ntfy"
    zmq_enabled: bool = True
    zmq_port: PortNumber = 5556
    # Description lives in config/pkl/types.pkl::DashboardConfig.externalUrl
    # (Pkl `///` is the single source of truth — descriptions.json ships to
    # the dashboard config-page tooltip and `docker/ibctl.toml` gets the
    # rendered comment above the field).
    external_url: str = ""
    # The session-lost monitor's timers and the version check's API client ID.
    # Descriptions: config/pkl/types.pkl::DashboardConfig.
    session_down_alert_minutes: int = Field(default=10, ge=0)
    session_down_renag_minutes: int = Field(default=60, ge=0)
    scheduled_restart_grace_minutes: int = Field(default=20, ge=0)
    version_probe_client_id: int = Field(default=9172, ge=0, le=2147483640)
    # Descriptions: config/pkl/types.pkl::DashboardConfig.sessionIdleMinutes.
    session_idle_minutes: int = Field(default=5, ge=0, le=1440)

    @field_validator("session_idle_minutes", mode="before")
    @classmethod
    def _session_idle_minutes_is_whole_minutes_in_range(cls, v):
        """Whole minutes, 0..1440, or an error that names the env var.

        The overlay turns IBCTL_SESSION_IDLE_MINUTES into an int when it is one
        and hands anything else over as text, so "abc" and "1.5" land here
        rather than quietly becoming the default of a setting that decides when
        a login ends. A quoted number or a float in the TOML is refused too.
        """
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 1440:
            raise ValueError(
                f"dashboard.session_idle_minutes must be a whole number of minutes from 0 to 1440 "
                f"(0 turns the idle logout off), got {v!r}. Set IBCTL_SESSION_IDLE_MINUTES to a "
                "number in that range, or leave it empty for the default (5)."
            )
        return v

    @field_validator("token")
    @classmethod
    def _token_must_be_env_only(cls, v: str) -> str:
        """dashboard.token security invariant — env-only.

        `max_length=0` also enforces this, but the field_validator gives a
        clear "set IBCTL_DASHBOARD_TOKEN, leave TOML empty" fix instead
        of the opaque string-length error.
        """
        if v:
            raise ValueError(
                "dashboard.token must be empty in TOML — the bearer token is env-only. "
                "Set IBCTL_DASHBOARD_TOKEN via env var and leave `token = \"\"` in TOML."
            )
        return v

    @field_validator("oidc_issuer")
    @classmethod
    def _oidc_issuer_is_url(cls, v: str) -> str:
        """URL check.

        Empty is allowed (oidc_enabled=false path); non-empty must be a
        full http(s):// URL so the FastAPI OIDC client can build valid
        `.well-known/openid-configuration` URLs.
        """
        if not v:
            return v
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                f"dashboard.oidc_issuer must be a full http(s):// URL, got {v!r}. "
                "Set IBCTL_OIDC_ISSUER=https://auth.example.com/application/o/ibctl/."
            )
        return v

    @field_validator("external_url")
    @classmethod
    def _external_url_is_url(cls, v: str) -> str:
        """URL check.

        Empty allowed (in-container callbacks path); non-empty must be a
        full http(s):// URL so ntfy action-button URLs are reachable from
        a phone.
        """
        if not v:
            return v
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                f"dashboard.external_url must be a full http(s):// URL, got {v!r}. "
                "Set IBCTL_DASHBOARD_EXTERNAL_URL=https://ibctl.example.com."
            )
        return v


class IbSystemStatusConfig(BaseModel):
    """IB system status scraper — consumed by dashboard daemon."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    ttl_seconds: int = Field(default=600, ge=1)
    check_interval_seconds: int = Field(default=300, ge=1)
    url: str = "https://www.interactivebrokers.com/en/software/systemStatus.php"
    region: IbStatusRegion = "NA"
    backend_hosts: list[str] = ["cdc1-hb1.ibllc.com", "cdc1-hb2.ibllc.com"]
    fallback_host: str = "interactivebrokers.com"
    extra_exchange_keywords: list[str] = []
    extra_benign_phrases: list[str] = []
    extra_blocking_keywords: list[str] = []

    @field_validator("url")
    @classmethod
    def _url_is_url(cls, v: str) -> str:
        """URL check.

        A malformed scraper URL turns into a silent HTTP failure loop; the
        preflight rejection surfaces the misconfig at boot instead.
        """
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                f"ib_system_status.url must be a full http(s):// URL, got {v!r}. "
                "Set IB_STATUS_URL to a full https:// URL for the scraper endpoint."
            )
        return v


class IbStatusConfig(BaseModel):
    """ibctl-side policy for IBSTATUS pushes — consumed by ibctl state machine.

    Separate from IbSystemStatusConfig which is the dashboard-side scraper.
    """

    model_config = ConfigDict(extra="forbid")

    # When IBSTATUS=unavailable arrives, should ibctl kick a Connected session?
    # Default false — IBSTATUS gates login retry, not active sessions.
    # The scraper can be wrong (CDN blips); Gateway's own UI label is the
    # authoritative signal via the revocation bus.
    #
    # Cross-field enforcement of the live-mode guard lives in
    # IbctlConfig.validate_cross_field_rules — this class cannot reach
    # auth.trading_mode on its own.
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

    # PrivateAttr replaces the previous `self.__dict__["_warnings"] = ...`
    # hack. PrivateAttr survives future frozen=True /
    # validate_assignment=True hardening; the __dict__ write does not.
    _warnings: list[str] = PrivateAttr(default_factory=list)

    @model_validator(mode="after")
    def validate_cross_field_rules(self) -> "IbctlConfig":
        """Cross-section invariants and warnings.

        Aggregates section-level `_warnings` (LoggingConfig, RecoveryConfig)
        and applies inter-section invariants such as port-conflict detection,
        dashboard/command-server dependency chains, the kick_active_session
        live-mode guard, oidc_scopes 'openid' presence, and
        dead-config warnings (external_url with dashboard disabled,
        cold_restart_day with empty cold_restart).
        """
        warnings: list[str] = []

        # Aggregate section-level warnings from child @model_validators.
        warnings.extend(self.logging._warnings)
        warnings.extend(self.timing.recovery._warnings)

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

        # Port conflict detection, with an actionable message.
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
                    f"Port conflict: {name} ({port}) collides with {seen[port]}. "
                    "Choose a different port for one of them — see docker/ibctl.toml "
                    "for the default port allocation."
                )
            seen[port] = name

        # Dashboard requires command server.
        if self.dashboard.enabled and not self.command_server.enabled:
            raise ValueError(
                "dashboard.enabled=true requires command_server.enabled=true — "
                "the dashboard connects to ibctl via the command server"
            )

        # IB system status scraper requires dashboard.
        if self.ib_system_status.enabled and not self.dashboard.enabled:
            raise ValueError(
                "ib_system_status.enabled=true requires dashboard.enabled=true — "
                "the status scraper runs inside the dashboard daemon"
            )

        # GitHub OAuth requires dashboard.
        if self.dashboard.github_oauth_enabled and not self.dashboard.enabled:
            raise ValueError(
                "dashboard.github_oauth_enabled=true requires dashboard.enabled=true — "
                "GitHub OAuth is a dashboard login method"
            )

        # OIDC/SSO requires dashboard.
        if self.dashboard.oidc_enabled and not self.dashboard.enabled:
            raise ValueError(
                "dashboard.oidc_enabled=true requires dashboard.enabled=true — "
                "OIDC/SSO is a dashboard login method"
            )

        # OIDC requires an issuer URL.
        if self.dashboard.oidc_enabled and not self.dashboard.oidc_issuer:
            raise ValueError(
                "dashboard.oidc_enabled=true requires dashboard.oidc_issuer to be set "
                "(e.g. https://auth.example.com/application/o/ibctl/)"
            )

        # oidc_scopes must include 'openid' when OIDC is
        # enabled — IBCTL_OIDC_SCOPES env can strip it silently.
        if self.dashboard.oidc_enabled and "openid" not in self.dashboard.oidc_scopes.split():
            raise ValueError(
                "dashboard.oidc_enabled=true requires dashboard.oidc_scopes to include 'openid' "
                f"(got {self.dashboard.oidc_scopes!r}). Set IBCTL_OIDC_SCOPES to a "
                "space-separated list containing 'openid' (e.g. 'openid profile email')."
            )

        # Notifications require dashboard.
        if self.dashboard.notifications_enabled and not self.dashboard.enabled:
            raise ValueError(
                "dashboard.notifications_enabled=true requires dashboard.enabled=true — "
                "the notification service runs inside the dashboard daemon"
            )

        # external_url + dashboard.enabled=false = dead config.
        if self.dashboard.external_url and not self.dashboard.enabled:
            warnings.append(
                "dashboard.external_url is set but dashboard.enabled=false — the URL "
                "points at a service that is not running. Remove external_url "
                "(unset IBCTL_DASHBOARD_EXTERNAL_URL) or set dashboard.enabled=true."
            )

        # tws_cold_restart_day set + tws_cold_restart empty = dead config.
        if self.session.tws_cold_restart_day != 0 and not self.session.tws_cold_restart:
            warnings.append(
                f"session.tws_cold_restart_day={self.session.tws_cold_restart_day} but "
                "session.tws_cold_restart is empty — the day is ignored without an HH:MM time. "
                "Set TWS_COLD_RESTART to enable weekly cold restart."
            )

        # ib_status.kick_active_session must not be accepted without context checks.
        # In live/both mode this is a foot-gun — a scraper CDN blip can kill an
        # authenticated live session. Escape hatch IBCTL_KICK_LIVE_SESSION_OK=1.
        if self.ib_status.kick_active_session:
            if self.auth.trading_mode in ("live", "both") and (
                os.environ.get("IBCTL_KICK_LIVE_SESSION_OK")
                not in ("1", "true", "yes", "on")
            ):
                raise ValueError(
                    "ib_status.kick_active_session=true with auth.trading_mode='"
                    f"{self.auth.trading_mode}' is a live-session foot-gun — a scraper CDN blip "
                    "can kill an authenticated live session. Set IBCTL_KICK_LIVE_SESSION_OK=1 "
                    "to opt in, or leave kick_active_session=false."
                )
            warnings.append(
                "ib_status.kick_active_session=true: any IBSTATUS=unavailable push will kick "
                "a Connected session. The scraper can be wrong (CDN blips) — Gateway's UI label "
                "is the authoritative session-health signal."
            )

        # Notification channel credential warnings — worded so operators see
        # the missed-alert consequence.
        if self.dashboard.notifications_enabled:
            ch = self.dashboard.notification_channel
            if ch == "slack" and not os.environ.get("IBCTL_SLACK_WEBHOOK_URL"):
                warnings.append(
                    "notification_channel=slack but IBCTL_SLACK_WEBHOOK_URL is not set — "
                    "Slack notifications will NOT fire until a webhook URL is configured; "
                    "set it now to avoid missed alerts."
                )
            if ch == "telegram":
                if not os.environ.get("IBCTL_TELEGRAM_BOT_TOKEN"):
                    warnings.append(
                        "notification_channel=telegram but IBCTL_TELEGRAM_BOT_TOKEN is not set — "
                        "Telegram notifications will NOT fire until it is configured; "
                        "set it now to avoid missed alerts."
                    )
                if not os.environ.get("IBCTL_TELEGRAM_CHAT_ID"):
                    warnings.append(
                        "notification_channel=telegram but IBCTL_TELEGRAM_CHAT_ID is not set — "
                        "Telegram notifications will NOT fire until it is configured; "
                        "set it now to avoid missed alerts."
                    )

        # HITL 2FA ntfy_callback strategy requires ntfy notifications enabled.
        # Signing-key + external_url env-presence hard errors live in validator.py
        # (env-only invariants, only enforced under check_env=True).
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

        # Trading-mode → userid presence invariant. Enforced here (not in
        # validator.py) so it fires under both check_env=True and --no-env.
        # tws_userid may be sourced from env at overlay time; this validator sees the
        # already-overlaid model (or the plain TOML on --no-env). In either
        # case an empty userid at this layer is unrecoverable.
        if not self.auth.tws_userid:
            raise ValueError(
                "auth.tws_userid is required. Set TWS_USERID (or "
                "TWS_USERID_FILE) in the environment, or write tws_userid "
                "into the TOML under [auth]."
            )
        if self.auth.trading_mode == "both" and not self.auth.paper.tws_userid:
            raise ValueError(
                "trading_mode=both requires auth.paper.tws_userid. Set "
                "TWS_USERID_PAPER (or TWS_USERID_PAPER_FILE) in the "
                "environment, or write paper.tws_userid into the TOML "
                "under [auth.paper]."
            )

        # paper.tws_userid set but trading_mode doesn't use it.
        if (
            self.auth.trading_mode in ("live", "paper")
            and self.auth.paper.tws_userid
        ):
            warnings.append(
                f"auth.paper.tws_userid is set but trading_mode='{self.auth.trading_mode}' "
                "does not use paper session — clear the paper block or set trading_mode='both'."
            )

        self._warnings = warnings
        return self

    def get_warnings(self) -> list[str]:
        return list(self._warnings)


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
    "twofa.backoff.unattended_hours": "IBCTL_TWOFA_UNATTENDED_HOURS",
    # Gateway
    "gateway.tws_path": "TWS_PATH",
    "gateway.tws_settings_path": "TWS_SETTINGS_PATH",
    "gateway.tws_major_vrsn": "TWS_MAJOR_VRSN",
    "gateway.time_zone": "TIME_ZONE",
    "gateway.time_zone_live": "TIME_ZONE_LIVE",
    "gateway.time_zone_paper": "TIME_ZONE_PAPER",
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
    "command_server.allowed_commands": "IBCTL_ALLOWED_COMMANDS",
    # Agent
    "agent.socket_path": "IBCTL_AGENT_SOCKET",
    # Logging
    "logging.level": "IBCTL_LOG_LEVEL",
    "logging.log_dir": "IBCTL_LOG_DIR",
    "logging.futures_session_logging": "IBCTL_FUTURES_SESSION_LOGGING",
    "logging.session_reopen_hour": "IBCTL_SESSION_REOPEN_HOUR",
    "logging.retention_days": "IBCTL_LOG_RETENTION_DAYS",
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
    "timing.recovery.giveup_callback_valid_hours": "IBCTL_RECOVERY_GIVEUP_CALLBACK_VALID_HOURS",
    "timing.recovery.giveup_alert_resend_interval_hours": "IBCTL_RECOVERY_GIVEUP_ALERT_RESEND_INTERVAL_HOURS",
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
    "dashboard.session_down_alert_minutes": "IBCTL_SESSION_DOWN_ALERT_MINUTES",
    "dashboard.session_down_renag_minutes": "IBCTL_SESSION_DOWN_RENAG_MINUTES",
    "dashboard.scheduled_restart_grace_minutes": "IBCTL_SCHEDULED_RESTART_GRACE_MINUTES",
    "dashboard.version_probe_client_id": "IBCTL_VERSION_PROBE_CLIENT_ID",
    "dashboard.session_idle_minutes": "IBCTL_SESSION_IDLE_MINUTES",
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

# Env vars that hold the IB login names: not secrets, but not for display either
# (see app.services.identity_mask).
IDENTITY_ENV_VARS: set[str] = {"TWS_USERID", "TWS_USERID_PAPER"}

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
