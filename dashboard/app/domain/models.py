"""Domain models for ibctl gateway status.

Frozen dataclasses — immutable value objects with no infrastructure imports.
These represent the gateway state as seen by API consumers.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ClientAdvisory:
    """Advice for API clients on whether/how to connect."""

    should_connect: bool
    should_wait: bool
    wait_reason: str | None = None
    client_id_likely_stale: bool = False


@dataclass(frozen=True)
class Stats:
    """Runtime statistics collected by ibctl."""

    restarts_today: int = 0
    relogins_today: int = 0
    dialogs_dismissed: int = 0
    last_2fa_duration_secs: float | None = None
    config_apply_duration_secs: float | None = None


@dataclass(frozen=True)
class Scheduling:
    """Upcoming scheduled events."""

    daily_restart: str | None = None
    daily_restart_in_secs: int | None = None
    cold_restart: str | None = None
    cold_restart_in_secs: int | None = None


@dataclass(frozen=True)
class GatewayStatus:
    """Full gateway status — the primary API response."""

    ready: bool
    state: str
    trading_mode: str
    uptime_secs: int = 0
    connected_uptime_secs: int | None = None
    socat_running: bool = False
    jvm_running: bool = False
    stats: Stats = field(default_factory=Stats)
    client_advisory: ClientAdvisory = field(
        default_factory=lambda: ClientAdvisory(
            should_connect=False, should_wait=True, wait_reason="unknown"
        )
    )

    @classmethod
    def from_json(cls, data: dict) -> GatewayStatus:
        """Parse from ibctl STATUS command JSON response."""
        advisory_data = data.get("client_advisory", {})
        stats_data = data.get("stats", {})

        return cls(
            ready=data.get("ready", False),
            state=data.get("state", "unknown"),
            trading_mode=data.get("trading_mode", "unknown"),
            uptime_secs=data.get("uptime_secs", 0),
            connected_uptime_secs=data.get("connected_uptime_secs"),
            socat_running=data.get("socat_running", False),
            jvm_running=data.get("jvm_running", False),
            stats=Stats(
                restarts_today=stats_data.get("restarts_today", 0),
                relogins_today=stats_data.get("relogins_today", 0),
                dialogs_dismissed=stats_data.get("dialogs_dismissed", 0),
                last_2fa_duration_secs=stats_data.get("last_2fa_duration_secs"),
                config_apply_duration_secs=stats_data.get("config_apply_duration_secs"),
            ),
            client_advisory=ClientAdvisory(
                should_connect=advisory_data.get("should_connect", False),
                should_wait=advisory_data.get("should_wait", True),
                wait_reason=advisory_data.get("wait_reason"),
                client_id_likely_stale=advisory_data.get("client_id_likely_stale", False),
            ),
        )


@dataclass(frozen=True)
class Transition:
    """A recorded state machine transition."""

    timestamp: str
    from_state: str
    to_state: str


@dataclass(frozen=True)
class StateMachineState:
    """State machine current state and transition history."""

    current: str
    history: list[Transition] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: dict) -> StateMachineState:
        return cls(
            current=data.get("current", "unknown"),
            history=[
                Transition(
                    timestamp=t.get("timestamp", ""),
                    from_state=t.get("from", ""),
                    to_state=t.get("to", ""),
                )
                for t in data.get("history", [])
            ],
        )


@dataclass(frozen=True)
class LogEntry:
    """A single log line."""

    timestamp: str
    level: str
    message: str
