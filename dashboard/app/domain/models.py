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
class Recovery:
    """Recovery-coordinator state exposed on the STATUS wire (PR-C stage 4).

    Mirrors the Rust ``queries.rs`` block. Every field defaults to a
    safe value so a downgraded ibctl daemon whose STATUS omits nested
    keys — or whose STATUS omits the ``recovery`` block entirely —
    still deserializes without crashing the dashboard's monitoring
    path (see :meth:`GatewayStatus.from_json`).

    Field semantics (from the stage-4 spec):

    - ``phase``: one of ``"aggressive"``, ``"backoff_every_15min"``,
      ``"given_up"`` (from ``RecoveryPhase::as_str`` on the Rust side).
    - ``phase_entered_at``: jiff ``Zoned`` wire string — RFC 9557 with
      a ``[tz]`` IANA bracket suffix, e.g.
      ``"2026-07-11T10:00:00-04:00[America/New_York]"``. NOT strict
      RFC 3339 — Python 3.11's ``datetime.fromisoformat`` and Node's
      ``Date.parse`` reject the bracket suffix; external consumers
      that need broad interop should strip everything from ``[``
      onward before parsing.
    - ``phase_elapsed_secs``: wall-clock delta from ``phase_entered_at``
      to the STATUS build instant, clamped ``>= 0``. Integer, not
      float; ZMQ subscribers may cast directly to ``int``.
    - ``last_full_success_at``: None until the first Connected dwell
      lands (``min_success_dwell_secs`` of stable Connected). When
      populated, matches ``phase_entered_at``'s Zoned format (bracket
      suffix included).
    - ``giveup_alert_sent_at``: None until GivenUp fires; used as the
      resend dedupe anchor at stage 5. When populated, RFC 3339 UTC-Z
      (e.g. ``"2026-07-11T14:00:00Z"``) — NO bracket suffix. This is
      DIFFERENT from ``phase_entered_at`` on the wire; the Rust
      accessor returns a ``jiff::Timestamp`` while the others return
      ``jiff::Zoned``. Downstream parsers that assume one format for
      every recovery timestamp will fail on this field — parse it
      with ``datetime.fromisoformat(s.replace("Z", "+00:00"))`` for
      Python <3.11, or ``datetime.fromisoformat(s)`` on 3.11+.
    - ``next_retry_at``: populated ONLY in ``backoff_every_15min`` —
      the next 15-min boundary strictly after now. Null otherwise so
      dashboards don't render a stale countdown. Same Zoned bracket
      format as ``phase_entered_at``.
    - ``blocked_awaiting_resume``: True when boot observed
      ``RefusedGivenUpAutoReset`` and the main loop is parked at the
      resume gate. Drives the RED-badge alert prefix in the header.
    """

    phase: str | None = None
    phase_entered_at: str | None = None
    phase_elapsed_secs: int = 0
    last_full_success_at: str | None = None
    giveup_alert_sent_at: str | None = None
    next_retry_at: str | None = None
    blocked_awaiting_resume: bool = False
    # PR-C stage-5 review-fix pass (finding B-HIGH-1): config fields the
    # coordinator emits on STATUS so the dashboard monitor's give-up
    # alert body and resend cadence gate reflect the operator's config
    # rather than a fabricated fallback. All optional so a downgraded
    # ibctl daemon (pre-review-fix) still parses.
    aggressive_phase_max_secs: int | None = None
    backoff_phase_max_secs: int | None = None
    min_success_dwell_secs: int | None = None
    callback_valid_hours: int | None = None
    giveup_alert_resend_interval_hours: int | None = None

    @classmethod
    def from_json(cls, data: dict) -> Recovery:
        """Parse a recovery block from the STATUS response.

        Defensive against missing keys — an older ibctl daemon whose
        STATUS omits some but not all fields still surfaces the ones
        it emits. The mixed-deploy scenario at stage-4 spec §3.
        """
        return cls(
            phase=data.get("phase"),
            phase_entered_at=data.get("phase_entered_at"),
            phase_elapsed_secs=data.get("phase_elapsed_secs", 0),
            last_full_success_at=data.get("last_full_success_at"),
            giveup_alert_sent_at=data.get("giveup_alert_sent_at"),
            next_retry_at=data.get("next_retry_at"),
            blocked_awaiting_resume=bool(data.get("blocked_awaiting_resume", False)),
            aggressive_phase_max_secs=data.get("aggressive_phase_max_secs"),
            backoff_phase_max_secs=data.get("backoff_phase_max_secs"),
            min_success_dwell_secs=data.get("min_success_dwell_secs"),
            callback_valid_hours=data.get("callback_valid_hours"),
            giveup_alert_resend_interval_hours=data.get(
                "giveup_alert_resend_interval_hours"
            ),
        )


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
    paused: bool = False
    ceiling_state: str | None = None
    stats: Stats = field(default_factory=Stats)
    client_advisory: ClientAdvisory = field(
        default_factory=lambda: ClientAdvisory(
            should_connect=False, should_wait=True, wait_reason="unknown"
        )
    )
    # PR-C stage 4: RecoveryCoordinator exposure. Optional so a
    # downgraded live/paper daemon (that predates stage 4) doesn't
    # crash the dashboard's status card. `None` here is the wire-level
    # "field absent" signal; when present, callers get the typed
    # `Recovery` value object. See stage-4 spec §3.
    recovery: Recovery | None = None

    @classmethod
    def from_json(cls, data: dict) -> GatewayStatus:
        """Parse from ibctl STATUS command JSON response."""
        advisory_data = data.get("client_advisory", {})
        stats_data = data.get("stats", {})

        socat_data = data.get("socat", {})
        jvm_data = data.get("jvm", {})

        # Recovery block: absent on older ibctl daemons (mixed-deploy
        # compat). Only wrap in a Recovery model when the key is
        # present; None on absence so consumers can `if status.recovery:`.
        recovery_data = data.get("recovery")
        recovery = Recovery.from_json(recovery_data) if isinstance(recovery_data, dict) else None

        return cls(
            ready=data.get("ready", False),
            state=data.get("state", "unknown"),
            trading_mode=data.get("trading_mode", "unknown"),
            uptime_secs=data.get("uptime_secs", 0),
            connected_uptime_secs=data.get("connected_uptime_secs"),
            socat_running=socat_data.get("running", False),
            jvm_running=jvm_data.get("alive", False),
            paused=data.get("paused", False),
            ceiling_state=data.get("ceiling_state"),
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
            recovery=recovery,
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
