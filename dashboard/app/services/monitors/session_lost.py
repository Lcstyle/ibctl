"""Monitor: alert when a session stays OUT of Connected, not when it leaves.

Dwell-triggered, replacing an earlier edge-triggered design.

WHY
---
The edge-triggered monitor paged on every `Connected -> X` transition. The
median time out of Connected is around 15 seconds, and nearly every
departure recovers within 10 minutes, so the overwhelming majority of those
pages were for blips that had already healed before the operator could read
the message. Typical examples are the scheduled daily warm restart and IB's
routine nightly reconnect: both self-recover and need no human.

Paging on the EDGE answers "did something happen?", which is nearly always
yes and nearly always irrelevant. Paging on the DWELL answers "is it still
broken?", which is the question an operator can act on.

A 10-minute threshold removes nearly all of those pages while still
catching every multi-hour outage — including a HITL wait lasting hours,
which the edge-triggered design also caught but then never mentioned again.

WHAT THIS ALSO FIXES
--------------------
* No "restored" notification ever existed. An operator who got a page had
  no way to learn it had cleared except by opening the dashboard. Now a
  recovery notice is sent — but ONLY if we actually paged, so a healed
  blip stays completely silent in both directions.
* Nothing ever re-asserted an ongoing outage. Every alert in this system
  was one-shot, including the HITL page, so a gateway could sit unable to
  trade for hours after a single notification. This monitor
  re-nags while the condition persists.
* `Connected` with `ready=false` (socat dead) was untradeable and
  unalarmed. It now counts as down.

SCHEDULED-RESTART SUPPRESSION
-----------------------------
The original scheduled-restart suppression checked whether *now* — at the
moment the alert_after threshold crossed — fell within
+/-SUPPRESS_WINDOW_MINUTES of a scheduled time. That can never fire: by
construction, the check only runs once `elapsed >= alert_after` (10 min
default), so if `down_since` is at the scheduled time, "now" at check time
is already >= alert_after minutes past it. With a 5-minute window and a
10-minute threshold, "now" has always already left the window before the
check that would use it ever runs. The disconnects and reconnects caused
by the daily warm restart and the weekly cold restart are expected — but
the suppression meant to cover them was dead code for any outage that
reached the page threshold at all.

Fixed by anchoring to when the outage BEGAN, not to the time of the check:
`_scheduled_restart_grace_deadline(down_since)` asks "did this episode
START near a scheduled restart?", and if so returns a deadline
`down_since + SCHEDULED_RESTART_GRACE_MINUTES` computed once and cached —
independent of how many ticks pass before the check runs. Widened from 5 to
20 minutes for the correlated case specifically: a scheduled cold restart's
own 2FA can retry three times at 120s each before HITL escalation (~6 min),
and HITL's own dedicated alert (see hitl_2fa.py, state-triggered, not
time-window-based) already covers "needs a human" — this grace only exists
so a working-as-designed reconnect doesn't ALSO produce a redundant "still
down" page while it's still legitimately in progress. It is bounded, not
unbounded: a failure that isn't 2FA-shaped at all (stuck before ever
reaching WaitingFor2fa/WaitingForHitl2fa) still pages once the grace
deadline passes — this monitor stays the backstop for that class of
failure, which hitl_2fa.py cannot see.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime

from app.services.effective_config import int_setting
from app.services.monitor_manager import Alert, Monitor

logger = logging.getLogger("dashboard.services.monitors.session_lost")

# States that are NOT "down" even though they are not Connected.
#
# WaitingForLaunch is the standby steady-state: on the failover host the
# gateway is deliberately not logged in, and paging every N minutes about
# that would be relentless and wrong.
#
# Shutdown is a deliberate exit. It IS untradeable, and leaving it out makes
# it permanently unalarmed — but paging about a gateway someone
# intentionally stopped is the noise this rewrite exists to remove. Left
# out consciously, not by oversight.
# NOTE: `Connected` is deliberately NOT in this set. Tradeability for
# Connected is decided by `ready` (socat alive), and listing it here would
# shadow that check — a Connected-but-not-ready gateway would be treated as
# healthy, which is the exact untradeable-and-silent case this monitor is
# supposed to start covering. Caught by
# test_connected_but_not_ready_counts_as_down.
NOT_DOWN_STATES = {"WaitingForLaunch", "Shutdown"}

# How close to a scheduled clock time an outage's START has to land to be
# treated as caused by that restart, not a coincidental unrelated failure
# that merely happens to overlap it. Matches cold_restart_pending's own
# 30s lead-time warning plus slack for detection lag between the schedule
# firing and this monitor observing the state leave Connected.
SCHEDULE_CORRELATION_MINUTES = 5

# How long, from the moment a schedule-correlated episode began, to
# withhold the "still down" page entirely. See the module docstring's
# SCHEDULED-RESTART SUPPRESSION section for why 20, not the same value as
# SCHEDULE_CORRELATION_MINUTES.
DEFAULT_SCHEDULED_RESTART_GRACE_MINUTES = 20

DEFAULT_ALERT_AFTER_MINUTES = 10
DEFAULT_RENAG_MINUTES = 60


def _scheduled_restart_grace_minutes() -> int:
    """dashboard.scheduled_restart_grace_minutes (env IBCTL_SCHEDULED_RESTART_GRACE_MINUTES)."""
    return int_setting("dashboard.scheduled_restart_grace_minutes", DEFAULT_SCHEDULED_RESTART_GRACE_MINUTES)


def _scheduled_restart_grace_deadline(down_since: float) -> float | None:
    """If `down_since` (epoch seconds) correlates with a scheduled restart,
    return the epoch deadline up to which paging should be withheld for
    THIS episode. Returns None if it doesn't correlate with either the
    daily AUTO_RESTART_TIME or the weekly TWS_COLD_RESTART.

    Takes `down_since` rather than reading the clock itself: the answer is
    then a pure function of when the episode began, computed once and
    cached by the caller, rather than silently changing meaning depending
    on how many ticks have passed since — which is exactly the bug in the
    function this replaced.
    """
    at = datetime.fromtimestamp(down_since)
    at_minutes = at.hour * 60 + at.minute

    cold_time = os.environ.get("TWS_COLD_RESTART", "")
    day_raw = os.environ.get("TWS_COLD_RESTART_DAY", "").strip()
    cold_day = int(day_raw) if day_raw else 0
    at_day = (at.weekday() + 1) % 7  # Python 0=Mon -> 0=Sun

    correlated = False
    if cold_time and at_day == cold_day:
        try:
            parts = cold_time.split(":")
            target = int(parts[0]) * 60 + int(parts[1])
            if abs(at_minutes - target) <= SCHEDULE_CORRELATION_MINUTES:
                correlated = True
        except (ValueError, IndexError):
            pass

    if not correlated:
        auto_time = os.environ.get("AUTO_RESTART_TIME", "")
        if auto_time:
            try:
                parsed = datetime.strptime(auto_time.strip(), "%I:%M %p")
                target = parsed.hour * 60 + parsed.minute
                if abs(at_minutes - target) <= SCHEDULE_CORRELATION_MINUTES:
                    correlated = True
            except ValueError:
                pass

    if not correlated:
        return None
    return down_since + _scheduled_restart_grace_minutes() * 60


def _fmt_duration(secs: float) -> str:
    mins = int(secs // 60)
    if mins < 60:
        return f"{mins}m"
    return f"{mins // 60}h {mins % 60}m"


class SessionLostMonitor(Monitor):
    """Page when a gateway has been unable to trade for longer than a threshold."""

    event_type = "session_lost"
    interval_seconds = 30

    def __init__(self) -> None:
        super().__init__()
        # mode -> epoch seconds when it left the tradeable set
        self._down_since: dict[str, float] = {}
        # mode -> the state it was in when we first saw it down (for the message)
        self._down_from: dict[str, str] = {}
        # mode -> epoch seconds of the most recent page for this episode
        self._paged_at: dict[str, float] = {}
        # mode -> epoch deadline (down_since + grace) below which the first
        # page is withheld, IF this episode correlates with a scheduled
        # restart. Computed once when the episode starts (see
        # _scheduled_restart_grace_deadline) and cached — not recomputed
        # against a moving "now" on every tick.
        self._grace_deadline: dict[str, float] = {}

    @staticmethod
    def _alert_after_secs() -> int:
        """dashboard.session_down_alert_minutes (env IBCTL_SESSION_DOWN_ALERT_MINUTES)."""
        return int_setting("dashboard.session_down_alert_minutes", DEFAULT_ALERT_AFTER_MINUTES) * 60

    @staticmethod
    def _renag_secs() -> int:
        """dashboard.session_down_renag_minutes (env IBCTL_SESSION_DOWN_RENAG_MINUTES)."""
        return int_setting("dashboard.session_down_renag_minutes", DEFAULT_RENAG_MINUTES) * 60

    def _clear(self, mode: str) -> None:
        self._down_since.pop(mode, None)
        self._down_from.pop(mode, None)
        self._paged_at.pop(mode, None)
        self._grace_deadline.pop(mode, None)

    async def check(self, registry, ns) -> list[Alert]:
        alert_after = self._alert_after_secs()
        if alert_after <= 0:
            return []
        renag = self._renag_secs()
        now = time.time()
        alerts: list[Alert] = []

        for inst in registry.cached_all_status():
            mode = inst.mode
            status = inst.status or {}
            state = status.get("state", "unknown")

            # Connected but not ready (socat dead) is untradeable — treat as
            # down. `ready` is only meaningful when Connected; elsewhere the
            # state itself already says we are down.
            tradeable = state == "Connected" and status.get("ready", True)
            benign = state in NOT_DOWN_STATES

            if tradeable or benign:
                if mode in self._down_since:
                    down_for = now - self._down_since[mode]
                    had_paged = mode in self._paged_at
                    self._clear(mode)
                    # Closure ONLY if we actually paged. A blip that healed
                    # inside the threshold was never announced, so announcing
                    # its recovery would reintroduce exactly the noise this
                    # rewrite removes.
                    if had_paged:
                        alerts.append(
                            Alert(
                                event_type=self.event_type,
                                title=f"ibctl: {mode.upper()} session restored",
                                body=(
                                    f"{mode.upper()} is back in {state} and able to trade.\n"
                                    f"Total time down: {_fmt_duration(down_for)}."
                                ),
                                priority="default",
                                tags="white_check_mark",
                            )
                        )
                        logger.info(
                            "session restored for %s after %s", mode, _fmt_duration(down_for)
                        )
                continue

            # --- still down ---
            if mode not in self._down_since:
                self._down_since[mode] = now
                self._down_from[mode] = state
                deadline = _scheduled_restart_grace_deadline(now)
                if deadline is not None:
                    self._grace_deadline[mode] = deadline
                    logger.info(
                        "%s left the tradeable set (state=%s) — correlates with a scheduled "
                        "restart, paging withheld until %s unless it fails to recover",
                        mode,
                        state,
                        datetime.fromtimestamp(deadline).strftime("%H:%M:%S"),
                    )
                else:
                    logger.info(
                        "%s left the tradeable set (state=%s) — %dm timer started, no page yet",
                        mode,
                        state,
                        alert_after // 60,
                    )
                continue

            elapsed = now - self._down_since[mode]

            last_paged = self._paged_at.get(mode)
            if last_paged is None:
                grace = self._grace_deadline.get(mode)
                if grace is not None and now < grace:
                    logger.info(
                        "session_lost page for %s withheld — %ds left in scheduled-restart grace",
                        mode,
                        int(grace - now),
                    )
                    continue
                if elapsed < alert_after:
                    continue
                self._paged_at[mode] = now
                alerts.append(
                    Alert(
                        event_type=self.event_type,
                        title=f"ibctl: {mode.upper()} still down after {_fmt_duration(elapsed)}",
                        body=(
                            f"{mode.upper()} has been unable to trade for "
                            f"{_fmt_duration(elapsed)} and has not recovered on its own.\n"
                            f"Current state: {state}\n"
                            f"Left Connected from: {self._down_from.get(mode, 'unknown')}\n\n"
                            f"This is a dwell alert — transient drops (median 15s) are "
                            f"not paged. You are seeing this because it persisted."
                        ),
                        priority="high",
                        tags="warning",
                    )
                )
                logger.warning(
                    "Alert sent: %s down for %s (state=%s)", mode, _fmt_duration(elapsed), state
                )
            elif renag > 0 and (now - last_paged) >= renag:
                self._paged_at[mode] = now
                alerts.append(
                    Alert(
                        event_type=self.event_type,
                        title=f"ibctl: {mode.upper()} STILL down — {_fmt_duration(elapsed)}",
                        body=(
                            f"{mode.upper()} remains unable to trade after "
                            f"{_fmt_duration(elapsed)}.\n"
                            f"Current state: {state}\n\n"
                            f"Still waiting on intervention."
                        ),
                        priority="high",
                        tags="warning",
                    )
                )
                logger.warning(
                    "Re-nag sent: %s still down for %s", mode, _fmt_duration(elapsed)
                )

        return alerts
