"""Monitor: the Sunday re-authentication, told to the operator per mode.

Three jobs, one contract: at the announced window every enabled
mode gets a clear outcome or a current, actionable path — the operator never
has to dig through overnight notifications for a link.

1. **Countdown** (just before the scheduled time): ONE message, a line per
   mode saying what is about to happen *to that mode* — rendered from the
   controller's own `cold_restart_plan` (the same decision ibctl will make
   when the fire lands; there is deliberately no second copy of that table
   here). A mode waiting for the operator's 2FA gets a fresh "Retry login"
   button. A standby host (every mode `standby`) sends nothing.

2. **Outcomes**: every new `last_cold_restart_outcome` ibctl records becomes
   one truthful notification — resumed login / challenge pending / waiting
   for operator / deferred / failed / completed / already satisfied. The
   first observation of a mode after a dashboard start is a baseline, not
   news. Standby and stopping are intentionally idle and stay silent.

3. **Success of a plain restart**: a mode that restarts from Connected is
   watched until it is back (two phases: leave Connected, then return), so
   the operator hears it worked without opening the dashboard.

Why this shape: a mode can sit waiting for 2FA for hours before the
scheduled fire. If the fire files it as "dormant" and this monitor stays
silent on that skip, the only way back is a link that is hours old.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime

from app.services.monitor_manager import Alert, Monitor
from app.services.monitors.hitl_2fa import retry_login_action

logger = logging.getLogger("dashboard.services.monitors.cold_restart_pending")

DAY_NAMES = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
]

# Ceiling on how long to keep watching a plain restart for its reconnect. Not
# a "this is stuck" threshold — session_lost.py's dwell alert and
# hitl_2fa.py's state-triggered alert own that job on their own timelines.
# This only bounds how long a stray watch entry lingers.
AWAIT_SUCCESS_MAX_SECS = 30 * 60

# Plans / outcomes for a mode that is intentionally idle (not failed).
_IDLE = {"standby", "stopping"}


def _format_time_12h(zoned_str: str) -> str:
    """Best-effort HH:MM AM/PM from a jiff ``Zoned`` display string, e.g.
    ``"2026-09-06T07:58:55.215136733-04:00[America/New_York]"`` -> ``"7:58 AM"``.

    Slices the fixed ISO-8601 prefix jiff's Display always produces. Falls
    back to the original string if it doesn't look like that shape, so a
    format change on the Rust side degrades to "a bit uglier", never to a
    crashed monitor tick.
    """
    try:
        hh, mm = int(zoned_str[11:13]), int(zoned_str[14:16])
        if zoned_str[13] != ":" or not (0 <= hh <= 23 and 0 <= mm <= 59):
            raise ValueError
    except (ValueError, IndexError, TypeError):
        return str(zoned_str)
    suffix = "AM" if hh < 12 else "PM"
    hh12 = hh % 12 or 12
    return f"{hh12}:{mm:02d} {suffix}"


def _since(status: dict) -> str | None:
    """Local wall-clock time the mode started waiting for 2FA, from STATUS
    `hitl.entered_at_secs_ago`, as "3:13 AM"."""
    secs = (status.get("hitl") or {}).get("entered_at_secs_ago")
    if not isinstance(secs, (int, float)):
        return None
    t = datetime.fromtimestamp(time.time() - secs)
    return f"{t.hour % 12 or 12}:{t.minute:02d} {'AM' if t.hour < 12 else 'PM'}"


def _parked(status: dict) -> bool:
    """The mode is waiting on the operator (WaitingForHitl2fa)."""
    return status.get("state") == "WaitingForHitl2fa"


# The gateway still shows its IB Key dialog while the mode is parked. The
# gateway closes that dialog itself when IBKR expires the push, so the push
# MAY still be approvable — but an open dialog is no proof the phone still
# shows it. Say both.
_OPEN_PROMPT = (
    "the gateway still shows an IB Key prompt, which may still be approvable — "
    "approve it if your phone shows it."
)


def _open_prompt_next_step(status: dict) -> str:
    if (status.get("hitl") or {}).get("relogin_armed"):
        return (
            "Otherwise ibctl re-submits the login in the running gateway (no restart) "
            "once the gateway closes it."
        )
    return (
        "Otherwise tap Retry login, which replaces that push with a new one: ibctl "
        "closes the prompt and re-submits the login in the running gateway (no restart)."
    )


def _countdown_line(mode: str, status: dict) -> str:
    """What the upcoming fire will do to this mode, and what (if anything)
    the operator should do — from the controller's `cold_restart_plan`."""
    m = mode.upper()
    plan = status.get("cold_restart_plan")
    state = status.get("state", "unknown")
    since = _since(status)
    waiting = f"waiting for 2FA since {since}" if since else "waiting for 2FA"
    hold = (status.get("maintenance") or {}).get("hold") or {}
    if hold.get("active"):
        # One maintenance event, two owners. The host is
        # updating the container runtime; ibctl decides afterwards.
        return (
            f"{m}: host maintenance '{hold.get('id', '?')}' is updating the container "
            "runtime — the Sunday re-auth waits for it. A gateway the update restarts is "
            "not restarted again: ibctl only finishes its login. Approve the IB Key prompt "
            "when it comes."
        )
    if plan == "restarted":
        return f"{m}: connected — will restart and log in again. Approve the IB Key prompt if asked."
    if plan == "resumed_login":
        return (
            f"{m}: {waiting} — ibctl will re-submit the login in the running gateway "
            "(no restart). Approve the IB Key prompt."
        )
    if plan == "awaiting_operator":
        return (
            f"{m}: {waiting} — tap Retry login to re-submit it in the running gateway "
            "(no restart), then approve the IB Key prompt."
        )
    if plan == "challenge_pending" and _parked(status):
        return f"{m}: {_OPEN_PROMPT} {_open_prompt_next_step(status)}"
    if plan == "challenge_pending":
        return f"{m}: an IB Key prompt is waiting now — approve it on your phone."
    if plan == "deferred":
        return f"{m}: already logging in ({state}) — ibctl will finish that login; approve the IB Key prompt if asked."
    if plan == "failed":
        return f"{m}: in Error — the re-login can't run. Open the dashboard."
    # An ibctl too old to publish a plan: say what we know, promise nothing.
    return f"{m}: {state} — 2FA approval (IB Key) may be required."


class ColdRestartPendingMonitor(Monitor):
    event_type = "cold_restart_pending"
    # Fired when ibctl's scheduler finds this week's re-auth already done.
    skipped_event_type = "cold_restart_skipped"
    # Fired when a restart reconnects, or an owed re-auth completes.
    success_event_type = "cold_restart_succeeded"
    # Fired for every other recorded outcome the operator should hear.
    outcome_event_type = "cold_restart_outcome"
    interval_seconds = 10  # Check frequently near restart time

    def __init__(self):
        self._alerted_today = False
        self._last_reset_day: int = -1
        # Plain-restart success watch, two phases (see module docstring):
        #   _awaiting_disconnect: restart expected, waiting for it to leave Connected
        #   _awaiting_success:    it left; waiting for it to come back
        self._awaiting_disconnect: dict[str, float] = {}
        self._awaiting_success: dict[str, float] = {}
        # mode -> STATUS dict, refreshed every tick before the countdown reads it.
        self._statuses: dict[str, dict] = {}
        # mode -> dedup key of the last outcome seen. A mode absent from this
        # dict has never been observed: its first observation is the
        # baseline and is never announced (dashboard restarts are not news).
        self._outcome_seen: dict[str, str | None] = {}

    async def check(self, registry, ns) -> list[Alert]:
        statuses = list(registry.cached_all_status())
        self._statuses = {inst.mode: (inst.status or {}) for inst in statuses}
        alerts = self._check_outcomes(ns)
        alerts.extend(self._check_success(ns))
        alerts.extend(self._check_pending(ns))
        return alerts

    # ------------------------------------------------------------------
    # 1. Countdown
    # ------------------------------------------------------------------

    def _check_pending(self, ns) -> list[Alert]:
        if not ns.is_event_enabled(self.event_type):
            return []

        cold_restart_time = os.environ.get("TWS_COLD_RESTART", "").strip()
        if not cold_restart_time:
            return []
        try:
            parts = cold_restart_time.split(":")
            target_hour, target_minute = int(parts[0]), int(parts[1])
        except (ValueError, IndexError):
            return []

        day_raw = os.environ.get("TWS_COLD_RESTART_DAY", "").strip()
        target_day = int(day_raw) if day_raw else 0  # 0 = Sunday default
        lead_seconds = ns.config.events.get(self.event_type, {}).get("lead_seconds", 30)

        now = datetime.now()
        current_day = (now.weekday() + 1) % 7  # Python: 0=Mon; convert to 0=Sun
        if current_day != self._last_reset_day:
            self._alerted_today = False
            self._last_reset_day = current_day
        if self._alerted_today or current_day != target_day:
            return []

        # ibctl fires AT the scheduled time (cold_restart.rs warns one lead
        # ahead), so this countdown is the real one.
        target_seconds = target_hour * 3600 + target_minute * 60
        current_seconds = now.hour * 3600 + now.minute * 60 + now.second
        seconds_until = target_seconds - current_seconds
        if not 0 < seconds_until <= lead_seconds:
            return []

        self._alerted_today = True
        active = {
            mode: s
            for mode, s in sorted(self._statuses.items())
            if s.get("cold_restart_plan") not in _IDLE
        }
        if self._statuses and not active:
            logger.info("Cold restart countdown suppressed — every mode is on standby")
            return []

        started = time.time()
        actions: list[dict] = []
        channel = getattr(ns.config, "channel", "")
        for mode, s in active.items():
            plan = s.get("cold_restart_plan")
            # Watch for a reconnect only where a restart will actually
            # happen (or an old ibctl that publishes no plan). Every other
            # mode's result arrives as an outcome record.
            if plan in (None, "restarted"):
                self._awaiting_disconnect[mode] = started
            if _parked(s):
                action = retry_login_action(mode, channel)
                if action:
                    actions.append(action)

        day_name = DAY_NAMES[target_day]
        lines = [f"Scheduled cold restart: {day_name} {target_hour:02d}:{target_minute:02d}"]
        lines += [_countdown_line(mode, s) for mode, s in active.items()]
        if not active:
            lines.append("2FA approval (IB Key) will be required. Have your phone ready.")
        return [
            Alert(
                event_type=self.event_type,
                title=f"ibctl: cold restart in {seconds_until}s",
                body="\n".join(lines),
                priority="urgent",
                tags="rotating_light,alarm_clock",
                actions=actions or None,
            )
        ]

    # ------------------------------------------------------------------
    # 2. Outcomes
    # ------------------------------------------------------------------

    def _check_outcomes(self, ns) -> list[Alert]:
        alerts: list[Alert] = []
        channel = getattr(ns.config, "channel", "")
        for mode, status in self._statuses.items():
            rec = status.get("last_cold_restart_outcome") or None
            key = f"{rec.get('recorded_at')}|{rec.get('outcome')}" if rec else None
            if mode not in self._outcome_seen:
                self._outcome_seen[mode] = key  # baseline: not news
                continue
            if key is None or key == self._outcome_seen[mode]:
                continue
            self._outcome_seen[mode] = key
            alert = self._outcome_alert(mode, rec, status, channel, ns)
            if alert is not None:
                alerts.append(alert)
        return alerts

    def _outcome_alert(self, mode: str, rec: dict, status: dict, channel: str, ns) -> Alert | None:
        m = mode.upper()
        outcome = rec.get("outcome")

        if outcome == "already_satisfied":
            # Nothing will leave Connected for this mode — stop watching.
            self._awaiting_disconnect.pop(mode, None)
            if not ns.is_event_enabled(self.skipped_event_type):
                return None
            when = _format_time_12h(rec.get("last_login_at", ""))
            return Alert(
                event_type=self.skipped_event_type,
                title=f"ibctl: {m} cold restart not needed",
                body=f"Already satisfied by a full re-auth at {when} today. No action needed for {m} this cycle.",
                priority="default",
                tags="information_source",
            )

        if outcome == "completed":
            self._awaiting_disconnect.pop(mode, None)
            self._awaiting_success.pop(mode, None)
            if not ns.is_event_enabled(self.success_event_type):
                return None
            when = _format_time_12h(rec.get("completed_at", ""))
            return Alert(
                event_type=self.success_event_type,
                title=f"ibctl: {m} Sunday re-authentication completed",
                body=f"{m} re-authenticated at {when} and is connected.",
                priority="default",
                tags="white_check_mark",
            )

        if outcome == "restarted":
            # Plain restart (possibly an owed one, long after the countdown):
            # watch for it to leave Connected and come back.
            self._awaiting_disconnect.setdefault(mode, time.time())
            return None

        if outcome in _IDLE or outcome is None:
            return None

        if not ns.is_event_enabled(self.outcome_event_type):
            return None

        if outcome == "restarted_by_boot":
            # The gateway started after the scheduled
            # time (host maintenance restarted it). The restart counts; the
            # login is owed until it succeeds.
            action = retry_login_action(mode, channel) if _parked(status) else None
            tail = (
                "It is parked waiting for you: tap Retry login, then approve the IB Key prompt."
                if action or _parked(status)
                else "Approve the IB Key prompt when it arrives; if it parks you'll get Retry login."
            )
            return Alert(
                event_type=self.outcome_event_type,
                title=f"ibctl: {m} restarted — Sunday login still owed",
                body=(
                    f"{m}'s gateway started after the scheduled time, so that restart counts "
                    "as this week's — ibctl will not restart it again. Its login is owed until "
                    f"it succeeds. {tail}"
                ),
                priority="high",
                tags="key",
                actions=[action] if action else None,
            )
        if outcome == "resumed_login":
            return Alert(
                event_type=self.outcome_event_type,
                title=f"ibctl: {m} — approve the IB Key prompt",
                body=(
                    f"{m} was waiting for 2FA; ibctl re-submitted its login in the running "
                    "gateway (no restart). Approve the IB Key prompt on your phone now. If it "
                    "times out, you'll get a fresh Retry login alert."
                ),
                priority="high",
                tags="key",
            )
        if outcome == "challenge_pending" and _parked(status):
            action = retry_login_action(mode, channel)
            return Alert(
                event_type=self.outcome_event_type,
                title=f"ibctl: {m} — IB Key prompt still on screen",
                body=(
                    f"{m} is waiting for 2FA and {_OPEN_PROMPT} {_open_prompt_next_step(status)} "
                    "Then approve the new IB Key prompt."
                ),
                priority="high",
                tags="key",
                actions=[action] if action else None,
            )
        if outcome == "challenge_pending":
            return Alert(
                event_type=self.outcome_event_type,
                title=f"ibctl: {m} — IB Key prompt waiting",
                body=(
                    f"An IB Key prompt for {m} is waiting — approve it on your phone. "
                    "The Sunday re-authentication completes when it's approved."
                ),
                priority="high",
                tags="key",
            )
        if outcome == "awaiting_operator":
            action = retry_login_action(mode, channel)
            return Alert(
                event_type=self.outcome_event_type,
                title=f"ibctl: {m} needs Retry login",
                body=(
                    f"{m} is waiting for 2FA and automatic resume is off. "
                    "Tap Retry login, then approve the IB Key prompt."
                ),
                priority="high",
                tags="key",
                actions=[action] if action else None,
            )
        if outcome == "deferred":
            return Alert(
                event_type=self.outcome_event_type,
                title=f"ibctl: {m} login already in progress",
                body=(
                    f"{m} was already logging in at the scheduled time ({rec.get('state', '?')}), "
                    "so there was no second restart. ibctl will confirm when the "
                    "re-authentication completes; approve the IB Key prompt if asked."
                ),
                priority="default",
                tags="hourglass_flowing_sand",
            )
        if outcome == "failed":
            return Alert(
                event_type=self.outcome_event_type,
                title=f"ibctl: {m} Sunday re-authentication could not run",
                body=(
                    f"{m} is in Error: {rec.get('detail') or 'no detail'}. "
                    "The re-login could not start. ibctl's own recovery continues — "
                    "open the dashboard to check it."
                ),
                priority="urgent",
                tags="rotating_light",
            )
        logger.warning("%s: unrecognized cold-restart outcome %r — not announced", mode, outcome)
        return None

    # ------------------------------------------------------------------
    # 3. Plain-restart success
    # ------------------------------------------------------------------

    def _check_success(self, ns) -> list[Alert]:
        if not self._awaiting_disconnect and not self._awaiting_success:
            return []

        now = time.time()
        alerts: list[Alert] = []

        for mode, status in self._statuses.items():
            started = self._awaiting_disconnect.get(mode)
            if started is None:
                continue
            tradeable = status.get("state") == "Connected" and status.get("ready", True)
            if now - started > AWAIT_SUCCESS_MAX_SECS:
                logger.info(
                    "%s: gave up waiting for the scheduled restart to actually begin "
                    "after %ds — it may never have left Connected",
                    mode,
                    AWAIT_SUCCESS_MAX_SECS,
                )
                del self._awaiting_disconnect[mode]
            elif not tradeable:
                # It left Connected — move to phase 2, keeping the ORIGINAL
                # timestamp so elapsed time measures from the warning.
                del self._awaiting_disconnect[mode]
                self._awaiting_success[mode] = started

        success_enabled = ns.is_event_enabled(self.success_event_type)
        for mode, status in self._statuses.items():
            started = self._awaiting_success.get(mode)
            if started is None:
                continue
            if now - started > AWAIT_SUCCESS_MAX_SECS:
                logger.info(
                    "%s: gave up watching for cold-restart reconnection after %ds — "
                    "session_lost/hitl_2fa remain the backstop for a genuinely stuck restart",
                    mode,
                    AWAIT_SUCCESS_MAX_SECS,
                )
                del self._awaiting_success[mode]
                continue
            if status.get("state") != "Connected" or not status.get("ready", True):
                continue
            elapsed = now - started
            del self._awaiting_success[mode]
            logger.info("%s: cold restart reconnected after %ds", mode, int(elapsed))
            if success_enabled:
                alerts.append(
                    Alert(
                        event_type=self.success_event_type,
                        title=f"ibctl: {mode.upper()} Sunday cold restart succeeded",
                        body=(
                            f"{mode.upper()} re-authenticated and reconnected "
                            f"{int(elapsed // 60)}m {int(elapsed % 60)}s after the scheduled restart."
                        ),
                        priority="default",
                        tags="white_check_mark",
                    )
                )
        return alerts
