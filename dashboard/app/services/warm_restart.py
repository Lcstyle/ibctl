"""Warm restart now: the dashboard's side of `WARMRESTART`.

`WARMRESTART` is the API's name for "warm restart this Gateway now". It takes a
mode and nothing else. The dashboard sends that ibctl a bare `SETRESTART`, which
ibctl reads as "restart as soon as the Gateway can, warm": it types the next
whole minute into the Gateway's auto-restart field, or the minute after when
fewer than two seconds of this one remain, and the Gateway restarts itself with
its saved session, so there is no 2FA. ibctl then re-applies the configured daily
time after the login.

This module owns the rules around that one command, whoever asks (a token or the
dashboard's own button):

- a per-mode minimum interval between accepted requests, saved with the other
  API-access state so a dashboard restart does not reset it;
- ibctl's own allow-list as the ceiling;
- an outcome read for token clients, who cannot read status or logs.

A request is logged, accepted or rejected, with who asked (the token's name, or
the signed-in person) and the address it came from.
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.domain.errors import DashboardError, IbctlCommandError
from app.services.api_access import ApiAccessError, ApiAccessStore
from app.services.ibctl_access import IbctlAccessReader

logger = logging.getLogger("dashboard.api_access")

IBCTL_COMMAND = "SETRESTART"  # bare: no time, ibctl picks the next minute
VALID_MODES = ("live", "paper")

# ibctl's own rule (gateway_zone::next_restart_minute): the next whole minute,
# or the one after when the current second is 58 or later.
_LAST_SECOND_FOR_NEXT_MINUTE = 57

# Allowance when comparing a time ibctl stamped with one the dashboard did, and
# how long after our request ibctl may take to type the time into the Gateway.
_SLACK_SECONDS = 2.0
_APPLY_WINDOW_SECONDS = 120.0
# How far ahead of the request the minute ibctl typed can be.
_MAX_LEAD_SECONDS = 180.0


def iso_utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def next_restart_minute(now: float) -> float:
    """The minute ibctl will type for a bare SETRESTART at `now`, as epoch seconds."""
    minute = math.floor(now / 60) * 60
    second = math.floor(now - minute)
    return minute + 60 * (1 if second <= _LAST_SECOND_FOR_NEXT_MINUTE else 2)


class WarmRestartRefused(Exception):
    """A request that was not carried out. `reason` is the API's error code."""

    def __init__(self, reason: str, detail: str, retry_after_s: int | None = None):
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail
        self.retry_after_s = retry_after_s


@dataclass(frozen=True)
class WarmRestartAccepted:
    mode: str
    scheduled_for: str


def _wait_text(seconds: int) -> str:
    return f"{seconds} s" if seconds < 60 else f"{math.ceil(seconds / 60)} min"


@dataclass(frozen=True)
class ButtonState:
    """What the dashboard's own Warm restart button should look like for one mode."""

    blocked_by_ibctl: bool = False
    allowlist_unread: bool = False
    retry_after_s: int = 0
    interval_minutes: int = 0
    state_unreadable: bool = False

    @property
    def disabled(self) -> bool:
        return self.blocked_by_ibctl or self.retry_after_s > 0 or self.state_unreadable

    @property
    def reason(self) -> str:
        """Why the button is greyed out; empty while it is usable."""
        if self.state_unreadable:
            return "The saved API access settings cannot be read, so the minimum interval is unknown."
        if self.blocked_by_ibctl:
            return f"Blocked by ibctl: its allowed commands (command_server.allowed_commands) do not include {IBCTL_COMMAND}."
        if self.retry_after_s > 0:
            return (
                f"Warm restarted recently: available again in {_wait_text(self.retry_after_s)} "
                f"(minimum interval {self.interval_minutes} min)."
            )
        return ""

    @property
    def hint(self) -> str:
        """A caveat on a usable button."""
        if self.allowlist_unread:
            return "ibctl's allow-list could not be read; ibctl decides when the command is sent."
        return ""


def log_rejected(actor: str, ip: str, mode: str | None, reason: str, detail: str = "") -> None:
    logger.warning(
        "Warm restart rejected: mode=%s by=%s ip=%s reason=%s%s",
        mode or "-", actor, ip, reason, f" ({detail})" if detail else "",
    )


# --- reading ibctl's STATUS back ---


def parse_instant(text) -> float | None:
    """Epoch seconds for an RFC 3339 time as ibctl prints it, with or without a `[zone]` suffix."""
    if not isinstance(text, str):
        return None
    try:
        moment = datetime.fromisoformat(text.split("[", 1)[0])
    except ValueError:
        return None
    return None if moment.tzinfo is None else moment.timestamp()


def clock_time_to_instant(clock_time, zone_name, near: float) -> float | None:
    """The instant ibctl meant by `clock_time` ("9:41 PM") in the Gateway's zone, near `near`.

    ibctl records only the clock time it typed. The one that belongs to a
    request made at `near` is the one that falls a minute or two after it;
    anything else is not this request, and gives None.
    """
    if not isinstance(clock_time, str) or not isinstance(zone_name, str):
        return None
    try:
        zone = ZoneInfo(zone_name)
        typed = datetime.strptime(clock_time.strip(), "%I:%M %p")
    except (ZoneInfoNotFoundError, ValueError):
        return None
    today = datetime.fromtimestamp(near, zone).date()
    matches = []
    for days in (-1, 0, 1):
        day = today + timedelta(days=days)
        moment = datetime(day.year, day.month, day.day, typed.hour, typed.minute, tzinfo=zone).timestamp()
        if 0 < moment - near <= _MAX_LEAD_SECONDS:
            matches.append(moment)
    return matches[0] if len(matches) == 1 else None


def _section(status: dict, key: str) -> dict:
    value = status.get(key)
    return value if isinstance(value, dict) else {}


def observe(record: dict, status: dict) -> dict:
    """What ibctl's STATUS now says about the request in `record`, added to what was seen before.

    What was seen is never overwritten: ibctl keeps one `last_setrestart` and one
    `last_jvm_exit`, and both are replaced by later events (the daily time it
    sets after the relaunch, a crash a day later), so an outcome read late
    would otherwise describe the wrong event.

    - `applied`, and the minute ibctl typed (`scheduled_for`): STATUS
      `last_setrestart`, when it is the record of a bare SETRESTART (`source`
      "now") made within a short window after this request. The typed clock
      time is read in STATUS `gateway_time_zone.effective`.
    - `warm`: STATUS `last_jvm_exit.warm`, for the first Gateway exit ibctl
      noticed at or after the minute the restart was set for, and only if ibctl
      did apply the time. `warm` is true when a saved session was found.
    - `relaunched_at`: STATUS `sunday_reauth.jvm_launched_at`, the moment the
      running JVM was launched (now minus its uptime), once that is after the
      exit above.
    """
    seen = dict(record.get("observed") or {})
    accepted = record["accepted_at"]

    setrestart = status.get("last_setrestart")
    if isinstance(setrestart, dict) and setrestart.get("source") == "now" and "applied" not in seen:
        at = parse_instant(setrestart.get("at"))
        if at is not None and accepted - _SLACK_SECONDS <= at <= accepted + _APPLY_WINDOW_SECONDS:
            seen["applied"] = bool(setrestart.get("applied"))
            zone = _section(status, "gateway_time_zone").get("effective")
            typed = clock_time_to_instant(setrestart.get("requested"), zone, accepted)
            if typed is not None:
                seen["scheduled_for"] = iso_utc(typed)

    due = parse_instant(seen.get("scheduled_for") or record.get("scheduled_for"))
    exit_record = status.get("last_jvm_exit")
    if isinstance(exit_record, dict) and "warm" not in seen and seen.get("applied") is not False and due is not None:
        exited = parse_instant(exit_record.get("at"))
        if exited is not None and exited >= due - _SLACK_SECONDS:
            seen["warm"] = bool(exit_record.get("warm"))
            seen["exit_at"] = iso_utc(exited)

    if "warm" in seen and "relaunched_at" not in seen:
        launched = parse_instant(_section(status, "sunday_reauth").get("jvm_launched_at"))
        exited = parse_instant(seen.get("exit_at"))
        if launched is not None and exited is not None and launched >= exited - _SLACK_SECONDS:
            seen["relaunched_at"] = iso_utc(launched)
    return seen


class WarmRestartService:
    def __init__(self, store: ApiAccessStore, registry, clock=time.time, access: IbctlAccessReader | None = None):
        self._store = store
        self._registry = registry
        self._clock = clock
        self._access = access or IbctlAccessReader(registry, clock=clock)

    def check_mode(self, mode) -> str:
        """The mode, if it is `live` or `paper` and this dashboard runs it."""
        if not isinstance(mode, str) or mode not in VALID_MODES:
            raise WarmRestartRefused("invalid_request", 'mode must be "live" or "paper"')
        if mode not in self._registry.modes():
            raise WarmRestartRefused("invalid_request", f"This dashboard does not run a {mode} instance.")
        return mode

    def _retry_after(self, mode: str, now: float) -> int:
        record = self._store.warm_restart_record(mode)
        if not record or not isinstance(record.get("accepted_at"), (int, float)):
            return 0
        interval = self._store.min_interval_minutes(mode) * 60
        elapsed = max(now - record["accepted_at"], 0)  # a clock that stepped back waits the full interval
        return 0 if elapsed >= interval else math.ceil(interval - elapsed)

    async def button_state(self, mode: str) -> ButtonState:
        """The button's state for `mode`: blocked by ibctl, rate limited, neither."""
        access = await self._access.read(mode)
        verdict = access.blocks(IBCTL_COMMAND)
        try:
            retry_after_s = self._retry_after(mode, self._clock())
            interval_minutes = self._store.min_interval_minutes(mode)
        except ApiAccessError:
            return ButtonState(blocked_by_ibctl=verdict is True, allowlist_unread=verdict is None, state_unreadable=True)
        return ButtonState(
            blocked_by_ibctl=verdict is True,
            allowlist_unread=verdict is None,
            retry_after_s=retry_after_s,
            interval_minutes=interval_minutes,
        )

    async def request(self, mode: str, *, actor: str, ip: str) -> WarmRestartAccepted:
        """Warm restart `mode` now, or raise `WarmRestartRefused` (already logged)."""
        try:
            return await self._request(mode, actor, ip)
        except WarmRestartRefused as refusal:
            log_rejected(actor, ip, mode, refusal.reason, refusal.detail)
            raise

    async def _request(self, mode: str, actor: str, ip: str) -> WarmRestartAccepted:
        self.check_mode(mode)
        access = await self._access.read(mode, fresh=True)
        if access.blocks(IBCTL_COMMAND) is True:
            raise self._blocked(mode)

        # Check the interval and take the slot with no await between them, so
        # two requests at once cannot both pass. A failed send gives it back.
        now = self._clock()
        wait = self._retry_after(mode, now)
        if wait:
            raise WarmRestartRefused(
                "rate_limited",
                f"the {mode} Gateway was warm restarted less than {self._store.min_interval_minutes(mode)} minutes ago",
                retry_after_s=wait,
            )
        previous = self._store.warm_restart_record(mode)
        scheduled_for = iso_utc(next_restart_minute(now))
        self._store.save_warm_restart_record(
            mode, {"accepted_at": now, "accepted_by": actor, "scheduled_for": scheduled_for, "observed": {}}
        )
        try:
            await self._registry.get_client(mode).send_command(IBCTL_COMMAND)
        except IbctlCommandError as exc:
            self._store.save_warm_restart_record(mode, previous)
            if "not allowed by command_server.allowed_commands" in exc.error:
                raise self._blocked(mode) from exc
            raise WarmRestartRefused("ibctl_refused", f"ibctl refused SETRESTART: {exc.error}") from exc
        except DashboardError as exc:
            self._store.save_warm_restart_record(mode, previous)
            raise WarmRestartRefused("ibctl_unavailable", exc.message) from exc
        except BaseException:
            self._store.save_warm_restart_record(mode, previous)
            raise
        self._registry.invalidate(mode)
        logger.info(
            "Warm restart accepted: mode=%s by=%s ip=%s scheduled_for=%s", mode, actor, ip, scheduled_for
        )
        return WarmRestartAccepted(mode, scheduled_for)

    @staticmethod
    def _blocked(mode: str) -> WarmRestartRefused:
        return WarmRestartRefused(
            "blocked_by_ibctl",
            f"{mode.upper()}'s ibctl does not allow {IBCTL_COMMAND} (command_server.allowed_commands)",
        )

    async def outcome(self, mode: str) -> dict:
        """The last accepted warm restart of `mode` and what became of it.

        - `requested_at`: when the dashboard accepted the request (its saved record).
        - `scheduled_for`: the minute ibctl typed, when STATUS still showed it;
          otherwise the dashboard's own computation, by ibctl's rule, from the
          moment it accepted the request.
        - `applied`, `warm`, `relaunched_at`: see `observe`. Null until ibctl's
          STATUS has shown them.
        """
        self.check_mode(mode)
        record = self._store.warm_restart_record(mode)
        if record is None or not isinstance(record.get("accepted_at"), (int, float)):
            return {"requested_at": None, "scheduled_for": None, "applied": None, "relaunched_at": None, "warm": None}
        try:
            status = await self._registry.get_client(mode).status_raw()
        except DashboardError as exc:
            raise WarmRestartRefused("ibctl_unavailable", exc.message) from exc
        seen = observe(record, status if isinstance(status, dict) else {})
        current = self._store.warm_restart_record(mode)  # a new request may have replaced it while we waited
        if seen != (record.get("observed") or {}) and current and current.get("accepted_at") == record["accepted_at"]:
            self._store.save_warm_restart_record(mode, {**current, "observed": seen})
        return {
            "requested_at": iso_utc(record["accepted_at"]),
            "scheduled_for": seen.get("scheduled_for") or record.get("scheduled_for"),
            "applied": seen.get("applied"),
            "relaunched_at": seen.get("relaunched_at"),
            "warm": seen.get("warm"),
        }
