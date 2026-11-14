"""The weekly Gateway version check and its saved result.

Once a week (Saturday 12:00 ET by default, with a missed run caught up on
start) the check reads IB's current stable and latest builds and probes one
logged-in Gateway for a desupport notice. The result is saved on the persist
volume so it survives restarts and the alerts can be evaluated daily without
another connection.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field, replace
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Awaitable, Callable
from zoneinfo import ZoneInfo

from app.services.gateway_version.desupport import DesupportNotice
from app.services.gateway_version.probe import ProbeResult, notice_from, probe_client_ids
from app.services.gateway_version.releases import CHANNELS, ChannelRelease
from app.services.gateway_version.versions import GatewayVersion

logger = logging.getLogger("dashboard.services.gateway_version")

ET = ZoneInfo("America/New_York")
DEFAULT_STATE_PATH = Path(os.environ.get("IBCTL_PERSIST_DIR", "/opt/ibctl/persist")) / "gateway_version.json"
# How soon a check that got no answer is tried again.
RETRY_SPACING = timedelta(minutes=10)
# Probe order: paper first, so a LIVE connection is touched only when paper is down.
PROBE_PREFERENCE = ("paper", "live")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class WeeklySchedule:
    """A weekly slot in Eastern wall-clock time; ``weekday`` is Monday=0 .. Sunday=6.

    "Which Saturday" is calendar arithmetic on dates; the slot becomes an
    instant once, through the zone, and is compared in UTC. A slot inside the
    hour DST skips or repeats (01:00-02:59) is refused: on those Sundays it
    would not exist, or would exist twice.
    """

    weekday: int = 5
    hour: int = 12
    minute: int = 0

    def __post_init__(self):
        if not (0 <= self.weekday <= 6 and 0 <= self.hour <= 23 and 0 <= self.minute <= 59):
            raise ValueError(f"not a weekly slot: weekday={self.weekday} {self.hour:02d}:{self.minute:02d}")
        if 1 <= self.hour <= 2:
            raise ValueError(
                f"{self.hour:02d}:{self.minute:02d} ET falls in the hour DST skips or repeats; pick another time"
            )

    def _instant(self, day: date) -> datetime:
        return datetime.combine(day, time(self.hour, self.minute), tzinfo=ET).astimezone(timezone.utc)

    def last_slot(self, now: datetime) -> datetime:
        """The most recent slot at or before ``now``, as a UTC instant."""
        today = now.astimezone(ET).date()
        day = today - timedelta(days=(today.weekday() - self.weekday) % 7)
        slot = self._instant(day)
        return slot if slot <= now else self._instant(day - timedelta(days=7))

    def due(self, last_check: datetime | None, now: datetime) -> bool:
        return last_check is None or last_check < self.last_slot(now)


@dataclass
class VersionState:
    running: str | None = None
    channel: str = "stable"
    checked_at: datetime | None = None
    releases: dict[str, ChannelRelease] = field(default_factory=dict)
    release_errors: dict[str, str] = field(default_factory=dict)
    probed_mode: str | None = None
    probe_error: str | None = None
    notice: DesupportNotice | None = None
    notice_first_seen: datetime | None = None
    # The last time a probe got an answer from IB. Only a site with one sends
    # version alerts, so the standby's dashboard never duplicates them.
    last_probe_at: datetime | None = None
    # Which alerts have gone out, so a restart never repeats one.
    alerts: dict = field(default_factory=dict)
    # Every build seen on each channel, oldest first. IB's version files name
    # only the current build, and the upgrade soak needs older ones too.
    history: dict[str, list[ChannelRelease]] = field(default_factory=dict)
    # When the probe, and IB's release files, started failing in a row: the
    # version alerts go blind after a week of it. A probe skipped because no
    # Gateway is Connected neither starts nor clears this.
    probe_failing_since: datetime | None = None
    releases_failing_since: datetime | None = None

    def to_json(self) -> dict:
        return {
            "running": self.running,
            "channel": self.channel,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
            "releases": {
                c: {"version": str(r.version), "released_on": r.released_on.isoformat()}
                for c, r in self.releases.items()
            },
            "release_errors": self.release_errors,
            "probed_mode": self.probed_mode,
            "probe_error": self.probe_error,
            "notice": None if self.notice is None else {
                "running": str(self.notice.running),
                "cutoff": self.notice.cutoff.isoformat(),
                "minimum": str(self.notice.minimum),
            },
            "notice_first_seen": self.notice_first_seen.isoformat() if self.notice_first_seen else None,
            "last_probe_at": self.last_probe_at.isoformat() if self.last_probe_at else None,
            "alerts": self.alerts,
            "history": {
                c: [{"version": str(r.version), "released_on": r.released_on.isoformat()} for r in rs]
                for c, rs in self.history.items()
            },
            "probe_failing_since": self.probe_failing_since.isoformat() if self.probe_failing_since else None,
            "releases_failing_since": self.releases_failing_since.isoformat() if self.releases_failing_since else None,
        }

    @classmethod
    def from_json(cls, data: dict) -> VersionState:
        def when(value):
            """An instant must say which clock it is on; one that doesn't is
            refused rather than assumed to be UTC."""
            if not value:
                return None
            parsed = datetime.fromisoformat(value)
            if parsed.utcoffset() is None:
                raise ValueError(f"saved time {value!r} has no UTC offset")
            return parsed

        notice = data.get("notice")
        return cls(
            running=data.get("running"),
            channel=data.get("channel", "stable"),
            checked_at=when(data.get("checked_at")),
            releases={
                c: ChannelRelease(c, GatewayVersion.parse(r["version"]), date.fromisoformat(r["released_on"]))
                for c, r in (data.get("releases") or {}).items()
            },
            release_errors=dict(data.get("release_errors") or {}),
            probed_mode=data.get("probed_mode"),
            probe_error=data.get("probe_error"),
            notice=None if not notice else DesupportNotice(
                running=GatewayVersion.parse(notice["running"]),
                cutoff=date.fromisoformat(notice["cutoff"]),
                minimum=GatewayVersion.parse(notice["minimum"]),
            ),
            notice_first_seen=when(data.get("notice_first_seen")),
            last_probe_at=when(data.get("last_probe_at")),
            alerts=dict(data.get("alerts") or {}),
            history={
                c: [ChannelRelease(c, GatewayVersion.parse(r["version"]), date.fromisoformat(r["released_on"])) for r in rs]
                for c, rs in (data.get("history") or {}).items()
            },
            probe_failing_since=when(data.get("probe_failing_since")),
            releases_failing_since=when(data.get("releases_failing_since")),
        )


# Builds remembered per channel. A dozen covers months of the stable channel
# and weeks of latest, well past any soak.
HISTORY_KEEP = 12


def _with_new_builds(history: dict[str, list[ChannelRelease]], releases: dict[str, ChannelRelease]) -> dict:
    """``history`` plus any build in ``releases`` it hasn't seen, oldest first."""
    merged = {c: list(rs) for c, rs in history.items()}
    for channel, release in releases.items():
        seen = merged.setdefault(channel, [])
        if all(r.version != release.version for r in seen):
            seen.append(release)
            del seen[:-HISTORY_KEEP]
    return merged


def load_state(path: Path) -> VersionState:
    try:
        return VersionState.from_json(json.loads(path.read_text()))
    except FileNotFoundError:
        return VersionState()
    except (ValueError, KeyError, TypeError) as exc:
        logger.warning("Gateway version state %s is unreadable (%s); starting empty", path, exc)
        return VersionState()


def save_state(path: Path, state: VersionState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state.to_json(), indent=2))
    os.replace(tmp, path)


def choose_probe_mode(registry) -> str | None:
    """One Connected mode: one that already has API clients first, then paper
    before live. Probing a mode with no clients would flip the no-clients
    count from 0 to 1 and reset that monitor's timer."""
    candidates = []
    for inst in registry.cached_all_status():
        status = inst.status or {}
        if status.get("state") != "Connected":
            continue
        clients = (status.get("clients") or {}).get("count", 0)
        rank = PROBE_PREFERENCE.index(inst.mode) if inst.mode in PROBE_PREFERENCE else len(PROBE_PREFERENCE)
        candidates.append((clients == 0, rank, inst.mode))
    return min(candidates)[2] if candidates else None


class GatewayVersionService:
    def __init__(
        self,
        registry,
        *,
        fetch_release: Callable[[str], Awaitable[ChannelRelease]],
        probe_mode: Callable[[str, int], Awaitable[ProbeResult]],
        state_path: Path = DEFAULT_STATE_PATH,
        running_version: str | None = None,
        channel: str = "stable",
        schedule: WeeklySchedule = WeeklySchedule(),
        clock: Callable[[], datetime] = _utcnow,
    ):
        self._registry = registry
        self._fetch_release = fetch_release
        self._probe_mode = probe_mode
        self._state_path = state_path
        self._running_version = running_version
        self._channel = channel
        self.schedule = schedule
        self._clock = clock
        self._state = load_state(state_path)
        self._task: asyncio.Task | None = None

    def current(self) -> VersionState:
        return self._state

    def now(self) -> datetime:
        """The service's clock (UTC): alerts that depend on elapsed time read it."""
        return self._clock()

    def save(self) -> None:
        save_state(self._state_path, self._state)

    def due(self) -> bool:
        """A check is due when:

        - the weekly slot has passed since the last check;
        - the image runs a different version than the one last checked (an
          upgrade: ask IB now rather than on Saturday);
        - the last check got no answer and ``RETRY_SPACING`` has passed: a
          probe that found no logged-in Gateway is retried once a mode is
          Connected (the start-up check runs while both are still logging
          in), and a failed release-file read is retried.
        """
        state, now = self._state, self._clock()
        upgraded = (
            state.checked_at is not None
            and self._running_version is not None
            and state.running != self._running_version
        )
        if upgraded or self.schedule.due(state.checked_at, now):
            return True
        if now - state.checked_at < RETRY_SPACING:
            return False
        unanswered = state.last_probe_at is None or state.last_probe_at < state.checked_at
        if unanswered and choose_probe_mode(self._registry) is not None:
            return True
        return bool(state.release_errors)

    def next_check(self) -> datetime:
        return self.schedule.last_slot(self._clock()) + timedelta(days=7)

    def start_check(self) -> bool:
        """Start a check in the background unless one is running."""
        if self._task is not None and not self._task.done():
            return False
        self._task = asyncio.create_task(self._run_logged(), name="gateway-version-check")
        return True

    async def wait_for_check(self) -> None:
        if self._task is not None:
            await self._task

    async def _run_logged(self) -> None:
        try:
            await self.run_check()
        except Exception:
            logger.exception("Gateway version check failed")

    async def _probe(self, mode: str) -> ProbeResult:
        """Probe ``mode`` as the first reserved client ID IB accepts.

        Only IB can say whether an ID is in use right now: the Gateway keeps
        a client tab for every ID that has connected since it started, so
        STATUS's ID list means "has connected", not "is connected". A cleanly
        closed ID is free again at once, so every probe starts at the first
        ID and moves up only on IB's 326 refusal.
        """
        for client_id in probe_client_ids():
            result = await self._probe_mode(mode, client_id)
            if not result.client_id_in_use:
                break
            logger.info("Gateway version probe (%s): IB says client %d is in use", mode, client_id)
        return result

    async def run_check(self) -> VersionState:
        """Read IB's release files, probe one logged-in Gateway, then replace
        the saved result in one step, so the alert evaluation never sees a
        half-updated state."""
        now = self._clock()
        previous = self._state

        releases, errors = {}, {}
        for channel in CHANNELS:
            try:
                releases[channel] = await self._fetch_release(channel)
            except Exception as exc:
                errors[channel] = f"{type(exc).__name__}: {exc}"
                logger.warning("Could not read IB's %s release file: %s", channel, errors[channel])

        notice, first_seen, last_probe_at = previous.notice, previous.notice_first_seen, previous.last_probe_at
        probe_failing_since = previous.probe_failing_since
        mode = choose_probe_mode(self._registry)
        if mode is None:
            probe_error = "skipped: no mode is Connected"
        else:
            result = await self._probe(mode)
            probe_error = result.error
            if probe_error is None:
                last_probe_at = now
                try:
                    found = notice_from(result.messages)
                except ValueError as exc:
                    probe_error = f"IB sent a 2172 that no longer parses: {exc}"
                else:
                    if found is None:
                        notice, first_seen = None, None
                    elif found != previous.notice:
                        notice, first_seen = found, now
            probe_failing_since = (previous.probe_failing_since or now) if probe_error else None
        if probe_error:
            logger.warning("Gateway version probe (%s): %s", mode, probe_error)

        self._state = replace(
            previous,
            running=self._running_version,
            channel=self._channel,
            checked_at=now,
            releases=releases or previous.releases,
            history=_with_new_builds(previous.history, releases),
            release_errors=errors,
            probed_mode=mode,
            probe_error=probe_error,
            notice=notice,
            notice_first_seen=first_seen,
            last_probe_at=last_probe_at,
            probe_failing_since=probe_failing_since,
            releases_failing_since=(previous.releases_failing_since or now) if errors else None,
            alerts=self._state.alerts,
        )
        self.save()
        state = self._state
        logger.info(
            "Gateway version check: running %s, stable %s, latest %s, cutoff %s",
            state.running,
            state.releases.get("stable") and state.releases["stable"].version,
            state.releases.get("latest") and state.releases["latest"].version,
            state.notice and state.notice.cutoff,
        )
        return state
