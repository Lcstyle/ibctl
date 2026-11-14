"""Is a Gateway upgrade due at the next Sunday window, and to which build?

A pure function of the policy, the saved version state and today's date. CI
reads it on Saturday to decide what to build, and the Sunday maintenance job
reads it again before swapping. Dates here are calendar labels in Eastern
time (the swap Sunday, IB's release and cutoff dates), never instants.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from app.services.gateway_version.policy import CADENCES, UpgradePolicy, cadence_allows
from app.services.gateway_version.releases import CHANNELS, ChannelRelease
from app.services.gateway_version.service import VersionState
from app.services.gateway_version.view import parse_or_none


@dataclass(frozen=True)
class Decision:
    due: bool
    swap_on: date
    target: str | None
    channel: str | None
    reason: str
    # True when IB's cutoff, not the cadence, is driving this decision.
    deadline: bool = False

    def to_json(self) -> dict:
        return {
            "due": self.due,
            "swap_on": self.swap_on.isoformat(),
            "target": self.target,
            "channel": self.channel,
            "reason": self.reason,
            "deadline": self.deadline,
        }


ET = ZoneInfo("America/New_York")


def today_et() -> date:
    """Today's date as the maintenance window reads it: Eastern."""
    return datetime.now(ET).date()


def next_sunday(today: date) -> date:
    """The maintenance Sunday this decision is for: today if it is Sunday."""
    return today + timedelta(days=(6 - today.weekday()) % 7)


def _known(state: VersionState, channel: str) -> list[ChannelRelease]:
    seen = list(state.history.get(channel, []))
    current = state.releases.get(channel)
    if current is not None and all(r.version != current.version for r in seen):
        seen.append(current)
    return seen


def decide(policy: UpgradePolicy, state: VersionState, today: date) -> Decision:
    sunday = next_sunday(today)

    def no(reason: str, deadline: bool = False) -> Decision:
        return Decision(False, sunday, None, None, reason, deadline)

    if not policy.enabled:
        return no("automatic upgrades are off")
    running = parse_or_none(state.running)
    if running is None:
        return no("the running version is unknown")

    notice = state.notice
    if notice is not None and not notice.met_by(running) and (notice.cutoff - sunday).days <= policy.deadline_days:
        channels = [policy.channel] + [c for c in CHANNELS if c != policy.channel]
        for channel in channels:
            qualifying = [r for r in _known(state, channel) if notice.met_by(r.version) and r.version > running]
            if qualifying:
                best = max(qualifying, key=lambda r: r.version)
                return Decision(
                    True, sunday, str(best.version), channel,
                    f"IB desupports {running} on {notice.cutoff.isoformat()}; "
                    f"{best.version} ({channel}) meets the minimum {notice.minimum}",
                    deadline=True,
                )
        return no(
            f"IB desupports {running} on {notice.cutoff.isoformat()}, but no build at or above "
            f"the minimum {notice.minimum} has been seen yet",
            deadline=True,
        )

    if not cadence_allows(policy.cadence, sunday):
        return no(f"{sunday.isoformat()} is not an upgrade Sunday ({CADENCES[policy.cadence]})")

    newer = [r for r in _known(state, policy.channel) if r.version > running]
    if not newer:
        return no(f"{running} is the newest {policy.channel} build")
    soaked = [r for r in newer if (sunday - r.released_on).days >= policy.soak_days]
    if not soaked:
        youngest = max(newer, key=lambda r: r.version)
        age = (sunday - youngest.released_on).days
        return no(
            f"{youngest.version} (released {youngest.released_on.isoformat()}) will have been out "
            f"{age} of {policy.soak_days} days on {sunday.isoformat()}"
        )
    best = max(soaked, key=lambda r: r.version)
    age = (sunday - best.released_on).days
    return Decision(
        True, sunday, str(best.version), policy.channel,
        f"{best.version} ({policy.channel}, released {best.released_on.isoformat()}) "
        f"will have been out {age} days on {sunday.isoformat()}",
    )
