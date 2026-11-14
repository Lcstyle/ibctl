"""One view of the Gateway version, for the JSON endpoint and the overview card,
so the two can never disagree."""

from __future__ import annotations

from datetime import date, datetime
from zoneinfo import ZoneInfo

from app.services.gateway_version.service import VersionState
from app.services.gateway_version.versions import GatewayVersion

# status -> the section health stripe the overview already uses.
HEALTH = {
    "below_minimum": "error",
    "upgraded_pending_confirmation": "warning",
    "behind": "warning",
    "unknown": "warning",
    "current": "ok",
}


STATUS_LABEL = {
    "below_minimum": "below IB's upcoming minimum",
    "upgraded_pending_confirmation": "upgraded, waiting for IB to confirm",
    "behind": "newer build available",
    "unknown": "not checked yet",
    "current": "current",
}

ET = ZoneInfo("America/New_York")


def et_display(value: datetime | None) -> str | None:
    """An instant as the operator reads it: Eastern wall-clock time."""
    return value.astimezone(ET).strftime("%a %b %-d %H:%M %Z") if value else None


def parse_or_none(text: str | None) -> GatewayVersion | None:
    try:
        return GatewayVersion.parse(text) if text else None
    except ValueError:
        return None


def status_of(state: VersionState, running: GatewayVersion | None) -> str:
    if state.checked_at is None or running is None:
        return "unknown"
    if state.notice is not None:
        return "upgraded_pending_confirmation" if state.notice.met_by(running) else "below_minimum"
    release = state.releases.get(state.channel)
    if release is not None and release.version > running:
        return "behind"
    return "current"


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def version_view(state: VersionState, today: date, next_check: datetime | None = None) -> dict:
    running = parse_or_none(state.running)
    status = status_of(state, running)
    notice = state.notice
    return {
        "status": status,
        "status_label": STATUS_LABEL[status],
        "health": HEALTH[status],
        "running": state.running,
        "channel": state.channel,
        "available": {c: str(r.version) for c, r in state.releases.items()},
        "released_on": {c: r.released_on.isoformat() for c, r in state.releases.items()},
        "notice": None if notice is None else {
            "running": str(notice.running),
            "cutoff": notice.cutoff.isoformat(),
            "minimum": str(notice.minimum),
            "first_seen": _iso(state.notice_first_seen),
        },
        "days_left": notice.days_left(today) if notice else None,
        "checked_at": _iso(state.checked_at),
        "next_check": _iso(next_check),
        "probed_mode": state.probed_mode,
        "probe_error": state.probe_error,
        "release_errors": state.release_errors,
    }
