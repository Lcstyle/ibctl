"""The health summary anonymous visitors may see.

Built field by field from a fixed whitelist: per-mode state, whether the API is
ready and since when, the ibctl version, and the Gateway version. Nothing from
the STATUS payload is passed through, so a field added to STATUS later (an
account id, a user name) stays out of the public view until someone adds it
here on purpose. Text fields must also look like what they claim to be, so a
stray value in one of them cannot carry anything else out.

`GET /api/v1/health` and the anonymous `/` page both render this one dict.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# ibctl state names: "Connected", "WaitingForHitl2fa", ...
_STATE = re.compile(r"[A-Za-z][A-Za-z0-9_ -]{0,39}")
# Version strings: "1.3.0", "0.1.0-test", "10.50.1f".
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,31}")


def _text(value: Any, pattern: re.Pattern[str]) -> str | None:
    return value if isinstance(value, str) and pattern.fullmatch(value) else None


def _seconds(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return float(value)


def _mode_entry(instance, cache_age: float | None, now: datetime) -> dict:
    status = instance.status if isinstance(instance.status, dict) else {}
    api_ready = status.get("ready") is True
    since = None
    connected_for = _seconds(status.get("connected_uptime_secs"))
    if api_ready and connected_for is not None:
        # The uptime was true when the status was cached, not now.
        began = now - timedelta(seconds=connected_for + (cache_age or 0.0))
        since = began.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "mode": instance.mode,
        "state": _text(status.get("state"), _STATE) or "unknown",
        "api_ready": api_ready,
        "since": since,
        "ibctl_version": _text(status.get("version"), _VERSION),
    }


def build_health_summary(registry, gateway_version=None, now: datetime | None = None) -> dict:
    """The whole public view: `{"status", "modes": [...], "gateway_version"}`.

    `registry` is the InstanceRegistry (its cached statuses are read; no
    connection is opened). `gateway_version` is the Gateway version service,
    or None when it is not running.
    """
    now = now or datetime.fromtimestamp(time.time(), tz=timezone.utc)
    modes = [
        _mode_entry(instance, registry.cache_age(instance.mode), now)
        for instance in registry.cached_all_status()
    ]
    running = gateway_version.current().running if gateway_version is not None else None
    return {
        "status": "ok",
        "modes": modes,
        "gateway_version": _text(running, _VERSION),
    }


def display_zone() -> str | None:
    """The container's time zone (`TZ`) when it names a real zone, else None (show UTC)."""
    name = os.environ.get("TZ", "").strip()
    if not name:
        return None
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return None
    return name


def local_time(instant: str | None, zone: str | None) -> str | None:
    """Show an RFC 3339 UTC instant on the clock of `zone`, for people to read.

    Display only: the API keeps the UTC instant. With no usable zone the time
    is shown in UTC, labelled as such. Anything that is not a timestamp gives None.
    """
    if not isinstance(instant, str):
        return None
    try:
        moment = datetime.strptime(instant, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    try:
        tz = ZoneInfo(zone) if zone else timezone.utc
    except (ZoneInfoNotFoundError, ValueError):
        tz = timezone.utc
    return moment.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S %Z")
