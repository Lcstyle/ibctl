"""Status API endpoint — primary integration point for external clients.

Reads from the InstanceRegistry's in-memory cache (populated by the SSE
background task every 2s). Never opens TCP connections to ibctl directly.
TCP fallback only during the first few seconds after startup when the
cache hasn't been populated yet.
"""

from __future__ import annotations

import logging
import os
from dataclasses import asdict
from datetime import datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.domain.errors import DashboardError
from app.domain.models import GatewayStatus
from app.services.health_summary import build_health_summary
from app.services.monitors.session_lost import (
    SCHEDULE_CORRELATION_MINUTES,
    _scheduled_restart_grace_minutes,
)

logger = logging.getLogger("dashboard.api.status")
router = APIRouter()

_DAY_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]


@router.get("/api/v1/status")
async def get_status(request: Request, mode: str | None = None):
    """Full gateway status with client advisory.

    Reads from cache (populated by SSE background task). Falls back to
    TCP only if cache is empty (first few seconds after startup).
    """
    registry = request.app.state.instance_registry
    target_mode = mode or registry.primary_mode()

    # Cache-first: read from in-memory cache (no TCP)
    cached = registry.cached_status_raw(target_mode)
    if cached:
        status = GatewayStatus.from_json(cached)
        response_data = asdict(status)
        age = registry.cache_age(target_mode)
        headers = {}
        if age is not None:
            headers["X-Cache-Age"] = str(round(age, 1))
            if age > 10.0:
                response_data["_stale"] = True
        return JSONResponse(content=response_data, headers=headers)

    # Fallback: cache not yet populated (startup)
    client = registry.get_client(target_mode)
    try:
        status = await client.status()
        return asdict(status)
    except DashboardError as e:
        logger.warning("Failed to get status: %s", e.message)
        return {
            "ready": False,
            "state": "unreachable",
            "trading_mode": "unknown",
            "client_advisory": {
                "should_connect": False,
                "should_wait": True,
                "wait_reason": "ibctl_unreachable",
                "client_id_likely_stale": False,
            },
            "error": e.message,
        }


@router.get("/api/v1/status/raw")
async def get_status_raw(request: Request, mode: str | None = None):
    """Raw ibctl STATUS pass-through — no model translation.

    Reads from cache. Used by the State page dial and SSE-driven updates.
    """
    registry = request.app.state.instance_registry
    target_mode = mode or registry.primary_mode()

    # Cache-first
    cached = registry.cached_status_raw(target_mode)
    if cached:
        age = registry.cache_age(target_mode)
        if age is not None and age > 10.0:
            cached = {**cached, "_stale": True}
        return cached

    # Fallback: cache not yet populated
    client = registry.get_client(target_mode)
    try:
        return await client.status_raw()
    except DashboardError as e:
        return {"state": "unreachable", "error": e.message, "paused": False, "ceiling_state": None}


@router.api_route("/api/v1/schedule", methods=["GET", "HEAD"])
async def get_schedule():
    """ibctl's own scheduled-restart configuration, for external clients.

    Built for IBKR API consumers on the same host that have their own
    connection-lost alert, edge-triggered, with no concept of "this
    disconnect is scheduled and expected" — session_lost.py used
    to have exactly that gap. Rather than have every consumer duplicate
    ibctl's AUTO_RESTART_TIME/TWS_COLD_RESTART parsing (and risk each one
    getting the anchor-to-now-vs-anchor-to-outage-start bug session_lost.py
    itself shipped once already), ibctl exposes the raw configuration here
    and each client applies the same shape of correlation logic itself:
    "did MY disconnect begin within `correlation_minutes` of one of these
    clock times? If so, don't page until `grace_minutes` have passed."

    Deliberately raw, not pre-computed: no `currently_in_progress: bool`
    field. That would need to interpret "now" against a timezone this
    endpoint has no way to guarantee the caller shares, and it would race
    against the caller's own knowledge of when ITS disconnect actually
    started — which is the exact anchoring bug this design avoids. The
    times are absolute strings in a named timezone; correlation is the
    caller's job, against the caller's own observed outage start.
    """
    tz_name = os.environ.get("TZ", "").strip() or None
    if tz_name is None:
        try:
            tz_name = datetime.now().astimezone().tzname()
        except Exception:
            tz_name = None

    auto_restart_time = os.environ.get("AUTO_RESTART_TIME", "").strip() or None
    auto_restart_24h = None
    if auto_restart_time:
        try:
            parsed = datetime.strptime(auto_restart_time, "%I:%M %p")
            auto_restart_24h = f"{parsed.hour:02d}:{parsed.minute:02d}"
        except ValueError:
            logger.warning("AUTO_RESTART_TIME=%r does not parse as '%%I:%%M %%p'", auto_restart_time)

    cold_restart_time = os.environ.get("TWS_COLD_RESTART", "").strip() or None
    cold_restart_day_raw = os.environ.get("TWS_COLD_RESTART_DAY", "").strip()
    try:
        cold_restart_day = int(cold_restart_day_raw) if cold_restart_day_raw else 0
    except ValueError:
        cold_restart_day = 0
    cold_restart_day = cold_restart_day if 0 <= cold_restart_day <= 6 else 0

    return {
        "timezone": tz_name,
        "auto_restart": {
            "configured": auto_restart_time is not None,
            # As IBCTL_TIME reads it: "%I:%M %p", e.g. "05:05 PM".
            "time_12h": auto_restart_time,
            # Convenience form, HH:MM 24h — None if auto_restart_time didn't
            # parse (misconfigured on ibctl's side; still reported so a
            # client can log the discrepancy rather than silently ignore it).
            "time_24h": auto_restart_24h,
        },
        "cold_restart": {
            "configured": cold_restart_time is not None,
            # HH:MM 24h, matching TWS_COLD_RESTART's own format directly.
            "time_24h": cold_restart_time,
            # 0=Sunday .. 6=Saturday, matching TWS_COLD_RESTART_DAY's own convention.
            "day": cold_restart_day,
            "day_name": _DAY_NAMES[cold_restart_day],
        },
        # How ibctl's own session_lost.py decides correlation and grace —
        # shared so a client's replica of the algorithm actually matches.
        "correlation_minutes": SCHEDULE_CORRELATION_MINUTES,
        "grace_minutes": _scheduled_restart_grace_minutes(),
    }


@router.api_route("/api/v1/health", methods=["GET", "HEAD"])
async def health(request: Request):
    """Public health summary — 200 whenever the dashboard is running.

    Open to anyone, logged in or not, so it carries only the fixed whitelist
    in `build_health_summary`: per-mode state, API ready and since when, and
    the ibctl and Gateway versions. Never pass the raw STATUS payload through.
    """
    return build_health_summary(
        request.app.state.instance_registry,
        getattr(request.app.state, "gateway_version", None),
    )
