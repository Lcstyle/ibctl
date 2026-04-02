"""Status API endpoint — primary integration point for external clients.

Reads from the InstanceRegistry's in-memory cache (populated by the SSE
background task every 2s). Never opens TCP connections to ibctl directly.
TCP fallback only during the first few seconds after startup when the
cache hasn't been populated yet.
"""

from __future__ import annotations

import logging
from dataclasses import asdict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.domain.errors import DashboardError
from app.domain.models import GatewayStatus

logger = logging.getLogger("dashboard.api.status")
router = APIRouter()


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


@router.get("/api/v1/health")
async def health():
    """Simple health check — always returns 200 if dashboard is running."""
    return {"status": "ok"}
