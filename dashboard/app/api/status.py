"""Status API endpoint — primary integration point for external clients."""

from __future__ import annotations

import logging
from dataclasses import asdict

from fastapi import APIRouter, Request

from app.domain.errors import DashboardError

logger = logging.getLogger("dashboard.api.status")
router = APIRouter()


@router.get("/api/v1/status")
async def get_status(request: Request, mode: str | None = None):
    """Full gateway status with client advisory.

    This is the primary endpoint for API clients to determine
    whether the gateway is ready for connections.
    Pass ?mode=paper or ?mode=live to query a specific instance.
    """
    registry = request.app.state.instance_registry
    target_mode = mode or registry.primary_mode()
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

    Used by the State page dial which needs all fields (paused,
    ceiling_state, jvm.alive, socat.running, etc.) without the
    lossy GatewayStatus model in between.
    """
    registry = request.app.state.instance_registry
    target_mode = mode or registry.primary_mode()
    client = registry.get_client(target_mode)
    try:
        return await client.status_raw()
    except DashboardError as e:
        return {"state": "unreachable", "error": e.message, "paused": False, "ceiling_state": None}


@router.get("/api/v1/health")
async def health():
    """Simple health check — always returns 200 if dashboard is running."""
    return {"status": "ok"}
