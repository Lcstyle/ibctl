"""Logs API endpoint."""

from __future__ import annotations

import logging
from dataclasses import asdict

from fastapi import APIRouter, Request

from app.domain.errors import DashboardError

logger = logging.getLogger("dashboard.api.logs")
router = APIRouter()


@router.get("/api/v1/logs")
async def get_logs(request: Request, level: str | None = None, limit: int = 100):
    """Get recent log lines, optionally filtered by level."""
    client = request.app.state.ibctl_client
    try:
        entries = await client.logs(limit=limit)
        if level:
            entries = [e for e in entries if e.level.upper() == level.upper()]
        return {"logs": [asdict(e) for e in entries]}
    except DashboardError as e:
        return {"logs": [], "error": e.message}


@router.get("/api/v1/state")
async def get_state(request: Request):
    """Get state machine current state and transition history."""
    client = request.app.state.ibctl_client
    try:
        state = await client.state()
        return asdict(state)
    except DashboardError as e:
        return {"current": "unreachable", "history": [], "error": e.message}


@router.get("/api/v1/config")
async def get_config(request: Request):
    """Get running configuration (passwords masked)."""
    client = request.app.state.ibctl_client
    try:
        return await client.config()
    except DashboardError as e:
        return {"error": e.message}


@router.get("/api/v1/windows")
async def get_windows(request: Request):
    """Get current Gateway windows and client tabs."""
    client = request.app.state.ibctl_client
    try:
        return await client.windows()
    except DashboardError as e:
        return {"windows": [], "error": e.message}
