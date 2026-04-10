"""Debug endpoints — gated behind IBCTL_DEBUG_MODE.

Includes pre-flight config validation and stubs for v2 introspection features.
"""

from __future__ import annotations

import logging
from dataclasses import asdict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("dashboard.api.debug")
router = APIRouter()


@router.get("/api/v1/debug/preflight")
async def preflight_check(request: Request):
    """Run pre-flight config validation and return results."""
    if not request.app.state.debug_mode:
        return JSONResponse(status_code=403, content={"error": "debug mode not enabled"})

    from app.preflight.validator import validate_config

    result = validate_config()
    return JSONResponse(
        content={
            "ok": result.ok,
            "errors": [asdict(e) for e in result.errors],
            "warnings": result.warnings,
        }
    )


@router.post("/api/v1/debug/state")
async def force_state(request: Request):
    """Force a state machine transition (debug only)."""
    if not request.app.state.debug_mode:
        return JSONResponse(status_code=403, content={"error": "debug mode not enabled"})
    return JSONResponse(status_code=501, content={"error": "not yet implemented"})


@router.post("/api/v1/debug/agent")
async def raw_agent_command(request: Request):
    """Send a raw command to the Java agent (debug only)."""
    if not request.app.state.debug_mode:
        return JSONResponse(status_code=403, content={"error": "debug mode not enabled"})
    return JSONResponse(status_code=501, content={"error": "not yet implemented"})
