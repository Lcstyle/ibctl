"""Debug endpoints — gated behind IBCTL_DEBUG_MODE.

These are stubs for v2 introspection features:
- Force state transitions
- Raw agent commands
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("dashboard.api.debug")
router = APIRouter()


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
