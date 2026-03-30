"""Command API endpoint — send commands to ibctl."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.domain.errors import DashboardError

logger = logging.getLogger("dashboard.api.command")
router = APIRouter()

ALLOWED_COMMANDS = {"STOP", "RESTART", "RECONNECTDATA", "RECONNECTACCOUNT", "ENABLEAPI"}


class CommandRequest(BaseModel):
    command: str


@router.post("/api/v1/command")
async def send_command(request: Request, body: CommandRequest):
    """Send a command to ibctl (STOP, RESTART, etc.)."""
    command = body.command.upper().strip()

    if command not in ALLOWED_COMMANDS:
        return {"ok": False, "error": f"Unknown command: {command}"}

    client = request.app.state.ibctl_client
    try:
        result = await client.send_command(command)
        logger.info("Command '%s' executed: %s", command, result)
        return {"ok": True, "command": command, "result": result}
    except DashboardError as e:
        logger.error("Command '%s' failed: %s", command, e.message)
        return {"ok": False, "command": command, "error": e.message}
