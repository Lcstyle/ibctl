"""Command API endpoint — send commands to ibctl instances."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.domain.errors import DashboardError

logger = logging.getLogger("dashboard.api.command")
router = APIRouter()

ALLOWED_COMMANDS = {"STOP", "RESTART", "RECONNECTDATA", "RECONNECTACCOUNT", "ENABLEAPI", "PAUSE", "RESUME"}
# SETSTATE is handled specially (has an argument)
SETSTATE_PREFIX = "SETSTATE "


class CommandRequest(BaseModel):
    command: str
    mode: str | None = None  # Target instance: "live", "paper", or None (primary)


@router.post("/api/v1/command")
async def send_command(request: Request, body: CommandRequest):
    """Send a command to a specific ibctl instance."""
    command = body.command.upper().strip()

    is_setstate = command.startswith(SETSTATE_PREFIX)
    if command not in ALLOWED_COMMANDS and not is_setstate:
        return {"ok": False, "error": f"Unknown command: {command}"}

    registry = request.app.state.instance_registry
    target_mode = body.mode or registry.primary_mode()

    try:
        client = registry.get_client(target_mode)
    except KeyError:
        return {"ok": False, "error": f"Unknown instance: {target_mode}"}

    try:
        result = await client.send_command(command)
        logger.info("Command '%s' sent to %s: %s", command, target_mode, result)
        return {"ok": True, "command": command, "mode": target_mode, "result": result}
    except DashboardError as e:
        logger.error("Command '%s' to %s failed: %s", command, target_mode, e.message)
        return {"ok": False, "command": command, "mode": target_mode, "error": e.message}
