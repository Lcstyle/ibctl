"""Command API endpoint — send commands to ibctl instances."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.domain.errors import DashboardError

logger = logging.getLogger("dashboard.api.command")
router = APIRouter()

ALLOWED_COMMANDS = {"STOP", "RESTART", "RECONNECTDATA", "RECONNECTACCOUNT", "ENABLEAPI", "PAUSE", "RESUME", "RESTARTSOCAT"}
# Commands with arguments — the keyword is uppercased but the argument preserves case
PREFIXED_COMMANDS = ("SETSTATE ", "PAUSE ")


class CommandRequest(BaseModel):
    command: str
    mode: str | None = None  # Target instance: "live", "paper", or None (primary)


@router.post("/api/v1/command")
async def send_command(request: Request, body: CommandRequest):
    """Send a command to a specific ibctl instance."""
    raw = body.command.strip()
    # Uppercase the keyword but preserve argument case (state names are case-sensitive)
    parts = raw.split(" ", 1)
    keyword = parts[0].upper()
    command = keyword if len(parts) == 1 else f"{keyword} {parts[1]}"

    is_prefixed = any(command.startswith(p) for p in PREFIXED_COMMANDS)
    if command not in ALLOWED_COMMANDS and not is_prefixed:
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
