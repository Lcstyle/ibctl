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
        # Invalidate cache so SSE picks up new state on next poll
        registry.invalidate(target_mode)
        logger.info("Command '%s' sent to %s: %s", command, target_mode, result)
        return {"ok": True, "command": command, "mode": target_mode, "result": result}
    except DashboardError as e:
        logger.error("Command '%s' to %s failed: %s", command, target_mode, e.message)
        return {"ok": False, "command": command, "mode": target_mode, "error": e.message}


# --- IB Status Override & Audit Log ---

class OverrideRequest(BaseModel):
    status: str  # "available" or "maintenance"
    reason: str = ""


@router.post("/api/v1/ib-status/override")
async def set_ib_status_override(request: Request, body: OverrideRequest):
    """Set a manual IB status override, disabling the scraper."""
    monitor = getattr(request.app.state, 'ib_status_monitor', None)
    if not monitor:
        return {"ok": False, "error": "IB status monitor not running"}

    if body.status not in ("available", "maintenance"):
        return {"ok": False, "error": f"Invalid status: {body.status} (must be 'available' or 'maintenance')"}

    monitor.set_override(body.status, body.reason)
    # Push immediately so ibctl instances get the update
    await monitor._check_and_push()
    return {"ok": True, "status": body.status, "reason": body.reason}


@router.delete("/api/v1/ib-status/override")
async def clear_ib_status_override(request: Request):
    """Clear the manual override, re-enabling the scraper."""
    monitor = getattr(request.app.state, 'ib_status_monitor', None)
    if not monitor:
        return {"ok": False, "error": "IB status monitor not running"}

    monitor.clear_override()
    # Scraper will pick up on next interval; do an immediate check
    await monitor._check_and_push()
    return {"ok": True, "message": "Override cleared — scraper re-enabled"}


@router.get("/api/v1/ib-status/audit-log")
async def get_ib_status_audit_log(request: Request):
    """Return the IB status transition audit log (newest first)."""
    monitor = getattr(request.app.state, 'ib_status_monitor', None)
    if not monitor:
        return {"ok": False, "error": "IB status monitor not running"}

    from datetime import datetime
    from zoneinfo import ZoneInfo
    import os

    tz_name = os.environ.get("TZ", "America/New_York")
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = ZoneInfo("America/New_York")

    events = []
    for event in monitor.audit_log:
        dt = datetime.fromtimestamp(event.timestamp, tz=tz)
        events.append({
            "timestamp": dt.strftime("%Y-%m-%d %I:%M:%S %p"),
            "from_status": event.from_status,
            "to_status": event.to_status,
            "reason": event.reason,
            "source": event.source,
        })

    return {
        "ok": True,
        "override_active": monitor.override_active,
        "override_status": monitor.override_status,
        "events": events,
    }
