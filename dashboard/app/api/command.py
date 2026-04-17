"""Command API endpoint — send commands to ibctl instances."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.domain.errors import DashboardError

logger = logging.getLogger("dashboard.api.command")
router = APIRouter()

ALLOWED_COMMANDS = {"STOP", "RESTART", "RECONNECTDATA", "RECONNECTACCOUNT", "ENABLEAPI", "PAUSE", "RESUME", "RESTARTSOCAT", "HITL_RESUME"}
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
        logger.warning("Rejected unknown command: '%s'", command)
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


# --- IB System Status API ---


@router.get("/api/v1/ib-status")
async def get_ib_status(request: Request):
    """Current IB system status with alerts and maintenance windows.

    Returns the scraper's latest view of IB system availability — the same
    data that drives ibctl's WaitingForIB state. External clients can poll
    this instead of running their own IB status scraper.
    """
    monitor = getattr(request.app.state, 'ib_status_monitor', None)
    if not monitor:
        return {"ok": False, "error": "IB status monitor not running"}

    scraper_status = monitor._scraper._last_status

    result = {
        "ok": True,
        "status": monitor._last_pushed_status,
        "override_active": monitor.override_active,
    }

    if monitor.override_active:
        result["override_status"] = monitor.override_status
        result["override_reason"] = monitor.override_reason

    if scraper_status:
        result["last_updated"] = scraper_status.last_updated.isoformat() if scraper_status.last_updated else None
        result["fetch_error"] = scraper_status.fetch_error
        result["alerts"] = [
            {
                "message": a.message,
                "severity": a.severity.value,
                "is_blocking": a.is_blocking(),
            }
            for a in scraper_status.alerts
        ]
        result["daily_resets"] = [
            {
                "region": w.region,
                "start_time": w.start_time.strftime("%H:%M"),
                "end_time": w.end_time.strftime("%H:%M"),
                "timezone": w.timezone,
            }
            for w in scraper_status.daily_resets
        ]
        result["weekend_resets"] = [
            {
                "region": w.region,
                "start_time": w.start_time.strftime("%H:%M"),
                "end_time": w.end_time.strftime("%H:%M"),
                "timezone": w.timezone,
            }
            for w in scraper_status.weekend_resets
        ]
    else:
        result["alerts"] = []
        result["daily_resets"] = []
        result["weekend_resets"] = []

    return result


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
    logger.info("IB status override set: %s (reason: %s)", body.status, body.reason or "none")
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
    logger.info("IB status override cleared — scraper re-enabled")
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


# --- Scraper Alert Configuration ---

SCRAPER_OVERRIDES_PATH = Path("/opt/ibctl/persist/config/scraper_overrides.json")


class ScraperOverridesRequest(BaseModel):
    extra_exchange_keywords: list[str] = []
    extra_benign_phrases: list[str] = []


def _load_scraper_overrides() -> dict:
    if SCRAPER_OVERRIDES_PATH.exists():
        try:
            return json.loads(SCRAPER_OVERRIDES_PATH.read_text())
        except Exception:
            pass
    return {"extra_exchange_keywords": [], "extra_benign_phrases": []}


def _save_scraper_overrides(data: dict):
    SCRAPER_OVERRIDES_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCRAPER_OVERRIDES_PATH.write_text(json.dumps(data, indent=2))


@router.get("/api/v1/ib-status/scraper-config")
async def get_scraper_config(request: Request):
    """Return current scraper alert classification rules."""
    from app.services.ib_status_scraper import SystemAlert

    overrides = _load_scraper_overrides()
    return {
        "ok": True,
        "builtin_exchange_keywords": list(SystemAlert.EXCHANGE_KEYWORDS),
        "builtin_benign_phrases": list(SystemAlert.BENIGN_PHRASES),
        "custom_exchange_keywords": overrides.get("extra_exchange_keywords", []),
        "custom_benign_phrases": overrides.get("extra_benign_phrases", []),
    }


@router.post("/api/v1/ib-status/scraper-config")
async def save_scraper_config(request: Request, body: ScraperOverridesRequest):
    """Save custom alert classification overrides (persisted to volume)."""
    from app.services.ib_status_scraper import SystemAlert

    # Normalize
    extra_exchanges = [k.strip().upper() for k in body.extra_exchange_keywords if k.strip()]
    extra_benign = [p.strip().upper() for p in body.extra_benign_phrases if p.strip()]

    # Save to disk
    data = {"extra_exchange_keywords": extra_exchanges, "extra_benign_phrases": extra_benign}
    _save_scraper_overrides(data)

    # Apply immediately (extend the class-level lists)
    for kw in extra_exchanges:
        if kw not in SystemAlert.EXCHANGE_KEYWORDS:
            SystemAlert.EXCHANGE_KEYWORDS = list(SystemAlert.EXCHANGE_KEYWORDS) + [kw]
    for phrase in extra_benign:
        if phrase not in SystemAlert.BENIGN_PHRASES:
            SystemAlert.BENIGN_PHRASES = list(SystemAlert.BENIGN_PHRASES) + [phrase]

    logger.info("Scraper overrides saved: %d exchange keywords, %d benign phrases", len(extra_exchanges), len(extra_benign))
    return {"ok": True}
