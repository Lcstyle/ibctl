"""Logs API — serves log files from the persistent log directory."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import asdict
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, HTTPException, Query, Request

from app.domain.errors import DashboardError
from app.services.identity_mask import mask_identity
from app.services.log_pages import DISPLAY_TZ, LogPage, read_after, read_before
from app.services.market_day_logging import get_market_day_date

logger = logging.getLogger("dashboard.api.logs")
router = APIRouter()

LOG_DIR = os.environ.get("IBCTL_LOG_DIR", "/opt/ibctl/persist/logs")
LOG_SOURCES = {
    "ibctl-live": "ibctl-live-",
    "ibctl-paper": "ibctl-paper-",
    "ibctl": "ibctl-",          # Single mode fallback
    "dashboard": "dashboard-",
}
PAGE_LIMIT_MAX = 1000
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _log_days(prefix: str) -> list[str]:
    """The days with a log file for a source, oldest first. Only exact
    ``<prefix>YYYY-MM-DD.log`` names count, so the single-mode ``ibctl-``
    prefix doesn't pick up ``ibctl-live-`` and ``ibctl-paper-`` files."""
    log_dir = Path(LOG_DIR)
    if not log_dir.is_dir():
        return []
    name = re.compile(re.escape(prefix) + r"(\d{4}-\d{2}-\d{2})\.log")
    days = []
    for f in log_dir.iterdir():
        m = name.fullmatch(f.name)
        if m and f.is_file():
            days.append(m.group(1))
    return sorted(days)


def _display_tz() -> str:
    name = os.environ.get("TZ", DISPLAY_TZ)
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return DISPLAY_TZ
    return name


@router.get("/api/v1/logs/page")
async def get_log_page(
    source: str = "ibctl",
    date: str | None = None,
    level: str | None = None,
    before: int | None = Query(None, ge=0),
    after: int | None = Query(None, ge=0),
    limit: int = Query(200, ge=1),
):
    """One page of a day's log file, by byte offset: the logs page's scroll-back and tail.

    No cursor gives the newest lines. ``before`` gives the lines that end at
    that offset (older), ``after`` the complete lines that start there (newer).
    A page covers bytes ``[start, end)``: page older with ``before=start`` and
    newer with ``after=end``. ``reset`` means the file was replaced under the
    cursor, so start again from the tail. ``date`` defaults to the current
    market day, which ``current_date`` always reports, so a viewer following
    "today" can tell when the day rolls over.
    """
    prefix = LOG_SOURCES.get(source)
    if prefix is None:
        raise HTTPException(400, f"unknown log source: {source}")
    if before is not None and after is not None:
        raise HTTPException(400, "give before or after, not both")
    if date is not None and not _DATE.fullmatch(date):
        raise HTTPException(400, "date must be YYYY-MM-DD")

    current = get_market_day_date()
    day = date or current
    path = Path(LOG_DIR) / f"{prefix}{day}.log"
    limit = min(limit, PAGE_LIMIT_MAX)
    exists = path.is_file()
    if not exists:
        page = LogPage(0, 0, 0, True, True)
    elif after is not None:
        page = await asyncio.to_thread(read_after, path, after, limit, level, tz=_display_tz())
    else:
        page = await asyncio.to_thread(read_before, path, before, limit, level, tz=_display_tz())

    days = await asyncio.to_thread(_log_days, prefix)
    prev_date = max((d for d in days if d < day), default=None)
    next_date = min((d for d in days if d > day), default=None)
    return {
        "source": source, "date": day, "current_date": current, "exists": exists,
        "prev_date": prev_date, "next_date": next_date, **asdict(page),
    }


@router.get("/api/v1/logs")
async def get_logs(
    source: str = "ibctl",
    date: str | None = None,
    level: str | None = None,
    tail: int = 200,
):
    """Get log lines from a specific source and date.

    Args:
        source: Log source — "ibctl" or "dashboard"
        date: Market day date (YYYY-MM-DD). Defaults to current market day.
        level: Filter by log level (ERROR, WARN, INFO, DEBUG)
        tail: Number of lines from the end (default 200)
    """
    prefix = LOG_SOURCES.get(source)
    if not prefix:
        return {"logs": [], "error": f"Unknown source: {source}"}

    if date is None:
        date = get_market_day_date()

    log_path = Path(LOG_DIR) / f"{prefix}{date}.log"
    if not log_path.exists():
        return {"logs": [], "date": date, "source": source, "file": str(log_path)}

    lines = _read_tail(log_path, tail)

    if level:
        level_upper = level.upper()
        # Match both WARN (Rust) and WARNING (Python) for the same filter
        if level_upper == "WARNING":
            lines = [l for l in lines if '"level":"WARNING"' in l or '"level":"WARN"' in l or "[WARNING]" in l or "[WARN]" in l]
        else:
            lines = [l for l in lines if f'"level":"{level_upper}"' in l or f"[{level_upper}]" in l]

    return {"logs": lines, "date": date, "source": source}


@router.get("/api/v1/logs/dates")
async def get_log_dates(source: str = "ibctl"):
    """List available log dates for a source, newest first."""
    prefix = LOG_SOURCES.get(source)
    if not prefix:
        return {"dates": [], "error": f"Unknown source: {source}"}

    return {"dates": _log_days(prefix)[::-1], "source": source}


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
    """Get running configuration (passwords masked, login names shown as set / not set)."""
    client = request.app.state.ibctl_client
    try:
        return mask_identity(await client.config())
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


def _read_tail(path: Path, n: int) -> list[str]:
    """Read the last n lines of a file efficiently."""
    try:
        with open(path, "rb") as f:
            # Seek from end to find last n newlines
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return []

            # Read in chunks from the end
            chunk_size = min(size, n * 512)  # Estimate ~512 bytes per line
            f.seek(max(0, size - chunk_size))
            data = f.read().decode("utf-8", errors="replace")
            lines = data.splitlines()
            return lines[-n:] if len(lines) > n else lines
    except Exception as e:
        logger.warning("Failed to read log file %s: %s", path, e)
        return []
