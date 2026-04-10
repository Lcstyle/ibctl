"""Logs API — serves log files from the persistent log directory."""

from __future__ import annotations

import logging
import os
from dataclasses import asdict
from pathlib import Path

from fastapi import APIRouter, Query, Request

from app.domain.errors import DashboardError
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

    log_dir = Path(LOG_DIR)
    if not log_dir.exists():
        return {"dates": []}

    dates = []
    for f in sorted(log_dir.glob(f"{prefix}*.log"), reverse=True):
        name = f.stem  # e.g. "ibctl-2026-04-09"
        if name.startswith(prefix):
            dates.append(name[len(prefix):])

    return {"dates": dates, "source": source}


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
