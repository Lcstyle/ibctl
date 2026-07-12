"""Configurable log file rotation for the dashboard daemon.

Supports two modes:
- **Calendar mode** (default): rotates at midnight local time, files named by calendar date.
- **Futures session mode**: rotates at the configured session reopen hour (default 6 PM ET),
  files named by the trading session date (the date when the session ends).

Mode is controlled by IBCTL_FUTURES_SESSION_LOGGING env var.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from logging.handlers import BaseRotatingHandler
from pathlib import Path
from zoneinfo import ZoneInfo

MARKET_TZ = ZoneInfo("America/New_York")


def _futures_session_logging() -> bool:
    return os.environ.get("IBCTL_FUTURES_SESSION_LOGGING", "").lower() in ("true", "yes", "1")


def _session_reopen_hour() -> int:
    try:
        h = int(os.environ.get("IBCTL_SESSION_REOPEN_HOUR", "18"))
        return h if 0 <= h < 24 else 18
    except ValueError:
        return 18


def get_log_date(ts: datetime | None = None) -> str:
    """Return the log date as YYYY-MM-DD based on configured mode.

    Calendar mode: today's date in local timezone.
    Futures session mode: after reopen hour ET, returns tomorrow's date (session end date).
    """
    if _futures_session_logging():
        return _futures_session_date(ts)
    else:
        return _calendar_date(ts)


# Backward-compatible alias
get_market_day_date = get_log_date


def _calendar_date(ts: datetime | None = None) -> str:
    """Calendar mode: today's local date."""
    if ts is None:
        return datetime.now().strftime("%Y-%m-%d")
    return ts.strftime("%Y-%m-%d")


def _futures_session_date(ts: datetime | None = None) -> str:
    """Futures session mode: date based on session reopen boundary."""
    reopen_hour = _session_reopen_hour()

    if ts is None:
        ts = datetime.now(MARKET_TZ)
    elif ts.tzinfo is None:
        ts = ts.replace(tzinfo=ZoneInfo("UTC"))

    eastern = ts.astimezone(MARKET_TZ)
    if eastern.hour >= reopen_hour:
        market_date = (eastern + timedelta(days=1)).date()
    else:
        market_date = eastern.date()
    return market_date.isoformat()


class MarketDayFileHandler(BaseRotatingHandler):
    """Rotating file handler that creates a new log file each day.

    Files: {log_dir}/{prefix}{YYYY-MM-DD}.log
    """

    def __init__(
        self,
        log_dir: str | Path,
        filename_prefix: str = "dashboard-",
        max_bytes: int = 10 * 1024 * 1024,
        encoding: str = "utf-8",
    ):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.filename_prefix = filename_prefix
        self.max_bytes = max_bytes
        self.current_log_date = get_log_date()
        filename = self._log_path()
        super().__init__(str(filename), mode="a", encoding=encoding)

    def _log_path(self) -> Path:
        return self.log_dir / f"{self.filename_prefix}{self.current_log_date}.log"

    def shouldRollover(self, record) -> int:
        new_day = get_log_date()
        if new_day != self.current_log_date:
            return 1
        if self.stream is None:
            self.stream = self._open()
        self.stream.seek(0, 2)
        msg = self.format(record) + "\n"
        if self.stream.tell() + len(msg.encode(self.encoding or "utf-8")) >= self.max_bytes:
            return 1
        return 0

    def doRollover(self):
        if self.stream:
            self.stream.close()
            self.stream = None
        self.current_log_date = get_log_date()
        self.baseFilename = str(self._log_path())
        if not self.delay:
            self.stream = self._open()


def setup_dashboard_logging(log_dir: str | None = None, log_level: str = "INFO"):
    """Configure the dashboard root logger with file handler.

    Idempotent: if a MarketDayFileHandler is already attached to root we
    return immediately. bootstrap.py calls this once before any other
    module imports; create_app() may call it a second time depending on
    env var presence — the guard prevents double-handlers (which would
    log every record twice).
    """
    import logging

    if not log_dir:
        return  # No file logging

    root = logging.getLogger()
    if any(isinstance(h, MarketDayFileHandler) for h in root.handlers):
        return

    handler = MarketDayFileHandler(log_dir=log_dir, filename_prefix="dashboard-")
    formatter = logging.Formatter(
        '{"ts":"%(asctime)s","level":"%(levelname)s","target":"%(name)s","msg":"%(message)s"}',
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)
    handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Add to root logger so all dashboard.* loggers get file output
    root.addHandler(handler)
    # Ensure root logger level allows messages through to the handler
    if root.level > handler.level:
        root.setLevel(handler.level)

    # Route uvicorn's own loggers and warnings into the same file handler so
    # that "Application startup failed" + traceback land in the durable JSONL
    # log. Without this they only reach docker stderr — the exact path that
    # lost the 2026-06-20 traceback when the container was later removed.
    # We APPEND the handler (don't clear existing ones) so uvicorn's own
    # stderr emission is preserved for live `docker logs` use.
    logging.captureWarnings(True)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "py.warnings"):
        lg = logging.getLogger(name)
        lg.addHandler(handler)
        if lg.level > handler.level or lg.level == 0:
            lg.setLevel(handler.level)
