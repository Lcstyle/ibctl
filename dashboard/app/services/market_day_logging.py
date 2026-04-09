"""Market-day-aware log handler for the dashboard daemon.

Rotates log files at the CME futures trading day boundary (6 PM US/Eastern).
Follows the ibkr-ec convention: log files are named by the date when the
market day ENDS (the trading session date).

Example: At 7 PM ET on Dec 29, writes to dashboard-2025-12-30.log
         At 5 PM ET on Dec 30, still writes to dashboard-2025-12-30.log
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from logging.handlers import BaseRotatingHandler
from pathlib import Path
from zoneinfo import ZoneInfo

MARKET_TZ = ZoneInfo("America/New_York")
MARKET_DAY_START_HOUR = 18  # 6 PM ET


def get_market_day_date(ts: datetime | None = None) -> str:
    """Return the market-day date as YYYY-MM-DD."""
    if ts is None:
        ts = datetime.now(MARKET_TZ)
    elif ts.tzinfo is None:
        ts = ts.replace(tzinfo=ZoneInfo("UTC"))

    eastern = ts.astimezone(MARKET_TZ)
    if eastern.hour >= MARKET_DAY_START_HOUR:
        market_date = (eastern + timedelta(days=1)).date()
    else:
        market_date = eastern.date()
    return market_date.isoformat()


class MarketDayFileHandler(BaseRotatingHandler):
    """Rotating file handler that creates a new log file each market day.

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
        self.current_market_day = get_market_day_date()
        filename = self._log_path()
        super().__init__(str(filename), mode="a", encoding=encoding)

    def _log_path(self) -> Path:
        return self.log_dir / f"{self.filename_prefix}{self.current_market_day}.log"

    def shouldRollover(self, record) -> int:
        new_day = get_market_day_date()
        if new_day != self.current_market_day:
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
        self.current_market_day = get_market_day_date()
        self.baseFilename = str(self._log_path())
        if not self.delay:
            self.stream = self._open()


def setup_dashboard_logging(log_dir: str | None = None, log_level: str = "INFO"):
    """Configure the dashboard root logger with market-day file handler."""
    import logging

    if not log_dir:
        return  # No file logging

    handler = MarketDayFileHandler(log_dir=log_dir, filename_prefix="dashboard-")
    formatter = logging.Formatter(
        '{"ts":"%(asctime)s","level":"%(levelname)s","target":"%(name)s","msg":"%(message)s"}',
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)
    handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Add to root logger so all dashboard.* loggers get file output
    root = logging.getLogger()
    root.addHandler(handler)
    # Ensure root logger level allows messages through to the handler
    if root.level > handler.level:
        root.setLevel(handler.level)
