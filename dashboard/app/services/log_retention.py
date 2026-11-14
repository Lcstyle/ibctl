"""Log retention: ``logging.retention_days``.

ibctl (live, paper, single mode) and the dashboard write one log file per day,
``<prefix>-YYYY-MM-DD.log``, into the log directory. With ``retention_days =
N`` the files whose day is N or more days before today are deleted, so N days
are kept, today included; 0 (the default) keeps everything. The dashboard does
this for every source, at start and then every few hours, so it needs no
support from ibctl. Nothing else in the log directory is ever touched.

The days in the file names are calendar or futures-session labels, not
instants, so they are compared as dates with the current log day.
"""

from __future__ import annotations

import asyncio
import logging
import re
import tomllib
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Callable

from app.services import effective_config
from app.services.market_day_logging import get_market_day_date
from app.services.monitor_manager import Alert, Monitor

logger = logging.getLogger("dashboard.services.log_retention")

LOG_FILE = re.compile(r"^(?:dashboard|ibctl|ibctl-live|ibctl-paper)-(\d{4}-\d{2}-\d{2})\.log$")


@dataclass
class PruneResult:
    deleted: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)


def expired(log_dir: Path, today: date, keep_days: int) -> list[Path]:
    """The daily log files due for deletion, oldest first."""
    if keep_days <= 0 or not log_dir.is_dir():
        return []
    cutoff = today - timedelta(days=keep_days)
    out = []
    for path in sorted(log_dir.iterdir()):
        m = LOG_FILE.match(path.name)
        if not m or not path.is_file():
            continue
        try:
            day = date.fromisoformat(m.group(1))
        except ValueError:
            continue
        if day <= cutoff:
            out.append(path)
    return out


def prune(log_dir: Path, today: date, keep_days: int) -> PruneResult:
    result = PruneResult()
    for path in expired(log_dir, today, keep_days):
        try:
            path.unlink()
        except OSError as exc:
            result.failed.append((path.name, str(exc)))
        else:
            result.deleted.append(path.name)
    return result


def configured_retention_days() -> int:
    """``logging.retention_days`` from ibctl.toml, with the IBCTL_LOG_RETENTION_DAYS
    override applied the way the rest of the config's env overrides are."""
    try:
        config = effective_config.load()
    except (OSError, tomllib.TOMLDecodeError) as exc:
        logger.warning("log retention: cannot read the config (%s); keeping all logs", exc)
        return 0
    days = config.get("logging", {}).get("retention_days", 0)
    return days if isinstance(days, int) and not isinstance(days, bool) and days > 0 else 0


class LogRetentionMonitor(Monitor):
    """Deletes expired daily log files; raises no alerts (failures are logged)."""

    event_type = "log_retention"
    interval_seconds = 6 * 3600

    def __init__(
        self,
        log_dir: str,
        keep_days: Callable[[], int] = configured_retention_days,
        today: Callable[[], date] = lambda: date.fromisoformat(get_market_day_date()),
    ):
        self._log_dir = Path(log_dir)
        self._keep_days = keep_days
        self._today = today

    async def check(self, registry, ns) -> list[Alert]:
        keep = self._keep_days()
        if keep <= 0:
            return []
        result = await asyncio.to_thread(prune, self._log_dir, self._today(), keep)
        if result.deleted:
            logger.info(
                "log retention (%d days): deleted %d files, %s to %s",
                keep, len(result.deleted), result.deleted[0], result.deleted[-1],
            )
        for name, error in result.failed:
            logger.warning("log retention: could not delete %s: %s", name, error)
        return []
