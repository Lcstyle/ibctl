"""Background service that scrapes IB system status and pushes to ibctl instances.

Runs as an async task alongside the dashboard. Polls the IB status page
at a configurable interval (default 5 min) and pushes IBSTATUS commands
to all registered ibctl instances via their TCP command servers.

Supports manual override: when set, the scraper is disabled and the
override status is pushed to all instances on every interval.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from app.services.ib_status_scraper import IBStatusScraper, ScraperConfig, SystemStatus

logger = logging.getLogger("dashboard.services.ib_monitor")


@dataclass
class StatusEvent:
    """A single IB status transition event for the audit log."""
    timestamp: float  # time.time()
    from_status: str
    to_status: str
    reason: str
    source: str  # "scraper" or "manual_override"


class IBStatusMonitor:
    """Background monitor that scrapes IB status and pushes to ibctl."""

    MAX_AUDIT_LOG = 200
    PERSIST_DIR = "/opt/ibctl/persist/config"
    AUDIT_LOG_FILE = "ib_status_audit.json"

    def __init__(
        self,
        registry,  # InstanceRegistry — imported at runtime to avoid circular
        check_interval_seconds: int = 300,  # 5 minutes
        scraper_config: ScraperConfig | None = None,
    ):
        self._registry = registry
        self._interval = check_interval_seconds
        self._scraper = IBStatusScraper(scraper_config)
        self._task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()
        self._last_pushed_status: str = "available"
        self._audit_log: deque[StatusEvent] = deque(maxlen=self.MAX_AUDIT_LOG)
        self._override_status: str | None = None  # None = scraper active
        self._override_reason: str = ""
        self._load_audit_log()

    @property
    def audit_log(self) -> list[StatusEvent]:
        """Return the audit log as a list (newest first)."""
        return list(reversed(self._audit_log))

    @property
    def override_active(self) -> bool:
        return self._override_status is not None

    @property
    def override_status(self) -> str | None:
        return self._override_status

    @property
    def override_reason(self) -> str:
        return self._override_reason

    def set_override(self, status: str, reason: str = ""):
        """Set a manual override, disabling the scraper.

        The override status will be pushed to all instances on every interval.
        """
        old = self._last_pushed_status
        self._override_status = status
        self._override_reason = reason or f"Manual override: {status}"
        self._record_event(old, status, self._override_reason, source="manual_override")
        logger.info("IB status override SET: %s (%s) — scraper disabled", status, self._override_reason)

    def clear_override(self):
        """Clear the manual override, re-enabling the scraper."""
        if self._override_status is not None:
            old = self._override_status
            self._override_status = None
            self._override_reason = ""
            self._record_event(old, "unknown", "Override cleared — scraper re-enabled", source="manual_override")
            logger.info("IB status override CLEARED — scraper re-enabled")

    def _record_event(self, from_status: str, to_status: str, reason: str, source: str = "scraper"):
        """Record a status transition in the audit log and persist to disk."""
        if from_status == to_status:
            return
        event = StatusEvent(
            timestamp=time.time(),
            from_status=from_status,
            to_status=to_status,
            reason=reason,
            source=source,
        )
        self._audit_log.append(event)
        logger.info("IB status event: %s → %s (%s) [%s]", from_status, to_status, reason, source)
        self._save_audit_log()

    def _audit_log_path(self) -> Path:
        return Path(self.PERSIST_DIR) / self.AUDIT_LOG_FILE

    def _load_audit_log(self):
        """Load persisted audit log from disk on startup."""
        path = self._audit_log_path()
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            for entry in data:
                self._audit_log.append(StatusEvent(
                    timestamp=entry["timestamp"],
                    from_status=entry["from_status"],
                    to_status=entry["to_status"],
                    reason=entry["reason"],
                    source=entry.get("source", "scraper"),
                ))
            if self._audit_log:
                self._last_pushed_status = self._audit_log[-1].to_status
            logger.info("Loaded %d audit log entries from disk", len(self._audit_log))
        except Exception as e:
            logger.warning("Failed to load audit log from %s: %s", path, e)

    def _save_audit_log(self):
        """Persist audit log to disk."""
        path = self._audit_log_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            data = [
                {
                    "timestamp": e.timestamp,
                    "from_status": e.from_status,
                    "to_status": e.to_status,
                    "reason": e.reason,
                    "source": e.source,
                }
                for e in self._audit_log
            ]
            path.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.warning("Failed to save audit log to %s: %s", path, e)

    async def start(self):
        """Start the background monitoring task."""
        self._stop_event.clear()
        self._task = asyncio.create_task(self._monitor_loop(), name="ib-status-monitor")
        logger.info("IB System Status monitor started (interval=%ds)", self._interval)

    async def stop(self):
        """Stop the background monitoring task."""
        if self._task:
            self._stop_event.set()
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
            self._task = None
            logger.info("IB System Status monitor stopped")

    async def _monitor_loop(self):
        """Main monitoring loop — scrape + push."""
        # Initial check immediately
        await self._check_and_push()

        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self._interval)
                break  # Event set — stopping
            except asyncio.TimeoutError:
                pass  # Normal timeout — check again

            await self._check_and_push()

    async def _check_and_push(self):
        """Scrape IB status (or use override) and push to all ibctl instances."""
        # Manual override: skip scraper, push override status directly
        if self._override_status is not None:
            await self._push_to_all(self._override_status, self._override_reason)
            self._last_pushed_status = self._override_status
            return

        try:
            # Run scraper in thread pool (it uses blocking requests)
            loop = asyncio.get_event_loop()
            status = await loop.run_in_executor(None, self._scraper.fetch_status)

            # Map to IBSTATUS command
            status_str = status.status.value  # available, maintenance, outage, etc.
            reason = ""

            if status.status == SystemStatus.MAINTENANCE:
                in_reset, window = status.is_in_reset_window(self._scraper.config.region)
                if window:
                    reason = f"Daily reset {window.region} {window.start_time.strftime('%H:%M')}-{window.end_time.strftime('%H:%M')} {window.timezone}"
                else:
                    reason = "Scheduled maintenance"
            elif status.status == SystemStatus.OUTAGE:
                blocking = [a for a in status.alerts if a.is_blocking()]
                if blocking:
                    reason = "; ".join(a.message[:100] for a in blocking[:3])
                else:
                    reason = "System outage (no specific blocking alerts)"
            elif status.status == SystemStatus.NO_INTERNET:
                reason = status.fetch_error or "Internet connectivity lost"
            elif status.status == SystemStatus.UNKNOWN:
                reason = status.fetch_error or "IB status page unreachable"

            # Record transition in audit log
            if status_str != self._last_pushed_status:
                self._record_event(self._last_pushed_status, status_str, reason, source="scraper")

            # Push to ALL instances
            await self._push_to_all(status_str, reason)
            self._last_pushed_status = status_str

        except Exception as e:
            logger.error("IB status check failed: %s", e, exc_info=True)

    async def _push_to_all(self, status: str, reason: str):
        """Push IBSTATUS command to all registered ibctl instances."""
        command = f'IBSTATUS {status} "{reason}"' if reason else f"IBSTATUS {status}"
        for mode in self._registry.modes():
            try:
                client = self._registry.get_client(mode)
                await client.send_command(command)
                logger.debug("Pushed IBSTATUS %s to %s", status, mode)
            except Exception as e:
                logger.debug("Failed to push IBSTATUS to %s: %s", mode, e)


def create_monitor(registry, config: dict | None = None) -> IBStatusMonitor:
    """Factory function to create an IBStatusMonitor from env/config."""
    interval = int(os.environ.get("IB_STATUS_CHECK_INTERVAL", "300"))

    # Backend hosts configurable via env (comma-separated) or defaults
    backend_hosts_str = os.environ.get("IB_STATUS_BACKEND_HOSTS", "")
    backend_hosts = [h.strip() for h in backend_hosts_str.split(",") if h.strip()] or None

    scraper_config = ScraperConfig(
        url=os.environ.get("IB_STATUS_URL", ScraperConfig().url),
        region=os.environ.get("IB_STATUS_REGION", "NA"),
        backend_hosts=backend_hosts,
        fallback_host=os.environ.get("IB_STATUS_FALLBACK_HOST", "interactivebrokers.com"),
    )

    # Alert classification overrides — layer 1: persisted JSON from dashboard UI
    from app.services.ib_status_scraper import SystemAlert
    overrides_path = Path("/opt/ibctl/persist/config/scraper_overrides.json")
    if overrides_path.exists():
        try:
            overrides = json.loads(overrides_path.read_text())
            for kw in overrides.get("extra_exchange_keywords", []):
                if kw not in SystemAlert.EXCHANGE_KEYWORDS:
                    SystemAlert.EXCHANGE_KEYWORDS = list(SystemAlert.EXCHANGE_KEYWORDS) + [kw]
            for phrase in overrides.get("extra_benign_phrases", []):
                if phrase not in SystemAlert.BENIGN_PHRASES:
                    SystemAlert.BENIGN_PHRASES = list(SystemAlert.BENIGN_PHRASES) + [phrase]
            logger.info("Loaded scraper overrides from disk: %s", overrides_path)
        except Exception as e:
            logger.warning("Failed to load scraper overrides: %s", e)

    # Alert classification overrides — layer 2: env vars (highest precedence)
    extra_exchanges = os.environ.get("IB_STATUS_EXTRA_EXCHANGE_KEYWORDS", "")
    if extra_exchanges:
        extras = [k.strip().upper() for k in extra_exchanges.split(",") if k.strip()]
        for kw in extras:
            if kw not in SystemAlert.EXCHANGE_KEYWORDS:
                SystemAlert.EXCHANGE_KEYWORDS = list(SystemAlert.EXCHANGE_KEYWORDS) + [kw]
        logger.info("Added exchange keywords from env: %s", extras)

    extra_benign = os.environ.get("IB_STATUS_EXTRA_BENIGN_PHRASES", "")
    if extra_benign:
        extras = [p.strip().upper() for p in extra_benign.split(",") if p.strip()]
        for phrase in extras:
            if phrase not in SystemAlert.BENIGN_PHRASES:
                SystemAlert.BENIGN_PHRASES = list(SystemAlert.BENIGN_PHRASES) + [phrase]
        logger.info("Added benign phrases from env: %s", extras)

    return IBStatusMonitor(
        registry=registry,
        check_interval_seconds=interval,
        scraper_config=scraper_config,
    )
