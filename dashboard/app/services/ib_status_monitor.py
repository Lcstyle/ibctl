"""Background service that scrapes IB system status and pushes to ibctl instances.

Runs as an async task alongside the dashboard. Polls the IB status page
at a configurable interval (default 5 min) and pushes IBSTATUS commands
to all registered ibctl instances via their TCP command servers.

Supports manual override: when set, the scraper is disabled and the
override status is pushed to all instances on every interval.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field

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
        """Record a status transition in the audit log."""
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
                reason = blocking[0].message[:200] if blocking else "System outage"
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

    return IBStatusMonitor(
        registry=registry,
        check_interval_seconds=interval,
        scraper_config=scraper_config,
    )
