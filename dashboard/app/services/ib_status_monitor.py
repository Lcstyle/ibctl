"""Background service that scrapes IB system status and pushes to ibctl instances.

Runs as an async task alongside the dashboard. Polls the IB status page
at a configurable interval (default 5 min) and pushes IBSTATUS commands
to all registered ibctl instances via their TCP command servers.
"""

from __future__ import annotations

import asyncio
import logging
import os

from app.services.ib_status_scraper import IBStatusScraper, ScraperConfig, SystemStatus

logger = logging.getLogger("dashboard.services.ib_monitor")


class IBStatusMonitor:
    """Background monitor that scrapes IB status and pushes to ibctl."""

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
        """Scrape IB status and push to all ibctl instances."""
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

            # Only push if status changed (or periodic refresh)
            if status_str != self._last_pushed_status:
                logger.info("IB system status changed: %s → %s (%s)", self._last_pushed_status, status_str, reason)
            else:
                logger.debug("IB system status: %s (%s)", status_str, reason or "ok")

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
        backend_port=int(os.environ.get("IB_STATUS_BACKEND_PORT", "443")),
        fallback_host=os.environ.get("IB_STATUS_FALLBACK_HOST", "interactivebrokers.com"),
        fallback_port=int(os.environ.get("IB_STATUS_FALLBACK_PORT", "443")),
    )

    return IBStatusMonitor(
        registry=registry,
        check_interval_seconds=interval,
        scraper_config=scraper_config,
    )
