"""Background monitor: alert when no API clients are connected.

Checks all configured instances every 60s. If an instance is Connected
and ready but has 0 API clients for longer than the configured timeout,
sends an ntfy alert. Resets the timer when clients connect.

Only monitors instances that are in Connected state — doesn't alert
during startup, authentication, or maintenance.
"""

from __future__ import annotations

import asyncio
import logging
import time

logger = logging.getLogger("dashboard.services.no_clients_monitor")


class NoClientsMonitor:
    """Background task that alerts when connected instances have 0 clients."""

    def __init__(self, registry, notification_service):
        self._registry = registry
        self._notification_service = notification_service
        self._task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()
        # Track when each mode first had 0 clients while Connected
        self._zero_since: dict[str, float] = {}  # mode → timestamp
        # Track if we already alerted for this zero-client period
        self._alerted: dict[str, bool] = {}

    async def start(self):
        self._stop_event.clear()
        self._task = asyncio.create_task(self._monitor_loop(), name="no-clients-monitor")
        logger.info("No-clients monitor started")

    async def stop(self):
        if self._task:
            self._stop_event.set()
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
            self._task = None
            logger.info("No-clients monitor stopped")

    async def _monitor_loop(self):
        while not self._stop_event.is_set():
            try:
                await self._check()
            except Exception as e:
                logger.error("No-clients monitor error: %s", e)

            # Check every 60 seconds
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=60)
                break  # Event set — stopping
            except asyncio.TimeoutError:
                pass  # Normal timeout — check again

    async def _check(self):
        ns = self._notification_service
        if not ns.is_event_enabled("no_clients"):
            return

        timeout_minutes = ns.get_event_timeout("no_clients")
        if timeout_minutes <= 0:
            return

        timeout_secs = timeout_minutes * 60
        now = time.time()

        instances = self._registry.cached_all_status()
        for inst in instances:
            mode = inst.mode
            status = inst.status or {}
            state = status.get("state", "unknown")
            ready = status.get("ready", False)
            clients = status.get("clients", {}).get("count", 0)

            if state == "Connected" and ready:
                if clients == 0:
                    # Start tracking if not already
                    if mode not in self._zero_since:
                        self._zero_since[mode] = now
                        self._alerted[mode] = False
                        logger.warning("No API clients on %s — starting %dm alert timer", mode, timeout_minutes)

                    elapsed = now - self._zero_since[mode]
                    if elapsed >= timeout_secs and not self._alerted.get(mode, False):
                        minutes = int(elapsed / 60)
                        await ns.send_alert(
                            event_type="no_clients",
                            title=f"ibctl: {mode.upper()} has 0 API clients",
                            body=f"{mode.upper()} has been Connected for {minutes}m with no API clients. "
                                 f"Check if trading algos are running.",
                            priority="urgent",
                            tags="warning",
                        )
                        self._alerted[mode] = True
                        logger.warning("Alert sent: %s has 0 clients for %dm", mode, minutes)
                else:
                    # Clients connected — reset timer
                    if mode in self._zero_since:
                        logger.info("API clients connected on %s — alert timer reset", mode)
                    self._zero_since.pop(mode, None)
                    self._alerted.pop(mode, None)
            else:
                # Not Connected/ready — don't track
                self._zero_since.pop(mode, None)
                self._alerted.pop(mode, None)
