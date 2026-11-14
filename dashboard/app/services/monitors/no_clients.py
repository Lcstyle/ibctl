"""Monitor: alert when no API clients are connected.

Checks cached status for Connected instances with 0 clients for longer
than a configurable timeout.
"""

from __future__ import annotations

import logging
import time

from app.services.monitor_manager import Alert, Monitor

logger = logging.getLogger("dashboard.services.monitors.no_clients")


class NoClientsMonitor(Monitor):
    event_type = "no_clients"
    interval_seconds = 60

    def __init__(self):
        self._zero_since: dict[str, float] = {}  # mode -> timestamp
        self._alerted: dict[str, bool] = {}

    async def check(self, registry, ns) -> list[Alert]:
        if not ns.is_event_enabled(self.event_type):
            return []

        timeout_minutes = ns.get_event_timeout(self.event_type)
        if timeout_minutes <= 0:
            return []

        timeout_secs = timeout_minutes * 60
        now = time.time()
        alerts: list[Alert] = []

        instances = registry.cached_all_status()
        for inst in instances:
            mode = inst.mode
            status = inst.status or {}
            state = status.get("state", "unknown")
            ready = status.get("ready", False)
            clients = status.get("clients", {}).get("count", 0)

            if state == "Connected" and ready:
                if clients == 0:
                    if mode not in self._zero_since:
                        self._zero_since[mode] = now
                        self._alerted[mode] = False
                        logger.warning("No API clients on %s — starting %dm alert timer", mode, timeout_minutes)

                    elapsed = now - self._zero_since[mode]
                    if elapsed >= timeout_secs and not self._alerted.get(mode, False):
                        minutes = int(elapsed / 60)
                        alerts.append(Alert(
                            event_type=self.event_type,
                            title=f"ibctl: {mode.upper()} has 0 API clients",
                            body=(
                                f"{mode.upper()} has been Connected for {minutes}m with no API clients. "
                                f"Check if API clients are expected to be running."
                            ),
                            priority="urgent",
                            tags="warning",
                        ))
                        self._alerted[mode] = True
                        logger.warning("Alert sent: %s has 0 clients for %dm", mode, minutes)
                else:
                    if mode in self._zero_since:
                        logger.info("API clients connected on %s — alert timer reset", mode)
                    self._zero_since.pop(mode, None)
                    self._alerted.pop(mode, None)
            else:
                self._zero_since.pop(mode, None)
                self._alerted.pop(mode, None)

        return alerts
