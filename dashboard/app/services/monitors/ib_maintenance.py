"""Monitor: alert when IB system status changes to maintenance or outage.

Reads the IBStatusMonitor's audit log for status transitions rather than
the state machine's transition history.
Disabled by default — enable in event configuration.
"""

from __future__ import annotations

import logging

from app.services.monitor_manager import Alert, Monitor

logger = logging.getLogger("dashboard.services.monitors.ib_maintenance")


class IBMaintenanceMonitor(Monitor):
    event_type = "ib_maintenance"
    interval_seconds = 60

    def __init__(self, ib_status_monitor=None):
        self._ib_status_monitor = ib_status_monitor
        self._initialized = False
        self._last_seen_key: str = ""

    async def check(self, registry, ns) -> list[Alert]:
        if not ns.is_event_enabled(self.event_type):
            return []
        if self._ib_status_monitor is None:
            return []

        audit_log = self._ib_status_monitor.audit_log  # newest first
        if not audit_log:
            self._initialized = True
            return []

        latest = audit_log[0]
        key = f"{latest.timestamp}|{latest.from_status}|{latest.to_status}"

        if not self._initialized:
            self._initialized = True
            self._last_seen_key = key
            return []

        if key == self._last_seen_key:
            return []

        self._last_seen_key = key

        # Only alert on transitions TO maintenance or outage
        if latest.to_status not in ("maintenance", "outage"):
            return []

        priority = "high" if latest.to_status == "outage" else "default"
        tags = "warning" if latest.to_status == "outage" else "construction"

        return [Alert(
            event_type=self.event_type,
            title=f"ibctl: IB system {latest.to_status}",
            body=(
                f"IB system status: {latest.from_status} -> {latest.to_status}\n"
                f"Reason: {latest.reason}\n"
                f"ibctl instances will enter WaitingForIB state."
            ),
            priority=priority,
            tags=tags,
        )]
