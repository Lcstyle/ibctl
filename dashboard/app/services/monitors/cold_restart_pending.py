"""Monitor: critical alert before scheduled cold restart.

Fires a high-priority notification when the current time approaches
the configured cold restart time, giving the operator time to prepare
for the IB Key 2FA prompt.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime

from app.services.monitor_manager import Alert, Monitor

logger = logging.getLogger("dashboard.services.monitors.cold_restart_pending")

DAY_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]


class ColdRestartPendingMonitor(Monitor):
    event_type = "cold_restart_pending"
    interval_seconds = 10  # Check frequently near restart time

    def __init__(self):
        self._alerted_today = False
        self._last_reset_day: int = -1

    async def check(self, registry, ns) -> list[Alert]:
        if not ns.is_event_enabled(self.event_type):
            return []

        cold_restart_time = os.environ.get("TWS_COLD_RESTART", "")
        if not cold_restart_time:
            return []

        # Parse HH:MM
        try:
            parts = cold_restart_time.split(":")
            target_hour, target_minute = int(parts[0]), int(parts[1])
        except (ValueError, IndexError):
            return []

        target_day = int(os.environ.get("TWS_COLD_RESTART_DAY", "0"))
        lead_seconds = ns.config.events.get(self.event_type, {}).get("lead_seconds", 30)

        now = datetime.now()
        current_day = (now.weekday() + 1) % 7  # Python: 0=Mon; convert to 0=Sun

        # Reset alert flag at start of new day
        if current_day != self._last_reset_day:
            self._alerted_today = False
            self._last_reset_day = current_day

        if self._alerted_today:
            return []

        # Only check on the configured day
        if current_day != target_day:
            return []

        # Calculate seconds until restart
        target_seconds = target_hour * 3600 + target_minute * 60
        current_seconds = now.hour * 3600 + now.minute * 60 + now.second
        seconds_until = target_seconds - current_seconds

        # Fire when within lead_seconds window (but not after restart time)
        if 0 < seconds_until <= lead_seconds:
            self._alerted_today = True
            day_name = DAY_NAMES[target_day]
            return [Alert(
                event_type=self.event_type,
                title=f"ibctl: cold restart in {seconds_until}s",
                body=(
                    f"Scheduled cold restart: {day_name} {target_hour:02d}:{target_minute:02d}\n"
                    f"2FA approval (IB Key) will be required.\n"
                    f"Have your phone ready."
                ),
                priority="urgent",
                tags="rotating_light,alarm_clock",
            )]

        return []
