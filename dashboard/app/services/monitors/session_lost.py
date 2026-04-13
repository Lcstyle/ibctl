"""Monitor: alert when session leaves Connected unexpectedly.

Detects Connected -> X transitions where X is not Restarting (warm restart)
or Shutdown (clean exit). Those have their own monitors.

Suppresses alerts within +/- 5 minutes of scheduled restart times
(cold restart and daily warm restart) to avoid false positives during
expected maintenance windows.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime

from app.services.monitor_manager import Alert, TransitionMonitor

logger = logging.getLogger("dashboard.services.monitors.session_lost")

# Transitions from Connected to these are handled by other monitors or are expected.
EXCLUDED_TARGETS = {"Restarting", "Shutdown"}

# Suppress window: +/- this many minutes around scheduled restart times
SUPPRESS_WINDOW_MINUTES = 5


def _within_restart_window() -> bool:
    """Check if current time is within +/- 5 minutes of a scheduled restart."""
    now = datetime.now()
    current_minutes = now.hour * 60 + now.minute

    # Check cold restart time
    cold_time = os.environ.get("TWS_COLD_RESTART", "")
    day_raw = os.environ.get("TWS_COLD_RESTART_DAY", "").strip()
    cold_day = int(day_raw) if day_raw else 0
    current_day = (now.weekday() + 1) % 7  # Python: 0=Mon; convert to 0=Sun

    if cold_time and current_day == cold_day:
        try:
            parts = cold_time.split(":")
            target = int(parts[0]) * 60 + int(parts[1])
            if abs(current_minutes - target) <= SUPPRESS_WINDOW_MINUTES:
                return True
        except (ValueError, IndexError):
            pass

    # Check daily warm restart time (AUTO_RESTART_TIME, format "HH:MM AM/PM")
    auto_time = os.environ.get("AUTO_RESTART_TIME", "")
    if auto_time:
        try:
            from datetime import datetime as dt
            parsed = dt.strptime(auto_time.strip(), "%I:%M %p")
            target = parsed.hour * 60 + parsed.minute
            if abs(current_minutes - target) <= SUPPRESS_WINDOW_MINUTES:
                return True
        except ValueError:
            pass

    return False


class SessionLostMonitor(TransitionMonitor):
    event_type = "session_lost"
    interval_seconds = 30

    def _scan_history(self, mode: str, history) -> tuple[str, Alert] | None:
        for transition in reversed(history):
            if transition.from_state != "Connected":
                continue
            if transition.to_state in EXCLUDED_TARGETS:
                continue

            # Suppress during scheduled restart windows
            if _within_restart_window():
                logger.info(
                    "session_lost suppressed for %s — within scheduled restart window",
                    mode,
                )
                return None

            key = f"{transition.timestamp}|{transition.from_state}|{transition.to_state}"
            return key, Alert(
                event_type=self.event_type,
                title=f"ibctl: {mode.upper()} session lost",
                body=(
                    f"{mode.upper()} left Connected state unexpectedly.\n"
                    f"Transition: Connected -> {transition.to_state}\n"
                    f"ibctl will attempt recovery."
                ),
                priority="high",
                tags="warning",
            )
        return None
