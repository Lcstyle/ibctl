"""Monitor: alert when session leaves Connected unexpectedly.

Detects Connected -> X transitions where X is not Restarting (warm restart)
or Shutdown (clean exit). Those have their own monitors.
"""

from __future__ import annotations

from app.services.monitor_manager import Alert, TransitionMonitor

# Transitions from Connected to these are handled by other monitors or are expected.
EXCLUDED_TARGETS = {"Restarting", "Shutdown"}


class SessionLostMonitor(TransitionMonitor):
    event_type = "session_lost"
    interval_seconds = 30

    def _scan_history(self, mode: str, history) -> tuple[str, Alert] | None:
        for transition in reversed(history):
            if transition.from_state != "Connected":
                continue
            if transition.to_state in EXCLUDED_TARGETS:
                continue
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
