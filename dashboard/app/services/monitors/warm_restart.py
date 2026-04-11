"""Monitor: alert when a warm restart occurs.

Detects Connected -> Restarting transitions (JVM warm restart).
Mutually exclusive with session_lost which excludes Restarting.
Disabled by default — enable in event configuration.
"""

from __future__ import annotations

from app.services.monitor_manager import Alert, TransitionMonitor


class WarmRestartMonitor(TransitionMonitor):
    event_type = "warm_restart"
    interval_seconds = 30

    def _scan_history(self, mode: str, history) -> tuple[str, Alert] | None:
        for transition in reversed(history):
            if transition.from_state != "Connected":
                continue
            if transition.to_state != "Restarting":
                continue
            key = f"{transition.timestamp}|{transition.from_state}|{transition.to_state}"
            return key, Alert(
                event_type=self.event_type,
                title=f"ibctl: {mode.upper()} warm restart",
                body=(
                    f"{mode.upper()} Gateway JVM is restarting.\n"
                    f"Session will resume automatically."
                ),
                priority="default",
                tags="arrows_counterclockwise",
            )
        return None
