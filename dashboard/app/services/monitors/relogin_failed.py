"""Monitor: alert when re-login attempts are exhausted.

Detects ReconnectingSession -> Restarting or ReauthPending transitions,
indicating the graduated re-login flow gave up.
"""

from __future__ import annotations

from app.services.monitor_manager import Alert, TransitionMonitor

# States that indicate re-login was abandoned.
FAILURE_TARGETS = {"Restarting", "ReauthPending"}


class ReloginFailedMonitor(TransitionMonitor):
    event_type = "relogin_failed"
    interval_seconds = 30

    def _scan_history(self, mode: str, history) -> tuple[str, Alert] | None:
        for transition in reversed(history):
            if transition.from_state != "ReconnectingSession":
                continue
            if transition.to_state not in FAILURE_TARGETS:
                continue
            key = f"{transition.timestamp}|{transition.from_state}|{transition.to_state}"
            action = "JVM restart" if transition.to_state == "Restarting" else "re-authentication"
            return key, Alert(
                event_type=self.event_type,
                title=f"ibctl: {mode.upper()} re-login failed",
                body=(
                    f"{mode.upper()} exhausted re-login attempts.\n"
                    f"Action taken: {action}\n"
                    f"Recovery in progress."
                ),
                priority="urgent",
                tags="rotating_light,warning",
            )
        return None
