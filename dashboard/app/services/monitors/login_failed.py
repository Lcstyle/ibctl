"""Monitor: alert on login failures.

Scans transition history for Error(...) states reached from login-phase states.
"""

from __future__ import annotations

from app.services.monitor_manager import Alert, TransitionMonitor

LOGIN_PHASE_STATES = {
    "WaitingForAgent",
    "WaitingForLogin",
    "Authenticating",
    "WaitingFor2fa",
    "HandlingSessionConflict",
    "DismissingPopups",
    "ConfiguringApi",
}


def _extract_error_message(state_name: str) -> str:
    if state_name.startswith("Error(") and state_name.endswith(")"):
        return state_name[6:-1]
    return state_name


class LoginFailedMonitor(TransitionMonitor):
    event_type = "login_failed"
    interval_seconds = 30

    def _scan_history(self, mode: str, history) -> tuple[str, Alert] | None:
        for transition in reversed(history):
            if transition.from_state not in LOGIN_PHASE_STATES:
                continue
            if not transition.to_state.startswith("Error("):
                continue
            key = f"{transition.timestamp}|{transition.from_state}|{transition.to_state}"
            message = _extract_error_message(transition.to_state)
            return key, Alert(
                event_type=self.event_type,
                title=f"ibctl: {mode.upper()} login failed",
                body=(
                    f"{mode.upper()} failed during {transition.from_state}. "
                    f"ibctl will restart and retry.\n\n"
                    f"Reason: {message}"
                ),
                priority="urgent",
                tags="rotating_light,warning",
            )
        return None
