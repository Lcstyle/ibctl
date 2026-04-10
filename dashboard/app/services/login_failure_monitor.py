"""Background monitor: alert on new login-failure transitions.

Polls the state transition history for each ibctl instance and emits a single
alert when a new terminal Error(...) transition occurs during the login flow.
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger("dashboard.services.login_failure_monitor")

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


class LoginFailureMonitor:
    """Background task that alerts when login fails and ibctl restarts."""

    def __init__(self, registry, notification_service):
        self._registry = registry
        self._notification_service = notification_service
        self._task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()
        self._last_seen_error: dict[str, str] = {}
        self._initialized = False

    async def start(self):
        self._stop_event.clear()
        self._task = asyncio.create_task(self._monitor_loop(), name="login-failure-monitor")
        logger.info("Login-failure monitor started")

    async def stop(self):
        if self._task:
            self._stop_event.set()
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
            self._task = None
            logger.info("Login-failure monitor stopped")

    async def _monitor_loop(self):
        while not self._stop_event.is_set():
            try:
                await self._check()
            except Exception as e:
                logger.error("Login-failure monitor error: %s", e)

            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=30)
                break
            except asyncio.TimeoutError:
                pass

    async def _check(self):
        ns = self._notification_service
        if not ns.is_event_enabled("login_failed"):
            return

        snapshot: dict[str, str] = {}
        pending_alerts: list[tuple[str, str, str]] = []

        for mode in self._registry.modes():
            client = self._registry.get_client(mode)
            state = await client.state()
            latest_error = self._latest_login_error(state.history)
            if latest_error is None:
                self._last_seen_error.pop(mode, None)
                continue

            key, from_state, to_state = latest_error
            snapshot[mode] = key
            if self._initialized and self._last_seen_error.get(mode) != key:
                pending_alerts.append((mode, from_state, to_state))

        if not self._initialized:
            self._initialized = True
            self._last_seen_error = snapshot
            return

        self._last_seen_error = snapshot
        for mode, from_state, to_state in pending_alerts:
            message = _extract_error_message(to_state)
            await ns.send_alert(
                event_type="login_failed",
                title=f"ibctl: {mode.upper()} login failed",
                body=(
                    f"{mode.upper()} failed during {from_state}. "
                    f"ibctl will restart and retry.\n\n"
                    f"Reason: {message}"
                ),
                priority="urgent",
                tags="rotating_light,warning",
            )
            logger.warning("Alert sent: %s login failed (%s)", mode, message)

    @staticmethod
    def _latest_login_error(history) -> tuple[str, str, str] | None:
        for transition in reversed(history):
            if transition.from_state not in LOGIN_PHASE_STATES:
                continue
            if not transition.to_state.startswith("Error("):
                continue
            key = f"{transition.timestamp}|{transition.from_state}|{transition.to_state}"
            return key, transition.from_state, transition.to_state
        return None
