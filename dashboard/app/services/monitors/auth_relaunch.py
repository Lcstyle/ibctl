"""Monitor: say why ibctl relaunched a gateway from the login path.

Everything on the login path now happens in the running gateway. A relaunch
still happens when the JVM exited, when an in-JVM retry found no login
form, or when a stuck IB Key prompt ignored Cancel — and each one sends a
new IB Key push, so the operator is told why. STATUS ``last_relaunch``
carries the reason. One with no reason, relaunched under an open prompt
(``abandoned_prompt``), is the abandoned-prompt regression: urgent.

A relaunch already in STATUS when the dashboard starts is history, not
news. An ibctl without ``last_relaunch`` is a no-op.
"""

from __future__ import annotations

import logging

from app.services.monitor_manager import Alert, Monitor

logger = logging.getLogger("dashboard.services.monitors.auth_relaunch")

LOGIN_STATES = {"WaitingFor2fa", "WaitingForHitl2fa", "Authenticating"}

_UNSET = object()


class AuthRelaunchMonitor(Monitor):
    event_type = "auth_relaunch"
    interval_seconds = 10

    def __init__(self):
        self._seen: dict[str, object] = {}

    async def check(self, registry, ns) -> list[Alert]:
        if not ns.is_event_enabled(self.event_type):
            return []
        alerts: list[Alert] = []
        for inst in registry.cached_all_status():
            status = inst.status or {}
            if "last_relaunch" not in status:
                continue
            rec = status.get("last_relaunch")
            at = rec.get("at") if isinstance(rec, dict) else None
            previous = self._seen.get(inst.mode, _UNSET)
            self._seen[inst.mode] = at
            if previous is _UNSET or at is None or at == previous:
                continue
            if rec.get("abandoned_prompt") or rec.get("from_state") in LOGIN_STATES:
                alerts.append(self._alert(inst.mode, rec))
        return alerts

    def _alert(self, mode: str, rec: dict) -> Alert:
        m = mode.upper()
        from_state = rec.get("from_state", "?")
        if rec.get("abandoned_prompt"):
            body = (
                f"{m}: ibctl relaunched the gateway from {from_state} while it showed "
                "an IB Key prompt, with no recorded reason — an outstanding push was "
                "abandoned (a regression). A new IB Key push follows."
            )
            priority = "urgent"
        else:
            detail = rec.get("detail") or rec.get("reason", "unknown reason")
            body = (
                f"{m}: ibctl relaunched the gateway from {from_state} because "
                f"{detail}. A new IB Key push follows; approve it in IBKR Mobile."
            )
            priority = "high"
        logger.warning("Gateway relaunch on %s: %s", mode, rec)
        return Alert(
            event_type=self.event_type,
            title=f"ibctl: {m} gateway relaunched during login",
            body=body,
            priority=priority,
            tags="arrows_counterclockwise,key",
        )
