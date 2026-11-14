"""Monitor: tell the operator an IB Key push is waiting.

ibctl used to give up on a push after 120 s and relaunch the gateway,
sending another, again and again while the prompt was still open. Now the
gateway ends the round, and a push past ``twofa.alert_after_secs`` is
simply outstanding: say so once per round. An open prompt is no proof the
phone still shows the push (IBKR does not publish its lifetime), so say
that too. An ibctl without the ``twofa`` block is a no-op.
"""

from __future__ import annotations

import logging

from app.services.monitor_manager import Alert, Monitor

logger = logging.getLogger("dashboard.services.monitors.twofa_push_waiting")


class TwoFaPushWaitingMonitor(Monitor):
    event_type = "twofa_push_waiting"
    interval_seconds = 10

    def __init__(self):
        self._announced: dict[str, bool] = {}

    async def check(self, registry, ns) -> list[Alert]:
        if not ns.is_event_enabled(self.event_type):
            return []
        alerts: list[Alert] = []
        for inst in registry.cached_all_status():
            twofa = (inst.status or {}).get("twofa")
            overdue = isinstance(twofa, dict) and bool(twofa.get("push_overdue"))
            if not overdue:
                self._announced[inst.mode] = False
                continue
            if self._announced.get(inst.mode):
                continue
            self._announced[inst.mode] = True
            alerts.append(self._alert(inst.mode, twofa))
        return alerts

    def _alert(self, mode: str, twofa: dict) -> Alert:
        m = mode.upper()
        secs = int(twofa.get("challenge_open_secs") or 0)
        ceiling_min = int(twofa.get("stuck_ceiling_secs") or 1800) // 60
        body = (
            f"{m}'s IB Key push has waited {secs // 60} min {secs % 60} s. Approve it "
            "in IBKR Mobile if your phone shows it — it may already have expired "
            "there. ibctl keeps the gateway running (no restart) and sends no other "
            "push while the gateway shows this prompt; when the gateway closes it, "
            f"ibctl retries the login in the running gateway. A prompt still open "
            f"after {ceiling_min} min is cancelled."
        )
        logger.info("IB Key push waiting on %s (%ss)", mode, secs)
        return Alert(
            event_type=self.event_type,
            title=f"ibctl: {m} IB Key push waiting",
            body=body,
            priority="high",
            tags="key,hourglass",
        )
