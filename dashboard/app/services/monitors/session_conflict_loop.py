"""Monitor: page when ibctl stops answering "Existing session detected".

A gateway can answer the dialog thousands of times in a few hours with one
10-minute dwell page as the only notification, while the evidence — every
dialog naming the host's own IP and a login time equal to ibctl's own previous
click, i.e. the gateway displacing itself — goes unread.

ibctl now stops answering after a burst (STATUS ``session_conflict.
breaker_open``) and publishes who the last dialog named. This turns the
breaker opening into one urgent page per episode, with advice that depends
on whether the other session is the gateway's own.

A breaker already open when the dashboard starts is paged too: it is a live
outage, not history. An ibctl without the ``session_conflict`` block is a
no-op.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.services.monitor_manager import Alert, Monitor

logger = logging.getLogger("dashboard.services.monitors.session_conflict_loop")


def _hhmmss_utc(iso: str | None) -> str | None:
    if not iso:
        return None
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return iso
    return t.strftime("%H:%M:%S UTC")


class SessionConflictLoopMonitor(Monitor):
    event_type = "session_conflict_loop"
    interval_seconds = 10

    def __init__(self):
        self._open: dict[str, bool] = {}

    async def check(self, registry, ns) -> list[Alert]:
        if not ns.is_event_enabled(self.event_type):
            return []
        alerts: list[Alert] = []
        for inst in registry.cached_all_status():
            sc = (inst.status or {}).get("session_conflict")
            if not isinstance(sc, dict):
                continue
            is_open = bool(sc.get("breaker_open"))
            was_open = self._open.get(inst.mode, False)
            self._open[inst.mode] = is_open
            if is_open and not was_open:
                alerts.append(self._alert(inst.mode, sc))
        return alerts

    def _alert(self, mode: str, sc: dict) -> Alert:
        m = mode.upper()
        last = sc.get("last") or {}
        ip = last.get("other_ip")
        when = _hhmmss_utc(last.get("other_connected_at"))
        who = f"IP {ip}, logged in at {when}" if ip else "unknown (the dialog text wasn't read)"
        if last.get("self_inflicted"):
            advice = (
                "That login time is this gateway's own last login: it is displacing "
                f"itself. Restart {m} from the dashboard; a fresh gateway logs in once."
            )
        else:
            advice = (
                f"Another client may hold {m}'s user — IBKR Mobile, Client Portal, or "
                f"another TWS/Gateway. Log it out, then restart {m} from the dashboard."
            )
        body = (
            f"{m}: {sc.get('recent', '?')} 'Existing session detected' dialogs within "
            f"{int(sc.get('window_secs', 600)) // 60} min. ibctl has stopped answering "
            f"them; the dialog is left on the gateway.\n"
            f"Other session: {who}.\n{advice}"
        )
        logger.warning("Session-conflict loop on %s — paging (other session: %s)", mode, who)
        return Alert(
            event_type=self.event_type,
            title=f"ibctl: {m} session-conflict loop — ibctl stopped retrying",
            body=body,
            priority="urgent",
            tags="rotating_light",
        )
