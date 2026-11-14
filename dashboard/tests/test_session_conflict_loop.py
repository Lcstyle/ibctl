"""The session-conflict loop page.

A mode can answer "Existing session detected" thousands of times over
hours. The only notification used to be one 10-minute dwell page; the
evidence — every dialog named the host's own IP and a login time equal to
ibctl's own previous click — sat unread in the logs.

ibctl now stops answering after a burst and publishes the evidence in
STATUS (`session_conflict`). This monitor turns the breaker opening into
one loud page per episode that says who holds the session.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.monitors.session_conflict_loop import SessionConflictLoopMonitor


class _Registry:
    def __init__(self, **modes: dict):
        self.instances = [SimpleNamespace(mode=m, status=s) for m, s in modes.items()]

    def cached_all_status(self):
        return self.instances

    def status_of(self, mode: str) -> dict:
        return next(i.status for i in self.instances if i.mode == mode)


class _NS:
    def __init__(self, enabled: bool = True):
        self._enabled = enabled

    def is_event_enabled(self, event_type: str) -> bool:
        return self._enabled and event_type == "session_conflict_loop"


def _status(breaker_open: bool, *, self_inflicted: bool = True, ip="203.0.113.7", last=True):
    sc = {"recent": 5, "threshold": 5, "window_secs": 600, "breaker_open": breaker_open, "last": None}
    if last:
        sc["last"] = {
            "at": "2026-09-26T12:10:18-04:00[America/New_York]",
            "other_ip": ip,
            "other_connected_at": "2026-09-26T16:09:57Z",
            "self_inflicted": self_inflicted,
            "recent": 5,
        }
    return {"state": "HandlingSessionConflict", "session_conflict": sc}


@pytest.mark.asyncio
async def test_breaker_opening_pages_once_with_the_evidence():
    reg = _Registry(paper=_status(False))
    mon = SessionConflictLoopMonitor()
    assert await mon.check(reg, _NS()) == []

    reg.status_of("paper")["session_conflict"] = _status(True)["session_conflict"]
    (a,) = await mon.check(reg, _NS())
    assert a.event_type == "session_conflict_loop"
    assert a.priority == "urgent"
    assert "PAPER" in a.title
    assert "203.0.113.7" in a.body and "16:09:57" in a.body
    assert "displacing itself" in a.body, "say it's the gateway's own session"
    assert "restart" in a.body.lower()

    assert await mon.check(reg, _NS()) == [], "one page per episode"


@pytest.mark.asyncio
async def test_a_breaker_already_open_at_startup_is_still_paged():
    # It is a live outage, not history: a dashboard restart must not hide it.
    mon = SessionConflictLoopMonitor()
    (a,) = await mon.check(_Registry(paper=_status(True)), _NS())
    assert "PAPER" in a.title


@pytest.mark.asyncio
async def test_another_client_holding_the_user_gets_different_advice():
    reg = _Registry(live=_status(True, self_inflicted=False, ip="198.51.100.23"))
    (a,) = await SessionConflictLoopMonitor().check(reg, _NS())
    assert "198.51.100.23" in a.body
    assert "displacing itself" not in a.body
    assert "log it out" in a.body.lower()


@pytest.mark.asyncio
async def test_closing_then_reopening_pages_again():
    reg = _Registry(paper=_status(True))
    mon = SessionConflictLoopMonitor()
    assert len(await mon.check(reg, _NS())) == 1
    reg.status_of("paper")["session_conflict"]["breaker_open"] = False
    assert await mon.check(reg, _NS()) == []
    reg.status_of("paper")["session_conflict"]["breaker_open"] = True
    assert len(await mon.check(reg, _NS())) == 1


@pytest.mark.asyncio
async def test_no_evidence_still_pages_honestly():
    (a,) = await SessionConflictLoopMonitor().check(_Registry(paper=_status(True, last=False)), _NS())
    assert "unknown" in a.body.lower()


@pytest.mark.asyncio
async def test_disabled_event_or_old_ibctl_is_silent():
    assert await SessionConflictLoopMonitor().check(_Registry(paper=_status(True)), _NS(enabled=False)) == []
    old = _Registry(paper={"state": "HandlingSessionConflict"})
    assert await SessionConflictLoopMonitor().check(old, _NS()) == []
