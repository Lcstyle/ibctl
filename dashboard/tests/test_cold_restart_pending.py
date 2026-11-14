"""ColdRestartPendingMonitor: the pre-restart warning, and the post-restart
success confirmation.

Without the confirmation, the pending warning ("cold restart in 30s, have
your phone ready") was the only signal — an operator who wanted to know the
Sunday cold restart actually succeeded had to open the dashboard.

No test file existed for this monitor before this change; the pending-alert
tests here are the first coverage it has ever had, not just for the new
success-watching behaviour.
"""

from __future__ import annotations

import time
from datetime import datetime
from types import SimpleNamespace

import pytest

from app.services.monitors.cold_restart_pending import (
    AWAIT_SUCCESS_MAX_SECS,
    ColdRestartPendingMonitor,
)


class _Registry:
    def __init__(self, instances):
        self._instances = instances
        self.instances = instances  # public alias for tests to mutate .status directly

    def cached_all_status(self):
        return self._instances

    def set(self, mode, state, ready=True):
        for i in self._instances:
            if i.mode == mode:
                i.status = {"state": state, "ready": ready}


def _inst(mode, state, ready=True):
    return SimpleNamespace(mode=mode, status={"state": state, "ready": ready})


class _NSStub:
    """Minimal NotificationService double: event toggles + the
    lead_seconds config the pending check reads."""

    class _Config:
        def __init__(self, lead_seconds=30):
            self.events = {"cold_restart_pending": {"lead_seconds": lead_seconds}}

    def __init__(
        self,
        *,
        pending_enabled=True,
        success_enabled=True,
        skipped_enabled=True,
        lead_seconds=30,
    ):
        self._pending_enabled = pending_enabled
        self._success_enabled = success_enabled
        self._skipped_enabled = skipped_enabled
        self.config = self._Config(lead_seconds)

    def is_event_enabled(self, event_type: str) -> bool:
        if event_type == "cold_restart_pending":
            return self._pending_enabled
        if event_type == "cold_restart_succeeded":
            return self._success_enabled
        if event_type == "cold_restart_skipped":
            return self._skipped_enabled
        return True


def _outcome(
    outcome="already_satisfied",
    recorded_at="2026-09-06T09:00:03-04:00[America/New_York]",
    last_login_at="2026-09-06T07:58:55-04:00[America/New_York]",
):
    """A `last_cold_restart_outcome` STATUS JSON blob, shaped exactly like
    queries.rs's serialization (which replaced `last_cold_restart_skip`)."""
    d = {"recorded_at": recorded_at, "outcome": outcome, "state": "Connected"}
    if outcome == "already_satisfied":
        d["last_login_at"] = last_login_at
    return d


class _FrozenDateTime(datetime):
    """Patches `cold_restart_pending.datetime` so _check_pending's
    `datetime.now()` call returns a fixed instant, without needing the test
    to actually run at that day/time."""

    _frozen: datetime

    @classmethod
    def now(cls, tz=None):
        return cls._frozen


def _freeze(monkeypatch, at: datetime) -> None:
    frozen = type("Frozen", (_FrozenDateTime,), {"_frozen": at})
    monkeypatch.setattr("app.services.monitors.cold_restart_pending.datetime", frozen)


# ---------------------------------------------------------------------------
# Pending alert — first-ever coverage of the pre-existing behaviour.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pending_alert_fires_within_the_lead_window(monkeypatch):
    monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
    mon = ColdRestartPendingMonitor()
    ns = _NSStub(lead_seconds=30)
    reg = _Registry([_inst("live", "Connected")])
    # Sunday 08:59:45 — 15s before restart, inside the 30s lead window.
    _freeze(monkeypatch, datetime(2026, 8, 23, 8, 59, 45))

    alerts = await mon.check(reg, ns)

    assert len(alerts) == 1
    assert alerts[0].event_type == "cold_restart_pending"
    assert "15s" in alerts[0].title


@pytest.mark.asyncio
async def test_pending_alert_does_not_fire_twice_in_one_day(monkeypatch):
    monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
    mon = ColdRestartPendingMonitor()
    ns = _NSStub(lead_seconds=30)
    reg = _Registry([_inst("live", "Connected")])
    _freeze(monkeypatch, datetime(2026, 8, 23, 8, 59, 45))

    first = await mon.check(reg, ns)
    second = await mon.check(reg, ns)

    assert len(first) == 1
    assert second == []


@pytest.mark.asyncio
async def test_pending_alert_arms_phase_1_not_phase_2(monkeypatch):
    """THE bug the first draft shipped with: at the moment the pending
    warning fires (a lead time BEFORE the actual restart), the mode is
    normally still sitting in Connected from before the restart even
    started. Arming the success-watch directly would declare victory
    before anything happened. It must arm the "watch for it to leave
    Connected first" phase instead.
    """
    monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
    mon = ColdRestartPendingMonitor()
    ns = _NSStub(lead_seconds=30)
    reg = _Registry([_inst("live", "Connected"), _inst("paper", "Connected")])
    _freeze(monkeypatch, datetime(2026, 8, 23, 8, 59, 45))

    await mon.check(reg, ns)

    assert "live" in mon._awaiting_disconnect
    assert "paper" in mon._awaiting_disconnect
    assert "live" not in mon._awaiting_success
    assert "paper" not in mon._awaiting_success


@pytest.mark.asyncio
async def test_staying_connected_through_the_warning_never_reports_success(monkeypatch):
    """End-to-end regression for the same bug, driven entirely through
    check() rather than by hand-seeding phase-2 state: a mode that never
    actually leaves Connected (e.g. it wasn't touched by this particular
    restart) must never produce a 'succeeded' alert, no matter how many
    ticks pass.
    """
    monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
    mon = ColdRestartPendingMonitor()
    ns = _NSStub(lead_seconds=30)
    reg = _Registry([_inst("live", "Connected")])
    _freeze(monkeypatch, datetime(2026, 8, 23, 8, 59, 45))

    await mon.check(reg, ns)  # fires the pending warning, arms phase 1
    for _ in range(5):
        assert await mon.check(reg, ns) == []


@pytest.mark.asyncio
async def test_full_cycle_leave_connected_then_return_reports_success(monkeypatch):
    """The real end-to-end path: pending warning fires, the mode actually
    leaves Connected (the restart happening), then returns — THAT sequence,
    and only that sequence, produces the success alert."""
    monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
    mon = ColdRestartPendingMonitor()
    ns = _NSStub(lead_seconds=30)
    reg = _Registry([_inst("live", "Connected")])
    _freeze(monkeypatch, datetime(2026, 8, 23, 8, 59, 45))

    await mon.check(reg, ns)
    assert await mon.check(reg, ns) == [], "still Connected — nothing to report yet"

    reg.set("live", "Authenticating")
    assert await mon.check(reg, ns) == [], (
        "left Connected — now watching for return, not yet"
    )
    assert "live" in mon._awaiting_success
    assert "live" not in mon._awaiting_disconnect

    reg.set("live", "Connected")
    alerts = await mon.check(reg, ns)
    assert len(alerts) == 1
    assert alerts[0].event_type == "cold_restart_succeeded"


# ---------------------------------------------------------------------------
# Success confirmation.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_success_alert_fires_once_a_watched_mode_reconnects(monkeypatch):
    monkeypatch.delenv(
        "TWS_COLD_RESTART", raising=False
    )  # pending path irrelevant here
    mon = ColdRestartPendingMonitor()
    ns = _NSStub()
    reg = _Registry([_inst("live", "Restarting")])
    mon._awaiting_success["live"] = time.time() - 30  # warning fired 30s ago

    reg.set("live", "Connected")
    alerts = await mon.check(reg, ns)

    assert len(alerts) == 1
    assert alerts[0].event_type == "cold_restart_succeeded"
    assert "LIVE" in alerts[0].title
    assert "succeeded" in alerts[0].title.lower()
    assert "live" not in mon._awaiting_success, "watch entry must clear on success"


@pytest.mark.asyncio
async def test_no_success_alert_while_still_reconnecting(monkeypatch):
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    mon = ColdRestartPendingMonitor()
    ns = _NSStub()
    reg = _Registry([_inst("live", "WaitingFor2fa")])
    mon._awaiting_success["live"] = time.time() - 30

    alerts = await mon.check(reg, ns)

    assert alerts == []
    assert "live" in mon._awaiting_success, "must keep watching — not yet Connected"


@pytest.mark.asyncio
async def test_connected_but_not_ready_is_not_a_success(monkeypatch):
    """Mirrors session_lost's own tradeable check: Connected with socat dead
    is untradeable, so it must not be reported as a successful reconnect."""
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    mon = ColdRestartPendingMonitor()
    ns = _NSStub()
    reg = _Registry([_inst("live", "Connected", ready=False)])
    mon._awaiting_success["live"] = time.time() - 30

    alerts = await mon.check(reg, ns)

    assert alerts == []
    assert "live" in mon._awaiting_success


@pytest.mark.asyncio
async def test_success_alert_respects_its_own_event_toggle(monkeypatch):
    """Disabling cold_restart_succeeded must not disable the pending
    warning, and must still clear the watch (not leak it forever just
    because the operator doesn't want the confirmation)."""
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    mon = ColdRestartPendingMonitor()
    ns = _NSStub(success_enabled=False)
    reg = _Registry([_inst("live", "Connected")])
    mon._awaiting_success["live"] = time.time() - 30

    alerts = await mon.check(reg, ns)

    assert alerts == []
    assert "live" not in mon._awaiting_success, "must still stop watching once resolved"


@pytest.mark.asyncio
async def test_watch_gives_up_silently_after_the_ceiling(monkeypatch):
    """Not a 'this is stuck' alert — session_lost.py and hitl_2fa.py already
    own that, on their own correctly-scoped timelines. This monitor just
    stops watching so a mode that never reconnects doesn't leak forever."""
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    mon = ColdRestartPendingMonitor()
    ns = _NSStub()
    reg = _Registry([_inst("live", "WaitingForHitl2fa")])
    mon._awaiting_success["live"] = time.time() - (AWAIT_SUCCESS_MAX_SECS + 60)

    alerts = await mon.check(reg, ns)

    assert alerts == [], "giving up must not itself page — that's another monitor's job"
    assert "live" not in mon._awaiting_success


# ---------------------------------------------------------------------------
# "Satisfied" notification — a mode that already re-authed earlier today
# gets skipped by ibctl's own cold_restart.rs scheduler (FreshAuthToday).
# Before this, that skip was silent: the operator got the generic pending
# warning and then nothing — no reconnect push ever came, and nothing told
# them it wasn't coming. For example, a mode that re-authed earlier that
# morning (an unrelated overnight 2FA) correctly skips the Sunday cold
# restart, but without this notification the operator only finds that out
# by asking.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_skip_notification_fires_for_fresh_auth_today(monkeypatch):
    monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
    mon = ColdRestartPendingMonitor()
    ns = _NSStub(lead_seconds=30)
    reg = _Registry([_inst("live", "Connected")])
    _freeze(monkeypatch, datetime(2026, 9, 6, 8, 59, 45))

    await mon.check(reg, ns)  # fires pending warning, arms phase 1
    assert "live" in mon._awaiting_disconnect

    reg.instances[0].status["last_cold_restart_outcome"] = _outcome()
    alerts = await mon.check(reg, ns)

    assert len(alerts) == 1
    assert alerts[0].event_type == "cold_restart_skipped"
    assert "live" not in mon._awaiting_disconnect, (
        "must stop waiting for a restart that isn't coming"
    )
    assert "live" not in mon._awaiting_success


@pytest.mark.asyncio
async def test_skip_notification_message_names_mode_and_time(monkeypatch):
    monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
    mon = ColdRestartPendingMonitor()
    ns = _NSStub(lead_seconds=30)
    reg = _Registry([_inst("live", "Connected")])
    _freeze(monkeypatch, datetime(2026, 9, 6, 8, 59, 45))

    await mon.check(reg, ns)
    reg.instances[0].status["last_cold_restart_outcome"] = _outcome(
        last_login_at="2026-09-06T07:58:55-04:00[America/New_York]"
    )
    alerts = await mon.check(reg, ns)

    assert len(alerts) == 1
    body = alerts[0].body
    assert "LIVE" in alerts[0].title or "LIVE" in body
    assert "7:58" in body, f"expected the fresh-auth time in the body, got: {body!r}"
    assert (
        "not needed" in alerts[0].title.lower()
        or "not needed" in body.lower()
        or "satisfied" in body.lower()
    )


@pytest.mark.asyncio
async def test_standby_outcome_does_not_notify(monkeypatch):
    """A standby host is the ordinary, every-week case for a failover site —
    alerting on it would just be weekly noise."""
    monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
    mon = ColdRestartPendingMonitor()
    ns = _NSStub(lead_seconds=30)
    reg = _Registry([_inst("live", "Connected")])
    _freeze(monkeypatch, datetime(2026, 9, 6, 8, 59, 45))

    await mon.check(reg, ns)
    reg.instances[0].status["last_cold_restart_outcome"] = _outcome(outcome="standby")
    alerts = await mon.check(reg, ns)

    assert alerts == []


@pytest.mark.asyncio
async def test_skip_notification_fires_only_once_per_outcome_record(monkeypatch):
    monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
    mon = ColdRestartPendingMonitor()
    ns = _NSStub(lead_seconds=30)
    reg = _Registry([_inst("live", "Connected")])
    _freeze(monkeypatch, datetime(2026, 9, 6, 8, 59, 45))

    await mon.check(reg, ns)
    reg.instances[0].status["last_cold_restart_outcome"] = _outcome()
    first = await mon.check(reg, ns)
    second = await mon.check(reg, ns)

    assert len(first) == 1
    assert second == []


@pytest.mark.asyncio
async def test_skip_notification_respects_its_own_event_toggle(monkeypatch):
    monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
    mon = ColdRestartPendingMonitor()
    ns = _NSStub(lead_seconds=30, skipped_enabled=False)
    reg = _Registry([_inst("live", "Connected")])
    _freeze(monkeypatch, datetime(2026, 9, 6, 8, 59, 45))

    await mon.check(reg, ns)
    reg.instances[0].status["last_cold_restart_outcome"] = _outcome()
    alerts = await mon.check(reg, ns)

    assert alerts == []
    assert "live" not in mon._awaiting_disconnect, (
        "must still stop watching once resolved"
    )


@pytest.mark.asyncio
async def test_an_outcome_seen_at_first_observation_is_not_announced(monkeypatch):
    """A stale outcome already present when the dashboard (re)starts is a
    baseline, not news — it must not spontaneously alert."""
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    mon = ColdRestartPendingMonitor()
    ns = _NSStub()
    reg = _Registry([_inst("live", "Connected")])
    reg.instances[0].status["last_cold_restart_outcome"] = _outcome()

    alerts = await mon.check(reg, ns)

    assert alerts == []


@pytest.mark.asyncio
async def test_modes_are_watched_independently(monkeypatch):
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    mon = ColdRestartPendingMonitor()
    ns = _NSStub()
    reg = _Registry([_inst("live", "Connected"), _inst("paper", "WaitingFor2fa")])
    mon._awaiting_success["live"] = time.time() - 30
    mon._awaiting_success["paper"] = time.time() - 30

    alerts = await mon.check(reg, ns)

    assert len(alerts) == 1
    assert "LIVE" in alerts[0].title
    assert "live" not in mon._awaiting_success
    assert "paper" in mon._awaiting_success, (
        "an unrelated mode's watch must be untouched"
    )
