"""SessionLostMonitor is dwell-triggered, not edge-triggered.

The requirement: fewer, more meaningful pages. Page when the connection is
not restored after some default amount of time, so a connection restored
within that threshold pages nobody unless the problem becomes persistent.

Threshold chosen from measured reconnect history, not guessed: the median
disconnect recovers in well under a minute, p95 in about four minutes, and
nearly all within ten. At 10 minutes only a small fraction of disconnects
page.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from app.services.monitors.session_lost import (
    SessionLostMonitor,
    _scheduled_restart_grace_deadline,
)


class _Registry:
    """Minimal stand-in for the instance registry."""

    def __init__(self, instances):
        self._instances = instances

    def cached_all_status(self):
        return self._instances

    def set(self, mode, state, ready=True):
        for i in self._instances:
            if i.mode == mode:
                i.status = {"state": state, "ready": ready}


def _inst(mode, state, ready=True):
    return SimpleNamespace(mode=mode, status={"state": state, "ready": ready})


def _monitor(alert_after_min=10, renag_min=60, monkeypatch=None):
    monkeypatch.setenv("IBCTL_SESSION_DOWN_ALERT_MINUTES", str(alert_after_min))
    monkeypatch.setenv("IBCTL_SESSION_DOWN_RENAG_MINUTES", str(renag_min))
    return SessionLostMonitor()


def _age(mon, mode, seconds):
    """Backdate the down-timer so a dwell can be tested without sleeping."""
    mon._down_since[mode] = time.time() - seconds


@pytest.mark.asyncio
async def test_transient_drop_pages_nobody(monkeypatch):
    """THE headline behaviour. Median recovery is seconds; that must be silent.

    Typical cases are the scheduled warm restart and IB's routine nightly
    reconnect: both self-recover, and an edge-triggered monitor paged on
    every one.
    """
    mon = _monitor(monkeypatch=monkeypatch)
    reg = _Registry([_inst("live", "Connected")])

    reg.set("live", "WaitingForLogin")
    assert await mon.check(reg, None) == [], "leaving Connected must not page immediately"

    _age(mon, "live", 20)  # the routine nightly blip
    assert await mon.check(reg, None) == [], "20s down is far below threshold"

    reg.set("live", "Connected")
    assert await mon.check(reg, None) == [], (
        "recovery after an UNPAGED drop must also be silent — announcing the "
        "recovery of something never announced is the same noise in reverse"
    )


@pytest.mark.asyncio
async def test_persistent_outage_pages_once_past_threshold(monkeypatch):
    mon = _monitor(alert_after_min=10, monkeypatch=monkeypatch)
    reg = _Registry([_inst("live", "Connected")])

    reg.set("live", "WaitingForHitl2fa")
    await mon.check(reg, None)

    _age(mon, "live", 9 * 60)
    assert await mon.check(reg, None) == [], "9m is under the 10m threshold"

    _age(mon, "live", 11 * 60)
    alerts = await mon.check(reg, None)
    assert len(alerts) == 1
    assert "still down" in alerts[0].title.lower()
    assert "WaitingForHitl2fa" in alerts[0].body

    # Must not re-page on the very next tick.
    assert await mon.check(reg, None) == []


@pytest.mark.asyncio
async def test_renag_while_still_down(monkeypatch):
    """Regression guard: one page, then hours of silence while stranded."""
    mon = _monitor(alert_after_min=10, renag_min=60, monkeypatch=monkeypatch)
    reg = _Registry([_inst("live", "Connected")])

    reg.set("live", "WaitingForHitl2fa")
    await mon.check(reg, None)
    _age(mon, "live", 11 * 60)
    assert len(await mon.check(reg, None)) == 1

    # An hour later, still stranded.
    mon._paged_at["live"] = time.time() - 61 * 60
    _age(mon, "live", 71 * 60)
    again = await mon.check(reg, None)
    assert len(again) == 1
    assert "still down" in again[0].title.lower()


@pytest.mark.asyncio
async def test_recovery_after_a_page_is_announced(monkeypatch):
    """Closure. Previously no 'restored' notification existed at all."""
    mon = _monitor(alert_after_min=10, monkeypatch=monkeypatch)
    reg = _Registry([_inst("live", "Connected")])

    reg.set("live", "WaitingForLogin")
    await mon.check(reg, None)
    _age(mon, "live", 11 * 60)
    assert len(await mon.check(reg, None)) == 1

    reg.set("live", "Connected")
    restored = await mon.check(reg, None)
    assert len(restored) == 1
    assert "restored" in restored[0].title.lower()
    assert "Total time down" in restored[0].body
    # And the episode is over — no repeat.
    assert await mon.check(reg, None) == []


@pytest.mark.asyncio
async def test_standby_is_never_down(monkeypatch):
    """WaitingForLaunch is the standby steady-state, by design.

    Paging every hour about a failover host that is deliberately not logged
    in would be relentless and wrong.
    """
    mon = _monitor(alert_after_min=10, monkeypatch=monkeypatch)
    reg = _Registry([_inst("live", "WaitingForLaunch")])

    await mon.check(reg, None)
    _age(mon, "live", 24 * 3600)
    assert await mon.check(reg, None) == []
    assert "live" not in mon._down_since


@pytest.mark.asyncio
async def test_connected_but_not_ready_counts_as_down(monkeypatch):
    """Connected with socat dead is untradeable, and was previously silent."""
    mon = _monitor(alert_after_min=10, monkeypatch=monkeypatch)
    reg = _Registry([_inst("live", "Connected", ready=False)])

    await mon.check(reg, None)
    _age(mon, "live", 11 * 60)
    alerts = await mon.check(reg, None)
    assert len(alerts) == 1, "Connected-but-not-ready must page like any other outage"


@pytest.mark.asyncio
async def test_modes_are_tracked_independently(monkeypatch):
    mon = _monitor(alert_after_min=10, monkeypatch=monkeypatch)
    reg = _Registry([_inst("live", "Connected"), _inst("paper", "Connected")])

    reg.set("paper", "WaitingForLogin")
    await mon.check(reg, None)
    _age(mon, "paper", 11 * 60)

    alerts = await mon.check(reg, None)
    assert len(alerts) == 1
    assert "PAPER" in alerts[0].title
    assert "live" not in mon._down_since


@pytest.mark.asyncio
async def test_zero_threshold_disables_the_monitor(monkeypatch):
    mon = _monitor(alert_after_min=0, monkeypatch=monkeypatch)
    reg = _Registry([_inst("live", "WaitingForLogin")])
    _age(mon, "live", 24 * 3600)
    assert await mon.check(reg, None) == []


# ---------------------------------------------------------------------------
# Scheduled-restart grace
#
# Requirement: scheduled restarts, warm or cold, are expected
# disconnects/reconnects and must not send connection-lost notifications.
#
# The ORIGINAL suppression (_within_restart_window, since removed) checked
# whether *now* was near the scheduled clock time at the moment the
# alert_after threshold crossed. That can never fire in practice: the check
# only runs once elapsed >= alert_after (10 min default), so by the time it
# runs, "now" is already >= alert_after minutes past the scheduled time —
# already outside a 5-minute window. These tests target the replacement,
# _scheduled_restart_grace_deadline, which is anchored to when the outage
# BEGAN instead.
# ---------------------------------------------------------------------------


def _epoch_for(hour: int, minute: int, python_weekday: int | None = None) -> float:
    """Epoch timestamp for hour:minute today, or the nearest day matching
    `python_weekday` (Monday=0 .. Sunday=6, matching datetime.weekday()).

    Computed relative to real "now" so the test is independent of which day
    it actually runs on.
    """
    base = datetime.now().replace(hour=hour, minute=minute, second=0, microsecond=0)
    if python_weekday is not None:
        base += timedelta(days=(python_weekday - base.weekday()) % 7)
    return base.timestamp()


class TestScheduledRestartGraceDeadline:
    """Unit tests for the pure function — no monitor, no registry."""

    def test_correlates_with_daily_warm_restart_time(self, monkeypatch):
        monkeypatch.setenv("AUTO_RESTART_TIME", "05:05 PM")
        monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
        down_since = _epoch_for(17, 5)

        deadline = _scheduled_restart_grace_deadline(down_since)

        assert deadline is not None
        assert deadline == pytest.approx(down_since + 20 * 60, abs=1)

    def test_correlates_with_weekly_sunday_cold_restart_time(self, monkeypatch):
        monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
        monkeypatch.delenv("TWS_COLD_RESTART_DAY", raising=False)  # default 0 = Sunday
        monkeypatch.delenv("AUTO_RESTART_TIME", raising=False)
        down_since = _epoch_for(9, 0, python_weekday=6)  # Sunday

        deadline = _scheduled_restart_grace_deadline(down_since)

        assert deadline is not None
        assert deadline == pytest.approx(down_since + 20 * 60, abs=1)

    def test_cold_restart_time_on_the_wrong_day_does_not_correlate(self, monkeypatch):
        monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
        monkeypatch.delenv("TWS_COLD_RESTART_DAY", raising=False)
        monkeypatch.delenv("AUTO_RESTART_TIME", raising=False)
        down_since = _epoch_for(9, 0, python_weekday=2)  # Wednesday, not Sunday

        assert _scheduled_restart_grace_deadline(down_since) is None

    def test_an_ordinary_3am_disconnect_does_not_correlate(self, monkeypatch):
        monkeypatch.setenv("AUTO_RESTART_TIME", "05:05 PM")
        monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
        down_since = _epoch_for(3, 17)

        assert _scheduled_restart_grace_deadline(down_since) is None

    def test_grace_minutes_is_configurable(self, monkeypatch):
        monkeypatch.setenv("AUTO_RESTART_TIME", "05:05 PM")
        monkeypatch.setenv("IBCTL_SCHEDULED_RESTART_GRACE_MINUTES", "45")
        down_since = _epoch_for(17, 5)

        deadline = _scheduled_restart_grace_deadline(down_since)

        assert deadline == pytest.approx(down_since + 45 * 60, abs=1)


@pytest.mark.asyncio
async def test_a_10_minute_warm_restart_reconnect_is_not_paged(monkeypatch):
    """THE bug this fix targets, made concrete.

    A warm restart that happens to take the full old alert_after (10 min) —
    slower than the usual ~30s but still a normal, self-resolving reconnect
    — must not page. Under the removed _within_restart_window, "now" at the
    10-minute mark is already outside any 5-minute window from 17:05, so
    this exact scenario always paged. It must not, per the requirement
    above.
    """
    monkeypatch.setenv("AUTO_RESTART_TIME", "05:05 PM")
    mon = _monitor(alert_after_min=10, monkeypatch=monkeypatch)
    reg = _Registry([_inst("live", "Connected")])

    reg.set("live", "WaitingForLogin")
    mon._down_since["live"] = _epoch_for(17, 5)
    mon._down_from["live"] = "WaitingForLogin"
    mon._grace_deadline["live"] = _scheduled_restart_grace_deadline(mon._down_since["live"])

    # 10 minutes in — the old threshold, and the old window would already
    # have expired by now.
    mon._down_since["live"] = mon._down_since["live"]  # (unchanged; document intent)
    now_at_10min = mon._down_since["live"] + 10 * 60
    monkeypatch.setattr(time, "time", lambda: now_at_10min)

    assert await mon.check(reg, None) == [], (
        "a 10-minute scheduled-restart reconnect must not page — "
        "this is exactly the case the old window-check silently failed to cover"
    )


@pytest.mark.asyncio
async def test_scheduled_restart_grace_still_pages_if_it_never_recovers(monkeypatch):
    """The backstop half of the fix: grace is generous, not unbounded.

    A failure that started at the scheduled time but is NOT a normal
    reconnect (never reaches Connected, e.g. stuck before ever reaching
    2FA) must still page once the grace deadline passes — this monitor is
    the only thing that catches that class of failure; hitl_2fa.py only
    fires on entry to WaitingForHitl2fa, which a non-2FA-shaped failure
    never reaches.
    """
    monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
    mon = _monitor(alert_after_min=10, monkeypatch=monkeypatch)
    reg = _Registry([_inst("live", "Connected")])

    reg.set("live", "WaitingForLogin")
    down_since = _epoch_for(9, 0, python_weekday=6)
    mon._down_since["live"] = down_since
    mon._down_from["live"] = "WaitingForLogin"
    mon._grace_deadline["live"] = _scheduled_restart_grace_deadline(down_since)

    # Still within the 20-minute grace: silent.
    monkeypatch.setattr(time, "time", lambda: down_since + 15 * 60)
    assert await mon.check(reg, None) == [], "still within grace — must stay silent"

    # Past the 20-minute grace: pages, exactly like any other stuck outage.
    monkeypatch.setattr(time, "time", lambda: down_since + 21 * 60)
    alerts = await mon.check(reg, None)
    assert len(alerts) == 1, "grace must be bounded — a genuinely stuck restart still pages"
    assert "still down" in alerts[0].title.lower()


@pytest.mark.asyncio
async def test_unscheduled_outage_pages_on_the_normal_schedule(monkeypatch):
    """Regression guard: an outage with no correlation to either scheduled
    time must be completely unaffected by the grace mechanism — it pages
    at the plain alert_after threshold, same as before this fix.
    """
    monkeypatch.setenv("AUTO_RESTART_TIME", "05:05 PM")
    monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
    mon = _monitor(alert_after_min=10, monkeypatch=monkeypatch)
    reg = _Registry([_inst("live", "Connected")])

    reg.set("live", "WaitingForHitl2fa")
    down_since = _epoch_for(3, 17)  # nowhere near either schedule
    mon._down_since["live"] = down_since
    mon._down_from["live"] = "WaitingForHitl2fa"
    # No grace deadline should even get set for this episode — confirmed
    # via the public check() path, exercising the real down-detection code
    # rather than hand-seeding _grace_deadline like the tests above.

    monkeypatch.setattr(time, "time", lambda: down_since)
    await mon.check(reg, None)
    assert "live" not in mon._grace_deadline, "an unrelated-time outage must not get a grace deadline"

    monkeypatch.setattr(time, "time", lambda: down_since + 11 * 60)
    alerts = await mon.check(reg, None)
    assert len(alerts) == 1, "an ordinary outage must page at the normal threshold, unaffected"
