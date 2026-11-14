"""Gateway version tracking — what the operator sees and is told.

Alerts are evaluated from the saved check result, so the countdown keeps
working between weekly checks and no alert is ever repeated after a restart.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from types import SimpleNamespace

from app.services.gateway_version.desupport import DesupportNotice
from app.services.gateway_version.monitor import GatewayVersionMonitor, evaluate_alerts
from app.services.gateway_version.releases import ChannelRelease
from app.services.gateway_version.service import GatewayVersionService, VersionState
from app.services.gateway_version.versions import GatewayVersion
from app.services.gateway_version.view import version_view

V = GatewayVersion.parse
NOTICE = DesupportNotice(running=V("1047.1"), cutoff=date(2026, 12, 15), minimum=V("1050.1"))
STABLE = ChannelRelease("stable", V("10.50.1f"), date(2026, 10, 5))
LATEST = ChannelRelease("latest", V("10.51.1e"), date(2026, 10, 26))


def state(**kw) -> VersionState:
    base = dict(
        running="10.47.1b",
        channel="stable",
        checked_at=datetime(2026, 11, 14, 17, tzinfo=timezone.utc),
        releases={"stable": STABLE, "latest": LATEST},
        probed_mode="paper",
        last_probe_at=datetime(2026, 11, 14, 17, tzinfo=timezone.utc),
        notice=NOTICE,
        notice_first_seen=datetime(2026, 11, 14, 17, tzinfo=timezone.utc),
    )
    base.update(kw)
    return VersionState(**base)


def everything_enabled(_event: str) -> bool:
    return True


def titles(alerts) -> list[str]:
    return [a.title for a in alerts]


class TestDesupportAlerts:
    def test_a_new_cutoff_is_announced_once(self):
        s = state()

        first = evaluate_alerts(s, today=date(2026, 11, 9), enabled=everything_enabled)
        again = evaluate_alerts(s, today=date(2026, 11, 9), enabled=everything_enabled)

        desupport = [a for a in first if a.event_type == "gateway_desupport"]
        assert len(desupport) == 1
        assert "2026-12-15" in desupport[0].title and "10.47.1" in desupport[0].title
        assert desupport[0].priority == "high", "36 days out is a warning, not yet urgent"
        assert "36 days" in desupport[0].body and "10.50.1" in desupport[0].body
        assert [a for a in again if a.event_type == "gateway_desupport"] == []

    def test_the_countdown_alerts_at_30_14_7_2_and_0_days_once_each(self):
        s = state()
        evaluate_alerts(s, today=date(2026, 11, 9), enabled=everything_enabled)
        sent = []
        day = date(2026, 11, 9)
        while day <= date(2026, 12, 20):
            for alert in evaluate_alerts(s, today=day, enabled=everything_enabled):
                if alert.event_type == "gateway_desupport":
                    sent.append((NOTICE.days_left(day), alert.priority))
            day = date.fromordinal(day.toordinal() + 1)

        assert sent == [(30, "urgent"), (14, "urgent"), (7, "urgent"), (2, "urgent"), (0, "urgent")]

    def test_first_seen_inside_the_window_is_one_urgent_alert_not_a_burst(self):
        s = state()

        alerts = evaluate_alerts(s, today=date(2026, 12, 10), enabled=everything_enabled)  # 5 days left

        desupport = [a for a in alerts if a.event_type == "gateway_desupport"]
        assert [a.priority for a in desupport] == ["urgent"]
        assert evaluate_alerts(s, today=date(2026, 12, 11), enabled=everything_enabled) == []
        assert [a.priority for a in evaluate_alerts(s, today=date(2026, 12, 13), enabled=everything_enabled)] == ["urgent"]

    def test_when_ib_stops_warning_the_operator_hears_it_once(self):
        s = state()
        evaluate_alerts(s, today=date(2026, 11, 9), enabled=everything_enabled)
        s.notice, s.running = None, "10.50.1f"

        resolved = evaluate_alerts(s, today=date(2026, 11, 22), enabled=everything_enabled)

        assert [a.event_type for a in resolved] == ["gateway_desupport"]
        assert "no longer" in resolved[0].body
        assert evaluate_alerts(s, today=date(2026, 11, 23), enabled=everything_enabled) == []

    def test_a_notice_that_returns_after_resolving_is_announced_again(self):
        s = state()
        evaluate_alerts(s, today=date(2026, 11, 9), enabled=everything_enabled)
        s.notice = None
        evaluate_alerts(s, today=date(2026, 11, 22), enabled=everything_enabled)
        s.notice = NOTICE

        again = evaluate_alerts(s, today=date(2026, 11, 29), enabled=everything_enabled)

        assert [a.event_type for a in again if a.event_type == "gateway_desupport"] == ["gateway_desupport"]

    def test_a_disabled_event_sends_nothing_and_stays_owed(self):
        s = state()

        assert evaluate_alerts(s, today=date(2026, 11, 9), enabled=lambda e: e != "gateway_desupport")[:0] == []
        later = evaluate_alerts(s, today=date(2026, 11, 9), enabled=everything_enabled)

        assert "gateway_desupport" in [a.event_type for a in later]

    def test_once_the_running_version_meets_the_minimum_the_countdown_stops(self):
        """Upgraded, but the stored notice predates it; the next check confirms."""
        s = state(running="10.50.1f")
        evaluate_alerts(s, today=date(2026, 11, 9), enabled=everything_enabled)

        alerts = evaluate_alerts(s, today=date(2026, 12, 14), enabled=everything_enabled)

        assert [a for a in alerts if a.event_type == "gateway_desupport"] == []


class TestUpdateAlerts:
    def test_a_newer_build_on_our_channel_is_announced_once_per_build(self):
        s = state(notice=None)

        first = evaluate_alerts(s, today=date(2026, 11, 9), enabled=everything_enabled)
        again = evaluate_alerts(s, today=date(2026, 11, 10), enabled=everything_enabled)

        update = [a for a in first if a.event_type == "gateway_update"]
        assert len(update) == 1 and "10.50.1f" in update[0].title
        assert update[0].priority == "default"
        assert again == []

    def test_no_update_alert_when_current_or_ahead(self):
        for running in ("10.50.1f", "10.51.1e"):
            s = state(notice=None, running=running)
            assert evaluate_alerts(s, today=date(2026, 11, 9), enabled=everything_enabled) == []

    def test_the_latest_channel_compares_against_latest(self):
        s = state(notice=None, running="10.50.1f", channel="latest")

        alerts = evaluate_alerts(s, today=date(2026, 11, 9), enabled=everything_enabled)

        assert ["10.51.1e" in a.title for a in alerts] == [True]


class TestOnlyTheActiveSiteAlerts:
    def test_a_site_with_no_logged_in_gateway_sends_nothing(self):
        """The standby's dashboard runs too; it must not duplicate every alert."""
        s = state(probed_mode=None, last_probe_at=None, notice=None)

        assert evaluate_alerts(s, today=date(2026, 11, 9), enabled=everything_enabled) == []


class TestView:
    def test_below_the_minimum(self):
        view = version_view(state(), today=date(2026, 11, 9))

        assert view["status"] == "below_minimum"
        assert view["health"] == "error"
        assert view["days_left"] == 36
        assert view["running"] == "10.47.1b"
        assert view["available"] == {"stable": "10.50.1f", "latest": "10.51.1e"}

    def test_upgraded_and_waiting_for_ib_to_confirm(self):
        view = version_view(state(running="10.50.1f"), today=date(2026, 11, 9))

        assert view["status"] == "upgraded_pending_confirmation"
        assert view["health"] == "warning"

    def test_behind_the_channel(self):
        view = version_view(state(notice=None, running="10.50.1e"), today=date(2026, 11, 9))

        assert (view["status"], view["health"]) == ("behind", "warning")

    def test_current(self):
        view = version_view(state(notice=None, running="10.50.1f"), today=date(2026, 11, 9))

        assert (view["status"], view["health"]) == ("current", "ok")
        assert view["days_left"] is None

    def test_never_checked(self):
        view = version_view(VersionState(running="10.50.1f"), today=date(2026, 11, 9))

        assert view["status"] == "unknown"
        assert view["checked_at"] is None


class _Registry:
    def cached_all_status(self):
        return [SimpleNamespace(mode="paper", status={"state": "Connected", "clients": {"count": 2}})]


class _NS:
    def is_event_enabled(self, _event):
        return True


class TestMonitor:
    async def test_it_starts_a_due_check_and_returns_alerts_from_the_saved_state(self, tmp_path):
        started = []

        async def fetch(channel):
            return {"stable": STABLE, "latest": LATEST}[channel]

        async def probe(mode, client_id):
            started.append(mode)
            from app.services.gateway_version.probe import ProbeResult
            return ProbeResult(messages=[(2172, "The version of the application you are running, 1047.1, needs to be upgraded, as it will be desupported on 20261215. The minimum supported version at that time will be 1050.1.")])

        svc = GatewayVersionService(
            _Registry(), fetch_release=fetch, probe_mode=probe, state_path=tmp_path / "gv.json",
            running_version="10.47.1b", channel="stable",
            clock=lambda: datetime(2026, 11, 14, 17, tzinfo=timezone.utc),
        )
        monitor = GatewayVersionMonitor(svc, today=lambda: date(2026, 11, 14))

        assert await monitor.check(_Registry(), _NS()) == [], "nothing known before the first check"
        await svc.wait_for_check()
        alerts = await monitor.check(_Registry(), _NS())

        assert started == ["paper"]
        assert sorted(a.event_type for a in alerts) == ["gateway_desupport", "gateway_update"]
        reloaded = GatewayVersionService(
            _Registry(), fetch_release=fetch, probe_mode=probe, state_path=tmp_path / "gv.json",
            running_version="10.47.1b", clock=lambda: datetime(2026, 11, 14, 17, tzinfo=timezone.utc),
        )
        assert await GatewayVersionMonitor(reloaded, today=lambda: date(2026, 11, 14)).check(_Registry(), _NS()) == [], (
            "alerts already sent must not repeat after a restart"
        )

    async def test_an_upgrade_triggers_a_check_at_once(self, tmp_path):
        """The image changed since the last check: confirm with IB now, not Saturday."""
        checked = []

        async def fetch(channel):
            return {"stable": STABLE, "latest": LATEST}[channel]

        async def probe(mode, client_id):
            checked.append(mode)
            from app.services.gateway_version.probe import ProbeResult
            return ProbeResult(messages=[])

        clock = lambda: datetime(2026, 11, 16, 15, tzinfo=timezone.utc)  # a Monday
        path = tmp_path / "gv.json"
        old = GatewayVersionService(_Registry(), fetch_release=fetch, probe_mode=probe, state_path=path,
                                    running_version="10.47.1b", clock=clock)
        await old.run_check()
        checked.clear()

        upgraded = GatewayVersionService(_Registry(), fetch_release=fetch, probe_mode=probe, state_path=path,
                                         running_version="10.50.1f", clock=clock)
        assert upgraded.due()
        await GatewayVersionMonitor(upgraded, today=lambda: date(2026, 11, 16)).check(_Registry(), _NS())
        await upgraded.wait_for_check()
        assert checked == ["paper"]
