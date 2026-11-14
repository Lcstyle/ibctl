"""The version check going blind: an alert when it can't see IB.

The weekly check feeds the desupport and update alerts. If its probe keeps
failing, IB's release files stay unreadable, or no check completes at all,
those alerts go quiet with nothing to say so. A week of failure is one alert,
and recovery is announced once.
"""

from __future__ import annotations

import json
from datetime import date, timedelta

from app.services.gateway_version.monitor import CHECK_FAILING_EVENT, evaluate_alerts
from app.services.gateway_version.probe import ProbeResult
from app.services.gateway_version.service import VersionState
from tests.test_gateway_version_alerts import state as version_state
from tests.test_gateway_version_check import Clock, Registry, connected, service, utc

SINCE = utc(2026, 11, 14, 17)


def everything(_event: str) -> bool:
    return True


def blind(s, now, enabled=everything):
    return [
        a
        for a in evaluate_alerts(s, today=now.date(), enabled=enabled, now=now)
        if a.event_type == CHECK_FAILING_EVENT
    ]


class TestTheCheckRecordsWhenItStartedFailing:
    async def test_a_failing_probe_keeps_the_time_of_its_first_failure(self, tmp_path):
        clock = Clock(SINCE)
        svc = service(
            tmp_path,
            Registry(paper=connected()),
            clock,
            probe_error="connect timed out",
        )

        await svc.run_check()
        clock.now = SINCE + timedelta(days=7)
        await svc.run_check()

        assert svc.current().probe_failing_since == SINCE

    async def test_a_probe_that_answers_clears_it(self, tmp_path):
        clock = Clock(SINCE)
        svc = service(
            tmp_path,
            Registry(paper=connected()),
            clock,
            probe_results=[
                ProbeResult(error="connect timed out"),
                ProbeResult(messages=[]),
            ],
        )

        await svc.run_check()
        clock.now = SINCE + timedelta(hours=2)
        await svc.run_check()

        assert svc.current().probe_failing_since is None

    async def test_no_connected_gateway_neither_starts_nor_clears_it(self, tmp_path):
        """With every Gateway down the probe can't be judged; the session
        alerts already cover a Gateway that is down."""
        clock = Clock(SINCE)
        registry = Registry(paper=connected())
        svc = service(tmp_path, registry, clock, probe_error="connect timed out")
        await svc.run_check()

        registry.modes = {"paper": {"state": "WaitingForLaunch"}}
        clock.now = SINCE + timedelta(days=1)
        await svc.run_check()

        assert svc.current().probe_failing_since == SINCE

        (tmp_path / "fresh").mkdir()
        fresh = service(
            tmp_path / "fresh",
            Registry(paper={"state": "WaitingForLaunch"}),
            Clock(SINCE),
        )
        await fresh.run_check()
        assert fresh.current().probe_failing_since is None

    async def test_unreadable_release_files_keep_the_time_of_the_first_failure(
        self, tmp_path
    ):
        clock = Clock(SINCE)
        svc = service(
            tmp_path,
            Registry(paper=connected()),
            clock,
            release_error=RuntimeError("HTTP 503"),
        )

        await svc.run_check()
        clock.now = SINCE + timedelta(days=7)
        await svc.run_check()

        assert svc.current().releases_failing_since == SINCE

    async def test_readable_release_files_clear_it(self, tmp_path):
        svc = service(tmp_path, Registry(paper=connected()), Clock(SINCE))

        await svc.run_check()

        assert svc.current().releases_failing_since is None


class TestSavedState:
    def test_the_failure_times_survive_a_restart(self):
        s = version_state(
            probe_failing_since=SINCE, releases_failing_since=SINCE + timedelta(hours=1)
        )

        back = VersionState.from_json(json.loads(json.dumps(s.to_json())))

        assert back.probe_failing_since == SINCE
        assert back.releases_failing_since == SINCE + timedelta(hours=1)

    def test_a_state_saved_before_these_fields_loads_as_not_failing(self):
        data = version_state().to_json()
        data.pop("probe_failing_since", None)
        data.pop("releases_failing_since", None)

        back = VersionState.from_json(data)

        assert back.probe_failing_since is None and back.releases_failing_since is None


class TestTheAlert:
    def test_a_probe_failing_for_a_week_alerts_once(self):
        s = version_state(probe_failing_since=SINCE, probe_error="connect timed out")
        now = SINCE + timedelta(days=7)

        first = blind(s, now)
        again = blind(s, now + timedelta(hours=1))

        assert len(first) == 1
        assert first[0].priority == "high"
        assert "connect timed out" in first[0].body
        assert "desupport" in first[0].body, "it says which alerts are blind"
        assert again == []

    def test_under_a_week_is_not_an_alert_yet(self):
        s = version_state(probe_failing_since=SINCE, probe_error="connect timed out")

        assert blind(s, SINCE + timedelta(days=7) - timedelta(minutes=1)) == []

    def test_release_files_unreadable_for_a_week_alert(self):
        s = version_state(
            releases_failing_since=SINCE,
            release_errors={"stable": "RuntimeError: HTTP 503"},
        )

        alerts = blind(s, SINCE + timedelta(days=7))

        assert len(alerts) == 1 and "HTTP 503" in alerts[0].body

    def test_no_completed_check_for_eight_days_alerts(self):
        s = version_state(checked_at=SINCE)

        assert blind(s, SINCE + timedelta(days=8) - timedelta(minutes=1)) == []
        alerts = blind(s, SINCE + timedelta(days=8))
        assert (
            len(alerts) == 1
            and "no version check has completed" in alerts[0].body.lower()
        )

    def test_a_second_cause_is_a_new_alert(self):
        s = version_state(probe_failing_since=SINCE, probe_error="connect timed out")
        now = SINCE + timedelta(days=7)
        blind(s, now)

        s.releases_failing_since = SINCE + timedelta(days=1)
        s.release_errors = {"latest": "RuntimeError: HTTP 503"}

        assert len(blind(s, SINCE + timedelta(days=8))) == 1

    def test_recovery_is_announced_once(self):
        s = version_state(probe_failing_since=SINCE, probe_error="connect timed out")
        blind(s, SINCE + timedelta(days=7))

        s.probe_failing_since, s.probe_error = None, None
        s.checked_at = SINCE + timedelta(days=7, hours=12)  # the check that answered
        back = blind(s, SINCE + timedelta(days=8))
        again = blind(s, SINCE + timedelta(days=8, hours=1))

        assert len(back) == 1 and back[0].priority == "default"
        assert "working again" in back[0].title
        assert again == []

    def test_a_disabled_event_sends_nothing_and_stays_owed(self):
        s = version_state(probe_failing_since=SINCE, probe_error="connect timed out")
        now = SINCE + timedelta(days=7)

        assert blind(s, now, enabled=lambda e: e != CHECK_FAILING_EVENT) == []
        assert len(blind(s, now)) == 1

    def test_without_a_time_there_is_no_blind_check(self):
        s = version_state(probe_failing_since=SINCE, probe_error="connect timed out")

        alerts = evaluate_alerts(s, today=date(2026, 11, 30), enabled=everything)

        assert [a for a in alerts if a.event_type == CHECK_FAILING_EVENT] == []
