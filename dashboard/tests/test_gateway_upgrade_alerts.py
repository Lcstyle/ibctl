"""Telling the operator about automatic Gateway upgrades before they happen.

The Sunday maintenance job already reports what a swap did. These alerts come
earlier: an upgrade is planned for Sunday, its image is built, it was called
off, or it can't happen. 2026-11-15 is the Sunday; ET is UTC-5 that week.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import date, datetime
from zoneinfo import ZoneInfo

from app.services.gateway_version.desupport import DesupportNotice
from app.services.gateway_version.monitor import GatewayVersionMonitor, evaluate_alerts
from app.services.gateway_version.policy import UpgradePolicy
from app.services.gateway_version.releases import ChannelRelease
from app.services.gateway_version.service import VersionState
from app.services.gateway_version.upgrade import (
    BuildReport,
    UpgradeRecord,
    UpgradeStore,
)
from app.services.gateway_version.upgrade_alerts import (
    BLOCKED_EVENT,
    SCHEDULED_EVENT,
    desupport_note,
    upgrade_alerts,
)
from app.services.gateway_version.versions import GatewayVersion
from tests.test_gateway_version_alerts import LATEST
from tests.test_gateway_version_alerts import state as version_state

V = GatewayVersion.parse
ET = ZoneInfo("America/New_York")
ON = UpgradePolicy(
    enabled=True,
    channel="stable",
    cadence="every_sunday",
    soak_days=7,
    deadline_days=21,
)
OFF = UpgradePolicy(enabled=False)
SHA = "c" * 40
NEAR_CUTOFF = DesupportNotice(
    running=V("1047.1"), cutoff=date(2026, 11, 30), minimum=V("1050.1")
)


def et(y, mo, d, h=12, mi=0) -> datetime:
    return datetime(y, mo, d, h, mi, tzinfo=ET)


def vs(**kw) -> VersionState:
    """Running 10.47.1b; stable 10.50.1f has been out since 2026-10-05; no desupport notice."""
    kw.setdefault("notice", None)
    return version_state(**kw)


def built(version="10.50.1f", status="built", at=None) -> UpgradeRecord:
    return UpgradeRecord(
        candidate=BuildReport(
            version, SHA, status, at or et(2026, 11, 14, 14), "pipeline-97"
        )
    )


def everything(_event: str) -> bool:
    return True


def run(s, *, policy=ON, record=None, now=None, enabled=everything):
    return upgrade_alerts(
        policy, s, record or UpgradeRecord(), now or et(2026, 11, 9), enabled
    )


def of(alerts, event):
    return [a for a in alerts if a.event_type == event]


class TestScheduled:
    def test_a_due_upgrade_is_announced_once_ahead_of_its_sunday(self):
        s = vs()

        first = run(s, now=et(2026, 11, 9))
        again = run(s, now=et(2026, 11, 10))

        assert [a.event_type for a in first] == [SCHEDULED_EVENT]
        a = first[0]
        assert "10.50.1f" in a.title and "Nov 15" in a.title
        assert a.priority == "high"
        for words in ("PAPER", "LIVE", "2FA", "09:00 ET", "Gateway tab"):
            assert words in a.body, words
        assert again == []

    def test_a_new_target_for_the_same_sunday_is_announced_again(self):
        s = vs()
        run(s)
        s.releases = {
            "stable": ChannelRelease("stable", V("10.50.2a"), date(2026, 10, 20)),
            "latest": LATEST,
        }

        again = run(s, now=et(2026, 11, 11))

        assert len(again) == 1 and "10.50.2a" in again[0].title

    def test_the_built_candidate_is_announced_once(self):
        s = vs()
        run(s)

        ready = run(s, record=built(), now=et(2026, 11, 14, 15))
        again = run(s, record=built(), now=et(2026, 11, 14, 16))

        assert [a.event_type for a in ready] == [SCHEDULED_EVENT]
        assert "built" in ready[0].title and SHA[:12] in ready[0].body
        assert again == []

    def test_turning_upgrades_off_before_the_sunday_says_so_once(self):
        s = vs()
        run(s)

        off = run(s, policy=OFF, now=et(2026, 11, 12))
        again = run(s, policy=OFF, now=et(2026, 11, 13))

        assert [a.event_type for a in off] == [SCHEDULED_EVENT]
        assert off[0].priority == "default"
        assert "10.50.1f" in off[0].title
        assert "automatic upgrades are off" in off[0].body
        assert again == []

    def test_no_called_off_message_once_the_upgrade_is_in(self):
        s = vs()
        run(s)
        s.running = "10.50.1f"

        assert run(s, now=et(2026, 11, 15, 10)) == []

    def test_a_plan_whose_sunday_has_passed_is_dropped_silently(self):
        s = vs()
        run(s)

        # Monday after: under first_sunday the next Sunday (Nov 22) is not an upgrade Sunday.
        assert (
            run(s, policy=replace(ON, cadence="first_sunday"), now=et(2026, 11, 16))
            == []
        )
        assert (
            run(s, policy=replace(ON, cadence="first_sunday"), now=et(2026, 11, 17))
            == []
        )

    def test_upgrades_off_from_the_start_say_nothing(self):
        assert run(vs(), policy=OFF) == []

    def test_a_disabled_event_sends_nothing_and_stays_owed(self):
        s = vs()

        assert run(s, enabled=lambda e: e != SCHEDULED_EVENT) == []
        assert of(run(s), SCHEDULED_EVENT) != []

    def test_what_was_sent_survives_a_restart(self):
        s = vs()
        run(s)

        restored = VersionState.from_json(json.loads(json.dumps(s.to_json())))

        assert run(restored, now=et(2026, 11, 10)) == []


class TestWontHappen:
    def test_a_failed_build_is_reported_at_once(self):
        s = vs()
        run(s)

        failed = of(
            run(s, record=built(status="failed"), now=et(2026, 11, 14, 14, 30)),
            BLOCKED_EVENT,
        )
        again = of(
            run(s, record=built(status="failed"), now=et(2026, 11, 14, 15)),
            BLOCKED_EVENT,
        )

        assert len(failed) == 1
        assert failed[0].priority == "high"
        assert "10.50.1f" in failed[0].title and "failed" in failed[0].title
        assert "pipeline-97" in failed[0].body
        assert again == []

    def test_nothing_built_by_saturday_evening_is_reported(self):
        s = vs()
        run(s)

        before = run(s, now=et(2026, 11, 14, 17, 59))
        late = run(s, now=et(2026, 11, 14, 18, 0))

        assert before == []
        assert [a.event_type for a in late] == [BLOCKED_EVENT]
        assert "nothing" in late[0].title.lower()

    def test_a_candidate_for_another_version_counts_as_nothing_built(self):
        s = vs()
        run(s)

        late = run(s, record=built(version="10.49.1a"), now=et(2026, 11, 14, 19))

        assert [a.event_type for a in late] == [BLOCKED_EVENT]
        assert "10.49.1a" in late[0].body

    def test_from_the_sunday_window_on_the_maintenance_job_reports_instead(self):
        s = vs()
        run(s)

        assert run(s, now=et(2026, 11, 15, 9, 0)) == []

    def test_a_desupport_deadline_makes_it_urgent(self):
        s = vs(notice=NEAR_CUTOFF)
        run(s)

        late = of(run(s, now=et(2026, 11, 14, 18, 30)), BLOCKED_EVENT)

        assert [a.priority for a in late] == ["urgent"]


class TestDesupportNote:
    """What the desupport alert says about automatic upgrades."""

    def test_upgrades_off_says_nothing_will_fix_it(self):
        note = desupport_note(OFF, vs(notice=NEAR_CUTOFF), date(2026, 11, 9))

        assert "Automatic upgrades are off" in note

    def test_an_unreadable_policy_says_so(self):
        assert "can't be read" in desupport_note(
            None, vs(notice=NEAR_CUTOFF), date(2026, 11, 9)
        )

    def test_a_planned_upgrade_names_the_build_and_the_sunday(self):
        note = desupport_note(ON, vs(notice=NEAR_CUTOFF), date(2026, 11, 9))

        assert "10.50.1f" in note and "Nov 15" in note

    def test_no_build_at_the_minimum_yet_says_so(self):
        notice = DesupportNotice(
            running=V("1047.1"), cutoff=date(2026, 11, 30), minimum=V("1052.1")
        )

        note = desupport_note(ON, vs(notice=notice), date(2026, 11, 9))

        assert "can't" in note and str(notice.minimum) in note

    def test_a_far_cutoff_says_when_upgrades_step_in(self):
        """Dec 15 is 30 days after Nov 15, past the 21-day deadline, and Nov 15
        is not a first Sunday, so nothing is due yet."""
        notice = DesupportNotice(
            running=V("1047.1"), cutoff=date(2026, 12, 15), minimum=V("1050.1")
        )

        note = desupport_note(
            replace(ON, cadence="first_sunday"), vs(notice=notice), date(2026, 11, 9)
        )

        assert "21 days" in note

    def test_the_desupport_alert_ends_with_the_note(self):
        alerts = evaluate_alerts(
            vs(notice=NEAR_CUTOFF),
            today=date(2026, 11, 9),
            enabled=everything,
            desupport_note="Automatic upgrades are off (Gateway tab).",
        )

        body = of(alerts, "gateway_desupport")[0].body
        assert body.endswith("Automatic upgrades are off (Gateway tab).")
        assert "Upgrade the Gateway image before the cutoff" not in body


class _NS:
    def is_event_enabled(self, _event):
        return True


class _Service:
    """The version service as the monitor uses it, with a saved state."""

    def __init__(self, state: VersionState, now: datetime):
        self._state, self._now, self.saved = state, now, 0

    def due(self):
        return False

    def start_check(self):
        return False

    def current(self):
        return self._state

    def save(self):
        self.saved += 1

    def now(self):
        return self._now


class TestMonitorWiring:
    async def test_the_monitor_sends_upgrade_alerts_from_the_saved_policy(
        self, tmp_path
    ):
        store = UpgradeStore(
            policy_path=tmp_path / "policy.json", record_path=tmp_path / "upgrade.json"
        )
        store.set_policy(ON)
        svc = _Service(vs(), now=et(2026, 11, 9))
        monitor = GatewayVersionMonitor(
            svc, today=lambda: date(2026, 11, 9), upgrades=store
        )

        alerts = await monitor.check(None, _NS())

        assert len(of(alerts, SCHEDULED_EVENT)) == 1
        assert svc.saved == 1, "what was sent is saved, so a restart repeats none"

    async def test_without_an_upgrade_store_the_monitor_sends_only_version_alerts(
        self, tmp_path
    ):
        svc = _Service(vs(), now=et(2026, 11, 9))

        alerts = await GatewayVersionMonitor(
            svc, today=lambda: date(2026, 11, 9)
        ).check(None, _NS())

        assert of(alerts, SCHEDULED_EVENT) == []

    async def test_the_desupport_alert_says_upgrades_are_off(self, tmp_path):
        store = UpgradeStore(
            policy_path=tmp_path / "policy.json", record_path=tmp_path / "upgrade.json"
        )
        svc = _Service(vs(notice=NEAR_CUTOFF), now=et(2026, 11, 9))

        alerts = await GatewayVersionMonitor(
            svc, today=lambda: date(2026, 11, 9), upgrades=store
        ).check(None, _NS())

        assert "Automatic upgrades are off" in of(alerts, "gateway_desupport")[0].body
