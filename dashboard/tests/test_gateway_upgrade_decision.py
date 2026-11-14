"""Gateway upgrades: the policy and the decision it leads to."""

from __future__ import annotations

import json
from datetime import date, datetime, timezone

import pytest

from app.services.gateway_version.decision import decide, next_sunday
from app.services.gateway_version.desupport import DesupportNotice
from app.services.gateway_version.policy import PolicyError, UpgradePolicy, load_policy, save_policy
from app.services.gateway_version.releases import ChannelRelease
from app.services.gateway_version.service import VersionState
from app.services.gateway_version.versions import GatewayVersion

V = GatewayVersion.parse
SAT_NOV_14 = date(2026, 11, 14)  # the Saturday check; the swap Sunday is Nov 15
SAT_NOV_28 = date(2026, 11, 28)  # the Sunday after is Nov 29, the last Sunday of the month
SAT_DEC_5 = date(2026, 12, 5)  # the Sunday after is Dec 6, the first Sunday of December


def rel(channel: str, version: str, released: date) -> ChannelRelease:
    return ChannelRelease(channel, V(version), released)


def state(running="10.50.1f", history=None, notice=None) -> VersionState:
    history = history or {}
    return VersionState(
        running=running,
        channel="stable",
        checked_at=datetime(2026, 11, 14, 17, tzinfo=timezone.utc),
        releases={c: max(rs, key=lambda r: r.version) for c, rs in history.items() if rs},
        history=history,
        notice=notice,
    )


ON = UpgradePolicy(enabled=True, channel="stable", cadence="every_sunday", soak_days=7, deadline_days=21)


class TestNextSunday:
    def test_saturday_looks_at_tomorrow(self):
        assert next_sunday(SAT_NOV_14) == date(2026, 11, 15)

    def test_sunday_is_today(self):
        assert next_sunday(date(2026, 11, 15)) == date(2026, 11, 15)

    def test_monday_looks_six_days_ahead(self):
        assert next_sunday(date(2026, 11, 16)) == date(2026, 11, 22)


class TestPolicy:
    def test_the_default_is_off_and_stable(self):
        policy = UpgradePolicy()
        assert policy.enabled is False
        assert policy.channel == "stable"

    @pytest.mark.parametrize("field, value", [
        ("channel", "beta"),
        ("cadence", "fortnightly"),
        ("soak_days", -1),
        ("soak_days", 91),
        ("deadline_days", -1),
        ("deadline_days", 91),
    ])
    def test_a_bad_value_is_refused(self, field, value):
        with pytest.raises(PolicyError):
            UpgradePolicy(**{field: value})

    def test_it_round_trips_through_the_file(self, tmp_path):
        path = tmp_path / "config" / "gateway_upgrade_policy.json"

        save_policy(path, ON)

        assert load_policy(path) == ON
        assert not list(path.parent.glob("*.tmp")), "the save is atomic: no temp file left behind"

    def test_no_file_means_the_default(self, tmp_path):
        assert load_policy(tmp_path / "missing.json") == UpgradePolicy()

    def test_an_unreadable_file_is_an_error_not_the_default(self, tmp_path):
        # Falling back to the default here would silently switch upgrades off
        # (or, for a future default, on); the operator has to see it.
        path = tmp_path / "policy.json"
        path.write_text("{not json")

        with pytest.raises(PolicyError):
            load_policy(path)

    def test_an_invalid_saved_value_is_an_error(self, tmp_path):
        path = tmp_path / "policy.json"
        path.write_text(json.dumps({"enabled": True, "channel": "nightly"}))

        with pytest.raises(PolicyError):
            load_policy(path)


class TestDecide:
    HISTORY = {
        "stable": [rel("stable", "10.50.1f", date(2026, 10, 5)), rel("stable", "10.51.1h", date(2026, 11, 2))],
        "latest": [rel("latest", "10.51.1e", date(2026, 10, 26)), rel("latest", "10.52.1a", date(2026, 11, 12))],
    }

    def test_off_is_never_due(self):
        d = decide(UpgradePolicy(), state(history=self.HISTORY), SAT_NOV_14)

        assert not d.due
        assert d.reason == "automatic upgrades are off"

    def test_a_soaked_newer_build_on_the_channel_is_due(self):
        d = decide(ON, state(history=self.HISTORY), SAT_NOV_14)

        assert d.due
        assert (d.target, d.channel, d.swap_on) == ("10.51.1h", "stable", date(2026, 11, 15))
        assert "13 days" in d.reason

    def test_a_build_younger_than_the_soak_waits(self):
        policy = UpgradePolicy(enabled=True, channel="latest", cadence="every_sunday", soak_days=7)
        # 10.52.1a is 3 days old on Nov 15; 10.51.1e (20 days) is the newest that has soaked.
        d = decide(policy, state(running="10.50.1f", history=self.HISTORY), SAT_NOV_14)

        assert d.due and d.target == "10.51.1e"

    def test_a_build_out_exactly_the_soak_on_the_sunday_qualifies(self):
        sunday = date(2026, 11, 15)
        exact = {"stable": [rel("stable", "10.51.1h", date(2026, 11, 8))]}  # 7 days before the Sunday
        short = {"stable": [rel("stable", "10.51.1h", date(2026, 11, 9))]}  # 6 days

        assert decide(ON, state(history=exact), SAT_NOV_14).due
        assert not decide(ON, state(history=short), SAT_NOV_14).due
        assert next_sunday(SAT_NOV_14) == sunday

    def test_nothing_soaked_and_newer_says_what_it_waits_for(self):
        policy = UpgradePolicy(enabled=True, channel="latest", cadence="every_sunday", soak_days=7)

        d = decide(policy, state(running="10.51.1e", history=self.HISTORY), SAT_NOV_14)

        assert not d.due
        assert "10.52.1a" in d.reason and "3 of 7 days" in d.reason

    def test_running_the_newest_build_is_not_due(self):
        d = decide(ON, state(running="10.51.1h", history=self.HISTORY), SAT_NOV_14)

        assert not d.due
        assert d.reason == "10.51.1h is the newest stable build"

    def test_first_sunday_cadence_skips_other_sundays(self):
        policy = UpgradePolicy(enabled=True, channel="stable", cadence="first_sunday", soak_days=7)

        assert not decide(policy, state(history=self.HISTORY), SAT_NOV_28).due
        assert decide(policy, state(history=self.HISTORY), SAT_DEC_5).due

    def test_an_unknown_running_version_is_never_due(self):
        d = decide(ON, state(running=None, history=self.HISTORY), SAT_NOV_14)

        assert not d.due and "running version" in d.reason


class TestDeadlineOverride:
    """IB's cutoff close enough beats the cadence and the soak."""

    def notice(self, cutoff: date, minimum="1051.1") -> DesupportNotice:
        return DesupportNotice(running=V("1050.1"), cutoff=cutoff, minimum=V(minimum))

    def test_a_near_cutoff_is_due_regardless_of_cadence_and_soak(self):
        policy = UpgradePolicy(enabled=True, channel="stable", cadence="first_sunday", soak_days=30, deadline_days=21)
        history = {"stable": [rel("stable", "10.50.1f", date(2026, 10, 5)), rel("stable", "10.51.1h", date(2026, 11, 12))]}

        d = decide(policy, state(history=history, notice=self.notice(date(2026, 12, 1))), SAT_NOV_28)

        assert d.due and d.deadline
        assert d.target == "10.51.1h"
        assert "2026-12-01" in d.reason

    def test_a_far_cutoff_follows_the_normal_rules(self):
        policy = UpgradePolicy(enabled=True, channel="stable", cadence="first_sunday", soak_days=7, deadline_days=21)
        history = {"stable": [rel("stable", "10.50.1f", date(2026, 10, 5)), rel("stable", "10.51.1h", date(2026, 11, 2))]}

        d = decide(policy, state(history=history, notice=self.notice(date(2027, 1, 31))), SAT_NOV_28)

        assert not d.due and not d.deadline

    def test_the_other_channel_is_used_when_the_tracked_one_has_no_qualifying_build(self):
        history = {
            "stable": [rel("stable", "10.50.1f", date(2026, 10, 5))],
            "latest": [rel("latest", "10.51.1e", date(2026, 10, 26))],
        }

        d = decide(ON, state(history=history, notice=self.notice(date(2026, 11, 30))), SAT_NOV_14)

        assert d.due and (d.target, d.channel) == ("10.51.1e", "latest")

    def test_no_build_meeting_the_minimum_says_so(self):
        history = {"stable": [rel("stable", "10.50.1f", date(2026, 10, 5))]}

        d = decide(ON, state(history=history, notice=self.notice(date(2026, 11, 30), minimum="1052.1")), SAT_NOV_14)

        assert not d.due and d.deadline
        assert "10.52.1" in d.reason

    def test_off_still_means_off(self):
        history = {"stable": [rel("stable", "10.51.1h", date(2026, 11, 2))]}

        d = decide(UpgradePolicy(), state(history=history, notice=self.notice(date(2026, 11, 20))), SAT_NOV_14)

        assert not d.due


class TestDecisionJson:
    def test_dates_are_labels_not_instants(self):
        d = decide(ON, state(history=TestDecide.HISTORY), SAT_NOV_14)

        out = d.to_json()

        assert out["swap_on"] == "2026-11-15"
        assert set(out) == {"due", "swap_on", "target", "channel", "reason", "deadline"}
