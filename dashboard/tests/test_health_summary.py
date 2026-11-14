"""The health summary anonymous visitors see is built field by field."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from app.domain.instance import InstanceStatus
from app.services.health_summary import build_health_summary

NOW = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)


class FakeRegistry:
    def __init__(self, instances: list[InstanceStatus], ages: dict[str, float] | None = None):
        self._instances = instances
        self._ages = ages or {}

    def cached_all_status(self):
        return self._instances

    def cache_age(self, mode):
        return self._ages.get(mode)


def summary(status, *, mode="paper", age=None, gateway_version=None):
    registry = FakeRegistry([InstanceStatus(mode=mode, status=status)], {mode: age} if age is not None else {})
    return build_health_summary(registry, gateway_version, now=NOW)


def gateway(running):
    return SimpleNamespace(current=lambda: SimpleNamespace(running=running))


def test_a_connected_mode_reports_state_readiness_since_and_version():
    entry = summary(
        {"state": "Connected", "ready": True, "connected_uptime_secs": 3600, "version": "1.3.0"}
    )["modes"][0]
    assert entry == {
        "mode": "paper",
        "state": "Connected",
        "api_ready": True,
        "since": "2026-11-14T11:00:00Z",
        "ibctl_version": "1.3.0",
    }


def test_since_allows_for_how_old_the_cached_status_is():
    entry = summary({"state": "Connected", "ready": True, "connected_uptime_secs": 3600}, age=90.0)["modes"][0]
    assert entry["since"] == "2026-11-14T10:58:30Z"


def test_since_is_only_given_while_the_api_is_ready():
    assert summary({"state": "Disconnected", "ready": False, "connected_uptime_secs": 3600})["modes"][0]["since"] is None
    assert summary({"state": "Connected", "ready": True})["modes"][0]["since"] is None
    assert summary({"state": "Connected", "ready": True, "connected_uptime_secs": None})["modes"][0]["since"] is None


def test_uptime_that_is_not_a_number_is_ignored():
    for bad in (True, "3600", -5, [1]):
        entry = summary({"state": "Connected", "ready": True, "connected_uptime_secs": bad})["modes"][0]
        assert entry["since"] is None, bad


def test_ready_means_exactly_true():
    for not_true in ("yes", 1, "true", None):
        assert summary({"state": "Connected", "ready": not_true})["modes"][0]["api_ready"] is False


def test_only_the_whitelisted_fields_come_out():
    status = {
        "state": "Connected",
        "ready": True,
        "version": "1.3.0",
        "account": "DU1234567",
        "tws_userid": "someone",
        "jvm": {"config_dir": "/x/someone"},
        "clients": {"ids": ["DU1234567"]},
    }
    result = summary(status, gateway_version=gateway("10.50.1f"))
    assert set(result) == {"status", "modes", "gateway_version"}
    assert set(result["modes"][0]) == {"mode", "state", "api_ready", "since", "ibctl_version"}
    text = str(result)
    assert "DU1234567" not in text and "someone" not in text


def test_text_that_does_not_look_like_a_state_or_version_is_dropped():
    entry = summary({"state": "Connected</td><script>", "ready": True, "version": "x" * 200})["modes"][0]
    assert entry["state"] == "unknown"
    assert entry["ibctl_version"] is None
    assert summary({"state": 7, "version": {"a": 1}})["modes"][0]["state"] == "unknown"


def test_a_mode_with_no_status_yet_is_unknown_and_not_ready():
    registry = FakeRegistry([InstanceStatus(mode="live", error="Starting up")])
    entry = build_health_summary(registry, None, now=NOW)["modes"][0]
    assert entry == {"mode": "live", "state": "unknown", "api_ready": False, "since": None, "ibctl_version": None}


def test_gateway_version_comes_from_the_version_service():
    assert summary({"state": "Connected"}, gateway_version=gateway("10.50.1f"))["gateway_version"] == "10.50.1f"
    assert summary({"state": "Connected"}, gateway_version=gateway(None))["gateway_version"] is None
    assert summary({"state": "Connected"}, gateway_version=None)["gateway_version"] is None
    assert summary({"state": "Connected"}, gateway_version=gateway("not a version!"))["gateway_version"] is None


def test_the_liveness_flag_is_always_ok():
    assert summary({"state": "Disconnected"})["status"] == "ok"


# --- the page shows local time; the API keeps UTC ------------------------------------------------

from app.services.health_summary import display_zone, local_time  # noqa: E402


def test_local_time_shows_the_container_zone_with_its_abbreviation():
    assert local_time("2026-11-14T12:10:05Z", "America/New_York") == "2026-11-14 07:10:05 EST"
    assert local_time("2026-07-14T12:10:05Z", "America/New_York") == "2026-07-14 08:10:05 EDT"


def test_local_time_falls_back_to_utc_for_a_missing_or_unknown_zone():
    assert local_time("2026-11-14T12:10:05Z", None) == "2026-11-14 12:10:05 UTC"
    assert local_time("2026-11-14T12:10:05Z", "Not/AZone") == "2026-11-14 12:10:05 UTC"


def test_local_time_leaves_anything_that_is_not_a_timestamp_alone():
    assert local_time(None, "America/New_York") is None
    assert local_time("garbage", "America/New_York") is None


def test_display_zone_reads_tz_and_ignores_a_bad_one(monkeypatch):
    monkeypatch.setenv("TZ", "America/New_York")
    assert display_zone() == "America/New_York"
    monkeypatch.setenv("TZ", "Not/AZone")
    assert display_zone() is None
    monkeypatch.delenv("TZ")
    assert display_zone() is None
