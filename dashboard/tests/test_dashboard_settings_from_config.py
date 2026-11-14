"""Dashboard tunables come from ibctl.toml, with their env vars still overriding.

The session-down alert timers, the scheduled-restart grace and the version
check's API client ID used to be env-only. They are [dashboard] settings now:
the value in ibctl.toml is used, the old env var still wins when it's set, and
the Config page shows the escape-hatch env vars that have no TOML key.
"""

from __future__ import annotations

import logging

import pytest

from app.api import pages
from app.config import DashboardSettings
from app.services import effective_config
from app.services.gateway_version import probe
from app.services.monitors import session_lost
from app.services.monitors.session_lost import SessionLostMonitor

TUNABLES = {
    "IBCTL_SESSION_IDLE_MINUTES": "session_idle_minutes",
    "IBCTL_SESSION_DOWN_ALERT_MINUTES": "session_down_alert_minutes",
    "IBCTL_SESSION_DOWN_RENAG_MINUTES": "session_down_renag_minutes",
    "IBCTL_SCHEDULED_RESTART_GRACE_MINUTES": "scheduled_restart_grace_minutes",
    "IBCTL_VERSION_PROBE_CLIENT_ID": "version_probe_client_id",
}


@pytest.fixture
def toml(tmp_path, monkeypatch):
    """Point IBCTL_CONFIG at a fresh file; clear the env overrides."""
    for env in TUNABLES:
        monkeypatch.delenv(env, raising=False)
    path = tmp_path / "ibctl.toml"
    monkeypatch.setenv("IBCTL_CONFIG", str(path))

    def write(text: str):
        path.write_text(text)

    return write


def test_a_setting_comes_from_the_toml(toml):
    toml("[dashboard]\nsession_down_alert_minutes = 25\n")

    assert effective_config.setting("dashboard.session_down_alert_minutes", 10) == 25


def test_its_env_var_still_wins(toml, monkeypatch):
    toml("[dashboard]\nsession_down_alert_minutes = 25\n")
    monkeypatch.setenv("IBCTL_SESSION_DOWN_ALERT_MINUTES", "3")

    assert effective_config.setting("dashboard.session_down_alert_minutes", 10) == 3


def test_no_file_or_no_key_gives_the_default(toml, tmp_path):
    assert effective_config.setting("dashboard.session_down_alert_minutes", 10) == 10
    toml("[dashboard]\n")
    assert effective_config.setting("dashboard.session_down_alert_minutes", 10) == 10


def test_an_unreadable_file_gives_the_default(toml):
    toml("[dashboard\nnot toml")

    assert effective_config.setting("dashboard.session_down_alert_minutes", 10) == 10


def test_session_down_timers_come_from_the_toml(toml):
    toml(
        "[dashboard]\n"
        "session_down_alert_minutes = 25\n"
        "session_down_renag_minutes = 90\n"
        "scheduled_restart_grace_minutes = 35\n"
    )

    assert SessionLostMonitor._alert_after_secs() == 25 * 60
    assert SessionLostMonitor._renag_secs() == 90 * 60
    assert session_lost._scheduled_restart_grace_minutes() == 35


def test_session_down_timers_keep_their_defaults(toml):
    toml("")

    assert SessionLostMonitor._alert_after_secs() == 10 * 60
    assert SessionLostMonitor._renag_secs() == 60 * 60
    assert session_lost._scheduled_restart_grace_minutes() == 20


def test_the_version_check_client_id_comes_from_the_toml(toml, monkeypatch):
    toml("[dashboard]\nversion_probe_client_id = 4100\n")
    assert probe.probe_client_id() == 4100

    monkeypatch.setenv("IBCTL_VERSION_PROBE_CLIENT_ID", "4200")
    assert probe.probe_client_id() == 4200


def test_the_version_check_client_id_default(toml):
    toml("")

    assert probe.probe_client_id() == 9172


@pytest.mark.parametrize("env", ["IBCTL_KICK_LIVE_SESSION_OK", "IBCTL_STANDBY_AUTO_LAUNCH_OK"])
def test_a_set_escape_hatch_shows_on_the_config_page_with_a_tooltip(env, toml, monkeypatch):
    toml("")
    monkeypatch.setenv(env, "1")

    items = [
        item
        for g in pages._build_config_groups(pages._load_local_config())
        for sub in g["subsections"]
        for item in sub["items"]
        if sub["label"] == "Runtime"
    ]

    [item] = [i for i in items if env in (i["description"] or "")]
    assert item["value"] == "1"


# --- Idle logout ---


def test_the_idle_logout_defaults_to_five_minutes(toml):
    toml("")

    assert DashboardSettings.from_env().session_idle_minutes == 5
    assert DashboardSettings().session_idle_minutes == 5


@pytest.mark.parametrize("minutes", [0, 1, 25, 1440])
def test_the_idle_logout_comes_from_the_toml(toml, minutes):
    toml(f"[dashboard]\nsession_idle_minutes = {minutes}\n")

    assert DashboardSettings.from_env().session_idle_minutes == minutes


@pytest.mark.parametrize(("raw", "expected"), [("3", 3), ("0", 0), ("1440", 1440), (" 7 ", 7)])
def test_its_env_var_wins_over_the_toml(toml, monkeypatch, raw, expected):
    toml("[dashboard]\nsession_idle_minutes = 25\n")
    monkeypatch.setenv("IBCTL_SESSION_IDLE_MINUTES", raw)

    assert DashboardSettings.from_env().session_idle_minutes == expected


def test_an_empty_env_var_leaves_the_toml_value(toml, monkeypatch):
    toml("[dashboard]\nsession_idle_minutes = 25\n")
    monkeypatch.setenv("IBCTL_SESSION_IDLE_MINUTES", "")

    assert DashboardSettings.from_env().session_idle_minutes == 25


@pytest.mark.parametrize("raw", ["1441", "-1", "abc", "1.5"])
def test_a_bad_env_value_that_got_past_preflight_falls_back_to_the_default_and_says_so(toml, monkeypatch, caplog, raw):
    toml("[dashboard]\nsession_idle_minutes = 25\n")
    monkeypatch.setenv("IBCTL_SESSION_IDLE_MINUTES", raw)

    with caplog.at_level(logging.WARNING, logger="dashboard.config"):
        settings = DashboardSettings.from_env()

    assert settings.session_idle_minutes == 5
    assert "session_idle_minutes" in caplog.text


@pytest.mark.parametrize("value", ["1441", "-3", "2.5", "true", '"soon"'])
def test_a_bad_toml_value_falls_back_to_the_default(toml, caplog, value):
    toml(f"[dashboard]\nsession_idle_minutes = {value}\n")

    with caplog.at_level(logging.WARNING, logger="dashboard.config"):
        assert DashboardSettings.from_env().session_idle_minutes == 5
    assert "session_idle_minutes" in caplog.text


def test_the_startup_line_says_how_long_a_login_may_sit_idle(toml, caplog):
    toml("[dashboard]\nsession_idle_minutes = 12\n")

    with caplog.at_level(logging.INFO, logger="dashboard.config"):
        DashboardSettings.from_env()

    assert "idle_logout=12min" in caplog.text
