"""One catalog of alerts, grouped, read by the Alerts page and the Gateway tab.

The Alerts page used to carry its own list of events. An event the backend
knew but the page did not (hitl_2fa_required) had no switch, and Save wrote it
out of the saved file. The catalog is now the one list, and it must cover
exactly the events the notification config knows.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from bs4 import BeautifulSoup
from httpx import ASGITransport, AsyncClient

from app.main import create_app
from app.services.notification_catalog import EVENTS, GROUPS, catalog_json
from app.services.notification_service import NotificationConfig

NTFY_PRIORITIES = ("min", "low", "default", "high", "urgent")
NEW_EVENTS = (
    "gateway_upgrade_scheduled",
    "gateway_upgrade_blocked",
    "gateway_version_check_failing",
)


def test_every_configured_event_has_exactly_one_catalog_entry():
    keys = [e.key for e in EVENTS]

    assert len(keys) == len(set(keys))
    assert sorted(keys) == sorted(NotificationConfig().events), (
        "an event without a catalog entry has no switch on the Alerts page"
    )


def test_the_groups_in_page_order():
    assert [(g.key, g.label) for g in GROUPS] == [
        ("login", "Login & 2FA"),
        ("connection", "Connection"),
        ("restarts", "Scheduled restarts"),
        ("gateway", "Gateway versions & upgrades"),
    ]
    assert {e.group for e in EVENTS} == {g.key for g in GROUPS}


def test_each_alert_sits_in_its_group():
    by_group = {g.key: [e.key for e in EVENTS if e.group == g.key] for g in GROUPS}

    assert by_group["login"] == [
        "login_failed",
        "relogin_failed",
        "hitl_2fa_required",
        "twofa_push_waiting",
        "auth_relaunch",
        "session_conflict_loop",
    ]
    assert by_group["connection"] == ["session_lost", "no_clients", "ib_maintenance"]
    assert by_group["restarts"] == [
        "cold_restart_pending",
        "cold_restart_succeeded",
        "cold_restart_skipped",
        "cold_restart_outcome",
        "warm_restart",
    ]
    assert by_group["gateway"] == [
        "gateway_update",
        "gateway_desupport",
        *NEW_EVENTS,
    ]


def test_loudness_is_the_ntfy_priorities_an_alert_can_go_out_at():
    for e in EVENTS:
        assert e.loudness, e.key
        assert all(p in NTFY_PRIORITIES for p in e.loudness), e.key
        assert list(e.loudness) == sorted(e.loudness, key=NTFY_PRIORITIES.index), (
            f"{e.key}: quietest first"
        )


def test_the_new_gateway_alerts_are_on_by_default():
    events = NotificationConfig().events

    for key in NEW_EVENTS:
        assert events[key] == {"enabled": True}, key


def test_the_catalog_json_keeps_page_order():
    data = catalog_json()

    assert [g["key"] for g in data["groups"]] == [g.key for g in GROUPS]
    first = data["groups"][0]["events"][0]
    assert set(first) == {"key", "label", "desc", "loudness", "timeout"}


@pytest.mark.asyncio
async def test_the_config_api_serves_the_catalog(settings):
    app = create_app(settings=settings)
    app.state.notification_service = SimpleNamespace(config=NotificationConfig())
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        d = (await c.get("/api/v1/notifications/config")).json()

    assert d["ok"] is True
    assert d["catalog"] == catalog_json()


@pytest.mark.asyncio
async def test_the_alerts_page_has_no_event_list_of_its_own(client):
    html = (await client.get("/notifications")).text

    assert "EVENT_LABELS = {" not in html
    soup = BeautifulSoup(html, "html.parser")
    tabs = soup.find(id="alerts-tabs")
    assert tabs is not None and tabs.get("role") == "tablist", "one tab per alert group"
    assert soup.find(id="alerts-jump") is None, "tabs, not jump links over one long list"
    assert soup.find(id="history-group") is not None, "the history filter by group"


@pytest.mark.asyncio
async def test_the_gateway_tab_links_to_its_alerts(client):
    soup = BeautifulSoup((await client.get("/gateway")).text, "html.parser")

    summary = soup.find(id="upgrade-alerts")
    assert summary is not None
    assert summary.find(
        "a", href=lambda h: h and h.endswith("/notifications#alerts-gateway")
    )
