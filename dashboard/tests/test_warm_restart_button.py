"""The "Warm restart (no 2FA)" button next to each Gateway's cold Restart.

It posts to the same endpoint the API uses, so the minimum interval is shared.
It is greyed out, with the reason beside it, while ibctl's allow-list blocks the
command or the interval has not passed; when ibctl's list cannot be read it
stays usable and says so.
"""

from __future__ import annotations

import pytest
from bs4 import BeautifulSoup

from app.instance_registry import _CachedResponse
from tests.api_access_helpers import WITHOUT_SETRESTART, FakeClock, bearer, build_app, client_for, member_client

LABEL = "Warm restart (no 2FA)"
URL = "/api/v1/warm-restart"


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def app(tmp_path, clock):
    return build_app(tmp_path, clock=clock)


@pytest.fixture
async def member(app):
    c = await member_client(app)
    yield c
    await c.aclose()


def plant_status(app) -> None:
    """The status cache a running dashboard has (a command empties it until the next push)."""
    status = {
        "version": "1.3.0", "ready": True, "state": "Connected", "uptime_secs": 7200, "connected_uptime_secs": 3600,
        "jvm": {"alive": True, "pid": 4242}, "socat": {"running": True}, "clients": {"count": 0},
        "client_advisory": {"should_connect": True}, "stats": {},
    }
    for mode in app.state.instance_registry.modes():
        app.state.instance_registry._cache[f"{mode}:STATUS"] = _CachedResponse(dict(status), ttl=60.0)


async def controls(app, member) -> dict[str, BeautifulSoup]:
    """Each mode's controls bar."""
    plant_status(app)
    soup = BeautifulSoup((await member.get("/partials/overview")).text, "html.parser")
    return {mode: soup.find(id=f"cmd-result-{mode}").parent for mode in app.state.instance_registry.modes()}


def warm_button(bar):
    return next(b for b in bar.find_all("button") if b.get_text(strip=True) == LABEL)


def notes(bar) -> str:
    return " ".join(n.get_text(" ", strip=True) for n in bar.select(".ctrl-note"))


class TestButton:
    async def test_it_sits_right_before_the_cold_restart_for_each_mode(self, app, member):
        for mode, bar in (await controls(app, member)).items():
            labels = [b.get_text(strip=True) for b in bar.find_all("button")]
            assert labels.index(LABEL) + 1 == labels.index("Restart"), (mode, labels)
            assert labels[-3:] == ["Restart", "Stop", "Start"]
            warm = warm_button(bar)
            assert f"sendWarmRestart('{mode}')" in warm["onclick"]
            assert "confirm(" in warm["onclick"]
            assert "2FA" in warm["onclick"]

    async def test_the_cold_restart_is_unchanged(self, app, member):
        bar = (await controls(app, member))["paper"]
        cold = next(b for b in bar.find_all("button") if b.get_text(strip=True) == "Restart")
        assert "sendCmd('RESTART','paper')" in cold["onclick"]

    async def test_it_is_usable_when_nothing_stands_in_the_way(self, app, member):
        for bar in (await controls(app, member)).values():
            assert not warm_button(bar).has_attr("disabled")
            assert "ibctl" not in notes(bar)

    async def test_the_page_carries_the_script_that_posts_it(self, app, member):
        html = (await member.get("/partials/overview")).text
        assert "function sendWarmRestart" in html
        assert "/api/v1/warm-restart" in html


class TestBlockedByIbctl:
    async def test_it_is_disabled_with_the_reason_beside_it(self, app, member):
        app.state.stubs["paper"].allowed = WITHOUT_SETRESTART
        bars = await controls(app, member)
        paper = warm_button(bars["paper"])
        assert paper.has_attr("disabled")
        assert "blocked by ibctl" in paper["title"].lower()
        assert "blocked by ibctl" in notes(bars["paper"]).lower()
        assert not warm_button(bars["live"]).has_attr("disabled"), "the other mode's ibctl still allows it"
        assert "ibctl" not in notes(bars["live"])

    async def test_an_unreadable_list_does_not_disable_it(self, app, member):
        for stub in app.state.stubs.values():
            stub.report_allowed = False
        bar = (await controls(app, member))["paper"]
        button = warm_button(bar)
        assert not button.has_attr("disabled")
        assert "could not be read" in button["title"]
        assert "blocked" not in button["title"].lower() and "blocked" not in notes(bar).lower()


class TestRateLimited:
    async def test_it_is_disabled_until_the_interval_has_passed(self, app, member, clock):
        assert (await member.post(URL, json={"mode": "paper"})).status_code == 202
        clock.advance(10 * 60)
        bars = await controls(app, member)
        paper = warm_button(bars["paper"])
        assert paper.has_attr("disabled")
        assert "20 min" in paper["title"] and "20 min" in notes(bars["paper"])
        assert "30 min" in notes(bars["paper"]), "the minimum interval is named"
        assert not warm_button(bars["live"]).has_attr("disabled"), "the interval is per mode"

        clock.advance(20 * 60)
        assert not warm_button((await controls(app, member))["paper"]).has_attr("disabled")

    async def test_an_api_restart_greys_the_button_too(self, app, member):
        async with client_for(app) as api:
            token = app.state.api_access.create_token("ci-bot", created_by="x")[1]
            assert (await api.post(URL, json={"mode": "live"}, headers=bearer(token))).status_code == 202
        bars = await controls(app, member)
        assert warm_button(bars["live"]).has_attr("disabled")
        assert not warm_button(bars["paper"]).has_attr("disabled")

    async def test_a_short_wait_is_given_in_seconds(self, app, member, clock):
        app.state.api_access.set_min_interval_minutes({"paper": 1})
        await member.post(URL, json={"mode": "paper"})
        clock.advance(20)
        assert "40 s" in notes((await controls(app, member))["paper"])

    async def test_the_interval_is_the_one_set_on_the_api_access_page(self, app, member, clock):
        app.state.api_access.set_min_interval_minutes({"paper": 5})
        await member.post(URL, json={"mode": "paper"})
        assert "5 min" in notes((await controls(app, member))["paper"])
        clock.advance(5 * 60)
        assert not warm_button((await controls(app, member))["paper"]).has_attr("disabled")


class TestUnreadableState:
    async def test_an_unreadable_settings_file_disables_it_and_says_why(self, app, member):
        app.state.api_access.path.parent.mkdir(parents=True, exist_ok=True)
        app.state.api_access.path.write_text("{not json")
        bar = (await controls(app, member))["paper"]
        assert warm_button(bar).has_attr("disabled")
        assert "cannot be read" in notes(bar)
