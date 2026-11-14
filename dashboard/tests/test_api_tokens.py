"""API tokens and the token-type checkboxes.

A named API token is a Bearer credential that is never a login. It is stored
hashed, shown once, and admits a request only to a route in TOKEN_ROUTES that
its own type has, and only while the operator has enabled that type on the API
access page (and, for Warm restart, while ibctl's own allow-list lets the
command through). The types themselves are tested in test_token_types.py.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest
from bs4 import BeautifulSoup

from app.middleware import auth as auth_module
from app.services import api_access
from app.services.api_access import TOKEN_TYPES, ApiAccessStore, TokenError
from tests.api_access_helpers import (
    WITHOUT_SETRESTART,
    FakeClock,
    bearer,
    build_app,
    client_for,
    member_client,
)
from tests.auth_helpers import TEST_PASSWORD, authed_settings, route_table
from tests.test_access_control import PUBLIC_ROUTES

PLAIN = {"Accept": "application/json"}


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def store(tmp_path, clock):
    return ApiAccessStore(tmp_path / "config" / "api_access.json", clock=clock)


@pytest.fixture
def app(tmp_path, clock):
    return build_app(tmp_path, clock=clock)


@pytest.fixture
async def member(app):
    c = await member_client(app)
    yield c
    await c.aclose()


@pytest.fixture
async def anon(app):
    async with client_for(app) as c:
        yield c


def page(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


async def create_token(member, name: str = "ci-bot") -> str:
    resp = await member.post("/api-access/tokens", data={"name": name, "type": "warm_restart"})
    assert resp.status_code == 200, resp.text[:300]
    return page(resp.text).select_one("#new-token").get_text(strip=True)


# --- The store: names, hashing, lookup ---


class TestTokenStore:
    def test_a_created_token_is_returned_once_and_listed_by_name(self, store, clock):
        token, plaintext = store.create_token("ci-bot", created_by="dashboard user")
        assert token.name == "ci-bot"
        assert plaintext.startswith(api_access.TOKEN_PREFIX)
        assert len(plaintext) >= 40
        listed = store.list_tokens()
        assert [t.name for t in listed] == ["ci-bot"]
        assert listed[0].created_at == clock.now
        assert listed[0].created_by == "dashboard user"
        assert plaintext not in repr(listed)

    def test_two_tokens_never_collide(self, store):
        _, first = store.create_token("one", created_by="x")
        _, second = store.create_token("two", created_by="x")
        assert first != second

    def test_the_file_holds_a_hash_and_never_the_token(self, store):
        _, plaintext = store.create_token("ci-bot", created_by="x")
        text = store.path.read_text()
        assert plaintext not in text
        assert hashlib.sha256(plaintext.encode()).hexdigest() in text
        assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600

    def test_the_file_is_written_atomically(self, store):
        with patch.object(api_access.os, "replace", wraps=os.replace) as replace:
            store.create_token("ci-bot", created_by="x")
        assert replace.call_count == 1
        assert [p.name for p in store.path.parent.iterdir()] == ["api_access.json"]

    @pytest.mark.parametrize("name", ["", " ", "has space", "-leading", "a/b", "x" * 65, "tab\tname", "café", "a;b"])
    def test_a_bad_name_is_refused(self, store, name):
        with pytest.raises(TokenError):
            store.create_token(name, created_by="x")
        assert store.list_tokens() == []

    @pytest.mark.parametrize("name", ["ci", "ci-bot", "ci_bot.2", "A1", "x" * 64])
    def test_a_plain_name_is_accepted(self, store, name):
        store.create_token(name, created_by="x")

    def test_names_are_unique_whatever_the_case(self, store):
        store.create_token("ci-bot", created_by="x")
        with pytest.raises(TokenError, match="already"):
            store.create_token("CI-Bot", created_by="x")
        assert len(store.list_tokens()) == 1

    def test_a_token_is_recognised_and_names_its_owner(self, store):
        _, plaintext = store.create_token("ci-bot", created_by="x")
        found = store.recognise(plaintext)
        assert found is not None and found.name == "ci-bot"

    def test_an_unknown_token_is_not_recognised(self, store):
        store.create_token("ci-bot", created_by="x")
        for presented in ("", "nope", api_access.TOKEN_PREFIX + "x" * 43, "y" * 5000, "café"):
            assert store.recognise(presented) is None

    def test_a_revoked_token_is_not_recognised(self, store):
        _, plaintext = store.create_token("ci-bot", created_by="x")
        assert store.revoke_token("ci-bot") is True
        assert store.recognise(plaintext) is None
        assert store.list_tokens() == []
        assert store.revoke_token("ci-bot") is False

    def test_the_comparison_is_constant_time(self, store):
        _, plaintext = store.create_token("ci-bot", created_by="x")
        store.create_token("other", created_by="x")
        with patch.object(api_access.hmac, "compare_digest", wraps=hmac.compare_digest) as compare:
            store.recognise(plaintext)
        assert compare.call_count == 2, "every stored hash is compared, with no early exit"

    def test_tokens_survive_a_new_store_on_the_same_file(self, store, clock):
        _, plaintext = store.create_token("ci-bot", created_by="x")
        again = ApiAccessStore(store.path, clock=clock)
        assert again.recognise(plaintext).name == "ci-bot"

    def test_an_unreadable_file_recognises_nothing_and_refuses_to_be_overwritten(self, store):
        _, plaintext = store.create_token("ci-bot", created_by="x")
        store.path.write_text("{not json")
        assert store.recognise(plaintext) is None
        assert store.is_enabled("warm_restart") is False
        with pytest.raises(api_access.ApiAccessError):
            store.create_token("another", created_by="x")
        assert store.path.read_text() == "{not json"


class TestEnabledTypes:
    def test_only_warm_restart_is_enabled_by_default(self, store):
        assert store.enabled_types() == frozenset({"warm_restart"})
        assert store.is_enabled("warm_restart") is True
        assert [t.name for t in TOKEN_TYPES] == ["warm_restart", "upgrade_ci", "upgrade_maintenance"]

    def test_ticks_are_saved_and_survive_a_new_store(self, store, clock):
        store.set_enabled([])
        assert store.is_enabled("warm_restart") is False
        assert ApiAccessStore(store.path, clock=clock).is_enabled("warm_restart") is False
        store.set_enabled(["warm_restart"])
        assert ApiAccessStore(store.path, clock=clock).is_enabled("warm_restart") is True

    def test_an_unknown_type_cannot_be_enabled(self, store):
        with pytest.raises(ValueError):
            store.set_enabled(["warm_restart", "RESTART"])

    def test_creating_a_token_keeps_the_ticks(self, store):
        store.set_enabled([])
        store.create_token("ci-bot", created_by="x")
        assert store.is_enabled("warm_restart") is False


# --- The API access page ---


class TestPage:
    async def test_it_is_login_only(self, anon):
        resp = await anon.get("/api-access")
        assert resp.status_code == 303 and "/login?next=" in resp.headers["location"]
        assert (await anon.get("/api-access", headers=PLAIN)).status_code == 401
        for method, path in (
            ("POST", "/api-access/tokens"),
            ("POST", "/api-access/tokens/ci-bot/revoke"),
            ("POST", "/api-access/settings"),
        ):
            assert (await anon.request(method, path, data={"name": "x"})).status_code == 401, path

    async def test_it_has_a_tab_in_the_nav(self, member):
        soup = page((await member.get("/api-access")).text)
        tab = soup.select_one("nav.tabs a[href$='/api-access']")
        assert tab is not None and "active" in tab["class"]
        assert soup.select_one("nav.tabs a[href$='/state']") is not None

    async def test_the_page_shows_how_to_call_the_api(self, member):
        html = (await member.get("/api-access")).text
        assert "/api/v1/warm-restart" in html and "Authorization: Bearer" in html

    async def test_the_default_page_has_warm_restart_ticked_and_nothing_else(self, member):
        soup = page((await member.get("/api-access")).text)
        boxes = soup.select("input[type=checkbox][name^=allow_]")
        assert [b["name"] for b in boxes] == ["allow_warm_restart", "allow_upgrade_ci", "allow_upgrade_maintenance"]
        assert [b["name"] for b in boxes if b.has_attr("checked")] == ["allow_warm_restart"]
        assert not any(b.has_attr("disabled") for b in boxes)
        assert "Warm restart" in soup.select_one("#api-type-warm_restart").get_text()

    async def test_a_new_token_is_shown_once_and_never_again(self, app, member, caplog):
        with caplog.at_level(logging.DEBUG):
            created = await member.post("/api-access/tokens", data={"name": "ci-bot", "type": "warm_restart"})
        assert created.status_code == 200
        assert "no-store" in created.headers["cache-control"]
        plaintext = page(created.text).select_one("#new-token").get_text(strip=True)
        assert plaintext.startswith(api_access.TOKEN_PREFIX)

        later = (await member.get("/api-access")).text
        assert "ci-bot" in later
        assert plaintext not in later
        assert page(later).select_one("#new-token") is None
        assert plaintext not in app.state.api_access.path.read_text()
        assert plaintext not in caplog.text
        for url in ("/api-access", "/", "/partials/overview", "/api/v1/status"):
            assert plaintext not in (await member.get(url)).text, url

    async def test_a_created_token_works_and_a_revoked_one_does_not(self, app, member, anon, monkeypatch):
        monkeypatch.setattr(auth_module, "TOKEN_ROUTES", {("GET", "/api/v1/notifications/config"): frozenset({"warm_restart"})})
        plaintext = await create_token(member)
        assert (await anon.get("/api/v1/notifications/config", headers=bearer(plaintext))).status_code == 200

        revoke = await member.post("/api-access/tokens/ci-bot/revoke")
        assert revoke.status_code == 303 and revoke.headers["location"].endswith("/api-access?revoked=ci-bot")
        assert (await anon.get("/api/v1/notifications/config", headers=bearer(plaintext))).status_code == 401
        assert "ci-bot" not in page((await member.get("/api-access")).text).select_one("#tokens").get_text()

    async def test_a_duplicate_or_bad_name_is_refused_with_a_reason(self, member):
        await create_token(member, "ci-bot")
        dup = await member.post("/api-access/tokens", data={"name": "CI-BOT", "type": "warm_restart"})
        assert dup.status_code == 409 and "already" in dup.text
        assert page(dup.text).select_one("#new-token") is None
        bad = await member.post("/api-access/tokens", data={"name": "no spaces allowed", "type": "warm_restart"})
        assert bad.status_code == 400 and "letters" in bad.text

    async def test_revoking_an_unknown_token_is_a_404(self, member):
        assert (await member.post("/api-access/tokens/ghost/revoke")).status_code == 404

    async def test_saving_the_ticks_persists_them(self, app, member):
        resp = await member.post("/api-access/settings", data={"interval_live": "30", "interval_paper": "30"})
        assert resp.status_code == 303
        assert app.state.api_access.is_enabled("warm_restart") is False
        soup = page((await member.get("/api-access")).text)
        assert not soup.select_one("input[name=allow_warm_restart]").has_attr("checked")

        await member.post("/api-access/settings", data={"allow_warm_restart": "on", "interval_live": "30", "interval_paper": "30"})
        assert app.state.api_access.is_enabled("warm_restart") is True


class TestBlockedByIbctl:
    async def test_a_type_ibctl_blocks_is_greyed_out_with_the_reason(self, app, member):
        app.state.api_access.set_enabled([])
        app.state.stubs["paper"].allowed = WITHOUT_SETRESTART
        app.state.stubs["live"].allowed = WITHOUT_SETRESTART
        row = page((await member.get("/api-access")).text).select_one("#api-type-warm_restart")
        box = row.select_one("input[type=checkbox]")
        assert box.has_attr("disabled")
        assert "blocked by ibctl" in row.get_text()
        assert "inactive" not in row.get_text()

    async def test_a_saved_tick_for_a_blocked_command_reads_inactive(self, app, member):
        for stub in app.state.stubs.values():
            stub.allowed = WITHOUT_SETRESTART
        row = page((await member.get("/api-access")).text).select_one("#api-type-warm_restart")
        assert row.select_one("input[type=checkbox]").has_attr("checked")
        assert "inactive: blocked by ibctl" in row.get_text()

    async def test_saving_while_blocked_keeps_the_saved_tick(self, app, member):
        for stub in app.state.stubs.values():
            stub.allowed = WITHOUT_SETRESTART
        # A disabled checkbox is not submitted by the browser.
        await member.post("/api-access/settings", data={"interval_live": "45", "interval_paper": "30"})
        assert app.state.api_access.is_enabled("warm_restart") is True
        assert app.state.api_access.min_interval_minutes("live") == 45

    async def test_an_allowed_command_is_not_greyed_out(self, app, member):
        row = page((await member.get("/api-access")).text).select_one("#api-type-warm_restart")
        assert not row.select_one("input[type=checkbox]").has_attr("disabled")
        assert "blocked by ibctl" not in row.get_text()

    async def test_an_unreachable_ibctl_is_not_called_blocking(self, app, member):
        for stub in app.state.stubs.values():
            stub.unreachable = True
        row = page((await member.get("/api-access")).text).select_one("#api-type-warm_restart")
        assert not row.select_one("input[type=checkbox]").has_attr("disabled")
        text = row.get_text()
        assert "could not be read" in text
        assert "blocked by ibctl" not in text

    async def test_an_ibctl_that_does_not_report_its_list_is_not_called_blocking(self, app, member):
        for stub in app.state.stubs.values():
            stub.report_allowed = False
        row = page((await member.get("/api-access")).text).select_one("#api-type-warm_restart")
        assert not row.select_one("input[type=checkbox]").has_attr("disabled")
        assert "could not be read" in row.get_text() and "blocked by ibctl" not in row.get_text()

    async def test_one_mode_blocking_is_named(self, app, member):
        app.state.stubs["live"].allowed = WITHOUT_SETRESTART
        row = page((await member.get("/api-access")).text).select_one("#api-type-warm_restart")
        assert "blocked by ibctl" in row.get_text() and "LIVE" in row.get_text()


# --- What a token may reach ---


@pytest.fixture
def token_route(monkeypatch):
    """Open one existing route to tokens of the Warm restart type."""
    route = ("GET", "/api/v1/notifications/config")
    monkeypatch.setattr(auth_module, "TOKEN_ROUTES", {route: frozenset({"warm_restart"})})
    return route


class TestWhatATokenMayReach:
    async def test_a_ticked_command_opens_its_route(self, app, anon, token_route):
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        assert (await anon.get("/api/v1/notifications/config", headers=bearer(plaintext))).status_code == 200

    async def test_a_disabled_type_is_a_403_not_a_401(self, app, anon, token_route, caplog):
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        app.state.api_access.set_enabled([])
        with caplog.at_level(logging.INFO):
            resp = await anon.get("/api/v1/notifications/config", headers=bearer(plaintext, **{"X-Real-IP": "203.0.113.9"}))
        assert resp.status_code == 403
        assert resp.json()["error"] == "not_allowed"
        record = next(r.getMessage() for r in caplog.records if "not enabled" in r.getMessage())
        assert "ci-bot" in record and "203.0.113.9" in record and plaintext not in caplog.text

    async def test_a_token_route_without_a_valid_token_is_still_a_401(self, anon, token_route, app):
        assert (await anon.get("/api/v1/notifications/config", headers=bearer("ibctl_made-up"))).status_code == 401
        assert (await anon.get("/api/v1/notifications/config")).status_code == 401

    async def test_a_revoked_token_is_a_401_and_is_logged_without_the_token(self, app, anon, token_route, caplog):
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        app.state.api_access.revoke_token("ci-bot")
        with caplog.at_level(logging.INFO):
            resp = await anon.get("/api/v1/notifications/config", headers=bearer(plaintext, **{"X-Real-IP": "203.0.113.9"}))
        assert resp.status_code == 401
        assert any("203.0.113.9" in r.getMessage() and "API token" in r.getMessage() for r in caplog.records)
        assert plaintext not in caplog.text

    async def test_the_dashboard_password_is_not_a_bearer_token(self, anon, token_route):
        assert (await anon.get("/api/v1/notifications/config", headers=bearer(TEST_PASSWORD))).status_code == 401

    async def test_a_token_does_not_log_anyone_in(self, app, anon):
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        html = (await anon.get("/", headers=bearer(plaintext))).text
        assert "hx-get" not in html  # still the anonymous summary
        assert (await anon.get("/api-access", headers=bearer(plaintext), follow_redirects=False)).status_code == 303

    async def test_a_token_means_nothing_when_no_login_is_configured(self, tmp_path, token_route):
        app = build_app(tmp_path, settings=authed_settings(token="", auth_secret=None, trading_mode="both"))
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        async with client_for(app) as c:
            assert (await c.get("/api/v1/notifications/config", headers=bearer(plaintext))).status_code == 403

    async def test_every_token_route_comes_from_the_types_table(self):
        declared = {route for t in TOKEN_TYPES for route in t.routes}
        assert set(auth_module.TOKEN_ROUTES) == declared
        for route, names in auth_module.TOKEN_ROUTES.items():
            assert names == {t.name for t in TOKEN_TYPES if route in t.routes}, route

    async def test_a_token_gets_nothing_outside_its_routes(self, app, anon):
        """Sweep the app's own route table: a token is refused on every route it was not given."""
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        routes = [r for r in route_table(app) if r not in PUBLIC_ROUTES and r not in auth_module.TOKEN_ROUTES]
        assert len(routes) > 40
        for method, path in routes:
            for headers in (bearer(plaintext, **PLAIN), bearer(plaintext)):
                resp = await anon.request(method, path, headers=headers)
                expected = (303,) if method == "GET" and not path.startswith("/api/") and "Accept" not in headers else (401, 403)
                assert resp.status_code in expected, (method, path, resp.status_code)
        assert all(stub.sent == [] for stub in app.state.stubs.values())



def test_the_file_lives_under_the_persist_directory_the_other_saved_state_uses():
    expected = Path(os.environ.get("IBCTL_PERSIST_DIR", "/opt/ibctl/persist")) / "config" / "api_access.json"
    assert api_access.DEFAULT_PATH == expected
