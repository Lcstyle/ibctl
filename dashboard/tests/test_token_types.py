"""Token types: a token has one type, and a type is a fixed bundle of routes.

A type's name, label, description and routes live in one table
(`app.services.api_access.TOKEN_TYPES`). A token reaches only the routes of its
own type, and only while the operator has enabled that type on the API access
page; the dashboard's own routes stay login-only. The file a dashboard saved
before types existed (no `type` on a token, a tick list keyed by command name)
loads as is.
"""

from __future__ import annotations

import json
import logging
import os
from unittest.mock import patch

import pytest
from bs4 import BeautifulSoup

from app.middleware import auth as auth_module
from app.services import api_access
from app.services.api_access import DEFAULT_TYPE, TOKEN_TYPES, ApiAccessStore, TokenError, hash_token
from tests.api_access_helpers import (
    WITHOUT_SETRESTART,
    FakeClock,
    bearer,
    build_app,
    client_for,
    member_client,
)
from tests.auth_helpers import TEST_PASSWORD, route_table
from tests.test_access_control import PUBLIC_ROUTES

OLD_TOKEN = "ibctl_" + "o" * 43  # nosecret: test value
IP = "203.0.113.9"
OTHER_ROUTE = ("GET", "/api/v1/notifications/config")  # a real route that is login-only


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
async def anon(app):
    async with client_for(app) as c:
        yield c


@pytest.fixture
async def member(app):
    c = await member_client(app)
    yield c
    await c.aclose()


def page(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


def write_old_file(path, **extra):
    """The file a dashboard saved before token types: no `type`, a tick list of command names."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "version": 1,
        "tokens": [
            {"name": "ci-bot", "hash": hash_token(OLD_TOKEN), "created_at": 1_700_000_000.0, "created_by": "dashboard user"}
        ],
        "allowed": ["WARMRESTART"],
        "min_interval_minutes": {"live": 45},
        "warm_restart": {"paper": {"accepted_at": 1_700_000_100.0}},
        **extra,
    }
    path.write_text(json.dumps(data))
    return data


# --- the table ---


class TestTheTypesTable:
    def test_a_type_has_a_name_a_label_a_description_and_routes(self):
        assert TOKEN_TYPES
        for t in TOKEN_TYPES:
            assert t.name and t.label and t.description and t.routes, t
            assert t.name == t.name.lower() and " " not in t.name

    def test_names_and_labels_are_unique(self):
        assert len({t.name for t in TOKEN_TYPES}) == len(TOKEN_TYPES)
        assert len({t.label for t in TOKEN_TYPES}) == len(TOKEN_TYPES)

    def test_warm_restart_is_the_default_type_and_has_exactly_its_two_routes(self):
        assert DEFAULT_TYPE == "warm_restart"
        warm = api_access.find_token_type("warm_restart")
        assert warm.label == "Warm restart client"
        assert set(warm.routes) == {("GET", "/api/v1/warm-restart"), ("POST", "/api/v1/warm-restart")}
        assert warm.ibctl_command == "SETRESTART"
        assert warm.default_enabled is True

    def test_an_unknown_type_is_none(self):
        assert api_access.find_token_type("root") is None

    def test_the_middleware_routes_are_the_table_inverted(self):
        expected: dict = {}
        for t in TOKEN_TYPES:
            for route in t.routes:
                expected[route] = expected.get(route, frozenset()) | {t.name}
        assert auth_module.TOKEN_ROUTES == expected

    def test_a_route_is_never_a_wildcard(self):
        for t in TOKEN_TYPES:
            for method, path in t.routes:
                assert method in {"GET", "POST"} and path.startswith("/api/v1/") and "{" not in path and "*" not in path


# --- the store ---


class TestTypedTokens:
    def test_a_token_is_created_with_a_type_and_the_file_records_it(self, store):
        token, _ = store.create_token("ci-bot", created_by="x", token_type="warm_restart")
        assert token.type == "warm_restart"
        assert store.list_tokens()[0].type == "warm_restart"
        assert json.loads(store.path.read_text())["tokens"][0]["type"] == "warm_restart"

    def test_the_type_defaults_to_warm_restart(self, store):
        token, _ = store.create_token("ci-bot", created_by="x")
        assert token.type == DEFAULT_TYPE

    @pytest.mark.parametrize("bad", ["", "WARMRESTART", "admin", "warm_restart ", None])
    def test_an_unknown_type_is_refused_and_nothing_is_saved(self, store, bad):
        with pytest.raises(TokenError, match="type"):
            store.create_token("ci-bot", created_by="x", token_type=bad)
        assert store.list_tokens() == []

    def test_a_recognised_token_carries_its_type(self, store):
        _, plaintext = store.create_token("ci-bot", created_by="x", token_type="warm_restart")
        assert store.recognise(plaintext).type == "warm_restart"

    def test_a_token_saved_with_a_type_this_build_does_not_know_keeps_it(self, store):
        _, plaintext = store.create_token("ci-bot", created_by="x")
        data = json.loads(store.path.read_text())
        data["tokens"][0]["type"] = "from_the_future"
        store.path.write_text(json.dumps(data))
        assert store.recognise(plaintext).type == "from_the_future"
        assert api_access.find_token_type("from_the_future") is None

    def test_the_plaintext_is_never_stored_whatever_the_type(self, store):
        _, plaintext = store.create_token("ci-bot", created_by="x", token_type="warm_restart")
        assert plaintext not in store.path.read_text()


class TestEnabledTypes:
    def test_the_defaults_come_from_the_table(self, store):
        assert store.enabled_types() == frozenset(t.name for t in TOKEN_TYPES if t.default_enabled)

    def test_the_choice_is_saved_as_enabled_types(self, store):
        store.set_enabled(["warm_restart"])
        assert json.loads(store.path.read_text())["enabled_types"] == ["warm_restart"]

    def test_an_unreadable_file_enables_nothing(self, store):
        store.create_token("ci-bot", created_by="x")
        store.path.write_text("{not json")
        assert store.is_enabled("warm_restart") is False

    def test_an_unknown_name_is_not_enabled(self, store):
        assert store.is_enabled("root") is False


# --- a file saved before types existed ---


class TestAnOldFile:
    async def test_an_old_token_still_opens_warm_restart(self, tmp_path, clock):
        app = build_app(tmp_path, clock=clock)
        write_old_file(app.state.api_access.path)
        async with client_for(app) as c:
            resp = await c.get("/api/v1/warm-restart", params={"mode": "paper"}, headers=bearer(OLD_TOKEN))
        assert resp.status_code == 200

    def test_a_token_without_a_type_is_a_warm_restart_token(self, store):
        write_old_file(store.path)
        [token] = store.list_tokens()
        assert (token.name, token.type) == ("ci-bot", "warm_restart")
        assert store.recognise(OLD_TOKEN).type == "warm_restart"

    def test_the_old_tick_list_maps_to_enabled_types(self, store):
        write_old_file(store.path, allowed=["WARMRESTART"])
        assert store.enabled_types() == frozenset({"warm_restart"})
        write_old_file(store.path, allowed=[])
        assert store.enabled_types() == frozenset()
        assert store.is_enabled("warm_restart") is False

    def test_a_file_with_no_tick_list_gets_the_defaults(self, store):
        data = write_old_file(store.path)
        del data["allowed"]
        store.path.write_text(json.dumps(data))
        assert store.enabled_types() == frozenset(t.name for t in TOKEN_TYPES if t.default_enabled)

    def test_the_other_settings_load_as_before(self, store):
        write_old_file(store.path)
        assert store.min_interval_minutes("live") == 45
        assert store.min_interval_minutes("paper") == api_access.DEFAULT_INTERVAL_MINUTES
        assert store.warm_restart_record("paper") == {"accepted_at": 1_700_000_100.0}

    def test_loading_alone_does_not_rewrite_the_file(self, store):
        write_old_file(store.path)
        before = store.path.read_text()
        store.list_tokens(), store.enabled_types(), store.recognise(OLD_TOKEN)
        assert store.path.read_text() == before

    def test_saving_writes_the_new_shape(self, store):
        write_old_file(store.path, something_from_elsewhere={"keep": ["me"]})
        store.set_min_interval_minutes({"paper": 20})
        saved = json.loads(store.path.read_text())

        assert saved["version"] == 2
        assert [t["type"] for t in saved["tokens"]] == ["warm_restart"]
        assert saved["enabled_types"] == ["warm_restart"]
        assert "allowed" not in saved
        assert saved["something_from_elsewhere"] == {"keep": ["me"]}
        assert saved["min_interval_minutes"] == {"live": 45, "paper": 20}
        assert saved["warm_restart"] == {"paper": {"accepted_at": 1_700_000_100.0}}

    def test_a_token_still_works_after_the_file_is_saved(self, store):
        """The migration must carry the token's hash and name across."""
        write_old_file(store.path)
        store.create_token("another", created_by="x", token_type="warm_restart")
        saved = {t["name"]: t for t in json.loads(store.path.read_text())["tokens"]}

        assert saved["ci-bot"]["hash"] == hash_token(OLD_TOKEN)
        assert saved["ci-bot"]["created_by"] == "dashboard user" and saved["ci-bot"]["created_at"] == 1_700_000_000.0
        assert store.recognise(OLD_TOKEN).name == "ci-bot"

    def test_an_unticked_old_dashboard_stays_unticked_after_a_save(self, store):
        write_old_file(store.path, allowed=[])
        store.create_token("another", created_by="x")
        assert json.loads(store.path.read_text())["enabled_types"] == []
        assert store.is_enabled("warm_restart") is False

    def test_the_new_shape_is_written_atomically(self, store):
        write_old_file(store.path)
        with patch.object(api_access.os, "replace", wraps=os.replace) as replace:
            store.set_min_interval_minutes({"paper": 20})
        assert replace.call_count == 1
        assert [p.name for p in store.path.parent.iterdir()] == ["api_access.json"]


# --- what a token reaches ---


@pytest.fixture
def other_route(monkeypatch):
    """A login-only route opened to one type this build does not have, to test the gate on its own."""
    monkeypatch.setattr(auth_module, "TOKEN_ROUTES", {OTHER_ROUTE: frozenset({"some_other_type"})})
    return OTHER_ROUTE


class TestTheGate:
    async def test_a_token_of_another_type_is_a_403_that_says_so(self, app, anon, other_route):
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x", token_type="warm_restart")
        resp = await anon.get("/api/v1/notifications/config", headers=bearer(plaintext))
        assert resp.status_code == 403
        assert resp.json()["error"] == "wrong_token_type"
        assert "warm_restart" in resp.json()["detail"]

    async def test_a_token_of_a_type_this_build_does_not_know_gets_nothing(self, app, anon, monkeypatch):
        monkeypatch.setattr(auth_module, "TOKEN_ROUTES", {OTHER_ROUTE: frozenset({"warm_restart"})})
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        data = json.loads(app.state.api_access.path.read_text())
        data["tokens"][0]["type"] = "from_the_future"
        app.state.api_access.path.write_text(json.dumps(data))
        assert (await anon.get("/api/v1/notifications/config", headers=bearer(plaintext))).status_code == 403

    async def test_a_disabled_type_is_a_403_naming_the_type_and_the_page(self, app, anon):
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        app.state.api_access.set_enabled([])
        resp = await anon.get("/api/v1/warm-restart", params={"mode": "paper"}, headers=bearer(plaintext))
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"] == "not_allowed"
        assert "Warm restart client" in body["detail"] and "warm_restart" in body["detail"]
        assert "API access page" in body["detail"]

    async def test_enabling_the_type_opens_it(self, app, anon):
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        app.state.api_access.set_enabled([])
        assert (await anon.get("/api/v1/warm-restart", params={"mode": "paper"}, headers=bearer(plaintext))).status_code == 403
        app.state.api_access.set_enabled(["warm_restart"])
        assert (await anon.get("/api/v1/warm-restart", params={"mode": "paper"}, headers=bearer(plaintext))).status_code == 200

    async def test_an_unreadable_file_fails_closed(self, app, anon):
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        app.state.api_access.path.write_text("{not json")
        resp = await anon.get("/api/v1/warm-restart", params={"mode": "paper"}, headers=bearer(plaintext))
        assert resp.status_code == 401  # nothing is recognised while the file cannot be read

    async def test_unknown_and_revoked_tokens_are_401_on_every_token_route(self, app, anon):
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        app.state.api_access.revoke_token("ci-bot")
        for method, path in auth_module.TOKEN_ROUTES:
            for credential in (plaintext, "ibctl_" + "z" * 43, TEST_PASSWORD, ""):
                headers = bearer(credential) if credential else {}
                resp = await anon.request(method, path, headers=headers)
                assert resp.status_code == 401, (method, path, credential[:6])

    async def test_a_token_is_not_a_login_anywhere_else(self, app, anon):
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        for method, path in (
            ("POST", "/api/session/touch"),
            ("GET", "/api/v1/status"),
            ("POST", "/api/v1/command"),
            ("GET", "/api-access"),
            ("POST", "/api-access/tokens"),
            ("POST", "/api-access/settings"),
        ):
            resp = await anon.request(method, path, headers=bearer(plaintext, Accept="application/json"))
            assert resp.status_code == 401, (method, path)
        assert all(stub.sent == [] for stub in app.state.stubs.values())


class TestEveryRouteIsRefusedUntilItIsGiven:
    """Sweep the app's own route table: a token reaches its type's routes and nothing else."""

    @pytest.mark.parametrize("type_name", [t.name for t in TOKEN_TYPES])
    async def test_a_token_reaches_exactly_the_routes_of_its_type(self, app, anon, type_name):
        app.state.api_access.set_enabled([t.name for t in TOKEN_TYPES])
        _, plaintext = app.state.api_access.create_token("sweep", created_by="x", token_type=type_name)
        mine = set(api_access.find_token_type(type_name).routes)
        routes = [r for r in route_table(app) if r not in PUBLIC_ROUTES]
        assert mine <= set(routes) and len(routes) > 40

        reached = set()
        for method, path in routes:
            resp = await anon.request(method, path, headers=bearer(plaintext, Accept="application/json"))
            if resp.status_code not in (401, 403):
                reached.add((method, path))

        assert reached == mine

    async def test_a_route_added_later_is_refused_to_every_type(self, app, anon):
        app.state.api_access.set_enabled([t.name for t in TOKEN_TYPES])
        called = []

        async def newcomer():
            called.append(1)
            return {"hello": "world"}

        app.add_api_route("/api/v1/added-later", newcomer, methods=["GET", "POST"])
        for t in TOKEN_TYPES:
            _, plaintext = app.state.api_access.create_token(f"tok-{t.name}", created_by="x", token_type=t.name)
            for method in ("GET", "POST"):
                resp = await anon.request(method, "/api/v1/added-later", headers=bearer(plaintext))
                assert resp.status_code in (401, 403), (t.name, method)
        assert called == []

    async def test_a_route_can_only_be_opened_by_putting_it_in_the_table(self, app, anon, monkeypatch):
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        assert (await anon.get("/api/v1/notifications/config", headers=bearer(plaintext))).status_code == 401
        monkeypatch.setattr(auth_module, "TOKEN_ROUTES", {OTHER_ROUTE: frozenset({"warm_restart"})})
        assert (await anon.get("/api/v1/notifications/config", headers=bearer(plaintext))).status_code == 200


# --- the audit log ---


class TestAuditLog:
    @staticmethod
    def lines(caplog):
        return [r.getMessage() for r in caplog.records if r.name == "dashboard.auth"]

    async def test_an_accepted_request_logs_the_name_the_type_and_the_address(self, app, anon, caplog):
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        with caplog.at_level(logging.INFO):
            await anon.get("/api/v1/warm-restart", params={"mode": "paper"}, headers=bearer(plaintext, **{"X-Real-IP": IP}))
        line = next(m for m in self.lines(caplog) if "accepted" in m.lower())
        assert "ci-bot" in line and "warm_restart" in line and IP in line and "/api/v1/warm-restart" in line
        assert plaintext not in caplog.text

    async def test_a_disabled_type_logs_the_name_the_type_and_the_address(self, app, anon, caplog):
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        app.state.api_access.set_enabled([])
        with caplog.at_level(logging.INFO):
            await anon.get("/api/v1/warm-restart", params={"mode": "paper"}, headers=bearer(plaintext, **{"X-Real-IP": IP}))
        line = next(m for m in self.lines(caplog) if "Rejected" in m)
        assert "ci-bot" in line and "warm_restart" in line and IP in line
        assert plaintext not in caplog.text

    async def test_another_types_route_logs_the_name_the_type_and_the_address(self, app, anon, other_route, caplog):
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        with caplog.at_level(logging.INFO):
            await anon.get("/api/v1/notifications/config", headers=bearer(plaintext, **{"X-Real-IP": IP}))
        line = next(m for m in self.lines(caplog) if "Rejected" in m)
        assert "ci-bot" in line and "warm_restart" in line and IP in line

    async def test_a_route_tokens_do_not_have_logs_the_name_the_type_and_the_address(self, app, anon, caplog):
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="x")
        with caplog.at_level(logging.INFO):
            resp = await anon.get("/api/v1/status", headers=bearer(plaintext, **{"X-Real-IP": IP, "Accept": "application/json"}))
        assert resp.status_code == 401
        line = next(m for m in self.lines(caplog) if "Rejected" in m)
        assert "ci-bot" in line and "warm_restart" in line and IP in line
        assert plaintext not in caplog.text

    async def test_an_unknown_token_logs_the_address_and_nothing_secret(self, app, anon, caplog):
        with caplog.at_level(logging.INFO):
            await anon.get("/api/v1/warm-restart", params={"mode": "paper"}, headers=bearer("ibctl_made-up", **{"X-Real-IP": IP}))
        assert any(IP in m and "not recognised" in m for m in self.lines(caplog))
        assert "ibctl_made-up" not in caplog.text


# --- the page ---


class TestThePage:
    async def test_the_create_form_has_a_name_and_a_type_dropdown_with_a_description_per_type(self, member):
        soup = page((await member.get("/api-access")).text)
        select = soup.select_one("form[action$='/api-access/tokens'] select[name=type]")
        assert select is not None and select.has_attr("required")
        options = [o["value"] for o in select.select("option") if o.get("value")]
        assert options == [t.name for t in TOKEN_TYPES]
        form = soup.select_one("form[action$='/api-access/tokens']")
        for t in TOKEN_TYPES:
            assert t.label in select.get_text()
            assert t.description in form.get_text(" ", strip=True)
        assert form.select_one("input[name=name]") is not None

    async def test_creating_a_token_saves_its_type_and_shows_it_once(self, app, member):
        resp = await member.post("/api-access/tokens", data={"name": "ci-bot", "type": "warm_restart"})
        assert resp.status_code == 200
        plaintext = page(resp.text).select_one("#new-token").get_text(strip=True)
        assert app.state.api_access.list_tokens()[0].type == "warm_restart"
        assert plaintext not in app.state.api_access.path.read_text()
        assert plaintext not in (await member.get("/api-access")).text

    @pytest.mark.parametrize("data", [{"name": "ci-bot"}, {"name": "ci-bot", "type": ""}, {"name": "ci-bot", "type": "admin"}])
    async def test_a_missing_or_unknown_type_is_a_400_and_creates_nothing(self, app, member, data):
        resp = await member.post("/api-access/tokens", data=data)
        assert resp.status_code == 400
        assert "type" in resp.text.lower()
        assert page(resp.text).select_one("#new-token") is None
        assert app.state.api_access.list_tokens() == []
        assert page(resp.text).select_one("input[name=name]")["value"] == "ci-bot"

    async def test_the_token_list_shows_the_type(self, app, member):
        app.state.api_access.create_token("ci-bot", created_by="x", token_type="warm_restart")
        soup = page((await member.get("/api-access")).text)
        row = soup.select_one("#tokens tbody tr")
        assert "ci-bot" in row.get_text()
        assert "Warm restart client" in row.get_text()
        assert "Type" in soup.select_one("#tokens thead").get_text()

    async def test_an_old_token_is_listed_as_a_warm_restart_client(self, app, member):
        write_old_file(app.state.api_access.path)
        row = page((await member.get("/api-access")).text).select_one("#tokens tbody tr")
        assert "ci-bot" in row.get_text() and "Warm restart client" in row.get_text()

    async def test_the_tick_section_lists_every_type_with_its_description(self, app, member):
        soup = page((await member.get("/api-access")).text)
        boxes = soup.select("input[type=checkbox][name^=allow_]")
        assert [b["name"] for b in boxes] == [f"allow_{t.name}" for t in TOKEN_TYPES]
        for t in TOKEN_TYPES:
            row = soup.select_one(f"#api-type-{t.name}")
            assert t.label in row.get_text() and t.description in row.get_text()

    async def test_the_defaults_tick_only_the_types_that_are_on_by_default(self, member):
        soup = page((await member.get("/api-access")).text)
        for t in TOKEN_TYPES:
            box = soup.select_one(f"input[name=allow_{t.name}]")
            assert box.has_attr("checked") is t.default_enabled, t.name

    async def test_ticking_a_type_enables_it(self, app, member):
        await member.post("/api-access/settings", data={"allow_warm_restart": "on", "interval_live": "30", "interval_paper": "30"})
        assert app.state.api_access.enabled_types() == frozenset({"warm_restart"})
        await member.post("/api-access/settings", data={"interval_live": "30", "interval_paper": "30"})
        assert app.state.api_access.enabled_types() == frozenset()

    async def test_a_type_ibctl_blocks_is_greyed_out_and_inactive(self, app, member):
        for stub in app.state.stubs.values():
            stub.allowed = WITHOUT_SETRESTART
        row = page((await member.get("/api-access")).text).select_one("#api-type-warm_restart")
        assert row.select_one("input[type=checkbox]").has_attr("disabled")
        assert "inactive: blocked by ibctl" in row.get_text()

    async def test_the_warm_restart_interval_settings_stay(self, member):
        soup = page((await member.get("/api-access")).text)
        assert soup.select_one("input[name=interval_live]") is not None
        assert soup.select_one("input[name=interval_paper]") is not None

    async def test_saving_redirects_under_the_proxy_prefix(self, app, member):
        app.state.templates.env.globals["root_path"] = "/ibctl"
        resp = await member.post("/api-access/settings", data={"interval_live": "30", "interval_paper": "30"})
        assert resp.status_code == 303 and resp.headers["location"] == "/ibctl/api-access?saved=1"
