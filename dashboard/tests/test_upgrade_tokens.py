"""The two Gateway upgrade token types: CI reports a build, the maintenance job reports a swap.

`upgrade_ci` reads GET /api/v1/gateway/upgrade and posts the candidate image;
`upgrade_maintenance` reads the same state and posts what its swap did. Neither
can call the other's POST, neither can touch the policy or anything else, and
both are off until the operator enables them on the API access page.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import pytest
from bs4 import BeautifulSoup

from app.services import api_access
from app.services.api_access import TOKEN_TYPES
from app.services.gateway_version.upgrade import UpgradeStore
from tests.api_access_helpers import bearer, build_app, client_for, member_client

SHA = "0123456789abcdef0123456789abcdef01234567"  # nosecret: a made-up commit id
STATE = "/api/v1/gateway/upgrade"
CANDIDATE = "/api/v1/gateway/upgrade/candidate"
SWAP = "/api/v1/gateway/upgrade/swap"
BUILD = {"version": "10.51.1h", "sha": SHA, "status": "built"}
SWAPPED = {"version": "10.51.1h", "sha": SHA, "result": "ok"}
IP = "203.0.113.9"
NOW = datetime(2026, 11, 14, 18, tzinfo=timezone.utc)

CI, MAINTENANCE, WARM = "upgrade_ci", "upgrade_maintenance", "warm_restart"
EVERY_TYPE = [WARM, CI, MAINTENANCE]

# Routes only a signed-in person may use: a token of any type is refused on all of them.
LOGIN_ONLY = [
    ("PUT", "/api/v1/gateway/upgrade/policy"),
    ("POST", "/api/v1/gateway/version/check"),
    ("GET", "/api/v1/gateway/version"),
    ("GET", "/api/v1/status"),
    ("GET", "/api/v1/logs"),
    ("POST", "/api/v1/command"),
    ("POST", "/api/session/touch"),
    ("GET", "/api-access"),
    ("POST", "/api-access/tokens"),
    ("POST", "/api-access/settings"),
]
POLICY = {"enabled": True, "channel": "stable", "cadence": "every_sunday", "soak_days": 7, "deadline_days": 21}


@pytest.fixture
def app(tmp_path):
    app = build_app(tmp_path)
    app.state.gateway_upgrade = UpgradeStore(tmp_path / "config" / "policy.json", tmp_path / "upgrade.json", clock=lambda: NOW)
    return app


@pytest.fixture
async def anon(app):
    async with client_for(app) as c:
        yield c


@pytest.fixture
async def member(app):
    c = await member_client(app)
    yield c
    await c.aclose()


@pytest.fixture
def tokens(app):
    """One token of each type, with every type enabled."""
    app.state.api_access.set_enabled(EVERY_TYPE)
    return {t: app.state.api_access.create_token(f"tok-{t}", created_by="x", token_type=t)[1] for t in EVERY_TYPE}


def page(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


class TestTheTypes:
    def test_ci_has_the_state_and_the_candidate(self):
        ci = api_access.find_token_type(CI)
        assert ci.label == "Gateway upgrade: CI"
        assert set(ci.routes) == {("GET", STATE), ("POST", CANDIDATE)}

    def test_maintenance_has_the_state_and_the_swap(self):
        job = api_access.find_token_type(MAINTENANCE)
        assert job.label == "Gateway upgrade: maintenance"
        assert set(job.routes) == {("GET", STATE), ("POST", SWAP)}

    def test_the_table_has_these_three_types_in_this_order(self):
        assert [t.name for t in TOKEN_TYPES] == EVERY_TYPE

    def test_the_upgrade_types_send_ibctl_nothing(self):
        assert api_access.find_token_type(CI).ibctl_command is None
        assert api_access.find_token_type(MAINTENANCE).ibctl_command is None

    def test_only_warm_restart_is_on_by_default(self, tmp_path):
        store = api_access.ApiAccessStore(tmp_path / "api_access.json")
        assert store.enabled_types() == {WARM}
        assert [t.name for t in TOKEN_TYPES if t.default_enabled] == [WARM]


class TestWhatEachTypeDoes:
    async def test_ci_reads_the_state_and_reports_a_build(self, app, anon, tokens):
        assert (await anon.get(STATE, headers=bearer(tokens[CI]))).status_code == 200
        resp = await anon.post(CANDIDATE, json=BUILD, headers=bearer(tokens[CI]))
        assert resp.status_code == 200
        assert resp.json()["candidate"]["sha"] == SHA
        assert app.state.gateway_upgrade.record().candidate.sha == SHA

    async def test_maintenance_reads_the_state_and_reports_a_swap(self, app, anon, tokens):
        assert (await anon.get(STATE, headers=bearer(tokens[MAINTENANCE]))).status_code == 200
        resp = await anon.post(SWAP, json=SWAPPED, headers=bearer(tokens[MAINTENANCE]))
        assert resp.status_code == 200
        assert app.state.gateway_upgrade.record().last_swap.result == "ok"

    async def test_the_report_is_still_validated_by_the_handler(self, app, anon, tokens):
        resp = await anon.post(CANDIDATE, json={**BUILD, "status": "great"}, headers=bearer(tokens[CI]))
        assert resp.status_code == 422
        assert app.state.gateway_upgrade.record().candidate is None


class TestAnotherTypeIsRefused:
    async def test_a_ci_token_cannot_report_a_swap(self, app, anon, tokens):
        resp = await anon.post(SWAP, json=SWAPPED, headers=bearer(tokens[CI]))
        assert resp.status_code == 403 and resp.json()["error"] == "wrong_token_type"
        assert app.state.gateway_upgrade.record().last_swap is None

    async def test_a_maintenance_token_cannot_steer_the_candidate(self, app, anon, tokens):
        resp = await anon.post(CANDIDATE, json=BUILD, headers=bearer(tokens[MAINTENANCE]))
        assert resp.status_code == 403 and resp.json()["error"] == "wrong_token_type"
        assert app.state.gateway_upgrade.record().candidate is None

    @pytest.mark.parametrize(("method", "path", "body"), [("GET", STATE, None), ("POST", CANDIDATE, BUILD), ("POST", SWAP, SWAPPED)])
    async def test_a_warm_restart_token_cannot_use_an_upgrade_route(self, app, anon, tokens, method, path, body):
        resp = await anon.request(method, path, json=body, headers=bearer(tokens[WARM]))
        assert resp.status_code == 403
        assert app.state.gateway_upgrade.record().candidate is None and app.state.gateway_upgrade.record().last_swap is None

    @pytest.mark.parametrize("kind", [CI, MAINTENANCE])
    async def test_an_upgrade_token_cannot_use_warm_restart(self, app, anon, tokens, kind):
        post = await anon.post("/api/v1/warm-restart", json={"mode": "paper"}, headers=bearer(tokens[kind]))
        get = await anon.get("/api/v1/warm-restart", params={"mode": "paper"}, headers=bearer(tokens[kind]))
        assert post.status_code == 403 and get.status_code == 403
        assert app.state.stubs["paper"].sent == []


class TestEveryTypeIsRefusedTheRest:
    @pytest.mark.parametrize("kind", EVERY_TYPE)
    @pytest.mark.parametrize(("method", "path"), LOGIN_ONLY)
    async def test_a_token_gets_nothing_a_person_alone_may_do(self, app, anon, tokens, kind, method, path):
        resp = await anon.request(method, path, headers=bearer(tokens[kind], Accept="application/json"))
        assert resp.status_code == 401, (kind, method, path)

    @pytest.mark.parametrize("kind", EVERY_TYPE)
    async def test_a_token_cannot_save_the_policy(self, app, anon, tokens, kind):
        resp = await anon.put("/api/v1/gateway/upgrade/policy", json=POLICY, headers=bearer(tokens[kind]))
        assert resp.status_code == 401
        assert app.state.gateway_upgrade.policy().enabled is False

    async def test_a_person_signed_in_still_uses_all_of_them_without_a_type(self, app, member):
        assert (await member.get(STATE)).status_code == 200
        assert (await member.post(CANDIDATE, json=BUILD)).status_code == 200
        assert (await member.post(SWAP, json=SWAPPED)).status_code == 200
        assert (await member.put("/api/v1/gateway/upgrade/policy", json=POLICY)).status_code == 200


class TestOffUntilEnabled:
    @pytest.mark.parametrize(("kind", "method", "path", "body"), [(CI, "GET", STATE, None), (CI, "POST", CANDIDATE, BUILD), (MAINTENANCE, "GET", STATE, None), (MAINTENANCE, "POST", SWAP, SWAPPED)])
    async def test_a_fresh_dashboard_refuses_them_saying_which_type(self, app, anon, kind, method, path, body):
        _, plaintext = app.state.api_access.create_token("tok", created_by="x", token_type=kind)
        resp = await anon.request(method, path, json=body, headers=bearer(plaintext))
        assert resp.status_code == 403
        detail = resp.json()["detail"]
        assert api_access.find_token_type(kind).label in detail and kind in detail and "API access page" in detail
        assert app.state.gateway_upgrade.record().candidate is None

    async def test_ticking_a_type_on_the_page_turns_it_on_for_that_type_only(self, app, anon, member):
        _, ci = app.state.api_access.create_token("ci", created_by="x", token_type=CI)
        _, job = app.state.api_access.create_token("job", created_by="x", token_type=MAINTENANCE)
        resp = await member.post(
            "/api-access/settings",
            data={"allow_warm_restart": "on", "allow_upgrade_ci": "on", "interval_live": "30", "interval_paper": "30"},
        )
        assert resp.status_code == 303
        assert (await anon.post(CANDIDATE, json=BUILD, headers=bearer(ci))).status_code == 200
        assert (await anon.get(STATE, headers=bearer(job))).status_code == 403

    async def test_unticking_it_turns_it_off_again(self, app, anon, member, tokens):
        assert (await anon.get(STATE, headers=bearer(tokens[CI]))).status_code == 200
        await member.post("/api-access/settings", data={"allow_warm_restart": "on", "interval_live": "30", "interval_paper": "30"})
        assert (await anon.get(STATE, headers=bearer(tokens[CI]))).status_code == 403

    async def test_ibctl_blocking_everything_does_not_touch_the_upgrade_types(self, app, anon, member, tokens):
        for stub in app.state.stubs.values():
            stub.allowed = []
        rows = {t.name: page((await member.get("/api-access")).text).select_one(f"#api-type-{t.name}") for t in TOKEN_TYPES}
        assert "blocked by ibctl" in rows[WARM].get_text()
        for kind in (CI, MAINTENANCE):
            assert "blocked by ibctl" not in rows[kind].get_text()
            assert not rows[kind].select_one("input[type=checkbox]").has_attr("disabled")
        assert (await anon.get(STATE, headers=bearer(tokens[CI]))).status_code == 200


class TestAudit:
    async def test_an_upgrade_call_is_logged_with_name_type_and_address(self, app, anon, tokens, caplog):
        with caplog.at_level(logging.INFO):
            await anon.post(CANDIDATE, json=BUILD, headers=bearer(tokens[CI], **{"X-Real-IP": IP}))
            await anon.post(SWAP, json=SWAPPED, headers=bearer(tokens[CI], **{"X-Real-IP": IP}))
        lines = [r.getMessage() for r in caplog.records if r.name == "dashboard.auth"]
        accepted = next(m for m in lines if "Accepted" in m)
        rejected = next(m for m in lines if "Rejected" in m)
        for line in (accepted, rejected):
            assert "tok-upgrade_ci" in line and "upgrade_ci" in line and IP in line
        assert CANDIDATE in accepted and SWAP in rejected
        assert tokens[CI] not in caplog.text


class TestThePage:
    async def test_the_dropdown_and_the_tick_list_have_all_three_types(self, member):
        soup = page((await member.get("/api-access")).text)
        select = soup.select_one("select[name=type]")
        assert [o["value"] for o in select.select("option") if o.get("value")] == EVERY_TYPE
        assert [b["name"] for b in soup.select("input[type=checkbox][name^=allow_]")] == [f"allow_{t}" for t in EVERY_TYPE]
        text = soup.select_one("form[action$='/api-access/tokens']").get_text(" ", strip=True)
        for t in TOKEN_TYPES:
            assert t.label in text and t.description in text

    async def test_the_upgrade_types_start_unticked_and_warm_restart_ticked(self, member):
        soup = page((await member.get("/api-access")).text)
        assert soup.select_one("input[name=allow_warm_restart]").has_attr("checked")
        assert not soup.select_one("input[name=allow_upgrade_ci]").has_attr("checked")
        assert not soup.select_one("input[name=allow_upgrade_maintenance]").has_attr("checked")

    @pytest.mark.parametrize("kind", [CI, MAINTENANCE])
    async def test_creating_an_upgrade_token_saves_its_type(self, app, member, kind):
        resp = await member.post("/api-access/tokens", data={"name": f"tok-{kind}", "type": kind})
        assert resp.status_code == 200
        assert app.state.api_access.list_tokens()[0].type == kind
        row = page((await member.get("/api-access")).text).select_one("#tokens tbody tr")
        assert api_access.find_token_type(kind).label in row.get_text()

    async def test_the_page_shows_how_to_call_each_type(self, member):
        html = (await member.get("/api-access")).text
        for path in ("/api/v1/warm-restart", STATE, CANDIDATE, SWAP):
            assert path in html
