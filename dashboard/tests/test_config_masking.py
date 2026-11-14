"""The IB login name never reaches a browser, logged in or not.

The Config page and the JSON config view show `tws_userid` as "set" or
"not set". Everything that carries ibctl's configuration to a response goes
through `app.services.identity_mask`, so these tests plant sentinel strings
at every source (ibctl.toml, the env overrides, ibctl's CONFIG reply) and
sweep the app's GET routes for them.
"""

from __future__ import annotations

import pytest
from bs4 import BeautifulSoup
from httpx import ASGITransport, AsyncClient

from app.main import create_app
from app.services.identity_mask import NOT_SET, SET, mask_identity
from tests.auth_helpers import authed_settings, log_in, route_table

LIVE_USER = "zq_sentinel_live_user"
PAPER_USER = "zq_sentinel_paper_user"
ENV_USER = "zq_sentinel_env_user"
ACCOUNT = "DU9988776"
SENTINELS = (LIVE_USER, PAPER_USER, ENV_USER, ACCOUNT)

TOML_WITH_USERS = f"""
[auth]
tws_userid = "{LIVE_USER}"
trading_mode = "both"

[auth.paper]
tws_userid = "{PAPER_USER}"
"""

TOML_WITHOUT_USERS = """
[auth]
tws_userid = ""
trading_mode = "both"

[auth.paper]
tws_userid = ""
"""


def planted_config_reply() -> dict:
    """ibctl's CONFIG reply with sentinels in the places a user name or account could sit."""
    return {
        "auth": {
            "username": LIVE_USER,
            "trading_mode": "both",
            "password": "********",
            "paper": {"username": PAPER_USER},
            "tws_userid": LIVE_USER,
        },
        "twofa": {"device": f"phone enrolled for {ACCOUNT}", "timeout_seconds": 180},
        "gateway": {"version": "10.50.1f", "settings_path": f"/home/ibgateway/Jts/{ACCOUNT}"},
    }


@pytest.fixture
def toml_file(tmp_path, monkeypatch):
    """Point the dashboard at a temp ibctl.toml with no env overrides leaking in."""
    for env in ("TWS_USERID", "TWS_USERID_FILE", "TWS_USERID_PAPER", "TWS_USERID_PAPER_FILE"):
        monkeypatch.delenv(env, raising=False)
    path = tmp_path / "ibctl.toml"
    monkeypatch.setenv("IBCTL_CONFIG", str(path))

    def write(text: str):
        path.write_text(text)

    write(TOML_WITH_USERS)
    return write


def config_rows(html: str) -> dict[str, str]:
    """The Config page's key -> displayed value, read from the rendered HTML."""
    rows = {}
    for key_span in BeautifulSoup(html, "html.parser").select("span.cfg-key"):
        value_span = key_span.find_next_sibling("span")
        rows[key_span.contents[0].strip()] = value_span.get_text(strip=True)
    return rows


def assert_no_sentinels(body: str, where: str):
    for sentinel in SENTINELS:
        assert sentinel not in body, f"{sentinel!r} leaked in {where}"


class TestConfigPage:
    async def test_userids_show_as_set_never_as_the_value(self, client, toml_file):
        resp = await client.get("/partials/config")
        assert resp.status_code == 200
        rows = config_rows(resp.text)
        assert rows["tws_userid"] == SET
        assert rows["paper.tws_userid"] == SET
        assert_no_sentinels(resp.text, "/partials/config")

    async def test_the_account_summary_line_hides_the_user_too(self, client, toml_file):
        resp = await client.get("/partials/config")
        summary = BeautifulSoup(resp.text, "html.parser").select_one("span.accordion-status")
        assert summary.get_text(strip=True) == f"both — {SET}"

    async def test_empty_userids_show_as_not_set(self, client, toml_file):
        toml_file(TOML_WITHOUT_USERS)
        resp = await client.get("/partials/config")
        rows = config_rows(resp.text)
        assert rows["tws_userid"] == NOT_SET
        assert rows["paper.tws_userid"] == NOT_SET

    async def test_a_userid_set_by_env_shows_as_set(self, client, toml_file, monkeypatch):
        toml_file(TOML_WITHOUT_USERS)
        monkeypatch.setenv("TWS_USERID", ENV_USER)
        monkeypatch.setenv("TWS_USERID_PAPER", ENV_USER)
        resp = await client.get("/partials/config")
        rows = config_rows(resp.text)
        assert rows["tws_userid"] == SET
        assert rows["paper.tws_userid"] == SET
        assert_no_sentinels(resp.text, "/partials/config")

    async def test_other_settings_still_show_their_values(self, client, toml_file):
        resp = await client.get("/partials/config")
        assert config_rows(resp.text)["trading_mode"] == "both"


class TestConfigJson:
    async def test_the_config_reply_is_masked(self, client, fake_client):
        fake_client._config = planted_config_reply()
        resp = await client.get("/api/v1/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth"]["username"] == SET
        assert data["auth"]["tws_userid"] == SET
        assert data["auth"]["paper"]["username"] == SET
        assert_no_sentinels(resp.text, "/api/v1/config")

    async def test_other_values_pass_through(self, client, fake_client):
        fake_client._config = planted_config_reply()
        data = (await client.get("/api/v1/config")).json()
        assert data["auth"]["trading_mode"] == "both"
        assert data["auth"]["password"] == "********"
        assert data["twofa"]["timeout_seconds"] == 180
        assert data["gateway"]["version"] == "10.50.1f"


class TestPreflightView:
    async def test_a_malformed_userid_is_not_echoed_back(self, fake_client, monkeypatch, tmp_path):
        monkeypatch.delenv("TWS_USERID_FILE", raising=False)
        monkeypatch.setenv("TWS_USERID", "zq bad user!")
        app = create_app(settings=authed_settings(debug_mode=True))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await log_in(c)
            resp = await c.get("/api/v1/debug/preflight")
        assert resp.status_code == 200
        body = resp.json()
        assert any(e["field"] == "auth.tws_userid" for e in body["errors"])
        assert "zq bad user" not in resp.text


class TestEveryGetRoute:
    """No GET route a logged-in person can reach carries a sentinel."""

    # The event stream never ends, so it can't be read to the end here. It
    # pushes STATUS replies only, which carry no config.
    STREAMING = {"/api/v1/events"}

    async def test_no_route_leaks_the_user_or_an_account(self, client, fake_client, toml_file):
        fake_client._config = planted_config_reply()
        routes = [
            path for method, path in route_table(create_app(settings=authed_settings()))
            if method == "GET" and path not in self.STREAMING
        ]
        assert "/partials/config" in routes and "/api/v1/config" in routes
        for path in routes:
            resp = await client.get(path, headers={"Accept": "*/*"})
            assert_no_sentinels(resp.text, f"GET {path}")


class TestMaskIdentity:
    def test_masks_by_key_name_at_any_depth(self):
        masked = mask_identity({"a": {"b": [{"tws_userid": "x"}, {"username": ""}]}})
        assert masked == {"a": {"b": [{"tws_userid": SET}, {"username": NOT_SET}]}}

    def test_scrubs_account_numbers_out_of_strings(self):
        masked = mask_identity({"path": "/jts/DU1234567/x", "n": 7, "ok": "10.50.1f", "xs": ["U7654321"]})
        assert "DU1234567" not in masked["path"] and "U7654321" not in masked["xs"][0]
        assert masked["n"] == 7 and masked["ok"] == "10.50.1f"

    def test_does_not_change_its_argument(self):
        original = {"auth": {"tws_userid": "secretish"}}
        mask_identity(original)
        assert original == {"auth": {"tws_userid": "secretish"}}

    def test_leaves_unrelated_user_lists_alone(self):
        data = {"github_oauth_allowed_users": ["octocat"], "oidc_allowed_users": "alice"}
        assert mask_identity(data) == data
