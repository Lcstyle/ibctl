"""Access control: who may reach what, with and without a login.

A "login" is a dashboard password, GitHub OAuth or OIDC, plus the visitor
having signed in through it. Without one, a visitor sees only a health summary.

Fixtures, all on the same app with a planted STATUS payload that carries
sentinel strings (an account number and a user name) nobody anonymous may see:
  anon        a visitor who is not logged in; a password is configured
  member      a visitor who signed in through the login form
  nologin     a dashboard with no login method configured at all
"""

from __future__ import annotations

import logging
import os
import re
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from app.config import DashboardSettings
from app.instance_registry import _CachedResponse
from app.main import create_app
from app.middleware import auth as auth_module
from app.services.gateway_version.service import VersionState
from tests.auth_helpers import TEST_PASSWORD, authed_settings, log_in, logged_in_cookies, route_table

SIGNING_KEY = "test-signing-key-for-access-tests"  # nosecret: test value

ACCOUNT = "DU7654321"
USER = "sentinel_user_xyz"
IBCTL_VERSION = "1.3.0-test"
GATEWAY_VERSION = "10.50.1f"
SENTINELS = (ACCOUNT, USER)


class _Client:
    """Stands in for the ibctl connection: records commands, never opens a socket."""

    def __init__(self):
        self.sent: list[str] = []

    async def send_command(self, command: str) -> str:
        self.sent.append(command)
        return "OK"


def sentinel_status(**overrides) -> dict:
    status = {
        "version": IBCTL_VERSION,
        "ready": True,
        "state": "Connected",
        "trading_mode": "paper",
        "uptime_secs": 7200,
        "connected_uptime_secs": 3600,
        "account": ACCOUNT,
        "tws_userid": USER,
        "jvm": {"alive": True, "pid": 4242, "config_dir": f"/home/ibgateway/Jts/{USER}"},
        "clients": {"count": 1, "ids": [ACCOUNT]},
        "ib_system": {"available": True, "status": "ok", "reason": f"account {ACCOUNT}"},
        "paused": False,
        "hitl": None,
        "stats": {},
        "client_advisory": {"should_connect": True, "should_wait": False},
    }
    status.update(overrides)
    return status


def build_app(settings):
    app = create_app(settings=settings)
    registry = app.state.instance_registry
    fake = _Client()
    app.state.fake_ibctl = fake
    for mode in registry.modes():
        registry._clients[mode] = fake
        registry._cache[f"{mode}:STATUS"] = _CachedResponse(sentinel_status(), ttl=60.0)
    app.state.ibctl_client = fake
    app.state.gateway_version = SimpleNamespace(
        current=lambda: VersionState(running=GATEWAY_VERSION), next_check=lambda: None
    )
    return app


def client_for(app) -> AsyncClient:
    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    client.app = app  # tests reach into the app's registry and fake ibctl
    return client


@pytest.fixture
async def anon():
    app = build_app(authed_settings(trading_mode="both"))
    with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
        async with client_for(app) as c:
            yield c


@pytest.fixture
async def member():
    app = build_app(authed_settings(trading_mode="both"))
    async with client_for(app) as c:
        await log_in(c)
        yield c


@pytest.fixture
async def nologin():
    app = build_app(authed_settings(token="", auth_secret=None, trading_mode="both"))
    with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
        async with client_for(app) as c:
            yield c


def oauth_only_settings():
    return authed_settings(
        token="",
        auth_secret=SecretStr("oauth-only-secret"),  # nosecret: test value
        github_client_id="client-id",
        github_client_secret=SecretStr("client-secret"),  # nosecret: test value
    )


# --- signed notification links work without a login ---

class TestSignedNotificationLinks:
    """Both callbacks authenticate themselves with an HMAC token in the URL,
    so they sit outside the login check; the handler still has to say no to a
    missing or wrong token."""

    @pytest.mark.asyncio
    async def test_twofa_callback_is_reachable_and_rejects_a_bad_token(self, anon):
        resp = await anon.get("/api/twofa/callback", params={"t": "not-a-real-token", "mode": "paper"})
        assert resp.status_code == 400
        assert resp.headers["content-type"].startswith("text/html")

    @pytest.mark.asyncio
    async def test_twofa_callback_rejects_a_missing_token(self, anon):
        resp = await anon.get("/api/twofa/callback", params={"mode": "paper"})
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_reconnect_callback_get_is_reachable_and_rejects_a_bad_token(self, anon):
        resp = await anon.get("/api/reconnect/callback", params={"t": "not-a-real-token", "mode": "paper"})
        assert resp.status_code == 403
        assert resp.json()["error"] == "invalid_token"

    @pytest.mark.asyncio
    async def test_reconnect_callback_post_is_reachable_and_rejects_a_bad_token(self, anon):
        resp = await anon.post("/api/reconnect/callback", data={"t": "not-a-real-token", "mode": "paper"})
        assert resp.status_code == 403
        assert resp.json()["error"] == "invalid_token"

    @pytest.mark.asyncio
    async def test_reconnect_callback_rejects_a_missing_token(self, anon):
        resp = await anon.get("/api/reconnect/callback", params={"mode": "paper"})
        assert resp.status_code == 403
        assert resp.json()["error"] == "invalid_token"
        resp = await anon.post("/api/reconnect/callback", data={"mode": "paper"})
        assert resp.status_code == 403
        assert resp.json()["error"] == "invalid_token"

    @pytest.mark.asyncio
    async def test_only_the_exact_callback_paths_are_exempt(self, anon):
        for path in (
            "/api/reconnect/callback/",
            "/api/reconnect/callback/extra",
            "/api/reconnect/callbacks",
            "/api/twofa/callback/",
            "/api/twofa/callback/extra",
        ):
            resp = await anon.get(path, headers={"Accept": "application/json"})
            assert resp.status_code == 401, path

    @pytest.mark.asyncio
    async def test_callbacks_work_with_no_login_configured_too(self, nologin):
        resp = await nologin.get("/api/twofa/callback", params={"t": "bad", "mode": "paper"})
        assert resp.status_code == 400
        resp = await nologin.get("/api/reconnect/callback", params={"t": "bad", "mode": "paper"})
        assert resp.status_code == 403
        assert resp.json()["error"] == "invalid_token"


# --- an anonymous visitor gets only the health summary ---

class TestAnonymousHealthSummary:
    @pytest.mark.asyncio
    async def test_root_is_a_200_summary_with_a_login_link(self, anon):
        resp = await anon.get("/")
        assert resp.status_code == 200
        html = resp.text
        assert "Connected" in html
        assert GATEWAY_VERSION in html
        assert IBCTL_VERSION in html
        assert re.search(r"<a[^>]+href=\"/login\"[^>]*>\s*Log in", html)
        assert "IBCTL_DASHBOARD_TOKEN" not in html  # the how-to-enable banner is for dashboards with no login

    @pytest.mark.asyncio
    async def test_root_lists_both_modes(self, anon):
        html = (await anon.get("/")).text
        assert "LIVE" in html and "PAPER" in html

    @pytest.mark.asyncio
    async def test_root_carries_nothing_from_the_status_payload_beyond_the_whitelist(self, anon):
        html = (await anon.get("/")).text
        for sentinel in SENTINELS:
            assert sentinel not in html
        assert "4242" not in html  # jvm pid

    @pytest.mark.asyncio
    async def test_root_pulls_in_no_login_only_part_of_the_dashboard(self, anon):
        html = (await anon.get("/")).text
        for forbidden in ("/partials/", "/api/v1/events", "hx-get", 'href="/state"', 'href="/logs"', 'href="/vnc"'):
            assert forbidden not in html, forbidden

    @pytest.mark.asyncio
    async def test_the_password_as_a_bearer_token_gets_the_summary_not_the_overview(self, anon):
        resp = await anon.get("/", headers={"Authorization": f"Bearer {TEST_PASSWORD}"})
        assert resp.status_code == 200
        assert "hx-get" not in resp.text

    @pytest.mark.asyncio
    async def test_health_endpoint_is_public_json_built_from_a_whitelist(self, anon):
        resp = await anon.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert set(data) == {"status", "modes", "gateway_version"}
        assert data["status"] == "ok"
        assert data["gateway_version"] == GATEWAY_VERSION
        assert {m["mode"] for m in data["modes"]} == {"live", "paper"}
        for entry in data["modes"]:
            assert set(entry) == {"mode", "state", "api_ready", "since", "ibctl_version"}
            assert entry["state"] == "Connected"
            assert entry["api_ready"] is True
            assert entry["ibctl_version"] == IBCTL_VERSION
            assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", entry["since"])

    @pytest.mark.asyncio
    async def test_the_summary_page_shows_since_in_the_container_zone_while_the_api_stays_utc(self, anon, monkeypatch):
        monkeypatch.setenv("TZ", "America/New_York")
        api = (await anon.get("/api/v1/health")).json()["modes"][0]["since"]
        html = (await anon.get("/")).text
        assert api.endswith("Z")
        assert re.search(r"since \d{4}-\d\d-\d\d \d\d:\d\d:\d\d E[SD]T", html), html
        assert " UTC" not in html

    @pytest.mark.asyncio
    async def test_health_endpoint_never_carries_the_planted_sentinels(self, anon):
        text = (await anon.get("/api/v1/health")).text
        for sentinel in SENTINELS:
            assert sentinel not in text
        assert "4242" not in text

    @pytest.mark.asyncio
    async def test_a_status_field_added_later_stays_out_of_the_summary(self, anon):
        registry = anon.app.state.instance_registry
        for mode in registry.modes():
            registry._cache[f"{mode}:STATUS"] = _CachedResponse(
                sentinel_status(brand_new_field="shiny-secret", ready=False), ttl=60.0
            )
        health = await anon.get("/api/v1/health")
        assert "shiny-secret" not in health.text + (await anon.get("/")).text
        entry = health.json()["modes"][0]
        assert entry["api_ready"] is False
        assert entry["since"] is None

    @pytest.mark.asyncio
    async def test_before_the_first_status_arrives_the_summary_says_so(self, anon):
        anon.app.state.instance_registry._cache.clear()
        data = (await anon.get("/api/v1/health")).json()
        assert data["status"] == "ok"
        for entry in data["modes"]:
            assert entry["state"] == "unknown"
            assert entry["api_ready"] is False
            assert entry["since"] is None
            assert entry["ibctl_version"] is None
        assert (await anon.get("/")).status_code == 200

    @pytest.mark.asyncio
    async def test_health_is_the_same_for_a_member(self, anon, member):
        a, m = (await anon.get("/api/v1/health")).json(), (await member.get("/api/v1/health")).json()
        assert set(a) == set(m)
        assert a["modes"][0]["state"] == m["modes"][0]["state"]


class TestLoggedInOverviewUnchanged:
    @pytest.mark.asyncio
    async def test_member_gets_the_full_overview_shell(self, member):
        resp = await member.get("/")
        assert resp.status_code == 200
        html = resp.text
        assert 'id="overview-content"' in html
        assert 'hx-get="/partials/overview"' in html
        assert 'href="/state"' in html  # the full navigation
        assert "Log in" not in html

    @pytest.mark.asyncio
    async def test_member_still_reaches_the_overview_partial(self, member):
        resp = await member.get("/partials/overview")
        assert resp.status_code == 200
        assert "Gateway state" in resp.text


# --- everything but the public allow-list needs a login ---

# The routes anyone may reach without a login. Every other route the app
# serves has to turn an anonymous request away: a route added later is covered
# by the sweeps below without anyone editing this file, and a route that is
# public by mistake fails them.
PUBLIC_ROUTES = {
    ("GET", "/"),
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/ib-status"),  # anonymous callers get a fixed list of fields
    ("GET", "/api/v1/schedule"),  # fixed restart timetable, the same for everyone
    ("GET", "/login"),
    ("POST", "/login"),
    ("POST", "/logout"),
    ("GET", "/auth/github"),
    ("GET", "/auth/github/callback"),
    ("GET", "/auth/oidc"),
    ("GET", "/auth/oidc/callback"),
    ("GET", "/api/twofa/callback"),
    ("GET", "/api/reconnect/callback"),
    ("POST", "/api/reconnect/callback"),
}

ALL_ROUTES = route_table(create_app(settings=authed_settings(trading_mode="both")))
PROTECTED_ROUTES = [r for r in ALL_ROUTES if r not in PUBLIC_ROUTES]


def _is_html_page(method: str, path: str) -> bool:
    return method == "GET" and not path.startswith("/api/")


class TestRouteTableSweep:
    def test_the_sweep_sees_the_real_route_table(self):
        paths = {path for _, path in ALL_ROUTES}
        for expected in (
            "/", "/api/v1/logs", "/api/v1/logs/page", "/api/v1/events", "/api/v1/command", "/state",
            "/api/v1/notifications/history", "/api/v1/gateway/upgrade/swap", "/partials/overview",
        ):
            assert expected in paths
        assert len(ALL_ROUTES) > 40
        assert PUBLIC_ROUTES <= set(ALL_ROUTES)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("method", "path"), PROTECTED_ROUTES, ids=lambda v: str(v))
    async def test_anonymous_request_is_turned_away(self, anon, method, path):
        resp = await anon.request(method, path)
        if _is_html_page(method, path):
            assert resp.status_code == 303, (method, path, resp.status_code)
            assert "/login?next=" in resp.headers["location"]
        else:
            assert resp.status_code == 401, (method, path, resp.status_code)
        resp = await anon.request(method, path, headers={"Accept": "application/json"})
        assert resp.status_code == 401, (method, path, resp.status_code)
        for sentinel in SENTINELS:
            assert sentinel not in resp.text

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("method", "path"), PROTECTED_ROUTES, ids=lambda v: str(v))
    async def test_nothing_protected_is_reachable_with_no_login_configured(self, nologin, method, path):
        resp = await nologin.request(method, path)
        if _is_html_page(method, path):
            assert resp.status_code == 303, (method, path, resp.status_code)
            assert resp.headers["location"] == "/", "a login page cannot work here; send people to the summary"
        else:
            assert resp.status_code == 403, (method, path, resp.status_code)
            detail = resp.json()["detail"]
            assert "No login is configured" in detail
            assert "IBCTL_DASHBOARD_TOKEN" in detail
        assert nologin.app.state.fake_ibctl.sent == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("method", "path"), sorted(PUBLIC_ROUTES), ids=lambda v: str(v))
    async def test_the_public_routes_do_not_ask_for_a_login(self, anon, method, path):
        kwargs = {"data": {"password": TEST_PASSWORD}} if (method, path) == ("POST", "/login") else {}
        resp = await anon.request(method, path, **kwargs)
        assert resp.status_code != 401
        assert "next=" not in resp.headers.get("location", "")

    @pytest.mark.asyncio
    async def test_static_files_are_public(self, anon, nologin):
        for c in (anon, nologin):
            assert (await c.get("/static/style.css")).status_code == 200

    @pytest.mark.asyncio
    async def test_unknown_paths_do_not_reveal_whether_they_exist(self, anon, member):
        assert (await anon.get("/api/v1/nothing-here", headers={"Accept": "application/json"})).status_code == 401
        assert (await member.get("/api/v1/nothing-here")).status_code == 404

    @pytest.mark.asyncio
    async def test_a_path_that_only_looks_like_a_public_one_stays_protected(self, anon):
        for path in ("/static/../api/v1/logs", "/api/v1/health/../logs", "/api/v1/health/x", "/staticfoo", "//api/v1/logs"):
            resp = await anon.get(path, headers={"Accept": "application/json"})
            assert resp.status_code in (401, 404), (path, resp.status_code)


# The families the spec names, listed by hand so they are checked even if the
# sweep above shared a blind spot with the middleware.
LOGIN_ONLY = [
    ("GET", "/api/v1/logs"),
    ("GET", "/api/v1/logs/page?source=ibctl-paper"),
    ("GET", "/api/v1/logs/dates"),
    ("GET", "/api/v1/events"),
    ("GET", "/partials/state-history"),
    ("GET", "/api/v1/notifications/history"),
    ("GET", "/api/v1/status"),
    ("GET", "/api/v1/status/raw"),
    ("GET", "/api/v1/state"),
    ("GET", "/api/v1/windows"),
    ("GET", "/api/v1/config"),
    ("GET", "/api/v1/ib-status/audit-log"),
    ("GET", "/api/v1/debug/preflight"),
    ("GET", "/vnc"),
    ("GET", "/logs"),
    ("GET", "/config"),
    ("GET", "/gateway"),
    ("POST", "/api/v1/command"),
    ("POST", "/api/v1/debug/agent"),
    ("POST", "/api/v1/notifications/test"),
]


class TestNamedLoginOnlyRoutes:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(("method", "path"), LOGIN_ONLY, ids=lambda v: str(v))
    async def test_anonymous_gets_nothing(self, anon, method, path):
        resp = await anon.request(method, path)
        assert resp.status_code in (303, 401)
        assert "ibctl-paper" not in resp.text
        for sentinel in SENTINELS:
            assert sentinel not in resp.text

    @pytest.mark.asyncio
    async def test_the_logs_are_off_for_anonymous_visitors_not_filtered(self, anon):
        resp = await anon.get("/api/v1/logs/page", params={"source": "ibctl-paper"}, headers={"Accept": "application/json"})
        assert resp.status_code == 401
        assert resp.json() == {"detail": "Unauthorized"}


# --- no login method configured ---

class TestNoLoginConfigured:
    @pytest.mark.asyncio
    async def test_actions_get_403_with_the_explanation(self, nologin):
        resp = await nologin.post("/api/v1/command", json={"command": "RESTART"})
        assert resp.status_code == 403
        detail = resp.json()["detail"]
        assert "No login is configured" in detail
        assert "IBCTL_DASHBOARD_TOKEN" in detail
        assert "GitHub OAuth" in detail and "OIDC" in detail
        assert nologin.app.state.fake_ibctl.sent == []

    @pytest.mark.asyncio
    async def test_root_is_a_summary_with_the_how_to_enable_banner(self, nologin):
        resp = await nologin.get("/")
        assert resp.status_code == 200
        html = resp.text
        assert "No login is configured" in html
        assert "IBCTL_DASHBOARD_TOKEN" in html
        assert "GitHub OAuth" in html and "OIDC" in html
        assert "Connected" in html
        assert not re.search(r"<a[^>]+href=\"/login\"", html), "there is no login to link to"
        for sentinel in SENTINELS:
            assert sentinel not in html

    @pytest.mark.asyncio
    async def test_health_stays_public(self, nologin):
        resp = await nologin.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_the_login_routes_lead_back_to_the_summary(self, nologin):
        for method, path in (("GET", "/login"), ("POST", "/login"), ("GET", "/auth/github"), ("GET", "/auth/oidc")):
            resp = await nologin.request(method, path, follow_redirects=True)
            assert resp.status_code == 200, (method, path)
            assert "No login is configured" in resp.text, (method, path)

    @pytest.mark.asyncio
    async def test_a_forged_session_cookie_gets_nothing(self, nologin):
        for secret in ("", "anything"):
            nologin.cookies.update(logged_in_cookies(secret=secret))
            resp = await nologin.get("/api/v1/status", headers={"Accept": "application/json"})
            assert resp.status_code == 403


# --- Login routes for methods that are not configured ---

class TestLoginRoutesForUnconfiguredMethods:
    @pytest.mark.asyncio
    async def test_password_only_login_page_offers_only_the_password(self, anon):
        html = (await anon.get("/login")).text
        assert 'name="password"' in html
        assert "Sign in with GitHub" not in html and "Sign in with SSO" not in html
        resp = await anon.get("/auth/github")
        assert resp.status_code == 303 and resp.headers["location"].endswith("/login")
        resp = await anon.get("/auth/oidc")
        assert resp.status_code == 303 and resp.headers["location"].endswith("/login")

    @pytest.mark.asyncio
    async def test_oauth_only_dashboard_has_no_password_form_and_refuses_password_posts(self):
        async with client_for(build_app(oauth_only_settings())) as c:
            html = (await c.get("/login")).text
            assert 'name="password"' not in html
            assert "Sign in with GitHub" in html
            resp = await c.post("/login", data={"password": "anything", "next": "/"})  # nosecret: test value
            assert resp.status_code == 403
            assert "not enabled" in resp.text
            assert "ibctl_dashboard_auth" not in resp.headers.get("set-cookie", "")
            assert (await c.get("/api/v1/status", headers={"Accept": "application/json"})).status_code == 401

    @pytest.mark.asyncio
    async def test_a_password_session_means_nothing_when_only_oauth_is_configured(self):
        async with client_for(build_app(oauth_only_settings())) as c:
            c.cookies.update(logged_in_cookies(secret="oauth-only-secret"))  # nosecret: test value
            assert (await c.get("/api/v1/status", headers={"Accept": "application/json"})).status_code == 401


# --- The seam API tokens use ---

class _Token:
    name = "a-client"
    type = "warm_restart"


def _recognise_a_token(self, request, settings):
    return _Token()


class TestApiTokenSeam:
    """A bearer API token is not a login. Until a route is explicitly opened
    to tokens, a request that carries one is anonymous."""

    @pytest.mark.asyncio
    async def test_a_recognised_token_alone_opens_nothing_by_default(self, anon, monkeypatch):
        monkeypatch.setattr(auth_module.TokenAuthMiddleware, "_recognise_api_token", _recognise_a_token)
        headers = {"Authorization": "Bearer some-api-token", "Accept": "application/json"}
        assert (await anon.get("/api/v1/status", headers=headers)).status_code == 401
        assert (await anon.post("/api/v1/command", headers=headers, json={"command": "RESTART"})).status_code == 401
        assert (await anon.get("/api/v1/logs", headers=headers)).status_code == 401
        html = (await anon.get("/", headers={"Authorization": "Bearer some-api-token"})).text
        assert "hx-get" not in html  # still the anonymous summary, not the overview

    @pytest.mark.asyncio
    async def test_only_routes_listed_for_tokens_accept_one(self, anon, monkeypatch):
        monkeypatch.setattr(auth_module.TokenAuthMiddleware, "_recognise_api_token", _recognise_a_token)
        monkeypatch.setattr(auth_module, "TOKEN_ROUTES", {("GET", "/api/v1/notifications/config"): frozenset({"warm_restart"})})
        headers = {"Authorization": "Bearer some-api-token"}
        assert (await anon.get("/api/v1/notifications/config", headers=headers)).status_code == 200
        assert (await anon.get("/api/v1/status", headers=headers)).status_code == 401
        assert (await anon.post("/api/v1/notifications/config", headers=headers)).status_code == 401

    @pytest.mark.asyncio
    async def test_without_a_recognised_token_a_token_route_is_still_login_only(self, anon, monkeypatch):
        monkeypatch.setattr(auth_module, "TOKEN_ROUTES", {("GET", "/api/v1/notifications/config"): frozenset({"warm_restart"})})
        resp = await anon.get("/api/v1/notifications/config", headers={"Authorization": "Bearer made-up"})
        assert resp.status_code == 401


# --- Settings and the startup line ---

LOGIN_ENV = (
    "IBCTL_DASHBOARD_TOKEN",
    "IBCTL_DASHBOARD_AUTH_SECRET",
    "IBCTL_GITHUB_OAUTH_CLIENT_ID",
    "IBCTL_GITHUB_OAUTH_CLIENT_SECRET",
    "IBCTL_OIDC_ISSUER",
    "IBCTL_OIDC_CLIENT_ID",
    "IBCTL_OIDC_CLIENT_SECRET",
)
GITHUB = {"IBCTL_GITHUB_OAUTH_CLIENT_ID": "id", "IBCTL_GITHUB_OAUTH_CLIENT_SECRET": "s"}  # nosecret: test value
OIDC = {"IBCTL_OIDC_ISSUER": "https://sso.example", "IBCTL_OIDC_CLIENT_ID": "id", "IBCTL_OIDC_CLIENT_SECRET": "s"}  # nosecret: test value


class TestLoginConfiguration:
    @pytest.mark.parametrize(
        ("env", "expected"),
        [
            ({}, "login=none"),
            ({"IBCTL_DASHBOARD_TOKEN": "pw"}, "login=password "),  # nosecret: test value
            (GITHUB, "login=github "),
            (OIDC, "login=oidc "),
            ({"IBCTL_DASHBOARD_TOKEN": "pw", **GITHUB, **OIDC}, "login=password+github+oidc "),  # nosecret: test value
        ],
        ids=["none", "password", "github", "oidc", "all"],
    )
    def test_the_startup_line_names_the_login_methods(self, monkeypatch, caplog, env, expected):
        for var in LOGIN_ENV:
            monkeypatch.delenv(var, raising=False)
        for var, value in env.items():
            monkeypatch.setenv(var, value)
        with caplog.at_level(logging.INFO, logger="dashboard.config"):
            DashboardSettings.from_env()
        line = next(r.getMessage() for r in caplog.records if "Config loaded" in r.getMessage())
        assert expected in line
        assert "auth=" not in line

    def test_the_startup_line_says_what_no_login_means(self, monkeypatch, caplog):
        for var in LOGIN_ENV:
            monkeypatch.delenv(var, raising=False)
        with caplog.at_level(logging.INFO, logger="dashboard.config"):
            DashboardSettings.from_env()
        line = next(r.getMessage() for r in caplog.records if "Config loaded" in r.getMessage())
        assert "health summary only" in line

    def test_login_configured_needs_a_password_or_an_sso_method(self):
        assert not DashboardSettings().login_configured
        assert DashboardSettings(token="pw").login_configured  # nosecret: test value
        assert not DashboardSettings(github_client_id="id").login_configured  # secret missing
        assert DashboardSettings(github_client_id="id", github_client_secret=SecretStr("s")).login_configured  # nosecret: test value

    def test_the_signing_secret_falls_back_the_way_from_env_does(self):
        assert DashboardSettings(auth_secret=SecretStr("explicit"), token="pw").signing_secret == "explicit"  # nosecret: test value
        assert DashboardSettings(token="pw").signing_secret == "pw"  # nosecret: test value
        assert DashboardSettings().signing_secret == ""
