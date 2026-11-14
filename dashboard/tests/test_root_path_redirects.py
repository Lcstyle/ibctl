"""The dashboard behind a reverse proxy that serves it under a path prefix.

nginx publishes the dashboard at `/ibctl/` and strips the prefix before
forwarding, so the app sees `/config` while the browser asked for
`/ibctl/config`. Every redirect it sends and the path of its cookies must carry
the prefix (IBCTL_ROOT_PATH), or the browser lands on whatever else lives at the
site root. With no prefix configured nothing changes.
"""

from __future__ import annotations

import time

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import create_app
from app.middleware.auth import AUTH_COOKIE_NAME
from app.session_cookies import Kind, sign
from tests.auth_helpers import TEST_AUTH_SECRET, TEST_PASSWORD, authed_settings

PREFIX = "/ibctl"


def _client(monkeypatch, root_path: str, **settings) -> AsyncClient:
    if root_path:
        monkeypatch.setenv("IBCTL_ROOT_PATH", root_path)
    else:
        monkeypatch.delenv("IBCTL_ROOT_PATH", raising=False)
    app = create_app(settings=authed_settings(**settings))
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def _login_form(next_path: str = "/", password: str = TEST_PASSWORD) -> dict:
    return {"password": password, "next": next_path}


@pytest.mark.parametrize(
    ("root_path", "expected_start"),
    [(PREFIX, f"{PREFIX}/login?next=/config"), ("", "/login?next=/config")],
)
async def test_a_protected_page_sends_an_anonymous_visitor_to_the_prefixed_login(monkeypatch, root_path, expected_start):
    async with _client(monkeypatch, root_path) as client:
        response = await client.get("/config")

    assert response.status_code == 303
    location = response.headers["location"]
    assert location.endswith(expected_start) or location == expected_start, location
    assert not location.startswith("http"), "a path, not an absolute URL: the proxy's scheme and host are not the app's to guess"


@pytest.mark.parametrize(
    ("next_path", "expected"),
    [
        ("/", f"{PREFIX}/"),
        ("/config", f"{PREFIX}/config"),
        ("/state?mode=paper", f"{PREFIX}/state?mode=paper"),
    ],
)
async def test_a_successful_login_returns_to_the_page_asked_for_under_the_prefix(monkeypatch, next_path, expected):
    async with _client(monkeypatch, PREFIX) as client:
        response = await client.post("/login", data=_login_form(next_path))

    assert response.status_code == 303
    assert response.headers["location"] == expected


@pytest.mark.parametrize("hostile", ["//evil.example/x", "https://evil.example/", "/login", "javascript:alert(1)"])
async def test_next_cannot_send_the_visitor_off_site_or_back_to_the_login_page(monkeypatch, hostile):
    async with _client(monkeypatch, PREFIX) as client:
        response = await client.post("/login", data=_login_form(hostile))

    assert response.headers["location"] == f"{PREFIX}/"


async def test_the_session_cookie_is_scoped_to_the_prefix_not_the_whole_site(monkeypatch):
    async with _client(monkeypatch, PREFIX) as client:
        response = await client.post("/login", data=_login_form())

    live = [
        h for h in response.headers.get_list("set-cookie") if h.startswith("ibctl_dashboard_auth=") and "Max-Age=0" not in h
    ]
    assert len(live) == 1, live
    assert f"Path={PREFIX}" in live[0] and "Path=/;" not in live[0], "the session cookie is not sent to the rest of the site"


async def test_without_a_prefix_the_cookie_path_and_redirects_are_unchanged(monkeypatch):
    async with _client(monkeypatch, "") as client:
        response = await client.post("/login", data=_login_form("/config"))

    assert response.headers["location"] == "/config"
    assert "Path=/;" in response.headers["set-cookie"] or response.headers["set-cookie"].rstrip().endswith("Path=/")


async def test_logout_returns_to_the_prefixed_login_and_clears_the_prefixed_cookie(monkeypatch):
    async with _client(monkeypatch, PREFIX) as client:
        response = await client.post("/logout")

    assert response.status_code == 303
    assert response.headers["location"] == f"{PREFIX}/login?reason=logout"
    cleared = [h for h in response.headers.get_list("set-cookie") if h.startswith("ibctl_dashboard_auth=")]
    assert any(f"Path={PREFIX}" in h for h in cleared), cleared
    assert all("Max-Age=0" in h for h in cleared), "logout sets no session cookie, it only clears them"


async def test_the_login_page_with_no_login_configured_points_at_the_prefixed_summary(monkeypatch):
    async with _client(monkeypatch, PREFIX, token="") as client:
        response = await client.get("/login")

    assert response.status_code == 303
    assert response.headers["location"] == f"{PREFIX}/"


async def test_the_controls_page_redirect_keeps_the_prefix(monkeypatch):
    async with _client(monkeypatch, PREFIX) as client:
        # Log in through the form first; controls is a login-only page.
        login = await client.post("/login", data=_login_form())
        cookie = login.headers["set-cookie"].split(";")[0]
        name, _, value = cookie.partition("=")
        response = await client.get("/controls", cookies={name: value})

    assert response.status_code in (302, 307)
    assert response.headers["location"] == f"{PREFIX}/state"


async def test_an_idle_session_goes_to_the_prefixed_login_saying_why(monkeypatch):
    stale = {"auth": "password", "iat": int(time.time()) - 3600, "act": int(time.time()) - 3600}
    async with _client(monkeypatch, PREFIX) as client:
        client.cookies.set(AUTH_COOKIE_NAME, sign(Kind.PASSWORD_SESSION, stale, TEST_AUTH_SECRET))
        page = await client.get("/config", headers={"Accept": "text/html"})
        poll = await client.get("/partials/overview")

    assert page.status_code == 303
    assert page.headers["location"] == f"{PREFIX}/login?next=/config&reason=idle"
    assert poll.status_code == 401 and poll.json()["reason"] == "idle"


async def test_a_refreshed_session_cookie_stays_scoped_to_the_prefix(monkeypatch):
    async with _client(monkeypatch, PREFIX) as client:
        stale = {"auth": "password", "iat": int(time.time()) - 600, "act": int(time.time()) - 60}
        client.cookies.set(AUTH_COOKIE_NAME, sign(Kind.PASSWORD_SESSION, stale, TEST_AUTH_SECRET))
        response = await client.get("/state", headers={"Accept": "text/html"})
        touch = await client.post("/api/session/touch")

    refreshed = [h for h in response.headers.get_list("set-cookie") if h.startswith("ibctl_dashboard_auth=")]
    assert refreshed and f"Path={PREFIX}" in refreshed[0] and "HttpOnly" in refreshed[0]
    assert touch.status_code == 204


async def test_the_login_page_notice_keeps_the_prefixed_form_action(monkeypatch):
    async with _client(monkeypatch, PREFIX) as client:
        html = (await client.get("/login?reason=idle")).text

    assert "You were signed out after 5 minutes of inactivity." in html
    assert f'action="{PREFIX}/login"' in html
