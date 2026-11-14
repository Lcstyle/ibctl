"""A browser holding two session cookies of the same name.

Before the dashboard learned its proxy prefix it set its session cookie at
`Path=/`. It now sets it at `Path=/ibctl`. A browser that still holds the old
cookie sends both on every request, and the server must not let the stale one
shadow the fresh one: the visitor would log in, be sent back to the health
summary, and never get past it. Login and logout also clear the legacy cookie so
it goes away for good.
"""

from __future__ import annotations

import time

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import create_app
from app.middleware.auth import AUTH_COOKIE_NAME, build_password_session
from app.session_cookies import Kind, sign
from tests.auth_helpers import TEST_AUTH_SECRET, TEST_PASSWORD, authed_settings

PREFIX = "/ibctl"


def _client(monkeypatch, root_path: str = PREFIX, **settings) -> AsyncClient:
    if root_path:
        monkeypatch.setenv("IBCTL_ROOT_PATH", root_path)
    else:
        monkeypatch.delenv("IBCTL_ROOT_PATH", raising=False)
    app = create_app(settings=authed_settings(**settings))
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def _stale_cookie() -> str:
    """The cookie an earlier build set: no activity time, issued an hour ago."""
    return sign(Kind.PASSWORD_SESSION, {"auth": "password", "iat": int(time.time()) - 3600}, TEST_AUTH_SECRET)


def _header(*values: str) -> dict:
    return {"Cookie": "; ".join(f"{AUTH_COOKIE_NAME}={v}" for v in values)}


@pytest.mark.parametrize("fresh_first", [True, False])
async def test_a_stale_cookie_does_not_shadow_a_fresh_one(monkeypatch, fresh_first):
    fresh, stale = build_password_session(TEST_AUTH_SECRET), _stale_cookie()
    headers = _header(fresh, stale) if fresh_first else _header(stale, fresh)

    async with _client(monkeypatch) as client:
        response = await client.post("/api/session/touch", headers=headers)

    assert response.status_code == 204, "the fresh session is the one that counts, whichever order they arrive in"


async def test_two_stale_cookies_are_still_signed_out_and_say_why(monkeypatch):
    async with _client(monkeypatch) as client:
        response = await client.post("/api/session/touch", headers=_header(_stale_cookie(), _stale_cookie()))

    assert response.status_code == 401


async def test_a_forged_cookie_beside_a_fresh_one_changes_nothing(monkeypatch):
    forged = sign(Kind.PASSWORD_SESSION, {"auth": "password", "iat": int(time.time()), "act": int(time.time())}, "some-other-secret")  # nosecret: test value
    async with _client(monkeypatch) as client:
        only_forged = await client.post("/api/session/touch", headers=_header(forged))
        with_fresh = await client.post("/api/session/touch", headers=_header(forged, build_password_session(TEST_AUTH_SECRET)))

    assert only_forged.status_code == 401
    assert with_fresh.status_code == 204


async def test_login_under_a_prefix_also_clears_the_legacy_root_cookie(monkeypatch):
    async with _client(monkeypatch) as client:
        response = await client.post("/login", data={"password": TEST_PASSWORD, "next": "/"})

    cookies = [h for h in response.headers.get_list("set-cookie") if h.startswith(f"{AUTH_COOKIE_NAME}=")]
    scoped = [h for h in cookies if f"Path={PREFIX}" in h and "Max-Age=0" not in h]
    legacy_cleared = [h for h in cookies if "Max-Age=0" in h and "Path=/;" in (h + ";")]
    assert len(scoped) == 1, cookies
    assert len(legacy_cleared) == 1, cookies


async def test_logout_under_a_prefix_clears_both_cookies(monkeypatch):
    async with _client(monkeypatch) as client:
        response = await client.post("/logout")

    cleared = [h for h in response.headers.get_list("set-cookie") if h.startswith(f"{AUTH_COOKIE_NAME}=")]
    assert any(f"Path={PREFIX}" in h for h in cleared), cleared
    assert any("Path=/;" in (h + ";") and f"Path={PREFIX}" not in h for h in cleared), cleared


async def test_without_a_prefix_there_is_no_separate_legacy_cookie_to_clear(monkeypatch):
    async with _client(monkeypatch, root_path="") as client:
        response = await client.post("/login", data={"password": TEST_PASSWORD, "next": "/"})

    cookies = [h for h in response.headers.get_list("set-cookie") if h.startswith(f"{AUTH_COOKIE_NAME}=")]
    assert len(cookies) == 1 and "Max-Age=0" not in cookies[0], cookies
