"""Tests for dashboard authentication middleware.

Verifies the auth contract:
- A password login (IBCTL_DASHBOARD_TOKEN) is accepted only through the login
  form, which sets a signed, expiring session cookie.
- The raw password is not a credential anywhere else: not in a cookie, not as
  `Authorization: Bearer`, not as an HTTP Basic password.
- Forged, expired and foreign-secret cookies are rejected.
- Anonymous requests to protected routes get a redirect (browsers) or a 401 (API).
- Static files always bypass auth.
"""

from __future__ import annotations

import base64
import time

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import create_app
from app.middleware.auth import (
    AUTH_COOKIE_NAME,
    OAUTH_COOKIE_NAME,
    build_oauth_state,
)
from app.session_cookies import Kind, sign
from tests.auth_helpers import TEST_AUTH_SECRET, TEST_PASSWORD, authed_settings, log_in

DAY = 24 * 60 * 60


async def _client(**overrides):
    app = create_app(settings=authed_settings(**overrides))
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.fixture
async def anon():
    """Anonymous client for an app with a dashboard password configured."""
    async with await _client() as c:
        yield c


@pytest.fixture
async def signed_in():
    """Client that signed in through the real login form."""
    async with await _client() as c:
        await log_in(c)
        yield c


def _password_cookie(*, secret: str = TEST_AUTH_SECRET, iat: int | None = None, **extra) -> str:
    payload = {"auth": "password", "iat": int(time.time()) if iat is None else iat, **extra}
    return sign(Kind.PASSWORD_SESSION, payload, secret)


# --- Password configured: endpoints require a login ---

class TestLoginRequired:
    @pytest.mark.asyncio
    async def test_api_rejects_no_auth(self, anon):
        resp = await anon.post("/api/v1/command", json={"command": "RESTART"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_status_rejects_no_auth(self, anon):
        resp = await anon.get("/api/v1/status")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_browser_redirects_to_login_with_next(self, anon):
        resp = await anon.get("/state?mode=paper")
        assert resp.status_code == 303
        location = resp.headers["location"]
        assert "/login" in location
        assert "next=/state?mode=paper" in location

    @pytest.mark.asyncio
    async def test_json_accept_header_gets_401_not_a_redirect(self, anon):
        resp = await anon.get("/state", headers={"Accept": "application/json"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_non_get_page_request_gets_401(self, anon):
        resp = await anon.post("/state")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_static_files_bypass_auth(self, anon):
        """Static assets should not require auth (404 expected, not 401)."""
        resp = await anon.get("/static/nonexistent.css")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_login_page_bypasses_auth(self, anon):
        resp = await anon.get("/login")
        assert resp.status_code == 200


# --- The login form sets a signed session ---

class TestSignedSession:
    @pytest.mark.asyncio
    async def test_login_form_sets_a_signed_cookie_that_is_not_the_password(self, anon):
        resp = await log_in(anon)
        cookie = resp.cookies.get(AUTH_COOKIE_NAME)
        assert cookie
        assert TEST_PASSWORD not in cookie
        assert cookie != TEST_PASSWORD
        assert "." in cookie  # <payload>.<signature>
        assert "HttpOnly" in resp.headers["set-cookie"]

    @pytest.mark.asyncio
    async def test_signed_cookie_is_accepted(self, signed_in):
        assert (await signed_in.get("/api/v1/status")).status_code == 200
        assert (await signed_in.get("/state")).status_code == 200

    @pytest.mark.asyncio
    async def test_wrong_password_sets_no_cookie_and_stays_out(self, anon):
        resp = await anon.post("/login", data={"password": "nope", "next": "/"})  # nosecret: test value
        assert resp.status_code == 401
        assert AUTH_COOKIE_NAME not in resp.cookies
        assert (await anon.get("/api/v1/status")).status_code == 401

    @pytest.mark.asyncio
    async def test_non_ascii_password_is_a_clean_rejection(self, anon):
        resp = await anon.post("/login", data={"password": "pässwörd", "next": "/"})  # nosecret: test value
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_a_cookie_minted_with_the_secret_is_accepted(self, anon):
        anon.cookies.set(AUTH_COOKIE_NAME, _password_cookie())
        assert (await anon.get("/api/v1/status")).status_code == 200

    @pytest.mark.asyncio
    async def test_logout_clears_the_session(self, signed_in):
        resp = await signed_in.post("/logout")
        assert resp.status_code == 303
        signed_in.cookies.clear()
        assert (await signed_in.get("/api/v1/status")).status_code == 401


class TestSessionRejections:
    @pytest.mark.asyncio
    async def test_raw_password_cookie_is_rejected(self, anon):
        anon.cookies.set(AUTH_COOKIE_NAME, TEST_PASSWORD)
        assert (await anon.get("/api/v1/status")).status_code == 401

    @pytest.mark.asyncio
    async def test_cookie_signed_with_another_secret_is_rejected(self, anon):
        anon.cookies.set(AUTH_COOKIE_NAME, _password_cookie(secret="some-other-secret"))  # nosecret: test value
        assert (await anon.get("/api/v1/status")).status_code == 401

    @pytest.mark.asyncio
    async def test_tampered_signature_is_rejected(self, anon):
        good = _password_cookie()
        encoded, signature = good.rsplit(".", 1)
        flipped = ("0" if signature[0] != "0" else "1") + signature[1:]
        anon.cookies.set(AUTH_COOKIE_NAME, f"{encoded}.{flipped}")
        assert (await anon.get("/api/v1/status")).status_code == 401

    @pytest.mark.asyncio
    async def test_tampered_payload_is_rejected(self, anon):
        _, signature = _password_cookie().rsplit(".", 1)
        forged_payload = sign(Kind.PASSWORD_SESSION, {"auth": "password", "iat": int(time.time()) + 10 * DAY}, "x").rsplit(".", 1)[0]
        anon.cookies.set(AUTH_COOKIE_NAME, f"{forged_payload}.{signature}")
        assert (await anon.get("/api/v1/status")).status_code == 401

    @pytest.mark.asyncio
    async def test_expired_cookie_is_rejected(self, anon):
        anon.cookies.set(AUTH_COOKIE_NAME, _password_cookie(iat=int(time.time()) - 8 * DAY))
        assert (await anon.get("/api/v1/status")).status_code == 401

    @pytest.mark.asyncio
    async def test_cookie_a_few_days_old_is_still_good_while_the_person_is_active(self, anon):
        anon.cookies.set(AUTH_COOKIE_NAME, _password_cookie(iat=int(time.time()) - 6 * DAY, act=int(time.time())))
        assert (await anon.get("/api/v1/status")).status_code == 200

    @pytest.mark.asyncio
    async def test_cookie_without_an_issue_time_is_rejected(self, anon):
        anon.cookies.set(AUTH_COOKIE_NAME, sign(Kind.PASSWORD_SESSION, {"auth": "password"}, TEST_AUTH_SECRET))
        assert (await anon.get("/api/v1/status")).status_code == 401

    @pytest.mark.asyncio
    async def test_a_signed_cookie_for_something_else_is_not_a_password_session(self, anon):
        """The same secret signs OAuth sessions and OAuth state; none of those is a password login."""
        for payload in ({"login": "someone", "iat": int(time.time())}, {"iat": int(time.time())}):
            anon.cookies.set(AUTH_COOKIE_NAME, sign(Kind.PASSWORD_SESSION, payload, TEST_AUTH_SECRET))
            assert (await anon.get("/api/v1/status")).status_code == 401

    @pytest.mark.asyncio
    async def test_a_password_shaped_cookie_signed_as_another_kind_is_not_a_password_session(self, anon):
        """The payload is right; the signature is for a different cookie, so it does not count."""
        payload = {"auth": "password", "iat": int(time.time()), "act": int(time.time())}
        for kind in (Kind.OAUTH_SESSION, Kind.OAUTH_STATE):
            anon.cookies.set(AUTH_COOKIE_NAME, sign(kind, payload, TEST_AUTH_SECRET))
            assert (await anon.get("/api/v1/status")).status_code == 401

    @pytest.mark.asyncio
    async def test_password_session_is_not_an_oauth_session(self, anon):
        """With no OAuth configured, the OAuth cookie slot grants nothing, whatever it holds."""
        anon.cookies.set(OAUTH_COOKIE_NAME, sign(Kind.OAUTH_SESSION, {"login": "someone", "iat": int(time.time())}, TEST_AUTH_SECRET))
        assert (await anon.get("/api/v1/status")).status_code == 401
        anon.cookies.clear()
        anon.cookies.set(OAUTH_COOKIE_NAME, _password_cookie())
        assert (await anon.get("/api/v1/status")).status_code == 401


class TestOauthSessionHardening:
    """An OAuth-enabled dashboard: only a real OAuth session cookie opens it."""

    async def _oauth_client(self):
        from pydantic import SecretStr

        return await _client(github_client_id="client-id", github_client_secret=SecretStr("client-secret"))

    @pytest.mark.asyncio
    async def test_oauth_session_cookie_is_accepted(self):
        async with await self._oauth_client() as c:
            c.cookies.set(OAUTH_COOKIE_NAME, sign(Kind.OAUTH_SESSION, {"login": "someone", "iat": int(time.time())}, TEST_AUTH_SECRET))
            assert (await c.get("/api/v1/status")).status_code == 200

    @pytest.mark.asyncio
    async def test_oauth_state_token_is_not_a_session(self):
        """The state value goes out in a redirect to anyone who starts a login; it must not log them in."""
        async with await self._oauth_client() as c:
            c.cookies.set(OAUTH_COOKIE_NAME, build_oauth_state("/", TEST_AUTH_SECRET))
            assert (await c.get("/api/v1/status")).status_code == 401

    @pytest.mark.asyncio
    async def test_password_cookie_is_not_an_oauth_session(self):
        async with await self._oauth_client() as c:
            c.cookies.set(OAUTH_COOKIE_NAME, _password_cookie())
            assert (await c.get("/api/v1/status")).status_code == 401


# --- The password works only through the login form ---

class TestPasswordOnlyThroughTheForm:
    @pytest.mark.asyncio
    async def test_bearer_with_the_password_is_rejected(self, anon):
        headers = {"Authorization": f"Bearer {TEST_PASSWORD}"}
        assert (await anon.get("/api/v1/status", headers=headers)).status_code == 401
        resp = await anon.post("/api/v1/command", json={"command": "RESTART"}, headers=headers)
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_bearer_with_the_password_does_not_open_pages(self, anon):
        resp = await anon.get("/state", headers={"Authorization": f"Bearer {TEST_PASSWORD}"})
        assert resp.status_code == 303
        assert "/login" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_basic_with_the_password_is_rejected(self, anon):
        creds = base64.b64encode(f"anyone:{TEST_PASSWORD}".encode()).decode()
        resp = await anon.get("/api/v1/status", headers={"Authorization": f"Basic {creds}"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_a_401_does_not_invite_basic_auth(self, anon):
        resp = await anon.get("/api/v1/status")
        assert "basic" not in resp.headers.get("www-authenticate", "").lower()
