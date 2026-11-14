"""Signed cookie values: one module builds and reads them (`app.session_cookies`).

What is covered: a value reads back as what was signed, a tampered value, a
value signed with another secret and a value of one kind read as another are all
refused, and a cookie in the format the dashboard used before it signed with
`itsdangerous` no longer validates. The same refusals are checked through the
real app, because the cookie slots are what a browser can write to.
"""

from __future__ import annotations

import hashlib
import hmac
import time

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from app.main import create_app
from app.middleware.auth import (
    AUTH_COOKIE_NAME,
    OAUTH_COOKIE_NAME,
    build_oauth_session,
    build_oauth_state,
    build_password_session,
    parse_oauth_session,
    parse_oauth_state,
    parse_password_session,
)
from app.session_cookies import Kind, sign, unsign
from tests.auth_helpers import TEST_AUTH_SECRET, authed_settings, legacy_cookie

OTHER_SECRET = "a-different-signing-secret"  # nosecret: test value
KINDS = list(Kind)


def _payload() -> dict:
    return {"login": "octocat", "iat": int(time.time()), "act": int(time.time())}


class TestSignAndUnsign:
    @pytest.mark.parametrize("kind", KINDS)
    def test_a_value_reads_back_as_what_was_signed(self, kind):
        payload = _payload()

        assert unsign(kind, sign(kind, payload, TEST_AUTH_SECRET), TEST_AUTH_SECRET) == payload

    @pytest.mark.parametrize("kind", KINDS)
    def test_the_value_is_safe_to_put_in_a_cookie(self, kind):
        value = sign(kind, _payload(), TEST_AUTH_SECRET)

        assert all(c.isalnum() or c in "-_." for c in value), value

    @pytest.mark.parametrize("kind", KINDS)
    def test_a_value_signed_with_another_secret_is_refused(self, kind):
        value = sign(kind, _payload(), OTHER_SECRET)

        assert unsign(kind, value, TEST_AUTH_SECRET) is None

    @pytest.mark.parametrize("kind", KINDS)
    def test_a_changed_signature_is_refused(self, kind):
        body, signature = sign(kind, _payload(), TEST_AUTH_SECRET).rsplit(".", 1)
        flipped = ("A" if signature[0] != "A" else "B") + signature[1:]

        assert unsign(kind, f"{body}.{flipped}", TEST_AUTH_SECRET) is None

    @pytest.mark.parametrize("kind", KINDS)
    def test_a_changed_payload_under_the_old_signature_is_refused(self, kind):
        _, signature = sign(kind, _payload(), TEST_AUTH_SECRET).rsplit(".", 1)
        forged_body = sign(kind, {**_payload(), "login": "someone-else"}, OTHER_SECRET).rsplit(".", 1)[0]

        assert unsign(kind, f"{forged_body}.{signature}", TEST_AUTH_SECRET) is None

    @pytest.mark.parametrize("garbage", ["", ".", "..", "abc", "a.b", "a.b.c", "é.é", "x" * 5000, " ", "\x00"])
    @pytest.mark.parametrize("kind", KINDS)
    def test_garbage_is_refused_and_never_raises(self, kind, garbage):
        assert unsign(kind, garbage, TEST_AUTH_SECRET) is None

    @pytest.mark.parametrize("kind", KINDS)
    def test_a_correctly_signed_value_that_is_not_an_object_is_refused(self, kind):
        from itsdangerous import URLSafeSerializer

        value = URLSafeSerializer(TEST_AUTH_SECRET, salt=kind.salt, signer_kwargs={"digest_method": hashlib.sha256}).dumps(["a"])

        assert unsign(kind, value, TEST_AUTH_SECRET) is None

    @pytest.mark.parametrize("kind", KINDS)
    def test_a_value_forged_with_an_empty_secret_is_refused_by_an_empty_secret(self, kind):
        """A dashboard with no login has no signing secret; an empty HMAC key is no key."""
        assert unsign(kind, sign(kind, _payload(), ""), "") is None


class TestKindsAreSeparate:
    """A value signed for one kind of cookie never validates as another."""

    @pytest.mark.parametrize("signed_as", KINDS)
    @pytest.mark.parametrize("read_as", KINDS)
    def test_only_the_same_kind_reads_it(self, signed_as, read_as):
        value = sign(signed_as, _payload(), TEST_AUTH_SECRET)

        assert (unsign(read_as, value, TEST_AUTH_SECRET) is not None) is (signed_as is read_as)

    def test_each_kind_has_its_own_salt(self):
        assert len({kind.salt for kind in Kind}) == len(Kind)

    def test_the_session_parsers_refuse_each_others_cookies(self):
        password = build_password_session(TEST_AUTH_SECRET)
        oauth = build_oauth_session("octocat", TEST_AUTH_SECRET)
        state = build_oauth_state("/", TEST_AUTH_SECRET)

        assert parse_password_session(password, TEST_AUTH_SECRET)
        assert parse_oauth_session(oauth, TEST_AUTH_SECRET)
        assert parse_oauth_state(state, TEST_AUTH_SECRET)
        for value in (oauth, state):
            assert parse_password_session(value, TEST_AUTH_SECRET) is None
        for value in (password, state):
            assert parse_oauth_session(value, TEST_AUTH_SECRET) is None
        for value in (password, oauth):
            assert parse_oauth_state(value, TEST_AUTH_SECRET) is None

    def test_a_value_with_the_right_claims_but_the_wrong_kind_is_still_refused(self):
        """An OAuth session payload (a `login`) signed for the password slot is not an OAuth session."""
        value = sign(Kind.PASSWORD_SESSION, {"login": "octocat", "iat": int(time.time())}, TEST_AUTH_SECRET)

        assert parse_oauth_session(value, TEST_AUTH_SECRET) is None


class TestTheOldFormat:
    """Before `itsdangerous` a value was base64(JSON) + "." + hex HMAC-SHA256. It must not validate now."""

    def test_the_helper_really_builds_the_old_format(self):
        payload = {"auth": "password", "iat": 1}
        body, signature = legacy_cookie(payload, TEST_AUTH_SECRET).rsplit(".", 1)

        assert signature == hmac.new(TEST_AUTH_SECRET.encode(), body.encode(), "sha256").hexdigest()

    @pytest.mark.parametrize("kind", KINDS)
    def test_an_old_cookie_is_refused(self, kind):
        assert unsign(kind, legacy_cookie(_payload(), TEST_AUTH_SECRET), TEST_AUTH_SECRET) is None

    def test_an_old_password_session_is_not_a_session(self):
        now = int(time.time())
        old = legacy_cookie({"auth": "password", "iat": now, "act": now}, TEST_AUTH_SECRET)

        assert parse_password_session(old, TEST_AUTH_SECRET) is None

    def test_an_old_oauth_state_is_not_a_state(self):
        old = legacy_cookie({"next": "/", "iat": int(time.time())}, TEST_AUTH_SECRET)

        assert parse_oauth_state(old, TEST_AUTH_SECRET) is None


def _client(**settings) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app(settings=authed_settings(**settings))), base_url="http://test")


class TestThroughTheApp:
    async def test_a_current_password_cookie_opens_the_api(self):
        async with _client() as client:
            client.cookies.set(AUTH_COOKIE_NAME, build_password_session(TEST_AUTH_SECRET))
            assert (await client.get("/api/v1/status")).status_code == 200

    async def test_an_old_format_password_cookie_is_a_401(self):
        now = int(time.time())
        async with _client() as client:
            client.cookies.set(AUTH_COOKIE_NAME, legacy_cookie({"auth": "password", "iat": now, "act": now}, TEST_AUTH_SECRET))
            assert (await client.get("/api/v1/status")).status_code == 401

    async def test_an_old_format_oauth_cookie_is_a_401(self):
        now = int(time.time())
        async with _client(github_client_id="id", github_client_secret=SecretStr("secret")) as client:
            client.cookies.set(OAUTH_COOKIE_NAME, legacy_cookie({"login": "octocat", "iat": now, "act": now}, TEST_AUTH_SECRET))
            assert (await client.get("/api/v1/status")).status_code == 401

    async def test_an_oauth_session_in_the_password_slot_is_a_401(self):
        async with _client() as client:
            client.cookies.set(AUTH_COOKIE_NAME, build_oauth_session("octocat", TEST_AUTH_SECRET))
            assert (await client.get("/api/v1/status")).status_code == 401

    async def test_a_password_session_in_the_oauth_slot_is_a_401(self):
        async with _client(github_client_id="id", github_client_secret=SecretStr("secret")) as client:
            client.cookies.set(OAUTH_COOKIE_NAME, build_password_session(TEST_AUTH_SECRET))
            assert (await client.get("/api/v1/status")).status_code == 401

    async def test_an_oauth_state_in_the_oauth_session_slot_is_a_401(self):
        async with _client(github_client_id="id", github_client_secret=SecretStr("secret")) as client:
            client.cookies.set(OAUTH_COOKIE_NAME, build_oauth_state("/", TEST_AUTH_SECRET))
            assert (await client.get("/api/v1/status")).status_code == 401

    async def test_a_session_in_the_state_slot_does_not_complete_a_login(self):
        """The callback needs the state value it handed out, signed as a state: a session is not one."""
        session = build_oauth_session("octocat", TEST_AUTH_SECRET)
        async with _client(github_client_id="id", github_client_secret=SecretStr("secret")) as client:
            client.cookies.set("ibctl_dashboard_oauth_state", session)
            response = await client.get("/auth/github/callback", params={"code": "x", "state": session})

        assert response.status_code == 401
        assert "Invalid GitHub OAuth callback" in response.text
        assert OAUTH_COOKIE_NAME not in response.headers.get("set-cookie", "")
