"""Idle logout: a signed session also ends after a stretch with no user activity.

A session cookie carries `iat` (issued) and `act` (last user activity). It is
valid while `now - act <= idle` and `now - iat <= 7 days`. Only requests that
are the person doing something move `act`: a page navigation, any request that
is not a GET or HEAD (the heartbeat included). Background polling of an open
page (`/partials/*`, JSON reads, the event stream, static files) is checked but
never extends the session, or an open tab would never time out.

The clock is moved by hand (`auth.now`); nothing sleeps.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from app.main import create_app
from app.middleware import auth
from app.middleware.auth import (
    AUTH_COOKIE_NAME,
    OAUTH_COOKIE_NAME,
    build_oauth_session,
)
from app.services.api_access import ApiAccessStore
from app.session_cookies import Kind, sign, unsign
from tests.auth_helpers import TEST_AUTH_SECRET, TEST_PASSWORD, authed_settings, log_in

START = 1_800_000_000.0
MINUTE = 60
DAY = 24 * 60 * 60
NAVIGATION = {"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}


class Clock:
    """The wall clock, moved by hand. Calling it returns epoch seconds."""

    def __init__(self, now: float = START):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch) -> Clock:
    fake = Clock()
    monkeypatch.setattr(auth, "now", fake)
    return fake


def client_for(**settings) -> AsyncClient:
    app = create_app(settings=authed_settings(**settings))
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def oauth_settings(**overrides) -> dict:
    return {"github_client_id": "client-id", "github_client_secret": SecretStr("client-secret"), **overrides}


def reissued(response, name: str = AUTH_COOKIE_NAME) -> dict | None:
    """The payload of the session cookie this response sets, or None when it sets none."""
    for header in response.headers.get_list("set-cookie"):
        if header.startswith(f"{name}="):
            kind = Kind.PASSWORD_SESSION if name == AUTH_COOKIE_NAME else Kind.OAUTH_SESSION
            return unsign(kind, header.split(";", 1)[0].split("=", 1)[1], TEST_AUTH_SECRET)
    return None


def password_cookie(*, iat: float, act: float | None = None, secret: str = TEST_AUTH_SECRET) -> str:
    payload = {"auth": "password", "iat": int(iat)}
    if act is not None:
        payload["act"] = int(act)
    return sign(Kind.PASSWORD_SESSION, payload, secret)


@pytest.fixture
async def member(clock):
    """A client that signed in through the form: a password session, idle limit 5 minutes."""
    async with client_for(session_idle_minutes=5) as c:
        await log_in(c)
        yield c


class TestTheSessionCookie:
    async def test_login_stamps_issue_time_and_activity_alike(self, clock):
        async with client_for() as anon:
            response = await anon.post("/login", data={"password": TEST_PASSWORD, "next": "/"})

        payload = reissued(response)
        assert payload == {"auth": "password", "iat": int(START), "act": int(START)}

    def test_an_oauth_session_carries_both_times_too(self, clock):
        payload = unsign(Kind.OAUTH_SESSION, build_oauth_session("octocat", TEST_AUTH_SECRET), TEST_AUTH_SECRET)

        assert payload == {"login": "octocat", "iat": int(START), "act": int(START)}


class TestIdleExpiry:
    async def test_a_fresh_session_is_valid(self, member):
        assert (await member.get("/state", headers=NAVIGATION)).status_code == 200

    async def test_exactly_at_the_limit_is_still_valid(self, member, clock):
        clock.advance(5 * MINUTE)

        assert (await member.get("/state", headers=NAVIGATION)).status_code == 200

    async def test_a_page_after_the_limit_redirects_to_login_saying_idle(self, member, clock):
        clock.advance(5 * MINUTE + 1)

        response = await member.get("/config", headers=NAVIGATION)

        assert response.status_code == 303
        assert response.headers["location"] == "/login?next=/config&reason=idle"

    async def test_the_page_asked_for_survives_in_next_even_with_a_query(self, member, clock):
        clock.advance(6 * MINUTE)

        response = await member.get("/state?mode=paper&x=1", headers=NAVIGATION)

        assert response.headers["location"] == "/login?next=/state?mode=paper%26x=1&reason=idle"

    async def test_an_api_call_after_the_limit_is_a_401_that_says_why(self, member, clock):
        clock.advance(6 * MINUTE)

        response = await member.get("/api/v1/status")

        assert response.status_code == 401
        assert response.json()["reason"] == "idle"
        assert "inactivity" in response.json()["detail"]

    async def test_a_json_accept_gets_the_401_not_a_redirect(self, member, clock):
        clock.advance(6 * MINUTE)

        response = await member.get("/state", headers={"Accept": "application/json"})

        assert response.status_code == 401 and response.json()["reason"] == "idle"

    async def test_a_background_poll_after_the_limit_is_a_401_not_a_redirect(self, member, clock):
        clock.advance(6 * MINUTE)

        for headers in ({}, {"HX-Request": "true"}):
            response = await member.get("/partials/overview", headers=headers)
            assert response.status_code == 401, headers
            assert response.json()["reason"] == "idle"

    async def test_a_post_after_the_limit_is_refused_too(self, member, clock):
        clock.advance(6 * MINUTE)

        response = await member.post("/api/session/touch")

        assert response.status_code == 401 and response.json()["reason"] == "idle"

    async def test_an_idle_session_is_simply_not_a_login_on_the_public_summary(self, member, clock):
        clock.advance(6 * MINUTE)

        response = await member.get("/", headers=NAVIGATION)

        assert response.status_code == 200
        assert "Log out" not in response.text

    async def test_a_forged_cookie_is_not_idle_it_is_just_not_signed_in(self, clock):
        async with client_for() as anon:
            anon.cookies.set(AUTH_COOKIE_NAME, password_cookie(iat=START, act=START, secret="some other secret"))  # nosecret: test value
            page = await anon.get("/config", headers=NAVIGATION)
            api = await anon.get("/api/v1/status")

        assert page.status_code == 303 and page.headers["location"] == "/login?next=/config"
        assert api.status_code == 401 and "reason" not in api.json()

    async def test_a_tampered_cookie_is_refused(self, member, clock):
        good = member.cookies.get(AUTH_COOKIE_NAME)
        encoded, _signature = good.rsplit(".", 1)
        member.cookies.clear()  # the tampered cookie is the only one this browser has
        member.cookies.set(AUTH_COOKIE_NAME, f"{encoded}.{'0' * 64}")

        assert (await member.get("/config", headers=NAVIGATION)).headers["location"] == "/login?next=/config"


class TestWhatCountsAsActivity:
    async def test_a_page_navigation_refreshes_the_cookie_keeping_the_issue_time(self, member, clock):
        clock.advance(2 * MINUTE)

        response = await member.get("/state", headers=NAVIGATION)

        assert reissued(response) == {"auth": "password", "iat": int(START), "act": int(START + 2 * MINUTE)}

    async def test_the_new_cookie_has_the_login_cookies_attributes(self, member, clock):
        clock.advance(MINUTE)

        header = next(h for h in (await member.get("/state", headers=NAVIGATION)).headers.get_list("set-cookie")
                      if h.startswith(AUTH_COOKIE_NAME))

        assert "HttpOnly" in header and "SameSite=lax" in header and "Path=/" in header
        assert "Secure" not in header

    async def test_the_new_cookie_is_secure_over_https(self, clock):
        app = create_app(settings=authed_settings())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="https://test") as client:
            await log_in(client)
            clock.advance(MINUTE)
            header = next(h for h in (await client.get("/state", headers=NAVIGATION)).headers.get_list("set-cookie")
                          if h.startswith(AUTH_COOKIE_NAME))

        assert "Secure" in header

    async def test_a_browser_navigation_without_an_html_accept_counts_by_sec_fetch_mode(self, member, clock):
        clock.advance(MINUTE)

        response = await member.get("/state", headers={"Accept": "*/*", "Sec-Fetch-Mode": "navigate"})

        assert reissued(response)["act"] == int(START + MINUTE)

    async def test_navigating_keeps_the_session_alive_past_the_limit(self, member, clock):
        for _ in range(4):
            clock.advance(4 * MINUTE)
            response = await member.get("/state", headers=NAVIGATION)
            assert response.status_code == 200

    async def test_polling_never_extends_the_session(self, member, clock):
        for _ in range(4):
            clock.advance(MINUTE)
            for path in ("/partials/overview", "/api/v1/status", "/static/style.css"):
                response = await member.get(path, headers={"Accept": "*/*"})
                assert reissued(response) is None, path

        clock.advance(2 * MINUTE)  # 6 minutes since the person last did anything

        assert (await member.get("/partials/overview")).status_code == 401

    async def test_a_partial_fetched_with_an_html_accept_is_still_a_poll(self, member, clock):
        clock.advance(MINUTE)

        response = await member.get("/partials/overview", headers=NAVIGATION)

        assert reissued(response) is None

    async def test_a_head_request_is_not_activity(self, member, clock):
        clock.advance(MINUTE)

        response = await member.head("/state", headers=NAVIGATION)

        assert reissued(response) is None

    async def test_any_post_is_activity(self, member, clock):
        clock.advance(2 * MINUTE)

        response = await member.post("/api/v1/command", json={})  # refused for its body; still the person acting

        assert response.status_code != 401
        assert reissued(response)["act"] == int(START + 2 * MINUTE)

    async def test_the_cookie_is_not_reissued_more_often_than_every_15_seconds(self, member, clock):
        clock.advance(10)
        assert reissued(await member.get("/state", headers=NAVIGATION)) is None

        clock.advance(6)
        assert reissued(await member.get("/state", headers=NAVIGATION))["act"] == int(START + 16)

        clock.advance(5)
        assert reissued(await member.get("/state", headers=NAVIGATION)) is None


class TestHeartbeat:
    async def test_touch_refreshes_the_cookie_and_answers_204(self, member, clock):
        clock.advance(3 * MINUTE)

        response = await member.post("/api/session/touch")

        assert response.status_code == 204 and response.content == b""
        assert reissued(response) == {"auth": "password", "iat": int(START), "act": int(START + 3 * MINUTE)}

    async def test_touch_keeps_a_session_alive_across_the_limit(self, member, clock):
        for _ in range(4):
            clock.advance(4 * MINUTE)
            assert (await member.post("/api/session/touch")).status_code == 204

        assert (await member.get("/state", headers=NAVIGATION)).status_code == 200

    async def test_touch_needs_a_login(self, clock):
        async with client_for() as anon:
            response = await anon.post("/api/session/touch")

        assert response.status_code == 401 and reissued(response) is None

    async def test_an_api_token_alone_does_not_pass_touch(self, clock, tmp_path):
        app = create_app(settings=authed_settings())
        app.state.api_access = ApiAccessStore(tmp_path / "api_access.json")
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="test")

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/session/touch", headers={"Authorization": f"Bearer {plaintext}"})

        assert response.status_code == 401

    async def test_touch_with_no_login_configured_is_refused(self, clock):
        async with client_for(token="") as client:
            assert (await client.post("/api/session/touch")).status_code == 403

    async def test_touch_is_a_post_only_route(self, member):
        assert (await member.get("/api/session/touch")).status_code == 405


class TestAbsoluteLimit:
    async def test_a_session_older_than_seven_days_ends_however_active(self, clock):
        async with client_for() as client:
            client.cookies.set(AUTH_COOKIE_NAME, password_cookie(iat=START - 7 * DAY - 1, act=START))
            response = await client.get("/config", headers=NAVIGATION)

        assert response.status_code == 303
        assert response.headers["location"] == "/login?next=/config"  # expired, not idle

    async def test_a_week_old_session_with_recent_activity_is_valid(self, clock):
        async with client_for() as client:
            client.cookies.set(AUTH_COOKIE_NAME, password_cookie(iat=START - 6 * DAY, act=START - MINUTE))
            response = await client.get("/state", headers=NAVIGATION)

        assert response.status_code == 200
        assert reissued(response)["iat"] == int(START - 6 * DAY)

    async def test_activity_does_not_move_the_issue_time(self, clock):
        async with client_for() as client:
            client.cookies.set(AUTH_COOKIE_NAME, password_cookie(iat=START - 7 * DAY + 60, act=START - 30))
            assert (await client.get("/state", headers=NAVIGATION)).status_code == 200
            clock.advance(2 * MINUTE)  # past the 7 days since issue
            assert (await client.get("/state", headers=NAVIGATION)).status_code == 303


class TestIdleLimitSetting:
    async def test_zero_disables_the_idle_logout(self, clock):
        async with client_for(session_idle_minutes=0) as client:
            client.cookies.set(AUTH_COOKIE_NAME, password_cookie(iat=START - 3 * DAY, act=START - 3 * DAY))
            response = await client.get("/state", headers=NAVIGATION)

        assert response.status_code == 200
        assert reissued(response) is None  # nothing to extend

    async def test_zero_still_enforces_the_absolute_limit(self, clock):
        async with client_for(session_idle_minutes=0) as client:
            client.cookies.set(AUTH_COOKIE_NAME, password_cookie(iat=START - 8 * DAY))
            assert (await client.get("/state", headers=NAVIGATION)).status_code == 303

    @pytest.mark.parametrize(("minutes", "age", "valid"), [(1, 61, False), (1, 60, True), (30, 29 * MINUTE, True), (30, 31 * MINUTE, False)])
    async def test_the_limit_follows_the_setting(self, clock, minutes, age, valid):
        async with client_for(session_idle_minutes=minutes) as client:
            client.cookies.set(AUTH_COOKIE_NAME, password_cookie(iat=START - age, act=START - age))
            response = await client.get("/state", headers=NAVIGATION)

        assert (response.status_code == 200) is valid

    async def test_the_default_is_five_minutes(self):
        assert authed_settings().session_idle_minutes == 5


class TestCookiesFromBeforeThisChange:
    async def test_a_cookie_without_act_counts_its_issue_time_as_the_activity(self, clock):
        async with client_for() as client:
            client.cookies.set(AUTH_COOKIE_NAME, password_cookie(iat=START - 4 * MINUTE))
            assert (await client.get("/state", headers=NAVIGATION)).status_code == 200

    async def test_a_cookie_without_act_ends_five_minutes_after_issue(self, clock):
        async with client_for() as client:
            client.cookies.set(AUTH_COOKIE_NAME, password_cookie(iat=START - 5 * MINUTE - 1))
            response = await client.get("/config", headers=NAVIGATION)

        assert response.headers["location"] == "/login?next=/config&reason=idle"

    async def test_using_one_adds_act_to_it(self, clock):
        async with client_for() as client:
            client.cookies.set(AUTH_COOKIE_NAME, password_cookie(iat=START - MINUTE))
            response = await client.get("/state", headers=NAVIGATION)

        assert reissued(response) == {"auth": "password", "iat": int(START - MINUTE), "act": int(START)}


class TestOauthSessions:
    @pytest.fixture
    async def octocat(self, clock):
        async with client_for(**oauth_settings()) as client:
            client.cookies.set(OAUTH_COOKIE_NAME, build_oauth_session("octocat", TEST_AUTH_SECRET))
            yield client

    async def test_a_fresh_oauth_session_is_valid(self, octocat):
        assert (await octocat.get("/state", headers=NAVIGATION)).status_code == 200

    async def test_an_idle_oauth_session_ends(self, octocat, clock):
        clock.advance(6 * MINUTE)

        page = await octocat.get("/config", headers=NAVIGATION)
        api = await octocat.get("/api/v1/status")

        assert page.headers["location"] == "/login?next=/config&reason=idle"
        assert api.status_code == 401 and api.json()["reason"] == "idle"

    async def test_navigating_refreshes_the_oauth_cookie_and_keeps_the_user(self, octocat, clock):
        clock.advance(2 * MINUTE)

        response = await octocat.get("/state", headers=NAVIGATION)

        assert reissued(response, OAUTH_COOKIE_NAME) == {"login": "octocat", "iat": int(START), "act": int(START + 2 * MINUTE)}
        assert reissued(response) is None

    async def test_polling_does_not_refresh_the_oauth_cookie(self, octocat, clock):
        clock.advance(2 * MINUTE)

        response = await octocat.get("/partials/overview")

        assert reissued(response, OAUTH_COOKIE_NAME) is None

    async def test_touch_refreshes_the_oauth_cookie(self, octocat, clock):
        clock.advance(2 * MINUTE)

        response = await octocat.post("/api/session/touch")

        assert response.status_code == 204
        assert reissued(response, OAUTH_COOKIE_NAME)["act"] == int(START + 2 * MINUTE)

    async def test_the_oauth_limit_ignores_zero_the_same_way(self, clock):
        async with client_for(**oauth_settings(session_idle_minutes=0)) as client:
            client.cookies.set(OAUTH_COOKIE_NAME, sign(Kind.OAUTH_SESSION, {"login": "octocat", "iat": int(START - DAY)}, TEST_AUTH_SECRET))
            assert (await client.get("/state", headers=NAVIGATION)).status_code == 200

    async def test_an_idle_password_cookie_does_not_hide_a_live_oauth_one(self, clock):
        async with client_for(**oauth_settings()) as client:
            client.cookies.set(AUTH_COOKIE_NAME, password_cookie(iat=START - DAY, act=START - DAY))
            client.cookies.set(OAUTH_COOKIE_NAME, build_oauth_session("octocat", TEST_AUTH_SECRET))
            response = await client.get("/state", headers=NAVIGATION)

        assert response.status_code == 200
        assert reissued(response) is None, "the idle password cookie must not be refreshed"


class TestApiTokensAreNotSessions:
    async def test_idle_logout_does_not_touch_a_token_call(self, clock, tmp_path, monkeypatch):
        monkeypatch.setattr(auth, "TOKEN_ROUTES", {("GET", "/api/v1/schedule"): frozenset({"warm_restart"})})
        app = create_app(settings=authed_settings())
        app.state.api_access = ApiAccessStore(tmp_path / "api_access.json")
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="test")

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            client.cookies.set(AUTH_COOKIE_NAME, password_cookie(iat=START - DAY, act=START - DAY))  # idle
            response = await client.get("/api/v1/schedule", headers={"Authorization": f"Bearer {plaintext}"})

        assert response.status_code == 200


class TestLogout:
    async def test_it_sends_the_visitor_to_the_login_page_saying_they_logged_out(self, member):
        response = await member.post("/logout")

        assert response.status_code == 303
        assert response.headers["location"] == "/login?reason=logout"

    async def test_it_clears_every_session_cookie_and_sets_none(self, member, clock):
        clock.advance(MINUTE)

        response = await member.post("/logout")

        headers = response.headers.get_list("set-cookie")
        for name in (AUTH_COOKIE_NAME, OAUTH_COOKIE_NAME, "ibctl_dashboard_oauth_state"):
            cleared = [h for h in headers if h.startswith(f'{name}=""') or h.startswith(f"{name}=;")]
            assert cleared, (name, headers)
        assert reissued(response) is None, "the activity refresh must not undo the logout"

    async def test_after_it_the_session_is_gone(self, member):
        await member.post("/logout")

        assert (await member.get("/config", headers=NAVIGATION)).status_code == 303

    async def test_it_works_for_an_idle_session_too(self, member, clock):
        clock.advance(10 * MINUTE)

        assert (await member.post("/logout")).headers["location"] == "/login?reason=logout"


class TestLoginPageMessages:
    async def test_idle_says_how_long(self, clock):
        async with client_for(session_idle_minutes=5) as client:
            html = (await client.get("/login?reason=idle")).text

        assert "You were signed out after 5 minutes of inactivity." in html

    @pytest.mark.parametrize(("minutes", "words"), [(1, "1 minute of"), (10, "10 minutes of"), (1440, "1440 minutes of")])
    async def test_the_number_is_the_setting(self, clock, minutes, words):
        async with client_for(session_idle_minutes=minutes) as client:
            html = (await client.get("/login?reason=idle")).text

        assert f"You were signed out after {words} inactivity." in html

    async def test_logout_says_so(self, clock):
        async with client_for() as client:
            html = (await client.get("/login?reason=logout")).text

        assert "You have been signed out." in html
        assert "inactivity" not in html

    async def test_no_reason_says_nothing(self, clock):
        async with client_for() as client:
            html = (await client.get("/login")).text

        assert "signed out" not in html

    @pytest.mark.parametrize("reason", ["<script>alert(1)</script>", "IDLE", "idle ", "other", "", "idle&reason=logout"])
    async def test_any_other_reason_is_ignored_and_never_echoed(self, clock, reason):
        async with client_for() as client:
            response = await client.get("/login", params={"reason": reason})

        assert response.status_code == 200
        assert "signed out" not in response.text
        assert "alert(1)" not in response.text
        assert reason.strip() == "" or reason not in response.text

    async def test_the_message_is_not_styled_as_an_error(self, clock):
        async with client_for() as client:
            html = (await client.get("/login?reason=idle")).text

        assert 'class="login-notice"' in html
        assert 'class="login-error"' not in html

    async def test_a_wrong_password_after_a_notice_still_shows_the_error(self, clock):
        async with client_for() as client:
            response = await client.post("/login", data={"password": "nope", "next": "/"})  # nosecret: test value

        assert response.status_code == 401 and "Invalid password" in response.text

    async def test_next_survives_next_to_the_reason(self, clock):
        async with client_for() as client:
            html = (await client.get("/login?next=/config&reason=idle")).text

        assert 'name="next" value="/config"' in html
