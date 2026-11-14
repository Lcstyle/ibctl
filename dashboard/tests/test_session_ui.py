"""The signed-in header: a Log out button and the idle sign-out script.

Both are on every page a logged-in visitor sees and on none an anonymous one
sees (the health summary, the login page). The button is a plain form post so
it works without JavaScript; the script is configured by data attributes.
"""

from __future__ import annotations

import pytest
from bs4 import BeautifulSoup
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from app.main import create_app
from app.middleware.auth import AUTH_COOKIE_NAME, OAUTH_COOKIE_NAME, build_oauth_session, build_password_session
from tests.auth_helpers import TEST_AUTH_SECRET, authed_settings, log_in

NAVIGATION = {"Accept": "text/html"}
PAGES = ["/", "/state", "/config", "/logs", "/controls", "/gateway", "/api-access", "/notifications", "/ib-status", "/vnc"]


def client(monkeypatch, root_path: str = "", **settings) -> AsyncClient:
    if root_path:
        monkeypatch.setenv("IBCTL_ROOT_PATH", root_path)
    else:
        monkeypatch.delenv("IBCTL_ROOT_PATH", raising=False)
    return AsyncClient(transport=ASGITransport(app=create_app(settings=authed_settings(**settings))), base_url="http://test")


def soup(response) -> BeautifulSoup:
    return BeautifulSoup(response.text, "html.parser")


def logout_form(page: BeautifulSoup):
    return page.select_one("nav.tabs form[action$='/logout']")


def session_script(page: BeautifulSoup):
    return page.select_one("script[src*='session.js']")


class TestSignedIn:
    @pytest.mark.parametrize("path", PAGES)
    async def test_every_page_has_the_logout_button_and_the_idle_script(self, monkeypatch, path):
        async with client(monkeypatch) as c:
            await log_in(c)
            response = await c.get(path, headers=NAVIGATION, follow_redirects=True)

        page = soup(response)
        form = logout_form(page)
        assert form is not None and form["method"] == "post" and form["action"] == "/logout", path
        assert form.select_one("button[type=submit]").get_text(strip=True) == "Log out"
        assert session_script(page) is not None, path

    async def test_the_button_says_who_is_signed_in(self, monkeypatch):
        async with client(monkeypatch) as c:
            await log_in(c)
            page = soup(await c.get("/state", headers=NAVIGATION))

        assert logout_form(page).select_one("button")["title"] == "Signed in as dashboard user"

    async def test_an_oauth_login_is_named_in_the_tooltip(self, monkeypatch):
        async with client(monkeypatch, github_client_id="client-id", github_client_secret=SecretStr("client-secret")) as c:  # nosecret: test value
            c.cookies.set(OAUTH_COOKIE_NAME, build_oauth_session("octocat", TEST_AUTH_SECRET))
            page = soup(await c.get("/state", headers=NAVIGATION))

        assert logout_form(page).select_one("button")["title"] == "Signed in as octocat"

    async def test_a_hostile_login_name_is_escaped(self, monkeypatch):
        evil = '"><script>alert(1)</script>'
        async with client(monkeypatch, github_client_id="client-id", github_client_secret=SecretStr("client-secret")) as c:  # nosecret: test value
            c.cookies.set(OAUTH_COOKIE_NAME, build_oauth_session(evil, TEST_AUTH_SECRET))
            response = await c.get("/state", headers=NAVIGATION)

        assert "<script>alert(1)" not in response.text
        assert logout_form(soup(response)).select_one("button")["title"] == f"Signed in as {evil}"

    async def test_the_script_is_configured_by_data_attributes(self, monkeypatch):
        async with client(monkeypatch, session_idle_minutes=10) as c:
            await log_in(c)
            script = session_script(soup(await c.get("/state", headers=NAVIGATION)))

        assert script["src"].startswith("/static/session.js")
        assert script["data-idle-seconds"] == "600"
        assert script["data-root"] == ""
        assert script.has_attr("defer")

    async def test_the_default_limit_reaches_the_page_as_300_seconds(self, monkeypatch):
        async with client(monkeypatch) as c:
            await log_in(c)
            script = session_script(soup(await c.get("/state", headers=NAVIGATION)))

        assert script["data-idle-seconds"] == "300"

    async def test_zero_still_shows_the_button_and_tells_the_script_to_stand_down(self, monkeypatch):
        async with client(monkeypatch, session_idle_minutes=0) as c:
            await log_in(c)
            page = soup(await c.get("/state", headers=NAVIGATION))

        assert logout_form(page) is not None
        assert session_script(page)["data-idle-seconds"] == "0"

    async def test_under_a_prefix_the_form_and_the_script_follow_it(self, monkeypatch):
        async with client(monkeypatch, "/ibctl") as c:
            # The login cookie is scoped to /ibctl, which the test's un-prefixed requests never match.
            c.cookies.set(AUTH_COOKIE_NAME, build_password_session(TEST_AUTH_SECRET))
            page = soup(await c.get("/state", headers=NAVIGATION))

        assert logout_form(page)["action"] == "/ibctl/logout"
        script = session_script(page)
        assert script["src"].startswith("/ibctl/static/session.js") and script["data-root"] == "/ibctl"

    async def test_the_button_works_end_to_end(self, monkeypatch):
        async with client(monkeypatch) as c:
            await log_in(c)
            page = soup(await c.get("/state", headers=NAVIGATION))
            response = await c.post(logout_form(page)["action"])
            after = await c.get("/state", headers=NAVIGATION)

        assert response.status_code == 303 and response.headers["location"] == "/login?reason=logout"
        assert after.status_code == 303


class TestAnonymous:
    async def test_the_health_summary_has_neither(self, monkeypatch):
        async with client(monkeypatch) as c:
            response = await c.get("/", headers=NAVIGATION)

        page = soup(response)
        assert response.status_code == 200
        assert logout_form(page) is None and session_script(page) is None
        assert "Log out" not in response.text

    async def test_the_login_page_has_neither(self, monkeypatch):
        async with client(monkeypatch) as c:
            response = await c.get("/login?reason=logout")

        page = soup(response)
        assert logout_form(page) is None and session_script(page) is None
        assert "Log out" not in response.text

    async def test_the_script_file_itself_is_public_like_the_other_static_files(self, monkeypatch):
        async with client(monkeypatch) as c:
            response = await c.get("/static/session.js")

        assert response.status_code == 200
        assert "javascript" in response.headers["content-type"]
        assert "/api/session/touch" in response.text
