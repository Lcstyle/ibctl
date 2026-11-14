"""Public IB status, HEAD on the public routes, and paths that match no route.

- `GET /api/v1/ib-status` is the IB system status other services poll. Anonymous
  callers get a fixed list of fields; a logged-in person gets the full reply. The
  routes beside it (audit log, override, scraper config) stay login-only.
- A monitor's `HEAD` on a public route gets what `GET` would, not a 405.
- A path that matches no route is refused like a protected one (no existence leak),
  and reached directly (without the proxy that strips the prefix) the prefix is
  stripped, so the login redirect no longer matches nothing and loops for ever.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import create_app
from tests.auth_helpers import authed_settings, log_in

PREFIX = "/ibctl"
OVERRIDE_REASON = "SENTINEL-override-reason-typed-by-an-operator"
FETCH_ERROR = "SENTINEL-fetch-error-with-an-internal-hostname.example"

PUBLIC_FIELDS = {
    "ok", "status", "override_active", "override_status", "last_updated",
    "alerts", "daily_resets", "weekend_resets",
}


def _window(region: str) -> SimpleNamespace:
    t = datetime(2026, 11, 14, 5, 0, tzinfo=timezone.utc)
    return SimpleNamespace(region=region, start_time=t, end_time=t.replace(hour=6), timezone="America/New_York")


def _monitor(override: bool = True) -> SimpleNamespace:
    alert = SimpleNamespace(
        message="Scheduled maintenance window", severity=SimpleNamespace(value="warning"), is_blocking=lambda: False
    )
    scraper_status = SimpleNamespace(
        last_updated=datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc),
        fetch_error=FETCH_ERROR,
        alerts=[alert],
        daily_resets=[_window("US")],
        weekend_resets=[_window("EU")],
    )
    return SimpleNamespace(
        _scraper=SimpleNamespace(_last_status=scraper_status),
        _last_pushed_status="maintenance" if override else "available",
        override_active=override,
        override_status="maintenance" if override else "",
        override_reason=OVERRIDE_REASON if override else "",
        audit_log=[],
    )


def _client(monkeypatch, root_path: str = "", token: str | None = None, **settings) -> AsyncClient:
    if root_path:
        monkeypatch.setenv("IBCTL_ROOT_PATH", root_path)
    else:
        monkeypatch.delenv("IBCTL_ROOT_PATH", raising=False)
    if token is not None:
        settings["token"] = token
    app = create_app(settings=authed_settings(**settings))
    app.state.ib_status_monitor = _monitor()
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# --- public, whitelisted IB status -------------------------------------------------------------


async def test_anonymous_callers_get_only_the_fixed_fields(monkeypatch):
    async with _client(monkeypatch) as client:
        response = await client.get("/api/v1/ib-status")

    assert response.status_code == 200
    body = response.json()
    assert set(body) == PUBLIC_FIELDS
    assert body["status"] == "maintenance" and body["override_active"] is True and body["override_status"] == "maintenance"
    assert body["alerts"] == [{"message": "Scheduled maintenance window", "severity": "warning", "is_blocking": False}]
    assert OVERRIDE_REASON not in response.text and FETCH_ERROR not in response.text


async def test_a_logged_in_person_still_gets_the_full_reply(monkeypatch):
    async with _client(monkeypatch) as client:
        await log_in(client)
        body = (await client.get("/api/v1/ib-status")).json()

    assert body["override_reason"] == OVERRIDE_REASON
    assert body["fetch_error"] == FETCH_ERROR


async def test_with_no_override_the_override_status_is_left_out(monkeypatch):
    async with _client(monkeypatch) as client:
        client._transport.app.state.ib_status_monitor = _monitor(override=False)
        body = (await client.get("/api/v1/ib-status")).json()

    assert body["override_active"] is False
    assert "override_status" not in body and "override_reason" not in body


async def test_it_is_public_even_when_no_login_is_configured(monkeypatch):
    async with _client(monkeypatch, token="") as client:
        response = await client.get("/api/v1/ib-status")

    assert response.status_code == 200 and set(response.json()) == PUBLIC_FIELDS


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/v1/ib-status/audit-log"),
        ("GET", "/api/v1/ib-status/scraper-config"),
        ("POST", "/api/v1/ib-status/scraper-config"),
        ("POST", "/api/v1/ib-status/override"),
        ("DELETE", "/api/v1/ib-status/override"),
    ],
)
async def test_the_routes_beside_it_stay_login_only(monkeypatch, method, path):
    async with _client(monkeypatch) as client:
        response = await client.request(method, path, json={"status": "maintenance", "reason": "x"})

    assert response.status_code in (401, 403), (method, path, response.status_code)
    assert OVERRIDE_REASON not in response.text


# --- HEAD on the public routes ---------------------------------------------------------------


@pytest.mark.parametrize("path", ["/", "/api/v1/health", "/api/v1/ib-status"])
async def test_head_on_a_public_route_is_what_get_would_be(monkeypatch, path):
    async with _client(monkeypatch) as client:
        got = await client.get(path)
        head = await client.head(path)

    assert head.status_code == got.status_code == 200
    assert head.content == b""


async def test_head_on_a_protected_route_is_refused_not_a_405(monkeypatch):
    async with _client(monkeypatch) as client:
        response = await client.head("/api/v1/status")

    assert response.status_code in (401, 403)


# --- paths that match no route -----------------------------------------------------------------


@pytest.mark.parametrize("path", ["/nonexistent", "/ibctl/nonexistent", "/x/y/z"])
async def test_a_path_that_matches_no_route_is_refused_like_a_protected_one(monkeypatch, path):
    """An anonymous visitor cannot tell which paths exist: same answer as a protected page."""
    async with _client(monkeypatch, root_path=PREFIX) as client:
        page = await client.get(path, headers={"Accept": "text/html"})
        api = await client.get(path, headers={"Accept": "application/json"})
        protected = await client.get("/config", headers={"Accept": "text/html"})

    assert page.status_code == protected.status_code == 303
    assert "/login" in page.headers["location"]
    assert api.status_code == 401


async def test_unknown_paths_are_refused_when_no_login_is_configured_too(monkeypatch):
    async with _client(monkeypatch, token="") as client:
        unknown = await client.get("/nonexistent", headers={"Accept": "application/json"})
        protected = await client.get("/api/v1/status", headers={"Accept": "application/json"})

    assert unknown.status_code == protected.status_code == 403


async def test_a_known_protected_page_still_redirects_to_the_login(monkeypatch):
    async with _client(monkeypatch) as client:
        response = await client.get("/config", headers={"Accept": "text/html"})

    assert response.status_code == 303 and "/login" in response.headers["location"]


# --- the dashboard reached directly with its prefix in the URL ---------------------------------


async def test_reached_directly_with_the_prefix_it_answers_as_it_does_behind_the_proxy(monkeypatch):
    async with _client(monkeypatch, root_path=PREFIX) as client:
        health = await client.get(f"{PREFIX}/api/v1/health")
        login = await client.get(f"{PREFIX}/login")
        ib = await client.get(f"{PREFIX}/api/v1/ib-status")

    assert health.status_code == 200 and health.json()["status"] == "ok"
    assert login.status_code == 200 and 'name="password"' in login.text
    assert ib.status_code == 200 and set(ib.json()) == PUBLIC_FIELDS


async def test_following_the_login_redirect_reached_directly_ends_at_the_login_page(monkeypatch):
    async with _client(monkeypatch, root_path=PREFIX) as client:
        url, hops = f"{PREFIX}/config", 0
        while hops < 5:
            response = await client.get(url, headers={"Accept": "text/html"})
            if response.status_code != 303:
                break
            url, hops = response.headers["location"], hops + 1

    assert response.status_code == 200 and 'name="password"' in response.text, (url, hops)
    assert hops <= 2


async def test_the_prefix_is_only_stripped_at_the_start_of_the_path(monkeypatch):
    async with _client(monkeypatch, root_path=PREFIX) as client:
        response = await client.get("/api/v1/health/ibctl/api/v1/health")

    assert response.status_code == 401, "not served as the health route"


# --- the restart schedule ------------------------------------------------------------------------

SCHEDULE_FIELDS = {"timezone", "auto_restart", "cold_restart", "correlation_minutes", "grace_minutes"}


async def test_the_restart_schedule_is_public_and_the_same_for_everyone(monkeypatch):
    """Monitors read it to tell an expected restart from an outage. Fixed fields, no free text."""
    monkeypatch.setenv("AUTO_RESTART_TIME", "05:05 PM")
    monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
    async with _client(monkeypatch) as client:
        anonymous = await client.get("/api/v1/schedule")
        await log_in(client)
        logged_in = await client.get("/api/v1/schedule")

    assert anonymous.status_code == 200
    assert set(anonymous.json()) == SCHEDULE_FIELDS
    assert anonymous.json()["auto_restart"]["time_24h"] == "17:05"
    assert anonymous.json() == logged_in.json(), "nothing here depends on who is asking"


async def test_head_on_the_schedule_is_what_get_would_be(monkeypatch):
    async with _client(monkeypatch) as client:
        head = await client.head("/api/v1/schedule")

    assert head.status_code == 200 and head.content == b""


async def test_the_schedule_is_public_even_when_no_login_is_configured(monkeypatch):
    async with _client(monkeypatch, token="") as client:
        response = await client.get("/api/v1/schedule")

    assert response.status_code == 200 and set(response.json()) == SCHEDULE_FIELDS
