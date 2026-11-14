"""Shared login plumbing for tests that build the whole dashboard app.

Most pages and every API route need a login, so tests that exercise them
configure a dashboard password and sign in through the real login form,
the same way a browser does.
"""

from __future__ import annotations

import hmac
import json
import re
from base64 import urlsafe_b64encode

from httpx import AsyncClient
from pydantic import SecretStr
from starlette.routing import WebSocketRoute

from app.config import DashboardSettings
from app.middleware.auth import AUTH_COOKIE_NAME, build_password_session

TEST_PASSWORD = "correct horse battery staple"  # nosecret: test value
TEST_AUTH_SECRET = "test-session-signing-secret"  # nosecret: test value


def legacy_cookie(payload: dict, secret: str = TEST_AUTH_SECRET) -> str:
    """A signed value in the format the dashboard used before it signed with `itsdangerous`.

    base64url(JSON) + "." + the hex HMAC-SHA256 of that text. Nothing builds
    this any more; tests use it to prove an old cookie no longer logs anyone in.
    """
    body = urlsafe_b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).decode().rstrip("=")
    return f"{body}.{hmac.new(secret.encode(), body.encode(), 'sha256').hexdigest()}"


def authed_settings(**overrides) -> DashboardSettings:
    """Settings with a dashboard password configured (a login is available)."""
    params = {
        "port": 8080,
        "token": TEST_PASSWORD,
        "auth_secret": SecretStr(TEST_AUTH_SECRET),
        "debug_mode": False,
        "ibctl_host": "127.0.0.1",
        "ibctl_port": 7462,
    }
    params.update(overrides)
    return DashboardSettings(**params)


async def log_in(client: AsyncClient, password: str = TEST_PASSWORD, next_path: str = "/"):
    """Sign `client` in through the real login form; its cookie jar keeps the session."""
    response = await client.post("/login", data={"password": password, "next": next_path})
    assert response.status_code == 303, f"login failed: {response.status_code} {response.text[:200]}"
    return response


def logged_in_cookies(secret: str = TEST_AUTH_SECRET) -> dict[str, str]:
    """The session cookie a successful password login sets, for clients built before they open.

    An `AsyncClient` can't send a request until its `async with` block starts,
    so factories that hand back an unopened client pass these as `cookies=`.
    """
    return {AUTH_COOKIE_NAME: build_password_session(secret)}


def route_table(app) -> list[tuple[str, str]]:
    """Every (METHOD, path) the app serves, read from its own route table.

    Included routers are flattened. Path parameters are filled with a dummy
    value, and HEAD is left out (it mirrors GET).
    """

    def walk(routes):
        for route in routes:
            if hasattr(route, "effective_route_contexts"):  # FastAPI keeps included routers nested
                yield from walk(route.effective_route_contexts())
            else:
                yield route

    found: set[tuple[str, str]] = set()
    for route in walk(app.routes):
        methods = getattr(getattr(route, "original_route", route), "methods", None)
        if not methods:
            continue  # a mount (static files), handled separately
        path = re.sub(r"\{[^}]+\}", "x", route.path)
        found.update((method, path) for method in methods if method != "HEAD")
    return sorted(found)


def websocket_route_table(app) -> list[str]:
    """Every websocket path the app serves, read from its own route table.

    `route_table` skips these (a websocket route has no HTTP methods), so the
    sweep over them is its own.
    """

    def walk(routes):
        for route in routes:
            if hasattr(route, "effective_route_contexts"):
                yield from walk(route.effective_route_contexts())
            else:
                yield route

    def path_of(route) -> str:
        # An included websocket route's context leaves `path` empty; the route itself has it.
        return route.path or getattr(getattr(route, "starlette_route", None), "path", "") or route.original_route.path

    return sorted({
        re.sub(r"\{[^}]+\}", "x", path_of(route))
        for route in walk(app.routes)
        if isinstance(getattr(route, "original_route", route), WebSocketRoute)
    })
