"""Tests for dashboard authentication middleware.

Verifies the auth contract:
- Token configured → API gets 401, browser GETs redirect to /login
- Token + correct auth → request passes through
- No token → open access (no 401)
- Static files always bypass auth
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import DashboardSettings
from app.main import create_app


def _make_app(token: str = "") -> create_app:
    """Create app with given token setting."""
    settings = DashboardSettings(
        port=8080,
        token=token,
        debug_mode=False,
        ibctl_host="127.0.0.1",
        ibctl_port=7462,
    )
    return create_app(settings=settings)


@pytest.fixture
async def authed_client():
    """Client for an app with token='test-secret'."""
    app = _make_app(token="test-secret")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
async def open_client():
    """Client for an app with no token (empty string)."""
    app = _make_app(token="")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# --- Token configured: endpoints require auth ---

class TestTokenConfigured:
    """When IBCTL_DASHBOARD_TOKEN is set, API endpoints require auth."""

    @pytest.mark.asyncio
    async def test_api_rejects_no_auth(self, authed_client):
        resp = await authed_client.post("/api/v1/command", json={"command": "RESTART"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_api_rejects_wrong_token(self, authed_client):
        resp = await authed_client.post(
            "/api/v1/command",
            json={"command": "RESTART"},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_api_accepts_bearer_token(self, authed_client):
        resp = await authed_client.post(
            "/api/v1/command",
            json={"command": "RESTART"},
            headers={"Authorization": "Bearer test-secret"},
        )
        assert resp.status_code in (200, 502)

    @pytest.mark.asyncio
    async def test_status_rejects_no_auth(self, authed_client):
        resp = await authed_client.get("/api/v1/status")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_status_accepts_bearer_token(self, authed_client):
        resp = await authed_client.get(
            "/api/v1/status",
            headers={"Authorization": "Bearer test-secret"},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_browser_redirects_to_login(self, authed_client):
        """Browser GET without auth redirects to /login."""
        resp = await authed_client.get("/")
        assert resp.status_code == 303
        assert "/login" in resp.headers.get("location", "")

    @pytest.mark.asyncio
    async def test_pages_accept_bearer_token(self, authed_client):
        resp = await authed_client.get(
            "/",
            headers={"Authorization": "Bearer test-secret"},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_static_files_bypass_auth(self, authed_client):
        """Static assets should not require auth (404 expected, not 401)."""
        resp = await authed_client.get("/static/nonexistent.css")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_api_accepts_basic_auth(self, authed_client):
        """HTTP Basic auth with token as password should work."""
        import base64
        creds = base64.b64encode(b":test-secret").decode()
        resp = await authed_client.get(
            "/api/v1/status",
            headers={"Authorization": f"Basic {creds}"},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_login_page_bypasses_auth(self, authed_client):
        """/login must be accessible without auth."""
        resp = await authed_client.get("/login")
        assert resp.status_code == 200


# --- No token configured: endpoints are open ---

class TestNoToken:
    """When IBCTL_DASHBOARD_TOKEN is empty, all endpoints are open."""

    @pytest.mark.asyncio
    async def test_api_open_no_token(self, open_client):
        resp = await open_client.get("/api/v1/status")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_pages_open_no_token(self, open_client):
        resp = await open_client.get("/")
        assert resp.status_code == 200
