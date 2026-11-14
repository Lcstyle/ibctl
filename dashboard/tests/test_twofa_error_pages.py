"""State-aware HTML error pages for /api/twofa/callback.

Clicking an old/invalid HITL retry link used to show raw JSON in the
browser, on top of the link not working. Every non-200 path now renders a
styled HTML page instead. For an
invalid/rejected token specifically, the page also checks ibctl's CURRENT
state for that mode and tailors the message: still stuck in
WaitingForHitl2fa -> "open the dashboard to resume" with a real link;
already left that state -> "already resolved, nothing to do".

Other failure reasons (rate-limited, signing key missing, unknown mode,
ibctl unreachable) get a plain styled page — no state check, since either
there's no meaningful mode to check, or we can't reach ibctl anyway.
"""

from __future__ import annotations

import os
from dataclasses import asdict
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.domain.errors import DashboardError
from app.instance_registry import _CachedResponse
from app.main import create_app
from tests.auth_helpers import authed_settings
from app.services import hitl_tokens

SIGNING_KEY = "test-signing-key-for-error-page-tests"


def _make_valid_token(mode: str = "live") -> str:
    return hitl_tokens.mint_token(SIGNING_KEY, mode, None)


def _make_app():
    # A dashboard password is configured and the client stays signed out:
    # a notification link works without a login.
    return create_app(settings=authed_settings())


class _RaisingClient:
    """A fake ibctl client whose send_command always fails — for the
    ibctl_unreachable path."""

    async def send_command(self, command: str) -> str:
        raise DashboardError("connection refused")

    async def status_raw(self) -> dict:
        raise DashboardError("connection refused")


@pytest.fixture
def reset_rate_limiter():
    import app.api.twofa as twofa_mod

    twofa_mod._ip_timestamps.clear()
    yield
    twofa_mod._ip_timestamps.clear()


@pytest.fixture
async def env(fake_client):
    """Everything a test needs: the HTTP client, the app (for reaching the
    registry), and a helper to set a mode's `hitl.active` flag in the
    STATUS cache — exactly the field the state-aware error page reads."""
    app = _make_app()
    app.state.ibctl_client = fake_client
    registry = app.state.instance_registry
    for mode in registry.modes():
        registry._clients[mode] = fake_client

    status_dict = asdict(fake_client._status)
    for mode in registry.modes():
        registry._cache[f"{mode}:STATUS"] = _CachedResponse(
            dict(status_dict), registry.STATUS_TTL
        )

    def set_hitl_active(mode: str, active: bool | None):
        existing = registry._cache.get(f"{mode}:STATUS")
        cached = dict(existing.data) if existing else dict(status_dict)
        if active is None:
            cached.pop("hitl", None)
        else:
            cached["hitl"] = {"active": active}
        registry._cache[f"{mode}:STATUS"] = _CachedResponse(cached, registry.STATUS_TTL)

    transport = ASGITransport(app=app)
    with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c, registry, set_hitl_active


class TestGenericFailuresAreHtml:
    @pytest.mark.asyncio
    async def test_signing_key_missing_is_html(self, env, reset_rate_limiter):
        client, _, _ = env
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IBCTL_NTFY_ACTION_SIGNING_KEY", None)
            resp = await client.get("/api/twofa/callback?t=x&mode=live")
        assert resp.status_code == 503
        assert "text/html" in resp.headers["content-type"]
        assert resp.text.lstrip().startswith("<!doctype html>"), (
            f"expected a rendered HTML page, not raw JSON: {resp.text!r}"
        )

    @pytest.mark.asyncio
    async def test_invalid_mode_is_html(self, env, reset_rate_limiter):
        client, _, _ = env
        token = _make_valid_token("live")
        resp = await client.get(f"/api/twofa/callback?t={token}&mode=bogus")
        assert resp.status_code == 400
        assert "text/html" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_rate_limited_is_html(self, env, reset_rate_limiter):
        client, _, _ = env
        token = _make_valid_token("live")
        url = f"/api/twofa/callback?t={token}&mode=live"
        for _ in range(10):
            await client.get(url)
        resp = await client.get(url)
        assert resp.status_code == 429
        assert "text/html" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_ibctl_unreachable_is_html(self, env, reset_rate_limiter):
        client, registry, set_hitl_active = env
        # Waiting for 2FA, so the retry is attempted — and ibctl is unreachable.
        set_hitl_active("live", True)
        registry._clients["live"] = _RaisingClient()
        token = _make_valid_token("live")
        resp = await client.get(f"/api/twofa/callback?t={token}&mode=live")
        assert resp.status_code == 502
        assert "text/html" in resp.headers["content-type"]


class TestInvalidTokenIsStateAware:
    @pytest.mark.asyncio
    async def test_bad_token_while_still_stuck_offers_dashboard_link(
        self, env, reset_rate_limiter
    ):
        client, _, set_hitl_active = env
        set_hitl_active("live", True)

        resp = await client.get("/api/twofa/callback?t=not-a-real-token&mode=live")

        assert resp.status_code == 400
        assert "text/html" in resp.headers["content-type"]
        assert "href=" in resp.text, "expected a link back to the dashboard"
        assert (
            "still needs 2fa" in resp.text.lower()
            or "still waiting" in resp.text.lower()
        )
        assert "isn't waiting on 2fa anymore" not in resp.text.lower(), (
            "must not claim the situation resolved when it's still active"
        )

    @pytest.mark.asyncio
    async def test_bad_token_when_already_resolved_says_nothing_to_do(
        self, env, reset_rate_limiter
    ):
        client, _, set_hitl_active = env
        set_hitl_active("live", False)

        resp = await client.get("/api/twofa/callback?t=not-a-real-token&mode=live")

        assert resp.status_code == 400
        assert "text/html" in resp.headers["content-type"]
        assert "resolved" in resp.text.lower() or "nothing to do" in resp.text.lower()

    @pytest.mark.asyncio
    async def test_bad_token_when_hitl_block_absent_says_nothing_to_do(
        self, env, reset_rate_limiter
    ):
        """No `hitl` key at all (mode never in HITL, or STATUS predates the
        field) must fail open toward "nothing to worry about", not toward
        a scary dead end."""
        client, _, set_hitl_active = env
        set_hitl_active("live", None)

        resp = await client.get("/api/twofa/callback?t=not-a-real-token&mode=live")

        assert resp.status_code == 400
        assert "resolved" in resp.text.lower() or "nothing to do" in resp.text.lower()

    @pytest.mark.asyncio
    async def test_expired_token_is_state_aware_too(
        self, env, reset_rate_limiter, monkeypatch
    ):
        """Reason=expired (still reachable for an in-flight pre-upgrade
        token, or a bounded reconnect-intent token replayed here) gets the
        same treatment as any other invalid_token reason."""
        import time as time_mod

        client, _, set_hitl_active = env
        set_hitl_active("live", True)
        token = hitl_tokens.mint_token(SIGNING_KEY, "live", 1)  # valid 1h

        future = time_mod.time() + 2 * 3600  # 2h later — past the 1h window
        monkeypatch.setattr(time_mod, "time", lambda: future)

        resp = await client.get(f"/api/twofa/callback?t={token}&mode=live")

        assert resp.status_code == 400
        assert "href=" in resp.text

    @pytest.mark.asyncio
    async def test_mode_mismatch_checks_the_url_mode(self, env, reset_rate_limiter):
        """Token minted for one mode but the URL names another — the state
        check must use the URL's mode (the one actually being asked
        about), not the token's claimed mode."""
        client, _, set_hitl_active = env
        set_hitl_active("live", False)  # live already resolved
        # Token's OWN mode field is "paper" — mismatch is detected from the
        # token string alone (no registry lookup needed for "paper"); the
        # state check that follows must still use the URL's mode ("live").
        token_for_paper = _make_valid_token("paper")

        resp = await client.get(f"/api/twofa/callback?t={token_for_paper}&mode=live")

        assert resp.status_code == 400
        assert "resolved" in resp.text.lower() or "nothing to do" in resp.text.lower()

    @pytest.mark.asyncio
    async def test_valid_token_still_returns_the_existing_success_page(
        self, env, reset_rate_limiter, fake_client
    ):
        """Regression: the happy path must be completely unaffected."""
        client, _, set_hitl_active = env
        set_hitl_active("live", True)
        token = _make_valid_token("live")

        resp = await client.get(f"/api/twofa/callback?t={token}&mode=live")

        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert fake_client._last_command == "HITL_RESUME"
