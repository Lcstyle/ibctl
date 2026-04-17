"""Tests for the twofa callback endpoint and the Hitl2faEntryMonitor.

Covers:
  - Existing happy/error paths in the callback endpoint (200, 400, 503)
  - Rate limiting: 11th request from same IP gets 429
  - ntfy retry: NotificationService.send_alert fails once, succeeds on second
    tick — verify second invocation was made.
"""

from __future__ import annotations

import os
import time
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import DashboardSettings
from app.domain.models import StateMachineState
from app.main import create_app
from app.services import hitl_tokens

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

SIGNING_KEY = "test-signing-key-for-tests"


def _make_valid_token(mode: str = "paper") -> str:
    return hitl_tokens.mint_token(SIGNING_KEY, mode, valid_hours=12)


def _make_app():
    settings = DashboardSettings(
        port=8080,
        token="",
        debug_mode=False,
        ibctl_host="127.0.0.1",
        ibctl_port=7462,
    )
    return create_app(settings=settings)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def reset_rate_limiter():
    """Clear the module-level rate-limit state before (and after) each test."""
    import app.api.twofa as twofa_mod
    twofa_mod._ip_timestamps.clear()
    yield
    twofa_mod._ip_timestamps.clear()


@pytest.fixture
async def callback_client(fake_client):
    """HTTP test client with fake ibctl backend, signing key set in env."""
    app = _make_app()
    app.state.ibctl_client = fake_client
    registry = app.state.instance_registry
    for mode in registry.modes():
        registry._clients[mode] = fake_client

    from dataclasses import asdict
    from app.instance_registry import _CachedResponse
    status_dict = asdict(fake_client._status)
    for mode in registry.modes():
        registry._cache[f"{mode}:STATUS"] = _CachedResponse(status_dict, registry.STATUS_TTL)

    transport = ASGITransport(app=app)
    with patch.dict(os.environ, {
        "IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY,
    }):
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c


# ---------------------------------------------------------------------------
# Callback endpoint: existing paths
# ---------------------------------------------------------------------------


class TestTwofaCallbackExistingPaths:
    """Existing 200/400/503 paths must keep working after rate-limit changes."""

    @pytest.mark.asyncio
    async def test_503_when_signing_key_missing(self, client, reset_rate_limiter):
        """Without IBCTL_NTFY_ACTION_SIGNING_KEY the endpoint returns 503."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IBCTL_NTFY_ACTION_SIGNING_KEY", None)
            resp = await client.get("/api/twofa/callback?t=sometoken&mode=paper")
        assert resp.status_code == 503
        assert resp.json()["error"] == "signing_key_not_configured"

    @pytest.mark.asyncio
    async def test_400_invalid_mode(self, callback_client, reset_rate_limiter):
        """Unknown mode returns 400."""
        token = _make_valid_token("paper")
        resp = await callback_client.get(f"/api/twofa/callback?t={token}&mode=invalid")
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_mode"

    @pytest.mark.asyncio
    async def test_400_bad_token(self, callback_client, reset_rate_limiter):
        """Malformed token returns 400."""
        resp = await callback_client.get("/api/twofa/callback?t=notavalidtoken&mode=paper")
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_token"

    @pytest.mark.asyncio
    async def test_200_valid_request(self, callback_client, reset_rate_limiter, fake_client):
        """Valid token + mode returns 200 HTML and dispatches HITL_RESUME."""
        token = _make_valid_token("live")
        resp = await callback_client.get(f"/api/twofa/callback?t={token}&mode=live")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert fake_client._last_command == "HITL_RESUME"


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestTwofaRateLimit:
    """10 req/min per IP; the 11th request in the window gets 429."""

    @pytest.mark.asyncio
    async def test_rate_limit_triggers_on_11th_request(self, callback_client, reset_rate_limiter):
        """Fire 11 requests from same IP — first 10 pass rate check, 11th is 429."""
        # The rate limiter runs before token validation, so we can use any
        # token/mode here; we just need to hit the limit.
        token = _make_valid_token("paper")
        url = f"/api/twofa/callback?t={token}&mode=paper"

        responses = []
        for _ in range(11):
            resp = await callback_client.get(url)
            responses.append(resp.status_code)

        # First 10 must NOT be 429.
        for i, code in enumerate(responses[:10]):
            assert code != 429, f"Request {i + 1} was unexpectedly rate-limited"

        # 11th must be 429.
        assert responses[10] == 429
        assert callback_client  # fixture sanity

        # Verify the 429 body.
        last_resp = await callback_client.get(url)
        assert last_resp.status_code == 429
        assert last_resp.json() == {"error": "rate_limited"}

    @pytest.mark.asyncio
    async def test_rate_limit_resets_after_window(self, callback_client, reset_rate_limiter):
        """After filling the window, old timestamps expire and new requests pass."""
        import app.api.twofa as twofa_mod

        token = _make_valid_token("paper")
        url = f"/api/twofa/callback?t={token}&mode=paper"

        # Fill the bucket with 10 fake timestamps just older than the window.
        past = time.time() - twofa_mod._RATE_LIMIT_WINDOW_SECS - 1.0
        twofa_mod._ip_timestamps["testclient"] = __import__("collections").deque(
            [past] * 10
        )

        # A new request should pass (old entries expire on first call).
        resp = await callback_client.get(url)
        assert resp.status_code != 429


# ---------------------------------------------------------------------------
# ntfy retry behaviour (Item 2)
# ---------------------------------------------------------------------------


class TestHitl2faMonitorRetry:
    """Monitor retries failed ntfy sends on subsequent check() ticks."""

    def _make_registry_stub(self, mode: str = "paper"):
        """Return a minimal registry double for monitor testing.

        The returned registry exposes a ``tick`` counter.  On tick 0 the
        history is empty (no HITL transition); on tick 1+ it includes one
        WaitingForHitl2fa entry.  This mirrors what the real system looks
        like: before the transition happens there's nothing in history, after
        the transition the entry appears.
        """
        from dataclasses import dataclass

        @dataclass
        class _Trans:
            from_state: str
            to_state: str
            timestamp: str

        @dataclass
        class _State:
            current: str
            history: list

        class _Registry:
            _tick = 0

            def advance(self_):
                self_._tick += 1

            def modes(self_):
                return [mode]

            def get_client(self_, m):
                outer = self_

                class _Client:
                    async def state(self__):
                        if outer._tick == 0:
                            return _State(current="Authenticating", history=[])
                        return _State(
                            current="WaitingForHitl2fa",
                            history=[
                                _Trans(
                                    from_state="Authenticating",
                                    to_state="WaitingForHitl2fa",
                                    timestamp="2026-04-16T12:00:00",
                                ),
                            ],
                        )
                return _Client()

            def cached_status_raw(self_, m):
                if self_._tick == 0:
                    return {}
                return {
                    "hitl": {
                        "active": True,
                        "next_retry_in_secs": 300,
                        "callback_valid_hours": 12,
                        "consecutive_2fa_timeouts": 3,
                    }
                }

        return _Registry()

    def _make_ns_stub(self, *, enabled: bool = True, send_results: list[bool] | None = None):
        """Return a minimal NotificationService double."""
        results = iter(send_results or [True])

        class _NS:
            config_channel = "ntfy"

            class config:
                channel = "ntfy"
                enabled = True

            def is_event_enabled(self_, event_type: str) -> bool:
                return enabled

            async def send_alert(self_, **kwargs) -> bool:
                return next(results, False)

        return _NS()

    @pytest.mark.asyncio
    async def test_send_called_on_first_attempt(self):
        """On new transition, send_alert is called exactly once."""
        from app.services.monitors.hitl_2fa import Hitl2faEntryMonitor

        monitor = Hitl2faEntryMonitor()
        registry = self._make_registry_stub()

        call_count = 0

        class _NS:
            class config:
                channel = "ntfy"
                enabled = True

            def is_event_enabled(self_, event_type: str) -> bool:
                return True

            async def send_alert(self_, **kwargs) -> bool:
                nonlocal call_count
                call_count += 1
                return True

        ns = _NS()

        # Tick 1 — no history yet → init run, no alerts.
        alerts = await monitor.check(registry, ns)
        assert alerts == []
        assert call_count == 0

        # Transition happens between ticks.
        registry.advance()

        # Tick 2 — HITL transition now visible → fires the send.
        alerts = await monitor.check(registry, ns)
        assert alerts == []  # we drive sends ourselves; nothing returned
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retry_on_send_failure(self):
        """If send fails on first attempt, retries on next tick (with default retries=1)."""
        from app.services.monitors.hitl_2fa import Hitl2faEntryMonitor

        monitor = Hitl2faEntryMonitor()
        registry = self._make_registry_stub()

        send_results = [False, True]  # fail once, succeed on retry
        call_count = 0

        class _NS:
            class config:
                channel = "ntfy"
                enabled = True

            def is_event_enabled(self_, event_type: str) -> bool:
                return True

            async def send_alert(self_, **kwargs) -> bool:
                nonlocal call_count
                call_count += 1
                return send_results[call_count - 1]

        ns = _NS()

        with patch.dict(os.environ, {"IBCTL_TWOFA_NTFY_SEND_RETRIES": "1"}):
            # Tick 1: initialise — no transition yet.
            await monitor.check(registry, ns)
            assert call_count == 0

            # Transition happens.
            registry.advance()

            # Tick 2: first attempt — fails.
            await monitor.check(registry, ns)
            assert call_count == 1
            assert monitor._send_succeeded.get("paper") is False
            assert monitor._send_retries_remaining.get("paper") == 1

            # Tick 3: retry — succeeds.
            await monitor.check(registry, ns)
            assert call_count == 2
            assert monitor._send_succeeded.get("paper") is True
            assert monitor._send_retries_remaining.get("paper") == 0

    @pytest.mark.asyncio
    async def test_no_retry_after_success(self):
        """Once send succeeds, no further sends are made on subsequent ticks."""
        from app.services.monitors.hitl_2fa import Hitl2faEntryMonitor

        monitor = Hitl2faEntryMonitor()
        registry = self._make_registry_stub()
        call_count = 0

        class _NS:
            class config:
                channel = "ntfy"
                enabled = True

            def is_event_enabled(self_, event_type: str) -> bool:
                return True

            async def send_alert(self_, **kwargs) -> bool:
                nonlocal call_count
                call_count += 1
                return True

        ns = _NS()

        with patch.dict(os.environ, {"IBCTL_TWOFA_NTFY_SEND_RETRIES": "2"}):
            await monitor.check(registry, ns)   # tick 1: init
            registry.advance()                   # transition happens
            await monitor.check(registry, ns)   # tick 2: fires — succeeds
            assert call_count == 1
            await monitor.check(registry, ns)   # tick 3: should NOT re-send
            await monitor.check(registry, ns)   # tick 4: still should not
            assert call_count == 1  # still 1

    @pytest.mark.asyncio
    async def test_retry_exhausted_stops_sending(self):
        """After retries are exhausted, no more sends even if still in HITL."""
        from app.services.monitors.hitl_2fa import Hitl2faEntryMonitor

        monitor = Hitl2faEntryMonitor()
        registry = self._make_registry_stub()
        call_count = 0

        class _NS:
            class config:
                channel = "ntfy"
                enabled = True

            def is_event_enabled(self_, event_type: str) -> bool:
                return True

            async def send_alert(self_, **kwargs) -> bool:
                nonlocal call_count
                call_count += 1
                return False  # always fail

        ns = _NS()

        with patch.dict(os.environ, {"IBCTL_TWOFA_NTFY_SEND_RETRIES": "1"}):
            await monitor.check(registry, ns)   # tick 1: init
            registry.advance()                   # transition happens
            await monitor.check(registry, ns)   # tick 2: attempt 1 — fails, 1 retry remaining
            assert call_count == 1
            await monitor.check(registry, ns)   # tick 3: retry 1 — fails, 0 remaining
            assert call_count == 2
            await monitor.check(registry, ns)   # tick 4: exhausted — no more sends
            await monitor.check(registry, ns)   # tick 5: still exhausted
            assert call_count == 2  # still 2


# ---------------------------------------------------------------------------
# Item 10: dashboard base URL fallback chain
# ---------------------------------------------------------------------------


class TestDashboardBaseUrlFallback:
    """The _resolve_dashboard_base_url helper picks the right URL source."""

    def test_external_url_takes_precedence(self):
        from app.services.monitors.hitl_2fa import _resolve_dashboard_base_url

        with patch.dict(
            os.environ,
            {
                "IBCTL_DASHBOARD_EXTERNAL_URL": "https://ibctl.example.com",
                "IBCTL_DASHBOARD_INTERNAL_URL": "http://internal:8080",
                "IBCTL_DASHBOARD_PORT": "9999",
            },
            clear=False,
        ):
            base, is_fallback = _resolve_dashboard_base_url()
            assert base == "https://ibctl.example.com"
            assert is_fallback is False

    def test_strips_trailing_slash_on_external(self):
        from app.services.monitors.hitl_2fa import _resolve_dashboard_base_url

        with patch.dict(
            os.environ,
            {"IBCTL_DASHBOARD_EXTERNAL_URL": "https://ibctl.example.com/"},
            clear=False,
        ):
            # Clear the others so the external path is isolated.
            os.environ.pop("IBCTL_DASHBOARD_INTERNAL_URL", None)
            base, is_fallback = _resolve_dashboard_base_url()
            assert base == "https://ibctl.example.com"
            assert is_fallback is False

    def test_internal_fallback_when_external_unset(self):
        from app.services.monitors.hitl_2fa import _resolve_dashboard_base_url

        with patch.dict(
            os.environ,
            {"IBCTL_DASHBOARD_INTERNAL_URL": "http://internal:8080"},
            clear=False,
        ):
            os.environ.pop("IBCTL_DASHBOARD_EXTERNAL_URL", None)
            base, is_fallback = _resolve_dashboard_base_url()
            assert base == "http://internal:8080"
            assert is_fallback is True

    def test_localhost_fallback_when_neither_url_set(self):
        from app.services.monitors.hitl_2fa import _resolve_dashboard_base_url

        with patch.dict(os.environ, {"IBCTL_DASHBOARD_PORT": "9090"}, clear=False):
            os.environ.pop("IBCTL_DASHBOARD_EXTERNAL_URL", None)
            os.environ.pop("IBCTL_DASHBOARD_INTERNAL_URL", None)
            base, is_fallback = _resolve_dashboard_base_url()
            assert base == "http://localhost:9090"
            assert is_fallback is True

    def test_localhost_fallback_default_port_when_unset(self):
        from app.services.monitors.hitl_2fa import _resolve_dashboard_base_url

        os.environ.pop("IBCTL_DASHBOARD_EXTERNAL_URL", None)
        os.environ.pop("IBCTL_DASHBOARD_INTERNAL_URL", None)
        os.environ.pop("IBCTL_DASHBOARD_PORT", None)
        base, is_fallback = _resolve_dashboard_base_url()
        assert base == "http://localhost:8080"
        assert is_fallback is True

    def test_empty_string_env_vars_fall_through(self):
        """Empty/whitespace env values should not short-circuit the fallback."""
        from app.services.monitors.hitl_2fa import _resolve_dashboard_base_url

        with patch.dict(
            os.environ,
            {
                "IBCTL_DASHBOARD_EXTERNAL_URL": "   ",
                "IBCTL_DASHBOARD_INTERNAL_URL": "",
                "IBCTL_DASHBOARD_PORT": "7777",
            },
            clear=False,
        ):
            base, is_fallback = _resolve_dashboard_base_url()
            assert base == "http://localhost:7777"
            assert is_fallback is True
