"""Tests for the reconnect give-up resume callback endpoint.

Stage 5 of PR-C adds a signed ntfy action callback that mirrors the HITL
2FA callback: an operator taps a link in the give-up alert, the dashboard
verifies the HMAC signature + intent + mode and forwards
``RESUME_RECONNECT <token>`` to the correct ibctl instance.

Split-flow (finding A-HIGH-1): GET renders a confirmation prompt with no
side effect; POST is what actually dispatches ``RESUME_RECONNECT``. Link-
preview crawlers, URL-defense scanners, and mobile "prefetch links"
features follow GETs but almost never POSTs, so the one-shot token can't
be auto-consumed by a non-operator client.

Mirrors ``tests/test_twofa.py`` conventions:
  - ``callback_client`` fixture with FakeIbctlClient wired into the registry
  - ``reset_reconnect_rate_limiter`` clears per-endpoint limiter state
  - HTTP status codes are the primary observable
  - The confirmation HTML page contains the mode and a mode-agnostic label
"""

from __future__ import annotations

import logging
import os
import time
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import DashboardSettings
from app.domain.errors import DashboardError
from app.main import create_app
from app.services import hitl_tokens

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

SIGNING_KEY = "test-signing-key-for-reconnect-tests"


# ---------------------------------------------------------------------------
# Token helpers (independent of module-under-test so they still work if the
# reconnect_tokens surface is renamed during GREEN implementation)
# ---------------------------------------------------------------------------


def _mint_reconnect_token(mode: str = "paper", valid_hours: int = 12) -> str:
    """Mint a valid v2 reconnect-intent token via the shared hitl_tokens API.

    Once ``app.services.reconnect_tokens.mint_token`` exists it should
    delegate to this same underlying function with intent="reconnect", so
    tokens minted either way are indistinguishable on the wire.
    """
    from app.services import reconnect_tokens  # noqa: F401  (RED import guard)

    return reconnect_tokens.mint_token(SIGNING_KEY, mode, valid_hours)


def _mint_hitl_token(mode: str = "paper", valid_hours: int = 12) -> str:
    """Mint an intent=hitl token — used to verify wrong-intent rejection."""
    return hitl_tokens.mint_token(SIGNING_KEY, mode, valid_hours, intent="hitl")


def _mint_expired_reconnect_token(mode: str = "paper") -> str:
    """Build a v2 reconnect token whose expires is 12h in the past."""
    from app.services.hitl_tokens import _sign

    issued = int(time.time()) - 48 * 3600
    expires = issued + 12 * 3600  # still 36h in the past
    prefix = f"v2.reconnect.{issued}.{expires}.{mode.lower()}"
    sig = _sign(SIGNING_KEY, prefix)
    return f"{prefix}.{sig}"


def _mint_wrong_signature_reconnect_token(mode: str = "paper") -> str:
    """Mint a token signed with the WRONG signing key."""
    from app.services import reconnect_tokens  # noqa: F401  (RED import guard)

    return reconnect_tokens.mint_token("some-other-key", mode, 12)


# ---------------------------------------------------------------------------
# App / fixture helpers
# ---------------------------------------------------------------------------


def _make_app(trading_mode: str = "both"):
    """Build a test app. trading_mode='both' → both live+paper registered."""
    settings = DashboardSettings(
        port=8080,
        token="",
        debug_mode=False,
        ibctl_host="127.0.0.1",
        ibctl_port=7462,
        trading_mode=trading_mode,
        ibctl_paper_host="127.0.0.1",
        ibctl_paper_port=7463,
    )
    return create_app(settings=settings)


@pytest.fixture
def reset_reconnect_rate_limiter():
    """Clear the per-endpoint limiter's IP timestamps + used-token cache
    before/after each test.

    The reconnect callback owns its own ``RateLimiter`` instance
    (independent of the HITL limiter — a 2FA burst must not lock out a
    legitimate reconnect resume). The instance is stored on
    ``app.api.reconnect._rate_limiter``. The replay-defence used-token
    cache is at ``app.api.reconnect._used_token_cache`` — clearing it too
    ensures a test that repeats a request via POST doesn't get a spurious
    "replay" rejection from a previous test's leftover state.
    """
    import app.api.reconnect as reconnect_mod

    reconnect_mod._rate_limiter._ip_timestamps.clear()
    reconnect_mod._used_token_cache.clear()
    yield
    reconnect_mod._rate_limiter._ip_timestamps.clear()
    reconnect_mod._used_token_cache.clear()


@pytest.fixture
async def callback_client(fake_client):
    """HTTP test client with fake ibctl backend + signing key in env.

    Mirrors ``test_twofa.callback_client``: seeds the registry cache so
    cache-first endpoints work, then patches
    ``IBCTL_NTFY_ACTION_SIGNING_KEY`` for the duration of the request.
    """
    app = _make_app()
    app.state.ibctl_client = fake_client
    registry = app.state.instance_registry
    for mode in registry.modes():
        registry._clients[mode] = fake_client

    from dataclasses import asdict
    from app.instance_registry import _CachedResponse
    status_dict = asdict(fake_client._status)
    for mode in registry.modes():
        registry._cache[f"{mode}:STATUS"] = _CachedResponse(
            status_dict, registry.STATUS_TTL
        )

    transport = ASGITransport(app=app)
    with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c


@pytest.fixture
async def live_only_callback_client(fake_client):
    """Single-mode (live) callback client — used to prove ``mode=paper``
    hits the ``no_instance`` (KeyError → 403) branch (finding C-MED-3)."""
    app = _make_app(trading_mode="live")
    registry = app.state.instance_registry
    for mode in registry.modes():
        registry._clients[mode] = fake_client
    from dataclasses import asdict
    from app.instance_registry import _CachedResponse
    status_dict = asdict(fake_client._status)
    for mode in registry.modes():
        registry._cache[f"{mode}:STATUS"] = _CachedResponse(
            status_dict, registry.STATUS_TTL
        )
    transport = ASGITransport(app=app)
    with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c


# ---------------------------------------------------------------------------
# GET endpoint — renders the confirmation prompt (no side effect)
# ---------------------------------------------------------------------------


class TestReconnectCallbackPromptGet:
    """GET /api/reconnect/callback — idempotent confirmation prompt.

    Under the split-flow design (finding A-HIGH-1), GET must NEVER
    dispatch RESUME_RECONNECT. A link-preview crawler / URL-defense
    scanner / mobile prefetch that follows the ntfy URL must not
    auto-consume the one-shot token.
    """

    @pytest.mark.asyncio
    async def test_get_valid_token_renders_prompt_without_dispatch(
        self, callback_client, reset_reconnect_rate_limiter, fake_client
    ):
        """GET with a valid token → 200 confirmation prompt, NO dispatch."""
        token = _mint_reconnect_token("paper")
        resp = await callback_client.get(
            f"/api/reconnect/callback?t={token}&mode=paper"
        )
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        body = resp.text
        # The confirmation prompt must contain a POST form so the dispatch
        # requires an explicit click. The hidden token field carries the
        # token verbatim through the browser to the POST handler.
        assert 'method="POST"' in body or "method='POST'" in body.lower()
        assert 'name="t"' in body
        assert 'name="mode"' in body
        # CRITICAL: the GET must NOT have dispatched — the fake client's
        # last_command must still be None (or unchanged from before).
        assert fake_client._last_command is None, (
            "GET rendered a confirmation prompt but MUST NOT have dispatched"
        )

    @pytest.mark.asyncio
    async def test_get_bad_signature_returns_403(
        self, callback_client, reset_reconnect_rate_limiter
    ):
        """A token signed with the wrong key → 403 on GET too."""
        token = _mint_wrong_signature_reconnect_token("paper")
        resp = await callback_client.get(
            f"/api/reconnect/callback?t={token}&mode=paper"
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_get_expired_token_returns_403(
        self, callback_client, reset_reconnect_rate_limiter
    ):
        """A well-signed but expired token → 403 with expiry as the reason."""
        token = _mint_expired_reconnect_token("paper")
        resp = await callback_client.get(
            f"/api/reconnect/callback?t={token}&mode=paper"
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_get_wrong_intent_hitl_token_rejected_as_403(
        self, callback_client, reset_reconnect_rate_limiter
    ):
        """Sending an intent=hitl token to /api/reconnect/callback → 403.

        Cross-flow replay defence. The v2 token format binds an ``intent``
        field so a valid HITL 2FA callback token cannot be redirected at
        the reconnect endpoint (or vice versa).
        """
        token = _mint_hitl_token("paper")
        resp = await callback_client.get(
            f"/api/reconnect/callback?t={token}&mode=paper"
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_get_mode_mismatch_returns_403(
        self, callback_client, reset_reconnect_rate_limiter
    ):
        """Token minted for paper + ``?mode=live`` URL → 403."""
        token = _mint_reconnect_token("paper")
        resp = await callback_client.get(
            f"/api/reconnect/callback?t={token}&mode=live"
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST endpoint — dispatches RESUME_RECONNECT
# ---------------------------------------------------------------------------


class TestReconnectCallbackDispatchPost:
    """POST /api/reconnect/callback — validated dispatch."""

    @pytest.mark.asyncio
    async def test_post_valid_token_dispatches_resume_reconnect(
        self, callback_client, reset_reconnect_rate_limiter, fake_client
    ):
        """A valid v2 reconnect token → RESUME_RECONNECT <token> dispatched."""
        token = _mint_reconnect_token("paper")
        resp = await callback_client.post(
            "/api/reconnect/callback",
            data={"t": token, "mode": "paper"},
        )
        assert resp.status_code == 200
        assert fake_client._last_command is not None
        assert fake_client._last_command.startswith("RESUME_RECONNECT ")
        assert token in fake_client._last_command

    @pytest.mark.asyncio
    async def test_post_bad_signature_returns_403(
        self, callback_client, reset_reconnect_rate_limiter, fake_client
    ):
        """Bad signature via POST → 403, no dispatch."""
        token = _mint_wrong_signature_reconnect_token("paper")
        resp = await callback_client.post(
            "/api/reconnect/callback",
            data={"t": token, "mode": "paper"},
        )
        assert resp.status_code == 403
        assert fake_client._last_command is None

    @pytest.mark.asyncio
    async def test_post_expired_token_returns_403(
        self, callback_client, reset_reconnect_rate_limiter, fake_client
    ):
        """Expired token via POST → 403, no dispatch."""
        token = _mint_expired_reconnect_token("paper")
        resp = await callback_client.post(
            "/api/reconnect/callback",
            data={"t": token, "mode": "paper"},
        )
        assert resp.status_code == 403
        assert fake_client._last_command is None

    @pytest.mark.asyncio
    async def test_post_wrong_intent_hitl_token_rejected(
        self, callback_client, reset_reconnect_rate_limiter, fake_client
    ):
        """HITL-intent token POSTed to reconnect endpoint → 403."""
        token = _mint_hitl_token("paper")
        resp = await callback_client.post(
            "/api/reconnect/callback",
            data={"t": token, "mode": "paper"},
        )
        assert resp.status_code == 403
        assert fake_client._last_command is None

    @pytest.mark.asyncio
    async def test_post_missing_signing_key_returns_500(
        self, client, reset_reconnect_rate_limiter, fake_client
    ):
        """Without IBCTL_NTFY_ACTION_SIGNING_KEY the endpoint returns 500."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IBCTL_NTFY_ACTION_SIGNING_KEY", None)
            resp = await client.post(
                "/api/reconnect/callback",
                data={"t": "whatever", "mode": "paper"},
            )
        assert resp.status_code == 500
        assert fake_client._last_command is None

    @pytest.mark.asyncio
    async def test_post_mode_mismatch_returns_403(
        self, callback_client, reset_reconnect_rate_limiter, fake_client
    ):
        """Token minted for paper + form ``mode=live`` → 403, no dispatch."""
        token = _mint_reconnect_token("paper")
        resp = await callback_client.post(
            "/api/reconnect/callback",
            data={"t": token, "mode": "live"},
        )
        assert resp.status_code == 403
        assert fake_client._last_command is None

    @pytest.mark.asyncio
    async def test_post_ibctl_daemon_rejects_returns_502(
        self, callback_client, reset_reconnect_rate_limiter, fake_client
    ):
        """DashboardError from send_command → 502 ibctl_unreachable."""
        async def rejecting_send_command(command: str) -> str:
            raise DashboardError("ibctl daemon does not support reconnect resume")

        fake_client.send_command = rejecting_send_command
        token = _mint_reconnect_token("paper")
        resp = await callback_client.post(
            "/api/reconnect/callback",
            data={"t": token, "mode": "paper"},
        )
        assert resp.status_code == 502
        assert resp.json()["error"] == "ibctl_unreachable"

    @pytest.mark.asyncio
    async def test_post_non_dashboard_exception_maps_to_502(
        self, callback_client, reset_reconnect_rate_limiter, fake_client
    ):
        """A non-DashboardError exception must NOT surface as a bare 500.

        Finding A-MED-4: if send_command raises TimeoutError /
        ConnectionRefusedError / OSError / RuntimeError / etc., the
        operator's browser should see a structured 502 payload with a
        distinguishable error key rather than a blank error page.
        """
        async def timing_out_send_command(command: str) -> str:
            raise TimeoutError("nc socket vanished")

        fake_client.send_command = timing_out_send_command
        token = _mint_reconnect_token("paper")
        resp = await callback_client.post(
            "/api/reconnect/callback",
            data={"t": token, "mode": "paper"},
        )
        assert resp.status_code == 502
        payload = resp.json()
        assert payload["error"] == "ibctl_dispatch_failed"
        assert payload["detail"] == "TimeoutError"

    @pytest.mark.asyncio
    async def test_post_ibctl_returns_nack_maps_to_502(
        self, callback_client, reset_reconnect_rate_limiter, fake_client
    ):
        """ibctl returning an ERROR-shaped string → 502 ibctl_command_rejected.

        Finding A-MED-5: silently rendering "Reconnect resumed" while the
        daemon returned "ERROR: not in given_up phase" would leave the
        operator believing the resume happened. The endpoint inspects the
        result for known NACK sentinels and returns a distinct error.
        """
        async def nack_send_command(command: str) -> str:
            return "ERROR: not in given_up phase"

        fake_client.send_command = nack_send_command
        token = _mint_reconnect_token("paper")
        resp = await callback_client.post(
            "/api/reconnect/callback",
            data={"t": token, "mode": "paper"},
        )
        assert resp.status_code == 502
        assert resp.json()["error"] == "ibctl_command_rejected"

    @pytest.mark.asyncio
    async def test_post_returns_html_confirmation_page(
        self, callback_client, reset_reconnect_rate_limiter
    ):
        """POST 200 body is HTML containing the mode + a reconnect-flavour label."""
        token = _mint_reconnect_token("live")
        resp = await callback_client.post(
            "/api/reconnect/callback",
            data={"t": token, "mode": "live"},
        )
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        body = resp.text
        assert "LIVE" in body
        assert "reconnect" in body.lower() or "resumed" in body.lower()

    @pytest.mark.asyncio
    async def test_post_wire_format_is_single_space_separator(
        self, callback_client, reset_reconnect_rate_limiter, fake_client
    ):
        """RESUME_RECONNECT<0x20>token — pins the ASCII space wire format.

        Finding C-HIGH-2: the Rust parser at ``command_server.rs:83`` uses
        ``splitn(2, ' ')``. Any other whitespace character (tab, newline,
        non-breaking space) would leak into the token and fail re-
        verification. This test pins the ASCII space at the byte level so
        a future refactor that "improves" the format catches the wire
        break BEFORE it hits an ibctl deploy.
        """
        token = _mint_reconnect_token("paper")
        resp = await callback_client.post(
            "/api/reconnect/callback",
            data={"t": token, "mode": "paper"},
        )
        assert resp.status_code == 200
        cmd = fake_client._last_command
        assert cmd is not None
        # Must start with the exact 17-byte prefix — 16 chars + 1 space.
        # Not a tab (\x09), not a newline (\x0A), not NBSP (\xC2\xA0).
        expected_prefix = "RESUME_RECONNECT "  # trailing 0x20
        assert cmd.startswith(expected_prefix)
        assert cmd[16] == " ", (
            f"delimiter must be ASCII 0x20; got {ord(cmd[16]):#x}"
        )
        # Guard against tab / newline / carriage return anywhere between
        # the sentinel and the token.
        for bad in ("\t", "\n", "\r"):
            assert bad not in cmd[:17], (
                f"wire format must not contain {bad!r}"
            )
        # The token itself must be the exact bytes we minted.
        assert cmd == expected_prefix + token


# ---------------------------------------------------------------------------
# Replay defence + branch coverage
# ---------------------------------------------------------------------------


class TestReconnectCallbackReplayAndBranches:
    """Additional branches surfaced by the review (findings A-MED-3, C-MED-3)."""

    @pytest.mark.asyncio
    async def test_second_post_of_same_token_is_replay(
        self, callback_client, reset_reconnect_rate_limiter, fake_client
    ):
        """A second POST with the same token → 403 replay (finding A-MED-3).

        The dashboard-side used-token cache closes the replay window that
        would otherwise re-open every time ibctl warm-restarts. First POST
        succeeds; the identical second POST returns 403 with
        ``reason=replay``.
        """
        token = _mint_reconnect_token("paper")
        first = await callback_client.post(
            "/api/reconnect/callback",
            data={"t": token, "mode": "paper"},
        )
        assert first.status_code == 200

        # Second POST — same token, same everything.
        second = await callback_client.post(
            "/api/reconnect/callback",
            data={"t": token, "mode": "paper"},
        )
        assert second.status_code == 403
        payload = second.json()
        assert payload["error"] == "invalid_token"
        assert payload["reason"] == "replay"

    @pytest.mark.asyncio
    async def test_post_paper_mode_on_live_only_deploy_returns_403(
        self, live_only_callback_client, reset_reconnect_rate_limiter, fake_client
    ):
        """A trading_mode='live' deploy rejects mode=paper via KeyError branch.

        Finding C-MED-3: the KeyError → 403 ``no_instance`` path was
        unreachable under trading_mode=both. This test builds a single-
        mode app and hits it with the OTHER mode to pin the branch.
        """
        token = _mint_reconnect_token("paper")
        resp = await live_only_callback_client.post(
            "/api/reconnect/callback",
            data={"t": token, "mode": "paper"},
        )
        assert resp.status_code == 403
        assert resp.json()["error"] == "invalid_mode"
        # No dispatch either.
        assert fake_client._last_command is None


# ---------------------------------------------------------------------------
# Rate-limit + recovery + structured logs
# ---------------------------------------------------------------------------


class TestReconnectRateLimitAndLogs:
    """Rate-limit windowing + operator-facing structured log surface."""

    @pytest.mark.asyncio
    async def test_get_rate_limited_returns_429(
        self, callback_client, reset_reconnect_rate_limiter
    ):
        """More than 10 GETs / min from the same IP → 429.

        Rate-limit applies to both GET and POST so a link-preview flood
        still counts against the budget and a would-be attacker can't
        squeeze the operator out of a POST slot by hammering GETs.
        """
        token = _mint_reconnect_token("paper")
        url = f"/api/reconnect/callback?t={token}&mode=paper"

        responses: list[int] = []
        for _ in range(11):
            resp = await callback_client.get(url)
            responses.append(resp.status_code)

        for i, code in enumerate(responses[:10]):
            assert code != 429, f"Request {i + 1} was unexpectedly rate-limited"

        assert responses[10] == 429
        payload = (await callback_client.get(url)).json()
        assert payload == {"error": "rate_limited"}

    @pytest.mark.asyncio
    async def test_rate_limit_resets_after_window(
        self, callback_client, reset_reconnect_rate_limiter
    ):
        """After filling the window, old timestamps expire and new requests pass.

        Finding C-LOW-7: symmetric with HITL's
        ``test_rate_limit_resets_after_window`` — the class-level unit
        test in test_callback_common only proves the RateLimiter class
        expires stale entries; this test proves the reconnect endpoint
        actually consults ``check()`` (a wiring bug that flipped the
        boolean would break this at the endpoint layer).
        """
        import app.api.reconnect as reconnect_mod
        from collections import deque

        token = _mint_reconnect_token("paper")
        url = f"/api/reconnect/callback?t={token}&mode=paper"

        # Fill the bucket with 10 fake timestamps just older than the window.
        past = time.time() - reconnect_mod._RATE_LIMIT_WINDOW_SECS - 1.0
        reconnect_mod._rate_limiter._ip_timestamps["testclient"] = deque([past] * 10)

        # A new request should pass — the stale entries sweep on first call.
        resp = await callback_client.get(url)
        assert resp.status_code != 429

    @pytest.mark.asyncio
    async def test_accept_log_has_stable_keys_and_no_token(
        self, callback_client, reset_reconnect_rate_limiter, caplog
    ):
        """On accept, the structured log emits ``recovery.callback.received``
        and ``recovery.callback.accepted`` with stable prefixes — and does
        NOT contain the full token (finding C-MED-5)."""
        token = _mint_reconnect_token("paper")
        with caplog.at_level(logging.INFO, logger="dashboard.api.reconnect"):
            resp = await callback_client.post(
                "/api/reconnect/callback",
                data={"t": token, "mode": "paper"},
            )
        assert resp.status_code == 200
        merged = "\n".join(r.getMessage() for r in caplog.records)
        assert "recovery.callback.received" in merged
        assert "recovery.callback.accepted" in merged
        # Full token must NEVER appear in logs — the token prefix (8 chars)
        # is fine but the whole HMAC blob would be a leak.
        assert token not in merged, (
            "structured log leaked the full callback token"
        )

    @pytest.mark.asyncio
    async def test_reject_log_carries_stable_reason_field(
        self, callback_client, reset_reconnect_rate_limiter, caplog
    ):
        """The ``reason=…`` field on rejection logs must remain stable so
        ops filters (``journalctl | grep 'reason=rate_limited'``) don't
        silently stop matching (finding C-MED-5)."""
        # Bad signature → reason=bad_signature
        token = _mint_wrong_signature_reconnect_token("paper")
        with caplog.at_level(logging.WARNING, logger="dashboard.api.reconnect"):
            resp = await callback_client.post(
                "/api/reconnect/callback",
                data={"t": token, "mode": "paper"},
            )
        assert resp.status_code == 403
        merged = "\n".join(r.getMessage() for r in caplog.records)
        assert "recovery.callback.rejected" in merged
        assert "reason=" in merged
        assert "bad_signature" in merged

    @pytest.mark.asyncio
    async def test_dispatch_error_detail_sanitizes_embedded_token(
        self, callback_client, reset_reconnect_rate_limiter, fake_client
    ):
        """Finding A-LOW-7: a DashboardError whose message contains the
        outbound token must not leak the token to the browser."""
        token = _mint_reconnect_token("paper")

        async def leaky_send_command(command: str) -> str:
            # Simulate a downstream layer that includes the outbound
            # command in the exception message.
            raise DashboardError(f"send failed for command: {command}")

        fake_client.send_command = leaky_send_command
        resp = await callback_client.post(
            "/api/reconnect/callback",
            data={"t": token, "mode": "paper"},
        )
        assert resp.status_code == 502
        payload = resp.json()
        # The response's `detail` MUST NOT contain the full token.
        detail = payload.get("detail", "")
        assert token not in detail, (
            f"error detail leaked full token: {detail!r}"
        )
