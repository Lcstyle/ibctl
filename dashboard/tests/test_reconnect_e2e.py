"""End-to-end wire test for the reconnect give-up flow (finding C-MED-6).

All existing tests mock the boundary immediately below themselves:
  - Monitor tests mock ``ns.send_alert`` (never a real HTTP call).
  - Callback tests mock ``client.send_command`` (never a real TCP write).

The gap: no single failing test would reveal a subtle contract drift
between the monitor's URL construction and the callback endpoint's
validation — for example if the monitor started passing
``expected_intent="hitl"`` while the callback still expected
``"reconnect"``, the reconnect happy path would silently break.

This test wires the monitor's minted URL through an ASGI HTTP transport
back into the callback endpoint of the same app. It catches:
  - intent mismatch
  - mode mismatch
  - token corruption in URL construction
  - wire-format drift (the RESUME_RECONNECT<space><token> shape)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import DashboardSettings
from app.main import create_app

SIGNING_KEY = "test-signing-key-for-e2e"


# ---------------------------------------------------------------------------
# Test doubles (kept independent of test_reconnect_giveup_monitor's stubs to
# avoid a cross-file import chain — mirrors the twofa E2E convention)
# ---------------------------------------------------------------------------


@dataclass
class _CapturedAlert:
    event_type: str
    title: str
    body: str
    priority: str
    tags: str
    actions: list[dict] | None
    force: bool
    kind: str | None


class _NSStub:
    class config:
        channel = "ntfy"
        enabled = True

    def __init__(self):
        self.calls: list[_CapturedAlert] = []

    def is_event_enabled(self, event_type):
        return True

    async def send_alert(self, **kwargs):
        self.calls.append(
            _CapturedAlert(
                event_type=kwargs.get("event_type", ""),
                title=kwargs.get("title", ""),
                body=kwargs.get("body", ""),
                priority=kwargs.get("priority", "default"),
                tags=kwargs.get("tags", ""),
                actions=kwargs.get("actions"),
                force=kwargs.get("force", False),
                kind=kwargs.get("kind"),
            )
        )
        return True


class _RegistryStub:
    def __init__(self, status_by_mode):
        self._status = dict(status_by_mode)

    def modes(self):
        return list(self._status.keys())

    def cached_status_raw(self, mode):
        return self._status.get(mode)


def _giveup_status():
    return {
        "recovery": {
            "phase": "given_up",
            "phase_entered_at": "2026-07-11T12:00:00-04:00",
            "giveup_alert_sent_at": None,
            "aggressive_phase_max_secs": 3600,
            "backoff_phase_max_secs": 10800,
            "min_success_dwell_secs": 60,
            "giveup_alert_resend_interval_hours": 6,
        }
    }


def _aggressive_status():
    stat = _giveup_status()
    stat["recovery"]["phase"] = "aggressive"
    return stat


def _make_app():
    settings = DashboardSettings(
        port=8080,
        token="",
        debug_mode=False,
        ibctl_host="127.0.0.1",
        ibctl_port=7462,
        trading_mode="both",
        ibctl_paper_host="127.0.0.1",
        ibctl_paper_port=7463,
    )
    return create_app(settings=settings)


@pytest.mark.asyncio
async def test_monitor_url_dispatches_via_callback():
    """Wires monitor → URL → HTTP POST → callback → RESUME_RECONNECT.

    Catches contract drift across all layers in a single failing test.
    """
    from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor
    from app.services import reconnect_tokens

    monitor = ReconnectGiveUpMonitor()
    ns = _NSStub()

    # Warm-up so cold-boot suppression doesn't skip the first fire.
    with patch.dict(
        os.environ,
        {
            "IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY,
            "IBCTL_DASHBOARD_EXTERNAL_URL": "http://test",
        },
    ):
        await monitor.check(
            _RegistryStub({"paper": _aggressive_status()}), ns,
        )
        # Now fire a fresh give-up for paper.
        registry = _RegistryStub({"paper": _giveup_status()})
        await monitor.check(registry, ns)

    assert len(ns.calls) == 1
    actions = ns.calls[0].actions or []
    assert len(actions) == 1
    url = actions[0]["url"]
    assert url.startswith("http://test/api/reconnect/callback")

    # Extract the token from the URL query string.
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    token = qs["t"][0]
    mode = qs["mode"][0]
    assert mode == "paper"

    # Validate the minted token as a reconnect token — this is a sanity
    # check that the monitor's mint side agrees on the intent boundary.
    valid, reason = reconnect_tokens.validate_token(SIGNING_KEY, token)
    assert valid, f"minted token must self-validate; got reason={reason}"

    # Now drive the URL through HTTP into the callback endpoint via ASGI.
    import app.api.reconnect as reconnect_mod
    reconnect_mod._rate_limiter._ip_timestamps.clear()
    reconnect_mod._used_token_cache.clear()

    from tests.conftest import FakeIbctlClient
    fake_client = FakeIbctlClient()
    app = _make_app()
    app.state.ibctl_client = fake_client
    reg = app.state.instance_registry
    for m in reg.modes():
        reg._clients[m] = fake_client
    from dataclasses import asdict
    from app.instance_registry import _CachedResponse
    status_dict = asdict(fake_client._status)
    for m in reg.modes():
        reg._cache[f"{m}:STATUS"] = _CachedResponse(status_dict, reg.STATUS_TTL)

    transport = ASGITransport(app=app)
    with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
        async with AsyncClient(
            transport=transport, base_url="http://test",
        ) as c:
            # GET first — should render prompt WITHOUT dispatching.
            resp_get = await c.get(parsed.path + "?" + parsed.query)
            assert resp_get.status_code == 200
            assert fake_client._last_command is None, (
                "GET must not dispatch under the split-flow design"
            )

            # POST with the same t + mode — dispatches.
            resp_post = await c.post(
                parsed.path,
                data={"t": token, "mode": mode},
            )
            assert resp_post.status_code == 200

    # Wire format contract: RESUME_RECONNECT<0x20><token>, exact bytes.
    cmd = fake_client._last_command
    assert cmd is not None
    assert cmd == f"RESUME_RECONNECT {token}"
