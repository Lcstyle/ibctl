"""RED-phase tests for the extracted `callback_common` module.

Stage 5 of PR-C introduces a second HMAC-signed ntfy callback (reconnect
give-up resume) that mirrors the HITL 2FA callback. Rather than duplicating
the rate limiter, the dashboard-base-URL resolver, and the confirmation
HTML template, all three are lifted out of `app.api.twofa` /
`app.services.monitors.hitl_2fa` into a shared `app.services.callback_common`
module.

These tests specify the extracted module's public surface:

  - `resolve_dashboard_base_url() -> tuple[str, bool]`
  - `confirmation_html(mode: str, *, action_label: str) -> str`
  - `RateLimiter(window_secs, max_requests)` with `.check(ip) -> bool`

They are written BEFORE the module exists, so all imports here will fail
until the extraction is done. That is the RED signal we want.
"""

from __future__ import annotations

import os
import time
from unittest.mock import patch


class TestResolveDashboardBaseUrlEnvPrecedence:
    """External URL > internal URL > localhost fallback. Same semantics as
    the current `hitl_2fa._resolve_dashboard_base_url` but under the new
    module path."""

    def test_callback_common_resolve_dashboard_base_url_env_precedence(self):
        from app.services.callback_common import resolve_dashboard_base_url

        # 1. IBCTL_DASHBOARD_EXTERNAL_URL wins outright.
        with patch.dict(
            os.environ,
            {
                "IBCTL_DASHBOARD_EXTERNAL_URL": "https://ibctl.example.com/",
                "IBCTL_DASHBOARD_INTERNAL_URL": "http://internal:8080",
                "IBCTL_DASHBOARD_PORT": "9999",
            },
            clear=False,
        ):
            base, is_fallback = resolve_dashboard_base_url()
            assert base == "https://ibctl.example.com"  # trailing / stripped
            assert is_fallback is False

        # 2. With external unset, internal is used (but flagged as fallback).
        with patch.dict(
            os.environ,
            {"IBCTL_DASHBOARD_INTERNAL_URL": "http://internal:8080"},
            clear=False,
        ):
            os.environ.pop("IBCTL_DASHBOARD_EXTERNAL_URL", None)
            base, is_fallback = resolve_dashboard_base_url()
            assert base == "http://internal:8080"
            assert is_fallback is True

        # 3. With neither set, http://localhost:<port> is constructed.
        with patch.dict(os.environ, {"IBCTL_DASHBOARD_PORT": "9090"}, clear=False):
            os.environ.pop("IBCTL_DASHBOARD_EXTERNAL_URL", None)
            os.environ.pop("IBCTL_DASHBOARD_INTERNAL_URL", None)
            base, is_fallback = resolve_dashboard_base_url()
            assert base == "http://localhost:9090"
            assert is_fallback is True


class TestConfirmationHtmlRendersMode:
    """The confirmation HTML template accepts an `action_label` param so the
    HITL flow can say 'Retry triggered' and the reconnect flow can say
    'Reconnect resumed' — same page skeleton, different heading."""

    def test_callback_common_confirmation_html_renders_mode(self):
        from app.services.callback_common import confirmation_html

        html = confirmation_html("live", action_label="Retry triggered")

        # Contains the mode uppercased.
        assert "LIVE" in html
        # Contains the action label.
        assert "Retry triggered" in html
        # It's a full HTML document.
        assert html.lstrip().lower().startswith("<!doctype html>")
        assert "</html>" in html

        # And it's escaping-safe: if the mode were an XSS attempt, it must
        # not surface unescaped tags.
        evil = confirmation_html("<script>alert(1)</script>", action_label="ok")
        assert "<script>" not in evil
        assert "&lt;script&gt;" in evil.lower() or "&lt;SCRIPT&gt;" in evil


class TestRateLimiterSecondWithinWindow:
    """The shared limiter is a stateful object so HITL and reconnect can
    have INDEPENDENT counters — a 2FA burst must not lock out a legitimate
    reconnect resume. The instance owns its own IP table."""

    def test_callback_common_rate_limiter_second_within_window(self):
        from app.services.callback_common import RateLimiter

        # 3 requests / 60s window — tight enough to test cheaply.
        limiter = RateLimiter(window_secs=60.0, max_requests=3)

        # First three pass, fourth is rejected — same IP, same window.
        assert limiter.check("10.0.0.1") is True
        assert limiter.check("10.0.0.1") is True
        assert limiter.check("10.0.0.1") is True
        assert limiter.check("10.0.0.1") is False

        # A different IP has its own bucket — not affected by the above.
        assert limiter.check("10.0.0.2") is True

        # A separate limiter instance shares no state (independent counters).
        other = RateLimiter(window_secs=60.0, max_requests=3)
        assert other.check("10.0.0.1") is True
        assert other.check("10.0.0.1") is True
        assert other.check("10.0.0.1") is True
        assert other.check("10.0.0.1") is False

    def test_callback_common_rate_limiter_window_expiry(self):
        """Timestamps older than `window_secs` fall out of the bucket."""
        from app.services.callback_common import RateLimiter

        limiter = RateLimiter(window_secs=60.0, max_requests=2)

        # Manually seed the limiter's internal state with stale timestamps
        # from >60s ago. The next .check() call should sweep them and allow
        # the request through.
        stale = time.time() - 120.0
        # The internal table is exposed as `_ip_timestamps` (mirroring the
        # current twofa module) so the extraction test can reach in.
        from collections import deque

        limiter._ip_timestamps["10.0.0.9"] = deque([stale, stale])

        # Fresh request after expiry should be allowed.
        assert limiter.check("10.0.0.9") is True
