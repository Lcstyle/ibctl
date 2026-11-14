"""Hitl2faEntryMonitor._build_rich_alert: the ntfy action link it mints must
never expire (see test_hitl_tokens_never_expires.py for the underlying
hitl_tokens mechanism this relies on).
"""

from __future__ import annotations

from app.services import hitl_tokens
from app.services.monitors.hitl_2fa import Hitl2faEntryMonitor

SIGNING_KEY = "test-signing-key-for-hitl-2fa-monitor"
BASE_URL = "https://ibctl.example.com"


class TestBuildRichAlertMintsNeverExpiring:
    def test_action_url_token_never_expires(self):
        mon = Hitl2faEntryMonitor()

        alert = mon._build_rich_alert(
            "live",
            status_raw={"hitl": {"next_retry_in_secs": 300}},
            can_use_action=True,
            signing_key=SIGNING_KEY,
            base_url=BASE_URL,
        )

        assert alert.actions, "expected an action button when can_use_action=True"
        url = alert.actions[0]["url"]
        token = url.split("t=", 1)[1].split("&", 1)[0]
        _, _, _, expires_str, _, _ = token.split(".")
        assert expires_str == "0", (
            f"expected a never-expiring token, got expires={expires_str!r}"
        )

        # And it must actually validate as such.
        valid, reason = hitl_tokens.validate_token(
            SIGNING_KEY, token, expected_intent="hitl"
        )
        assert valid is True
        assert reason == "ok"

    def test_body_does_not_promise_a_fixed_time_window(self):
        """The old body text ("valid 12h") is now false — don't ship a lie."""
        mon = Hitl2faEntryMonitor()

        alert = mon._build_rich_alert(
            "paper",
            status_raw={"hitl": {"next_retry_in_secs": 60}},
            can_use_action=True,
            signing_key=SIGNING_KEY,
            base_url=BASE_URL,
        )

        assert "valid" not in alert.body.lower() or "h)" not in alert.body.lower(), (
            f"body should not claim a fixed expiry window: {alert.body!r}"
        )

    def test_falls_back_to_plain_alert_without_signing_key(self):
        """Regression: unrelated to the expiry change, but this function's
        other branch must still behave once edited."""
        mon = Hitl2faEntryMonitor()

        alert = mon._build_rich_alert(
            "live",
            status_raw={"hitl": {}},
            can_use_action=False,
            signing_key="",
            base_url="",
        )

        assert alert.actions is None or alert.actions == []
        assert "dashboard" in alert.body.lower()
