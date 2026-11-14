"""RED-phase tests: hitl_tokens gains a "never expires" sentinel.

Problem: the HITL 2FA retry link is HMAC-signed with
a hard expiry baked in at mint time (default 12h). If the operator is away
longer than that, the link goes cryptographically dead — even though ibctl
ITSELF already treats a late resume safely: `Command::HitlResume` only acts
when the mode is *currently* `WaitingForHitl2fa` (state_machine/mod.rs:2950)
and otherwise just logs "ignored" and no-ops. The token's own timestamp is a
stricter, shorter-lived gate than the real safety net already provides.

Fix: `mint_token(..., valid_hours=None)` mints a token whose `expires`
segment is `0`, a sentinel `validate_token` treats as "never expires". This
is backward-safe by construction — under the OLD contract `valid_hours` was
always a positive int (`>= 1`), so `expires = issued + valid_hours*3600` was
NEVER producible as `0` by any pre-existing caller. No version bump needed;
`expires == 0` was simply an impossible value before, so reinterpreting it
carries zero ambiguity risk for any token minted under the old rules.

Scoped to the `hitl` intent only. `reconnect_tokens.mint_token` (give-up
resume) keeps a required, non-Optional `valid_hours: int` and is untouched —
that flow's own validity window is a separate, unrelated operator ask.
"""

from __future__ import annotations

import time

from app.services import hitl_tokens

SIGNING_KEY = "test-signing-key-for-never-expires-tests"


class TestMintNeverExpiring:
    def test_none_valid_hours_produces_expires_zero_segment(self):
        token = hitl_tokens.mint_token(SIGNING_KEY, "live", None)

        parts = token.split(".")
        assert len(parts) == 6, f"expected 6 segments, got {len(parts)}: {parts}"
        _, _, issued_str, expires_str, mode, _ = parts
        assert expires_str == "0", f"expected sentinel expires=0, got {expires_str!r}"
        assert mode == "live"
        assert int(issued_str) > 0


class TestValidateNeverExpiring:
    def test_never_expiring_token_is_valid_right_after_mint(self):
        token = hitl_tokens.mint_token(SIGNING_KEY, "paper", None)

        valid, reason = hitl_tokens.validate_token(
            SIGNING_KEY, token, expected_intent="hitl"
        )

        assert valid is True
        assert reason == "ok"

    def test_never_expiring_token_is_not_malformed(self):
        """The pre-existing malformed check was `expires <= issued` — a
        sentinel of 0 would trip that (0 <= issued is always true) unless
        the check is taught about the sentinel. Pin that down explicitly."""
        token = hitl_tokens.mint_token(SIGNING_KEY, "live", None)

        valid, reason = hitl_tokens.validate_token(
            SIGNING_KEY, token, expected_intent="hitl"
        )

        assert reason != "malformed"
        assert valid is True

    def test_never_expiring_token_still_valid_a_year_later(self, monkeypatch):
        token = hitl_tokens.mint_token(SIGNING_KEY, "live", None)

        future = time.time() + 365 * 24 * 3600
        monkeypatch.setattr(time, "time", lambda: future)
        valid, reason = hitl_tokens.validate_token(
            SIGNING_KEY, token, expected_intent="hitl"
        )

        assert valid is True
        assert reason == "ok"

    def test_never_expiring_token_still_checks_signature(self):
        """The sentinel must not accidentally bypass HMAC verification."""
        token = hitl_tokens.mint_token(SIGNING_KEY, "live", None)
        tampered = token[:-4] + "AAAA"

        valid, reason = hitl_tokens.validate_token(
            SIGNING_KEY, tampered, expected_intent="hitl"
        )

        assert valid is False
        assert reason == "bad_signature"

    def test_never_expiring_token_still_checks_intent(self):
        token = hitl_tokens.mint_token(SIGNING_KEY, "live", None, intent="hitl")

        valid, reason = hitl_tokens.validate_token(
            SIGNING_KEY, token, expected_intent="reconnect"
        )

        assert valid is False
        assert reason == "bad_intent"


class TestRegularExpiryStillWorks:
    """The sentinel must not weaken the ordinary bounded-expiry path — this
    is what reconnect_tokens (give-up resume) still relies on."""

    def test_bounded_token_still_expires(self, monkeypatch):
        token = hitl_tokens.mint_token(SIGNING_KEY, "live", 1, intent="reconnect")

        future = time.time() + 2 * 3600
        monkeypatch.setattr(time, "time", lambda: future)
        valid, reason = hitl_tokens.validate_token(
            SIGNING_KEY, token, expected_intent="reconnect"
        )

        assert valid is False
        assert reason == "expired"

    def test_bounded_token_still_valid_within_window(self):
        token = hitl_tokens.mint_token(SIGNING_KEY, "live", 12, intent="reconnect")

        valid, reason = hitl_tokens.validate_token(
            SIGNING_KEY, token, expected_intent="reconnect"
        )

        assert valid is True
        assert reason == "ok"
