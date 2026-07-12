"""RED-phase tests for hitl_tokens v2 wire format with intent parameterization.

Stage 5 of PR-C introduces a `reconnect` callback that reuses the HMAC
mint/verify machinery of `hitl_tokens`. To keep both flows on one code path
without letting a HITL 2FA token be replayed against the reconnect endpoint
(or vice versa) we bump the token wire format to v2 with an `intent` field
baked into the signed prefix:

    v2.<intent>.<issued>.<expires>.<mode>.<sig>   (6 dot-separated segments)

`mint_token` gets a keyword-only `intent` parameter defaulting to `"hitl"`
so existing HITL call sites don't have to change; `validate_token` gets
`expected_intent` defaulting to `"hitl"` for the same reason.

These tests are written BEFORE the module is updated, so every test in this
file is expected to fail against the current v1 implementation.
"""

from __future__ import annotations

from app.services import hitl_tokens

SIGNING_KEY = "test-signing-key-for-v2-tests"


class TestV2IntentRoundtrip:
    """Round-trip mint → validate with intent field."""

    def test_v2_hitl_token_roundtrip_default_intent(self):
        """A minted token with default intent validates as hitl."""
        token = hitl_tokens.mint_token(SIGNING_KEY, "paper", valid_hours=12)

        # New v2 wire format: 6 segments (v2.intent.issued.expires.mode.sig).
        parts = token.split(".")
        assert len(parts) == 6, f"expected 6 v2 segments, got {len(parts)}: {parts}"
        assert parts[0] == "v2"
        assert parts[1] == "hitl"  # default intent

        valid, reason = hitl_tokens.validate_token(SIGNING_KEY, token)
        assert valid is True
        assert reason == "ok"

    def test_v2_reconnect_token_roundtrip_explicit_intent(self):
        """A token minted with intent=reconnect validates when the caller
        passes expected_intent=reconnect."""
        token = hitl_tokens.mint_token(
            SIGNING_KEY, "live", valid_hours=6, intent="reconnect"
        )

        parts = token.split(".")
        assert len(parts) == 6
        assert parts[0] == "v2"
        assert parts[1] == "reconnect"

        valid, reason = hitl_tokens.validate_token(
            SIGNING_KEY, token, expected_intent="reconnect"
        )
        assert valid is True
        assert reason == "ok"


class TestV2IntentCrossReplay:
    """Cross-intent tokens must be rejected — a HITL token cannot resume a
    reconnect give-up and vice versa."""

    def test_hitl_token_rejected_when_expected_intent_reconnect(self):
        """A HITL-intent token replayed at the reconnect endpoint must fail."""
        hitl_token = hitl_tokens.mint_token(SIGNING_KEY, "paper", valid_hours=12)

        valid, reason = hitl_tokens.validate_token(
            SIGNING_KEY, hitl_token, expected_intent="reconnect"
        )
        assert valid is False
        assert reason == "bad_intent"

    def test_reconnect_token_rejected_when_expected_intent_hitl(self):
        """A reconnect-intent token replayed at the HITL endpoint must fail."""
        reconnect_token = hitl_tokens.mint_token(
            SIGNING_KEY, "paper", valid_hours=6, intent="reconnect"
        )

        # Default expected_intent is "hitl".
        valid, reason = hitl_tokens.validate_token(SIGNING_KEY, reconnect_token)
        assert valid is False
        assert reason == "bad_intent"


class TestV2IntentRejectionReasons:
    """The rejection reason for a cross-intent token is distinctive so the
    callback endpoint can log/audit it separately from bad signatures."""

    def test_bad_intent_returns_bad_intent_reason(self):
        """The reason string must be exactly `bad_intent` — not `malformed`,
        not `bad_signature`. Callback endpoints branch on this."""
        # Mint HITL, verify against reconnect — the intent mismatch alone
        # is what triggers this, so signature must be a valid HITL signature.
        token = hitl_tokens.mint_token(SIGNING_KEY, "paper", valid_hours=12)

        valid, reason = hitl_tokens.validate_token(
            SIGNING_KEY, token, expected_intent="reconnect"
        )
        assert valid is False
        assert reason == "bad_intent", (
            f"expected the distinctive `bad_intent` reason, got {reason!r}"
        )


class TestV1BackwardIncompat:
    """v1 tokens minted before the upgrade cannot validate under v2. This is
    fine operationally because HITL callback tokens are ≤12h and existing
    tests re-mint on each call — but we want the failure to be well-defined."""

    def test_v1_token_rejected_after_upgrade(self):
        """A hand-crafted v1-shaped token (5 segments, starts with `v1`) must
        fail validation with a distinctive reason — not silently accepted."""
        # Hand-craft a v1-shape token: v1.<issued>.<expires>.<mode>.<sig>
        # Signature doesn't have to be valid — we should reject on version/shape
        # before we even get to signature comparison.
        v1_token = "v1.1700000000.1700043200.paper.QUJDREVGRw"

        valid, reason = hitl_tokens.validate_token(SIGNING_KEY, v1_token)
        assert valid is False
        # Post-upgrade the segment count no longer matches v2 (5 vs 6) so
        # this comes back as `malformed` — but it MUST NOT come back as `ok`.
        assert reason in {"malformed", "bad_version"}, (
            f"v1 token was not rejected cleanly; got reason={reason!r}"
        )
