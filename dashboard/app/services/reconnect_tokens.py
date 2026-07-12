"""HMAC-signed callback tokens for the reconnect give-up resume flow.

Thin wrapper around ``app.services.hitl_tokens`` that pins ``intent="reconnect"``
so callers cannot accidentally cross-mint (or cross-validate) a HITL 2FA
token as a reconnect token. All the signing / expiry / mode logic lives in
``hitl_tokens``; this module only fixes the intent parameter.

Cross-flow replay defence: because the intent is baked into the HMAC prefix,
a v2 token minted by ``hitl_tokens.mint_token(..., intent="hitl")`` will fail
``validate_token`` here with reason ``"bad_intent"`` — visibly distinct from
``"bad_signature"`` for audit logs.
"""

from __future__ import annotations

from app.services.hitl_tokens import (
    mint_token as _mint,
    validate_token as _validate,
)

INTENT = "reconnect"


def mint_token(signing_key: str, mode: str, valid_hours: int) -> str:
    """Mint a v2 reconnect-intent token."""
    return _mint(signing_key, mode, valid_hours, intent=INTENT)


def validate_token(signing_key: str, token: str) -> tuple[bool, str]:
    """Verify a token, requiring ``intent == "reconnect"``."""
    return _validate(signing_key, token, expected_intent=INTENT)


def extract_mode(token: str) -> str | None:
    """Parse the mode field from a token without verifying the signature.

    Useful for structured logs at the callback endpoint. Callers MUST still
    call ``validate_token`` before trusting the mode for any action.
    """
    parts = token.split(".")
    if len(parts) != 6:
        return None
    return parts[4] or None
