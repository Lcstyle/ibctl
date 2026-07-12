"""HMAC-signed one-shot tokens for HITL 2FA and reconnect ntfy callback URLs.

Tokens are stateless — no server-side storage. The HMAC signature binds the
issued/expires timestamps, an ``intent`` field (``hitl`` or ``reconnect``),
and the target trading mode, so a token is only valid for one specific
ibctl callback flow, one instance, and a bounded time window.

The "one-shot" property is enforced on the ibctl side: it stamps the
relevant callback-token on entry to the waiting state, clears it on exit,
and rejects the RESUME command outside that state. This file only handles
minting and verifying the signature + expiry + intent.

Token format (v2):
    v2.<intent>.<issued_unix>.<expires_unix>.<mode>.<base64url_hmac>

HMAC input (the "prefix") is the first five dot-joined fields:
    v2.<intent>.<issued_unix>.<expires_unix>.<mode>

Base64 uses the URL-safe alphabet, unpadded.

The prior v1 format (``v1.<issued>.<expires>.<mode>.<sig>``, 5 segments)
is intentionally rejected by this module — v1 tokens still in flight during
deploy are ≤12h old and callers re-mint on each new entry, so operationally
this is safe. v1 tokens fail with the ``malformed`` reason because their
segment count no longer matches v2.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

VERSION = "v2"
DEFAULT_INTENT = "hitl"
VALID_INTENTS = frozenset({"hitl", "reconnect"})
# Modes we accept. The reconnect_tokens shim also cross-checks against this.
# Both intent and mode segments must be `.`-free so a malformed value cannot
# silently shift the 6-segment boundary and produce a permanently-unvalidatable
# token — symmetric with the intent allowlist above.
VALID_MODES = frozenset({"live", "paper"})


def _b64url_encode(data: bytes) -> str:
    """URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """URL-safe base64 decode, tolerating missing padding."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _sign(signing_key: str, prefix: str) -> str:
    mac = hmac.new(
        signing_key.encode("utf-8"),
        prefix.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64url_encode(mac)


def mint_token(
    signing_key: str,
    mode: str,
    valid_hours: int,
    *,
    intent: str = DEFAULT_INTENT,
) -> str:
    """Mint a new signed token for the given mode, valid for ``valid_hours``.

    Args:
        signing_key: HMAC-SHA256 key. Must be non-empty.
        mode: "live" or "paper" (normalized to lowercase).
        valid_hours: Token lifetime in hours. Must be positive.
        intent: Callback family this token authorizes — currently
            ``"hitl"`` (2FA resume) or ``"reconnect"`` (recovery-give-up
            resume). Default preserves the pre-v2 HITL call sites.

    Returns:
        A token string in the ``v2.<intent>.<issued>.<expires>.<mode>.<hmac>``
        format.

    Raises:
        ValueError: if ``signing_key`` is empty or ``intent`` is unknown.
    """
    if not signing_key:
        raise ValueError("signing_key is empty; cannot mint callback token")
    if intent not in VALID_INTENTS:
        raise ValueError(
            f"unknown intent {intent!r}; expected one of {sorted(VALID_INTENTS)}"
        )

    mode_norm = mode.lower()
    # Reject mode values that contain the token delimiter — otherwise the
    # produced token has >6 dots and every future validation returns
    # "malformed" with no signal at mint time. Keep the allowlist tight so a
    # bug or misconfigured caller fails loudly here rather than silently at
    # validation time. `intent` is already gated by VALID_INTENTS above.
    if "." in mode_norm:
        raise ValueError(
            f"mode {mode!r} must not contain '.'; token delimiter would shift"
        )
    if mode_norm not in VALID_MODES:
        raise ValueError(
            f"unknown mode {mode!r}; expected one of {sorted(VALID_MODES)}"
        )
    issued = int(time.time())
    expires = issued + int(valid_hours) * 3600
    prefix = f"{VERSION}.{intent}.{issued}.{expires}.{mode_norm}"
    sig = _sign(signing_key, prefix)
    return f"{prefix}.{sig}"


def validate_token(
    signing_key: str,
    token: str,
    *,
    expected_intent: str = DEFAULT_INTENT,
) -> tuple[bool, str]:
    """Verify a signed token's signature, intent, and expiry.

    Returns:
        (valid, reason) where reason is one of:
        - "ok"            — signature valid, intent matches, not expired
        - "malformed"     — could not parse the token structure
        - "bad_version"   — first segment is not ``v2`` (e.g. legacy v1)
        - "bad_intent"    — token's intent field does not match
                            ``expected_intent`` (defense against cross-flow
                            replay: a HITL token cannot resume a reconnect
                            give-up and vice versa)
        - "expired"       — expiry timestamp is in the past
        - "bad_signature" — HMAC does not match
    """
    if not token:
        return False, "malformed"

    parts = token.split(".")
    # v2 . intent . issued . expires . mode . sig  -> 6 segments
    if len(parts) != 6:
        return False, "malformed"

    version, intent, issued_str, expires_str, mode, sig = parts
    if version != VERSION:
        return False, "bad_version"
    if not intent:
        return False, "malformed"
    if not mode:
        return False, "malformed"

    try:
        issued = int(issued_str)
        expires = int(expires_str)
    except ValueError:
        return False, "malformed"

    if issued < 0 or expires <= issued:
        return False, "malformed"

    try:
        # Validate the signature decodes as URL-safe base64.
        _b64url_decode(sig)
    except (ValueError, base64.binascii.Error):
        return False, "malformed"

    prefix = f"{VERSION}.{intent}.{issued}.{expires}.{mode}"
    expected = _sign(signing_key, prefix)
    if not hmac.compare_digest(sig, expected):
        return False, "bad_signature"

    # Intent mismatch is a distinctive reason from bad_signature so callback
    # endpoints can audit cross-flow replay attempts separately. Check AFTER
    # signature so a random string doesn't leak the intent-check code path.
    if intent != expected_intent:
        return False, "bad_intent"

    if expires <= int(time.time()):
        return False, "expired"

    return True, "ok"


def extract_mode(token: str) -> str | None:
    """Parse the mode out of a token without verifying the signature.

    Useful for logging / error messages. Callers MUST still call
    ``validate_token`` before trusting the mode for any action.
    """
    parts = token.split(".")
    if len(parts) != 6:
        return None
    return parts[4] or None


def extract_intent(token: str) -> str | None:
    """Parse the intent out of a token without verifying the signature.

    Useful for structured logs / audit trails at the callback endpoints so
    a rejected token's intended flow can be reported without trusting it.
    """
    parts = token.split(".")
    if len(parts) != 6:
        return None
    return parts[1] or None
