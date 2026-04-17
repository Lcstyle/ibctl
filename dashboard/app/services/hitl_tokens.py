"""HMAC-signed one-shot tokens for HITL 2FA ntfy callback URLs.

Tokens are stateless — no server-side storage. The HMAC signature binds the
issued/expires timestamps and the target trading mode, so a token is only
valid for one specific ibctl instance and for a bounded time window.

The "one-shot" property is enforced on the ibctl side: it stamps
`hitl_callback_token` on entry to WaitingForHitl2fa, clears it on exit, and
rejects HITL_RESUME outside that state. This file only handles minting and
verifying the signature + expiry.

Token format:
    v1.<issued_unix>.<expires_unix>.<mode>.<base64url_hmac>

HMAC input (the "prefix") is the first four dot-joined fields:
    v1.<issued_unix>.<expires_unix>.<mode>

Base64 uses the URL-safe alphabet, unpadded.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

VERSION = "v1"


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


def mint_token(signing_key: str, mode: str, valid_hours: int) -> str:
    """Mint a new signed token for the given mode, valid for `valid_hours`.

    Args:
        signing_key: HMAC-SHA256 key. Must be non-empty.
        mode: "live" or "paper" (normalized to lowercase).
        valid_hours: Token lifetime in hours. Must be positive.

    Returns:
        A token string in the `v1.<issued>.<expires>.<mode>.<hmac>` format.

    Raises:
        ValueError: if signing_key is empty.
    """
    if not signing_key:
        raise ValueError("signing_key is empty; cannot mint HITL callback token")

    mode_norm = mode.lower()
    issued = int(time.time())
    expires = issued + int(valid_hours) * 3600
    prefix = f"{VERSION}.{issued}.{expires}.{mode_norm}"
    sig = _sign(signing_key, prefix)
    return f"{prefix}.{sig}"


def validate_token(signing_key: str, token: str) -> tuple[bool, str]:
    """Verify a signed token's signature and expiry.

    Returns:
        (valid, reason) where reason is one of:
        - "ok"            — signature valid and not yet expired
        - "malformed"     — could not parse the token structure
        - "expired"       — expiry timestamp is in the past
        - "bad_signature" — HMAC does not match
    """
    if not token:
        return False, "malformed"

    parts = token.split(".")
    # v1 . issued . expires . mode . sig  -> 5 segments
    if len(parts) != 5:
        return False, "malformed"

    version, issued_str, expires_str, mode, sig = parts
    if version != VERSION:
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

    prefix = f"{VERSION}.{issued}.{expires}.{mode}"
    expected = _sign(signing_key, prefix)
    if not hmac.compare_digest(sig, expected):
        return False, "bad_signature"

    if expires <= int(time.time()):
        return False, "expired"

    return True, "ok"


def extract_mode(token: str) -> str | None:
    """Parse the mode out of a token without verifying the signature.

    Useful for logging / error messages. Callers MUST still call
    `validate_token` before trusting the mode for any action.
    """
    parts = token.split(".")
    if len(parts) != 5:
        return None
    return parts[3] or None
