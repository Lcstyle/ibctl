"""Two-factor auth ntfy callback endpoint.

The HITL 2FA monitor sends an ntfy notification with a signed callback URL
when ibctl enters WaitingForHitl2fa. Clicking the action button on a phone
opens this endpoint in a browser, which validates the HMAC-signed token
and forwards a HITL_RESUME command to the target ibctl instance.

Security model:
  - No session / cookie auth — the HMAC signature IS the credential.
  - Signing key IBCTL_NTFY_ACTION_SIGNING_KEY is env-only, never in TOML.
  - Tokens are expiry-stamped, intent-stamped (``hitl``), and localized to
    one mode (live/paper).
  - One-shot enforcement lives inside ibctl: it clears its callback-token
    state on leaving WaitingForHitl2fa and rejects HITL_RESUME when not
    in that state. Replays after the window simply no-op on the ibctl side.

Rate-limiting, dashboard-URL resolution, and confirmation HTML come from
``app.services.callback_common``; see that module for the shared machinery
between this endpoint and ``/api/reconnect/callback``.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.domain.errors import DashboardError
from app.services import callback_common, hitl_tokens

logger = logging.getLogger("dashboard.api.twofa")
router = APIRouter()

VALID_MODES = {"live", "paper"}

# ---------------------------------------------------------------------------
# Backward-compat aliases so existing tests / callers keep working after the
# extraction into callback_common. New code should import from callback_common
# directly.
# ---------------------------------------------------------------------------

SIGNING_KEY_ENV = callback_common.SIGNING_KEY_ENV

_RATE_LIMIT_WINDOW_SECS = 60.0
_RATE_LIMIT_MAX_REQUESTS = 10

# The HITL endpoint gets its own limiter instance. The reconnect endpoint
# will construct its own — that's the whole point of RateLimiter being a
# class rather than module-level state.
_rate_limiter = callback_common.RateLimiter(
    window_secs=_RATE_LIMIT_WINDOW_SECS,
    max_requests=_RATE_LIMIT_MAX_REQUESTS,
)

# Existing tests reach into ``twofa_mod._ip_timestamps`` to clear state or
# seed stale timestamps. Alias the limiter's internal dict so those tests
# keep working without knowing about the refactor.
_ip_timestamps = _rate_limiter._ip_timestamps


def _check_rate_limit(ip: str) -> bool:
    return _rate_limiter.check(ip)


def _confirmation_html(mode: str) -> str:
    return callback_common.confirmation_html(mode, action_label="Retry triggered")


def _json_error(status_code: int, payload: dict) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=payload)


@router.get("/api/twofa/callback")
async def twofa_callback(request: Request, t: str = "", mode: str = ""):
    """Validate an HMAC-signed token and dispatch HITL_RESUME to ibctl.

    Query params:
        t:    the signed token (see hitl_tokens.mint_token)
        mode: "live" or "paper" — which instance to target

    Responses:
        429 {"error": "rate_limited"}              — too many requests from IP
        503 {"error": "signing_key_not_configured"} — when the env signing
            key is missing. Callbacks cannot be validated.
        400 {"error": "invalid_mode"}              — missing / unknown mode
        400 {"error": "invalid_token", "reason"}   — bad format / expired /
                                                      wrong signature / wrong
                                                      intent
        502 {"error": "ibctl_unreachable", ...}    — ibctl not responding
        200 (HTML)                                 — confirmation page
    """
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        logger.warning("HITL callback rate-limited for IP=%s", client_ip)
        return _json_error(429, {"error": "rate_limited"})

    signing_key = callback_common.get_signing_key()
    if not signing_key:
        logger.warning("HITL callback rejected: %s not configured", SIGNING_KEY_ENV)
        return _json_error(503, {"error": "signing_key_not_configured"})

    mode_lc = (mode or "").strip().lower()
    if mode_lc not in VALID_MODES:
        logger.warning("HITL callback rejected: invalid mode=%r", mode)
        return _json_error(400, {"error": "invalid_mode"})

    valid, reason = hitl_tokens.validate_token(signing_key, t, expected_intent="hitl")
    if not valid:
        # Do NOT echo the token itself.
        logger.warning(
            "HITL callback rejected for mode=%s: reason=%s",
            mode_lc, reason,
        )
        return _json_error(400, {"error": "invalid_token", "reason": reason})

    # Cross-check token mode against URL mode — defense in depth.
    token_mode = hitl_tokens.extract_mode(t)
    if token_mode and token_mode != mode_lc:
        logger.warning(
            "HITL callback mode mismatch: url=%s token=%s",
            mode_lc, token_mode,
        )
        return _json_error(400, {"error": "invalid_token", "reason": "mode_mismatch"})

    registry = request.app.state.instance_registry
    try:
        client = registry.get_client(mode_lc)
    except KeyError:
        logger.warning("HITL callback: no %s instance registered", mode_lc)
        return _json_error(400, {"error": "invalid_mode"})

    try:
        result = await client.send_command("HITL_RESUME")
        registry.invalidate(mode_lc)
        logger.info("HITL_RESUME dispatched to %s via ntfy callback: %s", mode_lc, result)
    except DashboardError as e:
        logger.error("HITL_RESUME to %s failed: %s", mode_lc, e.message)
        return _json_error(502, {"error": "ibctl_unreachable", "detail": e.message})

    return HTMLResponse(content=_confirmation_html(mode_lc), status_code=200)
