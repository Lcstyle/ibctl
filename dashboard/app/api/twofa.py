"""Two-factor auth ntfy callback endpoint.

The HITL 2FA monitor sends an ntfy notification with a signed callback URL
when ibctl enters WaitingForHitl2fa. Clicking the action button on a phone
opens this endpoint in a browser, which validates the HMAC-signed token
and forwards a HITL_RESUME command to the target ibctl instance.

Security model:
  - No session / cookie auth — the HMAC signature IS the credential.
  - Signing key IBCTL_NTFY_ACTION_SIGNING_KEY is env-only, never in TOML.
  - Tokens are expiry-stamped and localized to one mode (live/paper).
  - One-shot enforcement lives inside ibctl: it clears its callback-token
    state on leaving WaitingForHitl2fa and rejects HITL_RESUME when not
    in that state. Replays after the window simply no-op on the ibctl side.
"""

from __future__ import annotations

import html
import logging
import os
import time
from collections import deque

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.domain.errors import DashboardError
from app.services import hitl_tokens

logger = logging.getLogger("dashboard.api.twofa")
router = APIRouter()

VALID_MODES = {"live", "paper"}
SIGNING_KEY_ENV = "IBCTL_NTFY_ACTION_SIGNING_KEY"

# ---------------------------------------------------------------------------
# In-memory sliding-window rate limiter for the callback endpoint.
#
# Simple per-IP counter using a dict[str, deque[float]] where each deque
# holds the timestamps (epoch seconds) of requests within the last 60s.
# Not shared across multiple uvicorn workers — acceptable for this endpoint.
# ---------------------------------------------------------------------------

_RATE_LIMIT_WINDOW_SECS = 60.0
_RATE_LIMIT_MAX_REQUESTS = 10
# Bounds the IP table to prevent unbounded memory growth from port scans /
# many unique clients. When exceeded, the IP with the oldest most-recent hit
# is evicted — it won't have hit us in a while anyway.
_IP_TABLE_MAX_SIZE = 1024

# IP → deque of request timestamps in the last WINDOW seconds.
# Single-worker uvicorn is the deployment target, so no lock is needed.
# Behind a reverse proxy this keys on the proxy's IP — TODO when ingress lands.
_ip_timestamps: dict[str, deque[float]] = {}


def _evict_if_needed() -> None:
    """Drop the IP with the oldest last-hit when the table exceeds the cap."""
    if len(_ip_timestamps) <= _IP_TABLE_MAX_SIZE:
        return
    # Cheapest "oldest" heuristic: rightmost timestamp per bucket.
    oldest_ip = min(
        _ip_timestamps,
        key=lambda k: _ip_timestamps[k][-1] if _ip_timestamps[k] else 0.0,
    )
    _ip_timestamps.pop(oldest_ip, None)


def _check_rate_limit(ip: str) -> bool:
    """Return True if the request is allowed, False if rate-limited.

    Cleans up stale timestamps for the given IP opportunistically on each call.
    """
    now = time.time()
    cutoff = now - _RATE_LIMIT_WINDOW_SECS

    if ip not in _ip_timestamps:
        _ip_timestamps[ip] = deque()
        _evict_if_needed()

    bucket = _ip_timestamps[ip]

    # Drop timestamps older than the window.
    while bucket and bucket[0] < cutoff:
        bucket.popleft()

    # If the bucket is now empty AND we're above the cap, drop it entirely to
    # aid eviction. Cheap, happens at most once per burst.
    if not bucket and len(_ip_timestamps) > _IP_TABLE_MAX_SIZE:
        _ip_timestamps.pop(ip, None)
        _ip_timestamps[ip] = bucket

    if len(bucket) >= _RATE_LIMIT_MAX_REQUESTS:
        return False  # rate-limited

    bucket.append(now)
    return True


def _json_error(status_code: int, payload: dict) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=payload)


def _confirmation_html(mode: str) -> str:
    safe_mode = html.escape(mode.upper())
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>ibctl 2FA retry triggered</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
            Roboto, Helvetica, Arial, sans-serif;
            margin: 0; padding: 2rem;
            background: #0f172a; color: #e2e8f0; }}
    .card {{ max-width: 28rem; margin: 3rem auto; background: #1e293b;
             border-radius: 0.75rem; padding: 2rem;
             box-shadow: 0 10px 20px rgba(0,0,0,0.3); }}
    h1 {{ margin: 0 0 0.5rem 0; font-size: 1.5rem; }}
    p  {{ line-height: 1.5; color: #cbd5e1; }}
    .ok {{ color: #4ade80; font-weight: 600; }}
  </style>
</head>
<body>
  <div class="card">
    <h1 class="ok">Retry triggered</h1>
    <p>HITL_RESUME was sent to the <strong>{safe_mode}</strong> ibctl
       instance. 2FA should prompt again shortly.</p>
    <p>You may close this tab.</p>
  </div>
</body>
</html>
"""


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
                                                      wrong signature
        502 {"error": "ibctl_unreachable", ...}    — ibctl not responding
        200 (HTML)                                 — confirmation page
    """
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        logger.warning("HITL callback rate-limited for IP=%s", client_ip)
        return _json_error(429, {"error": "rate_limited"})

    signing_key = os.environ.get(SIGNING_KEY_ENV, "").strip()
    if not signing_key:
        logger.warning("HITL callback rejected: %s not configured", SIGNING_KEY_ENV)
        return _json_error(503, {"error": "signing_key_not_configured"})

    mode_lc = (mode or "").strip().lower()
    if mode_lc not in VALID_MODES:
        logger.warning("HITL callback rejected: invalid mode=%r", mode)
        return _json_error(400, {"error": "invalid_mode"})

    valid, reason = hitl_tokens.validate_token(signing_key, t)
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
