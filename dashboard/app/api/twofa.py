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
from fastapi.responses import HTMLResponse

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


def _confirmation_html(mode: str, status_raw: dict | None) -> str:
    """What the operator's tap did: the login is
    re-submitted in the RUNNING gateway — ibctl does not restart it. A tap is
    the operator asking for a fresh push, so an IB Key prompt still on screen
    is closed first."""
    m = mode.upper()
    if ((status_raw or {}).get("hitl") or {}).get("challenge_open"):
        return callback_common.confirmation_html(
            mode,
            action_label="Login retry started",
            detail=(
                f"The {m} gateway still shows an IB Key prompt. Your Retry replaces "
                "that push: ibctl closes that prompt and re-submits the login in the "
                "running gateway (no restart). Approve the new push on your phone "
                "when it arrives."
            ),
        )
    return callback_common.confirmation_html(
        mode,
        action_label="Login retry started",
        detail=(
            f"ibctl is re-submitting the {m} login in the running gateway (no restart). "
            "Approve the IB Key prompt on your phone when it arrives."
        ),
    )


def _error_page(
    status_code: int,
    heading: str,
    message: str,
    *,
    link_url: str | None = None,
) -> HTMLResponse:
    return HTMLResponse(
        status_code=status_code,
        content=callback_common.error_html(heading, message, link_url=link_url),
    )


def _invalid_token_page(request: Request, mode_lc: str) -> HTMLResponse:
    """A rejected/expired/tampered token gets a state-aware page: check
    whether `mode_lc` is CURRENTLY still waiting on 2FA. If it's not (the
    common case once the token is old — the operator resolved it another
    way, or it recovered on its own), there's nothing to do and saying so
    plainly beats a dead-end error. If it's still genuinely stuck, point
    at the dashboard instead of a link that no longer works.

    Defaults to "nothing to do" when the `hitl` block is absent — that's
    the overwhelmingly common shape (a mode that isn't currently stuck at
    all), and this page has no bearing on real alerting either way:
    session_lost.py / Hitl2faEntryMonitor own paging on their own
    independent, state-triggered timelines regardless of what this
    courtesy page says. Only an explicit `active: true` shows the "still
    needs action" variant.
    """
    registry = request.app.state.instance_registry
    status_raw = registry.cached_status_raw(mode_lc) or {}
    hitl_block = status_raw.get("hitl") or {}
    if not hitl_block.get("active"):
        return _error_page(
            400,
            "Nothing to do",
            f"This link no longer works, but that's fine — {mode_lc.upper()} "
            "isn't waiting on 2FA anymore.",
        )
    base_url, _ = callback_common.resolve_dashboard_base_url()
    return _error_page(
        400,
        f"{mode_lc.upper()} still needs 2FA",
        "This link no longer works, and the situation hasn't resolved on "
        f"its own — {mode_lc.upper()} is still waiting on 2FA. Open the "
        "dashboard to resume it from there.",
        link_url=base_url,
    )


# States in which a login is already under way: a retry would start a
# competing one (ibctl ignores HITL_RESUME outside WaitingForHitl2fa anyway;
# this page just tells the operator the truth instead of "Login retry started").
_LOGIN_IN_PROGRESS = {
    "Init",
    "Launching",
    "WaitingForAgent",
    "WaitingForLogin",
    "Authenticating",
    "WaitingFor2fa",
    "HandlingSessionConflict",
    "DismissingPopups",
    "WaitingForApiReady",
    "ConfiguringApi",
    "Restarting",
    "ReconnectingSession",
    "WaitingForIB",
}


def _nothing_to_retry_page(mode_lc: str, status_raw: dict) -> HTMLResponse | None:
    """A valid link tapped when there is nothing to retry: e.g. the
    Sunday cold restart already started a new login, or the operator is
    tapping an old link after the mode recovered. Returns a truthful page,
    or None when the mode IS waiting for the operator (go ahead and retry)."""
    state = status_raw.get("state", "")
    if (status_raw.get("hitl") or {}).get("active") or state == "WaitingForHitl2fa":
        return None
    m = mode_lc.upper()
    if state in _LOGIN_IN_PROGRESS:
        heading = f"{m} is already logging in"
        message = (
            f"A login for {m} is already in progress, so nothing was retried. "
            "Approve the IB Key prompt on your phone if one arrives."
        )
    elif state == "Connected":
        heading = "Nothing to do"
        message = f"{m} is connected — nothing to do."
    else:
        heading = "Nothing to retry"
        message = f"{m} isn't waiting for 2FA (state: {state or 'unknown'}), so nothing was retried."
    base_url, _ = callback_common.resolve_dashboard_base_url()
    return _error_page(200, heading, message, link_url=base_url or None)


@router.get("/api/twofa/callback")
async def twofa_callback(request: Request, t: str = "", mode: str = ""):
    """Validate an HMAC-signed token and dispatch HITL_RESUME to ibctl.

    Query params:
        t:    the signed token (see hitl_tokens.mint_token)
        mode: "live" or "paper" — which instance to target

    Every response is an HTML page: a raw JSON error body renders as-is in
    the browser the link opened, which only makes a dead link worse. Status
    codes are unchanged from before:

        429 — too many requests from IP
        503 — signing key not configured; callbacks cannot be validated
        400 — unknown mode, OR a rejected token. A rejected token's page
              is state-aware — see `_invalid_token_page`.
        502 — ibctl not responding
        200 — confirmation page (unchanged happy path)
    """
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        logger.warning("HITL callback rate-limited for IP=%s", client_ip)
        return _error_page(
            429,
            "Too many attempts",
            "Too many requests from this network in a short time. Wait a "
            "minute and try again.",
        )

    signing_key = callback_common.get_signing_key()
    if not signing_key:
        logger.warning("HITL callback rejected: %s not configured", SIGNING_KEY_ENV)
        return _error_page(
            503,
            "Not configured",
            "The dashboard isn't set up to validate this link right now. "
            "Contact the operator.",
        )

    mode_lc = (mode or "").strip().lower()
    if mode_lc not in VALID_MODES:
        logger.warning("HITL callback rejected: invalid mode=%r", mode)
        return _error_page(
            400,
            "Unknown instance",
            "This link doesn't name a recognized ibctl instance.",
        )

    valid, reason = hitl_tokens.validate_token(signing_key, t, expected_intent="hitl")
    if not valid:
        # Do NOT echo the token itself.
        logger.warning(
            "HITL callback rejected for mode=%s: reason=%s",
            mode_lc,
            reason,
        )
        return _invalid_token_page(request, mode_lc)

    # Cross-check token mode against URL mode — defense in depth.
    token_mode = hitl_tokens.extract_mode(t)
    if token_mode and token_mode != mode_lc:
        logger.warning(
            "HITL callback mode mismatch: url=%s token=%s",
            mode_lc,
            token_mode,
        )
        return _invalid_token_page(request, mode_lc)

    registry = request.app.state.instance_registry
    # Only retry what is actually waiting. With no cached STATUS at all,
    # fall through and let ibctl's own guard (HITL_RESUME acts only in
    # WaitingForHitl2fa) decide.
    status_raw = registry.cached_status_raw(mode_lc)
    if status_raw is not None:
        page = _nothing_to_retry_page(mode_lc, status_raw)
        if page is not None:
            logger.info(
                "HITL callback for %s: nothing to retry (state=%s) — not sending HITL_RESUME",
                mode_lc,
                status_raw.get("state"),
            )
            return page

    try:
        client = registry.get_client(mode_lc)
    except KeyError:
        logger.warning("HITL callback: no %s instance registered", mode_lc)
        return _error_page(
            400,
            "Unknown instance",
            "This link doesn't name a recognized ibctl instance.",
        )

    try:
        result = await client.send_command("HITL_RESUME")
        registry.invalidate(mode_lc)
        logger.info(
            "HITL_RESUME dispatched to %s via ntfy callback: %s", mode_lc, result
        )
    except DashboardError as e:
        logger.error("HITL_RESUME to %s failed: %s", mode_lc, e.message)
        return _error_page(
            502,
            "Couldn't reach ibctl",
            f"Dispatching to {mode_lc.upper()} failed: {e.message}",
        )

    return HTMLResponse(content=_confirmation_html(mode_lc, status_raw), status_code=200)
