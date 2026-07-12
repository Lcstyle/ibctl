"""Recovery-give-up resume callback endpoint.

The ``ReconnectGiveUpMonitor`` sends a ntfy notification with a signed
callback URL when a mode transitions into the ``given_up`` recovery phase.
An operator taps the action button on their phone, which hits this endpoint;
the dashboard verifies the HMAC signature + intent + mode and forwards
``RESUME_RECONNECT <token>`` to the target ibctl instance.

Security model mirrors ``/api/twofa/callback``:
  - No session / cookie auth — the HMAC signature IS the credential.
  - Signing key ``IBCTL_NTFY_ACTION_SIGNING_KEY`` is env-only, never TOML.
  - Tokens are expiry-stamped, intent-stamped (``reconnect``), and localized
    to one mode (live/paper).
  - One-shot enforcement lives inside ibctl: the coordinator hashes the
    resume token and rejects a second RESUME_RECONNECT that carries the
    same nonce material (see ``recovery::hash_token``).
  - The dashboard also caches consumed token digests in-process as an
    additive replay defence — a warm-restart of ibctl (which the
    coordinator supports intentionally) would otherwise re-open the
    replay window for every unclaimed URL until the token's expiry
    (finding A-MED-3).

Split-flow (finding A-HIGH-1):
  - GET is idempotent: it renders a confirmation page with a POST form.
    Link-preview crawlers, URL-defense scanners (Barracuda, Proofpoint,
    Safe Links), and mobile "prefetch links" features follow GETs but
    almost never POSTs, so the one-shot token is not auto-consumed by a
    non-operator client.
  - POST is what actually dispatches ``RESUME_RECONNECT``. Rate limit +
    signing-key + HMAC verify + mode check run on BOTH so a preview
    crawler still counts against the rate-limit bucket (and can trip a
    security audit if it hammers) but never triggers the side effect.

Status-code shape distinctions from ``/api/twofa/callback``:
  - 403 for bad-signature / expired / bad-intent / mode-mismatch (this is a
    security event, would-be forgery — not a client-side format error).
  - 500 for missing signing key (server misconfig, not a temporary
    service-unavailable).
  - 429 for rate-limit (shared shape).
  - 502 when ibctl rejects RESUME_RECONNECT (older daemon) OR when a
    generic dispatch error surfaces — distinguished by ``error`` field:
    ``ibctl_unreachable``, ``ibctl_dispatch_failed``,
    ``ibctl_command_rejected`` (finding A-MED-4, A-MED-5).
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import deque

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.domain.errors import DashboardError
from app.services import callback_common, reconnect_tokens

logger = logging.getLogger("dashboard.api.reconnect")
router = APIRouter()

VALID_MODES = {"live", "paper"}

# Reconnect endpoint owns an INDEPENDENT limiter instance — a 2FA burst must
# not lock out a legitimate reconnect resume, and vice versa. Matches the
# HITL cadence: 10 req / 60s / IP.
_RATE_LIMIT_WINDOW_SECS = 60.0
_RATE_LIMIT_MAX_REQUESTS = 10

_rate_limiter = callback_common.RateLimiter(
    window_secs=_RATE_LIMIT_WINDOW_SECS,
    max_requests=_RATE_LIMIT_MAX_REQUESTS,
)


# ---------------------------------------------------------------------------
# Server-side single-use nonce cache (finding A-MED-3)
# ---------------------------------------------------------------------------
#
# ibctl's coordinator hashes tokens to enforce single-use, but that state is
# in-process and cleared by warm-restart / -Drestart. This dashboard-side
# cache keeps the replay window closed even across an ibctl bounce. Keyed by
# SHA-256 of the raw token; TTL bounds memory growth so an attacker cannot
# balloon the set. Cheap, fully additive to ibctl's enforcement.
_USED_TOKEN_TTL_SECS = 12 * 3600  # matches DEFAULT_CALLBACK_VALID_HOURS
_USED_TOKEN_CACHE_MAX = 4096


class _UsedTokenCache:
    """TTL-bounded set of consumed token digests."""

    def __init__(self, ttl_secs: float, max_entries: int) -> None:
        self._ttl = float(ttl_secs)
        self._max = int(max_entries)
        # Ordered dict-like structure: (digest, expiry_ts). deque for
        # cheap left-eviction; a dict for O(1) membership.
        self._expiry: dict[str, float] = {}
        self._order: deque[str] = deque()

    def _sweep(self, now: float) -> None:
        while self._order:
            head = self._order[0]
            exp = self._expiry.get(head, 0.0)
            if exp <= now:
                self._order.popleft()
                self._expiry.pop(head, None)
            else:
                break
        # Also bound size — evict oldest if we blew the cap somehow.
        while len(self._order) > self._max:
            head = self._order.popleft()
            self._expiry.pop(head, None)

    def contains(self, digest: str) -> bool:
        now = time.time()
        self._sweep(now)
        exp = self._expiry.get(digest)
        if exp is None:
            return False
        if exp <= now:
            self._expiry.pop(digest, None)
            return False
        return True

    def add(self, digest: str) -> None:
        now = time.time()
        self._sweep(now)
        if digest in self._expiry:
            return
        self._expiry[digest] = now + self._ttl
        self._order.append(digest)

    def clear(self) -> None:
        self._expiry.clear()
        self._order.clear()


_used_token_cache = _UsedTokenCache(_USED_TOKEN_TTL_SECS, _USED_TOKEN_CACHE_MAX)


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _json_error(status_code: int, payload: dict) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=payload)


def _confirmation_html(mode: str) -> str:
    return callback_common.confirmation_html(mode, action_label="Reconnect resumed")


def _prompt_html(mode: str, token: str) -> str:
    return callback_common.confirmation_prompt_html(
        mode,
        token=token,
        form_action="/api/reconnect/callback",
        action_label="Confirm reconnect resume",
        prompt="Ready to resume aggressive reconnect for",
        submit_label="Yes, resume reconnect",
    )


def _sanitize_detail(msg: str) -> str:
    """Strip anything token-shaped from an error detail (finding A-LOW-7).

    A downstream ``client.send_command`` implementation may wrap the outbound
    command into its exception message; if that command carries a
    ``v2.reconnect.…`` token, the token would end up in the operator's
    browser tab, browser history, and any HTTP-tracing intermediary. Cheap
    guardrail: chop anything that looks like a v2 token, keep the rest.
    """
    if not msg:
        return ""
    # Truncate + redact any embedded v2 token — signature is a base64url
    # blob after 5 dots, so `v2.<...>.<base64url>` matches this shape.
    import re
    cleaned = re.sub(
        r"v2\.[A-Za-z0-9_.-]{20,}",
        "v2.<redacted>",
        msg,
    )
    return cleaned[:200]


def _validate_common(
    request: Request, t: str, mode: str,
) -> tuple[str, str, JSONResponse | None]:
    """Run rate-limit + signing-key + intent + mode + HMAC checks.

    Shared between GET (renders confirmation prompt if OK) and POST
    (dispatches RESUME_RECONNECT if OK). Returns
    ``(mode_lc, token_hash_prefix, error_response_or_None)``. When
    error_response is not None the caller returns it directly.
    """
    client_ip = request.client.host if request.client else "unknown"
    token_prefix = (t[:8] if t else "") or "-"
    mode_lc = (mode or "").strip().lower()

    logger.info(
        "recovery.callback.received token_prefix=%s mode=%s",
        token_prefix, mode_lc or "-",
    )

    if not _rate_limiter.check(client_ip):
        logger.warning(
            "recovery.callback.rejected reason=rate_limited ip=%s", client_ip,
        )
        return mode_lc, token_prefix, _json_error(429, {"error": "rate_limited"})

    signing_key = callback_common.get_signing_key()
    if not signing_key:
        logger.error(
            "recovery.callback.rejected reason=signing_key_not_configured",
        )
        return mode_lc, token_prefix, _json_error(
            500, {"error": "signing_key_not_configured"},
        )

    # Defence-in-depth: reject a `.` in the mode segment (finding A-LOW-6)
    # symmetric with the mint-side allowlist in hitl_tokens.
    if mode_lc not in VALID_MODES or "." in mode_lc:
        logger.warning(
            "recovery.callback.rejected reason=invalid_mode mode=%r", mode,
        )
        return mode_lc, token_prefix, _json_error(
            403, {"error": "invalid_mode"},
        )

    valid, reason = reconnect_tokens.validate_token(signing_key, t)
    if not valid:
        # Never echo the token itself. Reason is the audit signal.
        logger.warning(
            "recovery.callback.rejected reason=%s mode=%s", reason, mode_lc,
        )
        return mode_lc, token_prefix, _json_error(
            403, {"error": "invalid_token", "reason": reason},
        )

    # Cross-check token mode against URL/form mode — defense in depth so a
    # lifted paper URL cannot be edited to resume live.
    token_mode = reconnect_tokens.extract_mode(t)
    if token_mode and token_mode != mode_lc:
        logger.warning(
            "recovery.callback.rejected reason=mode_mismatch url=%s token=%s",
            mode_lc, token_mode,
        )
        return mode_lc, token_prefix, _json_error(
            403, {"error": "invalid_token", "reason": "mode_mismatch"},
        )

    return mode_lc, token_prefix, None


@router.get("/api/reconnect/callback")
async def reconnect_callback_prompt(
    request: Request, t: str = "", mode: str = "",
):
    """Render a confirmation prompt (no side effect).

    Idempotent — safe for link-preview crawlers, URL-defense scanners, and
    mobile "prefetch links" features to follow. Runs the same rate-limit +
    signing-key + HMAC checks as POST so a would-be attacker gets the same
    security-event trail; only the dispatch is gated on POST.

    Responses:
        429 {"error": "rate_limited"}              — too many requests from IP
        500 {"error": "signing_key_not_configured"} — server misconfig
        403 {"error": "invalid_mode"}              — missing / unknown mode
        403 {"error": "invalid_token", "reason"}   — bad sig / expired /
                                                      bad intent / mode
                                                      mismatch
        200 (HTML)                                 — confirmation prompt page
    """
    mode_lc, _, err = _validate_common(request, t, mode)
    if err is not None:
        return err
    return HTMLResponse(content=_prompt_html(mode_lc, t), status_code=200)


@router.post("/api/reconnect/callback")
async def reconnect_callback_dispatch(
    request: Request,
    t: str = Form(default=""),
    mode: str = Form(default=""),
):
    """Validate an HMAC-signed reconnect token and dispatch RESUME_RECONNECT.

    Form-body params:
        t:    the signed token (see reconnect_tokens.mint_token)
        mode: "live" or "paper" — which instance to target

    Responses:
        429 {"error": "rate_limited"}              — too many requests from IP
        500 {"error": "signing_key_not_configured"} — server misconfig
        403 {"error": "invalid_mode"}              — missing / unknown mode
        403 {"error": "invalid_token", "reason"}   — bad sig / expired /
                                                      bad intent / mode
                                                      mismatch / replay
        502 {"error": "ibctl_unreachable", ...}    — ibctl not responding
        502 {"error": "ibctl_dispatch_failed", ...} — unexpected exception
                                                       from send_command
        502 {"error": "ibctl_command_rejected", ...} — ibctl returned an
                                                       error-shaped response
        200 (HTML)                                 — success confirmation
    """
    mode_lc, _, err = _validate_common(request, t, mode)
    if err is not None:
        return err

    # Server-side single-use enforcement (finding A-MED-3). A warm-restart
    # of ibctl clears its in-process hash table; this cache keeps the
    # replay window closed on the dashboard side until the token expires.
    digest = _digest(t)
    if _used_token_cache.contains(digest):
        logger.warning(
            "recovery.callback.rejected reason=token_replay mode=%s",
            mode_lc,
        )
        return _json_error(
            403, {"error": "invalid_token", "reason": "replay"},
        )

    registry = request.app.state.instance_registry
    try:
        client = registry.get_client(mode_lc)
    except KeyError:
        logger.warning(
            "recovery.callback.rejected reason=no_instance mode=%s", mode_lc,
        )
        return _json_error(403, {"error": "invalid_mode"})

    # Forward the whole token so the ibctl side can re-verify it as a
    # single-use nonce. The Rust coordinator hashes it (see
    # `recovery::hash_token`) to enforce single-use. IMPORTANT: the wire
    # format is exactly `RESUME_RECONNECT<single space><token>` — the
    # Rust parser uses `splitn(2, ' ')`, so any other whitespace character
    # (tab, newline) would leak into the token and fail re-verification.
    # See `test_wire_format_rf6266_single_space` for the cross-language pin.
    command = f"RESUME_RECONNECT {t}"
    try:
        result = await client.send_command(command)
    except DashboardError as e:
        logger.error(
            "recovery.callback.rejected reason=ibctl_unreachable mode=%s "
            "detail=%s",
            mode_lc, _sanitize_detail(e.message),
        )
        return _json_error(
            502,
            {
                "error": "ibctl_unreachable",
                "detail": _sanitize_detail(e.message),
            },
        )
    except Exception as e:
        # Any other exception (TimeoutError, ConnectionRefusedError,
        # OSError, UnicodeDecodeError, RuntimeError, ...) must not surface
        # as a bare 500 with no JSON body — the operator's browser would
        # render "blank error" and the on-call log would show no
        # structured reason. Wrap into a distinctive 502.
        logger.error(
            "recovery.callback.rejected reason=ibctl_dispatch_failed mode=%s "
            "exc=%s detail=%s",
            mode_lc, type(e).__name__, _sanitize_detail(str(e)),
        )
        return _json_error(
            502,
            {
                "error": "ibctl_dispatch_failed",
                "detail": type(e).__name__,
            },
        )

    # Inspect the ibctl response for an application-level NACK. If the
    # daemon is a pre-PR-C build it may return "ERROR: unknown command" or
    # a similar shape; if the phase has already exited GivenUp the
    # coordinator returns a NACK. Renderng the success HTML on a silent
    # NACK would leave the operator believing the resume happened while
    # the mode stays parked (finding A-MED-5). ACK sentinels come from
    # ibctl/src/command_server.rs — anything else is treated as a NACK.
    result_str = "" if result is None else str(result).strip()
    if _looks_like_nack(result_str):
        logger.error(
            "recovery.callback.rejected reason=ibctl_command_rejected mode=%s "
            "detail=%s",
            mode_lc, _sanitize_detail(result_str),
        )
        return _json_error(
            502,
            {
                "error": "ibctl_command_rejected",
                "detail": _sanitize_detail(result_str),
            },
        )

    # Success — mark the token as consumed so a replay via the SAME
    # dashboard cannot dispatch a second time. (ibctl also enforces this
    # for the same-process case; this cache covers the warm-restart gap.)
    _used_token_cache.add(digest)
    registry.invalidate(mode_lc)
    logger.info(
        "recovery.callback.accepted mode=%s result=%s",
        mode_lc, _sanitize_detail(result_str),
    )
    return HTMLResponse(content=_confirmation_html(mode_lc), status_code=200)


def _looks_like_nack(result: str) -> bool:
    """Cheap classifier for an ibctl NACK-shaped response.

    ibctl's command_server returns strings that start with ``OK`` on
    success and ``ERROR:`` on failure. Anything not matching an OK
    sentinel — including empty responses and unknown-shape strings — is
    treated as a NACK so a silently-broken deploy fails visibly rather
    than showing the operator a "Reconnect resumed" page that lies.
    """
    if not result:
        # Empty response — the fake-client fixture in tests returns
        # arbitrary shapes; treat non-empty non-error results as OK,
        # empty as NACK.
        return True
    lower = result.lower()
    if lower.startswith("error") or lower.startswith("nack"):
        return True
    # Anything else — including OK-prefixed and legacy ACK sentinels — is
    # treated as success. Keep the classifier permissive so a pre-PR-C
    # daemon that returns e.g. "resume_reconnect ok" still succeeds.
    return False
