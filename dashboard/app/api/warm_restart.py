"""Warm restart now, over the API: `POST` it, `GET` how it went.

Token clients and signed-in people both come through here. A token reaches it
only if it is a Warm restart client token and that type is enabled on the API
access page (the auth middleware checks both); a signed-in person needs no
tick, and uses it from the Warm restart button. Either way the same minimum
interval applies.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.middleware.auth import client_ip
from app.services.api_access import ApiAccessError
from app.services.warm_restart import VALID_MODES, WarmRestartRefused, log_rejected

logger = logging.getLogger("dashboard.api_access")
router = APIRouter()

URL = "/api/v1/warm-restart"

_STATUS = {
    "invalid_request": 422,
    "rate_limited": 429,
    "blocked_by_ibctl": 403,
    "ibctl_refused": 502,
    "ibctl_unavailable": 503,
}


def _caller(request: Request) -> str:
    """Who is asking, for the log: the signed-in person, else the token's name."""
    login = getattr(request.state, "login", None)
    if login is not None:
        return login.name
    token = getattr(request.state, "api_token", None)
    return token.name if token is not None else "unknown"


def _error(refusal: WarmRestartRefused, status: int | None = None) -> JSONResponse:
    body: dict = {"error": refusal.reason, "detail": refusal.detail}
    headers = {}
    if refusal.retry_after_s is not None:
        body = {"error": refusal.reason, "retry_after_s": refusal.retry_after_s}
        headers["Retry-After"] = str(refusal.retry_after_s)
    return JSONResponse(status_code=status or _STATUS[refusal.reason], content=body, headers=headers)


def _unreadable(exc: ApiAccessError) -> JSONResponse:
    logger.error("Warm restart refused: %s", exc)
    return JSONResponse(
        status_code=503,
        content={"error": "api_access_unreadable", "detail": "The dashboard's saved API access settings cannot be read."},
    )


async def _mode_from_body(request: Request) -> str:
    """The one argument. Anything else in the request is refused, not ignored."""
    if not request.headers.get("content-type", "").lower().startswith("application/json"):
        raise _Malformed(415, "send the request as application/json")
    try:
        body = await request.json()
    except ValueError:
        raise _Malformed(400, "the body is not valid JSON") from None
    if not isinstance(body, dict):
        raise _Malformed(422, 'the body must be an object like {"mode": "paper"}')
    extra = sorted(set(body) - {"mode"})
    if extra:
        raise _Malformed(422, f"only mode is accepted, not {', '.join(extra)}")
    mode = body.get("mode")
    if mode not in VALID_MODES:
        raise _Malformed(422, 'mode is required and must be "live" or "paper"')
    return mode


class _Malformed(WarmRestartRefused):
    def __init__(self, status: int, detail: str):
        super().__init__("invalid_request", detail)
        self.status = status


@router.post(URL)
async def warm_restart(request: Request):
    """Warm restart one Gateway now. Body: `{"mode": "live" | "paper"}`."""
    actor, ip = _caller(request), client_ip(request)
    try:
        mode = await _mode_from_body(request)
    except _Malformed as refusal:
        log_rejected(actor, ip, None, refusal.reason, refusal.detail)
        return _error(refusal, refusal.status)
    try:
        accepted = await request.app.state.warm_restart.request(mode, actor=actor, ip=ip)
    except WarmRestartRefused as refusal:  # already logged
        return _error(refusal)
    except ApiAccessError as exc:
        return _unreadable(exc)
    return JSONResponse(
        status_code=202, content={"mode": accepted.mode, "scheduled_for": accepted.scheduled_for}
    )


@router.get(URL)
async def warm_restart_outcome(request: Request, mode: str | None = None):
    """The mode's last warm restart and what became of it."""
    actor, ip = _caller(request), client_ip(request)
    service = request.app.state.warm_restart
    try:
        service.check_mode(mode)
        body = await service.outcome(mode)
    except WarmRestartRefused as refusal:
        log_rejected(actor, ip, mode, refusal.reason, refusal.detail)
        return _error(refusal)
    except ApiAccessError as exc:
        return _unreadable(exc)
    logger.debug("Warm restart outcome read: mode=%s by=%s ip=%s", mode, actor, ip)
    return JSONResponse(content=body, headers={"Cache-Control": "no-store"})
