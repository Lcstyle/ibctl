"""The API access page: named API tokens, their types and which types are on.

Login-only, like every page. Forms post urlencoded, as the login form does.
A new token's secret is rendered in the response to the request that created it
and nowhere else: not in a redirect, not in the saved file, not in the log.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.middleware.auth import client_ip
from app.services.api_access import (
    MAX_INTERVAL_MINUTES,
    MIN_INTERVAL_MINUTES,
    TOKEN_TYPES,
    ApiAccessError,
    TokenError,
    find_token_type,
)
from app.urls import app_url

logger = logging.getLogger("dashboard.api_access")
router = APIRouter()


def _actor(request: Request) -> str:
    login = getattr(request.state, "login", None)
    return login.name if login else "dashboard user"


def _utc(epoch: float | None) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


async def _types(request: Request, modes: list[str]) -> list[dict]:
    """Each token type with its tick and, where it needs an ibctl command, what ibctl's own allow-list says."""
    store = request.app.state.api_access
    reader = request.app.state.ibctl_access
    accesses = await asyncio.gather(*(reader.read(mode, fresh=True) for mode in modes))
    rows = []
    for token_type in TOKEN_TYPES:
        verdicts = (
            {a.mode: a.blocks(token_type.ibctl_command) for a in accesses} if token_type.ibctl_command else {}
        )
        blocked = [m for m, v in verdicts.items() if v is True]
        unread = [m for m, v in verdicts.items() if v is None]
        rows.append({
            "name": token_type.name,
            "label": token_type.label,
            "description": token_type.description,
            "ibctl_command": token_type.ibctl_command,
            "ticked": store.is_enabled(token_type.name),
            "blocked": bool(blocked),
            "blocked_on": "" if len(blocked) == len(modes) else " on " + ", ".join(m.upper() for m in blocked),
            "unread": [m.upper() for m in unread],
        })
    return rows


async def _render(request: Request, status: int = 200, **extra):
    store = request.app.state.api_access
    modes = request.app.state.instance_registry.modes()
    context = {
        "active_tab": "api-access",
        "modes": modes,
        "min_interval": MIN_INTERVAL_MINUTES,
        "max_interval": MAX_INTERVAL_MINUTES,
        "file_error": "",
        "tokens": [],
        "types": [],
        "chosen_type": "",
        "intervals": {},
        "last_accepted": {},
        **extra,
    }
    try:
        context["tokens"] = [
            {
                "name": t.name,
                "type": t.type,
                "type_label": known.label if (known := find_token_type(t.type)) else t.type,
                "created": _utc(t.created_at),
                "created_by": t.created_by,
            }
            for t in store.list_tokens()
        ]
        context["types"] = await _types(request, modes)
        context["intervals"] = {m: store.min_interval_minutes(m) for m in modes}
        context["last_accepted"] = {
            m: _utc((store.warm_restart_record(m) or {}).get("accepted_at")) for m in modes
        }
    except ApiAccessError as exc:
        logger.error("API access page: %s", exc)
        context["file_error"] = str(exc)
        status = 500
    response = request.app.state.templates.TemplateResponse(request, "api_access.html", context, status_code=status)
    response.headers["Cache-Control"] = "no-store"
    return response


def _redirect(request: Request, query: str = "") -> RedirectResponse:
    return RedirectResponse(url=app_url(request, f"/api-access{query}"), status_code=303)


async def _form(request: Request) -> dict[str, list[str]]:
    return parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)


@router.get("/api-access", response_class=HTMLResponse, name="api_access_page")
async def api_access_page(request: Request, revoked: str | None = None, saved: str | None = None):
    notice = ""
    if revoked:
        notice = f"Token {revoked!r} revoked. Clients using it now get a 401."
    elif saved:
        notice = "Saved."
    return await _render(request, notice=notice)


@router.post("/api-access/tokens", response_class=HTMLResponse)
async def create_token(request: Request):
    form = await _form(request)
    name = form.get("name", [""])[0]
    chosen = form.get("type", [""])[0]
    if find_token_type(chosen) is None:
        return await _render(
            request, status=400, error="Choose the type of token: what it is for.", name=name, chosen_type=chosen
        )
    try:
        token, secret = request.app.state.api_access.create_token(name, created_by=_actor(request), token_type=chosen)
    except TokenError as exc:
        duplicate = "already exists" in str(exc)
        return await _render(request, status=409 if duplicate else 400, error=str(exc), name=name, chosen_type=chosen)
    except ApiAccessError as exc:
        return await _render(request, error=str(exc))
    logger.info(
        "API token created: name=%r type=%s by=%s ip=%s", token.name, token.type, _actor(request), client_ip(request)
    )
    return await _render(request, new_token=secret, new_token_name=token.name)


@router.post("/api-access/tokens/{name}/revoke")
async def revoke_token(request: Request, name: str):
    try:
        revoked = request.app.state.api_access.revoke_token(name)
    except ApiAccessError as exc:
        return await _render(request, error=str(exc))
    if not revoked:
        return await _render(request, status=404, error=f"There is no token named {name!r}.")
    logger.info("API token revoked: name=%r by=%s ip=%s", name, _actor(request), client_ip(request))
    return _redirect(request, f"?revoked={name}")


@router.post("/api-access/settings")
async def save_settings(request: Request):
    store = request.app.state.api_access
    modes = request.app.state.instance_registry.modes()
    form = await _form(request)

    intervals: dict[str, int] = {}
    for mode in modes:
        if f"interval_{mode}" not in form:
            continue
        try:
            intervals[mode] = int(form[f"interval_{mode}"][0])
        except ValueError:
            return await _render(request, status=400, error=f"The {mode.upper()} interval must be a whole number of minutes.")

    try:
        # A box ibctl blocks is greyed out, and a browser does not submit a
        # greyed-out box: keep what was saved for those.
        ticked = {t.name for t in TOKEN_TYPES if form.get(f"allow_{t.name}", [""])[0] == "on"}
        for row in await _types(request, modes):
            if row["blocked"]:
                ticked.discard(row["name"])
                if row["ticked"]:
                    ticked.add(row["name"])
        if intervals:
            store.set_min_interval_minutes(intervals)
        store.set_enabled(ticked)
    except ValueError as exc:
        return await _render(request, status=400, error=str(exc))
    except ApiAccessError as exc:
        return await _render(request, error=str(exc))
    logger.info(
        "API access settings saved: enabled_types=%s min_interval_minutes=%s by=%s ip=%s",
        sorted(ticked), intervals, _actor(request), client_ip(request),
    )
    return _redirect(request, "?saved=1")
