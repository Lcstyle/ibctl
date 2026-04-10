"""Web UI page routes — server-rendered via Jinja2 with HTMX live updates."""

from __future__ import annotations

import hmac
import logging
import os
from dataclasses import asdict
from urllib.parse import urlencode, parse_qs

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.domain.errors import DashboardError
from app.middleware.auth import (
    AUTH_COOKIE_NAME,
    OAUTH_COOKIE_NAME,
    OAUTH_STATE_COOKIE_NAME,
    build_oauth_session,
    build_oauth_state,
    parse_oauth_state,
)

logger = logging.getLogger("dashboard.pages")
router = APIRouter()

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_ORGS_URL = "https://api.github.com/user/orgs"


def _safe_next_path(next_path: str | None) -> str:
    if not next_path:
        return "/"
    if not next_path.startswith("/"):
        return "/"
    if next_path.startswith("//"):
        return "/"
    if next_path.startswith("/login"):
        return "/"
    return next_path


def _github_redirect_uri(request: Request) -> str:
    settings = request.app.state.settings
    if settings.github_redirect_uri:
        return settings.github_redirect_uri
    return str(request.url_for("github_oauth_callback"))


# --- Authentication pages ---


@router.get("/login", response_class=HTMLResponse, name="login_page")
async def login_page(request: Request, next: str | None = None):
    settings = request.app.state.settings
    if not settings.token and not settings.github_oauth_enabled and not settings.oidc_enabled:
        return RedirectResponse(url="/", status_code=303)

    templates = request.app.state.templates
    return templates.TemplateResponse(request, "login.html", {
        "next_path": _safe_next_path(next),
        "error": None,
        "github_oauth_enabled": settings.github_oauth_enabled,
        "oidc_enabled": settings.oidc_enabled,
    })


@router.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request):
    settings = request.app.state.settings
    token = settings.token
    if not token:
        return RedirectResponse(url="/", status_code=303)

    body = (await request.body()).decode("utf-8")
    form = parse_qs(body, keep_blank_values=True)
    password = form.get("password", [""])[0]
    next_path = _safe_next_path(form.get("next", ["/"])[0])

    if not hmac.compare_digest(password, token):
        templates = request.app.state.templates
        return templates.TemplateResponse(request, "login.html", {
            "next_path": next_path,
            "error": "Invalid password",
            "github_oauth_enabled": settings.github_oauth_enabled,
            "oidc_enabled": settings.oidc_enabled,
        }, status_code=401)

    response = RedirectResponse(url=next_path, status_code=303)
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/",
    )
    return response


# --- GitHub OAuth ---


async def _github_exchange_code(code: str, redirect_uri: str, settings) -> str:
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            GITHUB_TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret.get_secret_value(),
                "code": code,
                "redirect_uri": redirect_uri,
            },
        )
        resp.raise_for_status()
        payload = resp.json()
    access_token = payload.get("access_token", "")
    if not access_token:
        raise ValueError(payload.get("error_description") or "GitHub token exchange failed")
    return access_token


async def _github_fetch_user(access_token: str) -> dict:
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            GITHUB_USER_URL,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
        )
        resp.raise_for_status()
        return resp.json()


async def _github_fetch_orgs(access_token: str) -> list[str]:
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            GITHUB_ORGS_URL,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
            params={"per_page": "100"},
        )
        resp.raise_for_status()
        return [org.get("login", "") for org in resp.json() if org.get("login")]


def _github_user_allowed(settings, login: str, orgs: list[str]) -> bool:
    if settings.github_allowed_users and login not in settings.github_allowed_users:
        return False
    if settings.github_allowed_orgs and not set(orgs).intersection(settings.github_allowed_orgs):
        return False
    return True


@router.get("/auth/github", name="github_oauth_start")
async def github_oauth_start(request: Request, next: str | None = None):
    settings = request.app.state.settings
    if not settings.github_oauth_enabled:
        return RedirectResponse(url="/login", status_code=303)

    next_path = _safe_next_path(next)
    state = build_oauth_state(next_path, settings.auth_secret.get_secret_value())
    redirect_uri = _github_redirect_uri(request)
    scope = "read:user"
    if settings.github_allowed_orgs:
        scope = f"{scope} read:org"
    params = urlencode({
        "client_id": settings.github_client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
    })
    response = RedirectResponse(url=f"{GITHUB_AUTHORIZE_URL}?{params}", status_code=303)
    response.set_cookie(
        key=OAUTH_STATE_COOKIE_NAME,
        value=state,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/",
        max_age=600,
    )
    return response


@router.get("/auth/github/callback", response_class=HTMLResponse, name="github_oauth_callback")
async def github_oauth_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    settings = request.app.state.settings
    if not settings.github_oauth_enabled:
        return RedirectResponse(url="/login", status_code=303)

    cookie_state = request.cookies.get(OAUTH_STATE_COOKIE_NAME, "")
    state_payload = parse_oauth_state(state or "", settings.auth_secret.get_secret_value()) if state and state == cookie_state else None
    next_path = _safe_next_path(state_payload["next"]) if state_payload else "/"

    if error:
        templates = request.app.state.templates
        return templates.TemplateResponse(request, "login.html", {
            "next_path": next_path,
            "error": f"GitHub login failed: {error}",
            "github_oauth_enabled": True,
            "oidc_enabled": settings.oidc_enabled,
        }, status_code=401)

    if not state_payload or not code:
        templates = request.app.state.templates
        return templates.TemplateResponse(request, "login.html", {
            "next_path": "/",
            "error": "Invalid GitHub OAuth callback",
            "github_oauth_enabled": True,
            "oidc_enabled": settings.oidc_enabled,
        }, status_code=401)

    try:
        access_token = await _github_exchange_code(
            code=code,
            redirect_uri=_github_redirect_uri(request),
            settings=settings,
        )
        user = await _github_fetch_user(access_token)
        login = user.get("login", "")
        orgs = await _github_fetch_orgs(access_token) if settings.github_allowed_orgs else []
        if not login or not _github_user_allowed(settings, login, orgs):
            logger.warning(
                "GitHub OAuth login rejected: login=%r orgs=%s allowed_users=%s allowed_orgs=%s",
                login, orgs,
                list(settings.github_allowed_users),
                list(settings.github_allowed_orgs),
            )
            raise ValueError("GitHub account is not authorized for this dashboard")
    except (ValueError, httpx.HTTPError) as exc:
        templates = request.app.state.templates
        return templates.TemplateResponse(request, "login.html", {
            "next_path": next_path,
            "error": str(exc),
            "github_oauth_enabled": True,
            "oidc_enabled": settings.oidc_enabled,
        }, status_code=401)

    response = RedirectResponse(url=next_path, status_code=303)
    response.set_cookie(
        key=OAUTH_COOKIE_NAME,
        value=build_oauth_session(login, settings.auth_secret.get_secret_value()),
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/",
    )
    response.delete_cookie(OAUTH_STATE_COOKIE_NAME, path="/")
    return response


@router.post("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(AUTH_COOKIE_NAME, path="/")
    response.delete_cookie(OAUTH_COOKIE_NAME, path="/")
    response.delete_cookie(OAUTH_STATE_COOKIE_NAME, path="/")
    return response


# --- Generic OIDC (Authentik, Keycloak, etc.) ---


def _oidc_redirect_uri(request: Request) -> str:
    settings = request.app.state.settings
    if settings.oidc_redirect_uri:
        return settings.oidc_redirect_uri
    return str(request.url_for("oidc_callback"))


@router.get("/auth/oidc", name="oidc_start")
async def oidc_start(request: Request, next: str | None = None):
    settings = request.app.state.settings
    if not settings.oidc_enabled:
        return RedirectResponse(url="/login", status_code=303)

    # Discover OIDC endpoints from issuer
    discovery_url = f"{settings.oidc_issuer.rstrip('/')}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(discovery_url)
        resp.raise_for_status()
        oidc_config = resp.json()

    next_path = _safe_next_path(next)
    state = build_oauth_state(next_path, settings.auth_secret.get_secret_value())
    redirect_uri = _oidc_redirect_uri(request)
    params = urlencode({
        "client_id": settings.oidc_client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": settings.oidc_scopes,
        "state": state,
    })
    authorize_url = oidc_config["authorization_endpoint"]
    response = RedirectResponse(url=f"{authorize_url}?{params}", status_code=303)
    response.set_cookie(
        key=OAUTH_STATE_COOKIE_NAME,
        value=state,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/",
        max_age=600,
    )
    return response


@router.get("/auth/oidc/callback", response_class=HTMLResponse, name="oidc_callback")
async def oidc_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    settings = request.app.state.settings
    if not settings.oidc_enabled:
        return RedirectResponse(url="/login", status_code=303)

    cookie_state = request.cookies.get(OAUTH_STATE_COOKIE_NAME, "")
    state_payload = parse_oauth_state(state or "", settings.auth_secret.get_secret_value()) if state and state == cookie_state else None
    next_path = _safe_next_path(state_payload["next"]) if state_payload else "/"

    if error:
        templates = request.app.state.templates
        return templates.TemplateResponse(request, "login.html", {
            "next_path": next_path,
            "error": f"OIDC login failed: {error}",
            "github_oauth_enabled": settings.github_oauth_enabled,
            "oidc_enabled": settings.oidc_enabled,
        }, status_code=401)

    if not state_payload or not code:
        templates = request.app.state.templates
        return templates.TemplateResponse(request, "login.html", {
            "next_path": "/",
            "error": "Invalid OIDC callback",
            "github_oauth_enabled": settings.github_oauth_enabled,
            "oidc_enabled": settings.oidc_enabled,
        }, status_code=401)

    try:
        # Discover token endpoint
        discovery_url = f"{settings.oidc_issuer.rstrip('/')}/.well-known/openid-configuration"
        async with httpx.AsyncClient(timeout=10) as client:
            disc_resp = await client.get(discovery_url)
            disc_resp.raise_for_status()
            oidc_config = disc_resp.json()

        # Exchange code for tokens
        async with httpx.AsyncClient(timeout=10) as client:
            token_resp = await client.post(
                oidc_config["token_endpoint"],
                headers={"Accept": "application/json"},
                data={
                    "grant_type": "authorization_code",
                    "client_id": settings.oidc_client_id,
                    "client_secret": settings.oidc_client_secret.get_secret_value(),
                    "code": code,
                    "redirect_uri": _oidc_redirect_uri(request),
                },
            )
            token_resp.raise_for_status()
            tokens = token_resp.json()

        access_token = tokens.get("access_token", "")
        if not access_token:
            raise ValueError("OIDC token exchange failed")

        # Fetch userinfo
        async with httpx.AsyncClient(timeout=10) as client:
            user_resp = await client.get(
                oidc_config["userinfo_endpoint"],
                headers={"Authorization": f"Bearer {access_token}"},
            )
            user_resp.raise_for_status()
            userinfo = user_resp.json()

        # Extract identity — Authentik uses "preferred_username", "groups"
        username = (
            userinfo.get("preferred_username")
            or userinfo.get("email")
            or userinfo.get("sub", "")
        )
        groups = userinfo.get("groups", [])

        # Check allowlists
        if settings.oidc_allowed_users and username not in settings.oidc_allowed_users:
            logger.warning("OIDC login rejected: user=%r not in allowed_users", username)
            raise ValueError("User is not authorized for this dashboard")
        if settings.oidc_allowed_groups and not set(groups).intersection(settings.oidc_allowed_groups):
            logger.warning("OIDC login rejected: user=%r groups=%s not in allowed_groups", username, groups)
            raise ValueError("User's groups are not authorized for this dashboard")

    except (ValueError, httpx.HTTPError) as exc:
        templates = request.app.state.templates
        return templates.TemplateResponse(request, "login.html", {
            "next_path": next_path,
            "error": str(exc),
            "github_oauth_enabled": settings.github_oauth_enabled,
            "oidc_enabled": settings.oidc_enabled,
        }, status_code=401)

    response = RedirectResponse(url=next_path, status_code=303)
    response.set_cookie(
        key=OAUTH_COOKIE_NAME,
        value=build_oauth_session(username, settings.auth_secret.get_secret_value()),
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/",
    )
    response.delete_cookie(OAUTH_STATE_COOKIE_NAME, path="/")
    return response


# --- Page routes ---


@router.get("/", response_class=HTMLResponse)
async def overview_page(request: Request):
    templates = request.app.state.templates
    return templates.TemplateResponse(request, "overview.html", {"active_tab": "overview"})


@router.get("/state", response_class=HTMLResponse)
async def state_page(request: Request):
    templates = request.app.state.templates
    registry = request.app.state.instance_registry
    modes = registry.modes()
    # Default to paper if available, otherwise first mode
    default_mode = "paper" if "paper" in modes else modes[0]
    return templates.TemplateResponse(request, "state.html", {
        "active_tab": "state",
        "modes": modes,
        "default_mode": default_mode,
    })


@router.get("/config", response_class=HTMLResponse)
async def config_page(request: Request):
    templates = request.app.state.templates
    return templates.TemplateResponse(request, "config.html", {"active_tab": "config"})


@router.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    templates = request.app.state.templates
    return templates.TemplateResponse(request, "logs.html", {"active_tab": "logs"})


@router.get("/controls", response_class=HTMLResponse)
async def controls_page(request: Request):
    """Redirect to state machine tab (controls are integrated there now)."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/state")


@router.get("/ib-status", response_class=HTMLResponse)
async def ib_status_page(request: Request):
    templates = request.app.state.templates
    return templates.TemplateResponse(request, "ib_status.html", {"active_tab": "ib-status"})


@router.get("/notifications", response_class=HTMLResponse)
async def notifications_page(request: Request):
    templates = request.app.state.templates
    return templates.TemplateResponse(request, "notifications.html", {"active_tab": "notifications"})


@router.get("/vnc", response_class=HTMLResponse)
async def vnc_page(request: Request):
    templates = request.app.state.templates
    novnc_port = int(os.environ.get("IBCTL_NOVNC_PORT", "6080"))
    return templates.TemplateResponse(request, "vnc.html", {
        "active_tab": "vnc",
        "novnc_port": novnc_port,
        "vnc_password": os.environ.get("VNC_SERVER_PASSWORD", ""),
    })


# --- HTMX partial endpoints (polled by the UI for live updates) ---

@router.get("/partials/overview", response_class=HTMLResponse)
async def overview_partial(request: Request):
    registry = request.app.state.instance_registry
    templates = request.app.state.templates

    instances = registry.cached_all_status()
    instances_data = [
        {
            "mode": inst.mode,
            "status": inst.status or {"ready": False, "state": "unreachable"},
            "state_data": getattr(inst, 'state_data', None),
            "error": inst.error,
        }
        for inst in instances
    ]

    # IB Status data (if scraper is enabled)
    ib_data = None
    scraper_info = None
    monitor = getattr(request.app.state, 'ib_status_monitor', None)

    if monitor:
        scraper_info = {
            "running": monitor._task is not None and not monitor._task.done(),
            "url": monitor._scraper.config.url,
            "region": monitor._scraper.config.region,
            "interval": monitor._interval,
            "last_pushed_status": monitor._last_pushed_status,
            "last_fetch_error": None,
            "internet_ok": True,
            "ib_reachable": True,
        }

        ib_data = {
            "status": scraper_info["last_pushed_status"],
            "reason": "",
            "alerts": [],
        }

        if monitor._scraper._last_status:
            scraper_status = monitor._scraper._last_status
            scraper_info["last_fetch_error"] = scraper_status.fetch_error
            scraper_info["internet_ok"] = scraper_status.status.value != "no_internet"
            scraper_info["ib_reachable"] = scraper_status.status.value != "unknown"
            ib_data["status"] = scraper_status.status.value
            ib_data["reason"] = ""
            ib_data["alerts"] = [
                {"severity": a.severity.value, "message": a.message, "is_blocking": a.is_blocking()}
                for a in scraper_status.alerts
            ]

    # Site config from first instance status
    site_config = None
    if instances_data:
        first_status = instances_data[0].get("status", {}) or {}
        site_role = first_status.get("site_role", "primary")
        auto_launch = first_status.get("auto_launch", True)
        site_config = {"role": site_role, "auto_launch": auto_launch}

    return templates.TemplateResponse(request, "partials/overview_content.html", {
        "instances": instances_data,
        "ib_status": ib_data,
        "scraper_info": scraper_info,
        "site_config": site_config,
    })


@router.get("/partials/state-history", response_class=HTMLResponse)
async def state_history_partial(request: Request, mode: str | None = None):
    registry = request.app.state.instance_registry
    templates = request.app.state.templates

    # Use requested mode or default to primary
    target_mode = mode or registry.primary_mode()
    client = registry.get_client(target_mode)

    # Read STATE from cache (populated by SSE background task every 2s)
    cached_state = await registry.cached_command(target_mode, "STATE", registry.STATUS_TTL)
    if cached_state:
        state_dict = cached_state
    else:
        # Fallback: cache miss (startup or first load)
        try:
            state = await client.state()
            state_dict = asdict(state)
        except DashboardError:
            state_dict = {"current": "unreachable", "history": []}

    # Convert epoch timestamps to local time
    from datetime import datetime
    from zoneinfo import ZoneInfo
    tz_name = os.environ.get("TZ", "America/New_York")
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = ZoneInfo("America/New_York")
    for t in state_dict.get("history", []):
        try:
            epoch = int(t.get("timestamp", 0))
            if epoch > 1000000000:
                t["timestamp"] = datetime.fromtimestamp(epoch, tz=tz).strftime("%I:%M:%S %p")
        except (ValueError, TypeError):
            pass

    return templates.TemplateResponse(request, "partials/state_content.html", {
        "state": state_dict,
    })


@router.get("/partials/config", response_class=HTMLResponse)
async def config_partial(request: Request):
    registry = request.app.state.instance_registry
    templates = request.app.state.templates

    try:
        # Use cached config (5 min TTL) — config doesn't change at runtime
        config_data = await registry.cached_config(registry.primary_mode())
        if config_data is None:
            client = registry.get_client(registry.primary_mode())
            config = await client.config()
            config_data = asdict(config)
        config = type('Config', (), {'__getattr__': lambda s, k: config_data.get(k, {})})()
    except (DashboardError, Exception) as e:
        return templates.TemplateResponse(request, "partials/config_content.html", {
            "error": e.message, "config": {}, "env_vars": {},
        })

    # Collect relevant env vars for display
    relevant_prefixes = ("TWS_", "TRADING_", "TWOFA", "IBCTL_", "BYPASS_", "READ_ONLY",
                         "ALLOW_BLIND", "AUTO_RESTART", "AUTO_LOGOFF", "JAVA_HEAP",
                         "EXISTING_SESSION", "VNC_", "TZ", "DISPLAY", "GATEWAY_OR")
    env_vars = {k: v for k, v in sorted(os.environ.items()) if any(k.startswith(p) for p in relevant_prefixes)}

    return templates.TemplateResponse(request, "partials/config_content.html", {
        "config": config,
        "env_vars": env_vars,
    })


@router.get("/partials/logs", response_class=HTMLResponse)
async def logs_partial(
    request: Request,
    source: str = "ibctl",
    date: str | None = None,
    level: str | None = None,
):
    import json as jsonlib
    import os
    from pathlib import Path
    from app.services.market_day_logging import get_market_day_date

    templates = request.app.state.templates
    log_dir = os.environ.get("IBCTL_LOG_DIR", "/opt/ibctl/persist/logs")
    prefixes = {
        "ibctl-live": "ibctl-live-",
        "ibctl-paper": "ibctl-paper-",
        "ibctl": "ibctl-",
        "dashboard": "dashboard-",
    }
    prefix = prefixes.get(source, "ibctl-")

    if date is None:
        date = get_market_day_date()

    log_path = Path(log_dir) / f"{prefix}{date}.log"
    lines = []
    if log_path.exists():
        try:
            with open(log_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                chunk = min(size, 200 * 512)
                f.seek(max(0, size - chunk))
                data = f.read().decode("utf-8", errors="replace")
                lines = data.splitlines()[-200:]
        except Exception:
            lines = []

    # Parse JSON log lines into structured entries.
    # Convert UTC timestamps to local time (display layer — Axiom 3).
    from datetime import datetime as dt
    from zoneinfo import ZoneInfo
    tz_name = os.environ.get("TZ", "America/New_York")
    try:
        local_tz = ZoneInfo(tz_name)
    except Exception:
        local_tz = ZoneInfo("America/New_York")

    def utc_to_local(ts_str: str) -> str:
        """Convert a UTC ISO timestamp to local time for display."""
        if not ts_str:
            return ts_str
        try:
            # Handle both "2026-04-09T13:41:34.842Z" and "2026-04-09T13:41:34"
            clean = ts_str.rstrip("Z")
            parsed = dt.fromisoformat(clean).replace(tzinfo=ZoneInfo("UTC"))
            local = parsed.astimezone(local_tz)
            return local.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ts_str

    logs = []
    for line in lines:
        try:
            entry = jsonlib.loads(line)
            lvl = entry.get("level", "INFO").upper()
            filter_lvl = level.upper() if level else None
            # Normalize WARN/WARNING mismatch (Rust uses WARN, Python uses WARNING)
            if lvl == "WARN":
                lvl = "WARNING"
            if filter_lvl and lvl != filter_lvl:
                continue
            logs.append({
                "timestamp": utc_to_local(entry.get("ts", "")),
                "level": lvl,
                "message": entry.get("msg", line),
            })
        except (jsonlib.JSONDecodeError, ValueError):
            if level:
                continue
            logs.append({"timestamp": "", "level": "INFO", "message": line})

    # Get available dates for the date picker
    dates = []
    dir_path = Path(log_dir)
    if dir_path.exists():
        for f in sorted(dir_path.glob(f"{prefix}*.log"), reverse=True):
            name = f.stem
            if name.startswith(prefix):
                dates.append(name[len(prefix):])

    return templates.TemplateResponse(request, "partials/logs_content.html", {
        "logs": logs,
        "source": source,
        "date": date,
        "dates": dates,
    })


@router.get("/partials/ib-status", response_class=HTMLResponse)
async def ib_status_partial(request: Request):
    registry = request.app.state.instance_registry
    templates = request.app.state.templates

    # Get IB status from the scraper
    monitor = getattr(request.app.state, 'ib_status_monitor', None)
    scraper_status = None
    scraper_info = {
        "running": False, "url": "", "region": "NA", "interval": 300,
        "last_pushed_status": "unknown", "last_fetch_error": None,
        "internet_ok": True, "ib_reachable": True,
    }

    if monitor:
        scraper_info["running"] = monitor._task is not None and not monitor._task.done()
        scraper_info["url"] = monitor._scraper.config.url
        scraper_info["region"] = monitor._scraper.config.region
        scraper_info["interval"] = monitor._interval
        scraper_info["last_pushed_status"] = monitor._last_pushed_status
        scraper_info["override_active"] = monitor.override_active
        scraper_info["override_status"] = monitor.override_status
        scraper_info["override_reason"] = monitor.override_reason

        # Get last scraped status
        if monitor._scraper._last_status:
            scraper_status = monitor._scraper._last_status
            scraper_info["last_fetch_error"] = scraper_status.fetch_error
            scraper_info["internet_ok"] = scraper_status.status.value != "no_internet"
            scraper_info["ib_reachable"] = scraper_status.status.value != "unknown"

    # Build IB status dict for template
    ib_data = {
        "status": scraper_info["last_pushed_status"],
        "reason": "",
        "alerts": [],
        "daily_resets": [],
        "weekend_resets": [],
    }

    if scraper_status:
        ib_data["status"] = scraper_status.status.value
        ib_data["alerts"] = [
            {"severity": a.severity.value, "message": a.message, "is_blocking": a.is_blocking()}
            for a in scraper_status.alerts
        ]
        ib_data["daily_resets"] = [
            {"region": w.region, "start_time": w.start_time.strftime("%H:%M"), "end_time": w.end_time.strftime("%H:%M"), "timezone": w.timezone}
            for w in scraper_status.daily_resets
        ]
        ib_data["weekend_resets"] = [
            {"region": w.region, "start_time": w.start_time.strftime("%H:%M"), "end_time": w.end_time.strftime("%H:%M"), "timezone": w.timezone}
            for w in scraper_status.weekend_resets
        ]

    # Get per-instance ib_system from ibctl (cache read, no TCP)
    instances = registry.cached_all_status()
    instances_data = [
        {"mode": i.mode, "status": i.status, "error": i.error}
        for i in instances
    ]

    return templates.TemplateResponse(request, "partials/ib_status_content.html", {
        "ib_status": ib_data,
        "scraper_info": scraper_info,
        "instances": instances_data,
    })
