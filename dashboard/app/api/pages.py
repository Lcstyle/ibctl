"""Web UI page routes — server-rendered via Jinja2 with HTMX live updates."""

from __future__ import annotations

import hmac
import json
import logging
import os
from dataclasses import asdict
from pathlib import Path
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


# --- Pkl-canonical field descriptions ---
# Read once at module load. The renderer at ``tools/renderers/toml_renderer.py``
# writes this file alongside ``docker/ibctl.toml`` — it maps ``<section>.<key>``
# (dotted TOML path) to the Pkl ``///`` doc comment for that field. Missing at
# dev time (before ``make regenerate-configs`` has ever run) is not fatal:
# tooltips just degrade to no hover text.
_DESCRIPTIONS_PATH = Path(__file__).resolve().parents[1] / "preflight" / "descriptions.json"


def _load_field_descriptions() -> dict[str, str]:
    try:
        with _DESCRIPTIONS_PATH.open("r", encoding="utf-8") as f:
            payload = json.load(f)
        if not isinstance(payload, dict):
            logger.warning(
                "descriptions.json at %s is not a JSON object; ignoring",
                _DESCRIPTIONS_PATH,
            )
            return {}
        # Coerce values to str — the file is generated but defensively guard
        # against a hand-edited malformed entry.
        return {str(k): str(v) for k, v in payload.items()}
    except FileNotFoundError:
        logger.warning(
            "descriptions.json not found at %s — config-page tooltips will be "
            "empty. Run `make regenerate-configs` to emit it.",
            _DESCRIPTIONS_PATH,
        )
        return {}
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read descriptions.json: %s", exc)
        return {}


FIELD_DESCRIPTIONS: dict[str, str] = _load_field_descriptions()

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


@router.get("/gateway", response_class=HTMLResponse)
async def gateway_page(request: Request):
    templates = request.app.state.templates
    return templates.TemplateResponse(request, "gateway.html", {"active_tab": "gateway"})


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
        # queries.rs emits site as a nested object (see ibctl/src/state_machine/queries.rs:242
        # and :387): {"site": {"role": ..., "auto_launch": ...}}. Reading site_role /
        # auto_launch at the top level silently fell back to the "primary" / True defaults on
        # every standby node, which is why the Deployment Site card always displayed
        # "primary + auto-launch on boot" even when config.site.role was Standby.
        site = first_status.get("site", {}) or {}
        role = site.get("role", "primary")
        auto_launch = site.get("auto_launch", True)
        site_config = {"role": role, "auto_launch": auto_launch}

    # Gateway version card: the same view the JSON endpoint serves, plus
    # Eastern-time display strings for its two instants.
    gateway_version = None
    gv_service = getattr(request.app.state, "gateway_version", None)
    if gv_service is not None:
        from app.services.gateway_version.monitor import _today_et
        from app.services.gateway_version.view import et_display, version_view
        gv_state, gv_next = gv_service.current(), gv_service.next_check()
        gateway_version = version_view(gv_state, today=_today_et(), next_check=gv_next)
        gateway_version["checked_display"] = et_display(gv_state.checked_at)
        gateway_version["next_display"] = et_display(gv_next)

    return templates.TemplateResponse(request, "partials/overview_content.html", {
        "instances": instances_data,
        "ib_status": ib_data,
        "scraper_info": scraper_info,
        "site_config": site_config,
        "gateway_version": gateway_version,
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
    """Dynamic config display — reads TOML + env vars locally, no TCP round-trip.

    Contract: template always receives {"error": str|None, "sections": list}.
    On failure, sections=[] and error describes the problem.
    """
    templates = request.app.state.templates
    config_logger = logging.getLogger("dashboard.api.config")

    try:
        # Read config locally — we're in the same container, no need for TCP
        config_data = _load_local_config()
        sections = _build_config_groups(config_data)
    except Exception:
        config_logger.exception("Failed to load local config for display")
        return templates.TemplateResponse(request, "partials/config_content.html", {
            "error": "Failed to load configuration — check dashboard logs",
            "sections": [],
        })

    return templates.TemplateResponse(request, "partials/config_content.html", {
        "error": None,
        "sections": sections,
    })


def _load_local_config() -> dict:
    """Load ibctl config from TOML file + env var overrides.

    Reads the same TOML the Rust binary loads, applies the same env var
    overlay the preflight validator uses. No TCP needed — we're local.
    """
    from app.services import effective_config

    # The TOML with the env overrides applied (same logic as preflight)
    config = effective_config.load()

    # Add env-only values that don't appear in TOML
    env_only = {}
    for env_key, (label, _description) in ENV_ONLY_SETTINGS.items():
        val = os.environ.get(env_key)
        if val is not None and val != "":
            env_only[label] = val
    if env_only:
        config["environment"] = env_only

    return config


# Env vars with no TOML key, shown under "Runtime" when set: label, tooltip.
ENV_ONLY_SETTINGS: dict[str, tuple[str, str]] = {
    "TZ": ("Timezone", "Time zone of the container (an IANA name such as America/New_York). (env: TZ)"),
    "AUTO_RESTART_TIME": (
        "Auto Restart Time",
        "The Gateway's daily auto restart time, applied to its API settings. The session-down "
        "alert holds off when an outage starts at it. (env: AUTO_RESTART_TIME)",
    ),
    "READ_ONLY_API": ("Read-Only API", "Applied to the Gateway's API settings: the API accepts no orders. (env: READ_ONLY_API)"),
    "BYPASS_WARNING": (
        "Bypass Warnings",
        "Applied to the Gateway's API settings: bypass order precautions, so API orders skip "
        "the Gateway's warning dialogs. (env: BYPASS_WARNING)",
    ),
    "ALLOW_BLIND_TRADING": (
        "Allow Blind Trading",
        "Applied to the Gateway's API settings: allow orders for contracts without market data. "
        "(env: ALLOW_BLIND_TRADING)",
    ),
    "TWS_MASTER_CLIENT_ID": (
        "Master Client ID",
        "Applied to the Gateway's API settings: the API client ID that receives every client's "
        "orders and executions. (env: TWS_MASTER_CLIENT_ID)",
    ),
    "VNC_SERVER_PASSWORD": ("VNC Password", "Password of the VNC server. (env: VNC_SERVER_PASSWORD)"),  # pragma: allowlist secret
    "JAVA_HEAP_SIZE": ("Java Heap Size", "Gateway JVM heap in MB; overrides gateway.java_heap_size. (env: JAVA_HEAP_SIZE)"),
    "IBCTL_KICK_LIVE_SESSION_OK": (
        "Kick Live Session OK",
        "Preflight escape hatch: allows ib_status.kick_active_session with live trading, where a "
        "status-page blip can end an authenticated live session. (env: IBCTL_KICK_LIVE_SESSION_OK)",
    ),
    "IBCTL_STANDBY_AUTO_LAUNCH_OK": (
        "Standby Auto Launch OK",
        "Preflight escape hatch: allows a standby site to launch its Gateway at boot, racing the "
        "primary for the IB session. For hot-standby setups that coordinate this themselves. "
        "(env: IBCTL_STANDBY_AUTO_LAUNCH_OK)",
    ),
    "IBCTL_RECOVERY_DISABLED": (
        "Recovery Disabled",
        "Turns the reconnect recovery coordinator off; the inverse of timing.recovery.enabled. "
        "(env: IBCTL_RECOVERY_DISABLED)",
    ),
    "IBCTL_RECOVERY_FORCE_RESET": (
        "Recovery Force Reset",
        "Clears the recovery coordinator's saved give-up state when ibctl starts. "
        "(env: IBCTL_RECOVERY_FORCE_RESET)",
    ),
}
ENV_ONLY_DESCRIPTIONS = {f"environment.{label}": text for label, text in ENV_ONLY_SETTINGS.values()}


# Sub-section labels within each group
SECTION_LABELS = {
    "auth": "Account",
    "twofa": "2FA + HITL Backoff",
    "gateway": "Gateway",
    "session": "Session",
    "command_server": "Command Server",
    "agent": "Agent",
    "dashboard": "Dashboard",
    "ib_system_status": "IB Status Scraper",
    "logging": "Logging",
    "timing": "Timing + TCP Probe",
    "ib_status": "IB Status Policy",
    "site": "Site / Failover",
    "environment": "Runtime",
}


def _build_config_groups(config_data: dict) -> list[dict]:
    """Group config sections into collapsible accordion panels."""
    SECRET_KEYS = {"password", "secret", "token"}

    # Logical groupings: (group_label, group_key, [toml_sections], default_open)
    GROUPS = [
        ("Identity & Auth", "identity", ["environment", "auth", "twofa"], True),
        ("Gateway & Network", "gateway", ["gateway", "session", "command_server", "agent"], False),
        ("Dashboard & Alerts", "dashboard", ["dashboard", "ib_system_status"], False),
        ("Tuning & Operations", "tuning", ["timing", "logging", "ib_status", "site"], False),
    ]


    groups = []
    for group_label, group_key, section_keys, default_open in GROUPS:
        subsections = []
        for sk in section_keys:
            section_data = config_data.get(sk)
            if not isinstance(section_data, dict) or not section_data:
                continue
            items = _extract_items(sk, section_data, SECRET_KEYS)
            if items:
                subsections.append({
                    "label": SECTION_LABELS.get(sk, sk),
                    "items": items,
                })

        if subsections:
            # Summary line for the accordion header
            summary = _build_group_summary(group_key, config_data)
            groups.append({
                "key": group_key,
                "label": group_label,
                "summary": summary,
                "subsections": subsections,
                "default_open": default_open,
            })

    return groups


def _extract_items(
    section_name: str, section_data: dict, secret_keys: set
) -> list[dict]:
    """Extract key-value items from a config section, flattening one level.

    ``section_name`` is the TOML section (e.g. ``"twofa"`` or
    ``"twofa.backoff"``) — used to look each field's Pkl-canonical description
    up in ``FIELD_DESCRIPTIONS`` by dotted path. Every returned item carries
    a ``description`` field: ``str`` when the descriptions.json entry exists,
    ``None`` otherwise. The template guards on truthiness so ``None`` never
    leaks as ``title="None"``.
    """
    items = []
    for key, value in section_data.items():
        if isinstance(value, dict):
            for sub_key, sub_val in value.items():
                display_key = f"{key}.{sub_key}"
                masked = any(s in sub_key.lower() for s in secret_keys)
                # Sub-section fields live under ``section_name.key.sub_key`` in
                # descriptions.json (e.g. ``twofa.backoff.max_immediate_attempts``).
                dotted = f"{section_name}.{key}.{sub_key}"
                items.append({
                    "key": display_key,
                    "value": "********" if masked and sub_val else _format_val(sub_val),
                    "masked": masked,
                    "description": FIELD_DESCRIPTIONS.get(dotted) or ENV_ONLY_DESCRIPTIONS.get(dotted),
                })
        else:
            masked = any(s in key.lower() for s in secret_keys)
            dotted = f"{section_name}.{key}"
            items.append({
                "key": key,
                "value": "********" if masked and value else _format_val(value),
                "masked": masked,
                "description": FIELD_DESCRIPTIONS.get(dotted) or ENV_ONLY_DESCRIPTIONS.get(dotted),
            })
    return items


def _build_group_summary(group_key: str, config: dict) -> str:
    """One-line summary for the accordion header."""
    if group_key == "identity":
        mode = config.get("auth", {}).get("trading_mode", "?")
        user = config.get("auth", {}).get("tws_userid", "?")
        return f"{mode} — {user}"
    if group_key == "gateway":
        program = config.get("gateway", {}).get("gateway_or_tws", "gateway")
        heap = config.get("gateway", {}).get("java_heap_size", "?")
        return f"{program} — {heap}MB heap"
    if group_key == "dashboard":
        enabled = config.get("dashboard", {}).get("enabled", False)
        port = config.get("dashboard", {}).get("port", "?")
        return f"{'enabled' if enabled else 'disabled'} — port {port}" if enabled else "disabled"
    if group_key == "tuning":
        role = config.get("site", {}).get("role", "primary")
        level = config.get("logging", {}).get("level", "info")
        return f"site={role} — log={level}"
    return ""


def _format_val(v) -> str:
    """Format a config value for display."""
    if v is None or v == "":
        return "—"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, list):
        return ", ".join(str(x) for x in v) if v else "—"
    return str(v)


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
