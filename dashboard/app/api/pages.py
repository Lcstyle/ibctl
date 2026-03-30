"""Web UI page routes — server-rendered via Jinja2 with HTMX live updates."""

from __future__ import annotations

import logging
import os
from dataclasses import asdict

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.domain.errors import DashboardError

logger = logging.getLogger("dashboard.pages")
router = APIRouter()


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
    templates = request.app.state.templates
    registry = request.app.state.instance_registry
    modes = registry.modes()
    default_mode = "paper" if "paper" in modes else modes[0]
    return templates.TemplateResponse(request, "controls.html", {
        "active_tab": "controls",
        "modes": modes,
        "default_mode": default_mode,
    })


@router.get("/vnc", response_class=HTMLResponse)
async def vnc_page(request: Request):
    templates = request.app.state.templates
    novnc_port = int(os.environ.get("IBCTL_NOVNC_PORT", "6080"))
    vnc_password = os.environ.get("VNC_SERVER_PASSWORD", "")
    return templates.TemplateResponse(request, "vnc.html", {
        "active_tab": "vnc",
        "novnc_port": novnc_port,
        "vnc_password": vnc_password,
    })


# --- HTMX partial endpoints (polled by the UI for live updates) ---

@router.get("/partials/overview", response_class=HTMLResponse)
async def overview_partial(request: Request):
    registry = request.app.state.instance_registry
    templates = request.app.state.templates

    instances = await registry.all_status()
    instances_data = [
        {
            "mode": inst.mode,
            "status": inst.status or {"ready": False, "state": "unreachable"},
            "state_data": inst.state_data,
            "error": inst.error,
        }
        for inst in instances
    ]

    return templates.TemplateResponse(request, "partials/overview_content.html", {
        "instances": instances_data,
    })


@router.get("/partials/state-history", response_class=HTMLResponse)
async def state_history_partial(request: Request, mode: str | None = None):
    registry = request.app.state.instance_registry
    templates = request.app.state.templates

    # Use requested mode or default to primary
    target_mode = mode or registry.primary_mode()
    client = registry.get_client(target_mode)

    try:
        state = await client.state()
        state_dict = asdict(state)
    except DashboardError as e:
        state_dict = {"current": "unreachable", "history": []}

    return templates.TemplateResponse(request, "partials/state_content.html", {
        "state": state_dict,
    })


@router.get("/partials/config", response_class=HTMLResponse)
async def config_partial(request: Request):
    client = request.app.state.ibctl_client
    templates = request.app.state.templates

    try:
        config = await client.config()
    except DashboardError as e:
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
async def logs_partial(request: Request, level: str | None = None):
    client = request.app.state.ibctl_client
    templates = request.app.state.templates

    try:
        entries = await client.logs(limit=50)
        if level:
            entries = [e for e in entries if e.level.upper() == level.upper()]
        logs = [asdict(e) for e in entries]
    except DashboardError:
        logs = []

    return templates.TemplateResponse(request, "partials/logs_content.html", {
        "logs": logs,
    })
