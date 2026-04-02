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
    """Redirect to state machine tab (controls are integrated there now)."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/state")


@router.get("/ib-status", response_class=HTMLResponse)
async def ib_status_page(request: Request):
    templates = request.app.state.templates
    return templates.TemplateResponse(request, "ib_status.html", {"active_tab": "ib-status"})


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

    return templates.TemplateResponse(request, "partials/overview_content.html", {
        "instances": instances_data,
        "ib_status": ib_data,
        "scraper_info": scraper_info,
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
        # Convert epoch timestamps to local time using TZ from ibctl config
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
    except DashboardError as e:
        state_dict = {"current": "unreachable", "history": []}

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
