"""ibctl Dashboard — FastAPI application.

Serves both the REST API and web UI from a single process.
Connects to one or more ibctl command servers (live, paper, or both)
via the InstanceRegistry for multi-instance monitoring and control.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.router import api_router
from app.config import DashboardSettings
from app.instance_registry import InstanceRegistry
from app.middleware.auth import TokenAuthMiddleware

logger = logging.getLogger("dashboard")

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    settings: DashboardSettings = app.state.settings
    endpoints = settings.endpoints
    modes = ", ".join(f"{ep.mode}@{ep.host}:{ep.port}" for ep in endpoints)
    logger.info(
        "Dashboard starting on port %d (instances: %s)",
        settings.port, modes,
    )

    # Start IB System Status monitor
    from app.services.ib_status_monitor import create_monitor
    monitor = create_monitor(app.state.instance_registry)
    app.state.ib_status_monitor = monitor
    await monitor.start()

    yield

    # Stop IB System Status monitor
    await monitor.stop()
    logger.info("Dashboard shutting down")


def create_app(settings: DashboardSettings | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Accepts settings for dependency injection (tests pass a custom settings
    object; production uses DashboardSettings.from_env()).
    """
    if settings is None:
        settings = DashboardSettings.from_env()

    # IBCTL_ROOT_PATH is used for URL generation in templates only.
    # Do NOT pass it as FastAPI root_path — nginx strips the prefix with
    # trailing-slash proxy_pass, so the app must serve at / internally.
    root_path = os.environ.get("IBCTL_ROOT_PATH", "")
    app = FastAPI(
        title="ibctl Dashboard",
        version="0.2.0",
        lifespan=lifespan,
    )

    # Store settings on app state
    app.state.settings = settings
    app.state.debug_mode = settings.debug_mode

    # Create instance registry for multi-instance monitoring
    registry = InstanceRegistry(settings.endpoints)
    app.state.instance_registry = registry

    # Backward compatibility: ibctl_client points to the primary instance
    # (existing API endpoints like /api/v1/status use this)
    app.state.ibctl_client = registry.get_client(registry.primary_mode())

    # Auth middleware (must be added before routes)
    app.add_middleware(TokenAuthMiddleware)

    # Mount API routes
    app.include_router(api_router)

    # Mount static files
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Templates (for web UI) — inject root_path as global variable
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.globals["root_path"] = root_path
    app.state.templates = templates

    return app


# Default app instance for uvicorn
app = create_app()
