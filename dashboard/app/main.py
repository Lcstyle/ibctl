"""ibctl Dashboard — FastAPI application.

Serves both the REST API and web UI from a single process.
Connects to one or more ibctl command servers (live, paper, or both)
via the InstanceRegistry for multi-instance monitoring and control.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.router import api_router
from app.config import DashboardSettings
from app.instance_registry import InstanceRegistry

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
    yield
    logger.info("Dashboard shutting down")


def create_app(settings: DashboardSettings | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Accepts settings for dependency injection (tests pass a custom settings
    object; production uses DashboardSettings.from_env()).
    """
    if settings is None:
        settings = DashboardSettings.from_env()

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

    # Mount API routes
    app.include_router(api_router)

    # Mount static files
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Templates (for web UI)
    app.state.templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    return app


# Default app instance for uvicorn
app = create_app()
