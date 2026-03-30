"""ibctl Dashboard — FastAPI application.

Serves both the REST API and web UI from a single process.
Connects to ibctl's TCP command server for all gateway interaction.
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
from app.ibctl_client import TcpIbctlClient

logger = logging.getLogger("dashboard")

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    settings: DashboardSettings = app.state.settings
    logger.info(
        "Dashboard starting on port %d (ibctl at %s:%d)",
        settings.port, settings.ibctl_host, settings.ibctl_port,
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
        version="0.1.0",
        lifespan=lifespan,
    )

    # Store settings and client on app state for route access
    app.state.settings = settings
    app.state.ibctl_client = TcpIbctlClient(
        host=settings.ibctl_host,
        port=settings.ibctl_port,
    )
    app.state.debug_mode = settings.debug_mode

    # Mount API routes
    app.include_router(api_router)

    # Mount static files
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Templates (for web UI — Step 5)
    app.state.templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    return app


# Default app instance for uvicorn
app = create_app()
