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
from app.services.market_day_logging import setup_dashboard_logging

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

    registry = app.state.instance_registry

    # Start ZMQ PUB socket for external status subscribers.
    # Always on when dashboard is running — zero cost with no subscribers.
    # Port exposure is controlled by docker-compose, not this flag.
    zmq_publisher = None
    zmq_disabled = os.environ.get("IBCTL_ZMQ_ENABLED", "").lower() in ("false", "0", "no")
    if not zmq_disabled:
        from app.services.zmq_publisher import ZmqStatusPublisher
        zmq_port = int(os.environ.get("IBCTL_ZMQ_PORT", "5556"))
        zmq_publisher = ZmqStatusPublisher(bind_address=f"tcp://*:{zmq_port}")
        zmq_publisher.start(registry=registry)
        await zmq_publisher.start_heartbeat()
        registry.set_zmq_publisher(zmq_publisher)
        app.state.zmq_publisher = zmq_publisher

    # Start background cache population — uses SUBSCRIBE for push, falls back to polling
    await registry.start_background_poller()

    # Start IB System Status monitor (only if enabled in config)
    monitor = None
    ib_status_enabled = os.environ.get("IBCTL_IB_STATUS_ENABLED", "").lower() in ("true", "1", "yes")
    if ib_status_enabled:
        from app.services.ib_status_monitor import create_monitor
        monitor = create_monitor(registry)
        app.state.ib_status_monitor = monitor
        await monitor.start()
    else:
        logger.info("IB System Status monitor disabled")

    # Start Notification service
    from app.services.notification_service import NotificationService
    notification_service = NotificationService()
    app.state.notification_service = notification_service

    # Start monitor manager (single background task for all monitors)
    from app.services.monitor_manager import MonitorManager
    from app.services.monitors import (
        ColdRestartPendingMonitor, Hitl2faEntryMonitor, LoginFailedMonitor,
        NoClientsMonitor, SessionLostMonitor, ReloginFailedMonitor,
        WarmRestartMonitor, IBMaintenanceMonitor,
    )
    monitors = [
        ColdRestartPendingMonitor(),
        LoginFailedMonitor(),
        NoClientsMonitor(),
        SessionLostMonitor(),
        ReloginFailedMonitor(),
        WarmRestartMonitor(),
        IBMaintenanceMonitor(ib_status_monitor=monitor),
        Hitl2faEntryMonitor(),
    ]
    monitor_manager = MonitorManager(registry, notification_service, monitors)
    app.state.monitor_manager = monitor_manager
    await monitor_manager.start()

    if notification_service.config.enabled:
        logger.info("Notification service enabled (channel: %s)", notification_service.config.channel)
    else:
        logger.info("Notification service disabled (set IBCTL_NOTIFICATIONS_ENABLED=true to enable)")

    yield

    # Stop services (reverse order)
    await monitor_manager.stop()
    if monitor:
        await monitor.stop()
    await registry.stop_background_poller()
    if zmq_publisher:
        zmq_publisher.close()
    logger.info("Dashboard shutting down")


def create_app(settings: DashboardSettings | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Accepts settings for dependency injection (tests pass a custom settings
    object; production uses DashboardSettings.from_env()).
    """
    if settings is None:
        settings = DashboardSettings.from_env()

    # Set up file logging if IBCTL_LOG_DIR is configured
    log_dir = os.environ.get("IBCTL_LOG_DIR", "")
    if log_dir:
        setup_dashboard_logging(log_dir=log_dir, log_level=settings.log_level)
        logger.info("Dashboard file logging to %s/dashboard-*.log", log_dir)

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
