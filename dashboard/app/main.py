"""ibctl Dashboard — FastAPI application.

Serves both the REST API and web UI from a single process.
Connects to one or more ibctl command servers (live, paper, or both)
via the InstanceRegistry for multi-instance monitoring and control.
"""

from __future__ import annotations

# bootstrap MUST be the first non-stdlib import: it installs sys.excepthook,
# threading.excepthook, and signal handlers BEFORE any other dashboard code
# runs. Without this, an exception during module import (e.g. a bad import
# in a service module) would die with traceback only on docker stderr — the
# exact failure mode that lost the 2026-06-20 traceback.
import app.bootstrap  # noqa: F401

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.router import api_router
from app.config import DashboardSettings
from app.instance_registry import InstanceRegistry
from app.mbb import SPEC_VERSION as MBB_SPEC_VERSION, mbb
from app.middleware.auth import TokenAuthMiddleware
from app.services.market_day_logging import setup_dashboard_logging

CRASH_STAMP_PATH = Path(
    os.environ.get("IBCTL_LOG_DIR", "/opt/ibctl/persist/logs")
) / ".dashboard_crash.stamp"

logger = logging.getLogger("dashboard")

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


def _handle_asyncio_exception(loop, context):
    """Route unhandled asyncio task exceptions into the durable log.

    These bypass sys.excepthook entirely — without this hook they would
    only surface in uvicorn's stderr stream.
    """
    exc = context.get("exception")
    msg = context.get("message", "asyncio task exception")
    logger.error(
        "asyncio_unhandled",
        exc_info=exc if exc else None,
        extra={"event": "asyncio.unhandled", "asyncio_msg": msg},
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    settings: DashboardSettings = app.state.settings
    endpoints = settings.endpoints
    modes = ", ".join(f"{ep.mode}@{ep.host}:{ep.port}" for ep in endpoints)
    lifespan_t0 = time.monotonic()
    logger.info(
        "dashboard_startup",
        extra={
            "event": "dashboard.startup",
            "pid": os.getpid(),
            "port": settings.port,
            "modes": modes,
        },
    )

    asyncio.get_running_loop().set_exception_handler(_handle_asyncio_exception)

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
        NoClientsMonitor, ReconnectGiveUpMonitor, SessionLostMonitor,
        ReloginFailedMonitor, WarmRestartMonitor, IBMaintenanceMonitor,
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
        ReconnectGiveUpMonitor(),
    ]
    monitor_manager = MonitorManager(registry, notification_service, monitors)
    app.state.monitor_manager = monitor_manager
    await monitor_manager.start()

    if notification_service.config.enabled:
        logger.info("Notification service enabled (channel: %s)", notification_service.config.channel)
    else:
        logger.info("Notification service disabled (set IBCTL_NOTIFICATIONS_ENABLED=true to enable)")

    # Recovery alert: if the shell supervisor wrote a crash stamp last cycle,
    # send a "dashboard recovered" notification now that we're booted, then
    # delete the stamp. force=True bypasses event-enable gating because this
    # is a system-health signal not a user-toggleable monitor.
    await _send_recovery_alert_if_pending(notification_service)

    try:
        yield
    finally:
        # Stop services (reverse order)
        await monitor_manager.stop()
        if monitor:
            await monitor.stop()
        await registry.stop_background_poller()
        if zmq_publisher:
            zmq_publisher.close()
        logger.info(
            "dashboard_shutdown",
            extra={
                "event": "dashboard.shutdown",
                "pid": os.getpid(),
                "elapsed_s": round(time.monotonic() - lifespan_t0, 3),
            },
        )


async def _send_recovery_alert_if_pending(notification_service) -> None:
    """If the shell supervisor wrote a crash stamp, fire a recovery ntfy.

    Stamp format: "<epoch_seconds>|<exit_code>". Created by entrypoint.sh
    when notify_dashboard_crash() runs; deleted here on successful boot.
    Errors are swallowed so a malformed stamp never blocks startup — fail
    open, log, move on.
    """
    if not CRASH_STAMP_PATH.exists():
        return
    try:
        content = CRASH_STAMP_PATH.read_text().strip()
        crash_ts_str, _, exit_code = content.partition("|")
        crash_ts = int(crash_ts_str)
        elapsed = max(0, int(time.time()) - crash_ts)
        exit_code = exit_code or "unknown"
        await notification_service.send_alert(
            event_type="dashboard_recovered",
            title="ibctl: dashboard recovered",
            body=(
                f"Dashboard is back online after a {elapsed}s outage "
                f"(prior exit code: {exit_code})."
            ),
            priority="default",
            tags="white_check_mark",
            force=True,
        )
        logger.info(
            "recovery_alert_sent",
            extra={
                "event": "dashboard.recovered",
                "outage_s": elapsed,
                "prior_exit": exit_code,
            },
        )
    except (OSError, ValueError) as e:
        logger.warning(
            "recovery_alert_skipped",
            extra={"event": "dashboard.recovery_skipped", "reason": str(e)},
        )
    finally:
        try:
            CRASH_STAMP_PATH.unlink(missing_ok=True)
        except OSError:
            pass


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

    # Mnemonic build badge — computed once at startup from the SHA baked
    # into the image at docker build time. Empty inputs (local dev before CI
    # wires the ARGs) → empty badge (template skips render). All fields on
    # the state dict so the tooltip has full provenance.
    build_badge: dict[str, str] = {}
    if settings.build_sha:
        try:
            mnemonic = mbb(settings.build_sha[:7])
        except ValueError:
            # A malformed build SHA in the env should not crash the app —
            # skip the badge and log so it's visible.
            logger.warning(
                "build_badge_invalid_sha",
                extra={"event": "dashboard.build_badge_invalid", "sha": settings.build_sha[:16]},
            )
            mnemonic = ""
        if mnemonic:
            context = settings.trading_mode if settings.trading_mode else ""
            build_badge = {
                "spec_version": MBB_SPEC_VERSION,
                "mnemonic": mnemonic,
                "human_time": settings.build_time_human,
                "context": context,
                "sha": settings.build_sha,
                "built_at_utc": settings.build_time_utc,
            }
            logger.info(
                "build_badge_computed",
                extra={
                    "event": "dashboard.build_badge",
                    "mnemonic": mnemonic,
                    "sha": settings.build_sha[:7],
                    "human_time": settings.build_time_human,
                    "context": context,
                },
            )
    app.state.build_badge = build_badge

    # Templates (for web UI) — inject root_path as global variable
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.globals["root_path"] = root_path
    templates.env.globals["build_badge"] = build_badge
    app.state.templates = templates

    return app


# Default app instance for uvicorn
app = create_app()
