"""API router — mounts all API and page endpoints."""

from fastapi import APIRouter

from app.api import (
    command, debug, events, gateway_upgrade, gateway_version, logs, notifications, pages, reconnect, status, twofa,
)

api_router = APIRouter()
api_router.include_router(status.router)
api_router.include_router(command.router)
api_router.include_router(logs.router)
api_router.include_router(events.router)
api_router.include_router(debug.router)
api_router.include_router(notifications.router)
api_router.include_router(twofa.router)
api_router.include_router(reconnect.router)
api_router.include_router(gateway_version.router)
api_router.include_router(gateway_upgrade.router)
api_router.include_router(pages.router)
