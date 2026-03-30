"""API router — mounts all API and page endpoints."""

from fastapi import APIRouter

from app.api import command, debug, events, logs, pages, status

api_router = APIRouter()
api_router.include_router(status.router)
api_router.include_router(command.router)
api_router.include_router(logs.router)
api_router.include_router(events.router)
api_router.include_router(debug.router)
api_router.include_router(pages.router)
