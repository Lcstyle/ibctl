"""Gateway version API: what ibctl runs, what IB offers, and any cutoff IB announced."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.services.gateway_version.monitor import _today_et
from app.services.gateway_version.view import version_view

logger = logging.getLogger("dashboard.api.gateway_version")
router = APIRouter()


def _service(request: Request):
    return getattr(request.app.state, "gateway_version", None)


@router.get("/api/v1/gateway/version")
async def get_gateway_version(request: Request):
    """The running Gateway version against IB's stable and latest builds, any
    desupport cutoff IB announced (error 2172), and when the next weekly
    check runs. Instants are RFC 3339 with an offset; the cutoff is a date."""
    service = _service(request)
    if service is None:
        return JSONResponse({"error": "gateway version tracking is not running"}, status_code=503)
    return version_view(service.current(), today=_today_et(), next_check=service.next_check())


@router.post("/api/v1/gateway/version/check")
async def check_gateway_version(request: Request):
    """Run the weekly check now, in the background (e.g. right after an upgrade)."""
    service = _service(request)
    if service is None:
        return JSONResponse({"error": "gateway version tracking is not running"}, status_code=503)
    if not service.start_check():
        return JSONResponse({"started": False, "reason": "a check is already running"}, status_code=409)
    logger.info("Gateway version check started on request")
    return JSONResponse({"started": True}, status_code=202)
