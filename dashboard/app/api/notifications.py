"""Notification API — config, test, and history endpoints."""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Request
from pydantic import BaseModel

from pydantic import SecretStr

from app.services.notification_service import NotificationConfig

logger = logging.getLogger("dashboard.api.notifications")
router = APIRouter()


class NotificationConfigRequest(BaseModel):
    enabled: bool = False
    ntfy_url: str = "https://ntfy.sh"
    ntfy_topic: str = "ibctl"
    ntfy_token: str = ""
    events: dict = {}


@router.get("/api/v1/notifications/config")
async def get_notification_config(request: Request):
    ns = getattr(request.app.state, "notification_service", None)
    if not ns:
        return {"ok": False, "error": "Notification service not running"}
    config_dict = ns.config.to_dict(mask_token=True)
    env_locked = NotificationConfig.env_locked_fields()
    persist_mounted = NotificationConfig.persist_volume_mounted()
    return {"ok": True, "config": config_dict, "env_locked": env_locked, "persist_mounted": persist_mounted}


@router.post("/api/v1/notifications/config")
async def save_notification_config(request: Request, body: NotificationConfigRequest):
    ns = getattr(request.app.state, "notification_service", None)
    if not ns:
        return {"ok": False, "error": "Notification service not running"}

    env_locked = NotificationConfig.env_locked_fields()

    # Preserve env-locked values; wrap token in SecretStr
    token = ns.config.ntfy_token if env_locked.get("ntfy_token") else SecretStr(body.ntfy_token)
    config = NotificationConfig(
        enabled=body.enabled,
        ntfy_url=ns.config.ntfy_url if env_locked.get("ntfy_url") else body.ntfy_url,
        ntfy_topic=ns.config.ntfy_topic if env_locked.get("ntfy_topic") else body.ntfy_topic,
        ntfy_token=token,
        events=body.events,
    )
    config.save()
    ns.update_config(config)
    logger.info("Notification config updated via API")
    return {"ok": True}


@router.post("/api/v1/notifications/test")
async def send_test_notification(request: Request):
    ns = getattr(request.app.state, "notification_service", None)
    if not ns:
        return {"ok": False, "error": "Notification service not running"}

    success = await ns.send_test()
    logger.info("Test notification %s", "sent successfully" if success else "failed")
    return {"ok": success, "message": "Test notification sent" if success else "Failed to send"}


@router.get("/api/v1/notifications/history")
async def get_notification_history(request: Request):
    ns = getattr(request.app.state, "notification_service", None)
    if not ns:
        return {"ok": False, "error": "Notification service not running"}

    tz_name = os.environ.get("TZ", "America/New_York")
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = ZoneInfo("America/New_York")

    events = []
    for event in ns.history:
        dt = datetime.fromtimestamp(event.timestamp, tz=tz)
        events.append({
            "timestamp": dt.strftime("%Y-%m-%d %I:%M:%S %p"),
            "event_type": event.event_type,
            "title": event.title,
            "body": event.body,
            "priority": event.priority,
            "success": event.success,
            "error": event.error,
        })

    return {"ok": True, "events": events}
