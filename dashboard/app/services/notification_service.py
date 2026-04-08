"""Notification service for ibctl dashboard — ntfy.sh integration.

Sends alerts for operational events: no clients connected, session loss,
re-login failures, warm restarts, IB maintenance status changes.

Configuration stored in notifications.json, editable via dashboard UI.
Disabled by default — enable via IBCTL_NOTIFICATIONS_ENABLED=true or
the Notifications tab in the dashboard.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("dashboard.services.notifications")

# Default config file location (next to the dashboard app)
DEFAULT_CONFIG_PATH = "/opt/ibctl/dashboard/notifications.json"


@dataclass
class NotificationEvent:
    """Record of a sent notification."""
    timestamp: float
    event_type: str
    title: str
    body: str
    priority: str
    success: bool
    error: str = ""


@dataclass
class NotificationConfig:
    """Notification system configuration."""
    enabled: bool = False
    ntfy_url: str = "https://ntfy.sh"
    ntfy_topic: str = "ibctl"
    ntfy_token: str = ""
    events: dict[str, dict[str, Any]] = field(default_factory=lambda: {
        "no_clients": {"enabled": True, "timeout_minutes": 30},
        "session_lost": {"enabled": True},
        "relogin_failed": {"enabled": True},
        "warm_restart": {"enabled": False},
        "ib_maintenance": {"enabled": False},
    })

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "ntfy": {
                "url": self.ntfy_url,
                "topic": self.ntfy_topic,
                "token": self.ntfy_token,
            },
            "events": self.events,
        }

    @classmethod
    def from_dict(cls, data: dict) -> NotificationConfig:
        ntfy = data.get("ntfy", {})
        return cls(
            enabled=data.get("enabled", False),
            ntfy_url=ntfy.get("url", "https://ntfy.sh"),
            ntfy_topic=ntfy.get("topic", "ibctl"),
            ntfy_token=ntfy.get("token", ""),
            events=data.get("events", cls().events),
        )

    @classmethod
    def load(cls, path: str | None = None) -> NotificationConfig:
        """Load config from JSON file, with env var overrides."""
        config_path = path or os.environ.get("IBCTL_NOTIFICATIONS_CONFIG", DEFAULT_CONFIG_PATH)

        # Start with defaults
        config = cls()

        # Layer: JSON file
        if Path(config_path).exists():
            try:
                with open(config_path) as f:
                    data = json.load(f)
                config = cls.from_dict(data)
                logger.info("Loaded notification config from %s", config_path)
            except Exception as e:
                logger.warning("Failed to load notification config from %s: %s", config_path, e)

        # Layer: env var overrides (highest precedence)
        if os.environ.get("IBCTL_NOTIFICATIONS_ENABLED", "").lower() in ("true", "1", "yes"):
            config.enabled = True
        if url := os.environ.get("IBCTL_NTFY_URL"):
            config.ntfy_url = url
        if topic := os.environ.get("IBCTL_NTFY_TOPIC"):
            config.ntfy_topic = topic
        if token := os.environ.get("IBCTL_NTFY_TOKEN"):
            config.ntfy_token = token

        return config

    def save(self, path: str | None = None):
        """Persist config to JSON file."""
        config_path = path or os.environ.get("IBCTL_NOTIFICATIONS_CONFIG", DEFAULT_CONFIG_PATH)
        try:
            with open(config_path, "w") as f:
                json.dump(self.to_dict(), f, indent=2)
            logger.info("Saved notification config to %s", config_path)
        except Exception as e:
            logger.error("Failed to save notification config to %s: %s", config_path, e)


class NtfyClient:
    """Async HTTP client for ntfy.sh push notifications."""

    def __init__(self, url: str, topic: str, token: str = ""):
        self._url = url.rstrip("/")
        self._topic = topic
        self._token = token

    async def send(self, title: str, body: str, priority: str = "default", tags: str = "") -> bool:
        """Send a notification. Returns True on success."""
        import httpx

        url = f"{self._url}/{self._topic}"
        headers = {"X-Title": title}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if priority and priority != "default":
            headers["X-Priority"] = priority
        if tags:
            headers["X-Tags"] = tags

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, content=body, headers=headers)
                if resp.status_code == 200:
                    logger.info("Notification sent: %s", title)
                    return True
                logger.warning("Notification failed (HTTP %d): %s", resp.status_code, resp.text[:200])
                return False
        except Exception as e:
            logger.error("Notification send error: %s", e)
            return False


class NotificationService:
    """Manages notification config, sends alerts, deduplicates."""

    MAX_HISTORY = 50

    def __init__(self, config: NotificationConfig | None = None):
        self.config = config or NotificationConfig.load()
        self._client = self._make_client()
        self._history: deque[NotificationEvent] = deque(maxlen=self.MAX_HISTORY)
        self._last_sent: dict[str, float] = {}  # event_type → timestamp (dedup)
        self._cooldown_secs = 300  # Don't re-send same event type within 5 min

    def _make_client(self) -> NtfyClient:
        return NtfyClient(self.config.ntfy_url, self.config.ntfy_topic, self.config.ntfy_token)

    def update_config(self, config: NotificationConfig):
        """Update config and recreate client."""
        self.config = config
        self._client = self._make_client()

    @property
    def history(self) -> list[NotificationEvent]:
        return list(reversed(self._history))

    def is_event_enabled(self, event_type: str) -> bool:
        if not self.config.enabled:
            return False
        event_cfg = self.config.events.get(event_type, {})
        return event_cfg.get("enabled", False)

    def get_event_timeout(self, event_type: str) -> int:
        """Get timeout in minutes for time-based events. 0 = no timeout."""
        event_cfg = self.config.events.get(event_type, {})
        return event_cfg.get("timeout_minutes", 0)

    async def send_alert(
        self,
        event_type: str,
        title: str,
        body: str,
        priority: str = "default",
        tags: str = "",
        force: bool = False,
    ) -> bool:
        """Send a notification if the event type is enabled and not in cooldown."""
        if not force and not self.is_event_enabled(event_type):
            return False

        # Dedup: don't spam same event type
        now = time.time()
        if not force and event_type in self._last_sent:
            elapsed = now - self._last_sent[event_type]
            if elapsed < self._cooldown_secs:
                logger.debug("Notification suppressed (cooldown): %s", event_type)
                return False

        success = await self._client.send(title, body, priority, tags)

        self._history.append(NotificationEvent(
            timestamp=now,
            event_type=event_type,
            title=title,
            body=body,
            priority=priority,
            success=success,
        ))

        if success:
            self._last_sent[event_type] = now

        return success

    async def send_test(self) -> bool:
        """Send a test notification (bypasses enabled check and cooldown)."""
        return await self.send_alert(
            event_type="test",
            title="ibctl Test Notification",
            body="If you received this, notifications are working.",
            priority="low",
            tags="white_check_mark",
            force=True,
        )
