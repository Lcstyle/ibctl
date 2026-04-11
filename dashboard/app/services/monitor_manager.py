"""Monitor manager — single background task that dispatches to registered monitors.

Instead of N individual asyncio tasks (one per monitor type), one MonitorManager
runs a single loop and calls each monitor's check() when its interval elapses.
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

logger = logging.getLogger("dashboard.services.monitor_manager")

# Base tick interval — monitors whose interval has elapsed get dispatched.
BASE_TICK_SECONDS = 10


@dataclass
class Alert:
    """An alert to be sent via the notification service."""
    event_type: str
    title: str
    body: str
    priority: str = "default"
    tags: str = ""


class Monitor(ABC):
    """Base class for all notification monitors.

    Subclasses define event_type, interval_seconds, and implement check().
    The MonitorManager calls check() at the configured interval and sends
    any returned alerts via the notification service.
    """

    event_type: str = ""
    interval_seconds: int = 30

    async def check(self, registry, ns) -> list[Alert]:
        """Examine state and return alerts to send. Empty list = nothing to report."""
        return []


class TransitionMonitor(Monitor):
    """Base for monitors that scan state machine transition history.

    Provides the initialization guard (skip first check to avoid alerting on
    historical transitions) and per-mode dedup key tracking.
    """

    def __init__(self):
        self._initialized = False
        self._last_seen_key: dict[str, str] = {}

    async def check(self, registry, ns) -> list[Alert]:
        if not ns.is_event_enabled(self.event_type):
            return []

        snapshot: dict[str, str] = {}
        alerts: list[Alert] = []

        for mode in registry.modes():
            client = registry.get_client(mode)
            try:
                state = await client.state()
            except Exception:
                continue

            result = self._scan_history(mode, state.history)
            if result is None:
                self._last_seen_key.pop(mode, None)
                continue

            key, alert = result
            snapshot[mode] = key
            if self._initialized and self._last_seen_key.get(mode) != key:
                alerts.append(alert)

        if not self._initialized:
            self._initialized = True
            self._last_seen_key = snapshot
            return []

        self._last_seen_key.update(snapshot)
        return alerts

    @abstractmethod
    def _scan_history(self, mode: str, history) -> tuple[str, Alert] | None:
        """Scan transition history. Return (dedup_key, alert) or None."""
        ...


class MonitorManager:
    """Single background task that runs all registered monitors."""

    def __init__(self, registry, notification_service, monitors: list[Monitor]):
        self._registry = registry
        self._ns = notification_service
        self._monitors = monitors
        self._task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()
        self._last_run: dict[int, float] = {}  # id(monitor) -> timestamp

    async def start(self):
        self._stop_event.clear()
        self._task = asyncio.create_task(self._loop(), name="monitor-manager")
        names = [m.__class__.__name__ for m in self._monitors]
        logger.info("MonitorManager started (%d monitors: %s)", len(self._monitors), ", ".join(names))

    async def stop(self):
        if self._task:
            self._stop_event.set()
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
            self._task = None
            logger.info("MonitorManager stopped")

    async def _loop(self):
        while not self._stop_event.is_set():
            now = time.monotonic()

            for monitor in self._monitors:
                mid = id(monitor)
                last = self._last_run.get(mid, 0.0)
                if now - last < monitor.interval_seconds:
                    continue

                self._last_run[mid] = now
                try:
                    alerts = await monitor.check(self._registry, self._ns)
                    for alert in alerts:
                        await self._ns.send_alert(
                            event_type=alert.event_type,
                            title=alert.title,
                            body=alert.body,
                            priority=alert.priority,
                            tags=alert.tags,
                        )
                except Exception as e:
                    logger.error("%s check failed: %s", monitor.__class__.__name__, e)

            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=BASE_TICK_SECONDS)
                break
            except asyncio.TimeoutError:
                pass
