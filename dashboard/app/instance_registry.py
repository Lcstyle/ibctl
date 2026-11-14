"""Registry of ibctl instances for multi-instance monitoring.

Manages connections to one or more ibctl command servers (live, paper, or both).
Queries all instances concurrently and translates connection failures into
InstanceStatus(error=...) rather than propagating exceptions.

Supports two cache-population strategies:
  1. SUBSCRIBE (preferred): persistent push connection from ibctl, instant updates
  2. Polling fallback: 5s TCP STATUS poll for older ibctl binaries

An asyncio.Condition allows SSE endpoints, monitors, and ZMQ publishers to
wake instantly when new status arrives (no polling at any layer).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Callable

from app.domain.instance import InstanceEndpoint, InstanceStatus
from app.ibctl_client import IbctlClientProtocol, TcpIbctlClient

logger = logging.getLogger("dashboard.registry")


class _CachedResponse:
    """TTL cache entry with age tracking."""
    __slots__ = ("data", "expires", "written_at")

    def __init__(self, data: dict | str, ttl: float):
        self.data = data
        self.written_at = time.monotonic()
        self.expires = time.monotonic() + ttl

    @property
    def valid(self) -> bool:
        return time.monotonic() < self.expires

    @property
    def age(self) -> float:
        """Seconds since this cache entry was written."""
        return time.monotonic() - self.written_at


class InstanceRegistry:
    """Manages connections to multiple ibctl instances with response caching.

    Uses SUBSCRIBE for push-driven cache updates when supported, falling back
    to 5s TCP polling for older ibctl binaries. An asyncio.Condition notifies
    all waiters (SSE, monitors, ZMQ publisher) instantly on status changes.
    """

    # Cache TTLs in seconds
    STATUS_TTL = 15.0   # Safety net; subscribe updates cache on every push
    CONFIG_TTL = 300.0  # Config doesn't change at runtime (5 min)
    POLL_INTERVAL = 5.0  # Fallback polling interval (only used if SUBSCRIBE unsupported)

    def __init__(
        self,
        endpoints: list[InstanceEndpoint],
        client_factory: Callable[..., IbctlClientProtocol] = TcpIbctlClient,
    ):
        self._clients: dict[str, IbctlClientProtocol] = {}
        self._endpoints: dict[str, InstanceEndpoint] = {}
        self._cache: dict[str, _CachedResponse] = {}
        self._subscribe_clients: list = []  # SubscribeClient instances
        self._poller_task: asyncio.Task | None = None
        self._status_updated: asyncio.Condition = asyncio.Condition()

        for ep in endpoints:
            self._endpoints[ep.mode] = ep
            self._clients[ep.mode] = client_factory(host=ep.host, port=ep.port)
            logger.info("Registered %s instance at %s:%d", ep.mode, ep.host, ep.port)

    async def start_background_poller(self):
        """Start cache population — tries SUBSCRIBE first, falls back to polling.

        SUBSCRIBE gives instant push updates from ibctl. If the ibctl binary
        doesn't support SUBSCRIBE (older version), falls back to 5s TCP polling.
        """
        from app.services.subscribe_client import SubscribeClient

        for mode, ep in self._endpoints.items():
            sub = SubscribeClient(
                host=ep.host,
                port=ep.port,
                mode=mode,
                on_status=self._push_status_sync,
            )
            self._subscribe_clients.append(sub)
            await sub.start()

        # Monitor subscribe clients — if any fail (old ibctl), start fallback poller
        self._poller_task = asyncio.create_task(
            self._subscribe_watchdog(), name="subscribe-watchdog",
        )
        logger.info("Subscribe clients started for %d instances", len(self._endpoints))

    async def stop_background_poller(self):
        for sub in self._subscribe_clients:
            await sub.stop()
        self._subscribe_clients.clear()
        if self._poller_task:
            self._poller_task.cancel()
            try:
                await self._poller_task
            except asyncio.CancelledError:
                pass
            self._poller_task = None
        logger.info("Background status services stopped")

    async def _subscribe_watchdog(self):
        """Monitor subscribe clients. If any mark SUBSCRIBE as unsupported,
        start a fallback polling loop for those instances."""
        await asyncio.sleep(10)  # Give subscribe clients time to connect
        needs_polling = False
        for sub in self._subscribe_clients:
            if not sub.subscribe_supported:
                logger.info("Fallback to polling for %s (SUBSCRIBE not supported)", sub._mode)
                needs_polling = True

        if needs_polling:
            logger.info("Starting fallback polling loop (interval=%.0fs)", self.POLL_INTERVAL)
            while True:
                try:
                    await self.all_status()
                    await self._notify_update()
                except Exception as e:
                    logger.warning("Fallback poller error: %s", e)
                await asyncio.sleep(self.POLL_INTERVAL)

    def set_zmq_publisher(self, publisher):
        """Attach a ZMQ publisher to broadcast status updates externally."""
        self._zmq_publisher = publisher

    def _push_status_sync(self, mode: str, status: dict):
        """Called by SubscribeClient (sync callback) when status arrives."""
        cache_key = f"{mode}:STATUS"
        self._cache[cache_key] = _CachedResponse(status, self.STATUS_TTL)
        # Publish to ZMQ if configured
        zmq_pub = getattr(self, "_zmq_publisher", None)
        if zmq_pub:
            zmq_pub.publish(mode, status)
        # Schedule async notification on the event loop
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._notify_update())
        except RuntimeError:
            pass  # No running loop (shouldn't happen in production)

    async def _notify_update(self):
        """Wake all waiters (SSE, monitors, ZMQ publisher)."""
        async with self._status_updated:
            self._status_updated.notify_all()

    async def wait_for_update(self, timeout: float = 5.0) -> bool:
        """Block until a status update arrives or timeout expires.

        Returns True if notified (new data), False on timeout (heartbeat).
        """
        async with self._status_updated:
            try:
                await asyncio.wait_for(self._status_updated.wait(), timeout=timeout)
                return True
            except asyncio.TimeoutError:
                return False

    async def _poll_loop(self):
        """Refresh STATUS cache for all instances every POLL_INTERVAL seconds."""
        while True:
            try:
                await self.all_status()
                await self._notify_update()
            except Exception as e:
                logger.warning("Background poller error: %s", e)
            await asyncio.sleep(self.POLL_INTERVAL)

    async def all_status(self) -> list[InstanceStatus]:
        """Query all instances concurrently, return status for each."""
        tasks = [self._fetch_status(mode) for mode in self._clients]
        return await asyncio.gather(*tasks)

    async def status(self, mode: str) -> InstanceStatus:
        """Query a single instance's status."""
        if mode not in self._clients:
            return InstanceStatus(mode=mode, error=f"Unknown instance: {mode}")
        return await self._fetch_status(mode)

    async def cached_command(self, mode: str, command: str, ttl: float) -> dict | None:
        """Send a command with TTL caching. Returns parsed JSON or None."""
        cache_key = f"{mode}:{command}"
        cached = self._cache.get(cache_key)
        if cached and cached.valid:
            return cached.data

        client = self._clients.get(mode)
        if not client:
            return None

        try:
            raw = await client.send_command(command)
            data = json.loads(raw) if raw else {}
            self._cache[cache_key] = _CachedResponse(data, ttl)
            return data
        except Exception as e:
            logger.debug("Cache miss for %s:%s — %s", mode, command, e)
            return None

    async def cached_config(self, mode: str) -> dict | None:
        """Get CONFIG with 60s TTL cache."""
        return await self.cached_command(mode, "CONFIG", self.CONFIG_TTL)

    def cached_status_raw(self, mode: str) -> dict | None:
        """Read cached STATUS dict without opening TCP. Returns None if no cache.

        Returns data even if TTL-expired — stale data beats "unreachable".
        The TTL only governs when the SSE background task re-fetches via TCP.
        """
        cache_key = f"{mode}:STATUS"
        cached = self._cache.get(cache_key)
        if cached:
            return cached.data
        return None

    def cached_all_status(self) -> list[InstanceStatus]:
        """Read cached status for all instances. Never opens TCP.

        Returns data even if TTL-expired — stale data beats "unreachable".
        Only returns error if cache has never been populated (true startup).
        """
        results = []
        for mode in self._clients:
            cache_key = f"{mode}:STATUS"
            cached = self._cache.get(cache_key)
            if cached:
                results.append(InstanceStatus(mode=mode, status=cached.data))
            else:
                results.append(InstanceStatus(mode=mode, error="Starting up — cache not yet populated"))
        return results

    def cache_age(self, mode: str) -> float | None:
        """Seconds since cache was last written for this mode. None if no cache."""
        cache_key = f"{mode}:STATUS"
        cached = self._cache.get(cache_key)
        if cached:
            return cached.age
        return None

    def invalidate(self, mode: str | None = None):
        """Clear cache for a mode or all modes."""
        if mode:
            self._cache = {k: v for k, v in self._cache.items() if not k.startswith(f"{mode}:")}
        else:
            self._cache.clear()

    def get_client(self, mode: str) -> IbctlClientProtocol:
        """Get the raw client for a specific instance (for sending commands)."""
        return self._clients[mode]

    def modes(self) -> list[str]:
        """List registered instance modes."""
        return list(self._clients.keys())

    def primary_mode(self) -> str:
        """The first registered mode (for backward compatibility)."""
        return self.modes()[0]

    async def _fetch_status(self, mode: str) -> InstanceStatus:
        """Fetch status with 2s TTL cache, translating errors to InstanceStatus."""
        cache_key = f"{mode}:STATUS"
        cached = self._cache.get(cache_key)
        if cached and cached.valid:
            return InstanceStatus(mode=mode, status=cached.data)

        client = self._clients[mode]
        try:
            raw = await client.send_command("STATUS")
            status_data = json.loads(raw) if raw else {}
            self._cache[cache_key] = _CachedResponse(status_data, self.STATUS_TTL)
            return InstanceStatus(mode=mode, status=status_data)
        except Exception as e:
            logger.debug("Instance %s unreachable: %s", mode, e)
            err = str(e)
            if "Connection refused" in err or "ConnectionRefusedError" in err:
                err = "Starting up — waiting for ibctl daemon"
            elif "Timeout" in err or "timed out" in err:
                err = "Not responding — ibctl may be busy or starting"
            return InstanceStatus(mode=mode, error=err)
