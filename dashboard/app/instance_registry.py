"""Registry of ibctl instances for multi-instance monitoring.

Manages connections to one or more ibctl command servers (live, paper, or both).
Queries all instances concurrently and translates connection failures into
InstanceStatus(error=...) rather than propagating exceptions.

Includes a TTL cache for STATUS and CONFIG responses to reduce TCP round-trips.
STATUS is cached for 2s (matches HTMX poll interval), CONFIG is cached for 60s
(doesn't change at runtime).
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
    """Manages connections to multiple ibctl instances with response caching."""

    # Cache TTLs in seconds
    STATUS_TTL = 15.0   # SSE background task refreshes every 2s; 15s is a safety net
    CONFIG_TTL = 300.0  # Config doesn't change at runtime (5 min)

    def __init__(
        self,
        endpoints: list[InstanceEndpoint],
        client_factory: Callable[..., IbctlClientProtocol] = TcpIbctlClient,
    ):
        self._clients: dict[str, IbctlClientProtocol] = {}
        self._endpoints: dict[str, InstanceEndpoint] = {}
        self._cache: dict[str, _CachedResponse] = {}

        for ep in endpoints:
            self._endpoints[ep.mode] = ep
            self._clients[ep.mode] = client_factory(host=ep.host, port=ep.port)
            logger.info("Registered %s instance at %s:%d", ep.mode, ep.host, ep.port)

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
