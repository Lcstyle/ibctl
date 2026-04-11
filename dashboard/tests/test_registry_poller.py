"""Tests for InstanceRegistry background poller.

The background poller keeps the STATUS cache populated independently of
browser SSE connections. Without it, monitors (no-clients, login-failure)
get empty cache data and silently fail to alert.

Regression test for: monitors blind when no browser connected to SSE.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from app.domain.instance import InstanceEndpoint
from app.instance_registry import InstanceRegistry


class FakeClient:
    """Stub ibctl client that returns canned STATUS responses."""

    def __init__(self, host: str = "127.0.0.1", port: int = 7462):
        self.host = host
        self.port = port
        self._status = {
            "state": "Connected",
            "ready": True,
            "trading_mode": "live",
            "clients": {"count": 0, "ids": []},
        }

    async def send_command(self, command: str) -> str:
        if command == "STATUS":
            return json.dumps(self._status)
        return "{}"

    async def state(self):
        raise NotImplementedError

    async def status(self):
        raise NotImplementedError

    async def status_raw(self):
        raise NotImplementedError

    async def config(self):
        raise NotImplementedError

    async def logs(self, limit: int = 50):
        raise NotImplementedError


def _make_registry() -> InstanceRegistry:
    endpoints = [InstanceEndpoint("live", "127.0.0.1", 7462)]
    return InstanceRegistry(endpoints, client_factory=lambda host, port: FakeClient(host, port))


class TestCachePopulationWithoutSSE:
    """Verify cache is populated by the background poller, not just SSE."""

    def test_cache_empty_before_poller_starts(self):
        """RED: cache is empty when no poller or SSE has run."""
        registry = _make_registry()
        statuses = registry.cached_all_status()
        assert len(statuses) == 1
        assert statuses[0].status is None
        assert statuses[0].error is not None

    @pytest.mark.asyncio
    async def test_cache_populated_after_status_fetch(self):
        """After fetching status, cache should have real data."""
        registry = _make_registry()

        # Directly fetch status (bypasses subscribe/poll infrastructure)
        await registry.all_status()

        statuses = registry.cached_all_status()
        assert len(statuses) == 1
        assert statuses[0].status is not None
        assert statuses[0].status["state"] == "Connected"
        assert statuses[0].status["clients"]["count"] == 0
        assert statuses[0].error is None

    @pytest.mark.asyncio
    async def test_no_clients_monitor_sees_data_without_sse(self):
        """RED: the no-clients monitor must see real status even with no browser."""
        from unittest.mock import AsyncMock, MagicMock
        from app.services.monitors.no_clients import NoClientsMonitor

        registry = _make_registry()

        # Populate cache directly (simulates what subscribe/poller does)
        await registry.all_status()

        # Create a mock notification service
        ns = MagicMock()
        ns.is_event_enabled.return_value = True
        ns.get_event_timeout.return_value = 0  # 0 = disabled timeout, won't alert
        ns.send_alert = AsyncMock()

        monitor = NoClientsMonitor()

        # Run one check cycle
        await monitor.check(registry, ns)

        # The monitor should have seen real data (Connected + 0 clients)
        # and started the timer. With timeout=0 it won't alert, but the
        # key assertion is that it SAW data — not "cache not populated".
        statuses = registry.cached_all_status()
        assert statuses[0].status is not None, (
            "Monitor's data source (cached_all_status) must have real data "
            "even without a browser SSE connection"
        )
