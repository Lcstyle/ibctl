"""Test fixtures — fake ibctl client and test app."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.domain.models import GatewayStatus, LogEntry, StateMachineState
from app.main import create_app
from tests.auth_helpers import authed_settings, log_in


class FakeIbctlClient:
    """In-memory fake for testing — no TCP connections needed."""

    def __init__(self):
        self._status = GatewayStatus(
            ready=True,
            state="Connected",
            trading_mode="both",
            uptime_secs=3600,
            connected_uptime_secs=3500,
            socat_running=True,
            jvm_running=True,
        )
        self._state = StateMachineState(current="Connected", history=[])
        self._config = {
            "auth": {"username": "testuser", "trading_mode": "paper", "password": "********"},
            "gateway": {"tws_path": "/home/ibgateway/Jts", "version": "10.45.1b"},
        }
        self._windows = {"windows": [{"id": 123, "title": "IBKR Gateway", "tabs": []}]}
        self._logs: list[LogEntry] = []
        self._last_command: str | None = None

    async def status(self) -> GatewayStatus:
        return self._status

    async def status_raw(self) -> dict:
        from dataclasses import asdict
        return asdict(self._status)

    async def state(self) -> StateMachineState:
        return self._state

    async def config(self) -> dict:
        return self._config

    async def logs(self, limit: int = 100) -> list[LogEntry]:
        return self._logs[:limit]

    async def windows(self) -> dict:
        return self._windows

    async def send_command(self, command: str) -> str:
        self._last_command = command
        return command


@pytest.fixture
def fake_client():
    return FakeIbctlClient()


@pytest.fixture
def settings():
    """Settings with a dashboard password configured, so a login is possible."""
    return authed_settings()


def _wire_app(settings, fake_client):
    """The whole app, with the fake ibctl client and a populated status cache."""
    app = create_app(settings=settings)
    # Inject fake client into both legacy slot and registry
    app.state.ibctl_client = fake_client
    registry = app.state.instance_registry
    for mode in registry.modes():
        registry._clients[mode] = fake_client

    # Pre-populate registry cache so cache-first endpoints work in tests
    from dataclasses import asdict
    from app.instance_registry import _CachedResponse
    status_dict = asdict(fake_client._status)
    for mode in registry.modes():
        registry._cache[f"{mode}:STATUS"] = _CachedResponse(status_dict, registry.STATUS_TTL)
    return app


@pytest.fixture
async def anon_client(fake_client, settings):
    """A visitor who is not logged in."""
    app = _wire_app(settings, fake_client)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
async def client(fake_client, settings):
    """Async HTTP test client with fake ibctl backend, signed in through the login form."""
    app = _wire_app(settings, fake_client)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        await log_in(c)
        yield c
