"""Test fixtures — fake ibctl client and test app."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import DashboardSettings
from app.domain.models import GatewayStatus, LogEntry, StateMachineState
from app.main import create_app


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
    return DashboardSettings(
        port=8080,
        token="",
        debug_mode=False,
        ibctl_host="127.0.0.1",
        ibctl_port=7462,
    )


@pytest.fixture
async def client(fake_client, settings):
    """Async HTTP test client with fake ibctl backend."""
    app = create_app(settings=settings)
    app.state.ibctl_client = fake_client  # Replace real client with fake

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
