"""Shared plumbing for the API-token and warm-restart tests.

`build_app` makes the whole dashboard with its API-access file under a temp
directory, a clock the test moves by hand, and one stand-in ibctl per mode that
records what it is sent. Nothing sleeps and no socket is opened.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

from httpx import ASGITransport, AsyncClient

from app.domain.errors import IbctlCommandError, IbctlConnectionError
from app.instance_registry import _CachedResponse
from app.main import create_app
from app.services.api_access import ApiAccessStore
from app.services.ibctl_access import IbctlAccessReader
from app.services.warm_restart import WarmRestartService
from tests.auth_helpers import authed_settings, log_in

ALL_COMMANDS = [
    "STOP", "START", "RESTART", "RECONNECTDATA", "RECONNECTACCOUNT", "ENABLEAPI", "EXIT",
    "RESTARTSOCAT", "PAUSE", "RESUME", "HITL_RESUME", "RESUME_RECONNECT", "MAINT_HOLD",
    "MAINT_RELEASE", "SETSTATE", "IBSTATUS", "SETRESTART",
]
WITHOUT_SETRESTART = [c for c in ALL_COMMANDS if c != "SETRESTART"]
NOT_ALLOWED = "command not allowed by command_server.allowed_commands"

# A moment on a Saturday evening, UTC, 20 seconds into a minute.
START = datetime(2026, 11, 14, 21, 40, 20, tzinfo=timezone.utc).timestamp()


class FakeClock:
    """The wall clock, moved by hand. Calling it returns epoch seconds."""

    def __init__(self, now: float = START):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class StubIbctl:
    """One ibctl instance: records every command and answers CONFIG and STATUS."""

    def __init__(self, allowed: list[str] | None = None):
        self.allowed = list(ALL_COMMANDS) if allowed is None else allowed
        self.report_allowed = True  # False: CONFIG leaves allowed_commands out, as an older ibctl does
        self.unreachable = False
        self.refuse_setrestart_with: str | None = None
        self.sent: list[str] = []
        self.status: dict = {"state": "Connected", "ready": True}

    def _check_reachable(self, command: str) -> None:
        if self.unreachable:
            raise IbctlConnectionError("127.0.0.1", 7462, "Connection refused")

    async def config(self) -> dict:
        self._check_reachable("CONFIG")
        server: dict = {"enabled": True, "port": 7462}
        if self.report_allowed:
            server["allowed_commands"] = list(self.allowed)
        return {"command_server": server}

    async def status_raw(self) -> dict:
        self._check_reachable("STATUS")
        return dict(self.status)

    async def send_command(self, command: str) -> str:
        self._check_reachable(command)
        await asyncio.sleep(0)  # a real command crosses a socket: let other requests run
        self.sent.append(command)
        if command.split(" ")[0] == "SETRESTART" and self.refuse_setrestart_with:
            raise IbctlCommandError(command, self.refuse_setrestart_with)
        return command.split(" ")[0]


def build_app(tmp_path: Path, *, clock: FakeClock | None = None, settings=None, trading_mode: str = "both"):
    """The dashboard with its API-access file under `tmp_path` and stand-in ibctls."""
    app = create_app(settings=settings or authed_settings(trading_mode=trading_mode))
    app.state.clock = clock = clock or FakeClock()
    app.state.api_access = ApiAccessStore(tmp_path / "config" / "api_access.json", clock=clock)
    registry = app.state.instance_registry
    app.state.stubs = {}
    for mode in registry.modes():
        stub = StubIbctl()
        app.state.stubs[mode] = stub
        registry._clients[mode] = stub
        registry._cache[f"{mode}:STATUS"] = _CachedResponse({"state": "Connected", "ready": True}, ttl=60.0)
    app.state.ibctl_client = registry.get_client(registry.primary_mode())
    app.state.ibctl_access = IbctlAccessReader(registry, clock=clock)
    app.state.warm_restart = WarmRestartService(
        app.state.api_access, registry, clock=clock, access=app.state.ibctl_access
    )
    return app


def client_for(app) -> AsyncClient:
    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    client.app = app
    return client


async def member_client(app) -> AsyncClient:
    """A client signed in through the login form. Close it with `await client.aclose()`."""
    client = client_for(app)
    await log_in(client)
    return client


def bearer(token: str, **extra) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", **extra}
