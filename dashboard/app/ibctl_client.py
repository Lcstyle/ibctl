"""Async TCP client for ibctl's command server.

Sends line-based commands and parses JSON responses.
Protocol: send "COMMAND\n", receive "OK {json}\n" or "ERROR message\n".

Abstracted behind IbctlClientProtocol for testability — tests use
FakeIbctlClient instead of opening real TCP connections.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Protocol

from app.domain.errors import IbctlCommandError, IbctlConnectionError, IbctlTimeoutError
from app.domain.models import GatewayStatus, LogEntry, StateMachineState

logger = logging.getLogger("dashboard.client")


class IbctlClientProtocol(Protocol):
    """Abstract interface for ibctl communication."""

    async def status(self) -> GatewayStatus: ...
    async def status_raw(self) -> dict: ...
    async def state(self) -> StateMachineState: ...
    async def config(self) -> dict: ...
    async def logs(self, limit: int = 100) -> list[LogEntry]: ...
    async def windows(self) -> dict: ...
    async def send_command(self, command: str) -> str: ...


class TcpIbctlClient:
    """TCP client that connects to ibctl's command server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 7462, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    async def status(self) -> GatewayStatus:
        data = await self._query("STATUS")
        return GatewayStatus.from_json(data)

    async def status_raw(self) -> dict:
        """Raw STATUS response — no model translation, no field loss."""
        return await self._query("STATUS")

    async def state(self) -> StateMachineState:
        data = await self._query("STATE")
        return StateMachineState.from_json(data)

    async def config(self) -> dict:
        return await self._query("CONFIG")

    async def logs(self, limit: int = 100) -> list[LogEntry]:
        data = await self._query(f"LOGS {limit}")
        return [
            LogEntry(
                timestamp=entry.get("timestamp", ""),
                level=entry.get("level", ""),
                message=entry.get("message", ""),
            )
            for entry in data.get("logs", [])
        ]

    async def windows(self) -> dict:
        return await self._query("WINDOWS")

    async def send_command(self, command: str) -> str:
        return await self._send(command)

    async def _query(self, command: str) -> dict:
        """Send a query command and parse the JSON response."""
        raw = await self._send(command)
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            raise IbctlCommandError(command, f"Invalid JSON response: {e}")

    async def _send(self, command: str) -> str:
        """Send a command and return the raw response (after OK/ERROR prefix)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout,
            )
        except (ConnectionRefusedError, OSError) as e:
            raise IbctlConnectionError(self.host, self.port, str(e))
        except asyncio.TimeoutError:
            raise IbctlTimeoutError(command, self.timeout)

        try:
            writer.write(f"{command}\n".encode())
            await writer.drain()

            response = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout,
            )

            line = response.decode().strip()
            logger.debug("ibctl response for '%s': %s", command, line[:200])

            if line.startswith("OK "):
                return line[3:]  # Strip "OK " prefix
            elif line.startswith("ERROR "):
                raise IbctlCommandError(command, line[6:])
            elif line == "OK":
                return ""
            else:
                raise IbctlCommandError(command, f"Unexpected response: {line}")
        except asyncio.TimeoutError:
            raise IbctlTimeoutError(command, self.timeout)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
