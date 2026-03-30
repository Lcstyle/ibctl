"""Registry of ibctl instances for multi-instance monitoring.

Manages connections to one or more ibctl command servers (live, paper, or both).
Queries all instances concurrently and translates connection failures into
InstanceStatus(error=...) rather than propagating exceptions.

Follows dependency inversion: composes IbctlClientProtocol instances,
so tests can inject FakeIbctlClient without TCP.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable

from app.domain.instance import InstanceEndpoint, InstanceStatus
from app.ibctl_client import IbctlClientProtocol, TcpIbctlClient

logger = logging.getLogger("dashboard.registry")


class InstanceRegistry:
    """Manages connections to multiple ibctl instances."""

    def __init__(
        self,
        endpoints: list[InstanceEndpoint],
        client_factory: Callable[..., IbctlClientProtocol] = TcpIbctlClient,
    ):
        self._clients: dict[str, IbctlClientProtocol] = {}
        self._endpoints: dict[str, InstanceEndpoint] = {}

        for ep in endpoints:
            self._endpoints[ep.mode] = ep
            self._clients[ep.mode] = client_factory(host=ep.host, port=ep.port)
            logger.info("Registered %s instance at %s:%d", ep.mode, ep.host, ep.port)

    async def all_status(self) -> list[InstanceStatus]:
        """Query all instances concurrently, return status for each.

        Never raises — unreachable instances get InstanceStatus(error=...).
        """
        tasks = [self._fetch_status(mode) for mode in self._clients]
        return await asyncio.gather(*tasks)

    async def status(self, mode: str) -> InstanceStatus:
        """Query a single instance's status."""
        if mode not in self._clients:
            return InstanceStatus(mode=mode, error=f"Unknown instance: {mode}")
        return await self._fetch_status(mode)

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
        """Fetch status for one instance, translating errors to InstanceStatus."""
        client = self._clients[mode]
        try:
            status_data = await client._query("STATUS")
            state_data = await client._query("STATE")
            return InstanceStatus(
                mode=mode,
                status=status_data,
                state_data=state_data,
            )
        except Exception as e:
            logger.debug("Instance %s unreachable: %s", mode, e)
            return InstanceStatus(mode=mode, error=str(e))
