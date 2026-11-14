"""ibctl's own command allow-list, as ibctl reports it.

`command_server.allowed_commands` is the master switch for every caller: the
dashboard's buttons and API tokens included. ibctl reports its effective list
in its CONFIG reply. This reads it through the dashboard's ibctl client so the
API access page and the warm-restart button can say, ahead of time, that ibctl
would refuse a command.

If the list cannot be read (ibctl is unreachable, or an older ibctl does not
report it) nothing is called blocked: the answer is "could not be read", and
ibctl still makes the final call when the command is sent.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Callable

logger = logging.getLogger("dashboard.ibctl_access")

# How long a read is reused by the pages that poll. Sending a command always
# reads fresh.
CACHE_SECONDS = 30.0


@dataclass(frozen=True)
class IbctlAccess:
    """What one ibctl instance allows."""

    mode: str
    allowed: frozenset[str] | None  # None: could not be read
    problem: str = ""

    @property
    def readable(self) -> bool:
        return self.allowed is not None

    def blocks(self, ibctl_command: str) -> bool | None:
        """True if ibctl refuses the command, False if it accepts it, None if unknown."""
        if self.allowed is None:
            return None
        return ibctl_command.upper() not in self.allowed


class IbctlAccessReader:
    def __init__(self, registry, clock: Callable[[], float] = time.time):
        self._registry = registry
        self._clock = clock
        self._cache: dict[str, tuple[float, IbctlAccess]] = {}

    async def read(self, mode: str, *, fresh: bool = False) -> IbctlAccess:
        """The instance's allow-list. Never raises."""
        now = self._clock()
        cached = self._cache.get(mode)
        if not fresh and cached is not None and 0 <= now - cached[0] < CACHE_SECONDS:
            return cached[1]
        access = await self._fetch(mode)
        if access.readable:
            self._cache[mode] = (now, access)
        else:
            self._cache.pop(mode, None)
        return access

    async def _fetch(self, mode: str) -> IbctlAccess:
        try:
            config = await self._registry.get_client(mode).config()
        except Exception as exc:  # unreachable, timed out, malformed reply: all "could not be read"
            logger.debug("Could not read %s's command allow-list: %s", mode, exc)
            return IbctlAccess(mode, None, str(exc))
        server = config.get("command_server") if isinstance(config, dict) else None
        names = server.get("allowed_commands") if isinstance(server, dict) else None
        if not isinstance(names, list):
            return IbctlAccess(mode, None, "ibctl's CONFIG reply does not list its allowed commands")
        return IbctlAccess(mode, frozenset(str(n).upper() for n in names))
