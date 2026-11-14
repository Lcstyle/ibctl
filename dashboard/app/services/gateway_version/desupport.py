"""IB's desupport notice: API error 2172.

IB sends it on every new API connection once a cutoff is announced, e.g.:

    The version of the application you are running, 1047.1, needs to be
    upgraded, as it will be desupported on 20261215. The minimum supported
    version at that time will be 1050.1.

The cutoff is a calendar date, not an instant, so it stays a ``date``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime

from app.services.gateway_version.versions import GatewayVersion

DESUPPORT_CODE = 2172

_PATTERN = re.compile(
    r"running,\s*(?P<running>[\d.]+[a-z]?),.*?desupported on\s*(?P<cutoff>\d{8})"
    r".*?minimum supported version.*?will be\s*(?P<minimum>\d[\d.]*[a-z]?)",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True)
class DesupportNotice:
    running: GatewayVersion
    cutoff: date
    minimum: GatewayVersion

    def days_left(self, today: date) -> int:
        """Calendar days from ``today`` to the cutoff; negative once past it."""
        return (self.cutoff - today).days

    def met_by(self, version: GatewayVersion) -> bool:
        return version >= self.minimum


def parse_2172(text: str) -> DesupportNotice:
    """Parse a 2172 message. A message in any other shape is an error rather
    than a guess: a misread cutoff is worse than a missing one."""
    m = _PATTERN.search(text)
    if not m:
        raise ValueError(f"not a desupport notice: {text!r}")
    try:
        cutoff = datetime.strptime(m["cutoff"], "%Y%m%d").date()
    except ValueError as exc:
        raise ValueError(f"desupport notice has an impossible date {m['cutoff']!r}") from exc
    return DesupportNotice(
        running=GatewayVersion.parse(m["running"]),
        cutoff=cutoff,
        minimum=GatewayVersion.parse(m["minimum"].rstrip(".")),
    )
