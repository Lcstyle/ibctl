"""Multi-instance domain model for monitoring live and paper ibctl daemons.

Each ibctl instance runs independently with its own command server port.
The dashboard connects to each via InstanceEndpoint and aggregates their
status into InstanceStatus objects for rendering.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class InstanceEndpoint:
    """Connection details for one ibctl command server."""

    mode: str   # "live" or "paper"
    host: str
    port: int


@dataclass(frozen=True)
class InstanceStatus:
    """Status of a single ibctl instance, with identity.

    When the instance is unreachable, status is None and error describes why.
    The dashboard always renders — showing "Unreachable" for down instances.
    """

    mode: str
    status: dict[str, Any] | None = None  # Parsed STATUS JSON, None = unreachable
    state_data: dict[str, Any] | None = None  # Parsed STATE JSON (transition history)
    error: str | None = None
