"""The Gateway upgrade policy: whether, and how, ibctl keeps its Gateway current.

Set on the dashboard's Gateway tab and saved on the persist volume. It is off
until the operator turns it on; with it off nothing upgrades on its own, and
the desupport alerts still fire.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path

from app.services.gateway_version.releases import CHANNELS

DEFAULT_POLICY_PATH = (
    Path(os.environ.get("IBCTL_PERSIST_DIR", "/opt/ibctl/persist")) / "config" / "gateway_upgrade_policy.json"
)

# Which Sundays may carry an upgrade. The swap itself always runs in the Sunday
# 08:58 maintenance window; the cadence only decides which Sundays qualify.
CADENCES = {
    "every_sunday": "every Sunday",
    "first_sunday": "the first Sunday of the month",
}
MAX_DAYS = 90


class PolicyError(ValueError):
    """The policy is invalid, or its saved file cannot be read."""


def cadence_allows(cadence: str, sunday: date) -> bool:
    if cadence == "first_sunday":
        return sunday.day <= 7
    return True


@dataclass(frozen=True)
class UpgradePolicy:
    enabled: bool = False
    channel: str = "stable"
    cadence: str = "first_sunday"
    # Pick the newest build on the channel that has been out at least this many
    # days on the Sunday of the swap. A rule of "the newest build, once it is N
    # days old" would stall on the latest channel, which moves weekly.
    soak_days: int = 7
    # IB's cutoff this close (days after the swap Sunday) upgrades at the next
    # Sunday whatever the cadence and soak say.
    deadline_days: int = 21

    def __post_init__(self):
        if not isinstance(self.enabled, bool):
            raise PolicyError(f"enabled must be true or false, not {self.enabled!r}")
        if self.channel not in CHANNELS:
            raise PolicyError(f"channel must be one of {', '.join(CHANNELS)}, not {self.channel!r}")
        if self.cadence not in CADENCES:
            raise PolicyError(f"cadence must be one of {', '.join(CADENCES)}, not {self.cadence!r}")
        for name in ("soak_days", "deadline_days"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_DAYS:
                raise PolicyError(f"{name} must be a whole number of days from 0 to {MAX_DAYS}, not {value!r}")

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict) -> UpgradePolicy:
        if not isinstance(data, dict):
            raise PolicyError("the saved policy is not an object")
        known = {k: data[k] for k in ("enabled", "channel", "cadence", "soak_days", "deadline_days") if k in data}
        return cls(**known)


def load_policy(path: Path) -> UpgradePolicy:
    """The saved policy, or the default when none was ever saved.

    An unreadable or invalid file raises: falling back to the default would
    silently change whether upgrades happen.
    """
    try:
        text = path.read_text()
    except FileNotFoundError:
        return UpgradePolicy()
    try:
        return UpgradePolicy.from_json(json.loads(text))
    except json.JSONDecodeError as exc:
        raise PolicyError(f"{path} is not valid JSON: {exc}") from exc


def save_policy(path: Path, policy: UpgradePolicy) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(policy.to_json(), indent=2))
    os.replace(tmp, path)
