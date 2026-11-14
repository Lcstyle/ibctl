"""What has been built for an upgrade, what the last Sunday swap did, and
whether a swap is ready.

CI reports the image it built for a ``gateway/<version>`` branch; a Sunday
maintenance job reads the swap plan, swaps, and reports back. Both arrive
through the dashboard API and are saved on the persist volume.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from app.services.gateway_version.decision import Decision
from app.services.gateway_version.policy import DEFAULT_POLICY_PATH, UpgradePolicy, load_policy, save_policy
from app.services.gateway_version.versions import GatewayVersion

logger = logging.getLogger("dashboard.services.gateway_version.upgrade")

DEFAULT_RECORD_PATH = Path(os.environ.get("IBCTL_PERSIST_DIR", "/opt/ibctl/persist")) / "gateway_upgrade.json"
BUILD_STATUSES = ("built", "failed")
SWAP_RESULTS = ("ok", "rolled_back", "aborted", "failed")
MAX_DETAIL = 500
_SHA = re.compile(r"^[0-9a-f]{40}$")


class ReportError(ValueError):
    """A build or swap report that doesn't hold together."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _checked(version: str, sha: str, detail: str) -> None:
    try:
        GatewayVersion.parse(version)
    except ValueError as exc:
        raise ReportError(f"version {version!r} is not a Gateway version: {exc}") from exc
    if not _SHA.match(sha):
        raise ReportError(f"sha must be a full 40-character lowercase commit id, not {sha!r}")
    if len(detail) > MAX_DETAIL:
        raise ReportError(f"detail is longer than {MAX_DETAIL} characters")


def _when(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() is None:
        raise ValueError(f"saved time {value!r} has no UTC offset")
    return parsed


@dataclass(frozen=True)
class BuildReport:
    version: str
    sha: str
    status: str
    reported_at: datetime
    detail: str = ""

    def to_json(self) -> dict:
        return {"version": self.version, "sha": self.sha, "status": self.status,
                "reported_at": self.reported_at.isoformat(), "detail": self.detail}


@dataclass(frozen=True)
class SwapReport:
    version: str
    sha: str
    result: str
    reported_at: datetime
    detail: str = ""

    def to_json(self) -> dict:
        return {"version": self.version, "sha": self.sha, "result": self.result,
                "reported_at": self.reported_at.isoformat(), "detail": self.detail}


@dataclass(frozen=True)
class UpgradeRecord:
    candidate: BuildReport | None = None
    last_swap: SwapReport | None = None

    def to_json(self) -> dict:
        return {"candidate": self.candidate.to_json() if self.candidate else None,
                "last_swap": self.last_swap.to_json() if self.last_swap else None}

    @classmethod
    def from_json(cls, data: dict) -> UpgradeRecord:
        c, s = data.get("candidate"), data.get("last_swap")
        return cls(
            candidate=None if not c else BuildReport(c["version"], c["sha"], c["status"], _when(c["reported_at"]), c.get("detail", "")),
            last_swap=None if not s else SwapReport(s["version"], s["sha"], s["result"], _when(s["reported_at"]), s.get("detail", "")),
        )


@dataclass(frozen=True)
class SwapPlan:
    ready: bool
    version: str | None
    sha: str | None
    reason: str

    def to_json(self) -> dict:
        return {"ready": self.ready, "version": self.version, "sha": self.sha, "reason": self.reason}


def swap_plan(decision: Decision, candidate: BuildReport | None) -> SwapPlan:
    """Swap only to an image built for exactly the build the decision names."""
    if not decision.due:
        return SwapPlan(False, None, None, decision.reason)
    if candidate is None:
        return SwapPlan(False, None, None, f"nothing has been built for {decision.target}")
    if candidate.version != decision.target:
        return SwapPlan(False, None, None, f"the built candidate is {candidate.version}, not {decision.target}")
    if candidate.status != "built":
        detail = f": {candidate.detail}" if candidate.detail else ""
        return SwapPlan(False, None, None, f"the {candidate.version} build failed{detail}")
    return SwapPlan(True, candidate.version, candidate.sha,
                    f"{candidate.version} is built and due on {decision.swap_on.isoformat()}")


class UpgradeStore:
    def __init__(
        self,
        policy_path: Path = DEFAULT_POLICY_PATH,
        record_path: Path = DEFAULT_RECORD_PATH,
        clock: Callable[[], datetime] = _utcnow,
    ):
        self.policy_path = policy_path
        self.record_path = record_path
        self._clock = clock

    def policy(self) -> UpgradePolicy:
        """Raises PolicyError if the saved policy can't be read."""
        return load_policy(self.policy_path)

    def set_policy(self, policy: UpgradePolicy) -> None:
        save_policy(self.policy_path, policy)
        logger.info("Gateway upgrade policy saved: %s", policy.to_json())

    def record(self) -> UpgradeRecord:
        try:
            return UpgradeRecord.from_json(json.loads(self.record_path.read_text()))
        except FileNotFoundError:
            return UpgradeRecord()
        except (ValueError, KeyError, TypeError) as exc:
            logger.warning("Gateway upgrade record %s is unreadable (%s); treating it as empty", self.record_path, exc)
            return UpgradeRecord()

    def _save(self, record: UpgradeRecord) -> None:
        self.record_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.record_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(record.to_json(), indent=2))
        os.replace(tmp, self.record_path)

    def report_build(self, version: str, sha: str, status: str, detail: str = "") -> BuildReport:
        _checked(version, sha, detail)
        if status not in BUILD_STATUSES:
            raise ReportError(f"status must be one of {', '.join(BUILD_STATUSES)}, not {status!r}")
        report = BuildReport(version, sha, status, self._clock(), detail)
        self._save(replace(self.record(), candidate=report))
        logger.info("Gateway upgrade candidate reported: %s %s %s", version, sha[:12], status)
        return report

    def report_swap(self, version: str, sha: str, result: str, detail: str = "") -> SwapReport:
        _checked(version, sha, detail)
        if result not in SWAP_RESULTS:
            raise ReportError(f"result must be one of {', '.join(SWAP_RESULTS)}, not {result!r}")
        report = SwapReport(version, sha, result, self._clock(), detail)
        self._save(replace(self.record(), last_swap=report))
        logger.info("Gateway swap reported: %s %s %s", version, sha[:12], result)
        return report
