"""Alerts about automatic Gateway upgrades, before they happen.

The Sunday maintenance job reports what a swap did (installed, rolled back,
failed). These come earlier, from the same decision the Gateway tab shows:

- ``gateway_upgrade_scheduled``: an upgrade is planned for Sunday (once per
  Sunday and target); its candidate image is built; it was called off.
- ``gateway_upgrade_blocked``: a planned upgrade can't run, because its build
  failed, or nothing was built for it by Saturday 18:00 ET.

What was sent is kept in ``VersionState.alerts["upgrade"]``, saved with the
version state, so a restart repeats nothing. A disabled event sends nothing
and stays owed, as the version alerts do.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta
from typing import Callable

from app.services.gateway_version.decision import ET, Decision, decide
from app.services.gateway_version.policy import UpgradePolicy
from app.services.gateway_version.service import VersionState
from app.services.gateway_version.upgrade import UpgradeRecord, swap_plan
from app.services.gateway_version.versions import GatewayVersion
from app.services.gateway_version.view import parse_or_none
from app.services.monitor_manager import Alert

SCHEDULED_EVENT = "gateway_upgrade_scheduled"
BLOCKED_EVENT = "gateway_upgrade_blocked"
# The weekly upgrade build runs on Saturday afternoon; by 18:00 ET
# a missing one is not just slow.
NOTHING_BUILT_BY = time(18, 0)
# The Sunday maintenance job swaps from here on and reports what it did.
WINDOW_OPENS = time(9, 0)

SKIP_HINT = "To skip it, turn automatic upgrades off on the Gateway tab."


def _day(d: date) -> str:
    """'Sun Nov 15'."""
    return f"{d.strftime('%a %b')} {d.day}"


def _memo(state: VersionState) -> dict:
    return state.alerts.get("upgrade", {})


def _write(state: VersionState, memo: dict) -> None:
    if memo:
        state.alerts["upgrade"] = memo
    else:
        state.alerts.pop("upgrade", None)


def _scheduled(
    decision: Decision,
    state: VersionState,
    record: UpgradeRecord,
    today: date,
    memo: dict,
) -> list[Alert]:
    planned = memo.get("planned")
    if not decision.due:
        if planned is None:
            return []
        memo.pop("planned", None)
        memo.pop("ready", None)
        running = parse_or_none(state.running)
        sunday = date.fromisoformat(planned["sunday"])
        if (
            running is not None and running >= GatewayVersion.parse(planned["target"])
        ) or today > sunday:
            return []  # it went in, or its Sunday has passed: the Sunday job said what happened
        return [
            Alert(
                event_type=SCHEDULED_EVENT,
                title=f"ibctl: Sunday's Gateway upgrade to {planned['target']} is off",
                body=f"The upgrade planned for {_day(sunday)} won't run: {decision.reason}.",
                priority="default",
                tags="no_entry_sign",
            )
        ]

    alerts = []
    key = {"sunday": decision.swap_on.isoformat(), "target": decision.target}
    if planned != key:
        memo["planned"] = key
        memo.pop("ready", None)
        why = (
            f"{decision.reason[0].upper()}{decision.reason[1:]}."
            if decision.reason
            else ""
        )
        alerts.append(
            Alert(
                event_type=SCHEDULED_EVENT,
                title=f"ibctl: Gateway upgrade to {decision.target} on {_day(decision.swap_on)}",
                body=(
                    f"{why} The Sunday maintenance window installs it from about 09:00 ET: PAPER first as the "
                    "canary, then LIVE, which needs its 2FA approved. The candidate image is built on Saturday "
                    f"afternoon and you'll get another message when it is. {SKIP_HINT}"
                ),
                priority="high",
                tags="calendar,arrow_up",
            )
        )

    plan = swap_plan(decision, record.candidate)
    if plan.ready:
        ready = f"{decision.swap_on.isoformat()}|{plan.version}|{plan.sha}"
        if memo.get("ready") != ready:
            memo["ready"] = ready
            alerts.append(
                Alert(
                    event_type=SCHEDULED_EVENT,
                    title=f"ibctl: Gateway {plan.version} is built; it goes in {_day(decision.swap_on)} ~09:00 ET",
                    body=(
                        f"Candidate image {plan.sha[:12]} is built for {plan.version}. Sunday's window swaps PAPER to "
                        "it first and rolls back if PAPER doesn't connect; then LIVE restarts and needs its 2FA. "
                        f"{SKIP_HINT[:-1]} before 09:00 ET Sunday."
                    ),
                    priority="high",
                    tags="package,calendar",
                )
            )
    return alerts


def _blocked(
    decision: Decision, record: UpgradeRecord, now_et: datetime, memo: dict
) -> list[Alert]:
    if not decision.due:
        return []
    plan = swap_plan(decision, record.candidate)
    if plan.ready or now_et >= datetime.combine(decision.swap_on, WINDOW_OPENS, ET):
        return []
    sunday = _day(decision.swap_on)
    candidate = record.candidate
    if (
        candidate is not None
        and candidate.version == decision.target
        and candidate.status == "failed"
    ):
        key = f"{decision.swap_on.isoformat()}|{decision.target}|failed|{candidate.reported_at.isoformat()}"
        title = f"ibctl: Sunday's Gateway upgrade to {decision.target} won't happen: the build failed"
        body = (
            f"{plan.reason[0].upper()}{plan.reason[1:]}. Nothing is installed on {sunday} unless a "
            f"gateway/{decision.target} pipeline succeeds before 09:00 ET."
        )
    else:
        if now_et < datetime.combine(
            decision.swap_on - timedelta(days=1), NOTHING_BUILT_BY, ET
        ):
            return []
        key = f"{decision.swap_on.isoformat()}|{decision.target}|missing"
        title = f"ibctl: Sunday's Gateway upgrade to {decision.target} won't happen: nothing was built"
        body = (
            f"By Saturday evening, {plan.reason}. The weekly upgrade build makes it on Saturday afternoon; "
            f"check whether it ran. Nothing is installed on {sunday} without a built candidate."
        )
    if memo.get("blocked") == key:
        return []
    memo["blocked"] = key
    if decision.deadline:
        body += " IB desupports the running Gateway soon, so this needs fixing."
    return [
        Alert(
            event_type=BLOCKED_EVENT,
            title=title,
            body=body,
            priority="urgent" if decision.deadline else "high",
            tags="warning,package",
        )
    ]


def upgrade_alerts(
    policy: UpgradePolicy,
    state: VersionState,
    record: UpgradeRecord,
    now: datetime,
    enabled: Callable[[str], bool],
) -> list[Alert]:
    """Upgrade alerts due at ``now`` (an aware instant), recorded in ``state.alerts``."""
    now_et = now.astimezone(ET)
    decision = decide(policy, state, now_et.date())
    memo = dict(_memo(state))
    alerts: list[Alert] = []
    if enabled(SCHEDULED_EVENT):
        alerts.extend(_scheduled(decision, state, record, now_et.date(), memo))
    if enabled(BLOCKED_EVENT):
        alerts.extend(_blocked(decision, record, now_et, memo))
    _write(state, memo)
    return alerts


def desupport_note(
    policy: UpgradePolicy | None, state: VersionState, today: date
) -> str:
    """The desupport alert's last sentence: whether automatic upgrades will handle it."""
    if policy is None:
        return "The saved upgrade policy can't be read, so nothing will upgrade the Gateway automatically."
    if not policy.enabled:
        return (
            "Automatic upgrades are off (Gateway tab), so nothing will upgrade it by itself: "
            "turn them on or upgrade the image by hand before the cutoff."
        )
    decision = decide(policy, state, today)
    if decision.due:
        return f"Automatic upgrades will install {decision.target} on {_day(decision.swap_on)}."
    if decision.deadline and state.notice is not None:
        return (
            f"Automatic upgrades can't fix it yet: no build at or above {state.notice.minimum} has been seen. "
            "Upgrade by hand if none appears before the cutoff."
        )
    return (
        f"Automatic upgrades will upgrade it on the first Sunday within {policy.deadline_days} days of the "
        "cutoff, if not sooner."
    )
