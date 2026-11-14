"""Monitor: Gateway version alerts.

Starts the weekly check when it is due (in the background, so the shared
monitor loop never waits on IB), then evaluates alerts from the saved result:

- ``gateway_desupport``: IB announced a cutoff (warning), then 30/14/7/2/0
  days before it (urgent), and once when IB stops warning.
- ``gateway_update``: a newer build on our channel, once per build.
- ``gateway_version_check_failing``: the check has not reached IB for a week
  (probe or release files), or has not completed for eight days, so the two
  above can't fire; once more when it works again.
- With an upgrade store: the upgrade alerts (upgrade_alerts.py), and a
  desupport alert that says whether automatic upgrades will handle it.

Evaluating from the saved result keeps the countdown running between weekly
checks, and the record of sent alerts is saved so a restart repeats none.
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime, timedelta
from typing import Callable
from zoneinfo import ZoneInfo

from app.services.gateway_version.policy import PolicyError
from app.services.gateway_version.service import GatewayVersionService, VersionState
from app.services.gateway_version.upgrade import UpgradeStore
from app.services.gateway_version.upgrade_alerts import desupport_note as upgrade_note
from app.services.gateway_version.upgrade_alerts import upgrade_alerts
from app.services.gateway_version.versions import GatewayVersion
from app.services.gateway_version.view import parse_or_none
from app.services.monitor_manager import Alert, Monitor

logger = logging.getLogger("dashboard.services.monitors.gateway_version")

DESUPPORT_EVENT = "gateway_desupport"
UPDATE_EVENT = "gateway_update"
CHECK_FAILING_EVENT = "gateway_version_check_failing"
# A week of failure spans at least one weekly check and its retries.
BLIND_AFTER = timedelta(days=7)
# The weekly check plus a day: a check that never completes is blind too.
STALE_AFTER = timedelta(days=8)
COUNTDOWN_DAYS = (30, 14, 7, 2, 0)
ET = ZoneInfo("America/New_York")


def _today_et() -> date:
    """The operator's calendar day; IB's cutoff is a US calendar date."""
    return datetime.now(ET).date()


def _available(state: VersionState) -> str:
    parts = [f"{c} {r.version}" for c, r in sorted(state.releases.items())]
    return ", ".join(parts) or "unknown (IB's release files were not readable)"


def _desupport_alerts(
    state: VersionState, running: GatewayVersion | None, today: date, memo: dict, note: str | None = None,
) -> list[Alert]:
    notice = state.notice
    if notice is None:
        announced = memo.get("notice")
        if not announced:
            return []
        memo.pop("notice", None)
        memo.pop("countdown", None)
        return [Alert(
            event_type=DESUPPORT_EVENT,
            title="ibctl: Gateway desupport warning cleared",
            body=f"IB no longer warns about this Gateway (running {state.running}); the cutoff it announced no longer applies.",
            priority="default",
            tags="white_check_mark",
        )]
    if running is not None and notice.met_by(running):
        return []  # upgraded; the next check confirms with IB

    key = f"{notice.cutoff.isoformat()}|{notice.minimum}"
    days = notice.days_left(today)
    crossed = [t for t in COUNTDOWN_DAYS if days <= t]
    sent = set(memo.get("countdown", {}).get(key, []))
    tightest = min(crossed) if crossed else None
    first = memo.get("notice") != key
    if not first and (tightest is None or tightest in sent):
        return []

    memo["notice"] = key
    memo.setdefault("countdown", {})[key] = sorted(sent | set(crossed))
    when = "today" if days == 0 else (f"{-days} days ago" if days < 0 else f"in {days} days")
    return [Alert(
        event_type=DESUPPORT_EVENT,
        title=f"ibctl: Gateway {notice.running} will be desupported on {notice.cutoff} ({when})",
        body=(
            f"IB will desupport Gateway {notice.running} on {notice.cutoff}, {days} days from today. "
            f"The minimum supported version then is {notice.minimum}. Running {state.running}; "
            f"IB currently offers {_available(state)}. {note or 'Upgrade the Gateway image before the cutoff.'}"
        ),
        priority="urgent" if tightest is not None else "high",
        tags="warning,calendar",
    )]


def _update_alert(state: VersionState, running: GatewayVersion | None, memo: dict) -> Alert | None:
    release = state.releases.get(state.channel)
    if release is None or running is None or release.version <= running:
        return None
    key = f"{state.channel}:{release.version}"
    if memo.get("update") == key:
        return None
    memo["update"] = key
    return Alert(
        event_type=UPDATE_EVENT,
        title=f"ibctl: Gateway {release.version} is out on the {state.channel} channel",
        body=f"IB released Gateway {release.version} ({state.channel}) on {release.released_on}. Running {state.running}.",
        priority="default",
        tags="arrow_up",
    )


def _when_et(t: datetime) -> str:
    return f"{t.astimezone(ET).strftime('%a %b')} {t.astimezone(ET).day} {t.astimezone(ET):%H:%M} ET"


def _blind_alerts(state: VersionState, now: datetime, memo: dict) -> list[Alert]:
    causes = []
    if state.probe_failing_since is not None and now - state.probe_failing_since >= BLIND_AFTER:
        causes.append(("probe", state.probe_failing_since,
                       f"the Gateway probe has failed since {_when_et(state.probe_failing_since)}"
                       f" ({state.probe_error or 'no detail'})"))
    if state.releases_failing_since is not None and now - state.releases_failing_since >= BLIND_AFTER:
        errors = "; ".join(f"{c}: {e}" for c, e in sorted(state.release_errors.items())) or "no detail"
        causes.append(("releases", state.releases_failing_since,
                       f"IB's release files have been unreadable since {_when_et(state.releases_failing_since)}"
                       f" ({errors})"))
    if state.checked_at is not None and now - state.checked_at >= STALE_AFTER:
        causes.append(("stale", state.checked_at, f"no version check has completed since {_when_et(state.checked_at)}"))

    active = memo.get("blind")
    if not causes:
        if not active:
            return []
        memo.pop("blind", None)
        return [Alert(
            event_type=CHECK_FAILING_EVENT,
            title="ibctl: Gateway version check is working again",
            body="The weekly check is getting answers from IB again; desupport and update alerts are back.",
            priority="default",
            tags="white_check_mark",
        )]
    key = "|".join(f"{name}@{since.isoformat()}" for name, since, _ in causes)
    if active == key:
        return []
    memo["blind"] = key
    what = "; ".join(text for _, _, text in causes)
    return [Alert(
        event_type=CHECK_FAILING_EVENT,
        title="ibctl: Gateway version check is failing",
        body=(
            f"{what[0].upper()}{what[1:]}. Until it works, desupport warnings and update alerts can't be sent. "
            "The Gateway tab shows the last check."
        ),
        priority="high",
        tags="warning,mag",
    )]


def evaluate_alerts(
    state: VersionState,
    today: date,
    enabled: Callable[[str], bool],
    *,
    now: datetime | None = None,
    desupport_note: str | None = None,
) -> list[Alert]:
    """Alerts due now, recording each sent one in ``state.alerts``.

    Only a site that has had an answer from IB alerts: the standby's
    dashboard reads the same release files and must not duplicate them. A
    disabled event sends nothing and stays owed. ``now`` (an aware instant)
    turns on the check-failing alert; ``desupport_note`` replaces the
    desupport alert's closing advice.
    """
    if state.last_probe_at is None:
        return []
    running = parse_or_none(state.running)
    alerts: list[Alert] = []
    if enabled(DESUPPORT_EVENT):
        alerts.extend(_desupport_alerts(state, running, today, state.alerts, desupport_note))
    if enabled(UPDATE_EVENT):
        update = _update_alert(state, running, state.alerts)
        if update:
            alerts.append(update)
    if now is not None and enabled(CHECK_FAILING_EVENT):
        alerts.extend(_blind_alerts(state, now, state.alerts))
    for alert in alerts:
        logger.warning("Gateway version alert: %s", alert.title)
    return alerts


class GatewayVersionMonitor(Monitor):
    event_type = DESUPPORT_EVENT
    interval_seconds = 300

    def __init__(
        self,
        service: GatewayVersionService,
        today: Callable[[], date] = _today_et,
        *,
        upgrades: UpgradeStore | None = None,
    ):
        self._service = service
        self._today = today
        self._upgrades = upgrades
        self._policy_error: str | None = None

    def _policy(self):
        """The saved upgrade policy, or None when it can't be read (logged once per error)."""
        try:
            policy = self._upgrades.policy()
        except PolicyError as exc:
            if str(exc) != self._policy_error:
                logger.warning("Gateway upgrade policy unreadable; upgrade alerts are off until it is: %s", exc)
            self._policy_error = str(exc)
            return None
        self._policy_error = None
        return policy

    async def check(self, registry, ns) -> list[Alert]:
        if self._service.due() and self._service.start_check():
            logger.info("Gateway version check started")
        state = self._service.current()
        before = json.dumps(state.alerts, sort_keys=True)
        today, now = self._today(), self._service.now()
        policy, note = None, None
        if self._upgrades is not None:
            policy = self._policy()
            note = upgrade_note(policy, state, today)
        alerts = evaluate_alerts(state, today, ns.is_event_enabled, now=now, desupport_note=note)
        if policy is not None and state.last_probe_at is not None:
            alerts.extend(upgrade_alerts(policy, state, self._upgrades.record(), now, ns.is_event_enabled))
        if json.dumps(state.alerts, sort_keys=True) != before:
            self._service.save()
        return alerts
