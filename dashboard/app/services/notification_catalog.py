"""Every alert the dashboard can send, grouped the way the Alerts page shows them.

This is the one list. The Alerts page draws its switches from it and the
Gateway tab counts its group from it, so an event the notification config
knows always has a switch (tests/test_notification_catalog.py holds the two
to the same keys).

``loudness`` is the ntfy priorities an alert can go out at, quietest first:
it decides whether the phone buzzes. ``default`` shows as "normal".
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Group:
    key: str
    label: str


@dataclass(frozen=True)
class EventInfo:
    key: str
    group: str
    label: str
    desc: str
    loudness: tuple[str, ...]
    timeout: bool = False


GROUPS = (
    Group("login", "Login & 2FA"),
    Group("connection", "Connection"),
    Group("restarts", "Scheduled restarts"),
    Group("gateway", "Gateway versions & upgrades"),
)

EVENTS = (
    # Login & 2FA
    EventInfo(
        "login_failed",
        "login",
        "Login Failed",
        "A login attempt failed and ibctl restarted the Gateway",
        ("urgent",),
    ),
    EventInfo(
        "relogin_failed",
        "login",
        "Re-login Failed",
        "Every re-login attempt was used up",
        ("urgent",),
    ),
    EventInfo(
        "hitl_2fa_required",
        "login",
        "2FA Required",
        "A Gateway is waiting on its 2FA; with ntfy action signing set up the alert has a Retry login button",
        ("urgent",),
    ),
    EventInfo(
        "twofa_push_waiting",
        "login",
        "IB Key Push Waiting",
        "An IB Key push has gone unanswered past the 2FA alert time; ibctl keeps it and the Gateway running",
        ("high",),
    ),
    EventInfo(
        "auth_relaunch",
        "login",
        "Gateway Relaunched During Login",
        "Why ibctl relaunched a Gateway while logging in (a new IB Key push follows); urgent if an open push "
        "was abandoned",
        ("high", "urgent"),
    ),
    EventInfo(
        "session_conflict_loop",
        "login",
        "Session Conflict Loop",
        'ibctl stopped answering repeated "Existing session detected" dialogs, with who the other session is',
        ("urgent",),
    ),
    # Connection
    EventInfo(
        "session_lost",
        "connection",
        "Session Lost",
        "A Gateway left Connected unexpectedly",
        ("default", "high"),
    ),
    EventInfo(
        "no_clients",
        "connection",
        "No API Clients",
        "A Gateway is Connected but no API client has connected for the timeout",
        ("urgent",),
        timeout=True,
    ),
    EventInfo(
        "ib_maintenance",
        "connection",
        "IB Maintenance",
        "IB's status page changed to maintenance or an outage; high for an outage",
        ("default", "high"),
    ),
    # Scheduled restarts
    EventInfo(
        "cold_restart_pending",
        "restarts",
        "Cold Restart Warning",
        "Shortly before the scheduled Sunday cold restart, which needs 2FA",
        ("urgent",),
    ),
    EventInfo(
        "cold_restart_succeeded",
        "restarts",
        "Cold Restart Succeeded",
        "The scheduled Sunday cold restart reconnected",
        ("default",),
    ),
    EventInfo(
        "cold_restart_skipped",
        "restarts",
        "Cold Restart Not Needed",
        "A mode already re-authenticated today, so ibctl skipped its scheduled cold restart",
        ("default",),
    ),
    EventInfo(
        "cold_restart_outcome",
        "restarts",
        "Cold Restart Outcome",
        "What the Sunday cold restart did for a mode that needed more than a restart: resumed a 2FA wait, kept "
        "a pending IB Key prompt, joined a login in progress, or could not run",
        ("default", "high", "urgent"),
    ),
    EventInfo(
        "warm_restart",
        "restarts",
        "Warm Restart",
        "The Gateway JVM did a warm restart",
        ("default",),
    ),
    # Gateway versions & upgrades
    EventInfo(
        "gateway_update",
        "gateway",
        "Gateway Update Available",
        "IB released a newer Gateway build on the channel this image tracks, once per build",
        ("default",),
    ),
    EventInfo(
        "gateway_desupport",
        "gateway",
        "Gateway Desupport Cutoff",
        "IB announced a date after which this Gateway version is unsupported: when first seen, then urgent "
        "30, 14, 7, 2 and 0 days before it, and once when IB stops warning. Says whether automatic upgrades "
        "will handle it",
        ("default", "high", "urgent"),
    ),
    EventInfo(
        "gateway_upgrade_scheduled",
        "gateway",
        "Gateway Upgrade Scheduled",
        "An automatic upgrade is planned for Sunday's maintenance window (PAPER first, then LIVE with 2FA); "
        "again once its image is built, and if it is called off",
        ("default", "high"),
    ),
    EventInfo(
        "gateway_upgrade_blocked",
        "gateway",
        "Gateway Upgrade Won't Happen",
        "A planned upgrade can't run: its candidate build failed, or nothing was built by Saturday 18:00 ET; "
        "urgent before a desupport cutoff",
        ("high", "urgent"),
    ),
    EventInfo(
        "gateway_version_check_failing",
        "gateway",
        "Version Check Failing",
        "The weekly version check has not reached IB for a week (or not run for eight days), so update and "
        "desupport alerts can't be sent; once more when it works again",
        ("default", "high"),
    ),
)


def catalog_json() -> dict:
    return {
        "groups": [
            {
                "key": g.key,
                "label": g.label,
                "events": [
                    {
                        "key": e.key,
                        "label": e.label,
                        "desc": e.desc,
                        "loudness": list(e.loudness),
                        "timeout": e.timeout,
                    }
                    for e in EVENTS
                    if e.group == g.key
                ],
            }
            for g in GROUPS
        ]
    }
