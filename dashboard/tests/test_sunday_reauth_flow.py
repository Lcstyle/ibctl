"""The Sunday re-authentication, as the operator experiences it.

The failure this guards against: an unattended Docker upgrade overnight
restarts both gateways. LIVE needs IB Key, nobody is awake, and it parks in
WaitingForHitl2fa. At the Sunday window the operator is told "cold restart in
28s — have your phone ready", ibctl then skips LIVE as "dormant", the
dashboard stays silent on that skip, and the only way back is scrolling to
the hours-old 2FA notification.

Contract under test: at the announced window every enabled mode gets a clear
outcome or a current, actionable path — without digging for an old message.

* The countdown is ONE message with a line per mode, rendered from the
  controller's own `cold_restart_plan` (no second copy of the decision
  table here), with a "Retry login" button for a mode waiting on 2FA, and
  suppressed entirely on a standby.
* Every new `last_cold_restart_outcome` produces one truthful notification
  (the first observation after a dashboard start is a baseline, not news).
* The HITL alert says plainly there is no automatic retry; its button reads
  "Retry login" (approval happens in IB Key, not on the button).
* A retry link tapped when there is nothing to retry says so, and sends
  nothing.
"""

from __future__ import annotations

import os
from dataclasses import asdict
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.services import hitl_tokens
from app.services.monitors import hitl_2fa
from app.services.monitors.cold_restart_pending import ColdRestartPendingMonitor

SIGNING_KEY = "sunday-flow-test-signing-key"
BASE_URL = "https://dash.example.test/ibctl"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class _Registry:
    def __init__(self, **modes: dict):
        self.instances = [SimpleNamespace(mode=m, status=s) for m, s in modes.items()]

    def cached_all_status(self):
        return self.instances

    def status_of(self, mode: str) -> dict:
        return next(i.status for i in self.instances if i.mode == mode)


class _NS:
    class _Config:
        channel = "ntfy"

        def __init__(self):
            self.events = {"cold_restart_pending": {"lead_seconds": 30}}

    def __init__(self, disabled: set[str] | None = None):
        self.config = self._Config()
        self._disabled = disabled or set()

    def is_event_enabled(self, event_type: str) -> bool:
        return event_type not in self._disabled


def _status(state: str, plan: str, *, hitl_secs_ago: int | None = None, role="primary", **extra):
    s = {"state": state, "ready": True, "cold_restart_plan": plan, "site": {"role": role}}
    if hitl_secs_ago is not None:
        s["hitl"] = {"active": True, "entered_at_secs_ago": hitl_secs_ago}
    s.update(extra)
    return s


def _outcome(outcome: str, recorded_at="2026-09-27T09:00:00-04:00[America/New_York]", **extra):
    return {"recorded_at": recorded_at, "outcome": outcome, "state": "x", **extra}


class _Frozen(datetime):
    _at: datetime

    @classmethod
    def now(cls, tz=None):
        return cls._at


@pytest.fixture
def at_0859_30(monkeypatch):
    """Sunday 2026-09-27 08:59:30 — 30 s before a 09:00 cold restart."""
    monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
    monkeypatch.setenv("TWS_COLD_RESTART_DAY", "0")
    monkeypatch.setenv("IBCTL_NTFY_ACTION_SIGNING_KEY", SIGNING_KEY)
    monkeypatch.setenv("IBCTL_DASHBOARD_EXTERNAL_URL", BASE_URL)
    frozen = type("F", (_Frozen,), {"_at": datetime(2026, 9, 27, 8, 59, 30)})
    monkeypatch.setattr("app.services.monitors.cold_restart_pending.datetime", frozen)


# ---------------------------------------------------------------------------
# The countdown
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_countdown_is_one_message_with_a_line_per_mode(at_0859_30):
    reg = _Registry(
        live=_status("WaitingForHitl2fa", "resumed_login", hitl_secs_ago=5 * 3600 + 47 * 60),
        paper=_status("Connected", "restarted"),
    )
    alerts = await ColdRestartPendingMonitor().check(reg, _NS())

    assert len(alerts) == 1, "one countdown, not one per mode"
    a = alerts[0]
    assert a.event_type == "cold_restart_pending"
    assert "30s" in a.title
    live = next(line for line in a.body.splitlines() if line.startswith("LIVE"))
    assert "waiting for 2FA since" in live
    assert "IB Key" in live
    assert "running gateway" in live and "no restart" in live, (
        "the 03:00 restart already happened; 09:00 finishes the login in that JVM"
    )
    paper = next(line for line in a.body.splitlines() if line.startswith("PAPER"))
    assert "connected" in paper.lower() and "restart" in paper.lower()


@pytest.mark.asyncio
async def test_countdown_offers_retry_login_for_a_mode_waiting_on_2fa(at_0859_30):
    reg = _Registry(
        live=_status("WaitingForHitl2fa", "resumed_login", hitl_secs_ago=6 * 3600),
        paper=_status("Connected", "restarted"),
    )
    (a,) = await ColdRestartPendingMonitor().check(reg, _NS())

    assert a.actions, "the operator must not have to dig up the overnight link"
    (btn,) = a.actions
    assert btn["label"] == "Retry LIVE login"
    assert btn["url"].startswith(f"{BASE_URL}/api/twofa/callback?t=")
    assert btn["url"].endswith("&mode=live")
    token = btn["url"].split("t=", 1)[1].split("&", 1)[0]
    assert hitl_tokens.validate_token(SIGNING_KEY, token, expected_intent="hitl")[0]


@pytest.mark.asyncio
async def test_countdown_with_preemption_off_tells_the_operator_to_tap_retry(at_0859_30):
    reg = _Registry(live=_status("WaitingForHitl2fa", "awaiting_operator", hitl_secs_ago=600))
    (a,) = await ColdRestartPendingMonitor().check(reg, _NS())
    live = next(line for line in a.body.splitlines() if line.startswith("LIVE"))
    assert "Retry login" in live
    assert a.actions and a.actions[0]["label"] == "Retry LIVE login"


@pytest.mark.asyncio
async def test_countdown_for_a_pending_ib_key_prompt_says_approve_it_now(at_0859_30):
    reg = _Registry(live=_status("WaitingFor2fa", "challenge_pending"))
    (a,) = await ColdRestartPendingMonitor().check(reg, _NS())
    live = next(line for line in a.body.splitlines() if line.startswith("LIVE"))
    assert "IB Key" in live and "approve" in live.lower()
    assert not a.actions, "nothing to retry — a prompt is already out"


@pytest.mark.asyncio
async def test_countdown_with_the_gateway_still_showing_an_ib_key_prompt_is_honest(at_0859_30):
    """HITL while the Gateway still shows its IB Key dialog: the push MAY be
    approvable, or the phone may already have dropped it. Say both, and
    keep the retry one tap away."""
    hitl = {"active": True, "entered_at_secs_ago": 120, "challenge_open": True, "relogin_armed": False}
    reg = _Registry(live=_status("WaitingForHitl2fa", "challenge_pending", hitl=hitl))
    (a,) = await ColdRestartPendingMonitor().check(reg, _NS())
    live = next(line for line in a.body.splitlines() if line.startswith("LIVE"))
    assert "may still" in live
    assert "running gateway" in live and "no restart" in live
    assert "replaces" in live, "Retry closes the open prompt now"
    assert a.actions and a.actions[0]["label"] == "Retry LIVE login"


@pytest.mark.asyncio
async def test_countdown_under_a_host_maintenance_hold_says_the_reauth_waits(at_0859_30):
    """The host is updating the container runtime under a
    hold. "Will restart in 30 s" would be wrong — the re-auth waits, and a
    gateway the update restarts is not restarted again."""
    hold = {"hold": {"id": "hold-1", "active": True}, "last": None}
    reg = _Registry(live=_status("Connected", "restarted", maintenance=hold))
    (a,) = await ColdRestartPendingMonitor().check(reg, _NS())
    live = next(line for line in a.body.splitlines() if line.startswith("LIVE"))
    assert "host maintenance" in live and "hold-1" in live
    assert "will restart" not in live
    assert "not restarted again" in live


@pytest.mark.asyncio
async def test_countdown_is_suppressed_on_a_standby_host(at_0859_30):
    """A standby host must not send 'cold restart in 24s — 2FA will be
    required' for a restart it then ignores. A standby has nothing to say."""
    reg = _Registry(
        live=_status("WaitingForLaunch", "standby", role="standby"),
        paper=_status("WaitingForLaunch", "standby", role="standby"),
    )
    assert await ColdRestartPendingMonitor().check(reg, _NS()) == []


@pytest.mark.asyncio
async def test_countdown_only_watches_for_a_restart_that_will_happen(at_0859_30):
    reg = _Registry(
        live=_status("WaitingForHitl2fa", "resumed_login", hitl_secs_ago=3600),
        paper=_status("Connected", "restarted"),
    )
    mon = ColdRestartPendingMonitor()
    await mon.check(reg, _NS())
    assert "paper" in mon._awaiting_disconnect
    assert "live" not in mon._awaiting_disconnect, (
        "LIVE's result arrives as an outcome record, not a disconnect guess"
    )


# ---------------------------------------------------------------------------
# Outcome notifications
# ---------------------------------------------------------------------------


async def _baseline_then(outcome: dict, *, state="WaitingForHitl2fa", plan="resumed_login",
                         hitl_secs_ago=3600, ns=None, **status_extra):
    """First tick: no outcome (baseline). Second tick: `outcome` recorded."""
    reg = _Registry(live=_status(state, plan, hitl_secs_ago=hitl_secs_ago, **status_extra))
    mon = ColdRestartPendingMonitor()
    ns = ns or _NS()
    assert await mon.check(reg, ns) == []
    reg.status_of("live")["last_cold_restart_outcome"] = outcome
    return await mon.check(reg, ns), mon, reg, ns


@pytest.mark.asyncio
async def test_resumed_login_tells_the_operator_to_approve_the_ib_key_prompt(monkeypatch):
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    alerts, *_ = await _baseline_then(_outcome("resumed_login"), state="Restarting",
                                      hitl_secs_ago=None)
    (a,) = alerts
    assert a.event_type == "cold_restart_outcome"
    assert "LIVE" in a.title
    assert "IB Key" in a.body
    assert "running gateway" in a.body and "no restart" in a.body
    assert a.priority == "high"


@pytest.mark.asyncio
async def test_a_restart_by_boot_says_the_login_is_still_owed(monkeypatch):
    """The container restarted after 09:00 (host
    maintenance). The boot counts as the restart; the login does not count
    until it succeeds — say so, and give the operator the action."""
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    monkeypatch.setenv("IBCTL_NTFY_ACTION_SIGNING_KEY", SIGNING_KEY)
    monkeypatch.setenv("IBCTL_DASHBOARD_EXTERNAL_URL", BASE_URL)
    alerts, *_ = await _baseline_then(
        _outcome("restarted_by_boot"), state="WaitingFor2fa", plan="challenge_pending",
        hitl_secs_ago=None,
    )
    (a,) = alerts
    assert a.event_type == "cold_restart_outcome"
    assert "restart" in a.body and "counts" in a.body
    assert "owed" in a.body and "IB Key" in a.body
    assert not a.actions, "logging in now — nothing to retry yet"

    # Parked: the same news carries the Retry button.
    alerts, *_ = await _baseline_then(
        _outcome("restarted_by_boot"), state="WaitingForHitl2fa", plan="resumed_login",
        hitl_secs_ago=60,
    )
    (a,) = alerts
    assert a.actions and a.actions[0]["label"] == "Retry LIVE login"


@pytest.mark.asyncio
async def test_awaiting_operator_outcome_carries_a_retry_login_button(monkeypatch):
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    monkeypatch.setenv("IBCTL_NTFY_ACTION_SIGNING_KEY", SIGNING_KEY)
    monkeypatch.setenv("IBCTL_DASHBOARD_EXTERNAL_URL", BASE_URL)
    alerts, *_ = await _baseline_then(_outcome("awaiting_operator"), plan="awaiting_operator")
    (a,) = alerts
    assert a.actions and a.actions[0]["label"] == "Retry LIVE login"


@pytest.mark.asyncio
async def test_challenge_pending_outcome_says_approve_now(monkeypatch):
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    alerts, *_ = await _baseline_then(_outcome("challenge_pending"), state="WaitingFor2fa",
                                      plan="challenge_pending", hitl_secs_ago=None)
    (a,) = alerts
    assert "IB Key" in a.body and "approve" in a.body.lower()


@pytest.mark.asyncio
async def test_challenge_pending_while_parked_says_what_happens_when_the_prompt_closes(monkeypatch):
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    monkeypatch.setenv("IBCTL_NTFY_ACTION_SIGNING_KEY", SIGNING_KEY)
    monkeypatch.setenv("IBCTL_DASHBOARD_EXTERNAL_URL", BASE_URL)
    hitl = {"active": True, "entered_at_secs_ago": 90, "challenge_open": True, "relogin_armed": True}
    alerts, *_ = await _baseline_then(
        _outcome("challenge_pending", state="WaitingForHitl2fa"),
        plan="challenge_pending", hitl_secs_ago=None, hitl=hitl,
    )
    (a,) = alerts
    assert "may still" in a.body, "an open dialog is no proof the phone still has the prompt"
    assert "once the gateway closes it" in a.body and "no restart" in a.body
    assert a.actions and a.actions[0]["label"] == "Retry LIVE login"


@pytest.mark.asyncio
async def test_deferred_outcome_says_a_login_was_already_running(monkeypatch):
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    alerts, *_ = await _baseline_then(_outcome("deferred"), state="Launching",
                                      plan="deferred", hitl_secs_ago=None)
    (a,) = alerts
    assert "already" in a.body.lower() and "no second restart" in a.body.lower()


@pytest.mark.asyncio
async def test_failed_outcome_is_urgent_and_explains(monkeypatch):
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    alerts, *_ = await _baseline_then(_outcome("failed", detail="jvm died"), state="Error",
                                      plan="failed", hitl_secs_ago=None)
    (a,) = alerts
    assert a.priority == "urgent"
    assert "jvm died" in a.body


@pytest.mark.asyncio
async def test_completed_outcome_confirms_success_with_the_time(monkeypatch):
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    alerts, *_ = await _baseline_then(
        _outcome("completed", completed_at="2026-09-27T09:01:56-04:00[America/New_York]"),
        state="Connected", plan="restarted", hitl_secs_ago=None,
    )
    (a,) = alerts
    assert a.event_type == "cold_restart_succeeded"
    assert "9:01 AM" in a.body


@pytest.mark.asyncio
async def test_already_satisfied_outcome_says_not_needed(monkeypatch):
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    alerts, *_ = await _baseline_then(
        _outcome("already_satisfied", last_login_at="2026-09-27T03:03:50-04:00[America/New_York]"),
        state="Connected", plan="restarted", hitl_secs_ago=None,
    )
    (a,) = alerts
    assert a.event_type == "cold_restart_skipped"
    assert "3:03 AM" in a.body


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["standby", "stopping"])
async def test_intentionally_idle_outcomes_are_silent(monkeypatch, outcome):
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    alerts, *_ = await _baseline_then(_outcome(outcome), state="WaitingForLaunch",
                                      plan="standby", hitl_secs_ago=None)
    assert alerts == []


@pytest.mark.asyncio
async def test_each_outcome_is_notified_once(monkeypatch):
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    alerts, mon, reg, ns = await _baseline_then(_outcome("deferred"), state="Launching",
                                                plan="deferred", hitl_secs_ago=None)
    assert len(alerts) == 1
    assert await mon.check(reg, ns) == []


@pytest.mark.asyncio
async def test_an_outcome_already_present_at_startup_is_a_baseline_not_news(monkeypatch):
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    reg = _Registry(live=_status("Connected", "restarted",
                                 last_cold_restart_outcome=_outcome("completed",
                                                                    completed_at="x")))
    assert await ColdRestartPendingMonitor().check(reg, _NS()) == []


@pytest.mark.asyncio
async def test_outcome_notifications_respect_their_event_toggle(monkeypatch):
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    alerts, *_ = await _baseline_then(_outcome("deferred"), state="Launching", plan="deferred",
                                      hitl_secs_ago=None,
                                      ns=_NS(disabled={"cold_restart_outcome"}))
    assert alerts == []


@pytest.mark.asyncio
async def test_a_restarted_outcome_arms_the_success_watch(monkeypatch):
    """An owed restart can run long after the countdown (at the next
    Connected); its success must still be confirmed."""
    monkeypatch.delenv("TWS_COLD_RESTART", raising=False)
    alerts, mon, *_ = await _baseline_then(_outcome("restarted"), state="Connected",
                                           plan="restarted", hitl_secs_ago=None)
    assert alerts == []
    assert "live" in mon._awaiting_disconnect


# ---------------------------------------------------------------------------
# The HITL alert
# ---------------------------------------------------------------------------


def test_hitl_alert_says_there_is_no_automatic_retry():
    text = hitl_2fa._format_next_retry(None)
    assert "no automatic retry" in text.lower()
    assert "unknown" not in text.lower()


def test_hitl_button_reads_retry_login_not_approve():
    btn = hitl_2fa._build_action_button(BASE_URL, "tok", "live")
    assert btn["label"] == "Retry LIVE login"


# ---------------------------------------------------------------------------
# The callback: a retry link tapped when there is nothing to retry
# ---------------------------------------------------------------------------


@pytest.fixture
async def dash(fake_client):
    from app.instance_registry import _CachedResponse
    from app.main import create_app
    from tests.auth_helpers import authed_settings

    # A dashboard password is configured and the client stays signed out:
    # a notification link works without a login.
    app = create_app(settings=authed_settings())
    registry = app.state.instance_registry
    for mode in registry.modes():
        registry._clients[mode] = fake_client

    def set_status(mode: str, state: str, hitl_active: bool = False, challenge_open: bool = False):
        s = dict(asdict(fake_client._status))
        s["state"] = state
        s["hitl"] = {"active": True, "challenge_open": challenge_open} if hitl_active else None
        registry._cache[f"{mode}:STATUS"] = _CachedResponse(s, registry.STATUS_TTL)

    import app.api.twofa as twofa_mod
    twofa_mod._ip_timestamps.clear()
    with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            yield c, set_status
    twofa_mod._ip_timestamps.clear()


@pytest.mark.asyncio
async def test_retry_link_during_a_login_in_progress_sends_nothing_and_says_so(dash, fake_client):
    client, set_status = dash
    set_status("live", "Restarting")
    token = hitl_tokens.mint_token(SIGNING_KEY, "live", None)

    resp = await client.get(f"/api/twofa/callback?t={token}&mode=live")

    assert resp.status_code == 200
    assert fake_client._last_command is None, "nothing to retry — nothing sent"
    assert "already logging in" in resp.text.lower()
    assert "retry triggered" not in resp.text.lower()


@pytest.mark.asyncio
async def test_retry_link_while_connected_says_nothing_to_do(dash, fake_client):
    client, set_status = dash
    set_status("live", "Connected")
    token = hitl_tokens.mint_token(SIGNING_KEY, "live", None)

    resp = await client.get(f"/api/twofa/callback?t={token}&mode=live")

    assert resp.status_code == 200
    assert fake_client._last_command is None
    assert "connected" in resp.text.lower() and "nothing to do" in resp.text.lower()


@pytest.mark.asyncio
async def test_retry_link_while_waiting_on_2fa_still_retries(dash, fake_client):
    client, set_status = dash
    set_status("live", "WaitingForHitl2fa", hitl_active=True)
    token = hitl_tokens.mint_token(SIGNING_KEY, "live", None)

    resp = await client.get(f"/api/twofa/callback?t={token}&mode=live")

    assert resp.status_code == 200
    assert fake_client._last_command == "HITL_RESUME"


# ---------------------------------------------------------------------------
# The callback: what "Retry login" actually does
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_retry_link_resubmits_the_login_in_the_running_gateway(dash, fake_client):
    client, set_status = dash
    set_status("live", "WaitingForHitl2fa", hitl_active=True)
    token = hitl_tokens.mint_token(SIGNING_KEY, "live", None)

    resp = await client.get(f"/api/twofa/callback?t={token}&mode=live")

    assert resp.status_code == 200
    assert fake_client._last_command == "HITL_RESUME"
    assert "running gateway" in resp.text and "no restart" in resp.text


@pytest.mark.asyncio
async def test_retry_link_while_the_ib_key_prompt_is_still_up_says_so(dash, fake_client):
    client, set_status = dash
    set_status("live", "WaitingForHitl2fa", hitl_active=True, challenge_open=True)
    token = hitl_tokens.mint_token(SIGNING_KEY, "live", None)

    resp = await client.get(f"/api/twofa/callback?t={token}&mode=live")

    assert resp.status_code == 200
    assert fake_client._last_command == "HITL_RESUME"
    text = resp.text.lower()
    assert "still shows an ib key prompt" in text
    # The tap asks for a fresh push: the open prompt is closed.
    assert "replaces" in text and "closes that prompt" in text and "no restart" in text
