"""The dashboard side of the 2FA round policy.

ibctl used to give up on an IB Key push after 120 s — often with the prompt
still open — and relaunch the JVM, sending another push. Now the gateway
ends a round, and the
dashboard says what is happening:

- a push that has waited past ``twofa.alert_after_secs`` is outstanding —
  say so once, honestly (it may already have expired on the phone);
- every JVM relaunch from the login path carries a reason in STATUS
  ``last_relaunch`` — say why a new push is coming; one with no reason under
  an open prompt is the tripwire;
- a login parked overnight says it is parked for the night.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.monitors.auth_relaunch import AuthRelaunchMonitor
from app.services.monitors.hitl_2fa import Hitl2faEntryMonitor
from app.services.monitors.twofa_push_waiting import TwoFaPushWaitingMonitor


class _Registry:
    def __init__(self, **modes: dict):
        self.instances = [SimpleNamespace(mode=m, status=s) for m, s in modes.items()]

    def cached_all_status(self):
        return self.instances

    def status_of(self, mode: str) -> dict:
        return next(i.status for i in self.instances if i.mode == mode)


class _NS:
    def __init__(self, event: str, enabled: bool = True):
        self._event, self._enabled = event, enabled

    def is_event_enabled(self, event_type: str) -> bool:
        return self._enabled and event_type == self._event


def _waiting(open_secs: int | None, *, overdue: bool | None = None) -> dict:
    twofa = {
        "challenge_open": open_secs is not None,
        "challenge_open_secs": open_secs,
        "push_overdue": overdue if overdue is not None else (open_secs or 0) >= 120,
        "alert_after_secs": 120,
        "stuck_ceiling_secs": 1800,
        "cancel_sent": False,
        "rounds_failed": 0,
        "max_rounds": 3,
    }
    return {"state": "WaitingFor2fa", "twofa": twofa}


# -------- the push is waiting --------------------------------------------


@pytest.mark.asyncio
async def test_an_unanswered_push_is_announced_once_per_round():
    reg = _Registry(live=_waiting(30))
    mon = TwoFaPushWaitingMonitor()
    ns = _NS("twofa_push_waiting")
    assert await mon.check(reg, ns) == []

    reg.instances[0].status = _waiting(125)
    (a,) = await mon.check(reg, ns)
    assert a.event_type == "twofa_push_waiting"
    assert "LIVE" in a.title
    body = a.body.lower()
    assert "approve" in body and "ibkr mobile" in body
    assert "may already have expired" in body, "an open prompt is no proof the phone has it"
    assert "no restart" in body or "keeps the gateway running" in body
    assert await mon.check(reg, ns) == [], "once per round"

    # The round ends (prompt closed) and a new push goes unanswered.
    reg.instances[0].status = _waiting(None)
    assert await mon.check(reg, ns) == []
    reg.instances[0].status = _waiting(130)
    assert len(await mon.check(reg, ns)) == 1


@pytest.mark.asyncio
async def test_push_waiting_is_silent_when_disabled_or_on_an_old_ibctl():
    assert await TwoFaPushWaitingMonitor().check(_Registry(live=_waiting(500)), _NS("x")) == []
    old = _Registry(live={"state": "WaitingFor2fa"})
    assert await TwoFaPushWaitingMonitor().check(old, _NS("twofa_push_waiting")) == []


# -------- why the gateway was relaunched ---------------------------------


def _relaunch(at: str, reason: str, *, from_state="WaitingFor2fa", abandoned=False, detail="") -> dict:
    return {
        "state": "Restarting",
        "last_relaunch": {
            "at": at,
            "from_state": from_state,
            "reason": reason,
            "detail": detail or reason,
            "abandoned_prompt": abandoned,
        },
    }


@pytest.mark.asyncio
async def test_a_relaunch_from_the_login_path_says_why_a_new_push_is_coming():
    reg = _Registry(live={"state": "WaitingFor2fa", "last_relaunch": None})
    mon = AuthRelaunchMonitor()
    ns = _NS("auth_relaunch")
    assert await mon.check(reg, ns) == []

    reg.instances[0].status = _relaunch(
        "2026-09-28T03:40:00-04:00[America/New_York]",
        "prompt_ignored_cancel",
        detail="an IB Key prompt stayed open past the stuck ceiling and did not close on Cancel",
    )
    (a,) = await mon.check(reg, ns)
    assert a.event_type == "auth_relaunch"
    assert "LIVE" in a.title
    assert "did not close on Cancel" in a.body
    assert "new ib key push" in a.body.lower()
    assert a.priority == "high"
    assert await mon.check(reg, ns) == [], "one alert per relaunch"


@pytest.mark.asyncio
async def test_an_old_relaunch_seen_at_startup_is_history_not_news():
    reg = _Registry(live=_relaunch("2026-09-27T12:00:00-04:00[America/New_York]", "jvm_exited"))
    assert await AuthRelaunchMonitor().check(reg, _NS("auth_relaunch")) == []


@pytest.mark.asyncio
async def test_relaunches_outside_the_login_path_are_not_paged():
    reg = _Registry(live={"state": "Connected", "last_relaunch": None})
    mon = AuthRelaunchMonitor()
    await mon.check(reg, _NS("auth_relaunch"))
    reg.instances[0].status = _relaunch(
        "2026-09-28T09:00:00-04:00[America/New_York]", "unspecified", from_state="Connected"
    )
    assert await mon.check(reg, _NS("auth_relaunch")) == []


@pytest.mark.asyncio
async def test_a_relaunch_that_abandoned_an_open_push_is_the_tripwire():
    reg = _Registry(live={"state": "WaitingFor2fa", "last_relaunch": None})
    mon = AuthRelaunchMonitor()
    await mon.check(reg, _NS("auth_relaunch"))
    reg.instances[0].status = _relaunch(
        "2026-09-28T03:12:00-04:00[America/New_York]", "unspecified", abandoned=True
    )
    (a,) = await mon.check(reg, _NS("auth_relaunch"))
    assert a.priority == "urgent"
    assert "regression" in a.body and "abandoned" in a.body.lower()


# -------- parked for the night -------------------------------------------


def _hitl_status(reason: str | None, window: str | None = "22:00-08:00") -> dict:
    return {
        "state": "WaitingForHitl2fa",
        "hitl": {
            "active": True,
            "consecutive_2fa_timeouts": 1,
            "next_retry_in_secs": None,
            "challenge_open": False,
            "relogin_armed": False,
            "cancel_requested": False,
            "parked_reason": reason,
            "unattended_hours": window,
        },
    }


def test_a_login_parked_overnight_says_so():
    a = Hitl2faEntryMonitor()._build_rich_alert("live", _hitl_status("unattended_hours"), False, "", "")
    body = a.body.lower()
    assert "unattended hours" in body and "22:00-08:00" in body
    assert "no more pushes" in body
    assert "exhausted" not in body, "one push was sent, not three"


def test_a_login_parked_after_the_budget_keeps_the_old_wording():
    a = Hitl2faEntryMonitor()._build_rich_alert("live", _hitl_status("attempts_exhausted"), False, "", "")
    assert "exhausted automatic 2FA attempts" in a.body


def test_the_retry_button_text_says_it_replaces_the_current_push():
    # Before rounds ended on the Gateway's word, Retry waited for the gateway to close an open
    # prompt. Now it closes it: say the push is replaced.
    a = Hitl2faEntryMonitor()._build_rich_alert(
        "live", _hitl_status("attempts_exhausted"), True, "k" * 64, "https://dash.example"
    )
    assert "replaces the current ib key push" in a.body.lower()
    assert "no restart" in a.body


def test_a_parked_login_says_when_the_sunday_reauth_is_still_owed():
    # An obligation must not vanish because the
    # container started after 09:00 — the parked alert carries it.
    st = _hitl_status("attempts_exhausted")
    st["cold_restart_owed_since"] = "2026-10-04T09:02:10-04:00[America/New_York]"
    a = Hitl2faEntryMonitor()._build_rich_alert("live", st, False, "", "")
    assert "sunday re-authentication is still owed" in a.body.lower()
    b = Hitl2faEntryMonitor()._build_rich_alert("live", _hitl_status("attempts_exhausted"), False, "", "")
    assert "owed" not in b.body.lower()
