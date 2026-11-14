"""WARMRESTART: the API's name for "warm restart now".

POST /api/v1/warm-restart takes one argument, the mode, and has the dashboard
send ibctl a bare SETRESTART: ibctl restarts the Gateway as soon as it can,
warm. GET reads that mode's last outcome back, because a token cannot read
status or logs. A per-mode minimum interval, saved on disk and shared by the
dashboard button and the API, stops a client looping.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from app.middleware import auth as auth_module
from app.services.warm_restart import next_restart_minute
from tests.api_access_helpers import (
    NOT_ALLOWED,
    START,
    WITHOUT_SETRESTART,
    FakeClock,
    bearer,
    build_app,
    client_for,
    member_client,
)
from tests.auth_helpers import TEST_PASSWORD, authed_settings

URL = "/api/v1/warm-restart"
IP = "203.0.113.9"
OUTCOME_KEYS = {"requested_at", "scheduled_for", "applied", "relaunched_at", "warm"}


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def jiff(epoch: float, zone: str = "Africa/Abidjan") -> str:
    """A time the way ibctl prints one in STATUS (a jiff Zoned)."""
    moment = datetime.fromtimestamp(epoch, ZoneInfo(zone))
    offset = moment.strftime("%z")
    return f"{moment:%Y-%m-%dT%H:%M:%S}.123456789{offset[:3]}:{offset[3:]}[{zone}]"


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def app(tmp_path, clock):
    return build_app(tmp_path, clock=clock)


@pytest.fixture
def token(app):
    return app.state.api_access.create_token("ci-bot", created_by="x")[1]


@pytest.fixture
async def anon(app):
    async with client_for(app) as c:
        yield c


@pytest.fixture
async def member(app):
    c = await member_client(app)
    yield c
    await c.aclose()


def post(client, token, mode="paper", **headers):
    return client.post(URL, json={"mode": mode}, headers=bearer(token, **{"X-Real-IP": IP, **headers}))


def get(client, token, mode="paper"):
    return client.get(URL, params={"mode": mode}, headers=bearer(token))


def audit(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == "dashboard.api_access"]


# --- scheduled_for follows ibctl's rule ---


class TestNextRestartMinute:
    @pytest.mark.parametrize(
        ("second", "minutes_ahead"),
        [(0, 1), (1, 1), (20, 1), (57, 1), (57.9, 1), (58, 2), (59, 2), (59.9, 2)],
    )
    def test_the_next_whole_minute_or_the_one_after_in_the_last_two_seconds(self, second, minutes_ahead):
        minute = datetime(2026, 11, 14, 21, 40, tzinfo=timezone.utc).timestamp()
        assert next_restart_minute(minute + second) == minute + 60 * minutes_ahead

    def test_it_is_always_on_a_minute_boundary(self):
        assert next_restart_minute(START) % 60 == 0


# --- POST ---


class TestPost:
    async def test_a_ticked_token_gets_202_and_ibctl_gets_a_bare_setrestart(self, app, anon, token):
        resp = await post(anon, token)
        assert resp.status_code == 202
        assert resp.json() == {"mode": "paper", "scheduled_for": iso(START + 40)}
        assert app.state.stubs["paper"].sent == ["SETRESTART"]
        assert app.state.stubs["live"].sent == []

    async def test_live_goes_to_the_live_instance(self, app, anon, token):
        assert (await post(anon, token, "live")).status_code == 202
        assert app.state.stubs["live"].sent == ["SETRESTART"]
        assert app.state.stubs["paper"].sent == []

    async def test_late_in_a_minute_it_is_the_minute_after(self, app, anon, token, clock):
        clock.now = START + 38.5  # :58.5
        resp = await post(anon, token)
        assert resp.json()["scheduled_for"] == iso(START + 100)

    async def test_the_password_is_not_a_token(self, app, anon):
        resp = await anon.post(URL, json={"mode": "paper"}, headers=bearer(TEST_PASSWORD))
        assert resp.status_code == 401
        assert app.state.stubs["paper"].sent == []

    async def test_no_token_and_a_revoked_token_are_401(self, app, anon, token):
        assert (await anon.post(URL, json={"mode": "paper"})).status_code == 401
        app.state.api_access.revoke_token("ci-bot")
        assert (await post(anon, token)).status_code == 401
        assert app.state.stubs["paper"].sent == []

    async def test_a_made_up_token_is_401_while_real_ones_exist(self, app, anon, token):
        for fake in ("ibctl_" + "A" * 43, token[:-1] + ("A" if token[-1] != "A" else "B"), token.upper()):
            resp = await post(anon, fake)
            assert resp.status_code == 401, fake
        assert app.state.stubs["paper"].sent == []

    async def test_a_disabled_type_is_403(self, app, anon, token):
        app.state.api_access.set_enabled([])
        resp = await post(anon, token)
        assert resp.status_code == 403
        assert resp.json()["error"] == "not_allowed"
        assert app.state.stubs["paper"].sent == []

    async def test_a_command_ibctl_blocks_is_403_and_costs_nothing(self, app, anon, token):
        app.state.stubs["paper"].allowed = WITHOUT_SETRESTART
        resp = await post(anon, token)
        assert resp.status_code == 403
        assert resp.json()["error"] == "blocked_by_ibctl"
        assert app.state.stubs["paper"].sent == []
        app.state.stubs["paper"].allowed = ["SETRESTART"]
        assert (await post(anon, token)).status_code == 202, "the refused call did not start the interval"

    async def test_ibctl_refusing_at_send_time_is_a_403_and_costs_nothing(self, app, anon, token):
        app.state.stubs["paper"].refuse_setrestart_with = NOT_ALLOWED
        resp = await post(anon, token)
        assert resp.status_code == 403 and resp.json()["error"] == "blocked_by_ibctl"
        app.state.stubs["paper"].refuse_setrestart_with = None
        assert (await post(anon, token)).status_code == 202

    async def test_another_ibctl_error_is_a_502_and_costs_nothing(self, app, anon, token):
        app.state.stubs["paper"].refuse_setrestart_with = "the Gateway is not running"
        resp = await post(anon, token)
        assert resp.status_code == 502 and resp.json()["error"] == "ibctl_refused"
        app.state.stubs["paper"].refuse_setrestart_with = None
        assert (await post(anon, token)).status_code == 202

    async def test_an_unreachable_ibctl_is_not_called_blocking(self, app, anon, token):
        app.state.stubs["paper"].unreachable = True
        resp = await post(anon, token)
        assert resp.status_code == 503
        assert resp.json()["error"] == "ibctl_unavailable"
        app.state.stubs["paper"].unreachable = False
        assert (await post(anon, token)).status_code == 202, "a failed send does not start the interval"

    async def test_an_ibctl_that_does_not_report_its_list_is_asked_anyway(self, app, anon, token):
        app.state.stubs["paper"].report_allowed = False
        assert (await post(anon, token)).status_code == 202

    @pytest.mark.parametrize(
        ("body", "status"),
        [
            ({}, 422),
            ({"mode": None}, 422),
            ({"mode": ""}, 422),
            ({"mode": "demo"}, 422),
            ({"mode": "PAPER"}, 422),
            ({"mode": 7}, 422),
            ({"mode": ["paper"]}, 422),
            ({"mode": "paper", "time": "5:00 PM"}, 422),
            ({"mode": "paper", "fallback": "live"}, 422),
            (["paper"], 422),
        ],
    )
    async def test_a_bad_or_missing_mode_is_refused_and_sends_nothing(self, app, anon, token, body, status):
        resp = await anon.post(URL, json=body, headers=bearer(token))
        assert resp.status_code == status
        assert resp.json()["error"] == "invalid_request"
        assert all(stub.sent == [] for stub in app.state.stubs.values())
        assert (await post(anon, token)).status_code == 202, "a refused call did not start the interval"

    async def test_a_body_that_is_not_json_is_a_400(self, app, anon, token):
        resp = await anon.post(URL, content=b"{nope", headers=bearer(token, **{"Content-Type": "application/json"}))
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    async def test_a_form_post_is_refused(self, app, anon, token):
        resp = await anon.post(URL, data={"mode": "paper"}, headers=bearer(token))
        assert resp.status_code == 415
        assert app.state.stubs["paper"].sent == []

    async def test_a_mode_this_dashboard_does_not_run_is_refused_without_a_fallback(self, tmp_path, clock):
        app = build_app(tmp_path, clock=clock, trading_mode="paper")
        token = app.state.api_access.create_token("ci-bot", created_by="x")[1]
        async with client_for(app) as c:
            resp = await post(c, token, "live")
            assert resp.status_code == 422 and "not run" in resp.json()["detail"]
            assert app.state.stubs["paper"].sent == []

    async def test_a_signed_in_person_needs_no_tick(self, app, member):
        app.state.api_access.set_enabled([])
        resp = await member.post(URL, json={"mode": "paper"})
        assert resp.status_code == 202
        assert app.state.stubs["paper"].sent == ["SETRESTART"]


# --- The minimum interval ---


class TestRateLimit:
    async def test_the_second_call_inside_the_interval_is_429_with_the_wait(self, app, anon, token, clock):
        assert (await post(anon, token)).status_code == 202
        clock.advance(100)
        resp = await post(anon, token)
        assert resp.status_code == 429
        assert resp.json() == {"error": "rate_limited", "retry_after_s": 1700}
        assert resp.headers["Retry-After"] == "1700"
        assert app.state.stubs["paper"].sent == ["SETRESTART"], "the refused call sent nothing"

    async def test_a_fraction_of_a_second_rounds_the_wait_up(self, app, anon, token, clock):
        await post(anon, token)
        clock.advance(0.4)
        assert (await post(anon, token)).json()["retry_after_s"] == 1800

    async def test_after_the_interval_it_works_again(self, app, anon, token, clock):
        await post(anon, token)
        clock.advance(30 * 60 - 1)
        assert (await post(anon, token)).status_code == 429
        clock.advance(1)
        assert (await post(anon, token)).status_code == 202
        assert app.state.stubs["paper"].sent == ["SETRESTART", "SETRESTART"]

    async def test_the_interval_is_per_mode(self, app, anon, token):
        assert (await post(anon, token, "paper")).status_code == 202
        assert (await post(anon, token, "paper")).status_code == 429
        assert (await post(anon, token, "live")).status_code == 202
        assert (await post(anon, token, "live")).status_code == 429

    async def test_the_interval_is_set_per_mode_in_minutes(self, app, anon, token, clock):
        app.state.api_access.set_min_interval_minutes({"paper": 5})
        await post(anon, token, "paper")
        await post(anon, token, "live")
        clock.advance(300)
        assert (await post(anon, token, "paper")).status_code == 202
        assert (await post(anon, token, "live")).status_code == 429

    async def test_the_button_and_the_api_share_one_limiter(self, app, anon, member, token):
        assert (await member.post(URL, json={"mode": "paper"})).status_code == 202
        resp = await post(anon, token)
        assert resp.status_code == 429, "the button's restart counts against the API"
        assert (await post(anon, token, "live")).status_code == 202
        resp = await member.post(URL, json={"mode": "live"})
        assert resp.status_code == 429, "and the API's against the button"
        assert resp.headers["Retry-After"] == "1800"

    async def test_the_last_accepted_time_survives_a_new_app(self, tmp_path, clock, token, app):
        async with client_for(app) as first:
            assert (await post(first, token)).status_code == 202
        clock.advance(600)

        restarted = build_app(tmp_path, clock=clock)
        async with client_for(restarted) as second:
            resp = await post(second, token)
            assert resp.status_code == 429
            assert resp.json()["retry_after_s"] == 1200
            assert restarted.state.stubs["paper"].sent == []

    async def test_two_calls_at_once_get_one_through(self, app, anon, token):
        results = await asyncio.gather(post(anon, token), post(anon, token))
        assert sorted(r.status_code for r in results) == [202, 429]
        assert app.state.stubs["paper"].sent == ["SETRESTART"]

    async def test_a_clock_that_stepped_back_does_not_lock_the_mode_longer_than_the_interval(self, app, anon, token, clock):
        await post(anon, token)
        clock.advance(-3600)
        resp = await post(anon, token)
        assert resp.status_code == 429 and resp.json()["retry_after_s"] == 1800


# --- Every request is logged with who and from where ---


class TestAuditLog:
    async def test_an_accepted_token_request(self, app, anon, token, caplog):
        with caplog.at_level(logging.INFO, logger="dashboard.api_access"):
            await post(anon, token)
        [line] = audit(caplog)
        assert "accepted" in line and "ci-bot" in line and IP in line and "paper" in line and token not in line

    async def test_a_rate_limited_request(self, app, anon, token, caplog):
        await post(anon, token)
        caplog.clear()
        with caplog.at_level(logging.INFO, logger="dashboard.api_access"):
            await post(anon, token)
        [line] = audit(caplog)
        assert "rejected" in line and "rate_limited" in line and "ci-bot" in line and IP in line

    async def test_a_request_ibctl_blocks(self, app, anon, token, caplog):
        app.state.stubs["paper"].allowed = WITHOUT_SETRESTART
        with caplog.at_level(logging.INFO, logger="dashboard.api_access"):
            await post(anon, token)
        [line] = audit(caplog)
        assert "rejected" in line and "blocked_by_ibctl" in line and "ci-bot" in line and IP in line

    async def test_a_bad_request(self, app, anon, token, caplog):
        with caplog.at_level(logging.INFO, logger="dashboard.api_access"):
            await anon.post(URL, json={"mode": "demo"}, headers=bearer(token, **{"X-Real-IP": IP}))
        [line] = audit(caplog)
        assert "rejected" in line and "invalid_request" in line and "ci-bot" in line and IP in line

    async def test_a_request_of_a_disabled_type_names_the_token_its_type_and_the_address(self, app, anon, token, caplog):
        app.state.api_access.set_enabled([])
        with caplog.at_level(logging.INFO):
            await post(anon, token)
        text = " ".join(r.getMessage() for r in caplog.records)
        assert "ci-bot" in text and "warm_restart" in text and IP in text and "not enabled" in text

    async def test_a_signed_in_person_is_logged_as_the_dashboard_user(self, app, member, caplog):
        with caplog.at_level(logging.INFO, logger="dashboard.api_access"):
            await member.post(URL, json={"mode": "paper"}, headers={"X-Real-IP": IP})
            await member.post(URL, json={"mode": "paper"}, headers={"X-Real-IP": IP})
        accepted, rejected = audit(caplog)
        assert "accepted" in accepted and "dashboard user" in accepted and IP in accepted
        assert "rejected" in rejected and "dashboard user" in rejected and IP in rejected


# --- GET: the last outcome ---


def ibctl_status(app, mode="paper", **fields):
    app.state.stubs[mode].status = {"state": "Connected", "ready": True, **fields}


class TestOutcome:
    async def test_a_mode_never_restarted_has_nothing_to_report(self, app, anon, token):
        resp = await get(anon, token)
        assert resp.status_code == 200
        assert resp.json() == dict.fromkeys(OUTCOME_KEYS)

    async def test_right_after_a_request_only_the_dashboard_knows(self, app, anon, token):
        await post(anon, token)
        body = (await get(anon, token)).json()
        assert set(body) == OUTCOME_KEYS
        assert body == {
            "requested_at": iso(START),
            "scheduled_for": iso(START + 40),
            "applied": None,
            "relaunched_at": None,
            "warm": None,
        }

    async def test_it_is_the_asked_mode_only(self, app, anon, token):
        await post(anon, token, "paper")
        assert (await get(anon, token, "live")).json() == dict.fromkeys(OUTCOME_KEYS)

    async def test_ibctls_own_record_of_the_time_it_typed_wins(self, app, anon, token, clock):
        # The dashboard took the request at :57.9, so it works out the next
        # minute; ibctl handled it at :58.1 and, by its rule, typed the one after.
        clock.now = START + 37.9
        await post(anon, token)
        typed_at = START + 38.1
        ibctl_status(
            app,
            last_setrestart={"at": jiff(typed_at), "source": "now", "requested": "9:42 PM", "applied": True, "error": None},
            gateway_time_zone={"declared": None, "in_jts_ini": "Africa/Abidjan", "effective": "Africa/Abidjan", "matches_declared": None},
        )
        body = (await get(anon, token)).json()
        assert body["scheduled_for"] == iso(START + 100)  # 21:42:00Z, ibctl's, not the dashboard's 21:41:00Z
        assert body["applied"] is True

    async def test_the_time_ibctl_typed_is_read_in_the_gateways_zone(self, app, anon, token):
        await post(anon, token)
        ibctl_status(
            app,
            last_setrestart={"at": jiff(START + 41, "America/New_York"), "source": "now", "requested": "4:42 PM", "applied": True, "error": None},
            gateway_time_zone={"effective": "America/New_York"},
        )
        assert (await get(anon, token)).json()["scheduled_for"] == iso(START + 100)  # 4:42 PM EST is 21:42Z

    async def test_without_a_known_zone_the_dashboards_own_figure_stands(self, app, anon, token):
        await post(anon, token)
        ibctl_status(
            app,
            last_setrestart={"at": jiff(START + 41), "source": "now", "requested": "9:50 PM", "applied": True, "error": None},
        )
        body = (await get(anon, token)).json()
        assert body["scheduled_for"] == iso(START + 40)
        assert body["applied"] is True

    async def test_a_time_that_cannot_belong_to_this_request_is_not_used(self, app, anon, token):
        await post(anon, token)
        ibctl_status(
            app,
            last_setrestart={"at": jiff(START + 41), "source": "now", "requested": "3:00 AM", "applied": True, "error": None},
            gateway_time_zone={"effective": "Africa/Abidjan"},
        )
        assert (await get(anon, token)).json()["scheduled_for"] == iso(START + 40)

    async def test_ibctl_saying_it_did_not_apply_the_time_is_reported(self, app, anon, token):
        await post(anon, token)
        ibctl_status(
            app,
            last_setrestart={"at": jiff(START + 41), "source": "now", "requested": "9:41 PM", "applied": False, "error": "no field"},
            gateway_time_zone={"effective": "Africa/Abidjan"},
        )
        assert (await get(anon, token)).json()["applied"] is False

    @pytest.mark.parametrize(
        "record",
        [
            {"source": "login", "at_offset": 41},  # the daily time, not ours
            {"source": "time", "at_offset": 41},  # a TCP caller's explicit time
            {"source": "now", "at_offset": -600},  # an older request
            {"source": "now", "at_offset": 600},  # a later one
        ],
        ids=["login", "explicit-time", "older", "later"],
    )
    async def test_a_setrestart_that_is_not_this_request_is_ignored(self, app, anon, token, record):
        await post(anon, token)
        ibctl_status(
            app,
            last_setrestart={"at": jiff(START + record["at_offset"]), "source": record["source"], "requested": "9:41 PM", "applied": True, "error": None},
            gateway_time_zone={"effective": "Africa/Abidjan"},
        )
        assert (await get(anon, token)).json()["applied"] is None

    async def test_the_gateway_restarting_itself_is_warm_and_relaunched(self, app, anon, token):
        await post(anon, token)
        exit_at, launched = START + 43, START + 55
        ibctl_status(
            app,
            last_setrestart={"at": jiff(START + 5), "source": "now", "requested": "9:41 PM", "applied": True, "error": None},
            gateway_time_zone={"effective": "Africa/Abidjan"},
            last_jvm_exit={"at": jiff(exit_at), "from_state": "Connected", "warm": True},
            sunday_reauth={"jvm_launched_at": jiff(launched)},
        )
        assert (await get(anon, token)).json() == {
            "requested_at": iso(START),
            "scheduled_for": iso(START + 40),
            "applied": True,
            "relaunched_at": iso(launched),
            "warm": True,
        }

    async def test_an_exit_with_no_saved_session_is_not_warm(self, app, anon, token):
        await post(anon, token)
        ibctl_status(app, last_jvm_exit={"at": jiff(START + 43), "from_state": "Connected", "warm": False})
        body = (await get(anon, token)).json()
        assert body["warm"] is False
        assert body["relaunched_at"] is None

    async def test_the_relaunch_is_not_reported_before_the_new_jvm_is_up(self, app, anon, token):
        await post(anon, token)
        ibctl_status(
            app,
            last_jvm_exit={"at": jiff(START + 43), "from_state": "Connected", "warm": True},
            sunday_reauth={"jvm_launched_at": jiff(START - 7200)},  # the old JVM's launch
        )
        body = (await get(anon, token)).json()
        assert body["warm"] is True and body["relaunched_at"] is None

    @pytest.mark.parametrize("exit_offset", [-3600, 10], ids=["before-the-request", "before-the-minute-it-was-set-for"])
    async def test_an_exit_that_this_request_cannot_have_caused_is_ignored(self, app, anon, token, exit_offset):
        await post(anon, token)
        ibctl_status(app, last_jvm_exit={"at": jiff(START + exit_offset), "from_state": "Connected", "warm": True})
        assert (await get(anon, token)).json()["warm"] is None

    async def test_no_restart_is_expected_when_ibctl_did_not_apply_the_time(self, app, anon, token):
        await post(anon, token)
        ibctl_status(
            app,
            last_setrestart={"at": jiff(START + 5), "source": "now", "requested": "9:41 PM", "applied": False, "error": "x"},
            gateway_time_zone={"effective": "Africa/Abidjan"},
            last_jvm_exit={"at": jiff(START + 3600), "from_state": "Connected", "warm": False},
        )
        body = (await get(anon, token)).json()
        assert body["applied"] is False and body["warm"] is None

    async def test_what_was_seen_is_kept_when_ibctl_moves_on(self, app, anon, token):
        await post(anon, token)
        ibctl_status(
            app,
            last_setrestart={"at": jiff(START + 5), "source": "now", "requested": "9:41 PM", "applied": True, "error": None},
            gateway_time_zone={"effective": "Africa/Abidjan"},
        )
        await get(anon, token)
        ibctl_status(
            app,
            # After the relaunch ibctl sets the daily time and records that instead; later still, a crash.
            last_setrestart={"at": jiff(START + 70), "source": "login", "requested": "5:05 PM", "applied": True, "error": None},
            last_jvm_exit={"at": jiff(START + 43), "from_state": "Connected", "warm": True},
            sunday_reauth={"jvm_launched_at": jiff(START + 55)},
        )
        first = (await get(anon, token)).json()
        assert first["applied"] is True and first["warm"] is True and first["relaunched_at"] == iso(START + 55)

        ibctl_status(
            app,
            last_jvm_exit={"at": jiff(START + 9000), "from_state": "Connected", "warm": False},
            sunday_reauth={"jvm_launched_at": jiff(START + 9010)},
        )
        assert (await get(anon, token)).json() == first

    async def test_a_new_request_starts_a_new_outcome(self, app, anon, token, clock):
        await post(anon, token)
        ibctl_status(app, last_jvm_exit={"at": jiff(START + 43), "from_state": "Connected", "warm": True})
        assert (await get(anon, token)).json()["warm"] is True
        clock.advance(3600)
        await post(anon, token)
        body = (await get(anon, token)).json()
        assert body["requested_at"] == iso(START + 3600)
        assert body["warm"] is None

    async def test_a_remembered_outcome_survives_a_new_app(self, tmp_path, clock, token, app):
        async with client_for(app) as first:
            await post(first, token)
            ibctl_status(app, last_jvm_exit={"at": jiff(START + 43), "from_state": "Connected", "warm": True})
            await get(first, token)
        restarted = build_app(tmp_path, clock=clock)
        async with client_for(restarted) as second:
            assert (await get(second, token)).json()["warm"] is True

    async def test_an_unreachable_ibctl_is_a_503(self, app, anon, token):
        await post(anon, token)
        app.state.stubs["paper"].unreachable = True
        resp = await get(anon, token)
        assert resp.status_code == 503 and resp.json()["error"] == "ibctl_unavailable"

    async def test_the_outcome_needs_the_same_type_enabled_and_a_token(self, app, anon, token):
        assert (await anon.get(URL, params={"mode": "paper"})).status_code == 401
        app.state.api_access.set_enabled([])
        assert (await get(anon, token)).status_code == 403

    async def test_a_signed_in_person_can_read_it(self, app, member):
        assert (await member.get(URL, params={"mode": "paper"})).status_code == 200

    @pytest.mark.parametrize("params", [{}, {"mode": "demo"}, {"mode": ""}, {"mode": "Paper"}])
    async def test_a_bad_or_missing_mode_is_422(self, app, anon, token, params):
        resp = await anon.get(URL, params=params, headers=bearer(token))
        assert resp.status_code == 422 and resp.json()["error"] == "invalid_request"


# --- The routes a token has ---


class TestTokenRoutes:
    def test_the_warm_restart_routes_are_the_only_ones_a_warm_restart_token_has(self):
        mine = {route for route, types in auth_module.TOKEN_ROUTES.items() if "warm_restart" in types}
        assert mine == {("POST", URL), ("GET", URL)}

    async def test_a_token_cannot_reach_the_generic_command_endpoint(self, app, anon, token):
        resp = await anon.post("/api/v1/command", json={"command": "RESTART", "mode": "paper"}, headers=bearer(token))
        assert resp.status_code == 401
        assert app.state.stubs["paper"].sent == []

    async def test_no_login_means_no_token_access(self, tmp_path, clock):
        app = build_app(tmp_path, clock=clock, settings=authed_settings(token="", auth_secret=None, trading_mode="both"))
        token = app.state.api_access.create_token("ci-bot", created_by="x")[1]
        async with client_for(app) as c:
            assert (await post(c, token)).status_code == 403
            assert app.state.stubs["paper"].sent == []
