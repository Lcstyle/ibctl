"""Gateway version tracking — the probe and the weekly check.

The probe is a short read-only API connection; it runs in a subprocess so a
hung or misbehaving connection can never stall the dashboard. These tests use
a stand-in IB object and stand-in probe scripts; nothing touches a Gateway.
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.gateway_version.probe import (
    PROBE_CLIENT_IDS,
    ProbeConnectFailed,
    ProbeResult,
    collect_messages,
    notice_from,
    run_probe,
)
from app.services.gateway_version.releases import ChannelRelease
from app.services.gateway_version.service import GatewayVersionService, WeeklySchedule, load_state
from app.services.gateway_version.versions import GatewayVersion

REAL_2172 = (
    "The version of the application you are running, 1047.1, needs to be upgraded, as it will be "
    "desupported on 20261215. The minimum supported version at that time will be 1050.1. "
)
FARM_OK = (2104, "Market data farm connection is OK:usfarm")
REFUSED = (326, "Unable to connect as the client id is already in use. Retry with a unique client id.")


# ── the probe ───────────────────────────────────────────────────────────


class _Event(list):
    def __iadd__(self, handler):
        self.append(handler)
        return self

    def emit(self, *args):
        for handler in self:
            handler(*args)


class FakeIB:
    def __init__(self, messages=(), connect_error: Exception | None = None):
        self.errorEvent = _Event()
        self._messages = messages
        self._connect_error = connect_error
        self.connect_kwargs: dict = {}
        self.disconnected = False

    async def connectAsync(self, host, port, **kwargs):
        self.connect_kwargs = {"host": host, "port": port, **kwargs}
        for code, text in self._messages:
            self.errorEvent.emit(-1, code, text, None)
        if self._connect_error:
            raise self._connect_error

    def disconnect(self):
        self.disconnected = True


class TestCollectMessages:
    async def test_it_connects_read_only_with_no_startup_requests(self):
        ib = FakeIB(messages=[FARM_OK, (2172, REAL_2172)])
        none = object()

        messages = await collect_messages(ib, "127.0.0.1", 4002, 9172, connect_timeout=5, settle=0, fetch_fields=none)

        assert messages == [FARM_OK, (2172, REAL_2172)]
        assert ib.connect_kwargs == {
            "host": "127.0.0.1", "port": 4002, "clientId": 9172, "timeout": 5, "readonly": True, "fetchFields": none,
        }
        assert ib.disconnected

    async def test_it_disconnects_even_when_connecting_fails(self):
        ib = FakeIB(connect_error=ConnectionRefusedError("refused"))

        with pytest.raises(ProbeConnectFailed) as failed:
            await collect_messages(ib, "127.0.0.1", 4002, 9172, connect_timeout=5, settle=0, fetch_fields=None)

        assert str(failed.value) == "ConnectionRefusedError: refused"
        assert isinstance(failed.value.__cause__, ConnectionRefusedError)
        assert ib.disconnected

    async def test_a_refused_client_id_says_why(self):
        # Seen in production: IB sends 326 during the handshake, then
        # ib_async waits out its timeout and raises a bare TimeoutError().
        ib = FakeIB(messages=[REFUSED], connect_error=TimeoutError())

        with pytest.raises(ProbeConnectFailed) as failed:
            await collect_messages(ib, "127.0.0.1", 4002, 9172, connect_timeout=10, settle=0, fetch_fields=None)

        assert str(failed.value) == (
            "TimeoutError: no answer within 10s; IB said: 326 Unable to connect as the client id "
            "is already in use. Retry with a unique client id."
        )
        assert failed.value.messages == [REFUSED]

    async def test_a_bare_timeout_names_the_wait(self):
        ib = FakeIB(connect_error=TimeoutError())

        with pytest.raises(ProbeConnectFailed) as failed:
            await collect_messages(ib, "127.0.0.1", 4002, 9172, connect_timeout=5, settle=0, fetch_fields=None)

        assert str(failed.value) == "TimeoutError: no answer within 5s"


def fake_probe_script(tmp_path: Path, body: str) -> list[str]:
    script = tmp_path / "probe.py"
    script.write_text(body)
    return [sys.executable, str(script)]


class TestRunProbe:
    async def test_messages_come_back_from_the_subprocess(self, tmp_path):
        out = {"ok": True, "messages": [{"code": 2172, "text": REAL_2172}]}
        argv = fake_probe_script(tmp_path, f"import json; print(json.dumps({out!r}))")

        result = await run_probe(4002, argv=argv, timeout=10)

        assert result == ProbeResult(messages=[(2172, REAL_2172)], error=None)

    async def test_a_probe_that_hangs_is_killed_and_reported(self, tmp_path):
        argv = fake_probe_script(tmp_path, "import time; time.sleep(30)")

        result = await run_probe(4002, argv=argv, timeout=0.5)

        assert result.messages == []
        assert "did not finish" in result.error

    async def test_a_failed_connection_is_reported(self, tmp_path):
        out = {"ok": False, "error": "ConnectionRefusedError: refused"}
        argv = fake_probe_script(tmp_path, f"import json, sys; print(json.dumps({out!r})); sys.exit(1)")

        result = await run_probe(4002, argv=argv, timeout=10)

        assert result.error == "ConnectionRefusedError: refused"
        assert not result.client_id_in_use

    async def test_a_refused_client_id_comes_back_marked(self, tmp_path):
        out = {"ok": False, "error": "TimeoutError: no answer within 10s; IB said: 326 ...",
               "messages": [{"code": 326, "text": REFUSED[1]}]}
        argv = fake_probe_script(tmp_path, f"import json, sys; print(json.dumps({out!r})); sys.exit(1)")

        result = await run_probe(4002, argv=argv, timeout=10)

        assert result.error == out["error"]
        assert result.messages == [REFUSED]
        assert result.client_id_in_use

    async def test_output_that_does_not_parse_is_an_error(self, tmp_path):
        argv = fake_probe_script(tmp_path, "print('Traceback (most recent call last): boom')")

        result = await run_probe(4002, argv=argv, timeout=10)

        assert result.error and "unreadable" in result.error

    async def test_the_probe_runs_from_the_dashboard_root_wherever_the_dashboard_started(self, tmp_path, monkeypatch):
        from app.services.gateway_version import probe

        monkeypatch.chdir(tmp_path)
        argv = [sys.executable, "-c", "import json, os; print(json.dumps({'ok': True, 'messages': [{'code': 1, 'text': os.getcwd()}]}))"]

        result = await run_probe(4002, argv=argv, timeout=10)

        assert result.messages == [(1, str(probe.DASHBOARD_ROOT))]
        assert (probe.DASHBOARD_ROOT / "app" / "services" / "gateway_version" / "probe.py").is_file()

    def test_the_real_probe_command_runs_this_module_on_the_given_port(self):
        from app.services.gateway_version import probe

        argv = probe.probe_argv(4002, client_id=9175)
        assert argv[:3] == [sys.executable, "-m", "app.services.gateway_version.probe"]
        assert argv[argv.index("--port") + 1] == "4002"
        assert argv[argv.index("--client-id") + 1] == "9175"


def test_the_probe_ids_are_9172_to_9179():
    assert list(PROBE_CLIENT_IDS) == list(range(9172, 9180))


class TestNoticeFrom:
    def test_a_2172_becomes_a_notice(self):
        notice = notice_from([FARM_OK, (2172, REAL_2172)])
        assert notice is not None and notice.cutoff == date(2026, 12, 15)

    def test_no_2172_means_no_notice(self):
        assert notice_from([FARM_OK]) is None

    def test_an_unreadable_2172_is_an_error_not_silence(self):
        with pytest.raises(ValueError):
            notice_from([(2172, "IB rewrote this message")])


# ── the weekly check ────────────────────────────────────────────────────


def utc(*args) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


class Clock:
    def __init__(self, now: datetime):
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class Registry:
    def __init__(self, **modes: dict):
        self.modes = modes

    def cached_all_status(self):
        return [SimpleNamespace(mode=m, status=s) for m, s in self.modes.items()]


def connected(clients: int = 2, ids: tuple[str, ...] = ()) -> dict:
    return {"state": "Connected", "clients": {"count": clients, "ids": list(ids)}}


STABLE = ChannelRelease("stable", GatewayVersion(10, 50, 1, "f"), date(2026, 10, 5))
LATEST = ChannelRelease("latest", GatewayVersion(10, 51, 1, "e"), date(2026, 10, 26))


def _fetch_with(stable: ChannelRelease = STABLE, latest: ChannelRelease = LATEST):
    async def fetch(channel: str) -> ChannelRelease:
        return {"stable": stable, "latest": latest}[channel]
    return fetch


def service(
    tmp_path, registry, clock, *, probe_messages=(), probe_error=None, release_error=None, probed=None,
    probed_ids=None, probe_results=None,
):
    """``probe_results``, if given, are returned one per probe call, in order."""
    results = list(probe_results or [])

    async def fetch(channel: str) -> ChannelRelease:
        if release_error:
            raise release_error
        return {"stable": STABLE, "latest": LATEST}[channel]

    async def probe(mode: str, client_id: int) -> ProbeResult:
        if probed is not None:
            probed.append(mode)
        if probed_ids is not None:
            probed_ids.append(client_id)
        if results:
            return results.pop(0)
        return ProbeResult(messages=list(probe_messages), error=probe_error)

    return GatewayVersionService(
        registry,
        state_path=tmp_path / "gateway_version.json",
        running_version="10.47.1b",
        channel="stable",
        clock=clock,
        fetch_release=fetch,
        probe_mode=probe,
    )


class TestWeeklySchedule:
    """Saturday 12:00 ET. 2026-11-14 is a Saturday; ET is UTC-5 then."""

    schedule = WeeklySchedule()

    def test_never_checked_is_due(self):
        assert self.schedule.due(last_check=None, now=utc(2026, 11, 10, 15))

    def test_not_due_again_until_the_next_saturday_noon(self):
        checked = utc(2026, 11, 14, 17, 1)  # Sat 12:01 ET
        assert not self.schedule.due(last_check=checked, now=utc(2026, 11, 21, 16, 59))  # Sat 11:59 ET
        assert self.schedule.due(last_check=checked, now=utc(2026, 11, 21, 17, 0))  # Sat 12:00 ET

    def test_a_missed_saturday_is_caught_up(self):
        checked = utc(2026, 11, 7, 17, 1)  # the Saturday before
        assert self.schedule.due(last_check=checked, now=utc(2026, 11, 16, 9))  # dashboard back on Monday

    def test_the_slot_is_an_instant_in_utc(self):
        slot = self.schedule.last_slot(utc(2026, 11, 16, 9))
        assert slot == utc(2026, 11, 14, 17) and slot.utcoffset().total_seconds() == 0

    def test_a_slot_in_the_hour_dst_skips_or_repeats_is_refused(self):
        """02:30 does not exist on 2026-03-08 and happens twice on 2026-11-01."""
        for hour in (1, 2):
            with pytest.raises(ValueError):
                WeeklySchedule(weekday=6, hour=hour)

    def test_noon_is_eastern_time_across_the_dst_change(self):
        # 2026-10-31 is a Saturday in EDT (UTC-4): noon is 16:00 UTC.
        checked = utc(2026, 10, 24, 16, 1)
        assert not self.schedule.due(last_check=checked, now=utc(2026, 10, 31, 15, 59))
        assert self.schedule.due(last_check=checked, now=utc(2026, 10, 31, 16, 0))


class TestRunCheck:
    async def test_a_check_records_releases_and_the_notice(self, tmp_path):
        clock = Clock(utc(2026, 11, 14, 17))
        svc = service(tmp_path, Registry(live=connected(), paper=connected()), clock, probe_messages=[(2172, REAL_2172)])

        state = await svc.run_check()

        assert state.checked_at == clock.now
        assert state.releases["stable"] == STABLE and state.releases["latest"] == LATEST
        assert state.notice is not None and state.notice.cutoff == date(2026, 12, 15)
        assert state.notice_first_seen == clock.now

    async def test_each_build_seen_goes_into_the_history_once(self, tmp_path):
        """IB's files name only the current build; the upgrade soak needs older ones."""
        clock = Clock(utc(2026, 11, 14, 17))
        newer = ChannelRelease("stable", GatewayVersion(10, 51, 1, "h"), date(2026, 11, 20))
        svc = service(tmp_path, Registry(paper=connected()), clock)

        await svc.run_check()
        await svc.run_check()  # same builds again: no duplicates
        svc._fetch_release = _fetch_with(stable=newer)
        clock.now = utc(2026, 11, 21, 17)
        state = await svc.run_check()

        assert state.history["stable"] == [STABLE, newer]
        assert state.history["latest"] == [LATEST]
        reloaded = load_state(tmp_path / "gateway_version.json")
        assert reloaded.history == state.history

    async def test_the_history_keeps_the_last_dozen_per_channel(self, tmp_path):
        clock = Clock(utc(2026, 11, 14, 17))
        svc = service(tmp_path, Registry(paper=connected()), clock)
        for patch in range(1, 16):
            svc._fetch_release = _fetch_with(stable=ChannelRelease("stable", GatewayVersion(10, 60, patch, "a"), date(2026, 11, 1)))
            await svc.run_check()

        kept = svc.current().history["stable"]
        assert len(kept) == 12
        assert kept[-1].version == GatewayVersion(10, 60, 15, "a")

    async def test_it_probes_one_mode_preferring_paper(self, tmp_path):
        probed: list[str] = []
        svc = service(tmp_path, Registry(live=connected(), paper=connected()), Clock(utc(2026, 11, 14, 17)), probed=probed)

        await svc.run_check()

        assert probed == ["paper"]

    async def test_it_prefers_a_mode_that_already_has_clients(self, tmp_path):
        """A probe on a mode with 0 clients would reset the no-clients timer."""
        probed: list[str] = []
        svc = service(
            tmp_path, Registry(live=connected(3), paper=connected(0)), Clock(utc(2026, 11, 14, 17)), probed=probed
        )

        await svc.run_check()

        assert probed == ["live"]

    async def test_a_mode_that_is_not_connected_is_never_probed(self, tmp_path):
        probed: list[str] = []
        registry = Registry(live={"state": "WaitingFor2fa"}, paper=None)
        svc = service(tmp_path, registry, Clock(utc(2026, 11, 14, 17)), probed=probed)

        state = await svc.run_check()

        assert probed == []
        assert "no mode is Connected" in state.probe_error

    async def test_a_failed_probe_keeps_the_known_notice(self, tmp_path):
        """No answer is not the same as IB withdrawing the warning."""
        clock = Clock(utc(2026, 11, 14, 17))
        registry = Registry(paper=connected())
        await service(tmp_path, registry, clock, probe_messages=[(2172, REAL_2172)]).run_check()

        clock.now = utc(2026, 11, 21, 17)
        state = await service(tmp_path, registry, clock, probe_error="ConnectionRefusedError").run_check()

        assert state.notice is not None and state.notice.cutoff == date(2026, 12, 15)
        assert state.notice_first_seen == utc(2026, 11, 14, 17)
        assert state.probe_error == "ConnectionRefusedError"

    async def test_a_clean_probe_clears_the_notice(self, tmp_path):
        clock = Clock(utc(2026, 11, 14, 17))
        registry = Registry(paper=connected())
        await service(tmp_path, registry, clock, probe_messages=[(2172, REAL_2172)]).run_check()

        clock.now = utc(2026, 11, 21, 17)
        state = await service(tmp_path, registry, clock, probe_messages=[FARM_OK]).run_check()

        assert state.notice is None

    async def test_an_unreadable_2172_is_kept_as_an_error(self, tmp_path):
        svc = service(
            tmp_path, Registry(paper=connected()), Clock(utc(2026, 11, 14, 17)), probe_messages=[(2172, "reworded")]
        )

        state = await svc.run_check()

        assert state.notice is None
        assert "2172" in state.probe_error

    async def test_a_release_fetch_failure_is_recorded_and_the_probe_still_runs(self, tmp_path):
        probed: list[str] = []
        svc = service(
            tmp_path,
            Registry(paper=connected()),
            Clock(utc(2026, 11, 14, 17)),
            probe_messages=[(2172, REAL_2172)],
            release_error=TimeoutError("download2 timed out"),
            probed=probed,
        )

        state = await svc.run_check()

        assert probed == ["paper"]
        assert state.notice is not None
        assert "timed out" in state.release_errors["stable"]

    async def test_the_state_survives_a_restart(self, tmp_path):
        clock = Clock(utc(2026, 11, 14, 17))
        registry = Registry(paper=connected())
        await service(tmp_path, registry, clock, probe_messages=[(2172, REAL_2172)]).run_check()

        reloaded = service(tmp_path, registry, clock).current()

        assert reloaded.notice is not None and reloaded.notice.minimum == GatewayVersion(10, 50, 1)
        assert reloaded.releases["latest"] == LATEST
        assert reloaded.checked_at == clock.now

    def test_a_saved_time_without_an_offset_is_refused_not_assumed_utc(self, tmp_path):
        (tmp_path / "gateway_version.json").write_text(json.dumps({"checked_at": "2026-11-14T12:00:00"}))

        state = service(tmp_path, Registry(), Clock(utc(2026, 11, 14, 17))).current()

        assert state.checked_at is None

    def test_a_corrupt_state_file_starts_empty(self, tmp_path):
        (tmp_path / "gateway_version.json").write_text("{not json")

        state = service(tmp_path, Registry(), Clock(utc(2026, 11, 14, 17))).current()

        assert state.checked_at is None and state.notice is None

    async def test_only_one_check_runs_at_a_time(self, tmp_path):
        gate = asyncio.Event()
        calls: list[str] = []
        svc = service(tmp_path, Registry(paper=connected()), Clock(utc(2026, 11, 14, 17)))

        async def slow_probe(mode, client_id):
            calls.append(mode)
            await gate.wait()
            return ProbeResult(messages=[], error=None)

        svc._probe_mode = slow_probe
        assert svc.start_check()
        assert not svc.start_check(), "a second start while one runs must not start another"
        gate.set()
        await svc.wait_for_check()
        assert calls == ["paper"]

    def test_the_saved_file_is_json(self, tmp_path):
        """Operators read it directly when the dashboard is down."""
        asyncio.run(service(tmp_path, Registry(paper=connected()), Clock(utc(2026, 11, 14, 17)), probe_messages=[(2172, REAL_2172)]).run_check())

        saved = json.loads((tmp_path / "gateway_version.json").read_text())

        assert saved["notice"]["cutoff"] == "2026-12-15"
        assert saved["running"] == "10.47.1b"


class TestProbeClientIdChoice:
    """Only IB knows whether a client ID is in use right now. The Gateway's
    client tabs stay until it restarts, so STATUS's ID list means "has
    connected since", and excluding those would use up the IDs one probe at
    a time. A cleanly closed ID is free again at once (checked on a paper
    Gateway: 9172 reconnected 90 s after a disconnect), so
    every check starts at 9172 and moves up only on IB's 326."""

    NOW = utc(2026, 11, 14, 17)

    async def test_it_probes_as_9172_whatever_the_gateway_lists(self, tmp_path):
        ids: list[int] = []
        earlier = ("Client 1", "Client 9172", "Client 9173", "Client 50")
        svc = service(tmp_path, Registry(paper=connected(ids=earlier)), Clock(self.NOW), probed_ids=ids)

        await svc.run_check()

        assert ids == [9172]

    async def test_every_check_starts_at_9172_again(self, tmp_path):
        ids: list[int] = []
        clock = Clock(self.NOW)
        svc = service(tmp_path, Registry(paper=connected()), clock, probed_ids=ids)

        await svc.run_check()
        clock.now = utc(2026, 11, 21, 17)
        await svc.run_check()

        assert ids == [9172, 9172]

    REFUSED_RESULT = ProbeResult(messages=[REFUSED], error="TimeoutError: no answer within 10s; IB said: 326 ...")

    async def test_refused_ids_step_up_until_one_connects(self, tmp_path):
        ids: list[int] = []
        svc = service(
            tmp_path, Registry(paper=connected()), Clock(self.NOW), probed_ids=ids,
            probe_results=[self.REFUSED_RESULT, self.REFUSED_RESULT, ProbeResult(messages=[FARM_OK])],
        )

        state = await svc.run_check()

        assert ids == [9172, 9173, 9174]
        assert state.probe_error is None
        assert state.last_probe_at == self.NOW

    async def test_it_stops_at_the_end_of_the_block(self, tmp_path):
        ids: list[int] = []
        svc = service(
            tmp_path, Registry(paper=connected()), Clock(self.NOW), probed_ids=ids,
            probe_results=[self.REFUSED_RESULT] * 9 + [ProbeResult(messages=[FARM_OK])],
        )

        state = await svc.run_check()

        assert ids == list(range(9172, 9180))
        assert "326" in state.probe_error
        assert state.last_probe_at is None

    async def test_other_failures_are_not_retried(self, tmp_path):
        ids: list[int] = []
        svc = service(
            tmp_path, Registry(paper=connected()), Clock(self.NOW), probed_ids=ids,
            probe_results=[ProbeResult(error="ConnectionRefusedError: refused"), ProbeResult(messages=[FARM_OK])],
        )

        state = await svc.run_check()

        assert ids == [9172]
        assert state.probe_error == "ConnectionRefusedError: refused"


class TestRetryAnUnansweredCheck:
    """A check that got no answer is not left for a week (the start-up check
    runs while both modes are still logging in)."""

    async def _skipped_at_start(self, tmp_path, clock):
        registry = Registry(live={"state": "WaitingFor2fa"}, paper={"state": "Authenticating"})
        svc = service(tmp_path, registry, clock)
        await svc.run_check()
        return svc, registry

    async def test_it_retries_once_a_mode_is_connected(self, tmp_path):
        clock = Clock(utc(2026, 11, 9, 23, 30))  # a Monday evening
        svc, registry = await self._skipped_at_start(tmp_path, clock)

        registry.modes["paper"] = connected()
        clock.now = utc(2026, 11, 9, 23, 35)
        assert not svc.due(), "not before the retry spacing"
        clock.now = utc(2026, 11, 9, 23, 41)
        assert svc.due()

    async def test_a_site_with_no_logged_in_mode_does_not_retry(self, tmp_path):
        """The standby: no Gateway to ask, so no point fetching every ten minutes."""
        clock = Clock(utc(2026, 11, 9, 23, 30))
        svc, _ = await self._skipped_at_start(tmp_path, clock)

        clock.now = utc(2026, 11, 10, 9)
        assert not svc.due()

    async def test_an_answered_check_waits_for_saturday(self, tmp_path):
        clock = Clock(utc(2026, 11, 9, 23, 30))
        svc = service(tmp_path, Registry(paper=connected()), clock)
        await svc.run_check()

        clock.now = utc(2026, 11, 13, 12)
        assert not svc.due()

    async def test_a_failed_release_read_is_retried(self, tmp_path):
        clock = Clock(utc(2026, 11, 9, 23, 30))
        svc = service(tmp_path, Registry(paper=connected()), clock, release_error=TimeoutError("slow"))
        await svc.run_check()

        clock.now = utc(2026, 11, 9, 23, 41)
        assert svc.due()
