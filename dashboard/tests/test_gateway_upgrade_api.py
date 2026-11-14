"""Gateway upgrades: the API CI and the Sunday maintenance job talk to."""

from __future__ import annotations

from datetime import date, datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import gateway_upgrade as api
from app.services.gateway_version.decision import Decision
from app.services.gateway_version.releases import ChannelRelease
from app.services.gateway_version.service import VersionState
from app.services.gateway_version.upgrade import BuildReport, UpgradeStore, swap_plan
from app.services.gateway_version.versions import GatewayVersion

V = GatewayVersion.parse
SHA = "0123456789abcdef0123456789abcdef01234567"  # nosecret: a made-up commit id
NOW = datetime(2026, 11, 14, 18, tzinfo=timezone.utc)
SATURDAY = date(2026, 11, 14)


class FakeVersions:
    def __init__(self, state):
        self._state = state

    def current(self):
        return self._state


STATE = VersionState(
    running="10.50.1f",
    checked_at=datetime(2026, 11, 14, 17, tzinfo=timezone.utc),
    releases={"stable": ChannelRelease("stable", V("10.51.1h"), date(2026, 11, 2))},
    history={"stable": [ChannelRelease("stable", V("10.50.1f"), date(2026, 10, 5)),
                        ChannelRelease("stable", V("10.51.1h"), date(2026, 11, 2))]},
)

POLICY_ON = {"enabled": True, "channel": "stable", "cadence": "every_sunday", "soak_days": 7, "deadline_days": 21}


@pytest.fixture
def store(tmp_path):
    return UpgradeStore(tmp_path / "config" / "policy.json", tmp_path / "upgrade.json", clock=lambda: NOW)


def client_for(store, state=STATE) -> TestClient:
    app = FastAPI()
    app.include_router(api.router)
    app.state.gateway_upgrade = store
    app.state.gateway_version = FakeVersions(state)
    app.state.gateway_upgrade_today = lambda: SATURDAY
    return TestClient(app)


class TestPolicyEndpoints:
    def test_the_default_policy_is_off(self, store):
        body = client_for(store).get("/api/v1/gateway/upgrade").json()

        assert body["policy"]["enabled"] is False
        assert body["decision"]["due"] is False
        assert body["decision"]["reason"] == "automatic upgrades are off"
        assert set(body["cadences"]) == {"every_sunday", "first_sunday"}

    def test_saving_a_policy_changes_the_decision(self, store):
        client = client_for(store)

        r = client.put("/api/v1/gateway/upgrade/policy", json=POLICY_ON)

        assert r.status_code == 200
        assert r.json()["decision"]["due"] is True
        assert r.json()["decision"]["target"] == "10.51.1h"
        assert client.get("/api/v1/gateway/upgrade").json()["policy"] == POLICY_ON

    @pytest.mark.parametrize("bad", [
        {**POLICY_ON, "channel": "nightly"},
        {**POLICY_ON, "soak_days": 400},
        {**POLICY_ON, "enabled": "yes"},
        {**POLICY_ON, "soak_days": "7"},
    ])
    def test_a_bad_policy_is_refused_and_not_saved(self, store, bad):
        client = client_for(store)

        r = client.put("/api/v1/gateway/upgrade/policy", json=bad)

        assert r.status_code == 422
        assert client.get("/api/v1/gateway/upgrade").json()["policy"]["enabled"] is False

    def test_an_unreadable_saved_policy_is_shown_not_replaced(self, store, tmp_path):
        store.policy_path.parent.mkdir(parents=True, exist_ok=True)
        store.policy_path.write_text("{oops")

        body = client_for(store).get("/api/v1/gateway/upgrade").json()

        assert body["policy"] is None
        assert "not valid JSON" in body["policy_error"]
        assert body["decision"]["due"] is False
        assert body["swap"]["ready"] is False


class TestCandidateReports:
    def test_ci_reports_a_built_candidate(self, store):
        client = client_for(store)
        client.put("/api/v1/gateway/upgrade/policy", json=POLICY_ON)

        r = client.post("/api/v1/gateway/upgrade/candidate", json={"version": "10.51.1h", "sha": SHA, "status": "built"})

        assert r.status_code == 200
        body = client.get("/api/v1/gateway/upgrade").json()
        assert body["candidate"]["sha"] == SHA
        assert body["candidate"]["reported_at"] == "2026-11-14T18:00:00+00:00"
        assert body["swap"] == {"ready": True, "version": "10.51.1h", "sha": SHA,
                                "reason": "10.51.1h is built and due on 2026-11-15"}

    @pytest.mark.parametrize("bad", [
        {"version": "not-a-version", "sha": SHA, "status": "built"},
        {"version": "10.51.1h", "sha": "abc123", "status": "built"},
        {"version": "10.51.1h", "sha": SHA, "status": "maybe"},
        {"version": "10.51.1h", "sha": SHA, "status": "built", "detail": "x" * 501},
    ])
    def test_a_malformed_report_is_refused(self, store, bad):
        r = client_for(store).post("/api/v1/gateway/upgrade/candidate", json=bad)

        assert r.status_code == 422
        assert store.record().candidate is None

    def test_the_host_reports_a_swap(self, store):
        client = client_for(store)

        r = client.post("/api/v1/gateway/upgrade/swap",
                        json={"version": "10.51.1h", "sha": SHA, "result": "rolled_back", "detail": "PAPER never connected"})

        assert r.status_code == 200
        last = client.get("/api/v1/gateway/upgrade").json()["last_swap"]
        assert (last["result"], last["detail"]) == ("rolled_back", "PAPER never connected")

    def test_reports_survive_a_restart(self, store, tmp_path):
        client_for(store).post("/api/v1/gateway/upgrade/candidate", json={"version": "10.51.1h", "sha": SHA, "status": "built"})

        again = UpgradeStore(store.policy_path, store.record_path)

        assert again.record().candidate.sha == SHA


class TestSwapPlan:
    DUE = Decision(True, date(2026, 11, 15), "10.51.1h", "stable", "soaked")
    BUILT = BuildReport("10.51.1h", SHA, "built", NOW, "")

    def test_ready_when_due_and_the_candidate_is_that_build(self):
        assert swap_plan(self.DUE, self.BUILT).ready

    @pytest.mark.parametrize("decision, candidate, why", [
        (Decision(False, date(2026, 11, 15), None, None, "automatic upgrades are off"), BUILT, "automatic upgrades are off"),
        (DUE, None, "nothing has been built for 10.51.1h"),
        (DUE, BuildReport("10.51.1h", SHA, "failed", NOW, "tests failed"), "the 10.51.1h build failed: tests failed"),
        (DUE, BuildReport("10.51.1g", SHA, "built", NOW, ""), "the built candidate is 10.51.1g, not 10.51.1h"),
    ])
    def test_not_ready_says_why(self, decision, candidate, why):
        plan = swap_plan(decision, candidate)

        assert not plan.ready
        assert plan.reason == why


def test_no_service_is_a_503():
    app = FastAPI()
    app.include_router(api.router)

    assert TestClient(app).get("/api/v1/gateway/upgrade").status_code == 503
