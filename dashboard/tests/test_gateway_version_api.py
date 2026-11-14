"""Gateway version tracking — the JSON endpoint."""

from __future__ import annotations

from datetime import date, datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import gateway_version as gateway_version_api
from app.services.gateway_version.desupport import DesupportNotice
from app.services.gateway_version.releases import ChannelRelease
from app.services.gateway_version.service import VersionState
from app.services.gateway_version.versions import GatewayVersion

V = GatewayVersion.parse


class FakeService:
    def __init__(self, state: VersionState, start_returns: bool = True):
        self._state = state
        self._start_returns = start_returns
        self.started = 0

    def current(self):
        return self._state

    def next_check(self):
        return datetime(2026, 11, 21, 17, tzinfo=timezone.utc)

    def start_check(self):
        self.started += 1
        return self._start_returns


def client_with(service) -> TestClient:
    app = FastAPI()
    app.include_router(gateway_version_api.router)
    app.state.gateway_version = service
    return TestClient(app)


STATE = VersionState(
    running="10.47.1b",
    channel="stable",
    checked_at=datetime(2026, 11, 14, 17, tzinfo=timezone.utc),
    releases={"stable": ChannelRelease("stable", V("10.50.1f"), date(2026, 10, 5))},
    probed_mode="paper",
    notice=DesupportNotice(running=V("1047.1"), cutoff=date(2026, 12, 15), minimum=V("1050.1")),
)


def test_get_reports_the_version_status_cutoff_and_next_check():
    body = client_with(FakeService(STATE)).get("/api/v1/gateway/version").json()

    assert body["status"] == "below_minimum"
    assert body["running"] == "10.47.1b"
    assert body["notice"]["cutoff"] == "2026-12-15"
    assert body["available"] == {"stable": "10.50.1f"}
    assert body["checked_at"] == "2026-11-14T17:00:00+00:00", "instants carry their offset"
    assert body["next_check"] == "2026-11-21T17:00:00+00:00"
    assert isinstance(body["days_left"], int)


def test_post_check_starts_a_check():
    service = FakeService(STATE)

    response = client_with(service).post("/api/v1/gateway/version/check")

    assert response.status_code == 202
    assert response.json() == {"started": True}
    assert service.started == 1


def test_post_check_while_one_runs_says_so():
    response = client_with(FakeService(STATE, start_returns=False)).post("/api/v1/gateway/version/check")

    assert response.status_code == 409
    assert response.json() == {"started": False, "reason": "a check is already running"}


def test_without_the_service_the_endpoint_says_unavailable():
    app = FastAPI()
    app.include_router(gateway_version_api.router)

    response = TestClient(app).get("/api/v1/gateway/version")

    assert response.status_code == 503
