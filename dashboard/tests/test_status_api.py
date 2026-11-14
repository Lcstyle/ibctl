"""Tests for the status API endpoint."""

import pytest


@pytest.mark.asyncio
async def test_status_returns_200(client):
    response = await client.get("/api/v1/status")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_status_contains_ready_field(client):
    response = await client.get("/api/v1/status")
    data = response.json()
    assert "ready" in data
    assert data["ready"] is True


@pytest.mark.asyncio
async def test_status_contains_client_advisory(client):
    response = await client.get("/api/v1/status")
    data = response.json()
    assert "client_advisory" in data
    advisory = data["client_advisory"]
    assert "should_connect" in advisory
    assert "should_wait" in advisory
    assert "wait_reason" in advisory


@pytest.mark.asyncio
async def test_status_contains_state(client):
    response = await client.get("/api/v1/status")
    data = response.json()
    assert data["state"] == "Connected"


@pytest.mark.asyncio
async def test_health_returns_ok(client):
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# /api/v1/schedule — exposes ibctl's own scheduled-restart
# configuration for external clients to correlate their own
# connection-lost outages against, instead of each consumer duplicating
# AUTO_RESTART_TIME/TWS_COLD_RESTART parsing independently.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_schedule_returns_200(client):
    response = await client.get("/api/v1/schedule")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_schedule_reports_configured_auto_restart(client, monkeypatch):
    monkeypatch.setenv("AUTO_RESTART_TIME", "05:05 PM")
    response = await client.get("/api/v1/schedule")
    data = response.json()
    assert data["auto_restart"]["configured"] is True
    assert data["auto_restart"]["time_12h"] == "05:05 PM"
    assert data["auto_restart"]["time_24h"] == "17:05"


@pytest.mark.asyncio
async def test_schedule_reports_unconfigured_auto_restart(client, monkeypatch):
    monkeypatch.delenv("AUTO_RESTART_TIME", raising=False)
    response = await client.get("/api/v1/schedule")
    data = response.json()
    assert data["auto_restart"]["configured"] is False
    assert data["auto_restart"]["time_12h"] is None
    assert data["auto_restart"]["time_24h"] is None


@pytest.mark.asyncio
async def test_schedule_reports_a_malformed_auto_restart_time_honestly(client, monkeypatch):
    """Configured but unparseable must not silently look identical to
    'unconfigured' — a client reading configured=True, time_24h=None knows
    ibctl's own config is broken, rather than concluding no schedule exists."""
    monkeypatch.setenv("AUTO_RESTART_TIME", "not-a-time")
    response = await client.get("/api/v1/schedule")
    data = response.json()
    assert data["auto_restart"]["configured"] is True
    assert data["auto_restart"]["time_12h"] == "not-a-time"
    assert data["auto_restart"]["time_24h"] is None


@pytest.mark.asyncio
async def test_schedule_reports_cold_restart_day_and_time(client, monkeypatch):
    monkeypatch.setenv("TWS_COLD_RESTART", "09:00")
    monkeypatch.delenv("TWS_COLD_RESTART_DAY", raising=False)  # default 0 = Sunday
    response = await client.get("/api/v1/schedule")
    data = response.json()
    assert data["cold_restart"]["configured"] is True
    assert data["cold_restart"]["time_24h"] == "09:00"
    assert data["cold_restart"]["day"] == 0
    assert data["cold_restart"]["day_name"] == "Sunday"


@pytest.mark.asyncio
async def test_schedule_respects_custom_cold_restart_day(client, monkeypatch):
    monkeypatch.setenv("TWS_COLD_RESTART", "02:00")
    monkeypatch.setenv("TWS_COLD_RESTART_DAY", "3")  # Wednesday
    response = await client.get("/api/v1/schedule")
    data = response.json()
    assert data["cold_restart"]["day"] == 3
    assert data["cold_restart"]["day_name"] == "Wednesday"


@pytest.mark.asyncio
async def test_schedule_exposes_the_same_correlation_and_grace_ibctl_itself_uses(client, monkeypatch):
    """The whole point of this endpoint: a client's replica of the
    correlation algorithm must use the SAME numbers ibctl's own
    session_lost.py enforces, not independently-guessed defaults that
    could silently drift apart."""
    monkeypatch.setenv("IBCTL_SCHEDULED_RESTART_GRACE_MINUTES", "37")
    response = await client.get("/api/v1/schedule")
    data = response.json()
    assert data["correlation_minutes"] == 5
    assert data["grace_minutes"] == 37


@pytest.mark.asyncio
async def test_schedule_reports_a_timezone(client):
    response = await client.get("/api/v1/schedule")
    data = response.json()
    assert data["timezone"], "a client cannot correctly correlate clock times without knowing which timezone they're in"
