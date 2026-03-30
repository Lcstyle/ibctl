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
