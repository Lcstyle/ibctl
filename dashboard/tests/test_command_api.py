"""Tests for the command API endpoint."""

import pytest


@pytest.mark.asyncio
async def test_send_valid_command(client, fake_client):
    response = await client.post("/api/v1/command", json={"command": "RESTART"})
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["command"] == "RESTART"
    assert fake_client._last_command == "RESTART"


@pytest.mark.asyncio
async def test_send_unknown_command(client):
    response = await client.post("/api/v1/command", json={"command": "INVALID"})
    data = response.json()
    assert data["ok"] is False
    assert "Unknown command" in data["error"]


@pytest.mark.asyncio
async def test_command_case_insensitive(client, fake_client):
    response = await client.post("/api/v1/command", json={"command": "stop"})
    data = response.json()
    assert data["ok"] is True
    assert fake_client._last_command == "STOP"


@pytest.mark.asyncio
async def test_state_endpoint(client):
    response = await client.get("/api/v1/state")
    assert response.status_code == 200
    data = response.json()
    assert data["current"] == "Connected"


@pytest.mark.asyncio
async def test_config_endpoint(client):
    response = await client.get("/api/v1/config")
    assert response.status_code == 200
    data = response.json()
    assert data["auth"]["password"] == "********"


@pytest.mark.asyncio
async def test_windows_endpoint(client):
    response = await client.get("/api/v1/windows")
    assert response.status_code == 200
    data = response.json()
    assert "windows" in data
