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


# The State and Controls pages post their buttons form-encoded (htmx `values` /
# `hx-vals`). The API took JSON only, so every one of those buttons got a 422
# that htmx never shows: Stop "did nothing".


@pytest.mark.asyncio
async def test_a_form_encoded_button_reaches_the_gateway(client, fake_client):
    response = await client.post("/api/v1/command", data={"command": "STOP"})

    assert response.status_code == 200
    assert fake_client._last_command == "STOP"


@pytest.mark.asyncio
async def test_start_is_allowed_so_a_stopped_mode_can_be_started_again(client, fake_client):
    response = await client.post("/api/v1/command", json={"command": "START"})

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert fake_client._last_command == "START"


@pytest.mark.asyncio
async def test_a_body_with_no_command_is_a_clear_error(client):
    response = await client.post("/api/v1/command", data={"mode": "paper"})

    assert response.status_code == 422
    assert "command" in response.json()["error"]


@pytest.mark.asyncio
async def test_the_state_tab_has_a_start_button(client):
    html = (await client.get("/state")).text

    assert "sendCmd('START'" in html
