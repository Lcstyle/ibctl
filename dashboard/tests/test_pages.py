"""Tests for web UI page routes."""

import pytest


@pytest.mark.asyncio
async def test_overview_page_returns_200(client):
    response = await client.get("/")
    assert response.status_code == 200
    assert "ibctl" in response.text.lower()


@pytest.mark.asyncio
async def test_state_page_returns_200(client):
    response = await client.get("/state")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_config_page_returns_200(client):
    response = await client.get("/config")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_logs_page_returns_200(client):
    response = await client.get("/logs")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_controls_page_redirects_to_state(client):
    """Controls were merged into the State page — /controls redirects."""
    response = await client.get("/controls")
    assert response.status_code == 307
    assert "/state" in response.headers.get("location", "")


@pytest.mark.asyncio
async def test_overview_partial_returns_html(client):
    response = await client.get("/partials/overview")
    assert response.status_code == 200
    assert "Gateway" in response.text or "Connected" in response.text or "status" in response.text.lower()
