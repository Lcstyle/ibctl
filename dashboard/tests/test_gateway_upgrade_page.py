"""Gateway upgrades: the Gateway tab."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_the_gateway_tab_renders_the_policy_form(client):
    page = await client.get("/gateway")

    assert page.status_code == 200
    html = page.text
    for element in ('id="upgrade-enabled"', 'id="upgrade-channel"', 'id="upgrade-cadence"',
                    'id="upgrade-soak"', 'id="upgrade-deadline"', 'id="upgrade-save"', 'id="upgrade-decision"'):
        assert element in html, element
    assert "/api/v1/gateway/upgrade'" in html and "+ '/policy'" in html
    assert "method: 'PUT'" in html


@pytest.mark.asyncio
async def test_every_page_links_the_gateway_tab(client):
    html = (await client.get("/notifications")).text

    assert 'href="/gateway"' in html or '/gateway"' in html
