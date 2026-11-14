"""Gateway version tracking — the overview card."""

from __future__ import annotations

import html as html_lib
from datetime import date, datetime, timezone

import pytest

from app.services.gateway_version.desupport import DesupportNotice
from app.services.gateway_version.releases import ChannelRelease
from app.services.gateway_version.service import VersionState
from app.services.gateway_version.versions import GatewayVersion

V = GatewayVersion.parse


class FakeService:
    def __init__(self, state):
        self._state = state

    def current(self):
        return self._state

    def next_check(self):
        return datetime(2026, 11, 21, 17, tzinfo=timezone.utc)


def _app(client):
    return client._transport.app


BELOW = VersionState(
    running="10.47.1b",
    channel="stable",
    checked_at=datetime(2026, 11, 14, 17, tzinfo=timezone.utc),
    releases={
        "stable": ChannelRelease("stable", V("10.50.1f"), date(2026, 10, 5)),
        "latest": ChannelRelease("latest", V("10.51.1e"), date(2026, 10, 26)),
    },
    probed_mode="paper",
    notice=DesupportNotice(running=V("1047.1"), cutoff=date(2026, 12, 15), minimum=V("1050.1")),
)


@pytest.mark.asyncio
async def test_the_card_shows_the_cutoff_and_what_to_move_to(client):
    _app(client).state.gateway_version = FakeService(BELOW)

    html = html_lib.unescape((await client.get("/partials/overview")).text)  # the text a reader sees

    assert 'id="overview-gateway-version"' in html
    assert 'data-health="error"' in html.split('id="overview-gateway-version"')[1][:200]
    for text in ("10.47.1b", "10.50.1f", "10.51.1e", "2026-12-15", "10.50.1", "below IB's upcoming minimum"):
        assert text in html, text
    assert "Sat Nov 14 12:00 EST" in html, "times are shown in Eastern time"
    assert "Sat Nov 21 12:00 EST" in html


@pytest.mark.asyncio
async def test_a_probe_error_is_shown_not_hidden(client):
    state = VersionState(
        running="10.50.1f",
        checked_at=datetime(2026, 11, 14, 17, tzinfo=timezone.utc),
        probe_error="skipped: no mode is Connected",
    )
    _app(client).state.gateway_version = FakeService(state)

    html = (await client.get("/partials/overview")).text

    assert "skipped: no mode is Connected" in html
    assert "none announced" in html


@pytest.mark.asyncio
async def test_no_card_when_tracking_is_not_running(client):
    html = (await client.get("/partials/overview")).text

    assert 'id="overview-gateway-version"' not in html
