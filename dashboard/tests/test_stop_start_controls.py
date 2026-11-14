"""Stop and Start for each Gateway, on the overview and on the State tab.

STOP parks a Gateway in WaitingForLaunch. START is honoured only from there;
in any other state the Gateway logs it and ignores it, and Shutdown is the
terminal state EXIT leaves behind (ibctl/src/state_machine/mod.rs,
dispatch_command). So the buttons offer exactly what the Gateway will act on.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

from app.instance_registry import _CachedResponse
from tests.test_ui_redesign import _build_status_dict, _make_client

TRANSPORT_JS = Path(__file__).resolve().parents[1] / "app" / "static" / "transport.js"
STOPPED = frozenset({"WaitingForLaunch", "Shutdown"})


def _plant(app, states: dict[str, str], role: str) -> None:
    registry = app.state.instance_registry
    for mode, state in states.items():
        status = _build_status_dict(state=state)
        status["site"] = {"role": role, "auto_launch": role == "primary"}
        if state in STOPPED:
            status["jvm"] = {"pid": None, "alive": False, "uptime_secs": 0}
        registry._cache[f"{mode}:STATUS"] = _CachedResponse(status, ttl=60.0)


async def _controls(states: dict[str, str], role: str = "primary") -> dict[str, list]:
    """Each mode's controls-bar buttons, in page order."""
    app, client_ctx = await _make_client()
    _plant(app, states, role)
    async with client_ctx as client:
        html = (await client.get("/partials/overview")).text
    soup = BeautifulSoup(html, "html.parser")
    return {
        mode: soup.find(id=f"cmd-result-{mode}").parent.find_all("button")
        for mode in states
    }


def _by_label(buttons) -> dict:
    return {b.get_text(strip=True): b for b in buttons}


# --------------------------------------------------------------------------
# Overview
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stop_and_start_follow_restart_for_live_and_paper():
    bars = await _controls({"live": "Connected", "paper": "Connected"})

    for mode, buttons in bars.items():
        labels = [b.get_text(strip=True) for b in buttons]
        assert labels[-3:] == ["Restart", "Stop", "Start"], (mode, labels)
        by = _by_label(buttons)
        assert f"sendCmd('STOP','{mode}')" in by["Stop"]["onclick"]
        assert f"sendCmd('START','{mode}')" in by["Start"]["onclick"]
        assert "confirm(" in by["Stop"]["onclick"]
        assert "confirm(" in by["Start"]["onclick"]


@pytest.mark.asyncio
async def test_a_running_gateway_offers_stop_not_start():
    by = _by_label(
        (await _controls({"live": "Connected", "paper": "Authenticating"}))["paper"]
    )

    assert not by["Stop"].has_attr("disabled")
    assert by["Start"].has_attr("disabled")


@pytest.mark.asyncio
async def test_a_stopped_gateway_offers_start_not_stop():
    bars = await _controls({"live": "Connected", "paper": "WaitingForLaunch"})
    paper, live = _by_label(bars["paper"]), _by_label(bars["live"])

    assert not paper["Start"].has_attr("disabled")
    assert paper["Stop"].has_attr("disabled")
    assert live["Start"].has_attr("disabled"), "each mode follows its own state"
    assert not live["Stop"].has_attr("disabled")


@pytest.mark.asyncio
async def test_a_shut_down_gateway_offers_neither():
    """EXIT ends the process: START is ignored there and STOP has nothing to stop."""
    by = _by_label(
        (await _controls({"live": "Connected", "paper": "Shutdown"}))["paper"]
    )

    assert by["Start"].has_attr("disabled")
    assert by["Stop"].has_attr("disabled")


@pytest.mark.asyncio
async def test_stop_says_what_brings_the_gateway_back():
    by = _by_label(
        (await _controls({"live": "Connected", "paper": "Connected"}))["live"]
    )

    assert "until you press Start" in by["Stop"]["onclick"]


@pytest.mark.asyncio
async def test_start_on_a_standby_site_says_it_promotes_this_node():
    """START is how a standby node is promoted (the overview's standby notice says
    so), so the button stays available; its confirmation names the consequence."""
    standby = _by_label(
        (
            await _controls(
                {"live": "WaitingForLaunch", "paper": "WaitingForLaunch"},
                role="standby",
            )
        )["paper"]
    )
    primary = _by_label(
        (await _controls({"live": "WaitingForLaunch", "paper": "WaitingForLaunch"}))[
            "paper"
        ]
    )

    assert not standby["Start"].has_attr("disabled")
    assert "standby" in standby["Start"]["onclick"].lower()
    assert "standby" not in primary["Start"]["onclick"].lower()


# --------------------------------------------------------------------------
# State tab
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_state_tab_tags_every_transport_button_with_its_role(client):
    soup = BeautifulSoup((await client.get("/state")).text, "html.parser")

    roles = [b["data-transport"] for b in soup.select("[data-transport]")]
    assert sorted(roles) == sorted(["pause", "resume", "stop", "start"] * 2), (
        "desktop and mobile each carry pause, resume, stop and start"
    )
    for b in soup.select('[data-transport="start"]'):
        assert "sendCmd('START'" in b["onclick"]
    assert soup.find("script", src=lambda s: s and "/static/transport.js" in s)


NODE = shutil.which("node")


def _transport(state: str, paused: bool) -> dict:
    out = subprocess.run(
        [
            NODE,
            "-e",
            "const f = require(process.argv[1]);"
            "console.log(JSON.stringify(f(process.argv[2], process.argv[3] === 'true')))",
            str(TRANSPORT_JS),
            state,
            "true" if paused else "false",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(out.stdout)


@pytest.mark.skipif(NODE is None, reason="node is not installed")
@pytest.mark.parametrize(
    "state, paused, expected",
    [
        (
            "Connected",
            False,
            {"pause": True, "resume": False, "stop": True, "start": False},
        ),
        (
            "Connected",
            True,
            {"pause": False, "resume": True, "stop": True, "start": False},
        ),
        (
            "Authenticating",
            False,
            {"pause": True, "resume": False, "stop": True, "start": False},
        ),
        (
            "WaitingForLaunch",
            False,
            {"pause": False, "resume": False, "stop": False, "start": True},
        ),
        (
            "WaitingForLaunch",
            True,
            {"pause": False, "resume": True, "stop": False, "start": True},
        ),
        (
            "Shutdown",
            False,
            {"pause": False, "resume": False, "stop": False, "start": False},
        ),
    ],
)
def test_the_state_tab_offers_what_the_gateway_will_act_on(state, paused, expected):
    assert _transport(state, paused) == expected


# --------------------------------------------------------------------------
# A paused ibctl whose Gateway has exited
# --------------------------------------------------------------------------


async def _overview_with(paused_gateway_down: bool) -> BeautifulSoup:
    app, client_ctx = await _make_client()
    registry = app.state.instance_registry
    for mode in ("live", "paper"):
        status = _build_status_dict(state="Connected")
        status["site"] = {"role": "primary", "auto_launch": True}
        if paused_gateway_down and mode == "paper":
            status.update({"paused": True, "paused_gateway_down": True, "gateway_running": False, "ready": False})
            status["jvm"] = {"pid": None, "alive": False, "uptime_secs": 0}
        registry._cache[f"{mode}:STATUS"] = _CachedResponse(status, ttl=60.0)
    async with client_ctx as client:
        html = (await client.get("/partials/overview")).text
    return BeautifulSoup(html, "html.parser")


@pytest.mark.asyncio
async def test_a_paused_machine_with_no_gateway_says_so_and_offers_resume():
    soup = await _overview_with(paused_gateway_down=True)

    bar = soup.find(id="cmd-result-paper").parent
    by = _by_label(bar.find_all("button"))
    assert "sendCmd('RESUME','paper')" in by["Resume"]["onclick"]
    assert "Paused" in bar.get_text() and "Gateway is not running" in bar.get_text()

    live_bar = soup.find(id="cmd-result-live").parent
    assert "Resume" not in _by_label(live_bar.find_all("button")), "a healthy mode offers no Resume"
    assert "Gateway is not running" not in live_bar.get_text()


@pytest.mark.asyncio
async def test_the_gateway_state_row_does_not_pass_a_frozen_state_off_as_current():
    soup = await _overview_with(paused_gateway_down=True)

    text = " ".join(soup.get_text().split())
    assert "Connected (paused, Gateway not running)" in text
