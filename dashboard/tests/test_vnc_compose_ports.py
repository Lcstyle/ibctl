"""Compose publishes VNC's 5900 on IBCTL_VNC_BIND only, and no noVNC port at all.

The browser's VNC goes through the dashboard's login-checked `/websockify`, so
websockify's own port (6080) is never published. 5900 stays for a regular VNC
client, on the loopback address unless the operator sets IBCTL_VNC_BIND.

docker-compose.yml is hand-written; the files under examples/ are generated from
the Pkl schema by tools/renderers/compose_renderer.py. Both are checked.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
COMPOSE_FILES = [REPO / "docker-compose.yml", *sorted((REPO / "examples").glob("docker-compose*.yml"))]
VNC_MAPPING = "${IBCTL_VNC_BIND:-127.0.0.1}:5900:5900"  # nosecret: not a credential


def published_ports(compose: Path) -> list[str]:
    """Every `- "<mapping>"` list entry in the file, quotes and comments stripped."""
    mappings = []
    for line in compose.read_text().splitlines():
        entry = re.match(r"""\s*-\s*["']?([^"'#\s]+)["']?\s*(?:#.*)?$""", line)
        if entry and re.search(r":\d+$", entry.group(1)):
            mappings.append(entry.group(1))
    return mappings


def test_the_compose_files_are_found():
    assert len(COMPOSE_FILES) > 1 and all(path.exists() for path in COMPOSE_FILES)


@pytest.mark.parametrize("compose", COMPOSE_FILES, ids=lambda path: str(path.relative_to(REPO)))
class TestVncPorts:
    def test_the_noVNC_websocket_port_is_not_published(self, compose):
        assert [m for m in published_ports(compose) if m.endswith(":6080")] == []

    def test_5900_is_published_only_through_IBCTL_VNC_BIND(self, compose):
        vnc = [m for m in published_ports(compose) if m.endswith(":5900")]
        assert vnc == [VNC_MAPPING]


def test_websockify_listens_on_loopback_only():
    entrypoint = (REPO / "docker" / "entrypoint.sh").read_text()
    starts = [line.strip() for line in entrypoint.splitlines() if line.strip().startswith("websockify ")]
    assert starts == ['websockify --daemon "127.0.0.1:${NOVNC_PORT}" localhost:5900']


def _compose_files():
    root = REPO if "REPO" in globals() else Path(__file__).resolve().parents[2]
    return [root / "docker-compose.yml", *sorted((root / "examples").glob("docker-compose.*.yml"))]


@pytest.mark.parametrize("path", _compose_files(), ids=lambda p: p.name)
def test_a_file_that_publishes_5900_also_tells_the_container_where(path):
    """Preflight refuses a network bind without a VNC password, but only if the
    container can see IBCTL_VNC_BIND; compose otherwise uses it for the port only."""
    text = path.read_text()
    if "5900:5900" not in text:
        pytest.skip("does not publish VNC")
    assert "IBCTL_VNC_BIND: ${IBCTL_VNC_BIND:-127.0.0.1}" in text
