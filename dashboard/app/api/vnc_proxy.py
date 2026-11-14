"""The VNC websocket: the dashboard's `/websockify`, proxied to websockify.

websockify runs inside the container on loopback (docker/entrypoint.sh) and is
not published. The VNC page's noVNC client connects here instead, and this
route relays frames both ways to websockify at 127.0.0.1:IBCTL_NOVNC_PORT.

Only a logged-in person gets that far (`require_websocket_login`); everyone else
is refused before the socket is accepted.
"""

from __future__ import annotations

import asyncio
import logging
import os

from fastapi import APIRouter, Depends, WebSocket
from starlette.websockets import WebSocketDisconnect, WebSocketState
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidHandshake

from app.middleware.auth import Login, client_ip, require_websocket_login

logger = logging.getLogger("dashboard.api.vnc")
router = APIRouter()

DEFAULT_NOVNC_PORT = 6080
# A VNC clipboard or framebuffer update can be large; refuse anything past this.
MAX_FRAME_BYTES = 16 * 1024 * 1024
CONNECT_TIMEOUT_SECONDS = 5

NORMAL_CLOSURE = 1000
INTERNAL_ERROR = 1011


def upstream_url() -> str:
    """Where websockify listens: loopback, at the same port the entrypoint starts it on."""
    port = int(os.environ.get("IBCTL_NOVNC_PORT", str(DEFAULT_NOVNC_PORT)))
    return f"ws://127.0.0.1:{port}/"


async def _browser_to_websockify(websocket: WebSocket, upstream) -> None:
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return
        if message.get("bytes") is not None:
            await upstream.send(message["bytes"])
        elif message.get("text") is not None:
            await upstream.send(message["text"])


async def _websockify_to_browser(websocket: WebSocket, upstream) -> None:
    async for message in upstream:
        if isinstance(message, bytes):
            await websocket.send_bytes(message)
        else:
            await websocket.send_text(message)


@router.websocket("/websockify")
async def websockify(websocket: WebSocket, login: Login = Depends(require_websocket_login)):
    offered = websocket.scope.get("subprotocols", [])
    try:
        upstream = await connect(
            upstream_url(),
            subprotocols=offered or None,
            max_size=MAX_FRAME_BYTES,
            compression=None,
            ping_interval=None,
            open_timeout=CONNECT_TIMEOUT_SECONDS,
        )
    except (OSError, TimeoutError, InvalidHandshake) as exc:
        logger.warning("VNC websocket: websockify is not answering at %s: %s", upstream_url(), exc)
        await websocket.close(code=INTERNAL_ERROR)
        return

    ip = client_ip(websocket)
    async with upstream:
        await websocket.accept(subprotocol=upstream.subprotocol)
        logger.info("VNC websocket opened by %s from %s", login.name, ip)
        pumps = [
            asyncio.ensure_future(_browser_to_websockify(websocket, upstream)),
            asyncio.ensure_future(_websockify_to_browser(websocket, upstream)),
        ]
        try:
            await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for pump in pumps:
                pump.cancel()
            outcomes = await asyncio.gather(*pumps, return_exceptions=True)
    for outcome in outcomes:
        # A hang-up on either side is how a session normally ends; anything else is worth a line.
        if isinstance(outcome, Exception) and not isinstance(outcome, (ConnectionClosed, WebSocketDisconnect, RuntimeError)):
            logger.warning("VNC websocket for %s from %s ended on an error: %r", login.name, ip, outcome)
    logger.info("VNC websocket closed for %s from %s", login.name, ip)

    # websockify hung up (or a pump failed) while the browser was still there: tell it.
    if WebSocketState.CONNECTED == websocket.client_state == websocket.application_state:
        clean = upstream.close_code in (None, NORMAL_CLOSURE, 1001)
        try:
            await websocket.close(code=NORMAL_CLOSURE if clean else INTERNAL_ERROR)
        except (RuntimeError, WebSocketDisconnect):
            pass  # the browser went in the meantime
