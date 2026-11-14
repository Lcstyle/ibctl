"""SUBSCRIBE client — persistent push connection to an ibctl command server.

Sends SUBSCRIBE to the ibctl TCP command server and reads NDJSON status events
in real-time. Replaces the 5-second polling loop with instant push notifications.

Falls back to polling if the ibctl binary doesn't support SUBSCRIBE (older versions).
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Callable

logger = logging.getLogger("dashboard.services.subscribe")

# Reconnect backoff: 1s, 2s, 4s, 8s, capped at 15s
INITIAL_BACKOFF = 1.0
MAX_BACKOFF = 15.0
BACKOFF_MULTIPLIER = 2.0

# If SUBSCRIBE fails this many times consecutively, assume old ibctl without
# SUBSCRIBE support and stop retrying (caller should fall back to polling).
MAX_SUBSCRIBE_FAILURES = 3

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 60.0  # Must be > keepalive interval (30s)


class SubscribeClient:
    """Persistent SUBSCRIBE connection to one ibctl instance.

    Connects, sends SUBSCRIBE, reads NDJSON lines, and calls on_status()
    for each status event. Reconnects with backoff on disconnect.
    """

    def __init__(
        self,
        host: str,
        port: int,
        mode: str,
        on_status: Callable[[str, dict], None],
    ):
        self._host = host
        self._port = port
        self._mode = mode
        self._on_status = on_status
        self._task: asyncio.Task | None = None
        self._stop = False
        self._subscribe_supported = True
        self._consecutive_failures = 0

    @property
    def subscribe_supported(self) -> bool:
        """False if ibctl doesn't support SUBSCRIBE (old binary)."""
        return self._subscribe_supported

    async def start(self):
        self._stop = False
        self._task = asyncio.create_task(self._run(), name=f"subscribe-{self._mode}")
        logger.info("Subscribe client started for %s at %s:%d", self._mode, self._host, self._port)

    async def stop(self):
        self._stop = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Subscribe client stopped for %s", self._mode)

    async def _run(self):
        backoff = INITIAL_BACKOFF
        while not self._stop:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self._host, self._port),
                    timeout=CONNECT_TIMEOUT,
                )
            except (ConnectionRefusedError, OSError, asyncio.TimeoutError) as e:
                logger.debug("Subscribe %s: connect failed: %s", self._mode, e)
                self._consecutive_failures += 1
                if self._consecutive_failures >= MAX_SUBSCRIBE_FAILURES:
                    self._subscribe_supported = False
                    logger.info(
                        "Subscribe %s: %d consecutive failures, marking unsupported",
                        self._mode, self._consecutive_failures,
                    )
                    return  # Stop trying — caller should fall back to polling
                await asyncio.sleep(backoff)
                backoff = min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF)
                continue

            try:
                writer.write(b"SUBSCRIBE\n")
                await writer.drain()

                # Read first line to verify SUBSCRIBE is supported
                first_line = await asyncio.wait_for(reader.readline(), timeout=CONNECT_TIMEOUT)
                if not first_line:
                    raise ConnectionError("Empty response")

                first = first_line.decode().strip()
                if first.startswith("ERROR"):
                    # Old ibctl that doesn't know SUBSCRIBE
                    logger.info("Subscribe %s: server returned %s — not supported", self._mode, first)
                    self._subscribe_supported = False
                    writer.close()
                    return

                # Parse the first line as NDJSON event
                self._handle_line(first)
                self._consecutive_failures = 0
                backoff = INITIAL_BACKOFF
                logger.info("Subscribe %s: connected, receiving events", self._mode)

                # Read NDJSON lines until disconnect
                while not self._stop:
                    try:
                        line_bytes = await asyncio.wait_for(reader.readline(), timeout=READ_TIMEOUT)
                    except asyncio.TimeoutError:
                        logger.warning("Subscribe %s: read timeout (no keepalive?)", self._mode)
                        break
                    if not line_bytes:
                        break  # EOF — server closed connection
                    self._handle_line(line_bytes.decode().strip())

            except (ConnectionError, OSError, asyncio.TimeoutError) as e:
                logger.debug("Subscribe %s: connection lost: %s", self._mode, e)
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

            # Reconnect after disconnect
            if not self._stop:
                logger.info("Subscribe %s: reconnecting in %.0fs", self._mode, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF)

    def _handle_line(self, line: str):
        if not line:
            return
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("Subscribe %s: invalid JSON: %s", self._mode, line[:100])
            return

        event_type = event.get("type")
        if event_type in ("snapshot", "status"):
            status = event.get("status")
            if isinstance(status, dict):
                self._on_status(self._mode, status)
        elif event_type == "keepalive":
            pass  # Connection alive, nothing to do
        else:
            logger.debug("Subscribe %s: unknown event type: %s", self._mode, event_type)
