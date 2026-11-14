"""ZMQ PUB socket for pushing ibctl status events to external subscribers.

Binds a ZMQ PUB socket that external clients can subscribe to for
real-time status updates. Topic-prefixed messages allow subscribers
to filter by instance mode (live/paper).

Includes a heartbeat that re-publishes cached status every 5 seconds
to handle the ZMQ "late joiner" problem — new subscribers always receive
current state within seconds, even if no state change has occurred.

Message format: "status.{mode} {json}"
Example: "status.live {"ready":true,"state":"Connected",...}"
"""

from __future__ import annotations

import asyncio
import json
import logging

logger = logging.getLogger("dashboard.services.zmq_publisher")

HEARTBEAT_INTERVAL = 5.0  # seconds between heartbeat re-publishes


class ZmqStatusPublisher:
    """Publishes ibctl status events via ZMQ PUB for external subscribers."""

    def __init__(self, bind_address: str = "tcp://*:5556"):
        self._bind_address = bind_address
        self._pub = None
        self._ctx = None
        self._registry = None
        self._heartbeat_task: asyncio.Task | None = None
        self._stop = False

    def start(self, registry=None):
        import zmq

        self._ctx = zmq.Context()
        self._pub = self._ctx.socket(zmq.PUB)
        self._pub.setsockopt(zmq.SNDHWM, 1000)  # High-water mark
        self._pub.setsockopt(zmq.LINGER, 0)  # Don't block on close
        self._pub.bind(self._bind_address)
        self._registry = registry
        logger.info("ZMQ PUB socket bound on %s", self._bind_address)

    async def start_heartbeat(self):
        """Start periodic re-publish of cached status for late joiners."""
        self._stop = False
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(), name="zmq-heartbeat",
        )

    def publish(self, mode: str, status: dict):
        """Publish a status update. Subscribers filter by topic 'status.{mode}'."""
        if self._pub is None:
            return
        topic = f"status.{mode}"
        payload = json.dumps(status, separators=(",", ":"))
        try:
            self._pub.send_string(f"{topic} {payload}", flags=1)  # NOBLOCK
        except Exception:
            pass  # ZMQ send failures are non-fatal (no subscribers, HWM reached)

    async def _heartbeat_loop(self):
        """Re-publish cached status every HEARTBEAT_INTERVAL seconds.

        Solves the ZMQ late-joiner problem: new subscribers always receive
        current state within a few seconds, even if no state change has
        occurred since they connected.
        """
        while not self._stop:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            if self._registry is None:
                continue
            for inst in self._registry.cached_all_status():
                if inst.status is not None:
                    self.publish(inst.mode, inst.status)

    def close(self):
        self._stop = True
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None
        if self._pub:
            self._pub.close()
            self._pub = None
        if self._ctx:
            self._ctx.term()
            self._ctx = None
        logger.info("ZMQ PUB socket closed")
