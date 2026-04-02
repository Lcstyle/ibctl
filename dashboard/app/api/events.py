"""Server-Sent Events endpoint for real-time multi-instance updates.

Polls all ibctl instances every 2 seconds internally. Only pushes events
to the browser when state changes are detected. The browser uses these
to update the UI instantly without waiting for the HTMX poll interval.
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, Request
from sse_starlette.sse import EventSourceResponse

logger = logging.getLogger("dashboard.api.events")
router = APIRouter()


@router.get("/api/v1/events")
async def events(request: Request):
    """SSE stream — pushes state changes and periodic status for all instances."""

    async def event_generator():
        registry = request.app.state.instance_registry
        last_states: dict[str, str] = {}
        last_ready: dict[str, bool] = {}

        while True:
            if await request.is_disconnected():
                break

            try:
                instances = await registry.all_status()

                # Also cache STATE for each mode (used by state-history partial)
                for m in registry.modes():
                    await registry.cached_command(m, "STATE", registry.STATUS_TTL)

                for inst in instances:
                    mode = inst.mode
                    status = inst.status or {}
                    current_state = status.get("state", "unreachable")
                    current_ready = status.get("ready", False)
                    prev_state = last_states.get(mode)
                    prev_ready = last_ready.get(mode)

                    # State change — push immediately
                    if prev_state is not None and current_state != prev_state:
                        yield {
                            "event": "state_change",
                            "data": json.dumps({
                                "mode": mode,
                                "from": prev_state,
                                "to": current_state,
                                "ready": current_ready,
                            }),
                        }

                    # Ready change (connected/disconnected) — push
                    if prev_ready is not None and current_ready != prev_ready:
                        yield {
                            "event": "ready_change",
                            "data": json.dumps({
                                "mode": mode,
                                "ready": current_ready,
                                "state": current_state,
                            }),
                        }

                    last_states[mode] = current_state
                    last_ready[mode] = current_ready

                # Periodic heartbeat with full status (every poll)
                yield {
                    "event": "status",
                    "data": json.dumps([
                        {"mode": i.mode, "status": i.status, "error": i.error}
                        for i in instances
                    ]),
                }

            except Exception as e:
                logger.debug("SSE poll error: %s", e)
                yield {
                    "event": "error",
                    "data": json.dumps({"error": str(e)}),
                }

            await asyncio.sleep(2)

    return EventSourceResponse(event_generator())
