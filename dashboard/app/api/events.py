"""Server-Sent Events endpoint for real-time updates."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict

from fastapi import APIRouter, Request
from sse_starlette.sse import EventSourceResponse

from app.domain.errors import DashboardError

logger = logging.getLogger("dashboard.api.events")
router = APIRouter()


@router.get("/api/v1/events")
async def events(request: Request):
    """SSE stream of status updates. Polls ibctl every 2 seconds."""

    async def event_generator():
        client = request.app.state.ibctl_client
        last_state = None

        while True:
            if await request.is_disconnected():
                break

            try:
                status = await client.status()
                current_state = status.state

                # Always send status update
                yield {
                    "event": "status",
                    "data": json.dumps(asdict(status)),
                }

                # Send state_change event if state changed
                if last_state is not None and current_state != last_state:
                    yield {
                        "event": "state_change",
                        "data": json.dumps({
                            "from": last_state,
                            "to": current_state,
                        }),
                    }

                last_state = current_state
            except DashboardError:
                yield {
                    "event": "error",
                    "data": json.dumps({"error": "ibctl unreachable"}),
                }

            await asyncio.sleep(2)

    return EventSourceResponse(event_generator())
