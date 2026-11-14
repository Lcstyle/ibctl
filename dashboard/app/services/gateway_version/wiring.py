"""Build the Gateway version service from the container's environment."""

from __future__ import annotations

import logging
import os

import httpx

from app.services.gateway_version.probe import run_probe
from app.services.gateway_version.releases import CHANNELS, ChannelRelease, fetch_release
from app.services.gateway_version.service import GatewayVersionService
from app.services.monitors.false_connected import _port_for_mode as gateway_api_port

logger = logging.getLogger("dashboard.services.gateway_version")


def build_gateway_version_service(registry) -> GatewayVersionService:
    """The running version and channel come from the image
    (``IB_GATEWAY_VERSION``, ``IB_GATEWAY_CHANNEL``); the probe connects to
    the Gateway's in-container API port for the chosen mode."""
    channel = (os.environ.get("IB_GATEWAY_CHANNEL") or "stable").strip()
    if channel not in CHANNELS:
        logger.error("IB_GATEWAY_CHANNEL=%r is not one of %s; tracking the stable channel", channel, CHANNELS)
        channel = "stable"

    async def fetch(chan: str) -> ChannelRelease:
        async with httpx.AsyncClient() as client:
            return await fetch_release(client, chan)

    async def probe(mode: str, client_id: int):
        return await run_probe(gateway_api_port(mode), client_id=client_id)

    return GatewayVersionService(
        registry,
        fetch_release=fetch,
        probe_mode=probe,
        running_version=(os.environ.get("IB_GATEWAY_VERSION") or "").strip() or None,
        channel=channel,
    )
