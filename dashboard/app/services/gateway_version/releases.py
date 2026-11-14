"""IB's own record of the current build on each channel.

IB publishes one small JSONP file per channel. It names only the current
build, so it says what to move to, not when a version stops being supported
(that comes from error 2172).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date, datetime

import httpx

from app.services.gateway_version.versions import GatewayVersion

CHANNELS = ("stable", "latest")

# One weekly request; a slow or silent server gets this long, no retries.
# A failed fetch is recorded and the next weekly check tries again.
FETCH_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


def version_file_url(channel: str) -> str:
    return f"https://download2.interactivebrokers.com/installers/ibgateway/{channel}-standalone/version.json"


@dataclass(frozen=True)
class ChannelRelease:
    channel: str
    version: GatewayVersion
    released_on: date


def parse_version_file(channel: str, body: str) -> ChannelRelease:
    match = re.search(r"\{.*\}", body, re.DOTALL)
    if not match:
        raise ValueError(f"{channel} version file has no JSON object: {body[:80]!r}")
    try:
        data = json.loads(match.group(0))
        version = GatewayVersion.parse(str(data["buildVersion"]))
        released_on = datetime.strptime(str(data["buildDateTime"])[:8], "%Y%m%d").date()
    except (KeyError, ValueError) as exc:
        raise ValueError(f"{channel} version file does not parse: {exc}") from exc
    return ChannelRelease(channel=channel, version=version, released_on=released_on)


async def fetch_release(client: httpx.AsyncClient, channel: str) -> ChannelRelease:
    if channel not in CHANNELS:
        raise ValueError(f"unknown channel {channel!r}; expected one of {CHANNELS}")
    response = await client.get(version_file_url(channel), timeout=FETCH_TIMEOUT)
    response.raise_for_status()
    return parse_version_file(channel, response.text)
