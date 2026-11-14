"""Ask a Gateway what IB says about its version.

IB sends error 2172 (the desupport notice) on every new API connection once a
cutoff is announced, in the same burst as the farm-status messages. So a probe
is a short, read-only connection: connect with no startup data requests, listen
for a few seconds, disconnect. Verified against a paper Gateway: 2172 arrived
within tens of milliseconds of connecting.

The probe runs in a subprocess (``python -m app.services.gateway_version.probe``)
with a hard timeout, so a hung connection can never stall the dashboard and the
dashboard process never imports ib_async or its event-loop machinery.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path

from app.services.effective_config import int_setting
from app.services.gateway_version.desupport import DESUPPORT_CODE, DesupportNotice, parse_2172

logger = logging.getLogger("dashboard.services.gateway_version.probe")

# A block of client IDs no other API client uses. Every probe starts at the
# first and moves up only when IB refuses one as in use (326); a cleanly
# closed ID is free again at once. The no-clients monitor only sees a
# count, so the check prefers a mode that already has clients (see service).
# The first ID is the dashboard.version_probe_client_id setting; these are its default.
PROBE_CLIENT_ID = 9172
PROBE_CLIENT_IDS = range(PROBE_CLIENT_ID, PROBE_CLIENT_ID + 8)


def probe_client_id() -> int:
    """dashboard.version_probe_client_id (env IBCTL_VERSION_PROBE_CLIENT_ID)."""
    return int_setting("dashboard.version_probe_client_id", PROBE_CLIENT_ID)


def probe_client_ids() -> range:
    """The block a check tries, from the configured first ID."""
    first = probe_client_id()
    return range(first, first + len(PROBE_CLIENT_IDS))

# IB's refusal of a client ID that is already connected.
CLIENT_ID_IN_USE = 326
CONNECT_TIMEOUT = 10.0
# How long to listen after connecting. 2172 arrives within milliseconds; this
# is margin, not a requirement.
SETTLE_SECONDS = 3.0
# The whole subprocess, interpreter start-up included.
HARD_TIMEOUT = 45.0
# Where `app` is importable from; the probe runs with this as its working
# directory rather than relying on wherever the dashboard was started.
DASHBOARD_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class ProbeResult:
    messages: list[tuple[int, str]] = field(default_factory=list)
    error: str | None = None

    @property
    def client_id_in_use(self) -> bool:
        return any(code == CLIENT_ID_IN_USE for code, _ in self.messages)


class ProbeConnectFailed(Exception):
    """Connecting failed; the message keeps what IB said before it did.

    A refused client ID arrives as error 326 during the handshake, after
    which ib_async waits out its timeout and raises a bare TimeoutError()
    that on its own explains nothing.
    """

    def __init__(self, message: str, messages: list[tuple[int, str]]):
        super().__init__(message)
        self.messages = messages


def _connect_failure(exc: BaseException, messages: list[tuple[int, str]], timeout: float) -> str:
    detail = str(exc) or f"no answer within {timeout:g}s"
    said = "; ".join(f"{code} {text}" for code, text in messages)
    reason = f"{type(exc).__name__}: {detail}"
    return f"{reason}; IB said: {said}" if said else reason


async def collect_messages(
    ib, host: str, port: int, client_id: int, *, connect_timeout: float, settle: float, fetch_fields
) -> list[tuple[int, str]]:
    """Connect read-only, collect every (code, text) IB sends, disconnect.

    Raises ProbeConnectFailed if the connection cannot be made.
    """
    messages: list[tuple[int, str]] = []

    def on_error(_req_id, code, text, _contract):
        messages.append((int(code), str(text)))

    ib.errorEvent += on_error
    try:
        try:
            await ib.connectAsync(
                host, port, clientId=client_id, timeout=connect_timeout, readonly=True, fetchFields=fetch_fields
            )
        except Exception as exc:
            raise ProbeConnectFailed(_connect_failure(exc, messages, connect_timeout), list(messages)) from exc
        await asyncio.sleep(settle)
    finally:
        ib.disconnect()
    return messages


def notice_from(messages: list[tuple[int, str]]) -> DesupportNotice | None:
    """The desupport notice among the messages, if IB sent one.

    Raises ValueError for a 2172 whose text no longer parses: IB rewording
    its notice must be loud, not read as "no notice".
    """
    for code, text in messages:
        if code == DESUPPORT_CODE:
            return parse_2172(text)
    return None


def probe_argv(port: int, host: str = "127.0.0.1", client_id: int | None = None) -> list[str]:
    if client_id is None:
        client_id = probe_client_id()
    return [
        sys.executable, "-m", "app.services.gateway_version.probe",
        "--host", host, "--port", str(port), "--client-id", str(client_id),
    ]


def _messages(out: dict) -> list[tuple[int, str]]:
    return [(int(m["code"]), str(m["text"])) for m in out.get("messages", [])]


async def run_probe(
    port: int, *, client_id: int | None = None, argv: list[str] | None = None, timeout: float = HARD_TIMEOUT
) -> ProbeResult:
    """Run the probe subprocess against ``port`` as ``client_id``; never raises."""
    argv = argv or probe_argv(port, client_id=client_id)
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=DASHBOARD_ROOT, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
    except OSError as exc:
        return ProbeResult(error=f"cannot start the probe: {exc}")
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return ProbeResult(error=f"the probe did not finish within {timeout:g}s")

    lines = stdout.decode(errors="replace").strip().splitlines()
    try:
        out = json.loads(lines[-1])
    except (IndexError, ValueError):
        tail = (stderr.decode(errors="replace").strip() or stdout.decode(errors="replace").strip())[-300:]
        return ProbeResult(error=f"unreadable probe output (exit {proc.returncode}): {tail}")
    if not out.get("ok"):
        error = str(out.get("error") or f"probe failed (exit {proc.returncode})")
        return ProbeResult(messages=_messages(out), error=error)
    return ProbeResult(messages=_messages(out))


async def _main(host: str, port: int, client_id: int) -> int:
    from ib_async import IB, StartupFetchNONE

    logging.getLogger("ib_async").setLevel(logging.CRITICAL)
    try:
        messages = await collect_messages(
            IB(), host, port, client_id,
            connect_timeout=CONNECT_TIMEOUT, settle=SETTLE_SECONDS, fetch_fields=StartupFetchNONE,
        )
    except ProbeConnectFailed as exc:
        said = [{"code": c, "text": t} for c, t in exc.messages]
        print(json.dumps({"ok": False, "error": str(exc), "messages": said}))
        return 1
    except Exception as exc:  # the parent turns this into a recorded probe error
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}))
        return 1
    print(json.dumps({"ok": True, "messages": [{"code": c, "text": t} for c, t in messages]}))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read-only Gateway version probe")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--client-id", type=int, default=None)
    args = parser.parse_args()
    sys.exit(asyncio.run(_main(args.host, args.port, probe_client_id() if args.client_id is None else args.client_id)))
