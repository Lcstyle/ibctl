# ibctl Client Integration Guide

## Overview

ibctl exposes a TCP command server (default port 7462) that API clients can query
to make intelligent connection decisions. Instead of blindly attempting to connect
to IB Gateway and interpreting cryptic timeout errors, clients can ask ibctl for
a structured readiness advisory.

## Protocol

The command server uses a simple line-based protocol:

1. Open a TCP connection to the command server (default `127.0.0.1:7462`)
2. Send a command followed by `\n`
3. Read the response line: `OK {json}\n` or `ERROR message\n`
4. Close the connection

Each command is a single TCP connection (no keep-alive).

## STATUS Command

The primary integration endpoint. Returns a JSON object with Gateway state,
JVM process info, socat forwarding status, and a **client advisory** that tells
your application exactly what to do.

### Request

```
STATUS\n
```

### Response

```json
{
  "ready": true,
  "state": "Connected",
  "trading_mode": "paper",
  "uptime_secs": 3600,
  "connected_uptime_secs": 3500,
  "jvm": {
    "pid": 348,
    "alive": true,
    "uptime_secs": 3600,
    "config_dir": "/home/ibgateway/Jts_live",
    "agent_socket": "/run/ibctl/agent-live.sock"
  },
  "socat": {
    "running": true,
    "pid": 349
  },
  "stats": {
    "restarts_today": 0,
    "relogins_today": 0,
    "dialogs_dismissed": 3
  },
  "client_advisory": {
    "should_connect": true,
    "should_wait": false,
    "wait_reason": null,
    "client_id_likely_stale": false
  }
}
```

## Client Advisory

The `client_advisory` object is the key integration point. It tells your
application what action to take:

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `should_connect` | bool | `true` when Gateway is fully ready for API connections |
| `should_wait` | bool | `true` when Gateway is starting up — poll and wait |
| `wait_reason` | string? | Why the client should wait (see table below) |
| `client_id_likely_stale` | bool | `true` after a Gateway restart — rotate client IDs |

### Wait Reasons

| `wait_reason` | Meaning | Recommended Poll Interval |
|---------------|---------|--------------------------|
| `"launching"` | JVM is starting up | 5s |
| `"logging_in"` | Filling in credentials | 5s |
| `"2fa_pending"` | Waiting for 2FA approval (IB Key / TOTP) | 10s |
| `"session_conflict"` | Resolving an existing session conflict | 5s |
| `"configuring"` | Applying API configuration (almost ready) | 2s |
| `"restarting"` | Cold restart or error recovery in progress | 5s |

### Decision Table

| `should_connect` | `should_wait` | `wait_reason` | Action |
|---|---|---|---|
| `true` | `false` | `null` | **Connect now** — Gateway is ready |
| `false` | `true` | `"launching"` | Poll every 5s, do not attempt connection |
| `false` | `true` | `"2fa_pending"` | Poll every 10s — user action may be required |
| `false` | `true` | `"configuring"` | Poll every 2s — connection imminent |
| `false` | `true` | `"restarting"` | Poll every 5s, expect stale client IDs |
| `false` | `false` | `null` | Gateway shutdown or error — stop retrying |

### Client ID Staleness

When `client_id_likely_stale` is `true`, the Gateway has restarted since the
last Connected state. IB Gateway tracks connected client IDs across sessions,
so client IDs from before the restart may fail with Error 326 (Client ID in
use). Applications should rotate to a fresh client ID.

## Integration Pattern

### Python (asyncio)

```python
import asyncio
import json

async def get_gateway_advisory(host="127.0.0.1", port=7462, timeout=3.0):
    """Query ibctl for Gateway readiness advisory."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(b"STATUS\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.readline(), timeout=timeout)
        writer.close()

        line = response.decode().strip()
        if line.startswith("OK "):
            data = json.loads(line[3:])
            return data.get("client_advisory", {})
    except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
        return None  # ibctl unreachable — use fallback logic
    return None

async def connect_with_advisory(host, port):
    """Example: poll ibctl before connecting to Gateway."""
    while True:
        advisory = await get_gateway_advisory(host)

        if advisory is None:
            # ibctl not running — fall back to direct connection attempt
            break

        if advisory.get("should_connect"):
            break  # Ready — proceed with connection

        if advisory.get("should_wait"):
            reason = advisory.get("wait_reason", "unknown")
            interval = {"configuring": 2, "2fa_pending": 10}.get(reason, 5)
            print(f"Gateway not ready ({reason}) — polling in {interval}s")
            await asyncio.sleep(interval)
            continue

        # Not waiting, not connecting — shutdown/error state
        print(f"Gateway unavailable — stopping")
        return

    # Now safe to connect to IB Gateway API port
    # ...
```

### Rust

```rust
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

fn get_gateway_advisory(host: &str, port: u16) -> Option<serde_json::Value> {
    let mut stream = TcpStream::connect((host, port)).ok()?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(3))).ok()?;
    write!(stream, "STATUS\n").ok()?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;

    if line.starts_with("OK ") {
        serde_json::from_str(&line[3..]).ok()
    } else {
        None
    }
}
```

## Other Available Commands

| Command | Response | Description |
|---------|----------|-------------|
| `STATUS` | JSON | Full status with client advisory |
| `STATE` | JSON | State machine state + transition history |
| `CONFIG` | JSON | Running configuration (passwords masked) |
| `WINDOWS` | JSON | Visible Gateway windows and tabs |
| `STOP` | `OK` | Graceful shutdown |
| `RESTART` | `OK` | Restart Gateway JVM |
| `RECONNECTDATA` | `OK` | Reconnect market data (Ctrl+F) |
| `RECONNECTACCOUNT` | `OK` | Reconnect account (Ctrl+R) |
| `PAUSE` | `OK` | Freeze state machine (Direct Drive mode) |
| `RESUME` | `OK` | Resume automatic transitions |
| `SETSTATE <Name>` | `OK` | Force state (e.g., `SETSTATE Connected`) |

## Dual-Mode Deployments (TRADING_MODE=both)

When running in dual mode, the container runs **two ibctl instances**, each
with its own command server:

| Instance | API Port | Command Server Port | Default |
|----------|----------|--------------------|---------|
| Live | 4001 (via socat 4003) | **7462** | Yes |
| Paper | 4002 (via socat 4004) | **7463** | — |

**Clients must query the command server matching their trading mode:**

- Connecting to live API (port 4001/4003) → poll `STATUS` on port **7462**
- Connecting to paper API (port 4002/4004) → poll `STATUS` on port **7463**

Each command server is independent — querying live STATUS tells you nothing
about paper's readiness, and vice versa. Commands (RESTART, STOP, PAUSE) sent
to one instance do not affect the other.

### Single-Mode Deployments

When `TRADING_MODE=live` or `TRADING_MODE=paper`, there is only one ibctl
instance on port 7462. No special handling needed.

## Access Control

The command server respects the `control_from` configuration, which accepts
exact IP addresses, CIDR notation (e.g., `172.0.0.0/8`), and wildcards (`*`).
Connections from unauthorized IPs are rejected.

## Graceful Degradation

If ibctl is unreachable (container not started, command server disabled, network
issue), clients should fall back to their existing connection logic. The STATUS
endpoint is an optimization, not a dependency — applications must still handle
direct IB Gateway connection without it.
