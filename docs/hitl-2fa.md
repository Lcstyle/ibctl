# HITL 2FA Backoff

When IB Gateway requires 2FA (IB Key push notification) and the backend is
flapping overnight, ibctl would ordinarily restart the JVM and re-attempt 2FA
every ~2 minutes — indefinitely. If you're asleep, this generates dozens of
IB Key prompts before you wake up, and can result in a locked account or a
confused IBKR session state. The HITL (human-in-the-loop) backoff feature caps
the number of immediate attempts, then enters a cooperative waiting state
(`WaitingForHitl2fa`) where ibctl either retries on a schedule, waits for you
to tap a button on your phone, or both. Design rationale and failure analysis
are in [docs/investigation-log-2026-04-connected-state.md](investigation-log-2026-04-connected-state.md).

---

## How It Works

After `max_immediate_attempts` consecutive 2FA timeouts, ibctl stops the
tight restart loop and enters `WaitingForHitl2fa`. While in that state it can:

- **Auto-retry on a schedule** (`strategy = "periodic"`) — wake up after
  each interval in `intervals_minutes`, restart the JVM, and try 2FA again.
- **Send an ntfy alert with a "Retry Now" action button** (`strategy =
  "ntfy_callback"`) — a single push notification goes to your ntfy topic.
  Tapping the button from your phone sends `HITL_RESUME` to ibctl via a
  signed callback URL.
- **Both** (`strategy = "both"`) — scheduled retries keep the session alive
  unattended, and the ntfy button lets you force an immediate retry when you
  see the alert.

When ibctl successfully reaches `Connected`, the consecutive timeout counter
resets (subject to `counter_reset`), and normal operation resumes.

---

## Configuration — `[twofa.backoff]`

All knobs live in the `[twofa.backoff]` section of `ibctl.toml`. Every field
can also be set via environment variable (listed in the table).

| Field | Default | Env var | Description |
|-------|---------|---------|-------------|
| `max_immediate_attempts` | `3` | `IBCTL_TWOFA_MAX_IMMEDIATE_ATTEMPTS` | How many consecutive 2FA timeouts to allow before entering HITL. `0` disables HITL entirely (legacy loop-forever behavior). |
| `on_timeout` | `"restart_then_hitl"` | `IBCTL_TWOFA_ON_TIMEOUT` | What happens when a 2FA push times out. See values below. |
| `strategy` | `"periodic"` | `IBCTL_TWOFA_STRATEGY` | How ibctl exits HITL. See values below. |
| `intervals_minutes` | `[60]` | `IBCTL_TWOFA_INTERVALS_MINUTES` | Retry schedule in minutes. A single value gives a fixed interval. A list is traversed in order; the last value is held indefinitely. Used when `strategy` is `"periodic"` or `"both"`. |
| `callback_valid_hours` | `12` | `IBCTL_TWOFA_CALLBACK_VALID_HOURS` | Hours the signed ntfy action-button URL remains valid. One-shot — the URL is invalidated after first use. Range: 1–168. |
| `counter_reset` | `"any_reach"` | `IBCTL_TWOFA_COUNTER_RESET` | When to reset the consecutive-timeout counter after a successful `Connected`. `"any_reach"` resets immediately; `"stable"` requires `Connected` to hold for `stable_secs` first. |
| `stable_secs` | `300` | `IBCTL_TWOFA_STABLE_SECS` | Seconds `Connected` must persist before the counter resets when `counter_reset = "stable"`. Ignored for `"any_reach"`. |
| `cold_restart_preempts_hitl` | `true` | `IBCTL_TWOFA_COLD_RESTART_PREEMPTS_HITL` | If a scheduled cold restart fires while ibctl is in HITL, `true` lets it proceed (exits HITL, runs restart, re-enters login). `false` defers the cold restart until HITL exits normally. |
| `ntfy_send_retries` | `1` | `IBCTL_TWOFA_NTFY_SEND_RETRIES` | If the initial ntfy push fails (network blip, ntfy server down), how many additional attempts to make on subsequent scheduled wakeups. `0` gives up after the first failure. Only meaningful when `strategy` includes `ntfy_callback`. |

### `on_timeout` values

| Value | Behavior |
|-------|----------|
| `"restart_then_hitl"` | Kill the JVM, relaunch it, and count the attempt. After `max_immediate_attempts` exhausted attempts, enter HITL. **Default.** |
| `"restart_forever"` | Legacy pre-HITL behavior — restart without limit and never enter HITL. Effectively disables the feature regardless of other settings. |
| `"hitl_immediately"` | Enter HITL on the very first 2FA timeout, with no prior restart attempts. `max_immediate_attempts` is ignored. Requires `strategy != "disabled"`. |

### `strategy` values

| Value | Behavior |
|-------|----------|
| `"periodic"` | Auto-retry on the schedule in `intervals_minutes`. No ntfy alert sent. **Default.** |
| `"ntfy_callback"` | Send one ntfy push with a "Retry Now" action button. No automatic timer. Requires ntfy configured and `IBCTL_NTFY_ACTION_SIGNING_KEY` set. |
| `"both"` | Scheduled retries + ntfy alert. Retries keep the session alive unattended; the ntfy button forces an immediate attempt. |
| `"disabled"` | Enter HITL and stay there. No automatic recovery. Operator must send `HITL_RESUME` manually via the dashboard command interface. |

---

## TCP Probe — `[timing]`

ibctl probes Gateway's API port over TCP during post-authentication states.
This is independent of Swing UI label inspection: even if the Gateway UI still
shows a "Connected" label, a failed TCP probe reveals that the API port has
gone silent — which typically means Gateway silently reverted to the login
screen after a backend blip.

| Field | Default | Env var | Description |
|-------|---------|---------|-------------|
| `api_port_probe_interval_secs` | `5` | `IBCTL_API_PORT_PROBE_INTERVAL_SECS` | Seconds between TCP connection attempts to the Gateway API port. `0` disables the probe entirely. If disabled, only Swing label inspection and dashboard-side monitors detect session loss. |
| `api_port_probe_fails_before_revoke` | `3` | `IBCTL_API_PORT_PROBE_FAILS_BEFORE_REVOKE` | Consecutive TCP failures required before firing a revocation event. Absorbs transient OS-level blips (range 1–10). At the default values of 5s interval and 3 failures, session loss is detected within ~15 seconds. |

```toml
[timing]
api_port_probe_interval_secs = 5
api_port_probe_fails_before_revoke = 3
```

---

## `[ib_status]`

| Field | Default | Env var | Description |
|-------|---------|---------|-------------|
| `kick_active_session` | `false` | — | When the dashboard's IB system-status scraper pushes `IBSTATUS=unavailable`, should ibctl interrupt an already-authenticated `Connected` session? **Default: false.** |

The default is safe and recommended. `IBSTATUS` was designed as a
login-retry gate — if IBKR backends are unreachable, don't hammer them.
It was never meant to kill live sessions. The scraper can be wrong (CDN
blips, stale page caches), and Gateway's own UI label is the authoritative
"my session is healthy" signal, detected via the revocation bus.

Set `kick_active_session = true` only if you want to restore the historical
behavior where any `unavailable` push immediately transitions
`Connected → WaitingForIB`.

```toml
[ib_status]
kick_active_session = false
```

---

## Dashboard Integration — Required Env Vars

These env vars are secrets and must never appear in `ibctl.toml`. Set them
via your container's `environment:` block (varlock or direct Compose).

### `IBCTL_NTFY_ACTION_SIGNING_KEY`

Required when `strategy` is `"ntfy_callback"` or `"both"`. This is the
HMAC-SHA256 key used to sign callback URLs embedded in ntfy action buttons.
The dashboard validates the signature before dispatching `HITL_RESUME` to
ibctl, so a valid key is necessary for the button to work.

Generate a key:

```sh
openssl rand -hex 32
```

Set in Compose:

```yaml
environment:
  IBCTL_NTFY_ACTION_SIGNING_KEY: "your-generated-hex-key"
```

Preflight warns (but does not fail) at startup if this variable is missing
when the strategy requires it. The warning is promoted to a runtime failure
when the first ntfy push fires.

### `IBCTL_DASHBOARD_EXTERNAL_URL`

The publicly-reachable URL of the ibctl dashboard — the base URL used to
build ntfy action-button callback targets. Required when `strategy` includes
`ntfy_callback` and the dashboard sits behind a reverse proxy or is accessed
from outside the LAN (e.g. from your phone).

```yaml
environment:
  IBCTL_DASHBOARD_EXTERNAL_URL: "https://ibctl.your-domain.com"
```

If neither this env var nor `dashboard.external_url` in `ibctl.toml` is set,
callback URLs fall back to `http://localhost:<port>` — which is unreachable
from a phone. Preflight warns when this is missing with an ntfy strategy.

---

## Recommended Presets

### Overnight asleep

Most operators want this. You're not watching ibctl from midnight to 7am.
Retries happen every hour automatically, and a single ntfy alert lets you
force an immediate retry from bed if you see it.

```toml
[twofa.backoff]
max_immediate_attempts = 3
on_timeout = "restart_then_hitl"
strategy = "both"
intervals_minutes = [60]
callback_valid_hours = 12
counter_reset = "any_reach"
ntfy_send_retries = 1
```

Requires: `dashboard.notifications_enabled = true`, `dashboard.notification_channel = "ntfy"`,
`IBCTL_NTFY_ACTION_SIGNING_KEY` set, `IBCTL_DASHBOARD_EXTERNAL_URL` set.

### Always-on operator

You're watching the dashboard during market hours and will respond to ntfy
alerts promptly. No automatic timer — ibctl waits for you.

```toml
[twofa.backoff]
max_immediate_attempts = 3
on_timeout = "restart_then_hitl"
strategy = "ntfy_callback"
callback_valid_hours = 4
counter_reset = "any_reach"
ntfy_send_retries = 2
```

### Lights-out / never wake me

No ntfy, no phone alerts. ibctl retries on an exponential backoff schedule
and recovers by itself if the IBKR backend comes back.

```toml
[twofa.backoff]
max_immediate_attempts = 3
on_timeout = "restart_then_hitl"
strategy = "periodic"
intervals_minutes = [30, 60, 120, 240]
counter_reset = "any_reach"
```

`intervals_minutes` is traversed left-to-right; after the 240-minute entry is
reached, ibctl retries every 4 hours until `Connected` or manual intervention.

---

## Observing HITL State — STATUS JSON

When ibctl is in `WaitingForHitl2fa`, the `STATUS` command response includes
a `hitl` block:

```json
{
  "state": "WaitingForHitl2fa",
  "hitl": {
    "active": true,
    "entered_at_secs_ago": 432,
    "consecutive_2fa_timeouts": 3,
    "next_retry_in_secs": 3168,
    "intervals_index": 0,
    "ntfy_sent": true,
    "ntfy_attempts": 1
  }
}
```

| Field | Description |
|-------|-------------|
| `active` | Always `true` in this state. `null` when not in HITL. |
| `entered_at_secs_ago` | Seconds since ibctl entered `WaitingForHitl2fa`. |
| `consecutive_2fa_timeouts` | How many 2FA timeouts triggered HITL entry. |
| `next_retry_in_secs` | Seconds until the next scheduled auto-retry fires. `null` if strategy has no timer. |
| `intervals_index` | Which entry in `intervals_minutes` ibctl is currently using. |
| `ntfy_sent` | Whether the ntfy push succeeded for this HITL entry. |
| `ntfy_attempts` | Total ntfy send attempts for this HITL entry (including retries). |

---

## Manual Recovery

If you don't have ntfy configured, or the action-button URL expired or never
reached your phone, send `HITL_RESUME` manually from the dashboard's
state-machine command dialog.

`HITL_RESUME` is a privileged command — it is only accepted from localhost.
The dashboard, when running inside the same container or on the same host,
satisfies this requirement. Remote `nc`/`telnet` connections from other hosts
will be rejected.

From inside the container:

```sh
echo "HITL_RESUME" | nc 127.0.0.1 7462
```

Or use the dashboard's built-in command panel, which routes through localhost
automatically.

---

## What Not to Configure

**`strategy = "disabled"` with `on_timeout = "restart_then_hitl"`**

This is a dead-end: ibctl enters `WaitingForHitl2fa` and stays there
indefinitely with no automatic escape. It is valid if you always have an
operator present, but easy to set by accident. Preflight emits a warning.
If this is not intentional, set `strategy` to `"periodic"`, `"ntfy_callback"`,
or `"both"`.

**Very high `max_immediate_attempts`**

Setting this to 10 or 20 defeats the purpose. The whole point is to stop
the prompt storm early. Three attempts is enough to confirm a real failure
rather than a one-off blip.

**`intervals_minutes = [1]` with `ntfy_send_retries = 5`**

Retrying every minute with 5 ntfy-push retries can generate several
notifications per wakeup if your ntfy server is slow or rate-limiting. Use
intervals of at least 15 minutes in production, and keep `ntfy_send_retries`
at 1–2.
