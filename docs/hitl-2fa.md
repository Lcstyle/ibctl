# HITL 2FA Backoff

When IB Gateway requires 2FA (IB Key push notification) and nobody answers,
ibctl used to give up on each push after 120 s, restart the JVM and send
another — often while the previous push was still open. If you're asleep,
that is a stream of IB Key prompts before you wake up. The HITL (human-in-the-loop) backoff feature caps
the number of immediate attempts, then enters a cooperative waiting state
(`WaitingForHitl2fa`) where ibctl either retries on a schedule, waits for you
to tap a button on your phone, or both.

---

## How It Works

### A 2FA round ends when the Gateway ends it

No timer ends a round. While the Gateway shows its IB Key prompt, the push
is outstanding and kept — the Gateway can keep a prompt open for well over
15 minutes, and pushes can be approved minutes after they were sent. IBC
works the same way: it acts only when the prompt closes.

- **Prompt open past `twofa.exit_interval`** (120 s in the Docker config): ibctl logs a
  WARN and the dashboard sends "IB Key push waiting" once. Nothing else.
- **Prompt open past 30 min** (the stuck ceiling): ibctl logs an ERROR and
  clicks the prompt's Cancel in the running Gateway. If the prompt is still
  open 30 s later, it relaunches the JVM (ERROR, reason
  `prompt_ignored_cancel`). What the Gateway does on that Cancel is not yet
  verified in production.
- **Prompt closed, "API Server: connected"**: approved.
- **Prompt closed, login form back** (or no result within 180 s, or no
  challenge within `exit_interval` of the device picker closing): a **failed
  round**. It counts against `max_immediate_attempts`; while budget remains
  the login is re-submitted in the running Gateway (no JVM restart).

**Unattended hours** (`unattended_hours`, `22:00-08:00` in the Docker config): a round
that fails inside them parks in `WaitingForHitl2fa` after the first push,
keeping the Gateway running. It **stays parked** until your Retry or the
Sunday re-auth — no automatic retry fires inside the window, and none fires
because 08:00 came. STATUS `hitl.parked_reason` says `unattended_hours`.

**After any prompt closes** — expired, refused, approved, or cancelled by
ibctl — ibctl reads what the Gateway shows before doing anything: "API
Server: connected" is a completed login (never re-submitted over), the login
form back is a failed round, and neither is waited on up to 180 s, then the
in-JVM retry looks for a form for 60 s, then the JVM is relaunched.

**A form back makes a retry possible, not wanted.** A failed round goes
through the attempt budget and unattended hours first. A retry the backoff
policy scheduled is checked again when its push would actually go: armed at
21:59 under an open prompt that the Gateway closes at 22:05, it parks
instead. Your Retry, the Sunday re-auth, and a form returning outside a 2FA
round (a revoke or RE-LOGIN, i.e. a new login's first push) are not held.

Every JVM relaunch is recorded in STATUS `last_relaunch` with its reason;
the dashboard's "Gateway relaunched during login" alert repeats it. A
relaunch from a login state under an open prompt with no reason is the
abandoned-prompt tripwire (`abandoned_prompt: true`, ERROR `TRIPWIRE abandoned_prompt`).

### Parked: `WaitingForHitl2fa`

After `max_immediate_attempts` failed 2FA rounds in a row (or the first one
in unattended hours), ibctl enters `WaitingForHitl2fa`. While in that state it can:

- **Auto-retry on a schedule** (`strategy = "periodic"`) — wake up after
  each interval in `intervals_minutes` and retry the login.
- **Send an ntfy alert with a "Retry login" action button** (`strategy =
  "ntfy_callback"`) — a single push notification goes to your ntfy topic.
  Tapping the button from your phone sends `HITL_RESUME` to ibctl via a
  signed callback URL.
- **Both** (`strategy = "both"`) — scheduled retries keep the session alive
  unattended, and the ntfy button lets you force an immediate retry when you
  see the alert.

Every retry — the timer, the button, and a Sunday cold restart that finds
the mode parked here — re-submits the login **in the running Gateway**; the
JVM is not restarted. This is what IBC does with
`ReloginAfterSecondFactorAuthenticationTimeout=yes`. Two cases differ:

- **The Gateway still shows its IB Key dialog.** That push may still be
  approvable, so the timer and the Sunday fire never re-submit under it:
  they wait until the Gateway closes the dialog (it does so itself when IBKR
  expires the push — anywhere from a few minutes to over 15 minutes after opening), then re-submit 5 s
  later. **Your Retry is different**: it **replaces the current
  push** — ibctl clicks the dialog's Cancel, then re-submits the login for a
  new one, with the same 30 s fallback to a relaunch if the dialog stays. STATUS shows this as `hitl.challenge_open`,
  `hitl.relogin_armed` and `hitl.cancel_requested`.
- **The JVM has exited**, or the Gateway offers no login form within 60 s
  and is not connected. Then, and only then, ibctl relaunches the JVM, and
  logs an ERROR saying why.

A retry does not reset the 2FA attempt counter, so if its round fails the
mode parks here again with a fresh alert — it does not restart the JVM.

When ibctl successfully reaches `Connected`, the consecutive timeout counter
resets (subject to `counter_reset`), and normal operation resumes.

---

## Configuration — `[twofa.backoff]`

All knobs live in the `[twofa.backoff]` section of `ibctl.toml`. Every field
can also be set via environment variable (listed in the table).

| Field | Default | Env var | Description |
|-------|---------|---------|-------------|
| `max_immediate_attempts` | `3` | `IBCTL_TWOFA_MAX_IMMEDIATE_ATTEMPTS` | How many failed 2FA rounds in a row to allow before entering HITL. `0` disables HITL entirely (legacy loop-forever behavior). |
| `on_timeout` | `"restart_then_hitl"` | `IBCTL_TWOFA_ON_TIMEOUT` | What a failed 2FA round leads to. See values below. |
| `unattended_hours` | `""` (Docker config: `"22:00-08:00"`) | `IBCTL_TWOFA_UNATTENDED_HOURS` | `"HH:MM-HH:MM"` in the container's `TZ`, may wrap midnight; `""` or `"off"` = none. A round failing inside the window parks after one push and stays parked until your Retry or the Sunday re-auth; no HITL auto-retry fires inside it. Outranks `on_timeout`. |
| `strategy` | `"periodic"` | `IBCTL_TWOFA_STRATEGY` | How ibctl exits HITL. See values below. |
| `intervals_minutes` | `[60]` | `IBCTL_TWOFA_INTERVALS_MINUTES` | Retry schedule in minutes. A single value gives a fixed interval. A list is traversed in order; the last value is held indefinitely. Used when `strategy` is `"periodic"` or `"both"`. |
| `callback_valid_hours` | `12` | `IBCTL_TWOFA_CALLBACK_VALID_HOURS` | Hours the signed ntfy action-button URL remains valid. One-shot — the URL is invalidated after first use. Range: 1–168. |
| `counter_reset` | `"any_reach"` | `IBCTL_TWOFA_COUNTER_RESET` | When to reset the consecutive-timeout counter after a successful `Connected`. `"any_reach"` resets immediately; `"stable"` requires `Connected` to hold for `stable_secs` first. |
| `stable_secs` | `300` | `IBCTL_TWOFA_STABLE_SECS` | Seconds `Connected` must persist before the counter resets when `counter_reset = "stable"`. Ignored for `"any_reach"`. |
| `cold_restart_preempts_hitl` | `true` | `IBCTL_TWOFA_COLD_RESTART_PREEMPTS_HITL` | If a scheduled cold restart fires while ibctl is in HITL, `true` retries the login in the running Gateway (no JVM restart — the restart already happened; the login is what's outstanding). `false` leaves it to the operator's Retry login. Either way the week's re-authentication stays owed until a login completes. |
| `ntfy_send_retries` | `1` | `IBCTL_TWOFA_NTFY_SEND_RETRIES` | If the initial ntfy push fails (network blip, ntfy server down), how many additional attempts to make on subsequent scheduled wakeups. `0` gives up after the first failure. Only meaningful when `strategy` includes `ntfy_callback`. |

### `on_timeout` values

The names date from when a timer ended rounds and relaunched the JVM.
Retries now re-submit the login in the running Gateway.

| Value | Behavior |
|-------|----------|
| `"restart_then_hitl"` | Retry the login after a failed round. After `max_immediate_attempts` failed rounds, enter HITL. **Default.** |
| `"restart_forever"` | Retry without limit and never enter HITL (except in `unattended_hours`). |
| `"hitl_immediately"` | Enter HITL on the very first failed round. `max_immediate_attempts` is ignored. Requires `strategy != "disabled"`. |

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
via your container's `environment:` block (a secrets manager or direct Compose).

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
| `consecutive_2fa_timeouts` | How many failed 2FA rounds preceded HITL entry. |
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
