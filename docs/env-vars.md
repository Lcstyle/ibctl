# ibctl Environment Variable Reference

Most TOML settings have an environment variable override, listed below by
section; a setting not listed is set in `ibctl.toml` only. Env vars take
precedence over `ibctl.toml`. This doc is the catalog of env vars recognized
by ibctl and its dashboard.

**Sources of truth** (this doc is generated from these, so when in doubt
check them directly):

- `dashboard/app/preflight/models.py::ENV_MAP` — TOML-path → env-var mapping
- `ibctl/src/config.rs` — Rust config struct with env overrides
- `config/pkl/types.pkl` — Pkl schema (`@env` annotations)
- `ibctl.toml.example` — annotated example config

Secrets (passwords, signing keys, OAuth client secrets) are **env-only**
and never appear in `ibctl.toml`.

---

## Credentials & secrets (env-only)

| Variable | Purpose |
|---|---|
| `TWS_PASSWORD` | IB live account password. `_FILE` variant reads from a file. |
| `TWS_PASSWORD_PAPER` | IB paper account password. `_FILE` variant supported. |
| `TWOFACTOR_CODE` | TOTP secret (base32). `_FILE` variant supported. |
| `IBCTL_NTFY_ACTION_SIGNING_KEY` | HMAC-SHA256 signing key for HITL ntfy action URLs. Generate with `openssl rand -hex 32`. Required when `twofa.backoff.strategy` is `ntfy_callback` or `both`. See [docs/hitl-2fa.md](hitl-2fa.md). |
| `IBCTL_DASHBOARD_TOKEN` | The dashboard login password. Used only by the login form; it is not an API token. With no password and no OAuth/OIDC login configured, the dashboard shows the anonymous health summary only. |
| `IBCTL_DASHBOARD_AUTH_SECRET` | Dashboard session cookie signing key. Defaults to the login password; set it separately so changing the password does not also change the key. |
| `VNC_SERVER_PASSWORD` | VNC server password. |
| `IBCTL_GITHUB_OAUTH_CLIENT_SECRET` | GitHub OAuth client secret (when `dashboard.github_oauth_enabled=true`). |
| `IBCTL_OIDC_CLIENT_SECRET` | OIDC client secret (when `dashboard.oidc_enabled=true`). |

All other env vars mirror TOML fields. Grouped by section below.

---

## `[auth]`

| Variable | TOML path | Default |
|---|---|---|
| `TWS_USERID` | `auth.tws_userid` | `""` |
| `TWS_USERID_PAPER` | `auth.paper.tws_userid` | `""` |
| `TRADING_MODE` | `auth.trading_mode` | `"paper"` (values: `live` / `paper` / `both`) |

## `[twofa]`

| Variable | TOML path | Default |
|---|---|---|
| `TOTP_PROVIDER` | `twofa.provider` | `"oathtool"` |
| `TWOFA_TIMEOUT_ACTION` | `twofa.timeout_action` | `"restart"` |
| `TWOFA_EXIT_INTERVAL` | `twofa.exit_interval` | `180` (seconds) |
| `TWOFA_DEVICE` | `twofa.device` | `""` |
| `RELOGIN_AFTER_TWOFA_TIMEOUT` | `twofa.relogin_after_timeout` | `false` |

## `[twofa.backoff]` — HITL 2FA policy

All knobs also have full operator docs in [docs/hitl-2fa.md](hitl-2fa.md).

| Variable | TOML path | Default |
|---|---|---|
| `IBCTL_TWOFA_MAX_IMMEDIATE_ATTEMPTS` | `twofa.backoff.max_immediate_attempts` | `3` |
| `IBCTL_TWOFA_ON_TIMEOUT` | `twofa.backoff.on_timeout` | `"restart_then_hitl"` |
| `IBCTL_TWOFA_STRATEGY` | `twofa.backoff.strategy` | `"periodic"` |
| `IBCTL_TWOFA_INTERVALS_MINUTES` | `twofa.backoff.intervals_minutes` | `[60]` (comma-separated in env) |
| `IBCTL_TWOFA_CALLBACK_VALID_HOURS` | `twofa.backoff.callback_valid_hours` | `12` |
| `IBCTL_TWOFA_COUNTER_RESET` | `twofa.backoff.counter_reset` | `"any_reach"` |
| `IBCTL_TWOFA_STABLE_SECS` | `twofa.backoff.stable_secs` | `300` |
| `IBCTL_TWOFA_COLD_RESTART_PREEMPTS_HITL` | `twofa.backoff.cold_restart_preempts_hitl` | `true` |
| `IBCTL_TWOFA_NTFY_SEND_RETRIES` | `twofa.backoff.ntfy_send_retries` | `1` (hard-capped at 5) |
| `IBCTL_TWOFA_UNATTENDED_HOURS` | `twofa.backoff.unattended_hours` | `""` (none; the Docker config ships `"22:00-08:00"`). `HH:MM-HH:MM` in the container's time zone (`TZ`), may wrap midnight: a 2FA round that fails in these hours parks for the operator's Retry instead of sending another push |

## `[gateway]`

| Variable | TOML path | Default |
|---|---|---|
| `TWS_PATH` | `gateway.tws_path` | `/home/ibgateway/Jts` |
| `TWS_SETTINGS_PATH` | `gateway.tws_settings_path` | (uses `tws_path`) |
| `TWS_MAJOR_VRSN` | `gateway.tws_major_vrsn` | auto-detected |
| `TIME_ZONE` | `gateway.time_zone` | `""` (ibctl leaves jts.ini alone). The Gateway's session time zone, an IANA name such as `America/New_York`. See [Gateway session time zone](#gateway-session-time-zone). |
| `TIME_ZONE_LIVE` | `gateway.time_zone_live` | `""` (uses `time_zone`). Overrides `time_zone` for live mode. |
| `TIME_ZONE_PAPER` | `gateway.time_zone_paper` | `""` (uses `time_zone`). Overrides `time_zone` for paper mode. |
| `JAVA_HEAP_SIZE` | `gateway.java_heap_size` | `768` (MB) |
| `GATEWAY_OR_TWS` | `gateway.gateway_or_tws` | `"gateway"` |

### Gateway session time zone

The Gateway's session time zone comes from the `[Logon] TimeZone` line of its
`jts.ini`, not from the container's `TZ`. `TZ` only sets the clock zone of the
container and the JVM.

- Leave `TIME_ZONE` empty and ibctl does not touch the line: an existing install
  keeps the zone it has now, and ibctl only reports it.
- Set `TIME_ZONE` (or `TIME_ZONE_LIVE` / `TIME_ZONE_PAPER` for one mode) and ibctl
  writes it into that mode's `jts.ini` before every Gateway launch, then checks
  it after login.
- The two-space time strings IB sends (such as `20240102  15:30:00`) are in the
  Gateway's session zone. An API client that parses them should use the same zone.
- `AUTO_RESTART_TIME` is written in the container's `TZ`; ibctl converts it to the
  Gateway's session zone at every login.

Values are an IANA name (`America/New_York`, `Etc/GMT+5`, `UTC`) or empty. Pkl
checks the shape, preflight also looks the name up in the tz database.

## `[session]`

| Variable | TOML path | Default |
|---|---|---|
| `IBCTL_SESSION_ACTION` | `session.action` | `"primary"` |
| `IBCTL_ACCEPT_INCOMING` | `session.accept_incoming` | `"accept"` |
| `TWS_COLD_RESTART` | `session.tws_cold_restart` | `""` (HH:MM, empty disables) |
| `TWS_COLD_RESTART_DAY` | `session.tws_cold_restart_day` | `0` (0=Sun … 6=Sat) |

## `[timing]`

| Variable | TOML path | Default |
|---|---|---|
| `IBCTL_LOGIN_TIMEOUT` | `timing.login_dialog_timeout_secs` | `120` |
| `IBCTL_RESTART_DELAY` | `timing.restart_delay_secs` | `90` |
| `IBCTL_RELOGIN_ATTEMPTS` | `timing.relogin_max_attempts` | `1` |
| `IBCTL_RELOGIN_FAILURE_ACTION` | `timing.relogin_failure_action` | `"reauth"` |
| `IBCTL_API_PORT_PROBE_INTERVAL_SECS` | `timing.api_port_probe_interval_secs` | `5` (0 to disable) |
| `IBCTL_API_PORT_PROBE_FAILS_BEFORE_REVOKE` | `timing.api_port_probe_fails_before_revoke` | `3` |

## `[timing.recovery]` — reconnect recovery

| Variable | TOML path | Default |
|---|---|---|
| `IBCTL_RECOVERY_AGGRESSIVE_MAX_SECS` | `timing.recovery.aggressive_phase_max_secs` | `3600` |
| `IBCTL_RECOVERY_BACKOFF_MAX_SECS` | `timing.recovery.backoff_phase_max_secs` | `10800` |
| `IBCTL_RECOVERY_BACKOFF_INTERVAL_SECS` | `timing.recovery.backoff_interval_secs` | `900` |
| `IBCTL_RECOVERY_MIN_SUCCESS_DWELL_SECS` | `timing.recovery.min_success_dwell_secs` | `60` |
| `IBCTL_RECOVERY_FINGERPRINT_STREAK` | `timing.recovery.fingerprint_streak_forcing_hitl` | `8` |
| `IBCTL_RECOVERY_GIVEUP_CALLBACK_VALID_HOURS` | `timing.recovery.giveup_callback_valid_hours` | `12` (1..168) |
| `IBCTL_RECOVERY_GIVEUP_ALERT_RESEND_INTERVAL_HOURS` | `timing.recovery.giveup_alert_resend_interval_hours` | `6` |
| `IBCTL_RECOVERY_DISABLED` | (inverse of `timing.recovery.enabled`) | unset. `1` turns recovery off |
| `IBCTL_RECOVERY_FORCE_RESET` | (env only) | unset. `1` clears the saved give-up state when ibctl starts |

## `[command_server]`

| Variable | TOML path | Default |
|---|---|---|
| `IBCTL_COMMAND_SERVER_ENABLED` | `command_server.enabled` | `false` |
| `IBCTL_COMMAND_PORT` | `command_server.port` | `7462` |
| `IBCTL_CONTROL_FROM` | `command_server.control_from` | `"127.0.0.1"` (comma-separated) |
| `IBCTL_ALLOWED_COMMANDS` | `command_server.allowed_commands` | every action command (comma-separated). See [Allowed commands](#allowed-commands). |

### Allowed commands

`allowed_commands` lists the action commands the command server accepts. Any
other action command is refused with
`ERROR command not allowed by command_server.allowed_commands`.

- Default (unset or blank) is every action command: `STOP`, `START`, `RESTART`,
  `RECONNECTDATA`, `RECONNECTACCOUNT`, `ENABLEAPI`, `EXIT`, `RESTARTSOCAT`, `PAUSE`,
  `RESUME`, `HITL_RESUME`, `RESUME_RECONNECT`, `MAINT_HOLD`, `MAINT_RELEASE`,
  `SETSTATE`, `IBSTATUS`, `SETRESTART`. A blank value means "use the default", not
  "nothing".
- Names are trimmed and compared case-insensitively; duplicates are dropped. An
  unknown name fails preflight with the list of valid names.
- Queries (`STATUS`, `STATE`, `CONFIG`, `LOGS`, `WINDOWS`, `SUBSCRIBE`) are always
  allowed and are not valid names for this list.
- It is one list shared by the live and paper instances, and it gates every caller:
  TCP clients, dashboard buttons and API tokens alike. The localhost-only rule for
  privileged commands still applies on top.

Example: `IBCTL_ALLOWED_COMMANDS=SETRESTART,RECONNECTDATA` leaves those two as the
only action commands that work.

Warning: listing too few commands can break tooling that sends the others, for
example an approval flow that sends `STOP` and `START`. Those callers get the
refusal above.

## `[agent]`

| Variable | TOML path | Default |
|---|---|---|
| `IBCTL_AGENT_SOCKET` | `agent.socket_path` | `/run/ibctl/agent.sock` |
| `IBCTL_AGENT_TICK_MS` | (internal) | `50` |

## `[logging]`

| Variable | TOML path | Default |
|---|---|---|
| `IBCTL_LOG_LEVEL` | `logging.level` | `"info"` |
| `IBCTL_LOG_DIR` | `logging.log_dir` | `""` (stdout only) |
| `IBCTL_FUTURES_SESSION_LOGGING` | `logging.futures_session_logging` | `false` |
| `IBCTL_SESSION_REOPEN_HOUR` | `logging.session_reopen_hour` | `18` (ET) |
| `IBCTL_LOG_RETENTION_DAYS` | `logging.retention_days` | `0` (keep all; the Docker config ships `90`). Days of daily log files kept, today included; the dashboard deletes older ones |
| `RUST_LOG` | (target-level override) | `"ibctl=info"` |

## `[ib_system_status]` — dashboard scraper

| Variable | TOML path | Default |
|---|---|---|
| `IBCTL_IB_STATUS_ENABLED` | `ib_system_status.enabled` | `false` |
| `IB_STATUS_CHECK_INTERVAL` | `ib_system_status.check_interval_seconds` | `300` |
| `IB_STATUS_REGION` | `ib_system_status.region` | `"NA"` |

## `[site]`

| Variable | TOML path | Default |
|---|---|---|
| `IBCTL_SITE_ROLE` | `site.role` | `"primary"` |
| `IBCTL_AUTO_LAUNCH` | `site.auto_launch` | `true` |

## `[dashboard]`

| Variable | TOML path | Default |
|---|---|---|
| `IBCTL_DASHBOARD_ENABLED` | `dashboard.enabled` | `false` |
| `IBCTL_DASHBOARD_PORT` | `dashboard.port` | `8080` |
| `IBCTL_DASHBOARD_EXTERNAL_URL` | `dashboard.external_url` | `""` |
| `IBCTL_DASHBOARD_INTERNAL_URL` | (fallback only) | `""` |
| `IBCTL_DEBUG_MODE` | `dashboard.debug_mode` | `false` |
| `IBCTL_NOTIFICATIONS_ENABLED` | `dashboard.notifications_enabled` | `false` |
| `IBCTL_NOTIFICATION_CHANNEL` | `dashboard.notification_channel` | `"ntfy"` |
| `IBCTL_NTFY_URL` | (ntfy server) | `""` |
| `IBCTL_NTFY_TOPIC` | (ntfy topic) | `""` |
| `IBCTL_NTFY_TOKEN` | (ntfy bearer, optional) | `""` |
| `IBCTL_GITHUB_OAUTH_ENABLED` | `dashboard.github_oauth_enabled` | `false` |
| `IBCTL_GITHUB_OAUTH_CLIENT_ID` | (OAuth) | `""` |
| `IBCTL_GITHUB_OAUTH_REDIRECT_URI` | (OAuth) | `""` |
| `IBCTL_GITHUB_OAUTH_ALLOWED_USERS` | (OAuth, comma-separated) | `""` |
| `IBCTL_GITHUB_OAUTH_ALLOWED_ORGS` | (OAuth, comma-separated) | `""` |
| `IBCTL_OIDC_ENABLED` | `dashboard.oidc_enabled` | `false` |
| `IBCTL_OIDC_ISSUER` | `dashboard.oidc_issuer` | `""` |
| `IBCTL_OIDC_SCOPES` | `dashboard.oidc_scopes` | `"openid profile email"` |
| `IBCTL_OIDC_CLIENT_ID` | (OIDC) | `""` |
| `IBCTL_OIDC_REDIRECT_URI` | (OIDC) | `""` |
| `IBCTL_OIDC_ALLOWED_USERS` | (OIDC, comma-separated) | `""` |
| `IBCTL_OIDC_ALLOWED_GROUPS` | (OIDC, comma-separated) | `""` |
| `IBCTL_ZMQ_ENABLED` | `dashboard.zmq_enabled` | `true` |
| `IBCTL_ZMQ_PORT` | `dashboard.zmq_port` | `5556` |
| `IBCTL_SESSION_DOWN_ALERT_MINUTES` | `dashboard.session_down_alert_minutes` | `10` (0 turns the alert off) |
| `IBCTL_SESSION_DOWN_RENAG_MINUTES` | `dashboard.session_down_renag_minutes` | `60` (0 = one alert per outage) |
| `IBCTL_SCHEDULED_RESTART_GRACE_MINUTES` | `dashboard.scheduled_restart_grace_minutes` | `20` |
| `IBCTL_VERSION_PROBE_CLIENT_ID` | `dashboard.version_probe_client_id` | `9172` (uses this ID and the next 7) |
| `IBCTL_SESSION_IDLE_MINUTES` | `dashboard.session_idle_minutes` | `5` (0 = never sign out for inactivity; 0..1440) |

### Dashboard sessions: idle logout

A login ends after `session_idle_minutes` with no user activity, for the
password login and for GitHub OAuth / OIDC alike. Every session also still ends
7 days after it was issued, however active the person is, unless the idle
logout is off (0 removes only the idle limit). Set the value in `ibctl.toml` or
with `IBCTL_SESSION_IDLE_MINUTES`; the env var wins, an empty one is ignored,
and a change takes effect when the dashboard restarts. Preflight rejects a
value that isn't a whole number from 0 to 1440, naming the variable.

What counts as activity: a page navigation, any request that is not a GET or
HEAD (a button press, a form post), and the heartbeat the page sends while its
user is using it (`POST /api/session/touch`). A page's own background refreshes
(`/partials/*`, JSON reads, the event stream, static files) are checked against
the limit but never extend it, so a tab left open on the Overview does sign out.
Each of those requests moves the session's last-activity time at most once every
15 seconds.

In the browser, `static/session.js` watches mouse, keyboard, wheel and touch
input. Open tabs share it through `localStorage`, so activity in one tab keeps
the others signed in. It warns 30 seconds before the limit and, at the limit,
posts the logout form and goes to the login page. Any request the page makes
that comes back 401 sends it to the login page too. Browsers that block
`localStorage` still time out, per tab. The **Log out** button in the header
signs out at any time.

What it does not do:

- An API token is not a session and is not affected.
- A VNC websocket that is already open is not cut by the server, which checks
  the login only when the socket opens (a new socket from an idle session is
  refused). The browser's timer ends an open one, by signing out and leaving the
  page. If the browser stops running timers (a closed laptop, a frozen or
  sleeping tab) the socket stays open until it runs them again.
- A session cookie issued before the idle logout existed has no last-activity
  time, so its issue time stands in for it: such a session ends at most the
  idle limit after it was issued.

## Dashboard access

Since 2.0 the dashboard needs a login. What an anonymous visitor can reach:

| Path | What they get |
|---|---|
| `/` and `GET /api/v1/health` | Health summary: per-mode state, whether the API is ready and since when, ibctl and Gateway versions. |
| `GET /api/v1/ib-status` | IB's system status, fixed fields only. |
| `GET /api/v1/schedule` | The restart schedule. |
| `/login`, `/logout`, OAuth/OIDC callbacks, signed notification links | Signing in and out; each link carries its own signature. |

Everything else, including the overview, config, logs, VNC page and every other
API route, needs a login or an API token of the right type (see
[Dashboard API tokens](#dashboard-api-tokens)).

Ways to log in (at least one is needed to get past the health summary):

- a password: set `IBCTL_DASHBOARD_TOKEN`;
- GitHub OAuth: `dashboard.github_oauth_enabled` with the client id, redirect URI
  and allowed users or orgs, plus `IBCTL_GITHUB_OAUTH_CLIENT_SECRET`;
- OIDC: `dashboard.oidc_enabled` with the issuer and client id, plus
  `IBCTL_OIDC_CLIENT_SECRET`.

Set `IBCTL_DASHBOARD_AUTH_SECRET` to a random value (`openssl rand -hex 32`) so
the session cookies are signed with a key of their own. The dashboard is off until `IBCTL_DASHBOARD_ENABLED=true`. In the compose file it
listens on `IBCTL_DASHBOARD_BIND` (default `127.0.0.1`) port `IBCTL_DASHBOARD_PORT`
(default `3080`); put a TLS-terminating proxy in front of it before exposing it, and set
`IBCTL_ROOT_PATH` if the proxy publishes it under a path prefix.

## Dashboard API tokens

Scripts call the dashboard with a named API token, created on the API access
page and sent as `Authorization: Bearer <token>`. The token is shown once and
only a hash of it is kept. Every token has a **type**, chosen when it is
created, and a token can call only the routes of its own type:

| Type | Routes | Enabled by default |
|---|---|---|
| Warm restart client (`warm_restart`) | `GET` and `POST /api/v1/warm-restart` | yes |
| Gateway upgrade: CI (`upgrade_ci`) | `GET /api/v1/gateway/upgrade`, `POST /api/v1/gateway/upgrade/candidate` | no |
| Gateway upgrade: maintenance (`upgrade_maintenance`) | `GET /api/v1/gateway/upgrade`, `POST /api/v1/gateway/upgrade/swap` | no |

A type must also be enabled on the API access page before its tokens work, and
the two upgrade types start disabled: tokens of a disabled type get a 403 that
names the type. A token of one type gets a 403 on another type's routes (a CI
token cannot post the swap report, a maintenance token cannot post the
candidate). Warm restart is also capped by ibctl's own
`command_server.allowed_commands`, which must list `SETRESTART`.

```sh
# Warm restart client
curl -X POST https://dashboard.example/api/v1/warm-restart \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"mode": "paper"}'

# Gateway upgrade: CI (the image it built)
curl -X POST https://dashboard.example/api/v1/gateway/upgrade/candidate \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"version": "10.51.1h", "sha": "<40-hex commit>", "status": "built"}'

# Gateway upgrade: maintenance (what the swap did)
curl -X POST https://dashboard.example/api/v1/gateway/upgrade/swap \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"version": "10.51.1h", "sha": "<40-hex commit>", "result": "ok"}'
```

A token is not a login and reaches nothing else: not the other API routes, not
the upgrade policy, not the pages, and not `/api/session/touch`. A route added
to the dashboard later is closed to every token until it is added to a type.
The dashboard password is not a Bearer token. An unknown or revoked token gets
a 401. Every token request, accepted or refused, is logged with the token's
name, its type and the caller's address.

An `api_access.json` saved by an earlier build loads as is: its tokens count as
warm restart tokens and its warm restart tick carries over.

## Env-only switches and paths

No TOML key. The Config page lists the switches under Runtime when they're set.

| Variable | Purpose |
|---|---|
| `IBCTL_KICK_LIVE_SESSION_OK` | `1` lets preflight accept `ib_status.kick_active_session=true` with live trading, where a status-page blip can end an authenticated live session. |
| `IBCTL_STANDBY_AUTO_LAUNCH_OK` | `1` lets preflight accept `site.role="standby"` with `site.auto_launch=true`, for hot-standby setups that keep the two sites from racing for the IB session themselves. |
| `IBCTL_CONFIG` | Path of `ibctl.toml` (default `/opt/ibctl/ibctl.toml`). |
| `IBCTL_PERSIST_DIR` | Dashboard state directory (default `/opt/ibctl/persist`): Gateway version check and upgrade records. |
| `IBCTL_BIN` | ibctl binary preflight's payload check runs (default `/opt/ibctl/ibctl`). |

## VNC

`VNC_SERVER_PASSWORD` turns VNC on. There are two ways in.

- **The VNC tab of the dashboard.** The browser's websocket goes to the
  dashboard's own `/websockify` (under `IBCTL_ROOT_PATH`, if set), and the
  dashboard relays it to websockify inside the container. websockify listens on
  `127.0.0.1:${IBCTL_NOVNC_PORT:-6080}` there and is not published. This needs a
  login (a dashboard password, GitHub OAuth or OIDC): a visitor who isn't signed
  in, an API token and a dashboard with no login configured are all refused
  before the socket opens, and the VNC password is only written into the page of
  someone who is signed in. An idle login ends (see "Dashboard sessions"): the
  socket closes when the browser's idle timer signs out, and an idle session
  can't open a new one.
- **A regular VNC client** on port 5900, published as
  `${IBCTL_VNC_BIND:-127.0.0.1}:5900`. That is loopback unless the operator sets
  `IBCTL_VNC_BIND` (a compose variable) to another address, which is opt-in; the
  VNC password is then the only thing protecting it.
  Preflight enforces this: if `IBCTL_VNC_BIND` is anything but a loopback address
  and `VNC_SERVER_PASSWORD` (or `VNC_SERVER_PASSWORD_FILE`) is empty, the container
  refuses to start and says so. Compose passes `IBCTL_VNC_BIND` into the container
  for that check.

A reverse proxy in front of the dashboard must send the websocket path to the
**dashboard**, not to port 6080 (nothing publishes that port). With nginx, next
to the location that already proxies the dashboard:

```nginx
location /ibctl/websockify {
    proxy_pass http://127.0.0.1:3080/websockify;   # the dashboard: IBCTL_DASHBOARD_PORT
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 3600s;
}
```

---

## Preflight validation

Run before deploy to verify env-var + TOML coherence:

```bash
cd dashboard && python -m app.preflight --config ../docker/ibctl.toml
```

This validates cross-field rules (e.g. `strategy=ntfy_callback` requires
`IBCTL_NTFY_ACTION_SIGNING_KEY`) and prints soft warnings for non-obvious
configs (e.g. `api_port_probe_interval_secs=0` disabling the TCP probe).

## Adding a new env var

New env vars must be wired in three places so they're picked up everywhere:

1. `config/pkl/types.pkl` — Pkl field with `@env` annotation (and its `_emit`
   in `tools/renderers/toml_renderer.py`)
2. `ibctl/src/config.rs` — Rust struct field + env override in `apply_env_overrides`
   (settings only the dashboard reads skip this; they read
   `app/services/effective_config.py`)
3. `dashboard/app/preflight/models.py` — Pydantic field + entry in `ENV_MAP`,
   and its type in `app/preflight/env_overlay.py` when it isn't a string
4. A row in this file

Then regenerate: `make generate-configs`. `dashboard/tests/test_settings_consistency.py`
fails when one of these is missing.
