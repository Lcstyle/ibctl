# ibctl Environment Variable Reference

Every TOML configuration field has a matching environment variable override.
Env vars take precedence over `ibctl.toml`. This doc is the canonical
catalog of env vars recognized by ibctl + its dashboard.

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
| `IBCTL_DASHBOARD_AUTH_SECRET` | Dashboard session cookie signing key. |
| `VNC_SERVER_PASSWORD` | VNC server password. |
| `IBCTL_GITHUB_CLIENT_SECRET` | GitHub OAuth client secret (when `dashboard.github_oauth_enabled=true`). |
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

## `[gateway]`

| Variable | TOML path | Default |
|---|---|---|
| `TWS_PATH` | `gateway.tws_path` | `/home/ibgateway/Jts` |
| `TWS_SETTINGS_PATH` | `gateway.tws_settings_path` | (uses `tws_path`) |
| `TWS_MAJOR_VRSN` | `gateway.tws_major_vrsn` | auto-detected |
| `JAVA_HEAP_SIZE` | `gateway.java_heap_size` | `768` (MB) |
| `GATEWAY_OR_TWS` | `gateway.gateway_or_tws` | `"gateway"` |

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

## `[command_server]`

| Variable | TOML path | Default |
|---|---|---|
| `IBCTL_COMMAND_SERVER_ENABLED` | `command_server.enabled` | `false` |
| `IBCTL_COMMAND_PORT` | `command_server.port` | `7462` |
| `IBCTL_CONTROL_FROM` | `command_server.control_from` | `"127.0.0.1"` (comma-separated) |

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
| `RUST_LOG` | (target-level override) | `"ibctl=info"` |

## `[ib_status]`

| Variable | TOML path | Default |
|---|---|---|
| `IBCTL_IB_STATUS_KICK_ACTIVE_SESSION` | `ib_status.kick_active_session` | `false` |

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
| `IBCTL_GITHUB_CLIENT_ID` | (OAuth) | `""` |
| `IBCTL_OIDC_ENABLED` | `dashboard.oidc_enabled` | `false` |
| `IBCTL_OIDC_ISSUER` | `dashboard.oidc_issuer` | `""` |
| `IBCTL_OIDC_SCOPES` | `dashboard.oidc_scopes` | `"openid profile email"` |
| `IBCTL_OIDC_CLIENT_ID` | (OIDC) | `""` |
| `IBCTL_ZMQ_ENABLED` | `dashboard.zmq_enabled` | `true` |
| `IBCTL_ZMQ_PORT` | `dashboard.zmq_port` | `5556` |

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

1. `config/pkl/types.pkl` — Pkl field with `@env` annotation
2. `ibctl/src/config.rs` — Rust struct field + env override in `apply_env_overrides`
3. `dashboard/app/preflight/models.py` — Pydantic field + entry in `ENV_MAP`

Then regenerate: `make generate-configs`.
