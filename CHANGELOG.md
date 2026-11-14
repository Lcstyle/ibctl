# Changelog

## [Unreleased]

## [2.0.0] - 2026-11-14

**Breaking: the dashboard now requires authentication.** Read "Authentication" and
"Upgrading from 1.3.x" below before you update a running install.

### Authentication
- **Who can see what.** Without logging in, a visitor gets the health summary at
  `/` (per-mode state, whether the API is ready and since when, versions) and
  `GET /api/v1/health`, a fixed field list from `GET /api/v1/ib-status`, and
  `GET /api/v1/schedule`. Signed notification links and the sign-in routes also
  work. Everything else (overview, config, logs, VNC, every other API route)
  needs a login or an API token.
- **Logging in.** Set `IBCTL_DASHBOARD_TOKEN` (the login password), or configure
  GitHub OAuth or OIDC. Set `IBCTL_DASHBOARD_AUTH_SECRET` too, so session cookies
  are signed with a key of their own. With no login method configured, the
  dashboard shows the health summary only. Sessions are a signed cookie, end
  after 5 idle minutes (`session_idle_minutes`; `0` turns it off, background
  polling does not keep one alive) and can be ended with the Log out button.
  Sign-in works behind a reverse proxy path prefix (`IBCTL_ROOT_PATH`).
- **API tokens, by type.** Scripts and services no longer use the password. The
  new API access page issues named tokens, shown once and stored hashed. A token
  has a type that fixes the routes it can call: `warm_restart` (warm restart),
  `upgrade_ci` and `upgrade_maintenance` (the Gateway upgrade pipeline's read,
  build report and swap report). A type can be switched off for everyone; the
  two upgrade types start off. A token reaches nothing outside its type, and the
  dashboard password is **no longer accepted as a Bearer token**.
- **VNC behind the login.** The dashboard proxies `/websockify` after the login
  check and the compose file no longer publishes port 6080. A VNC client on port
  5900 still works. Preflight refuses to start when `IBCTL_VNC_BIND` is reachable
  from the network and no VNC password is set.
- **`command_server.allowed_commands`.** One list that gates every caller of the
  command socket. Blank keeps today's behaviour; queries are always allowed.

### Highlights
- **Warm restart on demand.** `POST /api/v1/warm-restart` (and `GET` for the last
  result), a Warm restart button, and a `WARMRESTART` command: the Gateway
  restarts through its saved session, with no 2FA, at most once per interval per
  mode.
- **Gateway time zone.** ibctl writes the declared zone before every launch and
  converts the restart time to it, and passes the Gateway's own Java options from
  its installer to the launch.

### Added
- A paused ibctl reports the live Gateway state; `SETRESTART` reports warm exits.
- The health summary shows times in the container's time zone (`TZ`); the JSON
  stays UTC.
- README: "Dashboard login and API access". `docs/env-vars.md`: "Dashboard
  access" and token types, with a `curl` example for each.

### Changed
- The Config views show the IB login name as set or not set, and scrub account
  numbers.
- Hotkeys are pressed in the right window, only ibctl's own confirmation prompts
  are confirmed, and the Gateway's main window is found even when the agent
  reports no visibility flag.

### Fixed
- `docker-compose.yml` passed the dashboard port `8080` to the container while
  publishing `3080` when `IBCTL_DASHBOARD_PORT` was unset; both now default to
  `3080`.

### Upgrading from 1.3.x
1. **Before you update,** set `IBCTL_DASHBOARD_TOKEN` (and
   `IBCTL_DASHBOARD_AUTH_SECRET`) or configure OAuth/OIDC. Otherwise the
   dashboard shows only the health summary after the update.
2. Replace anything that called the API with the password as a Bearer token:
   create an API token of the right type on the API access page and send it as
   `Authorization: Bearer ibctl_...`. The two Gateway-upgrade types must be
   switched on there before their tokens work.
3. Anything that used the published port 6080 should use the dashboard's
   `/websockify` path instead.
4. Check `IBCTL_VNC_BIND`: a network-reachable bind needs `VNC_SERVER_PASSWORD`.
5. Everyone signs in once more: session cookies from 1.3.x are not accepted.

## [1.3.0] - 2026-11-13

### Highlights
- **2FA that waits for a person, not a timer.** A failed login is retried
  inside the running Gateway instead of restarting it. A 2FA round ends when
  the Gateway ends it, so a push you are about to approve is never cut off.
  Only one login runs at a time, so ibctl no longer fights the Gateway's own
  re-login (the session-conflict loop). New `twofa.backoff.unattended_hours`
  (`"HH:MM-HH:MM"`, the Docker config ships `"22:00-08:00"`): a round that
  fails in those hours parks for the dashboard's Retry instead of sending
  another push overnight. The Sunday re-auth finishes an outstanding login
  instead of skipping it.
- **Host maintenance hold.** `MAINT_HOLD <id> <ttl_secs>` / `MAINT_RELEASE
  <id> <result>` on the command server keep ibctl's Sunday restart from
  racing a host doing its own maintenance. The hold is persisted, survives
  the container restart it covers, and expires on its own.
- **Gateway 10.50, stable channel.** The image builds Gateway 10.50.1f and
  runs it on the Java its installer bundles, found from the installer's own
  records. `ibctl preflight --payload` checks the Gateway payload (jars,
  vmoptions, Java) when the image is built and every time the container
  starts.
- **Gateway version tracking.** The dashboard checks the running Gateway's
  version every week and warns before an IB desupport cutoff (error 2172).
  A Gateway tab shows the version, the upgrade policy and its decision.
  Building upgrade candidates needs an installer store you host
  (`IB_GATEWAY_STORE`, pinned by sha256).
- **Logs page.** Scroll back through a whole log file and on into earlier
  days, with a marker between days. Full window width. Auto-scroll turns off
  when you scroll up and back on at the newest line, and the dashboard's
  refresh no longer reloads the viewer. New `logging.retention_days`: the
  dashboard deletes daily log files older than that (type default 0 keeps
  everything; the Docker config ships 90).

### Added
- Dashboard: Stop and Start per Gateway on the overview; tabs on the alerts
  page; `GET /api/v1/schedule` for the scheduled-restart settings; alerts
  before a Gateway upgrade and when the version check can't see the Gateway.
- Cold restart: a notification when a scheduled restart isn't needed, and a
  confirmation when one succeeds. The HITL retry link no longer expires.
- New `[dashboard]` settings for knobs that were env-only, same env names
  and defaults: `session_down_alert_minutes`, `session_down_renag_minutes`,
  `scheduled_restart_grace_minutes`, `version_probe_client_id`.
- Config page: every setting has a tooltip, and the env-only switches
  (`IBCTL_KICK_LIVE_SESSION_OK`, `IBCTL_STANDBY_AUTO_LAUNCH_OK`,
  `IBCTL_RECOVERY_DISABLED`, `IBCTL_RECOVERY_FORCE_RESET`) show under Runtime
  when they're set.
- Docker image label `IBCTL_BUILD_SHA`.

### Changed
- Pkl and preflight accept the same values for every setting. Pkl now checks
  the path, URL and IP formats preflight checks, so a bad profile fails at
  `make generate-configs`; cross-field rules stay in preflight.
- Env overrides: `IBCTL_TWOFA_INTERVALS_MINUTES="30,60"` passes preflight
  (it was handed the raw text), a bad number in an override keeps the TOML
  value the way ibctl does, and `docker-compose.yml` passes every override
  through. `docs/env-vars.md` lists them all.
- Dashboard log file: one valid JSON line per record with UTC times (quotes
  in a message used to break the line, and uvicorn's lines were written
  twice). The logs page shows local time.
- Pkl 0.33.0 (security fixes), current Rust dependencies with MSRV 1.85,
  dashboard on Python 3.14 with dependencies locked and resolved from PyPI
  only, current agent build plugins.

### Fixed
- Connected is revoked when the agent reports its own disconnect.
- IB's platform status no longer stands in for Gateway readiness.
- The session-down alert fires when a session stays down, not when it
  leaves, and is held through a scheduled restart.
- Login: the mode toggle and the API-type radio are clicked when they
  appear; agent actions report "not found" instead of an HTTP envelope.
- The warm-restart token is found from every state, not just Connected.
- Standby-mode dashboard rendering; dashboard page buttons reach the Gateway
  again; the State tab's Start button.
- Notifications: a saved config keeps events added later at their defaults.
- Preflight requires `twofa.secret_env` only when the strategy mints TOTP
  codes.

### Upgrade notes
- Preflight is stricter. It now rejects 0 for the timing ticks, delays and
  timeouts, an empty `command_server.control_from` (ibctl refused every
  peer with one anyway), an empty or relative `gateway.tws_path`, and
  malformed paths, URLs and IP addresses.
- The Docker config sets `logging.retention_days = 90` (daily log files
  older than 90 days are deleted) and `twofa.backoff.unattended_hours =
  "22:00-08:00"`. Set them to `0` and `""` to keep the old behavior.
- `docker build` with no installer store installs IB's current build for
  `IB_GATEWAY_CHANNEL` (stable by default) and prints its sha256; the image
  runs whatever build it installed. With `IB_GATEWAY_STORE` or
  `IB_GATEWAY_URL` it installs the pinned `IB_GATEWAY_VERSION` and checks
  `IB_GATEWAY_SHA256`.

## [1.2.0] - 2026-07-12

### Security
- Pin Pkl runtime to 0.32.0 via `mise.toml` — closes GHSA-87qh-25w9-mh34
  (packages readable/writable outside the configured cache directory) and
  GHSA-fgvf-hh2w-cxff (remote packages reading files past a local package
  dependency root). `make generate-configs` fails loud if the local Pkl
  version drifts from the pin.

### Changed
- Bumped Rust toolchain to 1.97 in CI (Dockerfile `rust-builder` stage +
  the CI clippy and rust-tests images). Added `rust-version = "1.83"`
  MSRV pin to `ibctl/Cargo.toml` (matches the prior CI floor; distro rustc
  on Fedora/Debian still builds locally). Bumping the MSRV in lockstep
  with the CI image is a follow-up once a rustup-managed dev environment
  is standardized.
- Bumped Alpine CI images from 3.20 (EOL 2026-05-01) to 3.22.
- Dashboard Python install path now `uv sync --frozen --no-dev` against a
  committed `dashboard/uv.lock`. Removes the free-form `pip install` in the
  Dockerfile that resolved unpinned versions at every build.
- Migrated dashboard dev deps from `[project.optional-dependencies].dev` to
  `[dependency-groups].dev` (PEP 735) — canonical uv form; no longer relies
  on uv's PEP-621-to-groups compatibility shim.
- Split `make check-configs` into `regenerate-configs` (mutating; requires
  the Pkl runtime) and `check-configs` (pure `git status` inspection; runs
  in any container). `generate-configs` kept as a legacy alias.

### Added
- `mise.toml` at repo root pinning `pkl = "0.32.0"`. Run `mise install`
  to sync a local dev environment.
- `renovate.json` — weekly patch bumps, monthly Docker + mise bumps, PRs
  land against `develop`.
- CI `uv-lock-check` step — verifies
  `dashboard/uv.lock` matches `pyproject.toml` before the Docker build.
- CI `configs-drift` step — runs `make check-configs`
  so hand-edited generated config artifacts fail CI before deploy.
- The CI pipeline now runs on pull requests against develop (test gate
  only — `build-image` and `deploy` are gated to develop push), so
  Renovate PRs get CI feedback without auto-deploying.

## [0.2.2] - 2026-03-30

### Security
- Passwords use `secrecy::SecretString` — zeroed on drop, redacted in Debug
- TOTP secret piped via stdin to oathtool (no longer visible in /proc/cmdline)
- Removed NOPASSWD sudoers and sudo package from Docker image
- UDS agent socket moved to /run/ibctl/ with 700 permissions
- Added `cargo audit` to CI pipeline
- Added global pre-commit hook for credential scanning (detect-secrets)

### Fixed
- CIDR subnet matching in `is_allowed()` (was string-only comparison)
- `supervisor.wait()` no longer blocks tokio runtime (now async polling)
- `supervisor.kill()` no longer blocks tokio runtime (async sleep)
- TOTP generation uses `spawn_blocking` to avoid blocking runtime
- ConfiguringApi state retries capped at 10, then restarts Gateway
- `TotpProvider::Builtin` returns clear error instead of silent oathtool fallback
- Socat zombie process prevented via `Drop` impl on `StateMachine`
- `find_java()` no longer spawns blocking `which` subprocess
- LOGS query returns explicit `not_implemented` error instead of fake empty array

### Changed
- 7 stringly-typed config fields converted to proper Rust enums
  (TradingMode, TotpProvider, TwoFaTimeoutAction, GatewayProgram,
   SessionAction, AcceptIncoming, LogLevel)
- Credential resolution deduplicated — handlers use Config directly
- `ApiConfigSettings::from_env()` replaces misleading `from_config()`
- Socat ports configurable via `[gateway]` config section
- State machine constructor uses `Channels` struct (was 8 separate args)
- Extracted `client_advisory()` pure function from state machine
- Extracted `parse_time_with_ampm()` and `PRECAUTION_LABELS` from api_config
- 10+ dead code items removed (zero compiler warnings)

### Added
- CI workflow: `cargo test` + `cargo clippy` + `cargo audit` on every push/PR
- Docker HEALTHCHECK via command server STATUS endpoint
- `.dockerignore` to reduce build context
- 57 unit tests across command_server, config, cold_restart, api_config, state_machine
- TCP command server rate limiting (max 10 concurrent connections)

## [0.2.1] - 2026-03-30

### Fixed
- TOML parser handles unknown sections (`[dashboard]`) via serde flatten
- `TimingConfig` tolerates partial TOML with `serde(default)`

## [0.2.0] - 2026-03-30

- Initial release
- Rust binary + Java agent replacing IBC for IB Gateway automation
- State machine with 11 states, 10+ dialog handlers
- HTTP+JSON over Unix domain socket for Rust-Java IPC
- IBC wire-compatible TCP command server
- Sunday cold restart timer
- Socat port forwarding owned by state machine
- Docker multi-stage build with GitHub Actions release workflow
