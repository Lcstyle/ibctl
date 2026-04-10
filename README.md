# ibctl

Drop-in replacement for [IBC](https://github.com/IbcAlpha/IBC) — automates IB Gateway/TWS login, 2FA, session management, and configuration.

IBC is being [deprecated September 2026](https://github.com/IbcAlpha/IBC/discussions/347). ibctl provides the same automation using a Rust supervisor + Java agent architecture that directly inspects Swing UI components (no xdotool, no pixel coordinates, no screen scraping).

## How it works

```
ibctl (Rust binary)          ibctl-agent.jar (Java agent)
┌─────────────────┐         ┌──────────────────────────┐
│ Process          │   UDS   │ Runs inside Gateway JVM  │
│ supervisor      ─┼─HTTP+──┼─ Swing component walking │
│ State machine    │  JSON   │ Click/type/read fields   │
│ TCP cmd server   │         │ Menu & tree navigation   │
│ Config (TOML+env)│         │ Window event monitoring  │
└─────────────────┘         └──────────────────────────┘
```

The Java agent is injected via `-javaagent:` into the Gateway JVM. It walks Swing component trees to find buttons, text fields, checkboxes, and menus — the same approach IBC uses internally. Every action is verified through the actual UI state, not blind input injection.

## Quick start

```bash
git clone https://github.com/lcstyle/ibctl
cd ibctl
docker build -t ibctl .
```

Create a `docker-compose.yml`:

```yaml
services:
  ibctl:
    image: ibctl
    environment:
      - TWS_USERID=your_username
      - TWS_PASSWORD=your_password
      - TRADING_MODE=paper          # live | paper | both
      - VNC_SERVER_PASSWORD=secret  # optional, for remote viewing
    ports:
      - "4001:4001"   # live API
      - "4002:4002"   # paper API
      - "7462:7462"   # command server (IBC-compatible)
      - "5900:5900"   # VNC (optional)
```

```bash
docker compose up -d
```

For live accounts with 2FA:

```yaml
    environment:
      - TWS_USERID=your_username
      - TWS_PASSWORD=your_password
      - TRADING_MODE=live
      - TWOFA_DEVICE=IB Key              # or "Mobile Authenticator app"
      - TWOFA_TIMEOUT_ACTION=restart      # restart login on 2FA timeout
      - TWOFA_EXIT_INTERVAL=120           # seconds to wait for mobile approval
      - RELOGIN_AFTER_TWOFA_TIMEOUT=yes   # keep retrying until approved
```

For dual mode (live + paper simultaneously):

```yaml
    environment:
      - TRADING_MODE=both
      - TWS_USERID=live_user
      - TWS_PASSWORD=live_pass
      - TWS_USERID_PAPER=paper_user
      - TWS_PASSWORD_PAPER=paper_pass
      - TWOFA_DEVICE=IB Key
```

## Environment variables

### Authentication

| Variable | Description | Default |
|----------|-------------|---------|
| `TWS_USERID` | IB account username | required |
| `TWS_PASSWORD` | IB account password | required |
| `TRADING_MODE` | `live`, `paper`, or `both` | `live` |
| `TWS_USERID_PAPER` | Paper account username (dual mode) | `$TWS_USERID` |
| `TWS_PASSWORD_PAPER` | Paper account password (dual mode) | `$TWS_PASSWORD` |

### Two-factor authentication

| Variable | Description | Default |
|----------|-------------|---------|
| `TWOFA_DEVICE` | 2FA device name (`IB Key`, `Mobile Authenticator app`) | — |
| `TWOFACTOR_CODE` | TOTP base32 secret (for automated code entry) | — |
| `TWOFA_TIMEOUT_ACTION` | `restart` or `exit` on 2FA timeout | `restart` |
| `TWOFA_EXIT_INTERVAL` | Seconds to wait for 2FA approval | `180` |
| `RELOGIN_AFTER_TWOFA_TIMEOUT` | `yes` to retry login on timeout | `yes` |

### API configuration (applied after login)

| Variable | Description | Default |
|----------|-------------|---------|
| `TWS_ACCEPT_INCOMING` | `accept`, `reject`, or `manual` | `accept` |
| `TWS_MASTER_CLIENT_ID` | Master API client ID | — |
| `READ_ONLY_API` | `yes` or `no` | — |
| `BYPASS_WARNING` | `yes` to bypass all order precaution warnings | — |
| `ALLOW_BLIND_TRADING` | `yes` or `no` | — |
| `EXISTING_SESSION_DETECTED_ACTION` | `primary`, `secondary`, `primaryoverride` | `primary` |

### Scheduling

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTO_RESTART_TIME` | Daily auto-restart time (e.g., `05:05 PM`) | — |
| `AUTO_LOGOFF_TIME` | Auto-logoff time (e.g., `11:45 PM`) | — |
| `TWS_COLD_RESTART` | Sunday cold restart time, 24h format (e.g., `09:00`) | — |

### Gateway settings

| Variable | Description | Default |
|----------|-------------|---------|
| `JAVA_HEAP_SIZE` | JVM heap size in MB | `768` |
| `VNC_SERVER_PASSWORD` | Enable VNC with this password | disabled |
| `IBCTL_COMMAND_PORT` | TCP command server port | `7462` |
| `IBCTL_LOG_LEVEL` | `debug`, `info`, `warn`, `error` | `info` |

Docker secrets are supported: any variable can use `_FILE` suffix to read from a file (e.g., `TWS_PASSWORD_FILE=/run/secrets/ib_password`).

## IBC-compatible command server

ibctl exposes an IBC-compatible TCP command server (default port 7462):

```bash
echo "STOP" | nc localhost 7462
echo "RESTART" | nc localhost 7462
echo "RECONNECTDATA" | nc localhost 7462
echo "RECONNECTACCOUNT" | nc localhost 7462
echo "ENABLEAPI" | nc localhost 7462
```

Wire protocol is identical to IBC — line-based, `COMMAND\n` → `OK message\n` or `ERROR message\n`.

## What's implemented

- [x] Login automation (IB API mode selection, trading mode, credentials, login button)
- [x] 2FA device selection (IB Key, Mobile Authenticator)
- [x] 2FA via IB Key mobile push (wait for approval, timeout with retry)
- [x] 2FA via TOTP code (oathtool integration, configurable provider)
- [x] Session conflict handling (primary/secondary/primaryoverride)
- [x] Post-login API configuration via Global Configuration dialog
  - Master Client ID
  - Read-Only API
  - Order precaution bypasses (all 9 checkboxes)
  - Auto-restart / auto-logoff time
- [x] Dialog auto-dismissal (paper trading warning, SSL reconnect, version notice, tip-of-day)
- [x] Dual mode (live + paper simultaneously)
- [x] IBC-compatible TCP command server (STOP, RESTART, RECONNECTDATA, RECONNECTACCOUNT, ENABLEAPI)
- [x] TOML config file + env var configuration with Docker secrets support
- [x] SIGTERM/SIGINT graceful shutdown
- [x] VNC support for remote viewing
- [x] Sunday cold restart (weekly full re-auth, mirrors IBC's ColdRestartTime)
- [x] Connection loss recovery (re-login dialog auto-handled)
- [x] Daily auto-restart recovery (handler state reset)

## What's not yet implemented

- [ ] AT-SPI accessibility tree fallback (v2)
- [ ] Built-in TOTP generation (v3, currently shells out to oathtool)
- [ ] OCR verification (v2)
- [ ] API port override
- [ ] Trusted API client IPs configuration
- [ ] Save TWS settings on schedule
- [ ] Full 27+ IBC dialog handler coverage

## Architecture

See [docs/architecture.md](docs/architecture.md) for detailed design documentation.

## Config validation (pre-flight)

ibctl validates your configuration before anything starts. When the container launches, a Pydantic-based pre-flight check runs against your TOML config and environment variables. If anything is wrong, you get a clear error message and the container exits before wasting time on Xvfb, VNC, or JVM startup.

```
$ docker compose up
Validating configuration...
PRE-FLIGHT FAILED:
  ERROR: auth.trading_mode (env: TRADING_MODE): Input should be 'live', 'paper' or 'both' [got: lve]
ERROR: Config validation failed. Fix the errors above and restart.
```

What it catches:
- Invalid enum values (trading mode, gateway program, log level, etc.)
- Port conflicts (two services on the same port)
- Missing credentials for dual mode (`trading_mode=both` without paper credentials)
- Invalid time formats (`tws_cold_restart` must be HH:MM or empty)
- Malformed TOML syntax
- Out-of-range values (ports, heap size, timing knobs)

The validator respects the same precedence as ibctl: env vars override TOML values, and `_FILE` variants (Docker secrets) take precedence over direct env vars.

## Configuration management (for developers)

ibctl uses [Pkl](https://pkl-lang.org/) as the single source of truth for configuration. The Pkl schema at `config/pkl/types.pkl` defines every config field, its type, default value, and associated environment variable.

Generated artifacts (committed to the repo):
- `docker/ibctl.toml` — Docker deployment defaults
- `ibctl.toml.example` — User-facing template
- `examples/docker-compose.*.yml` — Profile-specific Compose files
- `examples/.env.example` — Documented env var template

Users never need Pkl installed. The generated files are checked in and ready to use.

### Profiles

Profiles define deployment variants. Each inherits from a base and overrides what's different:

| Profile | Mode | Dashboard | VNC | Use case |
|---------|------|-----------|-----|----------|
| `base` | live | no | no | Default single instance |
| `live` | live | no | no | Live-only, no paper ports |
| `paper` | paper | no | no | Paper-only |
| `both` | both | no | no | Dual live + paper |
| `dashboard` | both | yes | yes | Full deployment with web UI |
| `standby` | live | no | no | Failover node, auto_launch=false |

### Developer workflow

After editing any file in `config/pkl/`:

```bash
# Install tools (first time only)
pip install -r tools/requirements.txt

# Regenerate all artifacts
make generate-configs

# Verify nothing drifted
make check-configs

# Run all tests
make test
```

### TOML field naming convention

IBC-origin fields use IBC's env var naming: `tws_userid`, `exit_interval`, `java_heap_size`, `gateway_or_tws`. ibctl-specific fields use the `IBCTL_` prefix: `IBCTL_COMMAND_PORT`, `IBCTL_LOG_LEVEL`, `IBCTL_SITE_ROLE`. TOML field names match their env var names (lowercased, under the appropriate section).

## Building from source

Requires Rust 1.75+ and JDK 17+:

```bash
# Build Rust binary
cargo build --release

# Build Java agent
cd agent
javac --release 17 -d target/classes src/main/java/ibctl/agent/*.java
jar cfm target/ibctl-agent.jar src/main/resources/META-INF/MANIFEST.MF -C target/classes .
```

Or use the multi-stage Docker build (no local toolchain needed):

```bash
docker build -t ibctl .
```

## License

MIT — same as [gnzsnz/ib-gateway-docker](https://github.com/gnzsnz/ib-gateway-docker).
