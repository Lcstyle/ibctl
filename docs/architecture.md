# ibctl Architecture

## Context

IBC (IB Controller), the 23-year-old Java tool that automates Interactive Brokers Gateway/TWS login and session management, is being deprecated September 1, 2026. The gnzsnz/ib-gateway-docker project depends heavily on IBC. The sole maintainer (age 73) is retiring.

**ibctl** is a Rust binary + Java agent that replaces IBC with a more robust, maintainable architecture. Unlike xdotool-based approaches (which blindly fire input without verification), ibctl uses a Java agent inside the JVM to inspect Swing component state, verify actions, and report success/failure.

### Verified Runtime Environment

- **IB Gateway image**: `ghcr.io/gnzsnz/ib-gateway:latest`
- **JDK**: Zulu 17.0.16 (OpenJDK 17) -- `UnixDomainSocketAddress` available
- **Gateway version**: 10.43.1b
- **Java path**: `/usr/local/i4j_jres/Oda-jK0QgTEmVssfllLP/17.0.16.0.101-zulu/bin/java`
- **License**: MIT (matching gnzsnz's repo)

---

## Architecture Overview

```
+----------------------------------------------------------+
|                        ibctl (Rust)                       |
+--------------+--------------+--------------+-------------+
|  Supervisor  |  Agent       |  Command     |  Config     |
|  - Launch JVM|  Client      |  Server      |  - TOML file|
|  - Monitor   |  - HTTP+JSON |  - IBC-wire  |  - Env vars |
|  - Restart   |  - over UDS  |  - compatible|  - Docker   |
|  - Signals   |  - Query UI  |  - IP ACL    |    secrets  |
+--------------+--------------+--------------+-------------+
|                    State Machine                          |
|  INIT -> LAUNCHING -> LOGIN -> 2FA -> POPUPS -> CONNECTED|
+----------------------------------------------------------+
|                  Dialog Handlers                          |
|  Login | TOTP | SessionConflict | TipOfDay | PaperWarn   |
|  AcceptConnection | VersionNotice                        |
+----------------------------------------------------------+
         | UDS: /tmp/ibctl.sock
         v
+----------------------------------------------------------+
|              ibctl-agent.jar (Java, ~150KB)               |
|  Injected via -javaagent: on JVM command line             |
+--------------+--------------+----------------------------+
|  HTTP Server |  Swing       |  Window                    |
|  (JDK 17 UDS|  Inspector   |  Monitor                   |
|   built-in)  |  - Tree walk |  - AWT event listener     |
|              |  - Find/read |  - Dialog detection        |
|              |  - Click/type|  - State reporting         |
+--------------+--------------+----------------------------+
         | Runs inside IB Gateway JVM
         v
+----------------------------------------------------------+
|           IB Gateway / TWS (Java Swing app)              |
+----------------------------------------------------------+
```

The Rust binary (`ibctl`) is the process supervisor and orchestrator. It launches IB Gateway with a Java agent (`ibctl-agent.jar`) injected via `-javaagent:`. The agent runs inside the Gateway JVM and exposes an HTTP+JSON API over a Unix domain socket. The Rust side drives the login flow by querying and commanding the agent.

---

## Agent IPC Protocol

HTTP+JSON over Unix domain socket at `/tmp/ibctl.sock`. The agent uses JDK 17's built-in `UnixDomainSocketAddress` with `com.sun.net.httpserver.HttpServer` (or a minimal custom HTTP handler over `ServerSocketChannel`).

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Agent liveness check |
| GET | `/windows` | List all visible windows (id, title, class, bounds) |
| GET | `/windows/{id}/components` | Component tree for a window |
| POST | `/windows/{id}/find` | Find component by type/index/text |
| POST | `/windows/{id}/click` | Click a button by label |
| POST | `/windows/{id}/type` | Type text into a field by index |
| POST | `/windows/{id}/key` | Send keystroke (for RECONNECTDATA=Ctrl+F etc.) |
| GET | `/windows/{id}/screenshot` | Capture window pixels (for future OCR) |

### Response Format

```json
{
  "ok": true,
  "data": { ... },
  "error": null
}
```

---

## TCP Command Server (IBC Wire-Compatible)

Line-based TCP protocol, exactly matching IBC's wire format for drop-in compatibility:

- **Request**: `COMMAND\n` (case-insensitive)
- **Response**: `OK message\n` or `ERROR message\n` or `INFO message\n`
- **Commands**: EXIT, STOP, RESTART, RECONNECTDATA, RECONNECTACCOUNT, ENABLEAPI
- **Access control**: IP allow-list (env var `IBCTL_CONTROL_FROM`)
- **Port**: env var `IBCTL_COMMAND_PORT` (default: 7462)

---

## State Machine

```
INIT
  | (parse config, validate env)
  v
LAUNCHING
  | (build classpath, launch JVM with -javaagent:)
  v
WAITING_FOR_AGENT
  | (poll /tmp/ibctl.sock until agent responds to /health)
  v
WAITING_FOR_LOGIN
  | (agent monitors for login frame via AWT WindowListener)
  v
AUTHENTICATING
  | (agent fills username/password, selects trading mode, clicks Login)
  v
WAITING_FOR_2FA  [if TOTP configured]
  | (agent detects 2FA dialog, ibctl generates TOTP via oathtool, agent types it)
  v
HANDLING_SESSION_CONFLICT  [if detected]
  | (agent clicks OK/Cancel based on configured action)
  v
DISMISSING_POPUPS
  | (agent dismisses tip-of-day, version notice, paper warning, etc.)
  v
CONNECTED
  | (monitoring loop -- watch for new dialogs, handle accept-connection)
  v
RESTARTING  [on RESTART command or crash]
  | (check for autorestart file -> skip auth if present)
  +---> back to LAUNCHING
```

---

## Project Structure

```
ibctl/
+-- Cargo.toml                    # workspace root
+-- LICENSE                       # MIT
+-- README.md
+-- ibctl.toml.example            # example config file
+-- .cargo/
|   +-- config.toml               # musl target config
+-- docs/
|   +-- architecture.md           # this document
+-- ibctl/                        # Rust binary crate
|   +-- Cargo.toml
|   +-- src/
|       +-- main.rs               # entry point, arg parsing, orchestration
|       +-- config.rs             # env var parsing, Docker secrets (_FILE)
|       +-- supervisor.rs         # JVM launch, classpath build, process monitor
|       +-- agent_client.rs       # HTTP+JSON client over UDS
|       +-- command_server.rs     # IBC-compatible TCP server
|       +-- state_machine.rs      # login flow state machine
|       +-- totp.rs               # TOTP provider trait + oathtool impl
|       +-- signals.rs            # SIGTERM/SIGINT handling
|       +-- handlers/
|           +-- mod.rs            # DialogHandler trait
|           +-- login.rs
|           +-- totp_entry.rs
|           +-- session_conflict.rs
|           +-- tip_of_day.rs
|           +-- accept_connection.rs
|           +-- paper_warning.rs
|           +-- version_notice.rs
+-- agent/                        # Java agent
|   +-- pom.xml                   # Maven build (Java 17 target, no external deps)
|   +-- src/main/java/ibctl/agent/
|   |   +-- IbctlAgent.java       # premain() entry point
|   |   +-- SwingInspector.java   # component tree walking
|   |   +-- WindowMonitor.java    # AWT event-driven dialog detection
|   |   +-- HttpApi.java          # HTTP server over UDS
|   |   +-- Actions.java          # click, type, key operations
|   +-- src/main/resources/
|       +-- META-INF/MANIFEST.MF  # Premain-Class: ibctl.agent.IbctlAgent
+-- .github/
    +-- workflows/
        +-- ci.yml                # Build Rust + Java, test, release
```

---

## Configuration

### Precedence (highest to lowest)

1. **Environment variables** -- highest priority, override everything (Docker-native)
2. **Config file** (TOML) -- `ibctl.toml`, path set via `IBCTL_CONFIG` env var or `--config` CLI arg
3. **Built-in defaults** -- lowest priority

Docker secrets (`_FILE` suffix) are supported for sensitive env vars. They read the file contents into the corresponding variable (e.g., `TWS_PASSWORD_FILE=/run/secrets/ib_password`).

**Security note**: Passwords and TOTP secrets are env-var-only (with `_FILE` support). They are never read from the config file to avoid accidentally committing secrets.

### Config File Format (`ibctl.toml`)

```toml
[auth]
username = "myuser"
# password via env var or _FILE only (never in config file)
trading_mode = "live"       # live | paper | both

[auth.paper]
username = "myuser_paper"   # only needed for dual mode

[twofa]
secret_env = "TWOFACTOR_CODE"  # env var name containing TOTP secret
provider = "oathtool"          # oathtool | builtin (v3)
timeout_action = "restart"     # restart | exit
timeout_seconds = 180

[gateway]
tws_path = "/home/ibgateway/Jts"
settings_path = ""             # defaults to tws_path
version = ""                   # auto-detect from tws_path
java_heap_mb = 768
program = "gateway"            # gateway | tws

[session]
action = "primary"             # primary | secondary | primaryoverride
accept_incoming = "accept"     # accept | reject | manual

[command_server]
enabled = true
port = 7462
bind_address = "0.0.0.0"
control_from = ["127.0.0.1"]   # IP allow-list

[agent]
socket_path = "/tmp/ibctl.sock"

[logging]
level = "info"                 # debug | info | warn | error

[timing]
ui_tick_ms = 100               # Rust-side delay between config dialog actions (ms)
agent_tick_ms = 50             # Java agent delay after each Swing click/type (ms)
post_login_delay_ms = 1000     # Wait after Login click before checking for 2FA (ms)
popup_quiet_secs = 5           # Seconds of no popups before considering login complete
popup_max_wait_secs = 30       # Max seconds to wait for popup dismissal
login_radio_delay_ms = 100     # Pause after radio button selection on login screen (ms)
```

### Environment Variable Reference

All env vars override their corresponding config file keys.

#### Authentication

| Variable | Config Key | Description | Default |
|----------|-----------|-------------|---------|
| `TWS_USERID` | `auth.username` | IB login username | required |
| `TWS_PASSWORD` / `_FILE` | -- | IB login password (env only) | required |
| `TRADING_MODE` | `auth.trading_mode` | `live`, `paper`, or `both` | `live` |
| `TWS_USERID_PAPER` | `auth.paper.username` | Paper account username | -- |
| `TWS_PASSWORD_PAPER` / `_FILE` | -- | Paper account password | -- |

#### Two-Factor Authentication

| Variable | Config Key | Description | Default |
|----------|-----------|-------------|---------|
| `TWOFACTOR_CODE` / `_FILE` | -- | TOTP base32 secret (env only) | optional |
| `TOTP_PROVIDER` | `twofa.provider` | `oathtool` or `builtin` | `oathtool` |
| `TWOFA_DEVICE` | -- | 2FA device name (`IB Key`, `Mobile Authenticator app`) | -- |
| `TWOFA_TIMEOUT_ACTION` | `twofa.timeout_action` | `restart`/`exit` on 2FA timeout | `restart` |
| `TWOFA_EXIT_INTERVAL` | `twofa.timeout_seconds` | Seconds to wait for 2FA | `180` |
| `RELOGIN_AFTER_TWOFA_TIMEOUT` | -- | `yes` to retry login on 2FA timeout | `yes` |

#### Post-Login API Configuration (applied via Global Configuration dialog)

| Variable | Description | Default |
|----------|-------------|---------|
| `TWS_MASTER_CLIENT_ID` | Master API client ID | -- |
| `READ_ONLY_API` | `yes` or `no` — API read-only mode | -- |
| `TWS_ACCEPT_INCOMING` | `accept`, `reject`, or `manual` — incoming API connections | `accept` |
| `BYPASS_WARNING` | `yes` to bypass all order precaution warnings | -- |
| `ALLOW_BLIND_TRADING` | `yes` or `no` — allow trading without market data | -- |
| `EXISTING_SESSION_DETECTED_ACTION` | `primary`, `secondary`, `primaryoverride` | `primary` |

#### Scheduling

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTO_RESTART_TIME` | Daily auto-restart time (e.g., `05:05 PM`) | -- |
| `AUTO_LOGOFF_TIME` | Auto-logoff time (e.g., `11:45 PM`) | -- |
| `TWS_COLD_RESTART` | Sunday cold restart time, 24h format (e.g., `09:00`) | -- |

#### Gateway Settings

| Variable | Config Key | Description | Default |
|----------|-----------|-------------|---------|
| `TWS_MAJOR_VRSN` | `gateway.version` | Gateway version | auto-detect |
| `TWS_PATH` | `gateway.tws_path` | TWS/Gateway install path | `/home/ibgateway/Jts` |
| `TWS_SETTINGS_PATH` | `gateway.settings_path` | Settings storage path | `$TWS_PATH` |
| `JAVA_HEAP_SIZE` | `gateway.java_heap_mb` | JVM heap in MB | `768` |
| `GATEWAY_OR_TWS` | `gateway.program` | `gateway` or `tws` | `gateway` |
| `TZ` | -- | Container timezone (e.g., `America/New_York`) | system default |
| `VNC_SERVER_PASSWORD` | -- | Enable VNC with this password | disabled |

#### Infrastructure

| Variable | Config Key | Description | Default |
|----------|-----------|-------------|---------|
| `IBCTL_COMMAND_PORT` | `command_server.port` | TCP command server port | `7462` |
| `IBCTL_CONTROL_FROM` | `command_server.control_from` | IP allow-list (comma-sep) | `127.0.0.1` |
| `IBCTL_AGENT_SOCKET` | `agent.socket_path` | UDS path for agent | `/tmp/ibctl.sock` |
| `IBCTL_LOG_LEVEL` | `logging.level` | Log verbosity | `info` |
| `IBCTL_CONFIG` | -- | Path to config file | `./ibctl.toml` |
| `IBCTL_AGENT_TICK_MS` | `timing.agent_tick_ms` | Java agent delay per action (ms) | `50` |

---

## JVM Launch

ibctl launches Gateway directly, replacing `ibcstart.sh`. IBC.jar is not on the classpath -- the Java agent replaces it entirely.

```
$JAVA_PATH/java \
  $MODULE_ACCESS_FLAGS \
  -cp $GATEWAY_CLASSPATH \       # jars/*.jar + i4jruntime.jar (NO IBC.jar)
  -javaagent:/path/to/ibctl-agent.jar=/tmp/ibctl.sock \
  $VM_OPTIONS \
  -DjtsConfigDir=$TWS_SETTINGS_PATH \
  -Dtwslaunch.autoupdate.serviceImpl=com.ib.tws.twslaunch.install4j.Install4jAutoUpdateService \
  -Dchannel=latest \
  -Dexe4j.isInstall4j=true \
  -DinstallType=standalone \
  ibgateway.GWClient                # Gateway's own main class
```

### Module Access Flags

Required for JDK 17 to allow Swing introspection (captured from ibcstart.sh):

```
--add-opens=java.base/java.util=ALL-UNNAMED
--add-opens=java.base/java.util.concurrent=ALL-UNNAMED
--add-exports=java.base/sun.util=ALL-UNNAMED
--add-exports=java.desktop/com.sun.java.swing.plaf.motif=ALL-UNNAMED
--add-opens=java.desktop/java.awt=ALL-UNNAMED
--add-opens=java.desktop/java.awt.dnd=ALL-UNNAMED
--add-opens=java.desktop/javax.swing=ALL-UNNAMED
--add-opens=java.desktop/javax.swing.event=ALL-UNNAMED
--add-opens=java.desktop/javax.swing.plaf.basic=ALL-UNNAMED
--add-opens=java.desktop/javax.swing.table=ALL-UNNAMED
--add-opens=java.desktop/sun.awt=ALL-UNNAMED
--add-exports=java.desktop/sun.awt.X11=ALL-UNNAMED
--add-exports=java.desktop/sun.swing=ALL-UNNAMED
--add-opens=jdk.management/com.sun.management.internal=ALL-UNNAMED
```

### Classpath Construction

The supervisor scans `$TWS_PATH/$VERSION/jars/*.jar` and appends `i4jruntime.jar`, building the full classpath dynamically. VM options are read from `$TWS_PATH/$VERSION/$PROGRAM.vmoptions` if present.

---

## Dual Mode (live + paper)

When `TRADING_MODE=both`:

1. Launch the first JVM for live mode with agent socket `/tmp/ibctl-live.sock`
2. Wait 15 seconds (matching current IBC behavior)
3. Launch the second JVM for paper mode with agent socket `/tmp/ibctl-paper.sock`
4. Run independent state machines per session
5. Use separate credentials: `TWS_USERID` for live, `TWS_USERID_PAPER` for paper
6. Use separate settings paths: `${TWS_SETTINGS_PATH}_live`, `${TWS_SETTINGS_PATH}_paper`

---

## Socat Port Forwarding

Gateway binds API ports to `127.0.0.1` only ("Allow connections from localhost only" is checked for security). Docker port mapping delivers from the bridge IP (172.x.x.x), which Gateway rejects. socat bridges external ports to localhost:

```
Host:4001 → Docker → Container:4003 → socat → 127.0.0.1:4001 (Gateway live)
Host:4002 → Docker → Container:4004 → socat → 127.0.0.1:4002 (Gateway paper)
```

ibctl **owns socat directly** — it is spawned from the Rust state machine only after the `ConfiguringApi` state completes. This eliminates race conditions where clients connect before API settings (Read-Only, Master Client ID, precaution bypasses) are applied. socat is killed on restart/shutdown and respawned on reconnect.

See the [Socat Port Forwarding wiki article](https://github.com/Lcstyle/ibctl/wiki/Socat-Port-Forwarding) for the full analysis.

## IPv4 Stack

Gateway must bind API ports to IPv4, not IPv6. The entrypoint sets `JDK_JAVA_OPTIONS=-Djava.net.preferIPv4Stack=true` before launching ibctl. Without this, Gateway binds to `:::4001` (IPv6 only) and IPv4 clients cannot connect.

## Sunday Cold Restart

IBKR requires a full re-login once a week (Sundays). Gateway does NOT have a built-in cold restart — this was an IBC feature that ibctl replicates.

ibctl runs a background timer that fires on Sunday at the `TWS_COLD_RESTART` time (24h format, respects `TZ` env var). When triggered:
1. Kills the JVM process
2. Resets all handler state (LoginHandler flag)
3. Relaunches with full re-authentication (including 2FA)

The timer only fires at the exact scheduled minute (not if the container starts after the time). A marker file in `TWS_SETTINGS_PATH` prevents re-triggering after a restart on the same day.

## Dialog Handlers

ibctl auto-handles these Gateway dialogs in the monitoring loop:

| Handler | Matches | Action |
|---------|---------|--------|
| LoginHandler | "IBKR Gateway", "IB Gateway", "Login" | Fill credentials, click Login (once per login cycle) |
| TotpEntryHandler | "Second Factor Authentication" | Enter TOTP code or wait for IB Key approval |
| SessionConflictHandler | "Existing session detected" | Click OK/Cancel based on session action config |
| SslReconnectHandler | "SSL", "Encryption" | Click "Reconnect using SSL" |
| ReloginHandler | "RE-LOGIN IS REQUIRED" | Click Cancel, return to login form for fresh re-auth |
| PaperWarningHandler | "Warning" (excludes "Configuration") | Click "I understand and accept" |
| TipOfDayHandler | "Tip of the Day" | Click Close/OK |
| AcceptConnectionHandler | "Accept incoming connection" | Accept/reject based on config |
| VersionNoticeHandler | "newer version", "update" | Click OK/dismiss |
| GatewayNotificationHandler | "IBKR Gateway" (small dialog) | Click Close/OK (catch-all for misc notifications) |

---

## Java Agent Key Classes

### IbctlAgent.java

The `premain()` entry point, invoked by the JVM before `main()`:

```java
public static void premain(String agentArgs, Instrumentation inst) {
    // Parse socket path from agentArgs (default: /tmp/ibctl.sock)
    // Start HTTP server on UDS in background daemon thread
    // Register AWT WindowListener for dialog detection
}
```

### SwingInspector.java

Provides Swing component introspection:

- `listWindows()` -- all visible Window instances with title, class, bounds
- `getComponentTree(Window)` -- recursive tree of all components
- `findTextField(Window, index)` -- JTextField by position (matching IBC pattern)
- `findButton(Window, label)` -- JButton by text label
- `clickButton(Window, label)` -- `SwingUtilities.invokeAndWait` + `doClick`
- `typeText(Window, fieldIndex, text)` -- `SwingUtilities.invokeAndWait` + `setText`
- `sendKey(Window, keyStroke)` -- dispatch KeyEvent

### HttpApi.java

JDK 17 built-in `com.sun.net.httpserver.HttpServer` bound to a `UnixDomainSocketAddress`:

```java
ServerSocketChannel channel = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
channel.bind(UnixDomainSocketAddress.of("/tmp/ibctl.sock"));
```

Custom `HttpHandler` implementations for each endpoint. JSON serialization via manual `StringBuilder` (zero external dependencies).

### WindowMonitor.java

Registers an `AWTEventListener` for `WindowEvent.WINDOW_OPENED` to detect new dialogs as they appear:

```java
Toolkit.getDefaultToolkit().addAWTEventListener(event -> {
    if (event.getID() == WindowEvent.WINDOW_OPENED) {
        // Record new window, notify any waiting requests
    }
}, AWTEvent.WINDOW_EVENT_MASK);
```

---

## Rust Dependencies

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
hyper = { version = "1", features = ["client", "http1"] }
hyper-util = "0.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
signal-hook = "0.3"
signal-hook-tokio = { version = "0.3", features = ["futures-v0_3"] }
nix = { version = "0.29", features = ["signal", "process"] }
log = "0.4"
env_logger = "0.11"
thiserror = "2"
toml = "0.8"
```

No `x11rb` needed in the initial version -- all UI interaction goes through the Java agent. `x11rb` is reserved for a future AT-SPI fallback path.
