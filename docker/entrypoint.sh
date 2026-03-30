#!/bin/bash
# ibctl entrypoint — replaces gnzsnz's run.sh + IBC
# Starts Xvfb, optional VNC, then ibctl (which launches Gateway directly)
# Supports TRADING_MODE=both (dual mode) by launching two ibctl instances
set -euo pipefail

# Force IPv4 for Gateway API ports — without this, Gateway binds to IPv6
# and IPv4 clients can't connect. Matches gnzsnz's JDK_JAVA_OPTIONS setting.
export JDK_JAVA_OPTIONS="${JDK_JAVA_OPTIONS:--Djava.net.preferIPv4Stack=true}"

echo "=========================================="
echo "  ibctl starting (mode=${TRADING_MODE:-live})"
echo "=========================================="

# Start Xvfb
DISPLAY=:1
export DISPLAY
rm -f /tmp/.X1-lock
Xvfb $DISPLAY -ac -screen 0 1024x768x16 &
XVFB_PID=$!

# Wait for X socket
echo "Waiting for Xvfb..."
timeout=50
elapsed=0
while [ ! -S "/tmp/.X11-unix/X1" ]; do
    sleep 0.2
    elapsed=$((elapsed + 1))
    if [ $elapsed -ge $timeout ]; then
        echo "ERROR: Timed out waiting for Xvfb"
        exit 1
    fi
done
echo "Xvfb ready"

# Optional VNC
if [ -n "${VNC_SERVER_PASSWORD:-}" ]; then
    echo "Starting VNC server"
    x11vnc -ncache_cr -display :1 -forever -shared -bg -noipv6 \
        -passwd "$VNC_SERVER_PASSWORD" &
fi

# Start websockify for noVNC (websocket proxy to VNC)
if [ -n "${VNC_SERVER_PASSWORD:-}" ]; then
    NOVNC_PORT="${IBCTL_NOVNC_PORT:-6080}"
    echo "Starting websockify on port ${NOVNC_PORT} -> VNC :5900"
    websockify --daemon ${NOVNC_PORT} localhost:5900
fi

# Start dashboard (FastAPI) — runs independently, connects to ibctl via TCP :7462
DASHBOARD_PORT="${IBCTL_DASHBOARD_PORT:-8080}"
echo "Starting dashboard on port ${DASHBOARD_PORT}"
cd /opt/ibctl/dashboard && .venv/bin/python -m uvicorn app.main:app \
    --host 0.0.0.0 --port "${DASHBOARD_PORT}" --log-level warning &
DASHBOARD_PID=$!

# Create jts.ini helper — ensures UseSSL=true and API-only mode
create_jts_ini() {
    local config_dir="$1"
    if [ ! -d "$config_dir" ]; then
        mkdir -p "$config_dir"
    fi
    # Always ensure ReadOnlyApi is off in existing jts.ini
    # This prevents the "API write access" warning race condition
    if [ -f "$config_dir/jts.ini" ]; then
        if grep -q "ReadOnlyApi" "$config_dir/jts.ini"; then
            sed -i 's/ReadOnlyApi=.*/ReadOnlyApi=no/' "$config_dir/jts.ini"
        else
            # Add to [IBGateway] section
            sed -i '/^\[IBGateway\]/a ReadOnlyApi=no' "$config_dir/jts.ini"
        fi
    fi
    if [ ! -f "$config_dir/jts.ini" ]; then
        echo "Creating jts.ini in $config_dir"
        if [ -f "${TWS_PATH:-/home/ibgateway/Jts}/jts.ini.tmpl" ]; then
            envsubst < "${TWS_PATH:-/home/ibgateway/Jts}/jts.ini.tmpl" > "$config_dir/jts.ini"
        else
            cat > "$config_dir/jts.ini" <<JTSEOF
[IBGateway]
WriteDebug=false
TrustedIPs=127.0.0.1
ApiOnly=true
ReadOnlyApi=no

[Logon]
Locale=en
TimeZone=${TIME_ZONE:-America/New_York}
displayedproxymsg=1
UseSSL=true
s3store=true

[Communication]
JTSEOF
        fi
    fi
}

# Trap for clean shutdown of all children
PIDS=()
cleanup() {
    echo "Shutting down..."
    # Stop ibctl instances
    for pid in "${PIDS[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    wait "${PIDS[@]}" 2>/dev/null || true
    echo "All instances stopped"
}
trap cleanup SIGINT SIGTERM

# --- socat port forwarding ---
# Gateway binds API to 127.0.0.1 inside the container.
# Docker port mapping delivers from the bridge IP (172.x.x.x), which
# Gateway rejects when "Allow connections from localhost only" is checked.
# socat bridges external-facing ports to localhost, matching gnzsnz's run.sh.
#
# Port convention (matches gnzsnz):
#   Live:  Gateway listens 127.0.0.1:4001, socat 0.0.0.0:4003 → 127.0.0.1:4001
#   Paper: Gateway listens 127.0.0.1:4002, socat 0.0.0.0:4004 → 127.0.0.1:4002
# socat is managed by ibctl directly — started only after configuration
# is complete, stopped on restart/shutdown. No shell-level socat needed.

# --- Single mode (live or paper) ---
if [ "${TRADING_MODE:-live}" != "both" ]; then
    JTS_CONFIG_DIR="${TWS_SETTINGS_PATH:-/home/ibgateway/Jts}"
    create_jts_ini "$JTS_CONFIG_DIR"

    echo "Starting ibctl in ${TRADING_MODE:-live} mode..."
    exec /opt/ibctl/ibctl --config /opt/ibctl/ibctl.toml
fi

# --- Dual mode (both live and paper) ---
# Mirrors gnzsnz's run.sh dual mode:
# 1. Start socat for both ports
# 2. Start live instance first
# 3. Wait 15 seconds
# 4. Start paper instance
# Each gets its own settings path, agent socket, and credentials

echo "=========================================="
echo "  DUAL MODE: starting live + paper"
echo "=========================================="

# --- Live instance ---
LIVE_SETTINGS="${TWS_SETTINGS_PATH:-/home/ibgateway/Jts}_live"
create_jts_ini "$LIVE_SETTINGS"

echo "Starting live instance..."
TRADING_MODE=live \
TWS_SETTINGS_PATH="$LIVE_SETTINGS" \
IBCTL_AGENT_SOCKET="/run/ibctl/agent-live.sock" \
/opt/ibctl/ibctl --config /opt/ibctl/ibctl.toml &
PIDS+=($!)
echo "Live instance PID: ${PIDS[-1]}"

# Wait before starting paper (matches gnzsnz's 15s delay)
echo "Waiting 15s before starting paper instance..."
sleep 15

# --- Paper instance ---
PAPER_SETTINGS="${TWS_SETTINGS_PATH:-/home/ibgateway/Jts}_paper"
create_jts_ini "$PAPER_SETTINGS"

# Paper uses separate credentials if provided
PAPER_USER="${TWS_USERID_PAPER:-$TWS_USERID}"
PAPER_PASS="${TWS_PASSWORD_PAPER:-$TWS_PASSWORD}"

# Read paper command server port from ibctl.toml (default 7463)
PAPER_CMD_PORT=$(grep -E '^\s*paper_port\s*=' /opt/ibctl/ibctl.toml | head -1 | sed 's/.*=\s*//' | tr -d ' ' || echo "7463")
[ -z "$PAPER_CMD_PORT" ] && PAPER_CMD_PORT=7463

echo "Starting paper instance (command server port: $PAPER_CMD_PORT)..."
TRADING_MODE=paper \
TWS_USERID="$PAPER_USER" \
TWS_PASSWORD="$PAPER_PASS" \
TWS_SETTINGS_PATH="$PAPER_SETTINGS" \
IBCTL_AGENT_SOCKET="/run/ibctl/agent-paper.sock" \
IBCTL_COMMAND_PORT="$PAPER_CMD_PORT" \
/opt/ibctl/ibctl --config /opt/ibctl/ibctl.toml &
PIDS+=($!)
echo "Paper instance PID: ${PIDS[-1]}"

echo "=========================================="
echo "  Both instances running"
echo "  Live PID:  ${PIDS[0]}"
echo "  Paper PID: ${PIDS[1]}"
echo "=========================================="

# Wait for either to exit
wait -n "${PIDS[@]}"
EXIT_CODE=$?
echo "An ibctl instance exited with code $EXIT_CODE"

# If one dies, stop the other
cleanup
exit $EXIT_CODE
