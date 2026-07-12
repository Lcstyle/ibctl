#!/bin/bash
# ibctl entrypoint — replaces gnzsnz's run.sh + IBC
# Starts Xvfb, optional VNC, then ibctl (which launches Gateway directly)
# Supports TRADING_MODE=both (dual mode) by launching two ibctl instances
set -euo pipefail

# Mnemonic build badge — the SOURCE_HEX baked at docker build is already in
# IBCTL_BUILD_SHA; here we compute deploy-time (container-start) timestamps.
# TZ=America/New_York is the ops timezone; override with $BADGE_TZ if needed.
# Both values are re-exported so child processes (uvicorn dashboard) inherit.
export IBCTL_BUILD_TIME_HUMAN=$(TZ="${BADGE_TZ:-America/New_York}" date +'%a %b %-d %H:%M %Z' 2>/dev/null || echo "")
export IBCTL_BUILD_TIME_UTC=$(date -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "")

# Force IPv4 for Gateway API ports — without this, Gateway binds to IPv6
# and IPv4 clients can't connect. Matches gnzsnz's JDK_JAVA_OPTIONS setting.
export JDK_JAVA_OPTIONS="${JDK_JAVA_OPTIONS:--Djava.net.preferIPv4Stack=true}"

# --- Auto-update ibctl binaries ---
# The deploy script downloads binaries on the HOST and volume-mounts them.
# If /opt/ibctl/bin/ exists (volume mount), use those instead of baked-in.
if [ -f /opt/ibctl/bin/ibctl ] && [ -f /opt/ibctl/bin/ibctl-agent.jar ]; then
    echo "Using volume-mounted binaries from /opt/ibctl/bin/"
    cp /opt/ibctl/bin/ibctl /opt/ibctl/ibctl && chmod +x /opt/ibctl/ibctl
    cp /opt/ibctl/bin/ibctl-agent.jar /opt/ibctl/ibctl-agent.jar
fi

# --- Pre-flight config validation ---
# Validates TOML + env vars against Pydantic models before starting anything.
# Uses the dashboard's Python venv (Pydantic is already installed via FastAPI).
echo "Validating configuration..."
if ! PYTHONPATH=/opt/ibctl/dashboard /opt/ibctl/dashboard/.venv/bin/python -m app.preflight 2>&1; then
    echo "ERROR: Config validation failed. Fix the errors above and restart."
    exit 1
fi

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

# Start dashboard (FastAPI) — optional, disabled by default.
# Set IBCTL_DASHBOARD_ENABLED=true to enable.
#
# The dashboard runs inside a supervisor loop. Without the loop, if the
# Python process exits (uncaught exception, OOM, signal), nothing restarts
# it: PID 1 (this script) keeps running because the Gateway JVM is alive,
# so docker-compose's restart policy never fires. We observed a multi-day
# silent dashboard outage that masked every notification (cold-restart
# pre-warning, HITL 2FA pings) until an operator noticed.
#
# Backoff: a fixed 5s between restarts is enough to absorb the common
# "uvicorn crashed on startup once" case without thrashing if something
# is fundamentally broken. Each restart logs to stderr with the exit
# status so post-mortem grep of dashboard-<date>.log surfaces the
# pattern.
#
# Crash alert: on every uvicorn exit, post an ntfy alert with the exit
# code and the last 30 lines of teed stderr. Rate-limited to one per
# 5 min via a stamp file so a crashloop doesn't spam ntfy every 5s.
# Survives the SIGKILL/OOM/segfault cases that Python's sys.excepthook
# cannot catch — those are exactly the deaths a Python-side hook misses.
# Companion: the dashboard's lifespan startup hook reads the stamp on
# next successful boot and fires a "dashboard recovered" ntfy, then
# deletes the stamp.
DASHBOARD_LOG_DIR="${IBCTL_LOG_DIR:-/opt/ibctl/persist/logs}"
DASHBOARD_STDERR_LOG="${DASHBOARD_LOG_DIR}/uvicorn.stderr"
DASHBOARD_ALERT_STAMP="${DASHBOARD_LOG_DIR}/.dashboard_alert.stamp"
DASHBOARD_CRASH_STAMP="${DASHBOARD_LOG_DIR}/.dashboard_crash.stamp"
DASHBOARD_ALERT_COALESCE_SECS=300

notify_dashboard_crash() {
    local exit_code="$1"
    # Always drop the crash-recovery stamp so the next successful boot can
    # fire a "recovered" ntfy. Independent of whether we send the crash
    # alert below (which is rate-limited).
    local now
    now=$(date +%s)
    mkdir -p "${DASHBOARD_LOG_DIR}" 2>/dev/null || true
    printf '%s|%s\n' "${now}" "${exit_code}" > "${DASHBOARD_CRASH_STAMP}" 2>/dev/null || true

    # Honour the dashboard's own notification-enabled flag.
    if [ "${IBCTL_NOTIFICATIONS_ENABLED:-false}" != "true" ]; then
        return 0
    fi
    if [ -z "${IBCTL_NTFY_TOPIC:-}" ]; then
        return 0
    fi
    local ntfy_url="${IBCTL_NTFY_URL:-https://ntfy.sh}"

    # 5-minute coalesce so a crashloop emits one alert, not a phone barrage.
    local last
    last=$(cat "${DASHBOARD_ALERT_STAMP}" 2>/dev/null || echo 0)
    if [ $((now - last)) -lt "${DASHBOARD_ALERT_COALESCE_SECS}" ]; then
        return 0
    fi

    local tail_lines
    tail_lines=$(tail -n 30 "${DASHBOARD_STDERR_LOG}" 2>/dev/null || true)
    local host
    host=$(hostname 2>/dev/null || echo unknown)
    local body
    body=$(printf 'host=%s exit=%s\nrestart in 5s\n---\n%s' \
        "${host}" "${exit_code}" "${tail_lines}")

    local auth_header=()
    if [ -n "${IBCTL_NTFY_TOKEN:-}" ]; then
        auth_header=(-H "Authorization: Bearer ${IBCTL_NTFY_TOKEN}")
    fi
    curl -sS --max-time 5 \
        "${auth_header[@]}" \
        -H "Title: ibctl: dashboard crashed (exit=${exit_code})" \
        -H "Priority: urgent" \
        -H "Tags: rotating_light,skull" \
        -d "${body}" \
        "${ntfy_url}/${IBCTL_NTFY_TOPIC}" >/dev/null 2>&1 || true
    echo "${now}" > "${DASHBOARD_ALERT_STAMP}" 2>/dev/null || true
}
export -f notify_dashboard_crash
export DASHBOARD_LOG_DIR DASHBOARD_STDERR_LOG DASHBOARD_ALERT_STAMP \
       DASHBOARD_CRASH_STAMP DASHBOARD_ALERT_COALESCE_SECS

if [ "${IBCTL_DASHBOARD_ENABLED:-false}" = "true" ]; then
    DASHBOARD_PORT="${IBCTL_DASHBOARD_PORT:-8080}"
    echo "Starting dashboard on port ${DASHBOARD_PORT} (auto-restart on exit, ntfy on crash)"
    mkdir -p "${DASHBOARD_LOG_DIR}" 2>/dev/null || true
    (
        # Subshell so the loop's `cd` and locals don't leak into the
        # outer entrypoint. The supervisor loop itself becomes a single
        # backgrounded process from PID 1's perspective.
        #
        # CRITICAL: disable errexit inside the loop. The outer entrypoint
        # uses `set -euo pipefail`, which subshells inherit. With errexit
        # on, the FIRST non-zero exit from uvicorn (e.g. 137 from SIGKILL)
        # would terminate the subshell BEFORE the loop iterates — which is
        # exactly the bug the supervisor loop is supposed to prevent. We
        # explicitly turn it off here so a uvicorn crash drops into the
        # log+sleep+relaunch path instead of killing the supervisor.
        set +e
        cd /opt/ibctl/dashboard || exit 1
        # Cap the teed stderr file so a tight crashloop can't fill the
        # persist volume. Truncate-and-rotate when we cross 5 MB.
        rotate_stderr_if_large() {
            local size
            size=$(stat -c %s "${DASHBOARD_STDERR_LOG}" 2>/dev/null || echo 0)
            if [ "${size:-0}" -gt 5242880 ]; then
                mv -f "${DASHBOARD_STDERR_LOG}" "${DASHBOARD_STDERR_LOG}.1" 2>/dev/null || true
            fi
        }
        while true; do
            rotate_stderr_if_large
            # --log-level info (was: warning). At warning level uvicorn
            # SUPPRESSES its "Application startup failed: ..." traceback
            # line — a hidden contributor to the 2026-06-20 silent death.
            # tee preserves docker-logs visibility while writing a durable
            # copy under the persist volume for the crash hook to attach.
            .venv/bin/python -m uvicorn app.main:app \
                --host 0.0.0.0 --port "${DASHBOARD_PORT}" --log-level info \
                2> >(tee -a "${DASHBOARD_STDERR_LOG}" >&2)
            ds_exit=$?
            echo "Dashboard exited (status=${ds_exit}); restarting in 5s" >&2
            notify_dashboard_crash "${ds_exit}"
            sleep 5
        done
    ) &
    DASHBOARD_PID=$!
else
    echo "Dashboard disabled (set IBCTL_DASHBOARD_ENABLED=true to enable)"
fi

# Convert AUTO_RESTART_TIME from local time (TZ) to UTC
# IB Gateway always interprets this time in UTC regardless of TIME_ZONE setting
# See: https://github.com/IbcAlpha/IBC/issues/245
if [ -n "${AUTO_RESTART_TIME:-}" ] && [ -n "${TZ:-}" ] && [ "$TZ" != "Etc/UTC" ] && [ "$TZ" != "UTC" ]; then
    UTC_RESTART=$(python3 -c "
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import sys
try:
    local_tz = ZoneInfo('${TZ}')
    utc = ZoneInfo('UTC')
    # Parse the time (e.g. '05:05 PM')
    t = datetime.strptime('${AUTO_RESTART_TIME}', '%I:%M %p')
    # Attach today's date in local timezone
    now = datetime.now(local_tz)
    local_dt = now.replace(hour=t.hour, minute=t.minute, second=0, microsecond=0)
    # Convert to UTC
    utc_dt = local_dt.astimezone(utc)
    print(utc_dt.strftime('%I:%M %p').lstrip('0'))
except Exception as e:
    print('', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null) && {
        echo "Auto restart: ${AUTO_RESTART_TIME} ${TZ} -> ${UTC_RESTART} UTC"
        export AUTO_RESTART_TIME="$UTC_RESTART"
    }
fi

# Create jts.ini helper — ensures UseSSL=true and API-only mode
create_jts_ini() {
    local config_dir="$1"
    if [ ! -d "$config_dir" ]; then
        mkdir -p "$config_dir"
    fi
    # Always fix existing jts.ini before Gateway launches
    if [ -f "$config_dir/jts.ini" ]; then
        # Ensure ReadOnlyApi is off (prevents "API write access" warning race)
        if grep -q "ReadOnlyApi" "$config_dir/jts.ini"; then
            sed -i 's/ReadOnlyApi=.*/ReadOnlyApi=no/' "$config_dir/jts.ini"
        else
            sed -i '/^\[IBGateway\]/a ReadOnlyApi=no' "$config_dir/jts.ini"
        fi
        # NOTE: Gateway defaults to Africa/Abidjan (UTC) when running headless
        # and overwrites jts.ini on every login (recreates the file, so chmod
        # is useless). This is a known IB Gateway bug — gnzsnz documents it.
        # AUTO_RESTART_TIME must be specified in UTC, not local time.
        # See: https://github.com/IbcAlpha/IBC/issues/245
        # See: https://github.com/gnzsnz/ib-gateway-docker/issues/43
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

# No delay — each ibctl instance uses its own agent socket
# and manages its own JVM independently

# --- Paper instance ---
PAPER_SETTINGS="${TWS_SETTINGS_PATH:-/home/ibgateway/Jts}_paper"
create_jts_ini "$PAPER_SETTINGS"

# Paper uses separate credentials if provided
PAPER_USER="${TWS_USERID_PAPER:-$TWS_USERID}"
PAPER_PASS="${TWS_PASSWORD_PAPER:-$TWS_PASSWORD}"

# Read paper command server port from ibctl.toml (default 7463)
PAPER_CMD_PORT=$(grep -E '^\s*paper_port\s*=' /opt/ibctl/ibctl.toml | head -1 | sed 's/.*=\s*//;s/#.*//' | tr -d ' ' || echo "7463")
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
