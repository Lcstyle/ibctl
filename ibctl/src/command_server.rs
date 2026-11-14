//! IBC wire-compatible TCP command server.
//!
//! Accepts line-based commands over TCP and dispatches them to the state machine.
//! Protocol: client sends `COMMAND\n`, server responds `OK message\n` or `ERROR message\n`.
//!
//! This is fully compatible with existing IBC tooling (e.g., gnzsnz scripts that send
//! commands like `STOP`, `RESTART`, `RECONNECTDATA` to port 7462).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// Maximum concurrent TCP connections to the command server.
const MAX_CONCURRENT_CONNECTIONS: usize = 10;

use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};

use crate::command_access::{command_name, unknown_names, CommandAccess};
use crate::config::CommandServerConfig;
use crate::types::{Command, Query, QuerySnapshot};

#[derive(Debug, Error)]
pub enum CommandServerError {
    #[error("failed to bind TCP listener on {addr}: {source}")]
    BindFailed {
        addr: String,
        source: std::io::Error,
    },
    #[error("connection error: {0}")]
    ConnectionError(#[from] std::io::Error),
}

/// Parsed input from a TCP command line — either an action or a query.
#[derive(Debug)]
pub(crate) enum ParsedCommand {
    Action(Command),
    Query(QueryType),
}

/// Query type without the response channel (used during parsing).
#[derive(Debug)]
pub(crate) enum QueryType {
    Status,
    State,
    Config,
    Logs(usize),
    Windows,
    /// Long-lived subscription: pushes NDJSON status events on every state change.
    Subscribe,
}

/// Parse a command string (case-insensitive) matching IBC's wire protocol,
/// extended with JSON query commands for the dashboard.
#[must_use]
pub(crate) fn parse_command(input: &str) -> Option<ParsedCommand> {
    let trimmed = input.trim();
    let upper = trimmed.to_uppercase();
    let parts: Vec<&str> = upper.split_whitespace().collect();

    match parts.first().copied() {
        // Legacy IBC action commands
        Some("STOP") => Some(ParsedCommand::Action(Command::Stop)),
        Some("START") => Some(ParsedCommand::Action(Command::Start)),
        Some("RESTART") => Some(ParsedCommand::Action(Command::Restart)),
        Some("RECONNECTDATA") => Some(ParsedCommand::Action(Command::ReconnectData)),
        Some("RECONNECTACCOUNT") => Some(ParsedCommand::Action(Command::ReconnectAccount)),
        Some("ENABLEAPI") => Some(ParsedCommand::Action(Command::EnableApi)),
        Some("EXIT") => Some(ParsedCommand::Action(Command::Exit)),
        Some("RESTARTSOCAT") => Some(ParsedCommand::Action(Command::RestartSocat)),
        // State machine control commands (God Mode)
        Some("PAUSE") => {
            // PAUSE with optional state name: "PAUSE WaitingForLogin"
            let orig_parts: Vec<&str> = trimmed.split_whitespace().collect();
            if let Some(state_name) = orig_parts.get(1) {
                Some(ParsedCommand::Action(Command::PauseAt(state_name.to_string())))
            } else {
                Some(ParsedCommand::Action(Command::Pause))
            }
        }
        Some("RESUME") => Some(ParsedCommand::Action(Command::Resume)),
        Some("HITL_RESUME") => Some(ParsedCommand::Action(Command::HitlResume)),
        Some("RESUME_RECONNECT") => {
            // Preserve original casing on the token; the argument is an
            // opaque signed value (the dashboard verifies its HMAC).
            let orig_parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            let token = orig_parts.get(1).copied().unwrap_or("").trim().to_string();
            if token.is_empty() {
                None
            } else {
                Some(ParsedCommand::Action(Command::ResumeReconnect(token)))
            }
        }
        // Host maintenance handshake. The id keeps its
        // original casing: the coordinator matches on it.
        Some("MAINT_HOLD") => {
            let orig: Vec<&str> = trimmed.split_whitespace().collect();
            match (orig.get(1), orig.get(2).and_then(|t| t.parse::<u64>().ok()), orig.len()) {
                (Some(id), Some(ttl_secs), 3) => Some(ParsedCommand::Action(Command::MaintHold {
                    id: id.to_string(),
                    ttl_secs,
                })),
                _ => None,
            }
        }
        Some("MAINT_RELEASE") => {
            let orig: Vec<&str> = trimmed.split_whitespace().collect();
            match (orig.get(1), orig.get(2), orig.len()) {
                (Some(id), Some(result), 3) => Some(ParsedCommand::Action(Command::MaintRelease {
                    id: id.to_string(),
                    result: result.to_string(),
                })),
                _ => None,
            }
        }
        Some("SETSTATE") => {
            // Use the original (non-uppercased) input to preserve state name casing
            let orig_parts: Vec<&str> = trimmed.split_whitespace().collect();
            let state_name = orig_parts.get(1).copied().unwrap_or("").to_string();
            if state_name.is_empty() {
                None
            } else {
                Some(ParsedCommand::Action(Command::SetState(state_name)))
            }
        }
        // IB system status (pushed by dashboard or future integrations).
        //
        // status: closed set — {available, unavailable, maintenance, degraded}.
        //   An unrecognized value would silently park the state machine in
        //   WaitingForIB (since `available = status == "available"`), which
        //   is a DoS in disguise if a well-meaning integration typos the
        //   value. Reject with ERROR instead.
        //
        // reason: stripped of control characters (newlines corrupt log-based
        //   monitoring via log-injection) and capped at 256 bytes.
        Some("IBSTATUS") => {
            let orig_parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
            let status_raw = orig_parts.get(1).copied().unwrap_or("available");
            let status = match status_raw {
                "available" | "unavailable" | "maintenance" | "degraded" => {
                    status_raw.to_string()
                }
                _ => return None,
            };
            let reason_raw = orig_parts
                .get(2)
                .map(|s| s.trim_matches('"'))
                .unwrap_or("");
            let reason: String = reason_raw
                .chars()
                .filter(|c| !c.is_control())
                .take(256)
                .collect();
            Some(ParsedCommand::Action(Command::IbStatus(status, reason)))
        }
        // Set the auto-restart time, in the Gateway's own time zone: SETRESTART 5:30 PM.
        // With no time, the Gateway restarts itself as soon as it can (warm).
        Some("SETRESTART") => {
            let orig_parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            let time_str = orig_parts.get(1).copied().unwrap_or("").trim().to_string();
            if time_str.is_empty() {
                // No time: restart as soon as the Gateway can, a warm restart.
                Some(ParsedCommand::Action(Command::SetRestartNow))
            } else if crate::gateway_zone::is_restart_time(&time_str) {
                Some(ParsedCommand::Action(Command::SetRestartTime(time_str)))
            } else {
                None
            }
        }
        // JSON query commands (for dashboard)
        Some("STATUS") => Some(ParsedCommand::Query(QueryType::Status)),
        Some("STATE") => Some(ParsedCommand::Query(QueryType::State)),
        Some("CONFIG") => Some(ParsedCommand::Query(QueryType::Config)),
        Some("LOGS") => {
            let limit = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(100);
            Some(ParsedCommand::Query(QueryType::Logs(limit)))
        }
        Some("WINDOWS") => Some(ParsedCommand::Query(QueryType::Windows)),
        Some("SUBSCRIBE") => Some(ParsedCommand::Query(QueryType::Subscribe)),
        _ => None,
    }
}

/// TCP command server compatible with IBC's line-based protocol.
pub struct CommandServer {
    config: CommandServerConfig,
}

impl CommandServer {
    pub fn new(config: CommandServerConfig) -> Self {
        Self { config }
    }

    /// Run the command server, listening for TCP connections and dispatching
    /// parsed commands/queries to the provided channels.
    pub async fn run(
        self,
        command_tx: mpsc::Sender<Command>,
        query_tx: mpsc::Sender<Query>,
        snapshot_rx: watch::Receiver<Arc<QuerySnapshot>>,
    ) -> Result<(), CommandServerError> {
        let addr = format!("{}:{}", self.config.bind_address, self.config.port);
        let listener = TcpListener::bind(&addr).await.map_err(|e| {
            CommandServerError::BindFailed {
                addr: addr.clone(),
                source: e,
            }
        })?;

        log::info!("Command server listening on {}", addr);

        let unknown = unknown_names(&self.config.allowed_commands);
        if !unknown.is_empty() {
            log::warn!(
                "command_server.allowed_commands names no ibctl command: {} (nothing is allowed by those names)",
                unknown.join(", "),
            );
        }
        let access = Arc::new(CommandAccess::new(&self.config.allowed_commands));
        log::info!("Command server accepts: {}", access.allowed().join(" "));

        // Limit concurrent connections to prevent resource exhaustion
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            log::warn!("Connection limit reached, rejecting {}", peer_addr);
                            drop(stream);
                            continue;
                        }
                    };
                    let control_from = self.config.control_from.clone();
                    let access = access.clone();
                    let cmd_tx = command_tx.clone();
                    let qry_tx = query_tx.clone();
                    let snap_rx = snapshot_rx.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_connection(stream, peer_addr, &control_from, &access, cmd_tx, qry_tx, snap_rx).await
                        {
                            log::error!("Error handling connection from {}: {}", peer_addr, e);
                        }
                        drop(permit); // release slot
                    });
                }
                Err(e) => {
                    log::error!("Failed to accept TCP connection: {}", e);
                }
            }
        }
    }
}

/// Handle a single TCP connection: read a command line, validate the sender's IP,
/// parse and dispatch the command, and send a response.
async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    control_from: &[String],
    access: &CommandAccess,
    command_tx: mpsc::Sender<Command>,
    query_tx: mpsc::Sender<Query>,
    snapshot_rx: watch::Receiver<Arc<QuerySnapshot>>,
) -> Result<(), CommandServerError> {
    if !is_allowed(&peer_addr.ip(), control_from) {
        log::warn!("Rejected connection from unauthorized IP: {}", peer_addr);
        stream.write_all(b"ERROR not authorized\n").await?;
        return Ok(());
    }

    let (reader, mut writer) = stream.split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    // Read one line with timeout (SEC-02 fix: prevents DoS via slow/stalled clients)
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        buf_reader.read_line(&mut line),
    ).await {
        Ok(Ok(0)) => return Ok(()),
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            log::error!("Failed to read from {}: {}", peer_addr, e);
            return Err(e.into());
        }
        Err(_) => {
            log::warn!("Read timeout from {} — closing connection", peer_addr);
            return Ok(());
        }
    }

    let trimmed = line.trim();
    log::debug!("Received from {}: {}", peer_addr, trimmed);

    match parse_command(trimmed) {
        Some(ParsedCommand::Action(cmd)) => {
            // The allow-list is the ceiling for every caller; queries are not subject to it.
            if !access.allows(&cmd) {
                log::warn!(
                    "Refused {} from {}: not in command_server.allowed_commands",
                    command_name(&cmd),
                    peer_addr,
                );
                writer.write_all(b"ERROR command not allowed by command_server.allowed_commands\n").await?;
                return Ok(());
            }
            // Privileged commands (SETSTATE, PAUSE, EXIT) require localhost
            if is_privileged_command(&cmd) && !is_localhost(&peer_addr.ip()) {
                log::warn!(
                    "Rejected privileged command from non-localhost IP {}: {}",
                    peer_addr, trimmed,
                );
                writer.write_all(b"ERROR privileged command requires localhost\n").await?;
                return Ok(());
            }
            let cmd_name = trimmed.to_uppercase();
            match command_tx.send(cmd).await {
                Ok(_) => {
                    writer.write_all(format!("OK {}\n", cmd_name).as_bytes()).await?;
                }
                Err(_) => {
                    writer.write_all(b"ERROR command channel closed\n").await?;
                }
            }
        }
        Some(ParsedCommand::Query(QueryType::Subscribe)) => {
            // Long-lived subscription: push NDJSON status events on every state change.
            // Uses the watch channel — wakes instantly when the state machine publishes
            // a new snapshot, zero polling. Holds the TCP connection open.
            log::info!("SUBSCRIBE from {} — starting event stream", peer_addr);
            let mut snap_rx = snapshot_rx.clone();

            // Send initial snapshot — clone data out of borrow before awaiting
            let (initial_line, initial_version) = {
                let snap = snap_rx.borrow_and_update();
                let line = format!(
                    "{{\"type\":\"snapshot\",\"version\":{},\"status\":{}}}\n",
                    snap.version, snap.status_json,
                );
                (line, snap.version)
            };
            writer.write_all(initial_line.as_bytes()).await?;

            let mut last_version = initial_version;
            loop {
                tokio::select! {
                    result = snap_rx.changed() => {
                        match result {
                            Ok(()) => {
                                let (version, status_json) = {
                                    let snap = snap_rx.borrow_and_update();
                                    (snap.version, snap.status_json.clone())
                                };
                                if version == last_version { continue; }
                                last_version = version;
                                let line = format!(
                                    "{{\"type\":\"status\",\"version\":{},\"status\":{}}}\n",
                                    version, status_json,
                                );
                                if writer.write_all(line.as_bytes()).await.is_err() {
                                    break; // client disconnected
                                }
                                if writer.flush().await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break, // watch channel closed (shutdown)
                        }
                    }
                    // Keepalive every 30s to detect dead connections
                    _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                        if writer.write_all(b"{\"type\":\"keepalive\"}\n").await.is_err() {
                            break;
                        }
                        if writer.flush().await.is_err() {
                            break;
                        }
                    }
                }
            }
            log::info!("SUBSCRIBE from {} — stream ended", peer_addr);
        }
        Some(ParsedCommand::Query(query_type)) => {
            // Hot-path queries: serve directly from the watch snapshot.
            // No mpsc round-trip, no blocking on the state machine loop.
            let snapshot_response = match query_type {
                QueryType::Status => Some(snapshot_rx.borrow().status_json.clone()),
                QueryType::State => Some(snapshot_rx.borrow().state_json.clone()),
                QueryType::Config => Some(snapshot_rx.borrow().config_json.clone()),
                _ => None, // LOGS, WINDOWS, SUBSCRIBE go through other paths
            };

            if let Some(json) = snapshot_response {
                writer.write_all(format!("OK {}\n", json).as_bytes()).await?;
            } else {
                // Slow-path queries (WINDOWS, LOGS): go through mpsc/oneshot
                let (resp_tx, resp_rx) = oneshot::channel();
                let query = match query_type {
                    QueryType::Logs(n) => Query::Logs(n, resp_tx),
                    QueryType::Windows => Query::Windows(resp_tx),
                    _ => unreachable!(), // STATUS/STATE/CONFIG/SUBSCRIBE handled above
                };

                match query_tx.send(query).await {
                    Ok(_) => {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            resp_rx,
                        ).await {
                            Ok(Ok(json)) => {
                                writer.write_all(format!("OK {}\n", json).as_bytes()).await?;
                            }
                            Ok(Err(_)) => {
                                writer.write_all(b"ERROR query response channel dropped\n").await?;
                            }
                            Err(_) => {
                                writer.write_all(b"ERROR query timeout\n").await?;
                            }
                        }
                    }
                    Err(_) => {
                        writer.write_all(b"ERROR query channel closed\n").await?;
                    }
                }
            }
        }
        None => {
            writer.write_all(format!("ERROR unknown command: {}\n", trimmed).as_bytes()).await?;
        }
    }

    Ok(())
}

/// Returns true if the command requires localhost-only access.
/// Privileged commands (SETSTATE, PAUSE, EXIT) can manipulate the state machine
/// in dangerous ways — they must not be accessible from the Docker network.
fn is_privileged_command(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::SetState(_)
            | Command::Pause
            | Command::PauseAt(_)
            | Command::Exit
            | Command::HitlResume
            | Command::ResumeReconnect(_)
            | Command::MaintHold { .. }
            | Command::MaintRelease { .. },
    )
}

/// Returns true if the address is loopback (127.0.0.1 or ::1).
fn is_localhost(addr: &IpAddr) -> bool {
    addr.is_loopback()
}

/// Check whether a client IP is in the allow-list.
///
/// Supports exact IP match, CIDR notation (e.g. "172.0.0.0/8"), and wildcard ("*").
/// An empty allow-list rejects all connections.
pub(crate) fn is_allowed(addr: &IpAddr, control_from: &[String]) -> bool {
    if control_from.is_empty() {
        return false;
    }

    let addr_str = addr.to_string();
    for allowed in control_from {
        let allowed = allowed.trim();
        if allowed == "*" {
            return true;
        }
        if allowed == addr_str {
            return true;
        }
        // CIDR notation: "network/prefix"
        if let Some((network_str, prefix_str)) = allowed.split_once('/') {
            if let (Ok(network), Ok(prefix_len)) =
                (network_str.parse::<IpAddr>(), prefix_str.parse::<u32>())
            {
                if cidr_contains(&network, prefix_len, addr) {
                    return true;
                }
            }
        }
        // Handle loopback equivalence: if allowed is 127.0.0.1, also accept ::1
        if allowed == "127.0.0.1" && addr_str == "::1" {
            return true;
        }
        if allowed == "::1" && addr_str == "127.0.0.1" {
            return true;
        }
    }

    false
}

/// Check if `addr` falls within the CIDR block defined by `network`/`prefix_len`.
fn cidr_contains(network: &IpAddr, prefix_len: u32, addr: &IpAddr) -> bool {
    match (network, addr) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            if prefix_len > 32 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = u32::MAX.checked_shl(32 - prefix_len).unwrap_or(0);
            (u32::from(*net) & mask) == (u32::from(*ip) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            if prefix_len > 128 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = u128::MAX.checked_shl(128 - prefix_len).unwrap_or(0);
            (u128::from(*net) & mask) == (u128::from(*ip) & mask)
        }
        _ => false, // v4 network vs v6 addr or vice versa
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    // --- is_allowed tests ---

    #[test]
    fn test_empty_allowlist_rejects_all() {
        let addr: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(!is_allowed(&addr, &[]));
    }

    #[test]
    fn test_wildcard_allows_all() {
        let addr: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(is_allowed(&addr, &["*".to_string()]));
    }

    #[test]
    fn test_exact_match() {
        let addr: IpAddr = "192.0.2.100".parse().unwrap();
        assert!(is_allowed(&addr, &["192.0.2.100".to_string()]));
    }

    #[test]
    fn test_exact_match_rejects_different_ip() {
        let addr: IpAddr = "192.0.2.101".parse().unwrap();
        assert!(!is_allowed(&addr, &["192.0.2.100".to_string()]));
    }

    #[test]
    fn test_setrestart_with_no_time_means_restart_now() {
        assert!(matches!(parse_command("SETRESTART"), Some(ParsedCommand::Action(Command::SetRestartNow))));
        assert!(matches!(parse_command("setrestart   "), Some(ParsedCommand::Action(Command::SetRestartNow))));
    }

    #[test]
    fn test_setrestart_with_a_time_keeps_it_and_rejects_a_malformed_one() {
        match parse_command("SETRESTART 5:30 PM") {
            Some(ParsedCommand::Action(Command::SetRestartTime(t))) => assert_eq!(t, "5:30 PM"),
            other => panic!("expected SetRestartTime, got {other:?}"),
        }
        for bad in ["SETRESTART 17:30", "SETRESTART soon", "SETRESTART 5:30 XM", "SETRESTART 13:00 PM"] {
            assert!(parse_command(bad).is_none(), "{bad} must be rejected");
        }
    }

    #[test]
    fn test_loopback_ipv4_allows_ipv6() {
        let addr: IpAddr = "::1".parse().unwrap();
        assert!(is_allowed(&addr, &["127.0.0.1".to_string()]));
    }

    #[test]
    fn test_loopback_ipv6_allows_ipv4() {
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_allowed(&addr, &["::1".to_string()]));
    }

    #[test]
    fn test_multiple_allowed_ips() {
        let addr: IpAddr = "198.51.100.5".parse().unwrap();
        assert!(is_allowed(&addr, &[
            "192.0.2.1".to_string(),
            "198.51.100.5".to_string(),
        ]));
    }

    // CIDR tests — these FAIL with current implementation (the known bug)
    #[test]
    fn test_cidr_slash_8_matches_subnet() {
        let addr: IpAddr = "172.17.0.2".parse().unwrap();
        assert!(is_allowed(&addr, &["172.0.0.0/8".to_string()]));
    }

    #[test]
    fn test_cidr_slash_16_matches_subnet() {
        let addr: IpAddr = "192.0.2.50".parse().unwrap();
        assert!(is_allowed(&addr, &["192.0.0.0/16".to_string()]));
    }

    #[test]
    fn test_cidr_slash_24_matches_subnet() {
        let addr: IpAddr = "203.0.113.99".parse().unwrap();
        assert!(is_allowed(&addr, &["203.0.113.0/24".to_string()]));
    }

    #[test]
    fn test_cidr_slash_24_rejects_outside_subnet() {
        let addr: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(!is_allowed(&addr, &["203.0.113.0/24".to_string()]));
    }

    #[test]
    fn test_cidr_slash_32_is_exact_match() {
        let addr: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(is_allowed(&addr, &["198.51.100.1/32".to_string()]));
    }

    #[test]
    fn test_mixed_exact_and_cidr() {
        let addr: IpAddr = "172.18.0.3".parse().unwrap();
        assert!(is_allowed(&addr, &[
            "127.0.0.1".to_string(),
            "172.0.0.0/8".to_string(),
        ]));
    }

    // --- parse_command tests ---

    #[test]
    fn test_parse_stop() {
        match parse_command("STOP") {
            Some(ParsedCommand::Action(Command::Stop)) => {}
            _ => panic!("Expected Action(Stop)"),
        }
    }

    #[test]
    fn test_parse_restart() {
        match parse_command("restart") {
            Some(ParsedCommand::Action(Command::Restart)) => {}
            _ => panic!("Expected Action(Restart)"),
        }
    }

    #[test]
    fn test_parse_case_insensitive() {
        match parse_command("ReConnectData") {
            Some(ParsedCommand::Action(Command::ReconnectData)) => {}
            _ => panic!("Expected Action(ReconnectData)"),
        }
    }

    #[test]
    fn test_parse_with_whitespace() {
        match parse_command("  STOP  \n") {
            Some(ParsedCommand::Action(Command::Stop)) => {}
            _ => panic!("Expected Action(Stop)"),
        }
    }

    #[test]
    fn test_parse_unknown_returns_none() {
        assert!(parse_command("INVALID").is_none());
        assert!(parse_command("").is_none());
    }

    #[test]
    fn test_parse_status_query() {
        match parse_command("STATUS") {
            Some(ParsedCommand::Query(QueryType::Status)) => {}
            _ => panic!("Expected Query(Status)"),
        }
    }

    #[test]
    fn test_parse_logs_with_limit() {
        match parse_command("LOGS 50") {
            Some(ParsedCommand::Query(QueryType::Logs(50))) => {}
            _ => panic!("Expected Query(Logs(50))"),
        }
    }

    #[test]
    fn test_parse_logs_default_limit() {
        match parse_command("LOGS") {
            Some(ParsedCommand::Query(QueryType::Logs(100))) => {}
            _ => panic!("Expected Query(Logs(100))"),
        }
    }

    #[test]
    fn test_parse_all_query_types() {
        assert!(matches!(parse_command("STATE"), Some(ParsedCommand::Query(QueryType::State))));
        assert!(matches!(parse_command("CONFIG"), Some(ParsedCommand::Query(QueryType::Config))));
        assert!(matches!(parse_command("WINDOWS"), Some(ParsedCommand::Query(QueryType::Windows))));
    }

    #[test]
    fn test_parse_start() {
        match parse_command("START") {
            Some(ParsedCommand::Action(Command::Start)) => {}
            _ => panic!("Expected Action(Start)"),
        }
    }

    #[test]
    fn test_start_is_not_privileged() {
        assert!(!is_privileged_command(&Command::Start));
    }

    #[test]
    fn test_parse_all_action_types() {
        assert!(matches!(parse_command("STOP"), Some(ParsedCommand::Action(Command::Stop))));
        assert!(matches!(parse_command("START"), Some(ParsedCommand::Action(Command::Start))));
        assert!(matches!(parse_command("RESTART"), Some(ParsedCommand::Action(Command::Restart))));
        assert!(matches!(parse_command("RECONNECTDATA"), Some(ParsedCommand::Action(Command::ReconnectData))));
        assert!(matches!(parse_command("RECONNECTACCOUNT"), Some(ParsedCommand::Action(Command::ReconnectAccount))));
        assert!(matches!(parse_command("ENABLEAPI"), Some(ParsedCommand::Action(Command::EnableApi))));
        assert!(matches!(parse_command("EXIT"), Some(ParsedCommand::Action(Command::Exit))));
    }

    // --- privileged command tests ---

    #[test]
    fn test_setstate_is_privileged() {
        assert!(is_privileged_command(&Command::SetState("Connected".into())));
    }

    #[test]
    fn test_pause_is_privileged() {
        assert!(is_privileged_command(&Command::Pause));
    }

    #[test]
    fn test_exit_is_privileged() {
        assert!(is_privileged_command(&Command::Exit));
    }

    #[test]
    fn test_stop_is_not_privileged() {
        assert!(!is_privileged_command(&Command::Stop));
    }

    #[test]
    fn test_restart_is_not_privileged() {
        assert!(!is_privileged_command(&Command::Restart));
    }

    #[test]
    fn test_ibstatus_is_not_privileged() {
        assert!(!is_privileged_command(&Command::IbStatus("available".into(), "".into())));
    }

    #[test]
    fn test_localhost_ipv4() {
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_localhost(&addr));
    }

    #[test]
    fn test_localhost_ipv6() {
        let addr: IpAddr = "::1".parse().unwrap();
        assert!(is_localhost(&addr));
    }

    #[test]
    fn test_docker_ip_not_localhost() {
        let addr: IpAddr = "172.17.0.3".parse().unwrap();
        assert!(!is_localhost(&addr));
    }

    // --- IBSTATUS input validation ---

    #[test]
    fn ibstatus_accepts_closed_set_values() {
        for s in ["available", "unavailable", "maintenance", "degraded"] {
            let cmd = parse_command(&format!("IBSTATUS {} ok", s));
            match cmd {
                Some(ParsedCommand::Action(Command::IbStatus(status, reason))) => {
                    assert_eq!(status, s);
                    assert_eq!(reason, "ok");
                }
                other => panic!("IBSTATUS {} should parse; got {:?}", s, other),
            }
        }
    }

    #[test]
    fn ibstatus_rejects_unknown_status_values() {
        for bad in ["MAINT", "AVAILABLE", "unknown", "partial-outage", "offline", ""] {
            let cmd = parse_command(&format!("IBSTATUS {} reason", bad));
            assert!(
                cmd.is_none(),
                "IBSTATUS {:?} should be rejected to avoid silent WaitingForIB",
                bad
            );
        }
    }

    #[test]
    fn ibstatus_strips_control_chars_from_reason() {
        let cmd = parse_command("IBSTATUS unavailable \"maint\n2026-04-16 fake\tlog\"");
        match cmd {
            Some(ParsedCommand::Action(Command::IbStatus(_, reason))) => {
                assert!(
                    !reason.contains('\n') && !reason.contains('\t'),
                    "control chars must be stripped to prevent log injection; got {:?}",
                    reason
                );
                assert!(reason.contains("maint"), "printable chars must survive");
            }
            other => panic!("expected IBSTATUS to parse; got {:?}", other),
        }
    }

    // --- RESUME_RECONNECT parsing ---

    #[test]
    fn resume_reconnect_rejects_empty_token() {
        // A bare `RESUME_RECONNECT` with no argument must NOT parse —
        // downstream, the state machine mints the resume token using
        // `nonce_material: token_str`, and an empty string collapses the
        // single-use nonce invariant (all `RESUME_RECONNECT<empty>`
        // taps in the same wall-second would produce the same hash).
        // Fail-fast at the parser so operators see the ERROR immediately.
        assert!(parse_command("RESUME_RECONNECT").is_none());
        assert!(parse_command("RESUME_RECONNECT   ").is_none());
    }

    #[test]
    fn resume_reconnect_preserves_token_original_casing() {
        // The token payload MUST NOT be uppercased — the dashboard
        // HMAC-verifies it against a dashboard-signed URL where the token is
        // case-sensitive. The wire format uses `splitn(2, ' ')` on the
        // ORIGINAL (non-uppercased) input, so casing must survive.
        match parse_command("RESUME_RECONNECT AbCdEf-123-XyZ") {
            Some(ParsedCommand::Action(Command::ResumeReconnect(t))) => {
                assert_eq!(t, "AbCdEf-123-XyZ");
            }
            other => panic!("expected ResumeReconnect with preserved casing, got {:?}", other),
        }
    }

    #[test]
    fn resume_reconnect_is_privileged_command() {
        // Privileged → localhost-only. The three-phase recovery fail-
        // safe leans on this gate to keep container-network peers from
        // firing the resume path.
        assert!(is_privileged_command(&Command::ResumeReconnect("any".into())));
    }

    // The host maintenance handshake.

    #[test]
    fn maint_hold_parses_its_id_verbatim_and_its_ttl() {
        match parse_command("MAINT_HOLD 2026-10-04.Runtime 1200") {
            Some(ParsedCommand::Action(Command::MaintHold { id, ttl_secs })) => {
                assert_eq!(id, "2026-10-04.Runtime");
                assert_eq!(ttl_secs, 1200);
            }
            other => panic!("expected MaintHold, got {other:?}"),
        }
        assert!(parse_command("MAINT_HOLD m1").is_none(), "no TTL");
        assert!(parse_command("MAINT_HOLD m1 soon").is_none(), "TTL not a number");
        assert!(parse_command("MAINT_HOLD").is_none());
    }

    #[test]
    fn maint_release_parses_its_id_and_result() {
        match parse_command("maint_release 2026-10-04.Runtime ok") {
            Some(ParsedCommand::Action(Command::MaintRelease { id, result })) => {
                assert_eq!(id, "2026-10-04.Runtime");
                assert_eq!(result, "ok");
            }
            other => panic!("expected MaintRelease, got {other:?}"),
        }
        assert!(parse_command("MAINT_RELEASE m1").is_none(), "the result is required");
    }

    #[test]
    fn the_maintenance_handshake_is_localhost_only() {
        assert!(is_privileged_command(&Command::MaintHold { id: "m".into(), ttl_secs: 60 }));
        assert!(is_privileged_command(&Command::MaintRelease { id: "m".into(), result: "ok".into() }));
    }

    #[test]
    fn ibstatus_caps_reason_at_256_bytes() {
        let long = "x".repeat(1024);
        let cmd = parse_command(&format!("IBSTATUS unavailable {}", long));
        match cmd {
            Some(ParsedCommand::Action(Command::IbStatus(_, reason))) => {
                assert_eq!(
                    reason.len(),
                    256,
                    "reason must be capped at 256 chars to bound memory"
                );
            }
            other => panic!("expected IBSTATUS to parse; got {:?}", other),
        }
    }

    // --- allowed_commands, end to end over a real connection ---

    /// Serve one connection from `peer`'s point of view with `allowed` as the
    /// list, send `line`, and return the reply plus whatever reached the
    /// state machine's command channel.
    async fn exchange(allowed: &[&str], line: &str) -> (String, Option<Command>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (command_tx, mut command_rx) = mpsc::channel(4);
        let (query_tx, _query_rx) = mpsc::channel(4);
        let (_snapshot_tx, snapshot_rx) = watch::channel(Arc::new(QuerySnapshot::initializing()));
        let access = CommandAccess::new(&allowed.iter().map(|s| s.to_string()).collect::<Vec<_>>());

        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            handle_connection(stream, peer, &["*".to_string()], &access, command_tx, query_tx, snapshot_rx)
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(format!("{line}\n").as_bytes()).await.unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        server.await.unwrap();
        (reply.trim().to_string(), command_rx.try_recv().ok())
    }

    #[tokio::test]
    async fn a_command_outside_the_list_is_refused_and_never_reaches_the_state_machine() {
        let (reply, delivered) = exchange(&["SETRESTART"], "STOP").await;

        assert_eq!(reply, "ERROR command not allowed by command_server.allowed_commands");
        assert!(delivered.is_none());
    }

    #[tokio::test]
    async fn a_command_in_the_list_goes_through() {
        let (reply, delivered) = exchange(&["SETRESTART"], "SETRESTART").await;

        assert_eq!(reply, "OK SETRESTART");
        assert!(matches!(delivered, Some(Command::SetRestartNow)));
    }

    #[tokio::test]
    async fn the_name_in_the_list_covers_the_command_with_an_argument() {
        let (reply, delivered) = exchange(&["setrestart"], "SETRESTART 5:05 PM").await;

        assert_eq!(reply, "OK SETRESTART 5:05 PM");
        assert!(matches!(delivered, Some(Command::SetRestartTime(t)) if t == "5:05 PM"));
    }

    #[tokio::test]
    async fn queries_are_allowed_whatever_the_list_says() {
        let (reply, delivered) = exchange(&["SETRESTART"], "STATUS").await;

        assert!(reply.starts_with("OK {"), "{reply}");
        assert!(delivered.is_none());
    }

    #[tokio::test]
    async fn an_unknown_command_still_gets_the_unknown_reply() {
        let (reply, _) = exchange(&["SETRESTART"], "FROBNICATE").await;

        assert_eq!(reply, "ERROR unknown command: FROBNICATE");
    }

    #[tokio::test]
    async fn a_privileged_command_in_the_list_stays_privileged() {
        // The list allows EXIT; being listed does not make it unprivileged. (A client on
        // loopback is all this test can be, so it checks the allowed path and that the
        // privilege classification is unchanged.)
        let (reply, delivered) = exchange(&["EXIT"], "EXIT").await;
        assert_eq!(reply, "OK EXIT");
        assert!(matches!(delivered, Some(Command::Exit)));
        assert!(is_privileged_command(&Command::Exit));
        assert!(!is_privileged_command(&Command::SetRestartNow));
    }
}
