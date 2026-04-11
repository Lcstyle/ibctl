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
pub(crate) enum ParsedCommand {
    Action(Command),
    Query(QueryType),
}

/// Query type without the response channel (used during parsing).
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
        // IB system status (pushed by dashboard)
        Some("IBSTATUS") => {
            let orig_parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
            let status = orig_parts.get(1).copied().unwrap_or("available").to_string();
            let reason = orig_parts.get(2).map(|s| s.trim_matches('"').to_string()).unwrap_or_default();
            Some(ParsedCommand::Action(Command::IbStatus(status, reason)))
        }
        // Set auto-restart time: SETRESTART 05:30 PM (UTC)
        Some("SETRESTART") => {
            let orig_parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            let time_str = orig_parts.get(1).copied().unwrap_or("").trim().to_string();
            if time_str.is_empty() {
                None
            } else {
                Some(ParsedCommand::Action(Command::SetRestartTime(time_str)))
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
                    let cmd_tx = command_tx.clone();
                    let qry_tx = query_tx.clone();
                    let snap_rx = snapshot_rx.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_connection(stream, peer_addr, &control_from, cmd_tx, qry_tx, snap_rx).await
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
    matches!(cmd, Command::SetState(_) | Command::Pause | Command::PauseAt(_) | Command::Exit)
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
        let addr: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(!is_allowed(&addr, &[]));
    }

    #[test]
    fn test_wildcard_allows_all() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(is_allowed(&addr, &["*".to_string()]));
    }

    #[test]
    fn test_exact_match() {
        let addr: IpAddr = "192.168.1.100".parse().unwrap();
        assert!(is_allowed(&addr, &["192.168.1.100".to_string()]));
    }

    #[test]
    fn test_exact_match_rejects_different_ip() {
        let addr: IpAddr = "192.168.1.101".parse().unwrap();
        assert!(!is_allowed(&addr, &["192.168.1.100".to_string()]));
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
        let addr: IpAddr = "10.0.0.5".parse().unwrap();
        assert!(is_allowed(&addr, &[
            "192.168.1.1".to_string(),
            "10.0.0.5".to_string(),
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
        let addr: IpAddr = "192.168.1.50".parse().unwrap();
        assert!(is_allowed(&addr, &["192.168.0.0/16".to_string()]));
    }

    #[test]
    fn test_cidr_slash_24_matches_subnet() {
        let addr: IpAddr = "10.0.1.99".parse().unwrap();
        assert!(is_allowed(&addr, &["10.0.1.0/24".to_string()]));
    }

    #[test]
    fn test_cidr_slash_24_rejects_outside_subnet() {
        let addr: IpAddr = "10.0.2.1".parse().unwrap();
        assert!(!is_allowed(&addr, &["10.0.1.0/24".to_string()]));
    }

    #[test]
    fn test_cidr_slash_32_is_exact_match() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(is_allowed(&addr, &["10.0.0.1/32".to_string()]));
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
}
