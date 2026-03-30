//! IBC wire-compatible TCP command server.
//!
//! Accepts line-based commands over TCP and dispatches them to the state machine.
//! Protocol: client sends `COMMAND\n`, server responds `OK message\n` or `ERROR message\n`.
//!
//! This is fully compatible with existing IBC tooling (e.g., gnzsnz scripts that send
//! commands like `STOP`, `RESTART`, `RECONNECTDATA` to port 7462).

use std::net::{IpAddr, SocketAddr};

use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use crate::config::CommandServerConfig;

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

/// Action commands dispatched to the state machine (fire-and-forget).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Stop,
    Restart,
    ReconnectData,
    ReconnectAccount,
    EnableApi,
    Exit,
}

/// Query commands that expect a JSON response via oneshot channel.
pub enum Query {
    /// Full gateway status with client advisory
    Status(oneshot::Sender<String>),
    /// State machine state + transition history
    State(oneshot::Sender<String>),
    /// Running config (passwords masked)
    Config(oneshot::Sender<String>),
    /// Last N log lines
    Logs(usize, oneshot::Sender<String>),
    /// Current Gateway windows + client tabs
    Windows(oneshot::Sender<String>),
}

impl std::fmt::Debug for Query {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Query::Status(_) => write!(f, "Query::Status"),
            Query::State(_) => write!(f, "Query::State"),
            Query::Config(_) => write!(f, "Query::Config"),
            Query::Logs(n, _) => write!(f, "Query::Logs({})", n),
            Query::Windows(_) => write!(f, "Query::Windows"),
        }
    }
}

/// Parsed input from a TCP command line — either an action or a query.
enum ParsedCommand {
    Action(Command),
    Query(QueryType),
}

/// Query type without the response channel (used during parsing).
enum QueryType {
    Status,
    State,
    Config,
    Logs(usize),
    Windows,
}

/// Parse a command string (case-insensitive) matching IBC's wire protocol,
/// extended with JSON query commands for the dashboard.
fn parse_command(input: &str) -> Option<ParsedCommand> {
    let trimmed = input.trim();
    let upper = trimmed.to_uppercase();
    let parts: Vec<&str> = upper.split_whitespace().collect();

    match parts.first().copied() {
        // Legacy IBC action commands
        Some("STOP") => Some(ParsedCommand::Action(Command::Stop)),
        Some("RESTART") => Some(ParsedCommand::Action(Command::Restart)),
        Some("RECONNECTDATA") => Some(ParsedCommand::Action(Command::ReconnectData)),
        Some("RECONNECTACCOUNT") => Some(ParsedCommand::Action(Command::ReconnectAccount)),
        Some("ENABLEAPI") => Some(ParsedCommand::Action(Command::EnableApi)),
        Some("EXIT") => Some(ParsedCommand::Action(Command::Exit)),
        // JSON query commands (for dashboard)
        Some("STATUS") => Some(ParsedCommand::Query(QueryType::Status)),
        Some("STATE") => Some(ParsedCommand::Query(QueryType::State)),
        Some("CONFIG") => Some(ParsedCommand::Query(QueryType::Config)),
        Some("LOGS") => {
            let limit = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(100);
            Some(ParsedCommand::Query(QueryType::Logs(limit)))
        }
        Some("WINDOWS") => Some(ParsedCommand::Query(QueryType::Windows)),
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
    ) -> Result<(), CommandServerError> {
        let addr = format!("{}:{}", self.config.bind_address, self.config.port);
        let listener = TcpListener::bind(&addr).await.map_err(|e| {
            CommandServerError::BindFailed {
                addr: addr.clone(),
                source: e,
            }
        })?;

        log::info!("Command server listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let control_from = self.config.control_from.clone();
                    let cmd_tx = command_tx.clone();
                    let qry_tx = query_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_connection(stream, peer_addr, &control_from, cmd_tx, qry_tx).await
                        {
                            log::error!("Error handling connection from {}: {}", peer_addr, e);
                        }
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
        Some(ParsedCommand::Query(query_type)) => {
            // Create a oneshot channel for the response
            let (resp_tx, resp_rx) = oneshot::channel();

            let query = match query_type {
                QueryType::Status => Query::Status(resp_tx),
                QueryType::State => Query::State(resp_tx),
                QueryType::Config => Query::Config(resp_tx),
                QueryType::Logs(n) => Query::Logs(n, resp_tx),
                QueryType::Windows => Query::Windows(resp_tx),
            };

            match query_tx.send(query).await {
                Ok(_) => {
                    // Wait for response from the state machine (with timeout)
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
        None => {
            writer.write_all(format!("ERROR unknown command: {}\n", trimmed).as_bytes()).await?;
        }
    }

    Ok(())
}

/// Check whether a client IP is in the allow-list.
///
/// Supports both exact IP match and wildcard entries.
/// An empty allow-list rejects all connections.
fn is_allowed(addr: &IpAddr, control_from: &[String]) -> bool {
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
