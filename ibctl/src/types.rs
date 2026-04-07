//! Shared types used across module boundaries.
//!
//! Domain newtypes and channel message types live here so that producer
//! modules (command_server, signals, cold_restart) and consumer modules
//! (state_machine) depend on shared type definitions rather than on each
//! other's implementation details.

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

/// A window identifier from the IB Gateway agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowId(pub u64);

impl std::fmt::Display for WindowId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A one-time TOTP code. Cannot be cloned — enforces single use.
#[allow(dead_code)]
pub struct TotpCode(String);

impl TotpCode {
    pub fn new(code: String) -> Self { Self(code) }
    /// Consume the code, returning the inner string.
    pub fn into_inner(self) -> String { self.0 }
}

// ---------------------------------------------------------------------------
// Channel message types — shared between producer and consumer modules
// ---------------------------------------------------------------------------

/// Action commands dispatched to the state machine (fire-and-forget).
/// Produced by: command_server (TCP commands from dashboard/CLI)
/// Consumed by: state_machine (main select loop)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Stop,
    Start,
    Restart,
    ReconnectData,
    ReconnectAccount,
    EnableApi,
    Exit,
    /// Restart socat port forwarding
    RestartSocat,
    /// Pause state machine — freeze in current state, still responds to queries.
    Pause,
    /// Pause at a specific state (ceiling) — state machine runs until it reaches this state
    PauseAt(String),
    /// Resume normal state transitions
    Resume,
    /// Force state machine to a specific state (God Mode)
    SetState(String),
    /// Set IB system status (pushed by dashboard/external clients)
    IbStatus(String, String), // (status, reason)
    /// Set auto-restart time via Gateway Settings UI (UTC, "HH:MM AM/PM" or "HH:MM")
    SetRestartTime(String),
}

/// Query commands that expect a JSON response via oneshot channel.
/// Produced by: command_server (TCP queries from dashboard/CLI)
/// Consumed by: state_machine (process_queries)
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

/// Signals that ibctl handles for lifecycle management.
/// Produced by: signals (OS signal handler)
/// Consumed by: state_machine (main select loop)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// SIGTERM — graceful shutdown requested (e.g., Docker stop)
    Terminate,
    /// SIGINT — interrupt (Ctrl+C)
    Interrupt,
}

/// Marker signal for the Sunday cold restart timer.
/// Produced by: cold_restart (background timer task)
/// Consumed by: state_machine (main select loop)
#[derive(Debug, Clone)]
pub struct ColdRestartSignal;
