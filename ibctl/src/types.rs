//! Shared types used across module boundaries.
//!
//! Domain newtypes and channel message types live here so that producer
//! modules (command_server, signals, cold_restart) and consumer modules
//! (state_machine) depend on shared type definitions rather than on each
//! other's implementation details.

use std::time::Instant;

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
    /// Resume from HITL 2FA wait — operator signal that 2FA is approved.
    ///
    /// Privileged (localhost-only). Only takes effect when the state machine
    /// is in `State::WaitingForHitl2fa`; ignored in all other states.
    HitlResume,
    /// Resume from three-phase recovery `GivenUp` — operator tapped the
    /// signed callback URL on the ntfy give-up alert. Argument is the
    /// opaque resume-token string; stage 3 accepts any non-empty value
    /// (stage 5 adds HMAC verification against the dashboard-signed URL).
    ///
    /// Privileged (localhost-only). Only takes effect when the recovery
    /// coordinator is in `RecoveryPhase::GivenUp`; ignored otherwise.
    ResumeReconnect(String),
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
/// Produced by: signals (OS signal handler), recovery coordinator
/// Consumed by: state_machine (main select loop), external subscribers
///
/// `Copy` was intentionally dropped in PR-C stage 5 when `RecoveryGaveUp`
/// landed: the variant carries a `String` (mode) and a `jiff::Zoned`
/// (phase_entered_at), neither of which is `Copy`. Existing OS-signal
/// pattern matches on `Signal::Terminate | Signal::Interrupt` still work
/// because `Clone` is preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    /// SIGTERM — graceful shutdown requested (e.g., Docker stop)
    Terminate,
    /// SIGINT — interrupt (Ctrl+C)
    Interrupt,
    /// Recovery coordinator entered `GivenUp` and fired its give-up
    /// alert. Additive to the existing in-line halt behaviour (JVM kill +
    /// WaitingForLaunch park) — external subscribers (SSE bus,
    /// dashboard) use this for push-side notification with lower latency
    /// than STATUS-poll would allow. Dedupe-gated: at most one send per
    /// GivenUp phase entry.
    RecoveryGaveUp {
        /// Trading mode ("live" | "paper") of the coordinator that gave up.
        mode: String,
        /// Wall-clock instant of the GivenUp phase entry (same clock the
        /// coordinator persists as `phase_entered_at`).
        phase_entered_at: jiff::Zoned,
    },
}

/// Why a scheduled cold restart was skipped. Surfaced via STATUS JSON
/// so the dashboard can render distinct messages for "we already
/// re-authed today" vs "this site is on standby".
#[derive(Debug, Clone)]
pub enum ColdRestartSkipReason {
    /// A fresh login completed earlier today, so the scheduled fire is
    /// redundant. Carries the timestamp of that completed login.
    FreshAuthToday { at: jiff::Zoned },
    /// The site is in a dormant state (standby, shutdown, or HITL-stalled)
    /// and has no JVM to restart. The fire is a no-op.
    DormantSite,
}

/// Signals from the Sunday cold restart timer.
/// Produced by: cold_restart (background timer task)
/// Consumed by: state_machine (main select loop)
#[derive(Debug, Clone)]
pub enum ColdRestartSignal {
    /// Time to cold-restart the JVM — full re-auth required.
    Fire,
    /// Scheduled time arrived but the fire was suppressed. The state
    /// machine records the reason so the dashboard can render distinct
    /// messages via STATUS JSON.
    Skipped(ColdRestartSkipReason),
}

/// Pre-built query responses published via `watch` channel.
///
/// The state machine publishes a new snapshot after every state transition
/// and observable mutation. The command server reads the latest snapshot
/// directly — no mpsc round-trip, no blocking on the state machine loop.
///
/// Wrapped in `Arc` for cheap clones across watch receivers.
#[derive(Clone, Debug)]
pub struct QuerySnapshot {
    /// Pre-built STATUS JSON response.
    pub status_json: String,
    /// Pre-built STATE JSON response.
    pub state_json: String,
    /// Pre-built CONFIG JSON response (immutable after init).
    pub config_json: String,
    /// When this snapshot was published.
    pub published_at: Instant,
    /// Monotonic version counter (aids debugging).
    pub version: u64,
    /// State machine start time — command server computes uptime at response time.
    pub start_time: Instant,
    /// Connected-since instant — command server computes connected uptime dynamically.
    pub connected_since: Option<Instant>,
}

impl QuerySnapshot {
    /// Initial snapshot before the state machine has started.
    pub fn initializing() -> Self {
        let now = Instant::now();
        Self {
            status_json: r#"{"state":"Initializing","ready":false}"#.to_string(),
            state_json: r#"{"current":"Initializing","history":[]}"#.to_string(),
            config_json: "{}".to_string(),
            published_at: now,
            version: 0,
            start_time: now,
            connected_since: None,
        }
    }
}
