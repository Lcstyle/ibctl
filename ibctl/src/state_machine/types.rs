//! Core types for the state machine: State enum, Stats, Transition, Channels, errors.

use std::collections::VecDeque;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tokio::sync::mpsc;

use crate::agent_client::AgentClient;
use crate::types::{ColdRestartSignal, Command, Query};
use crate::config::ValidConfig;
use crate::handlers::DialogHandlerRegistry;
use crate::types::Signal;
use crate::supervisor::Supervisor;

#[derive(Debug, Error)]
pub enum StateMachineError {
    #[error("supervisor error: {0}")]
    Supervisor(#[from] crate::supervisor::SupervisorError),
    #[error("agent error: {0}")]
    Agent(#[from] crate::agent_client::AgentError),
    #[error("handler error: {0}")]
    Handler(#[from] crate::handlers::HandlerError),
}

/// All possible states in the ibctl lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Standby mode: process running, JVM not launched. Awaiting START command.
    WaitingForLaunch,
    /// Initial state: parse config, validate environment
    Init,
    /// Launching the JVM with -javaagent
    Launching,
    /// Polling the agent's /health endpoint until it responds
    WaitingForAgent,
    /// Waiting for the login window to appear
    WaitingForLogin,
    /// Filling in credentials and clicking login
    Authenticating,
    /// Waiting for 2FA dialog (if TOTP configured)
    WaitingFor2fa,
    /// Handling an "existing session detected" dialog
    HandlingSessionConflict,
    /// Dismissing startup popups (tip of day, version notice, paper warning)
    DismissingPopups,
    /// Applying post-login API configuration (master client ID, read-only, etc.)
    ConfiguringApi,
    /// Fully connected and monitoring for new dialogs
    Connected,
    /// Restarting the Gateway JVM
    Restarting,
    /// Waiting for IB system to become available (maintenance/outage/no internet)
    WaitingForIB,
    /// Shutting down cleanly
    Shutdown,
    /// Unrecoverable error state
    Error(String),
}

impl State {
    /// Parse a state name from a string (for SETSTATE command).
    pub fn from_name(name: &str) -> Option<State> {
        match name {
            "WaitingForLaunch" => Some(State::WaitingForLaunch),
            "Init" => Some(State::Init),
            "Launching" => Some(State::Launching),
            "WaitingForAgent" => Some(State::WaitingForAgent),
            "WaitingForLogin" => Some(State::WaitingForLogin),
            "Authenticating" => Some(State::Authenticating),
            "WaitingFor2fa" => Some(State::WaitingFor2fa),
            "HandlingSessionConflict" => Some(State::HandlingSessionConflict),
            "DismissingPopups" => Some(State::DismissingPopups),
            "ConfiguringApi" => Some(State::ConfiguringApi),
            "Connected" => Some(State::Connected),
            "Restarting" => Some(State::Restarting),
            "WaitingForIB" => Some(State::WaitingForIB),
            "Shutdown" => Some(State::Shutdown),
            _ => None,
        }
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Error(msg) => write!(f, "Error({})", msg),
            other => write!(f, "{:?}", other),
        }
    }
}

/// Runtime statistics collected by the state machine.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Stats {
    pub restarts_today: u32,
    pub relogins_today: u32,
    pub dialogs_dismissed: u32,
    pub last_2fa_duration_secs: Option<f64>,
    pub config_apply_duration_secs: Option<f64>,
}

/// A recorded state transition.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Transition {
    pub timestamp: String,
    pub from: String,
    pub to: String,
}

/// Bundled mpsc receivers for the state machine's inbound channels.
pub struct Channels {
    pub signals: mpsc::Receiver<Signal>,
    pub commands: mpsc::Receiver<Command>,
    pub queries: mpsc::Receiver<Query>,
    pub cold_restart: mpsc::Receiver<ColdRestartSignal>,
}

/// Internal enum for interrupt sources.
pub(super) enum Interrupt {
    Signal(Signal),
    Command(Command),
    ColdRestart,
}

/// IB system status — pushed by dashboard or external clients via IBSTATUS command.
pub struct IbSystemStatus {
    pub(super) available: bool,
    pub(super) status: String,
    pub(super) reason: String,
    pub(super) last_updated: Option<Instant>,
    pub(super) return_state: Option<Box<State>>,
}

impl IbSystemStatus {
    fn new() -> Self {
        Self {
            available: true,
            status: "available".to_string(),
            reason: String::new(),
            last_updated: None,
            return_state: None,
        }
    }
}

/// Pause/ceiling controls for the state machine.
pub struct PauseControl {
    pub(super) paused: bool,
    pub(super) ceiling_state: Option<State>,
}

impl PauseControl {
    fn new() -> Self {
        Self {
            paused: false,
            ceiling_state: None,
        }
    }
}

/// The main state machine that orchestrates the IB Gateway lifecycle.
pub struct StateMachine {
    pub(super) state: State,
    pub(super) config: ValidConfig,
    pub(super) agent_client: AgentClient,
    pub(super) supervisor: Supervisor,
    pub(super) handler_registry: DialogHandlerRegistry,
    pub(super) signal_rx: mpsc::Receiver<Signal>,
    pub(super) command_rx: mpsc::Receiver<Command>,
    pub(super) query_rx: mpsc::Receiver<Query>,
    pub(super) cold_restart_rx: mpsc::Receiver<ColdRestartSignal>,
    pub(super) socat_process: Option<std::process::Child>,
    pub(super) config_retries: u32,
    pub(super) pause: PauseControl,
    pub(super) ib_status: IbSystemStatus,
    pub(super) start_time: Instant,
    pub(super) connected_since: Option<Instant>,
    pub(super) transition_history: VecDeque<Transition>,
    pub(super) cached_client_ids: Vec<String>,
    /// Set by do_connected when JVM exits during warm restart — carries the
    /// autorestart session hash to pass as -Drestart on relaunch (skips 2FA).
    pub(super) warm_restart_pending: Option<String>,
    /// Background task that periodically refreshes client IDs from the agent.
    /// Stored here so it survives cancellation of `do_connected()` by the
    /// `tokio::select!` loop and gets properly cleaned up on state transitions.
    pub(super) client_id_task: Option<tokio::task::JoinHandle<()>>,
    /// Watch receiver for client IDs from the background refresh task.
    pub(super) client_id_rx: Option<tokio::sync::watch::Receiver<Vec<String>>>,
    /// Tracks consecutive re-login dialog appearances. Reset on Connected.
    pub(super) relogin_attempts: u32,
    /// Window class recorded when entering Connected state. Used to detect silent
    /// session loss: if the main window's class changes (e.g. ibgateway.ay → ibgateway.az),
    /// Gateway reverted to the login form without showing a RE-LOGIN dialog.
    pub(super) connected_window_class: Option<String>,
    pub stats: Stats,
}

impl StateMachine {
    pub fn new(
        config: ValidConfig,
        agent_client: AgentClient,
        supervisor: Supervisor,
        handler_registry: DialogHandlerRegistry,
        channels: Channels,
    ) -> Self {
        Self {
            state: State::Init,
            config,
            agent_client,
            supervisor,
            handler_registry,
            signal_rx: channels.signals,
            command_rx: channels.commands,
            query_rx: channels.queries,
            cold_restart_rx: channels.cold_restart,
            socat_process: None,
            config_retries: 0,
            pause: PauseControl::new(),
            ib_status: IbSystemStatus::new(),
            start_time: Instant::now(),
            connected_since: None,
            transition_history: VecDeque::with_capacity(100),
            cached_client_ids: Vec::new(),
            warm_restart_pending: None,
            client_id_task: None,
            client_id_rx: None,
            relogin_attempts: 0,
            connected_window_class: None,
            stats: Stats::default(),
        }
    }

    /// Record a state transition in the history ring buffer.
    pub(super) fn record_transition(&mut self, from: &State, to: &State) {
        if from == to {
            return;
        }
        if self.transition_history.len() >= 100 {
            self.transition_history.pop_front();
        }
        self.transition_history.push_back(Transition {
            timestamp: chrono_timestamp(),
            from: from.to_string(),
            to: to.to_string(),
        });
    }
}

/// Compute client advisory fields from the current state.
/// Returns (should_connect, should_wait, wait_reason, client_id_likely_stale).
pub(crate) fn client_advisory(state: &State) -> (bool, bool, Option<&'static str>, bool) {
    let (should_connect, should_wait, wait_reason) = match state {
        State::WaitingForLaunch => (false, false, Some("standby")),
        State::Init | State::Launching | State::WaitingForAgent => (false, true, Some("launching")),
        State::WaitingForLogin | State::Authenticating => (false, true, Some("logging_in")),
        State::WaitingFor2fa => (false, true, Some("2fa_pending")),
        State::HandlingSessionConflict => (false, true, Some("session_conflict")),
        State::DismissingPopups | State::ConfiguringApi => (false, true, Some("configuring")),
        State::Connected => (true, false, None),
        State::Restarting => (false, true, Some("restarting")),
        State::WaitingForIB => (false, true, Some("ib_maintenance")),
        State::Shutdown => (false, false, None),
        State::Error(_) => (false, false, None),
    };
    let client_id_likely_stale = matches!(state, State::Restarting);
    (should_connect, should_wait, wait_reason, client_id_likely_stale)
}

/// Epoch seconds timestamp — browser converts to local time.
pub(super) fn chrono_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connected_should_connect() {
        let (should_connect, should_wait, reason, stale) = client_advisory(&State::Connected);
        assert!(should_connect);
        assert!(!should_wait);
        assert!(reason.is_none());
        assert!(!stale);
    }

    #[test]
    fn test_init_should_wait() {
        let (should_connect, should_wait, reason, _) = client_advisory(&State::Init);
        assert!(!should_connect);
        assert!(should_wait);
        assert_eq!(reason, Some("launching"));
    }

    #[test]
    fn test_2fa_pending() {
        let (should_connect, should_wait, reason, _) = client_advisory(&State::WaitingFor2fa);
        assert!(!should_connect);
        assert!(should_wait);
        assert_eq!(reason, Some("2fa_pending"));
    }

    #[test]
    fn test_restarting_stale_ids() {
        let (_, should_wait, reason, stale) = client_advisory(&State::Restarting);
        assert!(should_wait);
        assert_eq!(reason, Some("restarting"));
        assert!(stale);
    }

    #[test]
    fn test_shutdown_no_connect_no_wait() {
        let (should_connect, should_wait, _, _) = client_advisory(&State::Shutdown);
        assert!(!should_connect);
        assert!(!should_wait);
    }

    #[test]
    fn test_error_no_connect_no_wait() {
        let (should_connect, should_wait, _, _) = client_advisory(&State::Error("test".into()));
        assert!(!should_connect);
        assert!(!should_wait);
    }

    #[test]
    fn test_configuring_api_should_wait() {
        let (should_connect, should_wait, reason, _) = client_advisory(&State::ConfiguringApi);
        assert!(!should_connect);
        assert!(should_wait);
        assert_eq!(reason, Some("configuring"));
    }

    #[test]
    fn test_waiting_for_launch_standby() {
        let (should_connect, should_wait, reason, _) = client_advisory(&State::WaitingForLaunch);
        assert!(!should_connect);
        assert!(!should_wait);
        assert_eq!(reason, Some("standby"));
    }

    #[test]
    fn test_all_states_covered() {
        let states = vec![
            State::WaitingForLaunch,
            State::Init, State::Launching, State::WaitingForAgent,
            State::WaitingForLogin, State::Authenticating,
            State::WaitingFor2fa, State::HandlingSessionConflict,
            State::DismissingPopups, State::ConfiguringApi,
            State::Connected, State::Restarting, State::Shutdown,
            State::Error("test".into()),
        ];
        for state in &states {
            let (sc, sw, _, _) = client_advisory(state);
            if matches!(state, State::Connected) {
                assert!(sc, "Connected should allow connect");
                assert!(!sw, "Connected should not wait");
            }
        }
    }

    #[test]
    fn test_state_display() {
        assert_eq!(State::Init.to_string(), "Init");
        assert_eq!(State::Connected.to_string(), "Connected");
        assert_eq!(State::WaitingFor2fa.to_string(), "WaitingFor2fa");
        assert_eq!(State::Error("boom".into()).to_string(), "Error(boom)");
    }
}
