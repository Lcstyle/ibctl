//! Agent event types for the NDJSON event stream.
//!
//! Events are pushed by the Java agent over a dedicated Unix domain socket.
//! The state machine uses these to update its `AgentObservation` cache,
//! replacing periodic polling with event-driven observation.
//!
//! Only fields consumed by the state machine are declared here. Serde
//! silently skips any additional JSON fields (e.g. `ts`, `bounds` on
//! events where they aren't used).

use serde::Deserialize;

/// Events pushed by the Java agent over the NDJSON event socket.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentEvent {
    /// Protocol handshake — sent on connect.
    Hello {
        protocol_version: u32,
    },
    /// Full snapshot of all current windows — sent on connect after hello.
    Snapshot {
        seq: u64,
        windows: Vec<SnapshotWindow>,
    },
    /// A new window became visible.
    WindowOpened {
        seq: u64,
        window_id: u64,
        window_title: String,
        window_class: String,
        has_login_button: bool,
    },
    /// A window was closed/disposed.
    WindowClosed {
        seq: u64,
        window_id: u64,
        window_title: String,
    },
    /// Event queue overflowed — consumer must re-snapshot.
    Overflow {},
    /// Periodic heartbeat (every 30s).
    Keepalive {},
    /// Wave 3: Login form is ready with field details.
    LoginFormReady {
        text_field_count: u32,
        password_field_count: u32,
        login_button: Option<String>,
        selected_mode: Option<String>,
    },
    /// Wave 3: 2FA prompt with dialog structure details.
    TwofaPrompt {
        prompt_type: String,
        devices: Vec<String>,
    },
    /// Wave 3: Error/warning dialog with message and buttons.
    ErrorDialog {
        window_title: String,
        message: Option<String>,
        buttons: Vec<String>,
    },
    /// Connection Status label changed ("connected" ↔ "disconnected").
    /// Fired by the Java agent's connection status monitor thread.
    ConnectionStatusChanged {
        from: String,
        to: String,
    },
}

/// Window data from agent snapshot. Fields populated by serde, read by
/// reconciliation logic (e.g. bounds.width for window size filtering).
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Fields read via serde + application code; compiler can't trace through Deserialize
pub struct SnapshotWindow {
    pub window_id: u64,
    pub window_title: String,
    pub window_class: String,
    pub has_login_button: bool,
    pub bounds: Option<EventBounds>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Accessed via SnapshotWindow.bounds — compiler can't trace serde path
pub struct EventBounds {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

/// Centralized UI state model — the single source of truth for window state.
/// Updated by events, targeted HTTP queries, and reconciliation polls.
/// Read by transition() — the sole authority for state changes.
#[derive(Debug)]
pub struct AgentObservation {
    pub windows: Vec<ObservedWindow>,
    pub last_updated: std::time::Instant,
    pub last_event_seq: u64,
    pub synced: bool,
}

/// A window as observed by the agent.
#[derive(Debug, Clone)]
pub struct ObservedWindow {
    pub id: u64,
    pub title: String,
    pub class: String,
    pub has_login_button: bool,
}

impl AgentObservation {
    pub fn new() -> Self {
        Self {
            windows: Vec::new(),
            last_updated: std::time::Instant::now(),
            last_event_seq: 0,
            synced: false,
        }
    }

    /// Apply a snapshot — replaces all window state.
    pub fn apply_snapshot(&mut self, windows: Vec<SnapshotWindow>, seq: u64) {
        self.windows = windows
            .into_iter()
            .map(|w| ObservedWindow {
                id: w.window_id,
                title: w.window_title,
                class: w.window_class,
                has_login_button: w.has_login_button,
            })
            .collect();
        self.last_event_seq = seq;
        self.last_updated = std::time::Instant::now();
        self.synced = true;
        log::info!(
            "Observation snapshot applied: {} windows (seq={})",
            self.windows.len(),
            seq,
        );
    }

    /// Apply a window_opened event.
    pub fn window_opened(
        &mut self,
        id: u64,
        title: String,
        class: String,
        has_login_button: bool,
        seq: u64,
    ) {
        // Remove stale entry if exists (re-opened)
        self.windows.retain(|w| w.id != id);
        self.windows.push(ObservedWindow {
            id,
            title: title.clone(),
            class,
            has_login_button,
        });
        self.last_event_seq = seq;
        self.last_updated = std::time::Instant::now();
        log::debug!("Observation: window opened '{}' (id={}, seq={})", title, id, seq);
    }

    /// Apply a window_closed event.
    pub fn window_closed(&mut self, id: u64, seq: u64) {
        self.windows.retain(|w| w.id != id);
        self.last_event_seq = seq;
        self.last_updated = std::time::Instant::now();
        log::debug!("Observation: window closed (id={}, seq={})", id, seq);
    }

    /// Clear the login button flag on all gateway windows.
    /// Called after login credentials are submitted — the button is gone
    /// but no window event fires because the window mutates in place
    /// (IB Gateway doesn't close/reopen, it morphs).
    pub fn clear_login_buttons(&mut self) {
        for w in &mut self.windows {
            w.has_login_button = false;
        }
    }

    /// Mark as needing resync (overflow or disconnect).
    pub fn mark_desync(&mut self) {
        self.synced = false;
        log::warn!("Observation marked as desynced — needs re-snapshot");
    }

    /// Find the main Gateway window (by title).
    /// Matches IBC's GatewayLoginFrameHandler.recogniseWindow titles.
    /// The `has_login_button` field distinguishes login form from config/connected.
    pub fn main_gateway_window(&self) -> Option<&ObservedWindow> {
        self.windows.iter().find(|w| {
            let t = w.title.to_lowercase();
            (t.contains("ib gateway") || t.contains("ibkr gateway") || t.contains("interactive brokers gateway"))
                && !t.contains("configuration")
        })
    }

    /// Check if the login form is showing (main window has login button).
    /// This is the authoritative login detection — matches IBC's
    /// GatewayLoginFrameHandler which checks for "Log In"/"Paper Log In" buttons.
    pub fn has_login_form(&self) -> bool {
        self.windows.iter().any(|w| {
            let t = w.title.to_lowercase();
            (t.contains("ib gateway") || t.contains("ibkr gateway") || t.contains("interactive brokers gateway"))
                && w.has_login_button
        })
    }

    /// Check if any window looks like a 2FA dialog.
    /// Matches IBC's SecondFactorAuthenticationDialogHandler titles.
    pub fn has_2fa_dialog(&self) -> bool {
        self.windows.iter().any(|w| {
            let t = w.title.to_lowercase();
            t.contains("second factor authentication")
                || t.contains("security code card authentication")
                || t.contains("security code")
        })
    }

    /// Check if any window looks like a session conflict dialog.
    /// Matches IBC's ExistingSessionDetectedDialogHandler title.
    pub fn has_session_conflict(&self) -> bool {
        self.windows.iter().any(|w| {
            w.title.to_lowercase().contains("existing session")
        })
    }

    /// Check if any window looks like a re-login dialog.
    /// Matches IBC's ReloginDialogHandler title.
    pub fn has_relogin_dialog(&self) -> bool {
        self.windows.iter().any(|w| {
            let t = w.title.to_lowercase();
            t.contains("re-login is required") || t.contains("re-login") || t.contains("relogin")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_hello() {
        let json = r#"{"type":"hello","protocol_version":1,"agent_tick_ms":50,"ts":1000}"#;
        let event: AgentEvent = serde_json::from_str(json).unwrap();
        assert!(matches!(event, AgentEvent::Hello { protocol_version: 1, .. }));
    }

    #[test]
    fn test_deserialize_window_opened() {
        let json = r#"{"type":"window_opened","seq":1,"window_id":123,"window_title":"IBKR Gateway","window_class":"ibgateway.az","has_login_button":true,"bounds":{"x":0,"y":0,"width":800,"height":600},"ts":1000}"#;
        let event: AgentEvent = serde_json::from_str(json).unwrap();
        match event {
            AgentEvent::WindowOpened { window_title, has_login_button, seq, .. } => {
                assert_eq!(window_title, "IBKR Gateway");
                assert!(has_login_button);
                assert_eq!(seq, 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_deserialize_snapshot() {
        let json = r#"{"type":"snapshot","seq":1,"windows":[{"window_id":1,"window_title":"Test","window_class":"test.cls","has_login_button":false}],"ts":1000}"#;
        let event: AgentEvent = serde_json::from_str(json).unwrap();
        match event {
            AgentEvent::Snapshot { windows, .. } => {
                assert_eq!(windows.len(), 1);
                assert_eq!(windows[0].window_title, "Test");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_deserialize_overflow() {
        let json = r#"{"type":"overflow","seq":99,"ts":1000}"#;
        let event: AgentEvent = serde_json::from_str(json).unwrap();
        assert!(matches!(event, AgentEvent::Overflow { .. }));
    }

    #[test]
    fn test_observation_snapshot() {
        let mut obs = AgentObservation::new();
        assert!(!obs.synced);
        obs.apply_snapshot(
            vec![SnapshotWindow {
                window_id: 1,
                window_title: "IBKR Gateway".into(),
                window_class: "ibgateway.az".into(),
                has_login_button: true,
                bounds: None,
            }],
            1,
        );
        assert!(obs.synced);
        assert_eq!(obs.windows.len(), 1);
        assert!(obs.main_gateway_window().is_some());
    }

    #[test]
    fn test_observation_window_lifecycle() {
        let mut obs = AgentObservation::new();
        obs.window_opened(1, "IBKR Gateway".into(), "ibgateway.az".into(), true, 1);
        assert_eq!(obs.windows.len(), 1);

        obs.window_opened(2, "Second Factor Authentication".into(), "dialog".into(), false, 2);
        assert_eq!(obs.windows.len(), 2);
        assert!(obs.has_2fa_dialog());

        obs.window_closed(2, 3);
        assert_eq!(obs.windows.len(), 1);
        assert!(!obs.has_2fa_dialog());
    }

    #[test]
    fn test_deserialize_login_form_ready() {
        let json = r#"{"type":"login_form_ready","seq":5,"window_id":123,"text_field_count":1,"password_field_count":1,"login_button":"Log In","selected_mode":"Live Trading","ts":1000}"#;
        let event: AgentEvent = serde_json::from_str(json).unwrap();
        match event {
            AgentEvent::LoginFormReady { login_button, selected_mode, text_field_count, .. } => {
                assert_eq!(login_button, Some("Log In".into()));
                assert_eq!(selected_mode, Some("Live Trading".into()));
                assert_eq!(text_field_count, 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_deserialize_twofa_prompt() {
        let json = r#"{"type":"twofa_prompt","seq":6,"window_id":456,"prompt_type":"device_selection","devices":["IB Key","SMS"],"ts":1000}"#;
        let event: AgentEvent = serde_json::from_str(json).unwrap();
        match event {
            AgentEvent::TwofaPrompt { prompt_type, devices, .. } => {
                assert_eq!(prompt_type, "device_selection");
                assert_eq!(devices, vec!["IB Key", "SMS"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_deserialize_error_dialog() {
        let json = r#"{"type":"error_dialog","seq":7,"window_id":789,"window_title":"Warning","message":"Paper trading account","buttons":["OK"],"ts":1000}"#;
        let event: AgentEvent = serde_json::from_str(json).unwrap();
        match event {
            AgentEvent::ErrorDialog { message, buttons, .. } => {
                assert_eq!(message, Some("Paper trading account".into()));
                assert_eq!(buttons, vec!["OK"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_observation_desync() {
        let mut obs = AgentObservation::new();
        obs.apply_snapshot(vec![], 1);
        assert!(obs.synced);
        obs.mark_desync();
        assert!(!obs.synced);
    }
}
