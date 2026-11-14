//! Gateway hotkeys that ibctl presses itself.
//!
//! The Gateway has a family of Ctrl-Alt hotkeys that simulate connection
//! problems. `Ctrl-Alt-F` makes it drop and re-open its market-data
//! connections and `Ctrl-Alt-R` re-opens its connection to IB; each opens an
//! "Are you sure you want to execute ... hotkey action?" prompt first.
//!
//! This module holds what is needed to press one safely:
//!
//! - the keystrokes, in the form Java's `KeyStroke.getKeyStroke` parses (it
//!   rejects `ctrl+f`; the modifiers are words and the key a capital);
//! - choosing the Gateway's main window as the target, never a dialog;
//! - remembering that ibctl itself just pressed one, so its generic dialog
//!   handler confirms the prompt that follows and leaves any other
//!   "Are you sure" prompt, for example one caused by a stray key in a VNC
//!   session, for a person to answer;
//! - a record of what was pressed and whether the agent sent it.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::agent_client::WindowInfo;
use crate::config::TradingMode;

/// Drop and re-open the Gateway's market-data connections.
pub const RECONNECT_DATA_KEY: &str = "ctrl alt F";
/// Re-open the Gateway's connection to IB.
pub const RECONNECT_ACCOUNT_KEY: &str = "ctrl alt R";

/// How a Gateway hotkey confirmation prompt begins.
pub const CONFIRMATION_PREFIX: &str = "Are you sure you want to execute";

/// How long after a key press ibctl answers the prompt it causes.
pub const CONFIRMATION_WINDOW: Duration = Duration::from_secs(30);

/// How long ibctl waits for the agent to acknowledge a key press. The Gateway
/// holds the press open until the confirmation prompt it causes is answered,
/// and ibctl's own dialog handler answers it, so waiting longer than a moment
/// only stalls the handler. No reply in this time is not a failure.
pub const SEND_REPLY_WAIT: Duration = Duration::from_secs(2);

/// Smaller windows than this are dialogs, not the Gateway's main window.
const MAIN_WINDOW_MIN_AREA: i64 = 650 * 400;

fn area(window: &WindowInfo) -> i64 {
    window.bounds.as_ref().map_or(0, |b| i64::from(b.width) * i64::from(b.height))
}

/// The Gateway's main window among `windows`: the largest window titled for the
/// Gateway that is big enough not to be a dialog. (The agent lists only windows
/// that exist and sends no `visible` flag, so that field is not consulted.) A window carrying the
/// tag for `mode` (the agent stamps `[LIVE]` / `[PAPER]` on the title) is
/// preferred.
pub fn main_gateway_window(windows: &[WindowInfo], mode: TradingMode) -> Option<&WindowInfo> {
    let tag = match mode {
        TradingMode::Live => Some("[LIVE]"),
        TradingMode::Paper => Some("[PAPER]"),
        TradingMode::Both => None,
    };
    windows
        .iter()
        .filter(|w| {
            let title = w.title.to_lowercase();
            (title.contains("ibkr gateway") || title.contains("ib gateway")) && area(w) >= MAIN_WINDOW_MIN_AREA
        })
        .max_by_key(|w| (tag.is_some_and(|t| w.title.contains(t)), area(w)))
}

/// Whether a window's component dump holds a hotkey confirmation prompt.
pub fn is_hotkey_confirmation(dump: &serde_json::Value) -> bool {
    match dump {
        serde_json::Value::String(s) => s.trim_start().starts_with(CONFIRMATION_PREFIX),
        serde_json::Value::Array(items) => items.iter().any(is_hotkey_confirmation),
        serde_json::Value::Object(fields) => fields.values().any(is_hotkey_confirmation),
        _ => false,
    }
}

/// "ibctl just pressed a hotkey, so the next confirmation prompt is its own".
/// Shared between the state machine, which arms it before pressing, and the
/// dialog handler, which consumes it when the prompt appears.
#[derive(Clone, Default)]
pub struct HotkeyExpectation(Arc<Mutex<Option<Instant>>>);

impl HotkeyExpectation {
    pub fn arm(&self) {
        self.arm_at(Instant::now());
    }

    fn arm_at(&self, at: Instant) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(at);
    }

    /// Take the expectation if it was armed within `within` of `now`. One
    /// key press answers one prompt: it is cleared either way.
    pub fn consume_at(&self, now: Instant, within: Duration) -> bool {
        let armed = self.0.lock().unwrap_or_else(|e| e.into_inner()).take();
        armed.is_some_and(|at| now.saturating_duration_since(at) <= within)
    }

    pub fn consume(&self, within: Duration) -> bool {
        self.consume_at(Instant::now(), within)
    }
}

/// What ibctl last pressed, for STATUS.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HotkeyRecord {
    pub at: String,
    /// The command that asked for it (`RECONNECTDATA` / `RECONNECTACCOUNT`).
    pub command: &'static str,
    pub key: &'static str,
    pub window: Option<String>,
    /// `sent`, or `failed` with the reason in `error`.
    pub outcome: &'static str,
    pub error: Option<String>,
    /// Set when `sent` rests on no reply yet: the Gateway holds the key press
    /// until its confirmation prompt is answered.
    pub note: Option<&'static str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_client::Bounds;
    use crate::types::WindowId;

    fn window(id: u64, title: &str, width: i32, height: i32) -> WindowInfo {
        WindowInfo {
            id: WindowId(id),
            title: title.into(),
            class: "ibgateway.aw".into(),
            bounds: Some(Bounds { x: 0, y: 0, width, height }),
            // The agent's window list carries no `visible` field, so it parses as false.
            visible: false,
        }
    }

    #[test]
    fn the_keys_are_in_the_form_javas_key_stroke_parser_accepts() {
        // The "ctrl+f" ibctl used to send is not one: modifiers are words, the key is a capital.
        for key in [RECONNECT_DATA_KEY, RECONNECT_ACCOUNT_KEY] {
            assert!(!key.contains('+'), "{key}");
            let parts: Vec<&str> = key.split(' ').collect();
            assert_eq!(&parts[..2], ["ctrl", "alt"]);
            assert!(parts[2].len() == 1 && parts[2].chars().all(|c| c.is_ascii_uppercase()), "{key}");
        }
    }

    #[test]
    fn the_main_window_is_picked_over_a_dialog_with_the_same_title() {
        let windows = [
            window(1, "IBKR Gateway", 400, 200),
            window(2, "IBKR Gateway [PAPER]", 700, 558),
            window(3, "Warning", 500, 300),
        ];

        assert_eq!(main_gateway_window(&windows, TradingMode::Paper).map(|w| w.id), Some(WindowId(2)));
    }

    #[test]
    fn a_window_tagged_for_the_mode_wins_over_a_larger_untagged_one() {
        let windows = [window(1, "IBKR Gateway", 790, 680), window(2, "IBKR Gateway [PAPER]", 700, 558)];

        assert_eq!(main_gateway_window(&windows, TradingMode::Paper).map(|w| w.id), Some(WindowId(2)));
        assert_eq!(main_gateway_window(&windows, TradingMode::Live).map(|w| w.id), Some(WindowId(1)));
    }

    #[test]
    fn with_only_dialogs_open_there_is_no_main_window() {
        let windows = [window(1, "IBKR Gateway", 400, 200), window(2, "Warning", 800, 600)];
        assert!(main_gateway_window(&windows, TradingMode::Paper).is_none());
        assert!(main_gateway_window(&[], TradingMode::Paper).is_none());
    }

    #[test]
    fn a_dump_with_the_prompt_text_is_a_hotkey_confirmation() {
        let dump = serde_json::json!({
            "children": [
                {"class": "javax.swing.JLabel", "text": "Are you sure you want to execute \"simulate mkt data disconnect\" ctrl-alt-# hotkey action?"},
                {"class": "javax.swing.JButton", "text": "OK"}
            ]
        });
        assert!(is_hotkey_confirmation(&dump));
        assert!(is_hotkey_confirmation(&serde_json::json!({"labels": ["Are you sure you want to execute \"x\""]})));
    }

    #[test]
    fn other_dialogs_are_not_hotkey_confirmations() {
        assert!(!is_hotkey_confirmation(&serde_json::json!({"children": [{"text": "Your session has expired"}]})));
        assert!(!is_hotkey_confirmation(&serde_json::json!({"children": [{"text": "Are you sure you want to exit?"}]})));
        assert!(!is_hotkey_confirmation(&serde_json::json!({})));
    }

    #[test]
    fn an_armed_expectation_answers_one_prompt_within_the_window() {
        let expectation = HotkeyExpectation::default();
        let t0 = Instant::now();

        assert!(!expectation.consume_at(t0, Duration::from_secs(30)), "nothing armed");

        expectation.arm_at(t0);
        assert!(expectation.consume_at(t0 + Duration::from_secs(2), Duration::from_secs(30)));
        assert!(!expectation.consume_at(t0 + Duration::from_secs(3), Duration::from_secs(30)), "one press answers one prompt");
    }

    #[test]
    fn a_stale_expectation_does_not_answer_a_prompt_and_is_cleared() {
        let expectation = HotkeyExpectation::default();
        let t0 = Instant::now();
        expectation.arm_at(t0);

        assert!(!expectation.consume_at(t0 + Duration::from_secs(31), Duration::from_secs(30)));
        assert!(!expectation.consume_at(t0 + Duration::from_secs(32), Duration::from_secs(30)));
    }

    #[test]
    fn clones_share_one_expectation() {
        let a = HotkeyExpectation::default();
        let b = a.clone();
        a.arm();
        assert!(b.consume(Duration::from_secs(30)));
    }
}
