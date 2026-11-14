//! Dialog handler framework for IB Gateway popups and login dialogs.
//!
//! Each handler recognizes a specific dialog by its window title and knows
//! how to interact with it via the agent client. The registry dispatches
//! incoming windows to the appropriate handler.

pub mod accept_connection;
pub mod api_config;
pub mod gateway_notification;
pub mod login;
pub mod paper_warning;
pub mod relogin;
pub mod session_conflict;
pub mod ssl_reconnect;
pub mod tip_of_day;
pub mod totp_entry;
pub mod version_notice;

use std::future::Future;
use std::pin::Pin;

use crate::agent_client::{AgentClient, WindowInfo};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("agent communication failed: {0}")]
    AgentError(#[from] crate::agent_client::AgentError),
    #[error("handler '{handler}' failed: {reason}")]
    Failed { handler: String, reason: String },
}

/// Result of a dialog handler's attempt to process a window.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerResult {
    /// The dialog was recognized and successfully handled.
    Handled,
    /// The dialog was not recognized by this handler.
    NotApplicable,
    /// The handler recognized the dialog but encountered an error.
    Error(String),
}

/// Trait for handlers that can recognize and interact with specific IB Gateway dialogs.
///
/// Each implementation targets a specific dialog type (login, 2FA, session conflict, etc.)
/// and knows how to drive the UI via the agent client.
///
/// Uses a boxed future return type instead of `async fn` to maintain dyn-compatibility,
/// allowing handlers to be stored as `Box<dyn DialogHandler>` in the registry.
pub trait DialogHandler: Send + Sync {
    /// Human-readable name of this handler (for logging).
    fn name(&self) -> &str;

    /// Reset handler state for a fresh login cycle (e.g., after restart).
    /// Default implementation does nothing.
    fn reset(&self) {}

    /// Called once, by the state machine, on entry to `Connected` — the one
    /// moment the state machine itself is unambiguously sure no login form
    /// is outstanding. Default implementation does nothing; `LoginHandler`
    /// overrides it to stop matching the Gateway's main window.
    ///
    /// # Why this exists
    ///
    /// `do_connected()` runs a "reconciliation" sweep every tick — dispatch
    /// every handler against every open window, to auto-dismiss popups.
    /// `LoginHandler::can_handle()` matches on title alone ("ibkr gateway"),
    /// which the MAIN, already-connected window also satisfies, so it was
    /// dispatched there too, forever, for as long as the session stayed
    /// Connected. That used to be invisible: the old fail-open
    /// `click_button`/`type_text` bug meant this bogus dispatch "succeeded"
    /// on its first pass, setting `login_submitted` and self-silencing.
    /// Making those verbs honestly report `found` (see agent_client.rs)
    /// means this dispatch now genuinely fails every time — no false
    /// success to set the flag — so it never stops, logging a fresh ERROR
    /// every cycle on an otherwise perfectly healthy Connected session.
    ///
    /// `login_submitted` is `LoginHandler`'s own bookkeeping, but "we are
    /// Connected, therefore login is unambiguously done" is a fact only the
    /// state machine can assert with authority — so the state machine
    /// asserts it here, directly, rather than relying on a login attempt
    /// happening to succeed through this exact handler at exactly the right
    /// moment (a warm restart, for instance, never calls `handle()` at all).
    fn mark_login_complete(&self) {}

    /// Whether handling a window is a step of logging in: submitting
    /// credentials, entering a 2FA code, taking over a session, clicking
    /// Re-login. Such a handler is not a popup: generic popup sweeps
    /// (`dispatch_popup`) never run it. Only the state machine's login
    /// states do — one login at a time, with the session-conflict breaker in
    /// front of takeovers (a sweep logging in while the Gateway
    /// re-logged in itself can loop a mode for hours).
    fn is_login_step(&self) -> bool {
        false
    }

    /// Check if this handler can handle the given window, typically by inspecting the title.
    fn can_handle(&self, window: &WindowInfo) -> bool;

    /// Attempt to handle the dialog. Called only if `can_handle` returned true.
    fn handle<'a>(
        &'a self,
        client: &'a AgentClient,
        window: &'a WindowInfo,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>> + Send + 'a>>;
}

/// Registry of dialog handlers, dispatches windows to the first matching handler.
pub struct DialogHandlerRegistry {
    handlers: Vec<Box<dyn DialogHandler>>,
    /// Publishes the agent's latest `login_form_ready` to whichever handlers
    /// subscribed at construction (today: `LoginHandler`).
    ///
    /// The channel lives here rather than being threaded through
    /// `StateMachine::new` because the state machine already owns the registry,
    /// so this needs no new constructor parameters anywhere.
    pub login_form_tx: tokio::sync::watch::Sender<Option<crate::agent_events::LoginFormState>>,
    /// Armed by the state machine just before it presses a Gateway hotkey, so
    /// the generic dialog handler confirms the prompt that causes and no other.
    pub hotkey_expectation: crate::hotkey::HotkeyExpectation,
}

impl DialogHandlerRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        let (login_form_tx, _) = tokio::sync::watch::channel(None);
        Self {
            handlers: Vec::new(),
            login_form_tx,
            hotkey_expectation: crate::hotkey::HotkeyExpectation::default(),
        }
    }

    /// Register a dialog handler.
    pub fn register(&mut self, handler: Box<dyn DialogHandler>) {
        log::debug!("Registered dialog handler: {}", handler.name());
        self.handlers.push(handler);
    }

    /// Create a registry with all built-in handlers configured.
    ///
    /// Credentials are resolved at registration time: env vars override config file,
    /// matching the Docker-native convention (TWS_USERID, TWS_PASSWORD env vars).
    pub fn with_defaults(config: &crate::config::ValidConfig) -> Self {
        let mut registry = Self::new();

        // Use already-resolved config (env vars applied during Config::load)
        // The login handler waits on login_form_ready to know when the form has
        // finished composing and when the mode toggle has taken effect, instead
        // of polling the UI on a fixed time budget.
        let login_form_rx = registry.login_form_tx.subscribe();
        registry.register(Box::new(
            login::LoginHandler::new(
                config.auth.username.clone(),
                config.auth.password.clone(),
                config.auth.trading_mode,
            )
            .with_form_events(login_form_rx),
        ));
        registry.register(Box::new(totp_entry::TotpEntryHandler::new(
            config.twofa.secret_env.clone(),
            config.twofa.provider,
        )));
        registry.register(Box::new(session_conflict::SessionConflictHandler::new(
            config.session.action,
        )));
        registry.register(Box::new(relogin::ReloginHandler));
        registry.register(Box::new(ssl_reconnect::SslReconnectHandler));
        registry.register(Box::new(tip_of_day::TipOfDayHandler));
        registry.register(Box::new(
            accept_connection::AcceptConnectionHandler::new(
                config.session.accept_incoming,
            ),
        ));
        registry.register(Box::new(paper_warning::PaperWarningHandler));
        registry.register(Box::new(version_notice::VersionNoticeHandler));
        // Catch-all for Gateway notification dialogs (lowest priority)
        registry.register(Box::new(gateway_notification::GatewayNotificationHandler::new(
            registry.hotkey_expectation.clone(),
        )));

        registry
    }

    /// Reset all handler state for a fresh login cycle.
    pub fn reset(&self) {
        for handler in &self.handlers {
            handler.reset();
        }
        log::debug!("All dialog handlers reset");
    }

    /// Tell every handler that login is unambiguously complete. Called once,
    /// by the state machine, on entry to `Connected`. See
    /// `DialogHandler::mark_login_complete` for why this exists.
    pub fn mark_login_complete(&self) {
        for handler in &self.handlers {
            handler.mark_login_complete();
        }
    }

    /// `dispatch` for popup sweeps: skips login steps (`is_login_step`), so
    /// dismissing popups can never start a login or answer a session conflict.
    pub async fn dispatch_popup(
        &self,
        client: &AgentClient,
        window: &WindowInfo,
    ) -> Option<Result<HandlerResult, HandlerError>> {
        for handler in self.handlers.iter().filter(|h| !h.is_login_step()) {
            if handler.can_handle(window) {
                log::info!(
                    "Handler '{}' matched window '{}' (id={})",
                    handler.name(),
                    window.title,
                    window.id
                );
                return Some(handler.handle(client, window).await);
            }
        }
        None
    }

    /// Try to handle a window by dispatching to the first matching handler.
    ///
    /// Returns `None` if no handler recognized the window.
    pub async fn dispatch(
        &self,
        client: &AgentClient,
        window: &WindowInfo,
    ) -> Option<Result<HandlerResult, HandlerError>> {
        for handler in &self.handlers {
            if handler.can_handle(window) {
                log::info!(
                    "Handler '{}' matched window '{}' (id={})",
                    handler.name(),
                    window.title,
                    window.id
                );
                return Some(handler.handle(client, window).await);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WindowId;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Records whether `mark_login_complete()` was broadcast to it, without
    /// pulling in a real LoginHandler (and its config/secrecy dependencies)
    /// just to test the registry's own fan-out.
    struct RecordingHandler {
        marked: std::sync::Arc<AtomicBool>,
    }

    impl DialogHandler for RecordingHandler {
        fn name(&self) -> &str {
            "RecordingHandler"
        }
        fn can_handle(&self, _window: &WindowInfo) -> bool {
            false
        }
        fn handle<'a>(
            &'a self,
            _client: &'a AgentClient,
            _window: &'a WindowInfo,
        ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>> + Send + 'a>> {
            Box::pin(async { Ok(HandlerResult::NotApplicable) })
        }
        fn mark_login_complete(&self) {
            self.marked.store(true, Ordering::Relaxed);
        }
    }

    #[test]
    fn registry_broadcasts_mark_login_complete_to_every_handler() {
        let mut registry = DialogHandlerRegistry::new();
        let first_marked = std::sync::Arc::new(AtomicBool::new(false));
        let second_marked = std::sync::Arc::new(AtomicBool::new(false));
        registry.register(Box::new(RecordingHandler {
            marked: first_marked.clone(),
        }));
        // A second, distinct handler: a broadcast that only reached the
        // first-registered one would still pass a single-handler test.
        registry.register(Box::new(RecordingHandler {
            marked: second_marked.clone(),
        }));

        registry.mark_login_complete();

        assert!(first_marked.load(Ordering::Relaxed));
        assert!(
            second_marked.load(Ordering::Relaxed),
            "mark_login_complete must reach every registered handler, not just the first"
        );
    }

    #[test]
    fn default_mark_login_complete_is_a_harmless_no_op() {
        // A handler that doesn't override it (the vast majority — tip of
        // day, version notice, totp entry, etc.) must not need to.
        struct PlainHandler;
        impl DialogHandler for PlainHandler {
            fn name(&self) -> &str {
                "PlainHandler"
            }
            fn can_handle(&self, _window: &WindowInfo) -> bool {
                false
            }
            fn handle<'a>(
                &'a self,
                _client: &'a AgentClient,
                _window: &'a WindowInfo,
            ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>> + Send + 'a>>
            {
                Box::pin(async { Ok(HandlerResult::NotApplicable) })
            }
        }

        let mut registry = DialogHandlerRegistry::new();
        registry.register(Box::new(PlainHandler));
        registry.mark_login_complete(); // must not panic

        let window = WindowInfo {
            id: WindowId(1),
            title: "anything".to_string(),
            class: "c".to_string(),
            bounds: None,
            visible: true,
        };
        assert!(!registry.handlers[0].can_handle(&window));
    }
}
