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
    #[error("timeout waiting for dialog response")]
    Timeout,
}

/// Result of a dialog handler's attempt to process a window.
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
}

impl DialogHandlerRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
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
    pub fn with_defaults(config: &crate::config::Config) -> Self {
        let mut registry = Self::new();

        // Resolve credentials: env vars take precedence over config file
        let username = crate::config::env_or_file("TWS_USERID")
            .unwrap_or_else(|| config.auth.username.clone());
        let password = crate::config::env_or_file("TWS_PASSWORD")
            .unwrap_or_else(|| config.auth.password.clone());
        let trading_mode = std::env::var("TRADING_MODE")
            .unwrap_or_else(|_| config.auth.trading_mode.clone());

        registry.register(Box::new(login::LoginHandler::new(
            username,
            password,
            trading_mode,
        )));
        registry.register(Box::new(totp_entry::TotpEntryHandler::new(
            config.twofa.secret_env.clone(),
            config.twofa.provider.clone(),
        )));
        registry.register(Box::new(session_conflict::SessionConflictHandler::new(
            config.session.action.clone(),
        )));
        registry.register(Box::new(relogin::ReloginHandler));
        registry.register(Box::new(ssl_reconnect::SslReconnectHandler));
        registry.register(Box::new(tip_of_day::TipOfDayHandler));
        registry.register(Box::new(
            accept_connection::AcceptConnectionHandler::new(
                config.session.accept_incoming.clone(),
            ),
        ));
        registry.register(Box::new(paper_warning::PaperWarningHandler));
        registry.register(Box::new(version_notice::VersionNoticeHandler));
        // Catch-all for Gateway notification dialogs (lowest priority)
        registry.register(Box::new(gateway_notification::GatewayNotificationHandler));

        registry
    }

    /// Reset all handler state for a fresh login cycle.
    pub fn reset(&self) {
        for handler in &self.handlers {
            handler.reset();
        }
        log::debug!("All dialog handlers reset");
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
