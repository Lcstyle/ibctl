//! Login dialog handler.
//!
//! Recognizes the IB Gateway login window and fills in credentials.
//! Supports both live and paper trading modes.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::agent_client::{AgentClient, WindowInfo};
use crate::config::TradingMode;
use crate::handlers::{DialogHandler, HandlerError, HandlerResult};

/// Handles the IB Gateway login dialog by filling username, password,
/// and clicking the appropriate login button.
///
/// Tracks whether login has been submitted to avoid re-dispatching
/// on the main Gateway window (which shares a similar title).
/// Mirrors IBC's LoginFrameHandler which also tracks login state.
pub struct LoginHandler {
    username: String,
    password: String,
    trading_mode: TradingMode,
    /// Set to true after credentials are submitted.
    /// Prevents re-matching the main gateway window post-login.
    login_submitted: AtomicBool,
}

impl LoginHandler {
    pub fn new(username: String, password: String, trading_mode: TradingMode) -> Self {
        Self {
            username,
            password,
            trading_mode,
            login_submitted: AtomicBool::new(false),
        }
    }

}

impl DialogHandler for LoginHandler {
    fn name(&self) -> &str {
        "LoginHandler"
    }

    fn reset(&self) {
        self.login_submitted.store(false, Ordering::Relaxed);
    }

    fn can_handle(&self, window: &WindowInfo) -> bool {
        // Once login is submitted, don't match again until reset
        if self.login_submitted.load(Ordering::Relaxed) {
            return false;
        }

        let title = window.title.to_lowercase();
        title.contains("ibkr gateway")
            || title.contains("ib gateway")
            || title.contains("login")
            || title.contains("interactive brokers")
    }

    fn handle<'a>(
        &'a self,
        client: &'a AgentClient,
        window: &'a WindowInfo,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>> + Send + 'a>> {
        Box::pin(async move {
            log::info!(
                "Handling login dialog '{}' (mode={})",
                window.title,
                self.trading_mode
            );

            // Step 1: Select API type — "IB API" (not "FIX CTCI")
            // Matches IBC's GatewayLoginFrameHandler which checks/sets this
            // before filling credentials
            match client.click_button(window.id, "IB API").await {
                Ok(true) => log::info!("Selected 'IB API' mode"),
                Ok(false) => log::debug!("'IB API' button not found (may already be selected)"),
                Err(e) => log::debug!("Failed to click 'IB API': {}", e),
            }

            // Brief pause for UI to update after radio selection
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            // Step 2: Select trading mode — "Paper Trading" or "Live Trading"
            // Matches IBC's TradingModeManager which selects the mode
            let mode_label = match self.trading_mode {
                TradingMode::Paper => "Paper Trading",
                _ => "Live Trading",
            };
            match client.click_button(window.id, mode_label).await {
                Ok(true) => log::info!("Selected '{}' mode", mode_label),
                Ok(false) => log::debug!("'{}' button not found (may already be selected)", mode_label),
                Err(e) => log::debug!("Failed to click '{}': {}", mode_label, e),
            }

            // Brief pause for UI to update after mode selection
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            // Step 3: Fill username into the first text field (index 0)
            // Matches IBC pattern: SwingUtils.findTextField(window, 0)
            client
                .type_text(window.id, 0, &self.username)
                .await
                .map_err(HandlerError::AgentError)?;

            // Step 4: Fill password into the second text field (index 1)
            // Matches IBC pattern: SwingUtils.findTextField(window, 1)
            client
                .type_text(window.id, 1, &self.password)
                .await
                .map_err(HandlerError::AgentError)?;

            // Step 5: Click the login button
            // IBC tries multiple labels: "Log In", "Paper Log In"
            let button_labels: &[&str] = match self.trading_mode {
                TradingMode::Paper => &["Paper Log In", "Log In"],
                _ => &["Log In", "Paper Log In"],
            };

            let mut clicked = false;
            for label in button_labels {
                match client.click_button(window.id, label).await {
                    Ok(true) => {
                        log::info!("Clicked '{}' button", label);
                        clicked = true;
                        break;
                    }
                    _ => continue,
                }
            }

            if !clicked {
                log::error!("No login button found — tried {:?}", button_labels);
                return Ok(HandlerResult::Error("No login button found".into()));
            }

            // Mark login as submitted so we don't re-match the main window
            self.login_submitted.store(true, Ordering::Relaxed);

            log::info!("Login credentials submitted (mode={})", self.trading_mode);
            Ok(HandlerResult::Handled)
        })
    }
}
