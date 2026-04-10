//! Login dialog handler.
//!
//! Recognizes the IB Gateway login window and fills in credentials.
//! Supports both live and paper trading modes.
//!
//! After clicking the trading mode radio button, verifies the UI updated
//! by inspecting button labels via dump_components. This prevents the
//! paper-mode bug where credentials were submitted before the mode switch
//! took effect.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};

use secrecy::{ExposeSecret, SecretString};

use crate::agent_client::{AgentClient, WindowInfo};
use crate::config::TradingMode;
use crate::handlers::{DialogHandler, HandlerError, HandlerResult};
use crate::types::WindowId;

/// Text field index for the username input.
const USERNAME_FIELD: usize = 0;
/// Text field index for the password input.
const PASSWORD_FIELD: usize = 1;
/// Max attempts to verify mode switch took effect.
const MODE_VERIFY_ATTEMPTS: u32 = 5;
/// Delay between mode verification attempts (ms).
const MODE_VERIFY_DELAY_MS: u64 = 200;

/// Handles the IB Gateway login dialog by filling username, password,
/// and clicking the appropriate login button.
///
/// Tracks whether login has been submitted to avoid re-dispatching
/// on the main Gateway window (which shares a similar title).
/// Mirrors IBC's LoginFrameHandler which also tracks login state.
pub struct LoginHandler {
    username: String,
    password: SecretString,
    trading_mode: TradingMode,
    /// Set to true after credentials are submitted.
    /// Prevents re-matching the main gateway window post-login.
    login_submitted: AtomicBool,
}

impl LoginHandler {
    pub fn new(username: String, password: SecretString, trading_mode: TradingMode) -> Self {
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
            match client.click_button(window.id, "IB API").await {
                Ok(true) => log::info!("Selected 'IB API' mode"),
                Ok(false) => log::debug!("'IB API' button not found (may already be selected)"),
                Err(e) => log::debug!("Failed to click 'IB API': {}", e),
            }

            tokio::time::sleep(std::time::Duration::from_millis(MODE_VERIFY_DELAY_MS)).await;

            // Step 2: Select trading mode with verification.
            // The expected login button label confirms the mode switch took effect.
            let mode_label = match self.trading_mode {
                TradingMode::Paper => "Paper Trading",
                _ => "Live Trading",
            };
            let expected_button = match self.trading_mode {
                TradingMode::Paper => "Paper Log In",
                _ => "Log In",
            };

            match client.click_button(window.id, mode_label).await {
                Ok(true) => log::info!("Selected '{}' mode", mode_label),
                Ok(false) => log::debug!("'{}' button not found (may already be selected)", mode_label),
                Err(e) => log::debug!("Failed to click '{}': {}", mode_label, e),
            }

            // Verify the mode switch by checking button labels in the UI.
            // The login button changes from "Log In" to "Paper Log In" (or vice versa)
            // when the trading mode radio is toggled. This replaces the unreliable
            // hardcoded 100ms delay that caused the paper-mode login bug.
            let win_id = WindowId(window.id.0);
            let mut mode_verified = false;
            for attempt in 1..=MODE_VERIFY_ATTEMPTS {
                tokio::time::sleep(std::time::Duration::from_millis(MODE_VERIFY_DELAY_MS)).await;

                if let Ok(components) = client.dump_components(win_id).await {
                    let has_expected_button = components.get("buttons")
                        .and_then(|b| b.as_array())
                        .map(|buttons| {
                            buttons.iter().any(|btn| {
                                btn.get("text")
                                    .and_then(|t| t.as_str())
                                    .map(|t| t == expected_button)
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false);

                    if has_expected_button {
                        log::info!("Mode switch verified: '{}' button present (attempt {})", expected_button, attempt);
                        mode_verified = true;
                        break;
                    }
                    log::debug!("Mode switch not yet visible (attempt {}/{})", attempt, MODE_VERIFY_ATTEMPTS);
                }
            }

            if !mode_verified {
                log::warn!(
                    "Could not verify mode switch to '{}' after {} attempts — proceeding anyway",
                    mode_label, MODE_VERIFY_ATTEMPTS
                );
            }

            // Step 3: Fill username
            client
                .type_text(window.id, USERNAME_FIELD, &self.username)
                .await
                .map_err(HandlerError::AgentError)?;

            // Step 4: Fill password
            client
                .type_text(window.id, PASSWORD_FIELD, self.password.expose_secret())
                .await
                .map_err(HandlerError::AgentError)?;

            // Step 5: Click the login button — try expected label first
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

            self.login_submitted.store(true, Ordering::Relaxed);
            log::info!("Login credentials submitted (mode={})", self.trading_mode);
            Ok(HandlerResult::Handled)
        })
    }
}
