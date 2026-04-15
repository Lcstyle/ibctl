//! Session conflict dialog handler.
//!
//! When another session is already connected, IB Gateway shows a dialog
//! asking whether to take over (primary) or connect as secondary.

use std::future::Future;
use std::pin::Pin;

use crate::agent_client::{AgentClient, WindowInfo};
use crate::config::SessionAction;
use crate::handlers::{DialogHandler, HandlerError, HandlerResult};

/// Handles the "Existing session detected" dialog based on the configured
/// session action (primary, secondary, or primaryoverride).
pub struct SessionConflictHandler {
    action: SessionAction,
}

impl SessionConflictHandler {
    pub fn new(action: SessionAction) -> Self {
        Self { action }
    }
}

impl DialogHandler for SessionConflictHandler {
    fn name(&self) -> &str {
        "SessionConflictHandler"
    }

    fn can_handle(&self, window: &WindowInfo) -> bool {
        let title = window.title.to_lowercase();
        title.contains("existing session")
            || title.contains("session conflict")
            || title.contains("another session")
    }

    fn handle<'a>(
        &'a self,
        client: &'a AgentClient,
        window: &'a WindowInfo,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>> + Send + 'a>> {
        Box::pin(async move {
            log::info!(
                "Handling session conflict dialog '{}' (action={})",
                window.title,
                self.action
            );

            // Button labels — try most specific first to avoid clicking
            // "OK" on a different dialog (e.g., "Connection failed" error).
            // PRIMARY/PRIMARYOVERRIDE: reconnect and take over the session.
            // SECONDARY: cancel and exit.
            let button_candidates: &[&str] = match self.action {
                SessionAction::Secondary => &["Cancel", "Exit Application"],
                _ => &["Reconnect This Session", "Continue Login", "OK"],
            };

            for label in button_candidates {
                match client.click_button(window.id, label).await {
                    Ok(true) => {
                        log::info!("Session conflict resolved: clicked '{}'", label);
                        return Ok(HandlerResult::Handled);
                    }
                    Ok(false) => continue, // Button not found, try next
                    Err(e) => {
                        log::debug!("Button '{}' click failed: {}", label, e);
                        continue;
                    }
                }
            }

            log::warn!("No matching button found for session conflict action '{}'", self.action);
            Ok(HandlerResult::Error("no matching button found".into()))
        })
    }
}
