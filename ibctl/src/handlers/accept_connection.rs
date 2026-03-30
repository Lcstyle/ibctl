//! "Accept incoming connection" dialog handler.
//!
//! IB Gateway may prompt when an API client connects. This handler
//! accepts or rejects based on configuration.

use std::future::Future;
use std::pin::Pin;

use crate::agent_client::{AgentClient, WindowInfo};
use crate::handlers::{DialogHandler, HandlerError, HandlerResult};

/// Handles the "Accept incoming connection" dialog based on the
/// configured accept_incoming setting.
pub struct AcceptConnectionHandler {
    /// "accept", "reject", or "manual"
    action: String,
}

impl AcceptConnectionHandler {
    pub fn new(action: String) -> Self {
        Self { action }
    }
}

impl DialogHandler for AcceptConnectionHandler {
    fn name(&self) -> &str {
        "AcceptConnectionHandler"
    }

    fn can_handle(&self, window: &WindowInfo) -> bool {
        let title = window.title.to_lowercase();
        title.contains("accept incoming connection")
            || title.contains("api connection")
            || title.contains("incoming connection")
    }

    fn handle<'a>(
        &'a self,
        client: &'a AgentClient,
        window: &'a WindowInfo,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>> + Send + 'a>> {
        Box::pin(async move {
            log::info!(
                "Handling incoming connection dialog '{}' (action={})",
                window.title,
                self.action
            );

            match self.action.as_str() {
                "reject" => {
                    client
                        .click_button(window.id, "Reject")
                        .await
                        .map_err(HandlerError::AgentError)?;
                    log::info!("Rejected incoming API connection");
                }
                "manual" => {
                    log::info!("Incoming connection dialog left for manual handling");
                    return Ok(HandlerResult::NotApplicable);
                }
                _ => {
                    // "accept" (default)
                    client
                        .click_button(window.id, "Accept")
                        .await
                        .map_err(HandlerError::AgentError)?;
                    log::info!("Accepted incoming API connection");
                }
            }

            Ok(HandlerResult::Handled)
        })
    }
}
