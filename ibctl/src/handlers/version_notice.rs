//! Version update notice dialog handler.
//!
//! IB Gateway periodically shows notices about newer versions being available.
//! This handler dismisses them to avoid blocking the automation flow.

use std::future::Future;
use std::pin::Pin;

use crate::agent_client::{AgentClient, WindowInfo};
use crate::handlers::{DialogHandler, HandlerError, HandlerResult};

/// Dismisses version update notice dialogs.
pub struct VersionNoticeHandler;

impl DialogHandler for VersionNoticeHandler {
    fn name(&self) -> &str {
        "VersionNoticeHandler"
    }

    fn can_handle(&self, window: &WindowInfo) -> bool {
        let title = window.title.to_lowercase();
        title.contains("newer version")
            || title.contains("update available")
            || title.contains("version")
                && (title.contains("update") || title.contains("upgrade") || title.contains("new"))
    }

    fn handle<'a>(
        &'a self,
        client: &'a AgentClient,
        window: &'a WindowInfo,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>> + Send + 'a>> {
        Box::pin(async move {
            log::info!("Dismissing version notice dialog '{}'", window.title);

            // Try "OK" first, then "Close", then "Dismiss"
            let buttons = ["OK", "Close", "Dismiss"];
            for label in &buttons {
                if client.click_button(window.id, label).await.is_ok() {
                    log::debug!("Version notice dismissed via '{}' button", label);
                    return Ok(HandlerResult::Handled);
                }
            }

            // If none of the buttons worked, try pressing Escape
            client
                .send_key(window.id, "Escape")
                .await
                .map_err(HandlerError::AgentError)?;

            log::debug!("Version notice dismissed via Escape key");
            Ok(HandlerResult::Handled)
        })
    }
}
