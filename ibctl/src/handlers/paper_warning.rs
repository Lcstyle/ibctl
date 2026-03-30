//! Paper trading warning dialog handler.
//!
//! IB Gateway shows a warning when connecting to the paper trading environment:
//! "This is not a brokerage account. This is a 'paper' trading account..."
//! Button: "I understand and accept"
//!
//! Matches IBC's NonBrokerageAccountDialogHandler which checks for
//! "Non-Brokerage Account" title and clicks the accept button.

use std::future::Future;
use std::pin::Pin;

use crate::agent_client::{AgentClient, WindowInfo};
use crate::handlers::{DialogHandler, HandlerError, HandlerResult};

/// Dismisses the paper trading / non-brokerage account warning dialog.
pub struct PaperWarningHandler;

impl DialogHandler for PaperWarningHandler {
    fn name(&self) -> &str {
        "PaperWarningHandler"
    }

    fn can_handle(&self, window: &WindowInfo) -> bool {
        let title = window.title.to_lowercase();
        // Exclude configuration dialogs — "Trader Workstation Configuration (Simulated Trading)"
        // was falsely matching "simulated trading" and creating a stuck loop
        if title.contains("configuration") {
            return false;
        }
        title.contains("paper trading")
            || title.contains("non-brokerage")
            || title.contains("warning")
    }

    fn handle<'a>(
        &'a self,
        client: &'a AgentClient,
        window: &'a WindowInfo,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>> + Send + 'a>> {
        Box::pin(async move {
            log::info!("Dismissing paper trading warning '{}'", window.title);

            // Try button labels in order — IBC tries multiple variants
            let candidates = [
                "I understand and accept",
                "OK",
                "Yes",
                "Accept",
            ];

            for label in &candidates {
                match client.click_button(window.id, label).await {
                    Ok(true) => {
                        log::info!("Paper warning dismissed via '{}'", label);
                        return Ok(HandlerResult::Handled);
                    }
                    _ => continue,
                }
            }

            log::warn!("No matching button for paper warning dialog");
            Ok(HandlerResult::Error("no matching button found".into()))
        })
    }
}
