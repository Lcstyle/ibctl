//! "Tip of the Day" dialog handler.
//!
//! IB Gateway shows a "Tip of the Day" dialog on startup. This handler
//! dismisses it by clicking the close button.

use std::future::Future;
use std::pin::Pin;

use crate::agent_client::{AgentClient, WindowInfo};
use crate::handlers::{DialogHandler, HandlerError, HandlerResult};

/// Dismisses the "Tip of the Day" dialog.
pub struct TipOfDayHandler;

impl DialogHandler for TipOfDayHandler {
    fn name(&self) -> &str {
        "TipOfDayHandler"
    }

    fn can_handle(&self, window: &WindowInfo) -> bool {
        let title = window.title.to_lowercase();
        title.contains("tip of the day") || title.contains("tips")
    }

    fn handle<'a>(
        &'a self,
        client: &'a AgentClient,
        window: &'a WindowInfo,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>> + Send + 'a>> {
        Box::pin(async move {
            log::info!("Dismissing tip of the day dialog '{}'", window.title);

            // Try "Close" first, fall back to "OK"
            let result = client.click_button(window.id, "Close").await;
            if result.is_err() {
                client
                    .click_button(window.id, "OK")
                    .await
                    .map_err(HandlerError::AgentError)?;
            }

            log::debug!("Tip of the day dismissed");
            Ok(HandlerResult::Handled)
        })
    }
}
