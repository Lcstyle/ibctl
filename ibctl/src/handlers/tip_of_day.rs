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

            // Try "Close" first, fall back to "OK".
            //
            // This was `if result.is_err()`, which never fired for the case it
            // was written for. A missing "Close" button came back as `Ok(true)`
            // from the HTTP envelope, not as an error, so the "OK" fallback was
            // unreachable and the handler reported the dialog dismissed while
            // it was still on screen. `Ok(false)` now means "no such button",
            // so the fallback works and an undismissable dialog is reported
            // rather than assumed away.
            let closed = matches!(client.click_button(window.id, "Close").await, Ok(true));
            if !closed {
                let dismissed = client
                    .click_button(window.id, "OK")
                    .await
                    .map_err(HandlerError::AgentError)?;
                if !dismissed {
                    log::warn!(
                        "Tip-of-the-day dialog '{}' has neither 'Close' nor 'OK'",
                        window.title
                    );
                    return Ok(HandlerResult::Error(
                        "no dismiss button on tip-of-the-day dialog".into(),
                    ));
                }
            }

            log::debug!("Tip of the day dismissed");
            Ok(HandlerResult::Handled)
        })
    }
}
