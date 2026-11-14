//! Generic Gateway notification dialog handler.
//!
//! Catches various notification/warning dialogs from the Gateway that
//! have the title "IBKR Gateway" and aren't caught by more specific handlers.
//! Examples:
//! - "An API client is attempting to send a request that needs API write access"
//! - "Your session has expired"
//! - Generic informational messages
//!
//! Clicks "Close" or "OK" to dismiss.

use std::future::Future;
use std::pin::Pin;

use crate::agent_client::{AgentClient, WindowInfo};
use crate::handlers::{DialogHandler, HandlerError, HandlerResult};

pub struct GatewayNotificationHandler;

impl DialogHandler for GatewayNotificationHandler {
    fn name(&self) -> &str {
        "GatewayNotificationHandler"
    }

    fn can_handle(&self, window: &WindowInfo) -> bool {
        // Match "IBKR Gateway" titled dialogs that aren't the main window.
        // The main window is large (700x550+), notification dialogs are smaller.
        let title = window.title.to_lowercase();
        if !title.contains("ibkr gateway") && !title.contains("ib gateway") {
            return false;
        }
        // Only match smaller dialogs (notifications), not the main window
        if let Some(ref bounds) = window.bounds {
            bounds.width < 650 && bounds.height < 400
        } else {
            false
        }
    }

    fn handle<'a>(
        &'a self,
        client: &'a AgentClient,
        window: &'a WindowInfo,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>> + Send + 'a>> {
        Box::pin(async move {
            log::info!("Dismissing Gateway notification dialog (id={})", window.id);

            // Try Close first, then OK
            if let Ok(true) = client.click_button(window.id, "Close").await {
                log::info!("Gateway notification dismissed via 'Close'");
                return Ok(HandlerResult::Handled);
            }
            if let Ok(true) = client.click_button(window.id, "OK").await {
                log::info!("Gateway notification dismissed via 'OK'");
                return Ok(HandlerResult::Handled);
            }

            log::debug!("No Close/OK button found in Gateway notification");
            Ok(HandlerResult::NotApplicable)
        })
    }
}
