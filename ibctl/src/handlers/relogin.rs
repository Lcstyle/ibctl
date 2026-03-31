//! Re-login dialog handler.
//!
//! When the connection is lost, Gateway shows "RE-LOGIN IS REQUIRED —
//! Your connection was lost. Would you like to re-login?" with Re-login
//! and Cancel buttons. IBC's LoginFailedDialogHandler clicks Re-login.

use std::future::Future;
use std::pin::Pin;

use crate::agent_client::{AgentClient, WindowInfo};
use crate::handlers::{DialogHandler, HandlerError, HandlerResult};

pub struct ReloginHandler;

impl DialogHandler for ReloginHandler {
    fn name(&self) -> &str {
        "ReloginHandler"
    }

    fn can_handle(&self, window: &WindowInfo) -> bool {
        let title = window.title.to_lowercase();
        title.contains("re-login") || title.contains("relogin") || title.contains("login is required")
    }

    fn handle<'a>(
        &'a self,
        client: &'a AgentClient,
        window: &'a WindowInfo,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>> + Send + 'a>> {
        Box::pin(async move {
            log::info!("Connection lost dialog detected — clicking Cancel to return to login form");

            match client.click_button(window.id, "Cancel").await {
                Ok(true) => {
                    log::info!("Clicked 'Cancel' on re-login dialog");
                    Ok(HandlerResult::Handled)
                }
                _ => {
                    let _ = client.click_button(window.id, "OK").await;
                    Ok(HandlerResult::Handled)
                }
            }
        })
    }
}
