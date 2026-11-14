//! SSL reconnection dialog handler.
//!
//! IB Gateway may prompt to reconnect using SSL encryption after login.
//! Dialog title: "USE SSL ENCRYPTION"
//! Button: "Reconnect using SSL"
//!
//! This dialog appears when the initial connection is made without SSL.
//! Always click "Reconnect using SSL" — never "Exit Application".

use std::future::Future;
use std::pin::Pin;

use crate::agent_client::{AgentClient, WindowInfo};
use crate::handlers::{DialogHandler, HandlerError, HandlerResult};

/// Handles the SSL reconnection dialog by clicking "Reconnect using SSL".
pub struct SslReconnectHandler;

impl DialogHandler for SslReconnectHandler {
    fn name(&self) -> &str {
        "SslReconnectHandler"
    }

    fn can_handle(&self, window: &WindowInfo) -> bool {
        let title = window.title.to_lowercase();
        title.contains("ssl") || title.contains("encryption")
    }

    fn handle<'a>(
        &'a self,
        client: &'a AgentClient,
        window: &'a WindowInfo,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>> + Send + 'a>> {
        Box::pin(async move {
            log::info!("Handling SSL reconnection dialog '{}'", window.title);

            match client.click_button(window.id, "Reconnect using SSL").await {
                Ok(true) => {
                    log::info!("Clicked 'Reconnect using SSL'");
                    Ok(HandlerResult::Handled)
                }
                _ => {
                    // Fallback — try just "OK"
                    match client.click_button(window.id, "OK").await {
                        Ok(true) => {
                            log::info!("SSL dialog dismissed via 'OK'");
                            Ok(HandlerResult::Handled)
                        }
                        _ => {
                            log::warn!("No matching button for SSL dialog");
                            Ok(HandlerResult::Error("no matching button".into()))
                        }
                    }
                }
            }
        })
    }
}
