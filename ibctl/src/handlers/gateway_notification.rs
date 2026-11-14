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

pub struct GatewayNotificationHandler {
    /// Set when ibctl has just pressed a Gateway hotkey: the confirmation
    /// prompt that follows is ibctl's own and is the one it answers.
    expectation: crate::hotkey::HotkeyExpectation,
}

impl GatewayNotificationHandler {
    pub fn new(expectation: crate::hotkey::HotkeyExpectation) -> Self {
        Self { expectation }
    }
}

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
            // A hotkey confirmation ("Are you sure you want to execute ...") is
            // answered only when ibctl pressed the hotkey. The same prompt from
            // a stray key in a VNC session is left for a person.
            if let Ok(dump) = client.dump_components(window.id).await {
                if crate::hotkey::is_hotkey_confirmation(&dump) {
                    if !self.expectation.consume(crate::hotkey::CONFIRMATION_WINDOW) {
                        log::warn!(
                            "Gateway confirmation prompt (id={}) was not triggered by ibctl; left for the operator",
                            window.id
                        );
                        return Ok(HandlerResult::NotApplicable);
                    }
                    log::info!("Confirming the hotkey prompt ibctl triggered (id={})", window.id);
                }
            }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_client::{Bounds, MockAgent};
    use crate::hotkey::HotkeyExpectation;
    use crate::types::WindowId;

    fn dialog() -> WindowInfo {
        WindowInfo {
            id: WindowId(9),
            title: "IBKR Gateway".into(),
            class: "ibgateway.aw".into(),
            bounds: Some(Bounds { x: 0, y: 0, width: 450, height: 170 }),
            visible: true,
        }
    }

    fn prompt_dump() -> serde_json::Value {
        serde_json::json!({"children": [
            {"text": "Are you sure you want to execute \"simulate mkt data disconnect\" ctrl-alt-# hotkey action?"},
            {"text": "OK"}, {"text": "Cancel"}
        ]})
    }

    async fn run(handler: &GatewayNotificationHandler, dump: serde_json::Value) -> (HandlerResult, Vec<String>) {
        // The real prompt has OK and Cancel, no Close button.
        let mock = MockAgent {
            dump_response: dump,
            click_not_found: ["Close".to_string()].into_iter().collect(),
            ..MockAgent::default()
        };
        let clicked = mock.clicked.clone();
        let client = AgentClient::mock(mock);
        let result = handler.handle(&client, &dialog()).await.unwrap();
        let clicks = clicked.lock().unwrap().clone();
        (result, clicks)
    }

    #[tokio::test]
    async fn a_hotkey_prompt_ibctl_triggered_is_confirmed() {
        let expectation = HotkeyExpectation::default();
        let handler = GatewayNotificationHandler::new(expectation.clone());
        expectation.arm();

        let (result, clicks) = run(&handler, prompt_dump()).await;

        assert_eq!(result, HandlerResult::Handled);
        assert_eq!(clicks.last().map(String::as_str), Some("OK"));
    }

    #[tokio::test]
    async fn a_hotkey_prompt_ibctl_did_not_trigger_is_left_for_a_person() {
        let handler = GatewayNotificationHandler::new(HotkeyExpectation::default());

        let (result, clicks) = run(&handler, prompt_dump()).await;

        assert_eq!(result, HandlerResult::NotApplicable);
        assert!(clicks.is_empty(), "nothing is clicked: {clicks:?}");
    }

    #[tokio::test]
    async fn an_ordinary_gateway_dialog_is_still_dismissed_without_any_expectation() {
        let handler = GatewayNotificationHandler::new(HotkeyExpectation::default());

        let (result, clicks) = run(&handler, serde_json::json!({"children": [{"text": "Your session has expired"}]})).await;

        assert_eq!(result, HandlerResult::Handled);
        assert!(!clicks.is_empty());
    }
}
