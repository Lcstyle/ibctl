//! Two-factor authentication dialog handler.
//!
//! Recognizes the TOTP/2FA challenge dialog and submits a generated code.

use std::future::Future;
use std::pin::Pin;

use secrecy::{ExposeSecret, SecretString};

use crate::agent_client::{AgentClient, WindowInfo};
use crate::config::TotpProvider;
use crate::handlers::{DialogHandler, HandlerError, HandlerResult};
use crate::totp;

/// Handles the second factor authentication dialog by generating a TOTP
/// code and entering it.
pub struct TotpEntryHandler {
    /// Name of the env var holding the TOTP secret
    secret_env: String,
    /// TOTP provider type
    provider: TotpProvider,
}

impl TotpEntryHandler {
    pub fn new(secret_env: String, provider: TotpProvider) -> Self {
        Self {
            secret_env,
            provider,
        }
    }
}

impl DialogHandler for TotpEntryHandler {
    fn name(&self) -> &str {
        "TotpEntryHandler"
    }

    fn can_handle(&self, window: &WindowInfo) -> bool {
        let title = window.title.to_lowercase();
        title.contains("second factor authentication")
            || title.contains("2fa")
            || title.contains("two-factor")
            || title.contains("security code")
    }

    fn handle<'a>(
        &'a self,
        client: &'a AgentClient,
        window: &'a WindowInfo,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>> + Send + 'a>> {
        Box::pin(async move {
            log::info!("Handling 2FA dialog '{}'", window.title);

            // Read the TOTP secret from the configured env var (wrapped in SecretString)
            let secret = SecretString::from(
                std::env::var(&self.secret_env).map_err(|_| HandlerError::Failed {
                    handler: self.name().to_string(),
                    reason: format!("TOTP secret env var '{}' not set", self.secret_env),
                })?
            );

            // Generate TOTP code in a blocking task to avoid blocking the runtime
            let provider_type = self.provider;
            let handler_name = self.name().to_string();
            let totp_code = tokio::task::spawn_blocking(move || {
                let provider = totp::create_provider(provider_type)?;
                provider.generate(secret.expose_secret())
            })
            .await
            .map_err(|e| HandlerError::Failed {
                handler: handler_name.clone(),
                reason: format!("TOTP task panicked: {}", e),
            })?
            .map_err(|e| HandlerError::Failed {
                handler: handler_name,
                reason: format!("failed to generate TOTP code: {}", e),
            })?;

            // Consume the single-use TotpCode and type it into the first text field
            let code = totp_code.into_inner();
            client
                .type_text(window.id, 0, &code)
                .await
                .map_err(HandlerError::AgentError)?;

            // Prefer the explicit OK/submit button. Some Gateway builds do not
            // accept Enter as form submission on the 2FA challenge dialog.
            let submitted = client
                .click_button(window.id, "OK")
                .await
                .map_err(HandlerError::AgentError)?;

            if !submitted {
                log::debug!("No OK button found in 2FA dialog — falling back to Enter");
                client
                    .send_key(window.id, "Enter")
                    .await
                    .map_err(HandlerError::AgentError)?;
            }

            log::info!("2FA code submitted");
            Ok(HandlerResult::Handled)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WindowId;

    #[test]
    fn test_can_handle_second_factor_window() {
        let handler = TotpEntryHandler::new("TWOFACTOR_CODE".to_string(), TotpProvider::Oathtool);
        let window = WindowInfo {
            id: WindowId(1),
            title: "Second Factor Authentication".to_string(),
            class: "dialog".to_string(),
            bounds: None,
            visible: true,
        };

        assert!(handler.can_handle(&window));
    }

    #[test]
    fn test_can_handle_security_code_window() {
        let handler = TotpEntryHandler::new("TWOFACTOR_CODE".to_string(), TotpProvider::Oathtool);
        let window = WindowInfo {
            id: WindowId(1),
            title: "Security Code".to_string(),
            class: "dialog".to_string(),
            bounds: None,
            visible: true,
        };

        assert!(handler.can_handle(&window));
    }
}
