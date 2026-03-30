//! TOTP (Time-based One-Time Password) generation for two-factor authentication.
//!
//! The primary implementation shells out to `oathtool`, which is widely available
//! in Docker images. A built-in Rust implementation may be added in a future version.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("TOTP provider '{0}' not found or not supported")]
    UnsupportedProvider(String),
    #[error("failed to execute oathtool: {0}")]
    ExecutionFailed(#[from] std::io::Error),
    #[error("oathtool returned non-zero exit code: {0}")]
    OathtoolFailed(String),
    #[error("TOTP secret not configured")]
    NoSecret,
}

/// Trait for TOTP code generation providers.
pub trait TotpProvider: Send + Sync {
    /// Generate a 6-digit TOTP code from a base32-encoded secret.
    fn generate(&self, secret: &str) -> Result<String, TotpError>;
}

/// TOTP provider that shells out to the `oathtool` command-line utility.
///
/// Equivalent to: `oathtool --totp --base32 $SECRET`
pub struct OathtoolProvider;

impl TotpProvider for OathtoolProvider {
    fn generate(&self, secret: &str) -> Result<String, TotpError> {
        let output = std::process::Command::new("oathtool")
            .args(["--totp", "--base32", secret])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TotpError::OathtoolFailed(stderr.to_string()));
        }

        let code = String::from_utf8_lossy(&output.stdout).trim().to_string();
        log::debug!("Generated TOTP code (length={})", code.len());
        Ok(code)
    }
}

/// Factory function to create a TOTP provider by name.
///
/// Supported providers:
/// - `"oathtool"` — shells out to the `oathtool` CLI tool
/// - `"builtin"` — reserved for future Rust-native implementation
pub fn create_provider(name: &str) -> Result<Box<dyn TotpProvider>, TotpError> {
    match name {
        "oathtool" => Ok(Box::new(OathtoolProvider)),
        other => Err(TotpError::UnsupportedProvider(other.to_string())),
    }
}
