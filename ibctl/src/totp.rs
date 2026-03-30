//! TOTP (Time-based One-Time Password) generation for two-factor authentication.
//!
//! The primary implementation shells out to `oathtool`, which is widely available
//! in Docker images. A built-in Rust implementation may be added in a future version.

use crate::config::TotpProvider;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("failed to execute oathtool: {0}")]
    ExecutionFailed(#[from] std::io::Error),
    #[error("oathtool returned non-zero exit code: {0}")]
    OathtoolFailed(String),
}

/// Trait for TOTP code generation providers.
pub trait TotpCodeGenerator: Send + Sync {
    /// Generate a 6-digit TOTP code from a base32-encoded secret.
    fn generate(&self, secret: &str) -> Result<String, TotpError>;
}

/// TOTP provider that shells out to the `oathtool` command-line utility.
///
/// Equivalent to: `oathtool --totp --base32 $SECRET`
pub struct OathtoolProvider;

impl TotpCodeGenerator for OathtoolProvider {
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

/// Factory function to create a TOTP code generator by provider type.
pub fn create_provider(provider: TotpProvider) -> Box<dyn TotpCodeGenerator> {
    match provider {
        TotpProvider::Oathtool => Box::new(OathtoolProvider),
        TotpProvider::Builtin => Box::new(OathtoolProvider), // TODO: native impl
    }
}
