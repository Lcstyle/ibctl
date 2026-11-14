//! TOTP (Time-based One-Time Password) generation for two-factor authentication.
//!
//! The primary implementation shells out to `oathtool`, piping the secret via
//! stdin to avoid exposing it in /proc/PID/cmdline.

use crate::config::TotpProvider;
use crate::types::TotpCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("failed to execute oathtool: {0}")]
    ExecutionFailed(#[from] std::io::Error),
    #[error("oathtool returned non-zero exit code: {0}")]
    OathtoolFailed(String),
    #[error("builtin TOTP provider not yet implemented — use provider = \"oathtool\"")]
    BuiltinNotImplemented,
}

/// Trait for TOTP code generation providers.
pub trait TotpCodeGenerator: Send + Sync {
    /// Generate a 6-digit TOTP code from a base32-encoded secret.
    fn generate(&self, secret: &str) -> Result<TotpCode, TotpError>;
}

/// TOTP provider that shells out to the `oathtool` command-line utility.
///
/// The secret is piped via stdin (not passed as a command-line argument)
/// to prevent exposure in /proc/PID/cmdline.
pub struct OathtoolProvider;

impl TotpCodeGenerator for OathtoolProvider {
    fn generate(&self, secret: &str) -> Result<TotpCode, TotpError> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut child = Command::new("oathtool")
            .args(["--totp", "--base32", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Write secret to stdin and close it
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(secret.as_bytes())?;
        }

        let output = child.wait_with_output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TotpError::OathtoolFailed(stderr.to_string()));
        }

        let code = String::from_utf8_lossy(&output.stdout).trim().to_string();
        log::debug!("Generated TOTP code (length={})", code.len());
        Ok(TotpCode::new(code))
    }
}

/// Factory function to create a TOTP code generator by provider type.
pub fn create_provider(provider: TotpProvider) -> Result<Box<dyn TotpCodeGenerator>, TotpError> {
    match provider {
        TotpProvider::Oathtool => Ok(Box::new(OathtoolProvider)),
        TotpProvider::Builtin => Err(TotpError::BuiltinNotImplemented),
    }
}
