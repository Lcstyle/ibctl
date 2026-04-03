//! Shared newtypes for domain values.

use serde::{Deserialize, Serialize};

/// A window identifier from the IB Gateway agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowId(pub u64);

impl std::fmt::Display for WindowId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A one-time TOTP code. Cannot be cloned — enforces single use.
pub struct TotpCode(String);

impl TotpCode {
    pub fn new(code: String) -> Self { Self(code) }
    /// Consume the code, returning the inner string.
    pub fn into_inner(self) -> String { self.0 }
}
