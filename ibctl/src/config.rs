//! Configuration loading with layered precedence:
//! 1. Built-in defaults (lowest)
//! 2. TOML config file
//! 3. Environment variables (highest)
//!
//! Docker secrets (_FILE suffix) supported for sensitive values.

use std::fmt;
use std::path::Path;

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use thiserror::Error;

// --- Typed enums for config fields ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TradingMode {
    Live,
    Paper,
    Both,
}

impl fmt::Display for TradingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Live => write!(f, "live"),
            Self::Paper => write!(f, "paper"),
            Self::Both => write!(f, "both"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TotpProvider {
    Oathtool,
    Builtin,
}

impl fmt::Display for TotpProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oathtool => write!(f, "oathtool"),
            Self::Builtin => write!(f, "builtin"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TwoFaTimeoutAction {
    Restart,
    Exit,
}

impl fmt::Display for TwoFaTimeoutAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Restart => write!(f, "restart"),
            Self::Exit => write!(f, "exit"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GatewayProgram {
    Gateway,
    Tws,
}

impl fmt::Display for GatewayProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gateway => write!(f, "gateway"),
            Self::Tws => write!(f, "tws"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionAction {
    Primary,
    Secondary,
    #[serde(rename = "primaryoverride")]
    PrimaryOverride,
}

impl fmt::Display for SessionAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Primary => write!(f, "primary"),
            Self::Secondary => write!(f, "secondary"),
            Self::PrimaryOverride => write!(f, "primaryoverride"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcceptIncoming {
    Accept,
    Reject,
    Manual,
}

impl fmt::Display for AcceptIncoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept => write!(f, "accept"),
            Self::Reject => write!(f, "reject"),
            Self::Manual => write!(f, "manual"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Debug => write!(f, "debug"),
            Self::Info => write!(f, "info"),
            Self::Warn => write!(f, "warn"),
            Self::Error => write!(f, "error"),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file '{path}': {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("missing required configuration: {0}")]
    Missing(String),
}

/// Top-level configuration for ibctl.
/// Unknown TOML sections are silently ignored — this allows the config file
/// to contain sections for other components (e.g., [dashboard]) without
/// breaking ibctl's parser.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub auth: AuthConfig,
    pub twofa: TwoFaConfig,
    pub gateway: GatewayConfig,
    pub session: SessionConfig,
    pub command_server: CommandServerConfig,
    pub agent: AgentConfig,
    pub logging: LoggingConfig,
    pub timing: TimingConfig,
    /// Catch-all for unknown sections (e.g., [dashboard]) — silently ignored.
    #[serde(flatten)]
    _extra: std::collections::HashMap<String, toml::Value>,
}

#[derive(Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub username: String,
    /// Password is env-only (TWS_PASSWORD / TWS_PASSWORD_FILE). Never in config file.
    #[serde(skip)]
    pub password: SecretString,
    pub trading_mode: TradingMode,
    pub paper: PaperAuthConfig,
}

impl Clone for AuthConfig {
    fn clone(&self) -> Self {
        Self {
            username: self.username.clone(),
            password: SecretString::from(self.password.expose_secret().to_string()),
            trading_mode: self.trading_mode,
            paper: self.paper.clone(),
        }
    }
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthConfig")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("trading_mode", &self.trading_mode)
            .field("paper", &self.paper)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(default)]
pub struct PaperAuthConfig {
    pub username: String,
    /// Paper password is env-only (TWS_PASSWORD_PAPER / TWS_PASSWORD_PAPER_FILE).
    #[serde(skip)]
    pub password: SecretString,
}

impl Clone for PaperAuthConfig {
    fn clone(&self) -> Self {
        Self {
            username: self.username.clone(),
            password: SecretString::from(self.password.expose_secret().to_string()),
        }
    }
}

impl Default for PaperAuthConfig {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: SecretString::from(String::new()),
        }
    }
}

impl fmt::Debug for PaperAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaperAuthConfig")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TwoFaConfig {
    /// Name of the env var holding the TOTP secret (default: "TWOFACTOR_CODE")
    pub secret_env: String,
    pub provider: TotpProvider,
    pub timeout_action: TwoFaTimeoutAction,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GatewayConfig {
    pub tws_path: String,
    pub settings_path: String,
    pub version: String,
    pub java_heap_mb: u32,
    pub program: GatewayProgram,
    /// Gateway API port (live: 4001, paper: 4002)
    pub live_api_port: u16,
    pub paper_api_port: u16,
    /// Socat forwarding port (live: 4003, paper: 4004)
    pub live_socat_port: u16,
    pub paper_socat_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SessionConfig {
    pub action: SessionAction,
    pub accept_incoming: AcceptIncoming,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CommandServerConfig {
    pub enabled: bool,
    pub port: u16,
    pub bind_address: String,
    pub control_from: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    pub socket_path: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: LogLevel,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct TimingConfig {
    /// Delay between UI actions in the config dialog (ms)
    pub ui_tick_ms: u64,
    /// Java agent-side delay after each Swing action (ms)
    pub agent_tick_ms: u64,
    /// Delay after login button click before checking for 2FA (ms)
    pub post_login_delay_ms: u64,
    /// Popup quiet threshold — seconds of no popups before considering login complete
    pub popup_quiet_secs: u64,
    /// Max time to wait for popups before moving on (seconds)
    pub popup_max_wait_secs: u64,
    /// Delay after clicking login radio buttons (IB API, Paper Trading) (ms)
    pub login_radio_delay_ms: u64,
    /// Seconds to wait for JVM graceful shutdown (SIGTERM) before SIGKILL
    pub jvm_shutdown_timeout_secs: u64,
}

// --- Default implementations ---

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            ui_tick_ms: 100,
            agent_tick_ms: 50,
            post_login_delay_ms: 1000,
            popup_quiet_secs: 5,
            popup_max_wait_secs: 30,
            login_radio_delay_ms: 100,
            jvm_shutdown_timeout_secs: 5,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: SecretString::from(String::new()),
            trading_mode: TradingMode::Live,
            paper: PaperAuthConfig::default(),
        }
    }
}


impl Default for TwoFaConfig {
    fn default() -> Self {
        Self {
            secret_env: "TWOFACTOR_CODE".to_string(),
            provider: TotpProvider::Oathtool,
            timeout_action: TwoFaTimeoutAction::Restart,
            timeout_seconds: 180,
        }
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            tws_path: "/home/ibgateway/Jts".to_string(),
            settings_path: String::new(),
            version: String::new(),
            java_heap_mb: 768,
            program: GatewayProgram::Gateway,
            live_api_port: 4001,
            paper_api_port: 4002,
            live_socat_port: 4003,
            paper_socat_port: 4004,
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            action: SessionAction::Primary,
            accept_incoming: AcceptIncoming::Accept,
        }
    }
}

impl Default for CommandServerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 7462,
            bind_address: "0.0.0.0".to_string(),
            control_from: vec!["127.0.0.1".to_string()],
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            socket_path: "/run/ibctl/agent.sock".to_string(),
        }
    }
}


impl Config {
    /// Load configuration with layered precedence:
    /// defaults -> TOML file -> environment variables.
    pub fn load(path: Option<&str>) -> Result<Config, ConfigError> {
        // Start with defaults
        let mut config = Config::default();

        // Layer 2: TOML file (if it exists)
        let config_path = path
            .map(String::from)
            .or_else(|| std::env::var("IBCTL_CONFIG").ok())
            .unwrap_or_else(|| "ibctl.toml".to_string());

        if Path::new(&config_path).exists() {
            let contents = std::fs::read_to_string(&config_path).map_err(|e| {
                ConfigError::ReadFile {
                    path: config_path.clone(),
                    source: e,
                }
            })?;
            config = toml::from_str(&contents)?;
            log::info!("Loaded config from {}", config_path);
        } else if path.is_some() {
            // Explicit path was given but file doesn't exist
            return Err(ConfigError::ReadFile {
                path: config_path.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "config file not found",
                ),
            });
        } else {
            log::debug!("No config file found at {}, using defaults + env", config_path);
        }

        // Layer 3: Environment variable overrides
        config.apply_env_overrides();

        Ok(config)
    }

    /// Apply environment variable overrides on top of current config.
    /// Env vars have highest precedence.
    fn apply_env_overrides(&mut self) {
        // Auth
        if let Some(v) = env_or_file("TWS_USERID") {
            self.auth.username = v;
        }
        if let Some(v) = env_or_file("TWS_PASSWORD") {
            self.auth.password = SecretString::from(v);
        }
        if let Some(v) = env_or_file("TRADING_MODE") {
            match v.to_lowercase().as_str() {
                "live" => self.auth.trading_mode = TradingMode::Live,
                "paper" => self.auth.trading_mode = TradingMode::Paper,
                "both" => self.auth.trading_mode = TradingMode::Both,
                other => log::warn!("Unknown TRADING_MODE '{}', keeping default", other),
            }
        }

        // Paper auth
        if let Some(v) = env_or_file("TWS_USERID_PAPER") {
            self.auth.paper.username = v;
        }
        if let Some(v) = env_or_file("TWS_PASSWORD_PAPER") {
            self.auth.paper.password = SecretString::from(v);
        }

        // 2FA
        if let Ok(v) = std::env::var("TOTP_PROVIDER") {
            match v.to_lowercase().as_str() {
                "oathtool" => self.twofa.provider = TotpProvider::Oathtool,
                "builtin" => self.twofa.provider = TotpProvider::Builtin,
                other => log::warn!("Unknown TOTP_PROVIDER '{}', keeping default", other),
            }
        }
        if let Ok(v) = std::env::var("TWOFA_TIMEOUT_ACTION") {
            match v.to_lowercase().as_str() {
                "restart" => self.twofa.timeout_action = TwoFaTimeoutAction::Restart,
                "exit" => self.twofa.timeout_action = TwoFaTimeoutAction::Exit,
                other => log::warn!("Unknown TWOFA_TIMEOUT_ACTION '{}', keeping default", other),
            }
        }
        if let Some(v) = std::env::var("TWOFA_EXIT_INTERVAL").ok().and_then(|s| s.parse().ok()) {
            self.twofa.timeout_seconds = v;
        }

        // Gateway
        if let Ok(v) = std::env::var("TWS_PATH") {
            self.gateway.tws_path = v;
        }
        if let Ok(v) = std::env::var("TWS_SETTINGS_PATH") {
            self.gateway.settings_path = v;
        }
        if let Ok(v) = std::env::var("TWS_MAJOR_VRSN") {
            self.gateway.version = v;
        }
        if let Some(v) = std::env::var("JAVA_HEAP_SIZE").ok().and_then(|s| s.parse().ok()) {
            self.gateway.java_heap_mb = v;
        }
        if let Ok(v) = std::env::var("GATEWAY_OR_TWS") {
            match v.to_lowercase().as_str() {
                "gateway" => self.gateway.program = GatewayProgram::Gateway,
                "tws" => self.gateway.program = GatewayProgram::Tws,
                other => log::warn!("Unknown GATEWAY_OR_TWS '{}', keeping default", other),
            }
        }

        // Session
        if let Ok(v) = std::env::var("IBCTL_SESSION_ACTION") {
            match v.to_lowercase().as_str() {
                "primary" => self.session.action = SessionAction::Primary,
                "secondary" => self.session.action = SessionAction::Secondary,
                "primaryoverride" => self.session.action = SessionAction::PrimaryOverride,
                other => log::warn!("Unknown IBCTL_SESSION_ACTION '{}', keeping default", other),
            }
        }
        if let Ok(v) = std::env::var("IBCTL_ACCEPT_INCOMING") {
            match v.to_lowercase().as_str() {
                "accept" => self.session.accept_incoming = AcceptIncoming::Accept,
                "reject" => self.session.accept_incoming = AcceptIncoming::Reject,
                "manual" => self.session.accept_incoming = AcceptIncoming::Manual,
                other => log::warn!("Unknown IBCTL_ACCEPT_INCOMING '{}', keeping default", other),
            }
        }

        // Command server
        if let Ok(v) = std::env::var("IBCTL_COMMAND_SERVER_ENABLED") {
            self.command_server.enabled = v.to_lowercase() != "false" && v != "0" && v.to_lowercase() != "no";
        }
        if let Some(v) = std::env::var("IBCTL_COMMAND_PORT").ok().and_then(|s| s.parse().ok()) {
            self.command_server.port = v;
        }
        if let Ok(v) = std::env::var("IBCTL_CONTROL_FROM") {
            self.command_server.control_from =
                v.split(',').map(|s| s.trim().to_string()).collect();
        }

        // Agent
        if let Ok(v) = std::env::var("IBCTL_AGENT_SOCKET") {
            self.agent.socket_path = v;
        }

        // Logging
        if let Ok(v) = std::env::var("IBCTL_LOG_LEVEL") {
            match v.to_lowercase().as_str() {
                "debug" => self.logging.level = LogLevel::Debug,
                "info" => self.logging.level = LogLevel::Info,
                "warn" | "warning" => self.logging.level = LogLevel::Warn,
                "error" => self.logging.level = LogLevel::Error,
                other => log::warn!("Unknown IBCTL_LOG_LEVEL '{}', keeping default", other),
            }
        }
    }

    /// Validate that required fields are present.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.auth.username.is_empty() {
            return Err(ConfigError::Missing(
                "auth.username (or TWS_USERID env var)".to_string(),
            ));
        }
        if self.auth.password.expose_secret().is_empty() {
            return Err(ConfigError::Missing(
                "TWS_PASSWORD or TWS_PASSWORD_FILE env var".to_string(),
            ));
        }
        if matches!(self.auth.trading_mode, TradingMode::Both | TradingMode::Paper)
            && self.auth.paper.username.is_empty()
            && self.auth.trading_mode == TradingMode::Both
        {
            log::warn!("trading_mode=both but no paper username set; will use main credentials");
        }
        Ok(())
    }

}

/// Read an environment variable, with Docker secrets `_FILE` support.
///
/// If `VAR_FILE` is set, reads the file contents. Otherwise returns `VAR` value.
/// The `_FILE` variant takes precedence (Docker secrets pattern).
pub fn env_or_file(var: &str) -> Option<String> {
    // Check _FILE variant first (Docker secrets)
    let file_var = format!("{}_FILE", var);
    if let Ok(path) = std::env::var(&file_var) {
        match std::fs::read_to_string(&path) {
            Ok(contents) => return Some(contents.trim().to_string()),
            Err(e) => {
                log::warn!("Failed to read secret file {} (from {}): {}", path, file_var, e);
            }
        }
    }

    // Fall back to direct env var
    std::env::var(var).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Enum deserialization tests ---

    #[test]
    fn test_trading_mode_deserialize() {
        assert_eq!(
            toml::from_str::<AuthConfig>("trading_mode = \"live\"").unwrap().trading_mode,
            TradingMode::Live
        );
        assert_eq!(
            toml::from_str::<AuthConfig>("trading_mode = \"paper\"").unwrap().trading_mode,
            TradingMode::Paper
        );
        assert_eq!(
            toml::from_str::<AuthConfig>("trading_mode = \"both\"").unwrap().trading_mode,
            TradingMode::Both
        );
    }

    #[test]
    fn test_totp_provider_deserialize() {
        assert_eq!(
            toml::from_str::<TwoFaConfig>("provider = \"oathtool\"").unwrap().provider,
            TotpProvider::Oathtool
        );
        assert_eq!(
            toml::from_str::<TwoFaConfig>("provider = \"builtin\"").unwrap().provider,
            TotpProvider::Builtin
        );
    }

    #[test]
    fn test_session_action_deserialize() {
        assert_eq!(
            toml::from_str::<SessionConfig>("action = \"primary\"").unwrap().action,
            SessionAction::Primary
        );
        assert_eq!(
            toml::from_str::<SessionConfig>("action = \"secondary\"").unwrap().action,
            SessionAction::Secondary
        );
        assert_eq!(
            toml::from_str::<SessionConfig>("action = \"primaryoverride\"").unwrap().action,
            SessionAction::PrimaryOverride
        );
    }

    #[test]
    fn test_gateway_program_deserialize() {
        assert_eq!(
            toml::from_str::<GatewayConfig>("program = \"gateway\"").unwrap().program,
            GatewayProgram::Gateway
        );
        assert_eq!(
            toml::from_str::<GatewayConfig>("program = \"tws\"").unwrap().program,
            GatewayProgram::Tws
        );
    }

    #[test]
    fn test_log_level_deserialize() {
        assert_eq!(
            toml::from_str::<LoggingConfig>("level = \"debug\"").unwrap().level,
            LogLevel::Debug
        );
        assert_eq!(
            toml::from_str::<LoggingConfig>("level = \"error\"").unwrap().level,
            LogLevel::Error
        );
    }

    #[test]
    fn test_invalid_enum_value_fails() {
        assert!(toml::from_str::<AuthConfig>("trading_mode = \"invalid\"").is_err());
        assert!(toml::from_str::<GatewayConfig>("program = \"something\"").is_err());
    }

    // --- Display tests (used in JSON serialization) ---

    #[test]
    fn test_enum_display_roundtrip() {
        assert_eq!(TradingMode::Live.to_string(), "live");
        assert_eq!(TradingMode::Paper.to_string(), "paper");
        assert_eq!(TradingMode::Both.to_string(), "both");
        assert_eq!(SessionAction::PrimaryOverride.to_string(), "primaryoverride");
        assert_eq!(AcceptIncoming::Manual.to_string(), "manual");
        assert_eq!(LogLevel::Warn.to_string(), "warn");
    }

    // --- Config defaults tests ---

    #[test]
    fn test_default_config_values() {
        let config = Config::default();
        assert_eq!(config.auth.trading_mode, TradingMode::Live);
        assert_eq!(config.twofa.provider, TotpProvider::Oathtool);
        assert_eq!(config.twofa.timeout_action, TwoFaTimeoutAction::Restart);
        assert_eq!(config.gateway.program, GatewayProgram::Gateway);
        assert_eq!(config.session.action, SessionAction::Primary);
        assert_eq!(config.session.accept_incoming, AcceptIncoming::Accept);
        assert_eq!(config.logging.level, LogLevel::Info);
        assert_eq!(config.command_server.port, 7462);
        assert!(config.command_server.enabled);
    }

    // --- TOML parsing tests ---

    #[test]
    fn test_parse_minimal_toml() {
        let toml_str = r#"
[auth]
trading_mode = "paper"

[gateway]
program = "tws"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.auth.trading_mode, TradingMode::Paper);
        assert_eq!(config.gateway.program, GatewayProgram::Tws);
        // Defaults for unspecified fields
        assert_eq!(config.twofa.provider, TotpProvider::Oathtool);
    }

    #[test]
    fn test_unknown_toml_sections_ignored() {
        let toml_str = r#"
[auth]
trading_mode = "live"

[dashboard]
enabled = true
port = 8080

[some_future_feature]
key = "value"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.auth.trading_mode, TradingMode::Live);
    }

    // --- Validation tests ---

    #[test]
    fn test_validate_missing_username() {
        let config = Config::default();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_missing_password() {
        let mut config = Config::default();
        config.auth.username = "testuser".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_ok_with_credentials() {
        let mut config = Config::default();
        config.auth.username = "testuser".to_string();
        config.auth.password = SecretString::from("testpass".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_password_redacted_in_debug() {
        let mut config = Config::default();
        config.auth.password = SecretString::from("supersecret".to_string());
        let debug_output = format!("{:?}", config.auth);
        assert!(
            !debug_output.contains("supersecret"),
            "Password leaked in Debug output: {}", debug_output
        );
        assert!(debug_output.contains("REDACTED"));
    }

    #[test]
    fn test_password_expose_secret() {
        let mut config = Config::default();
        config.auth.password = SecretString::from("mypass".to_string());
        assert_eq!(config.auth.password.expose_secret(), "mypass");
    }
}
