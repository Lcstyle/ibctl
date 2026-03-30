//! Configuration loading with layered precedence:
//! 1. Built-in defaults (lowest)
//! 2. TOML config file
//! 3. Environment variables (highest)
//!
//! Docker secrets (_FILE suffix) supported for sensitive values.

use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

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
#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub username: String,
    /// Password is env-only (TWS_PASSWORD / TWS_PASSWORD_FILE). Never in config file.
    #[serde(skip)]
    pub password: String,
    /// "live", "paper", or "both"
    pub trading_mode: String,
    pub paper: PaperAuthConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PaperAuthConfig {
    pub username: String,
    /// Paper password is env-only (TWS_PASSWORD_PAPER / TWS_PASSWORD_PAPER_FILE).
    #[serde(skip)]
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TwoFaConfig {
    /// Name of the env var holding the TOTP secret (default: "TWOFACTOR_CODE")
    pub secret_env: String,
    /// "oathtool" or "builtin"
    pub provider: String,
    /// "restart" or "exit"
    pub timeout_action: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GatewayConfig {
    pub tws_path: String,
    pub settings_path: String,
    pub version: String,
    pub java_heap_mb: u32,
    /// "gateway" or "tws"
    pub program: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SessionConfig {
    /// "primary", "secondary", or "primaryoverride"
    pub action: String,
    /// "accept", "reject", or "manual"
    pub accept_incoming: String,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// "debug", "info", "warn", or "error"
    pub level: String,
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

impl Default for Config {
    fn default() -> Self {
        Self {
            auth: AuthConfig::default(),
            twofa: TwoFaConfig::default(),
            gateway: GatewayConfig::default(),
            session: SessionConfig::default(),
            command_server: CommandServerConfig::default(),
            agent: AgentConfig::default(),
            logging: LoggingConfig::default(),
            timing: TimingConfig::default(),
            _extra: std::collections::HashMap::new(),
        }
    }
}

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
            password: String::new(),
            trading_mode: "live".to_string(),
            paper: PaperAuthConfig::default(),
        }
    }
}

impl Default for PaperAuthConfig {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
        }
    }
}

impl Default for TwoFaConfig {
    fn default() -> Self {
        Self {
            secret_env: "TWOFACTOR_CODE".to_string(),
            provider: "oathtool".to_string(),
            timeout_action: "restart".to_string(),
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
            program: "gateway".to_string(),
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            action: "primary".to_string(),
            accept_incoming: "accept".to_string(),
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
            socket_path: "/tmp/ibctl.sock".to_string(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
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
            self.auth.password = v;
        }
        if let Some(v) = env_or_file("TRADING_MODE") {
            self.auth.trading_mode = v;
        }

        // Paper auth
        if let Some(v) = env_or_file("TWS_USERID_PAPER") {
            self.auth.paper.username = v;
        }
        if let Some(v) = env_or_file("TWS_PASSWORD_PAPER") {
            self.auth.paper.password = v;
        }

        // 2FA
        if let Some(v) = std::env::var("TOTP_PROVIDER").ok() {
            self.twofa.provider = v;
        }
        if let Some(v) = std::env::var("TWOFA_TIMEOUT_ACTION").ok() {
            self.twofa.timeout_action = v;
        }
        if let Some(v) = std::env::var("TWOFA_EXIT_INTERVAL").ok().and_then(|s| s.parse().ok()) {
            self.twofa.timeout_seconds = v;
        }

        // Gateway
        if let Some(v) = std::env::var("TWS_PATH").ok() {
            self.gateway.tws_path = v;
        }
        if let Some(v) = std::env::var("TWS_SETTINGS_PATH").ok() {
            self.gateway.settings_path = v;
        }
        if let Some(v) = std::env::var("TWS_MAJOR_VRSN").ok() {
            self.gateway.version = v;
        }
        if let Some(v) = std::env::var("JAVA_HEAP_SIZE").ok().and_then(|s| s.parse().ok()) {
            self.gateway.java_heap_mb = v;
        }
        if let Some(v) = std::env::var("GATEWAY_OR_TWS").ok() {
            self.gateway.program = v;
        }

        // Session
        if let Some(v) = std::env::var("IBCTL_SESSION_ACTION").ok() {
            self.session.action = v;
        }
        if let Some(v) = std::env::var("IBCTL_ACCEPT_INCOMING").ok() {
            self.session.accept_incoming = v;
        }

        // Command server
        if let Ok(v) = std::env::var("IBCTL_COMMAND_SERVER_ENABLED") {
            self.command_server.enabled = v.to_lowercase() != "false" && v != "0" && v.to_lowercase() != "no";
        }
        if let Some(v) = std::env::var("IBCTL_COMMAND_PORT").ok().and_then(|s| s.parse().ok()) {
            self.command_server.port = v;
        }
        if let Some(v) = std::env::var("IBCTL_CONTROL_FROM").ok() {
            self.command_server.control_from =
                v.split(',').map(|s| s.trim().to_string()).collect();
        }

        // Agent
        if let Some(v) = std::env::var("IBCTL_AGENT_SOCKET").ok() {
            self.agent.socket_path = v;
        }

        // Logging
        if let Some(v) = std::env::var("IBCTL_LOG_LEVEL").ok() {
            self.logging.level = v;
        }
    }

    /// Validate that required fields are present.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.auth.username.is_empty() {
            return Err(ConfigError::Missing(
                "auth.username (or TWS_USERID env var)".to_string(),
            ));
        }
        if self.auth.password.is_empty() {
            return Err(ConfigError::Missing(
                "TWS_PASSWORD or TWS_PASSWORD_FILE env var".to_string(),
            ));
        }
        if self.auth.trading_mode == "both" || self.auth.trading_mode == "paper" {
            if self.auth.paper.username.is_empty() && self.auth.trading_mode == "both" {
                log::warn!("trading_mode=both but no paper username set; will use main credentials");
            }
        }
        Ok(())
    }

    /// Returns the effective settings path (falls back to tws_path if empty).
    pub fn effective_settings_path(&self) -> &str {
        if self.gateway.settings_path.is_empty() {
            &self.gateway.tws_path
        } else {
            &self.gateway.settings_path
        }
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
