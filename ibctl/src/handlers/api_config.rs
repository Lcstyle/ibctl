//! Post-login API configuration handler.
//!
//! After successful login, opens the Gateway's Global Configuration dialog
//! and sets API options: Master Client ID, Read-only API, order precaution
//! bypasses, auto-restart time. Mirrors IBC's ConfigureApiTask.

use crate::agent_client::AgentClient;
use crate::types::WindowId;

/// Errors that can occur during API configuration.
#[derive(Debug, thiserror::Error)]
pub enum ApiConfigError {
    #[error("agent error: {0}")]
    Agent(#[from] crate::handlers::HandlerError),
    #[error("{0}")]
    Other(String),
}

/// Parse an env var as a boolean: "yes", "true", "1" → true.
fn env_bool(var: &str) -> Option<bool> {
    std::env::var(var).ok().map(|v| {
        matches!(v.to_lowercase().as_str(), "yes" | "true" | "1")
    })
}

/// API configuration settings resolved from environment variables.
/// These mirror IBC's env-var-only settings (TWS_MASTER_CLIENT_ID, etc.)
/// and are intentionally not in the TOML config file.
#[derive(Debug, Clone)]
pub struct ApiConfigSettings {
    pub master_client_id: Option<String>,
    pub read_only_api: Option<bool>,
    pub bypass_order_precautions: Option<bool>,
    pub allow_blind_trading: Option<bool>,
    pub auto_restart_time: Option<String>,
    pub auto_logoff_time: Option<String>,
}

impl ApiConfigSettings {
    pub fn from_env() -> Self {
        Self {
            master_client_id: std::env::var("TWS_MASTER_CLIENT_ID").ok()
                .filter(|s| !s.is_empty()),
            read_only_api: env_bool("READ_ONLY_API"),
            bypass_order_precautions: env_bool("BYPASS_WARNING"),
            allow_blind_trading: env_bool("ALLOW_BLIND_TRADING"),
            auto_restart_time: std::env::var("AUTO_RESTART_TIME").ok()
                .filter(|s| !s.is_empty()),
            auto_logoff_time: std::env::var("AUTO_LOGOFF_TIME").ok()
                .filter(|s| !s.is_empty()),
        }
    }

    pub fn has_settings(&self) -> bool {
        self.master_client_id.is_some()
            || self.read_only_api.is_some()
            || self.bypass_order_precautions.is_some()
            || self.allow_blind_trading.is_some()
            || self.auto_restart_time.is_some()
            || self.auto_logoff_time.is_some()
    }
}

/// Checkbox labels for order precaution bypasses in the API/Precautions page.
const PRECAUTION_LABELS: &[&str] = &[
    "Bypass Order Precautions for API Orders",
    "Bypass Bond warning for API Orders",
    "Bypass negative yield to worst confirmation for API Orders",
    "Bypass Called Bond warning for API Orders",
    "Bypass \"same action pair trade\" warning for API orders",
    "Bypass price-based volatility risk warning for API Orders",
    "Bypass Redirect Order warning for Stock API Orders",
    "Bypass No Overfill Protection precaution",
    "Bypass Route Marketable to BBO warning for API orders",
];

/// Short pause — just enough for the Swing EDT to process the previous action.
/// Configurable via [timing] ui_tick_ms in ibctl.toml.
async fn tick(ms: u64) {
    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
}

/// Dismiss any popup dialogs that aren't the config dialog.
async fn dismiss_popups(client: &AgentClient, config_win_id: WindowId) {
    if let Ok(windows) = client.list_windows().await {
        for w in &windows {
            if w.id != config_win_id {
                let _ = client.click_button(w.id, "Yes").await;
                let _ = client.click_button(w.id, "OK").await;
            }
        }
    }
}

pub async fn apply_api_config(
    client: &AgentClient,
    settings: &ApiConfigSettings,
    tick_ms: u64,
) -> Result<(), ApiConfigError> {
    if !settings.has_settings() {
        log::info!("No API configuration settings to apply");
        return Ok(());
    }

    log::info!("Applying API configuration settings");

    // Find the main Gateway window
    let windows = client.list_windows().await
        .map_err(|e| ApiConfigError::Other(format!("Failed to list windows: {}", e)))?;
    let main_window = windows.iter().find(|w| {
        let t = w.title.to_lowercase();
        t.contains("ibkr gateway") || t.contains("ib gateway")
    });
    let win = match main_window {
        Some(w) => w,
        None => {
            return Err(ApiConfigError::Other("Main Gateway window not found — cannot apply API config".to_string()));
        }
    };

    // Open Configure -> Settings
    // Retry opening the config dialog up to 3 times.
    // Failure to open it is an ERROR, not a warning — proceeding without
    // configuration causes Read-Only API warnings when clients connect.
    let mut config_win = None;
    for attempt in 1..=3 {
        log::info!("Opening config dialog (attempt {})", attempt);

        match client.click_menu(win.id, "Configure/Settings").await {
            Ok(true) => {}
            _ => {
                // Fallback: try just "Configure" then wait for Settings submenu
                let _ = client.click_menu(win.id, "Configure").await;
                tick(tick_ms).await;
            }
        }

        // Poll for config dialog to appear
        for _ in 0..20 {
            tick(tick_ms).await;
            let wins = client.list_windows().await.unwrap_or_default();
            config_win = wins.into_iter().find(|w| {
                w.title.to_lowercase().contains("configuration")
            });
            if config_win.is_some() { break; }
        }

        if config_win.is_some() { break; }

        // Dismiss any lingering menu by clicking the window center
        let cx = win.bounds.as_ref().map(|b| b.width / 2).unwrap_or(350);
        let cy = win.bounds.as_ref().map(|b| b.height / 2).unwrap_or(275);
        let _ = client.click_at(win.id, cx, cy).await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    let config_win = match config_win {
        Some(w) => w,
        None => {
            log::error!("Configuration dialog not found after 3 attempts — config NOT applied");
            return Err(ApiConfigError::Other("Configuration dialog not found after 3 attempts".to_string()));
        }
    };
    let cid = config_win.id;
    log::info!("Configuration dialog found: {}", config_win.title);

    // --- API -> Settings ---
    client.select_tree_node(cid, "API").await
        .map_err(|e| ApiConfigError::Other(format!("Failed to select API: {}", e)))?;
    tick(tick_ms).await;
    client.select_tree_node(cid, "Settings").await
        .map_err(|_| ApiConfigError::Other("Failed to navigate to API/Settings".to_string()))?;
    tick(tick_ms).await;

    // Master Client ID (field index 1)
    if let Some(ref id) = settings.master_client_id {
        log::info!("Setting Master Client ID to {}", id);
        let _ = client.type_text(cid, 1, id).await;
    }

    // Read-Only API: force toggle to ensure it registers
    if let Some(read_only) = settings.read_only_api {
        if !read_only {
            log::info!("Ensuring Read-only API is OFF");
            let _ = client.set_checkbox(cid, "Read-Only API", Some(true)).await;
            let _ = client.set_checkbox(cid, "Read-Only API", Some(false)).await;
        } else {
            let _ = client.set_checkbox(cid, "Read-Only API", Some(true)).await;
        }
    }

    // --- API -> Precautions ---
    if let Some(bypass) = settings.bypass_order_precautions {
        client.select_tree_node(cid, "Precautions").await.ok();
        tick(tick_ms).await;
        log::info!("Setting order precaution bypasses to {}", bypass);

        for label in PRECAUTION_LABELS {
            let _ = client.set_checkbox(cid, label, Some(bypass)).await;
        }
        // Single sweep for confirmation dialogs
        tick(tick_ms).await;
        dismiss_popups(client, cid).await;
    }

    // --- Lock and Exit ---
    if settings.auto_restart_time.is_some() || settings.auto_logoff_time.is_some() {
        client.select_tree_node(cid, "Lock and Exit").await.ok();
        tick(tick_ms).await;

        if let Some(ref restart_time) = settings.auto_restart_time {
            let (time_val, am_pm) = parse_time_with_ampm(restart_time);
            log::info!("Setting Auto Restart: {} {}", time_val, am_pm);
            let _ = client.type_text(cid, 0, time_val).await;
            let _ = client.click_button(cid, am_pm).await;
            let _ = client.click_button(cid, "Auto restart").await;
            tick(tick_ms).await;
            dismiss_popups(client, cid).await;
        } else if let Some(ref logoff_time) = settings.auto_logoff_time {
            let (time_val, am_pm) = parse_time_with_ampm(logoff_time);
            log::info!("Setting Auto Logoff: {} {}", time_val, am_pm);
            let _ = client.type_text(cid, 0, time_val).await;
            let _ = client.click_button(cid, am_pm).await;
            let _ = client.click_button(cid, "Auto logoff").await;
        }
    }

    // --- Save and close ---
    let _ = client.click_button(cid, "Apply").await;
    tick(tick_ms).await;
    let _ = client.click_button(cid, "OK").await;
    tick(tick_ms).await;

    // Dismiss post-config dialogs (max 3 sweeps)
    for _ in 0..3 {
        tick(tick_ms).await;
        let post = client.list_windows().await.unwrap_or_default();
        if post.len() <= 1 { break; }
        for w in &post {
            let _ = client.click_button(w.id, "OK").await;
        }
    }

    // Click center of main window to dismiss any lingering menus
    let final_windows = client.list_windows().await.unwrap_or_default();
    if let Some(main_win) = final_windows.first() {
        let cx = main_win.bounds.as_ref().map(|b| b.width / 2).unwrap_or(350);
        let cy = main_win.bounds.as_ref().map(|b| b.height / 2).unwrap_or(275);
        let _ = client.click_at(main_win.id, cx, cy).await;
    }

    log::info!("API configuration applied successfully");
    Ok(())
}

/// Parse a time string like "11:30 PM" or "09:00" into (time, am_pm).
/// Defaults to "PM" if no AM/PM suffix is provided.
pub(crate) fn parse_time_with_ampm(input: &str) -> (&str, &str) {
    let parts: Vec<&str> = input.split_whitespace().collect();
    let time_val = parts.first().copied().unwrap_or(input);
    let am_pm = parts.get(1).copied().unwrap_or("PM");
    (time_val, am_pm)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- ApiConfigSettings tests ---

    #[test]
    fn test_has_settings_empty() {
        let s = ApiConfigSettings {
            master_client_id: None,
            read_only_api: None,
            bypass_order_precautions: None,
            allow_blind_trading: None,
            auto_restart_time: None,
            auto_logoff_time: None,
        };
        assert!(!s.has_settings());
    }

    #[test]
    fn test_has_settings_with_master_id() {
        let s = ApiConfigSettings {
            master_client_id: Some("0".to_string()),
            read_only_api: None,
            bypass_order_precautions: None,
            allow_blind_trading: None,
            auto_restart_time: None,
            auto_logoff_time: None,
        };
        assert!(s.has_settings());
    }

    #[test]
    fn test_has_settings_with_read_only() {
        let s = ApiConfigSettings {
            master_client_id: None,
            read_only_api: Some(false),
            bypass_order_precautions: None,
            allow_blind_trading: None,
            auto_restart_time: None,
            auto_logoff_time: None,
        };
        assert!(s.has_settings());
    }

    #[test]
    fn test_has_settings_with_bypass() {
        let s = ApiConfigSettings {
            master_client_id: None,
            read_only_api: None,
            bypass_order_precautions: Some(true),
            allow_blind_trading: None,
            auto_restart_time: None,
            auto_logoff_time: None,
        };
        assert!(s.has_settings());
    }

    // --- parse_time_with_ampm tests ---

    #[test]
    fn test_parse_time_with_ampm_full() {
        assert_eq!(parse_time_with_ampm("11:30 PM"), ("11:30", "PM"));
        assert_eq!(parse_time_with_ampm("09:00 AM"), ("09:00", "AM"));
    }

    #[test]
    fn test_parse_time_without_ampm_defaults_pm() {
        assert_eq!(parse_time_with_ampm("11:30"), ("11:30", "PM"));
    }

    #[test]
    fn test_parse_time_lowercase() {
        assert_eq!(parse_time_with_ampm("3:45 pm"), ("3:45", "pm"));
    }

    // --- PRECAUTION_LABELS constant test ---

    #[test]
    fn test_precaution_labels_count() {
        assert_eq!(PRECAUTION_LABELS.len(), 9);
    }
}
