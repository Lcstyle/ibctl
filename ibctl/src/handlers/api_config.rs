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
///
/// These strings are prefixes of the Gateway JLabel text (Gateway adds
/// trailing periods on some rows, plus extra qualifiers on the
/// "No Overfill" row). The matcher does case-insensitive `startsWith`,
/// which handles those. Case matches Gateway's own inconsistent
/// rendering — most rows say "API Orders" but rows 5 and 9 use
/// lowercase "API orders". Faithful mirroring keeps the exact-match
/// fast path hitting.
///
/// Rows 5 and 9 (embedded `"…"`) go on the wire as JSON-escaped `\"`;
/// see HttpApi.decodeJsonString for the wire-side decode fix that made
/// this class of label match at all (Lcstyle/ibctl#4).
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

/// Summary returned by `apply_api_config` for the state machine to fold into
/// its Stats counters. A non-zero `precaution_labels_not_found` signals label
/// drift between our constants and the Gateway UI — the CORE-level fix is a
/// tolerant matcher in the Java agent; this count is the TRIPWIRE that
/// screams if the tolerant matcher itself starts missing.
#[derive(Debug, Clone, Default)]
pub struct ApiConfigReport {
    pub precaution_labels_not_found: u32,
    pub read_only_api_label_not_found: u32,
}

/// Gateway version string used only for diagnostic warn logs on label drift.
/// Reads at call time (not init) so a container restart with a different
/// TWS_MAJOR_VRSN picks up the new value without a re-plumbing.
fn gateway_version_hint() -> String {
    std::env::var("IB_GATEWAY_VERSION")
        .or_else(|_| std::env::var("TWS_MAJOR_VRSN"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Short pause — just enough for the Swing EDT to process the previous action.
/// Configurable via \[timing\] ui_tick_ms in ibctl.toml.
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

/// Toggle each PRECAUTION_LABELS entry on the currently-selected Precautions
/// panel, returning the count of labels the Gateway UI didn't match.
///
/// A non-zero return means the Java-side tolerant matcher failed too —
/// either Gateway renamed a checkbox or the label carries a Unicode oddity
/// beyond what `SwingInspector.normalizeLabel` handles today. Each miss is
/// warn-logged with the current `IB_GATEWAY_VERSION` so drift can be
/// correlated to a specific Gateway release.
///
/// Extracted from apply_api_config so the tripwire is unit-testable without
/// having to mock every menu-navigation call the outer function performs.
async fn apply_precaution_labels(client: &AgentClient, cid: WindowId, bypass: bool) -> u32 {
    let mut missing = 0u32;
    for label in PRECAUTION_LABELS {
        match client.set_checkbox(cid, label, Some(bypass)).await {
            Ok(outcome) if !outcome.found => {
                log::warn!(
                    "PRECAUTION_LABELS drift: '{}' not found (IB Gateway {}); Gateway responded: {}",
                    label,
                    gateway_version_hint(),
                    outcome.error.as_deref().unwrap_or("<no error>")
                );
                missing = missing.saturating_add(1);
            }
            Ok(_) => {}
            Err(e) => log::warn!("set_checkbox failed for '{}': {}", label, e),
        }
    }
    missing
}

pub async fn apply_api_config(
    client: &AgentClient,
    settings: &ApiConfigSettings,
    tick_ms: u64,
) -> Result<ApiConfigReport, ApiConfigError> {
    let mut report = ApiConfigReport::default();

    if !settings.has_settings() {
        log::info!("No API configuration settings to apply");
        return Ok(report);
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

    // Read-Only API: force toggle to ensure it registers.
    // Wraps each call so a Gateway UI rename shows up as a
    // read_only_api_label_not_found bump on /api/status. Dedup within the
    // force-toggle sequence: the same missing label counts once, not twice.
    if let Some(read_only) = settings.read_only_api {
        let mut ro_missing_seen = false;
        let mut check = |outcome: crate::agent_client::CheckboxOutcome| {
            if !outcome.found && !ro_missing_seen {
                log::warn!(
                    "PRECAUTION_LABELS drift: 'Read-Only API' not found (IB Gateway {}); Gateway responded: {}",
                    gateway_version_hint(),
                    outcome.error.as_deref().unwrap_or("<no error>")
                );
                report.read_only_api_label_not_found = 1;
                ro_missing_seen = true;
            }
        };
        if !read_only {
            log::info!("Ensuring Read-only API is OFF");
            if let Ok(o) = client.set_checkbox(cid, "Read-Only API", Some(true)).await { check(o); }
            if let Ok(o) = client.set_checkbox(cid, "Read-Only API", Some(false)).await { check(o); }
        } else if let Ok(o) = client.set_checkbox(cid, "Read-Only API", Some(true)).await { check(o); }
    }

    // --- API -> Precautions ---
    if let Some(bypass) = settings.bypass_order_precautions {
        client.select_tree_node(cid, "Precautions").await.ok();
        tick(tick_ms).await;
        log::info!("Setting order precaution bypasses to {}", bypass);

        report.precaution_labels_not_found = apply_precaution_labels(client, cid, bypass).await;

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
    Ok(report)
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

    /// Faithfulness test: PRECAUTION_LABELS should mirror the exact casing
    /// IB Gateway 10.47.1b renders. Live probe on 2026-07-12 showed rows 5
    /// and 9 use lowercase "API orders" while the other 5 API-Orders rows
    /// use "API Orders". Case-insensitive matching hides mismatches, but
    /// keeping the constant faithful lets the exact-match fast path hit
    /// (which is a fraction faster) and preserves debuggability when
    /// eyeballing logs.
    #[test]
    fn test_precaution_labels_mirror_gateway_casing() {
        let lowercase_orders_indices = [4usize, 8];
        for (i, label) in PRECAUTION_LABELS.iter().enumerate() {
            if lowercase_orders_indices.contains(&i) {
                assert!(
                    label.contains("API orders"),
                    "row {i} should use lowercase 'API orders' to mirror Gateway 10.47.1b; got: {label:?}"
                );
            } else if label.to_lowercase().contains("api orders") {
                assert!(
                    label.contains("API Orders"),
                    "row {i} should use capital 'API Orders' to mirror Gateway 10.47.1b; got: {label:?}"
                );
            }
        }
    }

    // --- Tripwire tests: apply_precaution_labels counts found:false ---

    use crate::agent_client::{AgentClient, MockAgent};

    #[tokio::test]
    async fn apply_precaution_labels_returns_zero_when_all_labels_match() {
        let client = AgentClient::mock(MockAgent::default());
        let missing = apply_precaution_labels(&client, WindowId(1), true).await;
        assert_eq!(missing, 0);
    }

    #[tokio::test]
    async fn apply_precaution_labels_counts_the_embedded_quote_case() {
        // Simulate the Lcstyle/ibctl#4 failure shape: exactly one label
        // — the embedded-quote row — comes back found:false, the other
        // eight match. Before the fix on the agent's JSON decoder, the
        // wire-side `\"` escape survived into `setCheckBox`, so this row
        // never matched Gateway's ASCII-quote JLabel text.
        let mut not_found = std::collections::HashSet::new();
        not_found.insert(
            "Bypass \"same action pair trade\" warning for API orders".to_string(),
        );
        let client = AgentClient::mock(MockAgent {
            not_found_labels: not_found,
            ..Default::default()
        });
        let missing = apply_precaution_labels(&client, WindowId(1), true).await;
        assert_eq!(missing, 1);
    }

    #[tokio::test]
    async fn apply_precaution_labels_counts_every_missing_label_up_to_len() {
        // Full drift — every label goes missing. Saturating_add guards
        // against overflow; assert we hit the array length.
        let mut not_found = std::collections::HashSet::new();
        for label in PRECAUTION_LABELS {
            not_found.insert((*label).to_string());
        }
        let client = AgentClient::mock(MockAgent {
            not_found_labels: not_found,
            ..Default::default()
        });
        let missing = apply_precaution_labels(&client, WindowId(1), true).await;
        assert_eq!(missing as usize, PRECAUTION_LABELS.len());
    }

    #[tokio::test]
    async fn set_checkbox_outcome_reads_found_false_from_mock() {
        // Direct check on the wire type — MockAgent should surface
        // found:false when a label is in not_found_labels, not conflate
        // it with the outer envelope's ok field.
        let mut not_found = std::collections::HashSet::new();
        not_found.insert("Missing Label".to_string());
        let client = AgentClient::mock(MockAgent {
            not_found_labels: not_found,
            ..Default::default()
        });

        let hit = client
            .set_checkbox(WindowId(1), "Present Label", Some(true))
            .await
            .expect("mock cannot fail");
        assert!(hit.found);

        let miss = client
            .set_checkbox(WindowId(1), "Missing Label", Some(true))
            .await
            .expect("mock cannot fail");
        assert!(!miss.found);
        assert!(miss.error.is_some());
    }
}
