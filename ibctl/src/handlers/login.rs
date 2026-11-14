//! Login dialog handler.
//!
//! Recognizes the IB Gateway login window and fills in credentials.
//! Supports both live and paper trading modes.
//!
//! After clicking the trading mode radio button, verifies the UI updated
//! by inspecting button labels via dump_components. This prevents the
//! paper-mode bug where credentials were submitted before the mode switch
//! took effect.
//!
//! The handler is fail-CLOSED throughout: if the mode cannot be verified, or a
//! credential field is missing, or this mode's login button is absent, it
//! returns `HandlerResult::Error` and submits nothing. Every one of those
//! conditions previously fell through to "submit anyway", which could leave a
//! paper session sitting on a filled-in login form with no error recorded.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};

use secrecy::{ExposeSecret, SecretString};

use crate::agent_client::{AgentClient, WindowInfo};
use crate::agent_events::LoginFormState;
use crate::config::TradingMode;
use crate::handlers::{DialogHandler, HandlerError, HandlerResult};
use crate::types::WindowId;

/// Text field index for the username input.
pub(crate) const USERNAME_FIELD: usize = 0;
/// Text field index for the password input.
pub(crate) const PASSWORD_FIELD: usize = 1;
/// How long "Log In" may take to enable after the credentials are typed.
const LOG_IN_ENABLE_WAIT_MS: u64 = 2000;

/// Whether a window with this title means the Gateway is logging in by
/// itself: its own re-login after a backend drop opens "Login"; any login
/// shows "Authenticating..." / "Attempt N: Authenticating..." and then
/// "Starting application...". A second login submitted meanwhile — the same
/// JVM, the same user — is what puts a gateway into a loop of displacing its
/// own session.
pub(crate) fn is_gateway_login_in_flight(title: &str) -> bool {
    let t = title.trim().to_lowercase();
    t == "login" || t.contains("authenticating") || t.contains("starting application")
}
/// How long to wait for the requested trading mode to show up in the UI.
///
/// This was 5 attempts x 200ms — a one-second budget — and that is where the
/// paper login lost its race. When the JVM is slow to compose the login panel
/// (measured at 7-9s during a startup regression, against a usual ~2s) the mode
/// toggle may not even exist yet one second after we asked for it, so the
/// switch was never applied and the wrong mode's button was the only one on
/// screen.
///
/// A deadline generous enough to cover a slow startup replaces the fixed
/// attempt count. It costs nothing in the normal case, because the wait is
/// woken by the agent's `login_form_ready` event rather than spent sleeping — a
/// form that composes quickly is verified in milliseconds.
const MODE_VERIFY_TIMEOUT_SECS: u64 = 20;
/// Fallback poll interval, used only while no form event arrives.
///
/// Kept because an agent that predates the re-emitting watcher fires
/// `login_form_ready` exactly once, from WINDOW_OPENED, and never again. On
/// that agent an event-only wait would block for the whole deadline and then
/// fail, so the UI is still asked directly. A version skew degrades to the old
/// polling behaviour instead of breaking.
const MODE_VERIFY_POLL_MS: u64 = 250;
/// Delay after selecting the API type, before the mode click.
const API_TYPE_SETTLE_MS: u64 = 200;

/// Handles the IB Gateway login dialog by filling username, password,
/// and clicking the appropriate login button.
///
/// Tracks whether login has been submitted to avoid re-dispatching
/// on the main Gateway window (which shares a similar title).
/// Mirrors IBC's LoginFrameHandler which also tracks login state.
pub struct LoginHandler {
    username: String, // nosecret
    password: SecretString,
    trading_mode: TradingMode,
    /// Set to true after credentials are submitted.
    /// Prevents re-matching the main gateway window post-login.
    login_submitted: AtomicBool,
    /// The agent's latest view of the login form, if the registry wired it up.
    ///
    /// `None` in unit tests and on any construction path that does not supply
    /// it; the handler then relies on the `dump_components` fallback alone.
    login_form: Option<tokio::sync::watch::Receiver<Option<LoginFormState>>>,
}

impl LoginHandler {
    pub fn new(username: String, password: SecretString, trading_mode: TradingMode) -> Self { // nosecret
        Self {
            username,
            password,
            trading_mode,
            login_submitted: AtomicBool::new(false),
            login_form: None,
        }
    }

    /// Subscribe this handler to the agent's `login_form_ready` stream.
    ///
    /// With it, the mode-switch wait is woken by the form actually changing.
    /// Without it, the wait falls back to polling `dump_components`.
    pub fn with_form_events(
        mut self,
        rx: tokio::sync::watch::Receiver<Option<LoginFormState>>,
    ) -> Self {
        self.login_form = Some(rx);
        self
    }
}

impl DialogHandler for LoginHandler {
    fn name(&self) -> &str {
        "LoginHandler"
    }

    fn reset(&self) {
        self.login_submitted.store(false, Ordering::Relaxed);
    }

    fn is_login_step(&self) -> bool {
        true
    }

    fn mark_login_complete(&self) {
        // Stop matching the main Gateway window. Without this, do_connected's
        // popup-reconciliation sweep (which runs every tick, purely to
        // auto-dismiss popups) keeps dispatching to this handler forever on
        // any window titled "IBKR Gateway" — including the one we are
        // legitimately connected through, since that title match is on
        // substring alone. See DialogHandler::mark_login_complete.
        self.login_submitted.store(true, Ordering::Relaxed);
    }

    fn can_handle(&self, window: &WindowInfo) -> bool {
        // Once login is submitted, don't match again until reset
        if self.login_submitted.load(Ordering::Relaxed) {
            return false;
        }

        let title = window.title.to_lowercase();
        title.contains("ibkr gateway")
            || title.contains("ib gateway")
            || title.contains("login")
            || title.contains("interactive brokers")
    }

    fn handle<'a>(
        &'a self,
        client: &'a AgentClient,
        window: &'a WindowInfo,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>> + Send + 'a>> {
        Box::pin(async move {
            log::info!(
                "Handling login dialog '{}' (mode={})",
                window.title,
                self.trading_mode
            );

            // One login in flight per JVM. If the Gateway is already
            // logging in by itself, a second login from here displaces it and
            // gets displaced back — for hours.
            if let Ok(windows) = client.list_windows().await {
                if let Some(busy) = windows
                    .iter()
                    .find(|w| w.id != window.id && is_gateway_login_in_flight(&w.title))
                {
                    log::warn!(
                        "The Gateway is logging in by itself ('{}' open) — not submitting a \
                         second login",
                        busy.title
                    );
                    return Ok(HandlerResult::NotApplicable);
                }
            }

            // Step 1: Select API type — "IB API" (not "FIX CTCI")
            // "may already be selected" used to excuse the Ok(false) branch. It
            // was never a real explanation — the agent's findButton locates a
            // radio whether or not it is selected, so a miss means the widget
            // is genuinely not in the tree yet. It also could not fire, since
            // the envelope made every click report success.
            let mut api_type_clicked = false;
            match client.click_button(window.id, "IB API").await {
                Ok(true) => {
                    api_type_clicked = true;
                    log::info!("Selected 'IB API' mode");
                }
                Ok(false) => log::info!(
                    "'IB API' radio not present yet — the panel is still being built; \
                     will select it once it appears"
                ),
                Err(e) => log::debug!("Failed to click 'IB API': {}", e),
            }

            tokio::time::sleep(std::time::Duration::from_millis(API_TYPE_SETTLE_MS)).await;

            // Step 2: Select trading mode with verification.
            // The expected login button label confirms the mode switch took effect.
            let mode_label = match self.trading_mode {
                TradingMode::Paper => "Paper Trading",
                _ => "Live Trading",
            };
            let expected_button = match self.trading_mode {
                TradingMode::Paper => "Paper Log In",
                _ => "Log In",
            };

            let win_id = WindowId(window.id.0);

            // The pre-click component dump that lived here is gone. It existed to
            // answer one question — when the mode click missed, was the toggle
            // ABSENT (a startup race) or PRESENT-but-not-clicked (a click
            // defect)? — which was unanswerable only because click_button
            // returned the HTTP envelope and so reported success either way.
            // Now that it reports the agent's `found`, Ok(false) IS "absent"
            // and the answer arrives for free. Removing the dump also gives
            // back an RTT on the exact path whose timing was in question.
            let t_click = std::time::Instant::now();

            let mut mode_clicked = false;
            match client.click_button(window.id, mode_label).await {
                Ok(true) => {
                    mode_clicked = true;
                    log::info!("Selected '{}' mode", mode_label);
                }
                // This is the startup race, stated plainly. The verification
                // wait below is what recovers from it: the toggle appears, the
                // agent re-emits login_form_ready, and we click through then.
                Ok(false) => log::warn!(
                    "'{}' toggle not present at click time — Gateway has not built \
                     it yet; waiting for the form to report the switch",
                    mode_label
                ),
                Err(e) => log::warn!("Failed to click '{}': {}", mode_label, e),
            }

            // Wait for the mode switch to be visible, event-first.
            //
            // Two independent confirmations of the same fact, whichever arrives
            // first:
            //
            //   1. `login_form_ready` naming `expected_button`. The agent
            //      re-emits that event whenever the form's composition or
            //      selected mode changes, so this is a push notification that
            //      the switch landed — no polling interval to lose a race
            //      against.
            //   2. `dump_components` showing the button. Needed because an
            //      agent without the re-emitting watcher sends the event once,
            //      before Gateway has finished building the panel, and never
            //      corrects it. Without this fallback a version skew would
            //      block for the whole deadline and then fail closed on a
            //      perfectly healthy form.
            //
            // Between checks we sleep on `changed()` raced against a poll tick,
            // so a fast form is confirmed in milliseconds and a slow one is
            // still confirmed rather than timing out at one second.
            // tokio's clock, not std's: `std::time::Instant` is unaffected by
            // `time::pause()`, so a deadline built from it would never arrive
            // under a paused-clock test while the virtual clock raced ahead.
            let deadline = tokio::time::Instant::now()
                + std::time::Duration::from_secs(MODE_VERIFY_TIMEOUT_SECS);
            let mut form_events = self.login_form.clone();
            let mut mode_verified = false;
            let mut attempt = 0u32;

            while !mode_verified {
                attempt += 1;

                // --- 1. the event, if the agent has told us anything yet ---
                if let Some(rx) = form_events.as_mut() {
                    // borrow_and_update marks this value seen, so the
                    // `changed()` below waits for the NEXT change rather than
                    // returning immediately on one we already looked at.
                    let observed = rx.borrow_and_update().clone();
                    if let Some(form) = observed {
                        if form.login_button.as_deref() == Some(expected_button) {
                            log::info!(
                                "Mode switch verified via login_form_ready: button={:?} mode={:?} \
                                 (attempt {}, {}ms)",
                                form.login_button,
                                form.selected_mode,
                                attempt,
                                t_click.elapsed().as_millis()
                            );
                            mode_verified = true;
                            break;
                        }
                        log::debug!(
                            "login_form_ready so far: button={:?} mode={:?} fields={}/{} \
                             — waiting for {:?}",
                            form.login_button,
                            form.selected_mode,
                            form.text_field_count,
                            form.password_field_count,
                            expected_button
                        );
                    }
                }

                // --- 2. ask the UI directly ---
                match client.dump_components(win_id).await {
                    Ok(components) => {
                        let labels: Vec<&str> = components
                            .get("buttons")
                            .and_then(|b| b.as_array())
                            .map(|bs| {
                                bs.iter()
                                    .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                                    .collect()
                            })
                            .unwrap_or_default();

                        if labels.contains(&expected_button) {
                            log::info!(
                                "Mode switch verified: '{}' button present (attempt {}, {}ms)",
                                expected_button,
                                attempt,
                                t_click.elapsed().as_millis()
                            );
                            mode_verified = true;
                            break;
                        }

                        // If the toggle was not in the tree when we first
                        // clicked, click it the moment it appears. Nothing else
                        // in this loop performs the click, so without this a
                        // late-arriving toggle would never be actioned: the wait
                        // could only ever burn the full deadline and fail closed,
                        // and the retry from the top would pay for it again.
                        // This is the whole point of waiting on the form rather
                        // than on a clock — we act when the UI is ready, not
                        // when a timer says it should have been.
                        // Same race, same panel: the API-type radio is next to
                        // the mode toggle, so if one was missing so was the
                        // other. Gateway defaults to IB API, which is why a
                        // miss here has been survivable — but relying on a
                        // default we never confirmed is what the rest of this
                        // handler stopped doing, so select it once it exists.
                        if !api_type_clicked && labels.contains(&"IB API") {
                            match client.click_button(window.id, "IB API").await {
                                Ok(true) => {
                                    api_type_clicked = true;
                                    log::info!("Selected 'IB API' mode — radio appeared late");
                                }
                                Ok(false) => log::debug!(
                                    "'IB API' vanished between the dump and the click"
                                ),
                                Err(e) => {
                                    log::debug!("Failed to click 'IB API' on retry: {}", e)
                                }
                            }
                        }

                        if !mode_clicked && labels.contains(&mode_label) {
                            match client.click_button(window.id, mode_label).await {
                                Ok(true) => {
                                    mode_clicked = true;
                                    log::info!(
                                        "Selected '{}' mode — toggle appeared {}ms after \
                                         the first attempt",
                                        mode_label,
                                        t_click.elapsed().as_millis()
                                    );
                                }
                                Ok(false) => log::debug!(
                                    "'{}' vanished between the dump and the click",
                                    mode_label
                                ),
                                Err(e) => log::warn!(
                                    "Failed to click '{}' on retry: {}",
                                    mode_label,
                                    e
                                ),
                            }
                        }

                        // Log WHAT is present, not just that the expected label
                        // is missing: a toggle that shows up on a later pass is
                        // a race, one that never shows up is a different bug.
                        log::info!(
                            "login.instrument stage=verify_miss attempt={} elapsed_ms={} \
                             target_present={} button_count={} buttons={:?}",
                            attempt,
                            t_click.elapsed().as_millis(),
                            labels.contains(&mode_label),
                            labels.len(),
                            labels
                        );
                    }
                    // Previously `if let Ok(...)` with no else, so a dump error
                    // was indistinguishable from "button absent" and five
                    // transport failures produced the same verdict as a genuine
                    // miss. Now they are distinguishable.
                    Err(e) => log::warn!(
                        "login.instrument stage=verify_dump_failed attempt={} err={}",
                        attempt,
                        e
                    ),
                }

                let now = tokio::time::Instant::now();
                if now >= deadline {
                    break;
                }

                // --- 3. sleep until the form changes, or the next tick ---
                let tick = std::cmp::min(
                    std::time::Duration::from_millis(MODE_VERIFY_POLL_MS),
                    deadline - now,
                );
                let mut channel_closed = false;
                match form_events.as_mut() {
                    Some(rx) => {
                        tokio::select! {
                            // `changed()` errors the moment the sender is
                            // dropped, and would then return instantly forever —
                            // turning this wait into a busy loop. Detect it and
                            // fall back to plain polling.
                            res = rx.changed() => channel_closed = res.is_err(),
                            _ = tokio::time::sleep(tick) => {}
                        }
                    }
                    None => tokio::time::sleep(tick).await,
                }
                if channel_closed {
                    log::warn!(
                        "login_form_ready channel closed — falling back to polling \
                         dump_components for the rest of this attempt"
                    );
                    form_events = None;
                    tokio::time::sleep(tick).await;
                }
            }

            // Fail CLOSED when the mode cannot be verified.
            //
            // This used to warn and continue. Continuing means typing this
            // mode's credentials into a form that may still be showing the
            // other mode, and then submitting them. The two outcomes are not
            // symmetrical:
            //
            //   * A login that does not happen is recoverable. Returning
            //     `Error` leaves `login_submitted` false, the registry is
            //     reset, and the state machine re-dispatches this handler on
            //     the next tick — by which time the form has settled. The
            //     retry is bounded by `login_dialog_timeout_secs`, and a
            //     gateway stuck out of Connected is paged after 10 minutes by
            //     the dwell monitor, so this cannot fail silently.
            //
            //   * A login submitted against the wrong mode is not
            //     recoverable, and repeated wrong-mode submissions are how an
            //     IBKR account gets locked for failed attempts.
            //
            // So: no credentials leave this function until the button that
            // belongs to this mode has actually been observed.
            if !mode_verified {
                log::error!(
                    "Mode switch to '{}' unverified after {} checks over {}ms \
                     (deadline {}s) — NOT submitting credentials; retrying on the next tick",
                    mode_label,
                    attempt,
                    t_click.elapsed().as_millis(),
                    MODE_VERIFY_TIMEOUT_SECS
                );
                return Ok(HandlerResult::Error(format!(
                    "mode switch to '{mode_label}' could not be verified"
                )));
            }

            // Step 3: Fill username.
            //
            // The bool is the agent's `found`, so a missing field is now
            // visible instead of being reported as a successful type.
            if !client
                .type_text(window.id, USERNAME_FIELD, &self.username)
                .await
                .map_err(HandlerError::AgentError)?
            {
                log::error!(
                    "Username field (index {}) not found — not submitting",
                    USERNAME_FIELD
                );
                return Ok(HandlerResult::Error("username field not found".into()));
            }

            // Step 4: Fill password.
            //
            // Gating this matters more than gating the username. With the old
            // always-true return, a missing password field meant we went on to
            // click Log In with an empty password; on a retry loop that is a
            // stream of failed authentication attempts against IBKR, which is
            // exactly what gets an account locked out.
            if !client
                .type_text(window.id, PASSWORD_FIELD, self.password.expose_secret())
                .await
                .map_err(HandlerError::AgentError)?
            {
                log::error!(
                    "Password field (index {}) not found — not submitting",
                    PASSWORD_FIELD
                );
                return Ok(HandlerResult::Error("password field not found".into()));
            }

            // Step 4b: the button must be live now that the credentials are in.
            // The Gateway keeps "Log In" disabled while the password is empty
            // (its form after an expired IB Key push), and Swing's
            // doClick on a disabled button does nothing while the agent still
            // reports found:true — a submit that never happened. A dump that
            // omits "enabled" is not treated as disabled. Polled briefly in
            // case the Gateway enables it a beat after the text lands.
            let enable_deadline = tokio::time::Instant::now()
                + std::time::Duration::from_millis(LOG_IN_ENABLE_WAIT_MS);
            let still_disabled = loop {
                let disabled = client
                    .dump_components(win_id)
                    .await
                    .ok()
                    .and_then(|c| c.get("buttons").and_then(|b| b.as_array()).cloned())
                    .is_some_and(|buttons| {
                        buttons.iter().any(|b| {
                            b.get("text").and_then(|t| t.as_str()) == Some(expected_button)
                                && b.get("enabled").and_then(|e| e.as_bool()) == Some(false)
                        })
                    });
                if !disabled || tokio::time::Instant::now() >= enable_deadline {
                    break disabled;
                }
                tokio::time::sleep(std::time::Duration::from_millis(MODE_VERIFY_POLL_MS)).await;
            };
            if still_disabled {
                log::error!(
                    "'{}' is still disabled after the credentials were entered — not submitted",
                    expected_button
                );
                return Ok(HandlerResult::Error(format!(
                    "'{expected_button}' still disabled after entering credentials"
                )));
            }

            // Step 5: Submit, using this mode's own button and no other.
            //
            // This was a two-entry list — `["Paper Log In", "Log In"]` for
            // paper, mirrored for live — described as "try the expected label
            // first" with the other mode's label as a fallback. While
            // `click_button` returned the HTTP envelope, the first entry always
            // reported success, so the fallback was unreachable and therefore
            // harmless. Surfacing the agent's real `found` makes it reachable,
            // and for paper it would click the LIVE login button using paper
            // credentials — in precisely the situation where the mode switch
            // had already gone wrong. A cross-mode fallback is not a
            // resilience measure here, it is a way to log into the wrong
            // account.
            //
            // `expected_button` is the label whose presence was just verified,
            // which makes it both the correct thing to click and the only
            // thing worth clicking.
            match client.click_button(window.id, expected_button).await {
                Ok(true) => log::info!("Clicked '{}' button", expected_button),
                Ok(false) => {
                    // Verification succeeded moments ago, so this is a genuine
                    // surprise: the form changed under us mid-handler.
                    log::error!(
                        "Login button '{}' vanished after mode verification — not submitted",
                        expected_button
                    );
                    return Ok(HandlerResult::Error(format!(
                        "login button '{expected_button}' not found"
                    )));
                }
                Err(e) => {
                    log::error!("Clicking '{}' failed: {}", expected_button, e);
                    return Ok(HandlerResult::Error(format!(
                        "clicking '{expected_button}' failed: {e}"
                    )));
                }
            }

            self.login_submitted.store(true, Ordering::Relaxed);
            log::info!("Login credentials submitted (mode={})", self.trading_mode);
            Ok(HandlerResult::Handled)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_client::{AgentApi, AgentError, CheckboxOutcome, MockAgent};

    /// A login window with the given submit-button labels present.
    ///
    /// `dump_components` is what the mode verification reads, so this is the
    /// knob that decides whether the form "looks like" paper or live.
    fn mock_with_buttons(labels: &[&str]) -> MockAgent {
        MockAgent {
            dump_response: serde_json::json!({
                "buttons": labels
                    .iter()
                    .map(|l| serde_json::json!({"text": l}))
                    .collect::<Vec<_>>(),
                "textfields": [{"index": 0}, {"index": 1}],
            }),
            ..Default::default()
        }
    }

    fn login_window() -> WindowInfo {
        WindowInfo {
            id: WindowId(1),
            title: "IB Gateway Login".to_string(),
            class: "dialog".to_string(),
            bounds: None,
            visible: true,
        }
    }

    fn live_handler() -> LoginHandler {
        LoginHandler::new(
            "liveuser".to_string(),
            SecretString::from("livepass".to_string()),
            TradingMode::Live,
        )
    }

    /// A live login form whose "Log In" is `enabled` as given.
    fn live_form(log_in_enabled: bool) -> serde_json::Value {
        serde_json::json!({
            "buttons": [{"text": "IB API"}, {"text": "Live Trading"},
                        {"text": "Log In", "enabled": log_in_enabled}],
            "textfields": [{"index": 0}, {"index": 1}],
        })
    }

    /// Clicking a disabled JButton is a silent no-op in Swing, and the agent
    /// still answers found:true — a "submitted" login that never happened.
    /// "Log In" must be enabled once the credentials are in, or nothing is
    /// clicked and the handler says so.
    #[tokio::test(start_paused = true)]
    async fn login_is_not_submitted_while_log_in_stays_disabled() {
        let mock = MockAgent { dump_response: live_form(false), ..Default::default() };
        let clicked = mock.clicked.clone();
        let client = AgentClient::mock(mock);
        let handler = live_handler();

        let result = handler.handle(&client, &login_window()).await.unwrap();

        assert!(matches!(result, HandlerResult::Error(_)), "got {result:?}");
        assert!(!clicked.lock().unwrap().contains(&"Log In".to_string()));
        assert!(!handler.login_submitted.load(Ordering::Relaxed));
    }

    /// The Gateway's form after an expired IB Key push: "Log In" disabled
    /// with an empty password, enabled once one is typed. That is a form to
    /// submit into, not one to reject.
    #[tokio::test(start_paused = true)]
    async fn login_submits_once_entering_the_credentials_enables_log_in() {
        let mock = MockAgent {
            dump_response: live_form(false),
            dump_after_type: Some(live_form(true)),
            ..Default::default()
        };
        let clicked = mock.clicked.clone();
        let client = AgentClient::mock(mock);
        let handler = live_handler();

        let result = handler.handle(&client, &login_window()).await.unwrap();

        assert_eq!(result, HandlerResult::Handled);
        assert!(clicked.lock().unwrap().contains(&"Log In".to_string()));
    }

    /// The Gateway's own login is running ('Login', 'Authenticating...',
    /// 'Starting application...'). A second login from the same JVM is what
    /// can loop a gateway for hours.
    #[tokio::test(start_paused = true)]
    async fn login_is_not_submitted_while_the_gateway_is_logging_in_itself() {
        for busy in ["Login", "Authenticating...", "Starting application..."] {
            let mut mock = MockAgent { dump_response: live_form(true), ..Default::default() };
            mock.windows = vec![
                login_window(),
                WindowInfo { id: WindowId(2), title: busy.into(), class: "dialog".into(), bounds: None, visible: true },
            ];
            let clicked = mock.clicked.clone();
            let client = AgentClient::mock(mock);
            let handler = live_handler();

            let result = handler.handle(&client, &login_window()).await.unwrap();

            assert_eq!(result, HandlerResult::NotApplicable, "'{busy}' open");
            assert!(clicked.lock().unwrap().is_empty(), "nothing touched while '{busy}' is open");
            assert!(!handler.login_submitted.load(Ordering::Relaxed));
        }
    }

    fn paper_handler() -> LoginHandler {
        LoginHandler::new(
            "paperuser".to_string(),
            SecretString::from("paperpass".to_string()),
            TradingMode::Paper,
        )
    }

    /// THE regression test. Reproduces the observed production failure: the
    /// paper form is still showing Live mode, so "Paper Log In" does not exist.
    ///
    /// Before the fix, `click_button` answered `Ok(true)` for the absent
    /// button, the handler set `login_submitted`, reported `Handled`, and the
    /// gateway sat on a filled-in login form indefinitely with nothing logged.
    #[tokio::test(start_paused = true)]
    async fn paper_login_refuses_to_submit_when_the_form_is_in_live_mode() {
        let mock = mock_with_buttons(&["Log In"]);
        let client = AgentClient::mock(mock);
        let handler = paper_handler();
        let window = login_window();

        let result = handler.handle(&client, &window).await.unwrap();

        assert!(
            matches!(result, HandlerResult::Error(_)),
            "expected fail-closed Error, got {result:?}"
        );
        assert!(
            !handler.login_submitted.load(Ordering::Relaxed),
            "login must NOT be marked submitted — that flag is what stops the \
             state machine from retrying"
        );
    }

    /// The hazard that the CORE fix would otherwise have activated.
    ///
    /// The old submit list was `["Paper Log In", "Log In"]`. It was dead code
    /// only because the first entry always claimed success. Make a miss
    /// reportable and that fallback comes alive — clicking the LIVE login
    /// button with paper credentials, in exactly the situation where the mode
    /// switch had already failed. Nothing may click "Log In" in paper mode.
    #[tokio::test(start_paused = true)]
    async fn paper_login_never_clicks_the_live_button() {
        let mock = mock_with_buttons(&["Log In"]);
        let clicked = mock.clicked.clone();
        let client = AgentClient::mock(mock);
        let handler = paper_handler();

        let _ = handler.handle(&client, &login_window()).await.unwrap();

        let clicked = clicked.lock().unwrap();
        assert!(
            !clicked.iter().any(|l| l == "Log In"),
            "paper mode clicked the LIVE login button: {clicked:?}"
        );
    }

    /// The happy path still works: form is in paper mode, so verification
    /// passes and the paper button is the one clicked.
    #[tokio::test(start_paused = true)]
    async fn paper_login_submits_when_the_form_is_in_paper_mode() {
        let mock = mock_with_buttons(&["Paper Log In"]);
        let clicked = mock.clicked.clone();
        let client = AgentClient::mock(mock);
        let handler = paper_handler();

        let result = handler.handle(&client, &login_window()).await.unwrap();

        assert!(
            matches!(result, HandlerResult::Handled),
            "expected Handled, got {result:?}"
        );
        assert!(handler.login_submitted.load(Ordering::Relaxed));
        let clicked = clicked.lock().unwrap();
        assert!(
            clicked.iter().any(|l| l == "Paper Log In"),
            "paper login button was never clicked: {clicked:?}"
        );
    }

    /// Live mode is the mirror image and must not reach for the paper button.
    #[tokio::test(start_paused = true)]
    async fn live_login_never_clicks_the_paper_button() {
        let mock = mock_with_buttons(&["Paper Log In"]);
        let clicked = mock.clicked.clone();
        let client = AgentClient::mock(mock);
        let handler = LoginHandler::new(
            "liveuser".to_string(),
            SecretString::from("livepass".to_string()),
            TradingMode::Live,
        );

        let result = handler.handle(&client, &login_window()).await.unwrap();

        assert!(matches!(result, HandlerResult::Error(_)), "got {result:?}");
        let clicked = clicked.lock().unwrap();
        assert!(
            !clicked.iter().any(|l| l == "Paper Log In"),
            "live mode clicked the PAPER login button: {clicked:?}"
        );
    }

    /// A missing credential field must abort before submitting.
    ///
    /// Previously `type_text` always answered `Ok(true)`, so a missing password
    /// field meant clicking Log In with an empty password. Repeated on the
    /// retry loop, that is a stream of failed authentications against IBKR —
    /// which is how an account gets locked.
    #[tokio::test(start_paused = true)]
    async fn a_missing_credential_field_aborts_before_submitting() {
        let mut mock = mock_with_buttons(&["Paper Log In"]);
        mock.type_text_found = false;
        let clicked = mock.clicked.clone();
        let client = AgentClient::mock(mock);
        let handler = paper_handler();

        let result = handler.handle(&client, &login_window()).await.unwrap();

        assert!(
            matches!(result, HandlerResult::Error(_)),
            "expected Error, got {result:?}"
        );
        let clicked = clicked.lock().unwrap();
        assert!(
            !clicked.iter().any(|l| l.contains("Log In")),
            "submitted despite a missing credential field: {clicked:?}"
        );
        assert!(!handler.login_submitted.load(Ordering::Relaxed));
    }
    fn paper_form(button: &str) -> LoginFormState {
        LoginFormState {
            text_field_count: 1,
            password_field_count: 1,
            login_button: Some(button.to_string()),
            selected_mode: Some("Paper Trading".to_string()),
        }
    }

    /// The event alone is sufficient. `dump_components` reports no buttons at
    /// all here, so if verification succeeds it succeeded on the event.
    #[tokio::test(start_paused = true)]
    async fn mode_is_verified_from_the_form_event_alone() {
        let client = AgentClient::mock(mock_with_buttons(&[]));
        let (tx, rx) = tokio::sync::watch::channel(Some(paper_form("Paper Log In")));
        let handler = paper_handler().with_form_events(rx);

        let result = handler.handle(&client, &login_window()).await.unwrap();

        assert!(
            matches!(result, HandlerResult::Handled),
            "the form event named the expected button; expected Handled, got {result:?}"
        );
        drop(tx);
    }

    /// THE timing regression, as a test.
    ///
    /// The form event arrives six seconds late — a slow JVM composing the login
    /// panel. The old implementation gave up after 5 attempts x 200ms = one
    /// second and fell through to "proceed anyway", which is how paper
    /// credentials ended up in a form still showing Live mode. The wait is now
    /// bounded by a deadline and woken by the event, so a late form is still
    /// verified rather than lost.
    ///
    /// `join!` rather than `spawn` so the sender stays owned by this scope —
    /// dropping it would close the channel and race the assertion.
    #[tokio::test(start_paused = true)]
    async fn a_form_event_six_seconds_late_still_verifies() {
        let client = AgentClient::mock(mock_with_buttons(&[]));
        let (tx, rx) = tokio::sync::watch::channel(None);
        let handler = paper_handler().with_form_events(rx);

        let window = login_window();
        let (result, ()) = tokio::join!(handler.handle(&client, &window), async {
            tokio::time::sleep(std::time::Duration::from_secs(6)).await;
            let _ = tx.send(Some(paper_form("Paper Log In")));
        });

        assert!(
            matches!(result.unwrap(), HandlerResult::Handled),
            "a 6s-late form event must still verify — the old budget was 1s"
        );
    }

    /// A form event that never names the expected button must still fail closed,
    /// not hang and not proceed. This is the version of the wrong-mode failure
    /// where the mode switch genuinely never takes effect.
    #[tokio::test(start_paused = true)]
    async fn a_form_event_stuck_in_the_wrong_mode_fails_closed() {
        let client = AgentClient::mock(mock_with_buttons(&["Log In"]));
        let (tx, rx) = tokio::sync::watch::channel(Some(paper_form("Log In")));
        let handler = paper_handler().with_form_events(rx);

        let result = handler.handle(&client, &login_window()).await.unwrap();

        assert!(
            matches!(result, HandlerResult::Error(_)),
            "stuck in live mode must fail closed, got {result:?}"
        );
        assert!(!handler.login_submitted.load(Ordering::Relaxed));
        drop(tx);
    }

    /// A dropped sender must not turn the wait into a busy loop; it degrades to
    /// polling. Here polling can see the button, so it still verifies.
    #[tokio::test(start_paused = true)]
    async fn a_closed_form_channel_degrades_to_polling() {
        let client = AgentClient::mock(mock_with_buttons(&["Paper Log In"]));
        let (tx, rx) = tokio::sync::watch::channel(None);
        drop(tx); // sender gone before the handler even runs
        let handler = paper_handler().with_form_events(rx);

        let result = handler.handle(&client, &login_window()).await.unwrap();

        assert!(
            matches!(result, HandlerResult::Handled),
            "must fall back to dump_components, got {result:?}"
        );
    }
    /// The production scenario, end to end, against a panel that behaves like
    /// the real one.
    ///
    /// The panel does not exist for the first few dumps, so the mode click
    /// misses. Gateway then finishes building it, in Live mode — submit reads
    /// "Log In". The wait notices the toggle has appeared, clicks it, the
    /// submit button relabels to "Paper Log In", verification passes, and the
    /// paper button is the one submitted.
    ///
    /// Under the old design this attempt was unrecoverable: the click missed,
    /// nothing retried it, verification looked for a label that could not
    /// appear, and after one second the handler submitted anyway — into a form
    /// still in Live mode.
    #[tokio::test(start_paused = true)]
    async fn a_toggle_that_appears_late_is_clicked_when_it_arrives() {
        let sim = LoginPanelSim::new(3); // panel shows up on the 4th dump
        let clicked = sim.clicked.clone();
        let client = AgentClient::mock_api(sim);
        let handler = paper_handler();

        let result = handler.handle(&client, &login_window()).await.unwrap();

        assert!(
            matches!(result, HandlerResult::Handled),
            "a late panel must still produce a login, got {result:?}"
        );
        let clicked = clicked.lock().unwrap();
        assert!(
            clicked.iter().filter(|l| *l == "Paper Trading").count() >= 2,
            "the mode toggle should have been clicked once on the missing panel \
             and again once it appeared: {clicked:?}"
        );
        assert!(
            clicked.iter().any(|l| l == "Paper Log In"),
            "the paper submit button was never clicked: {clicked:?}"
        );
        assert!(
            !clicked.iter().any(|l| l == "Log In"),
            "never the live button: {clicked:?}"
        );
        assert!(
            clicked.iter().filter(|l| *l == "IB API").count() >= 2,
            "the API-type radio missed the same absent panel and must also be \
             selected once it appears: {clicked:?}"
        );
    }

    /// The same simulator with a panel that is ready immediately — the fast
    /// path must not be slowed down or confused by the retry logic.
    #[tokio::test(start_paused = true)]
    async fn a_panel_that_is_ready_immediately_logs_straight_in() {
        let sim = LoginPanelSim::new(0);
        let clicked = sim.clicked.clone();
        let client = AgentClient::mock_api(sim);
        let handler = paper_handler();

        let result = handler.handle(&client, &login_window()).await.unwrap();

        assert!(matches!(result, HandlerResult::Handled), "got {result:?}");
        let clicked = clicked.lock().unwrap();
        assert_eq!(
            clicked.iter().filter(|l| *l == "Paper Trading").count(),
            1,
            "no retry should be needed on a ready panel: {clicked:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // A faithful stand-in for the Gateway login panel.
    //
    // MockAgent answers every verb from a fixed field, so a click there succeeds
    // whether or not the button is in the dump. That is fine for most tests and
    // useless for this one: the whole failure being fixed is a panel whose
    // contents change while the handler is working on it. This fake keeps clicks
    // and dumps consistent with one another and models the single Gateway
    // behaviour the login flow turns on — toggling the trading mode relabels the
    // submit button.
    // ---------------------------------------------------------------------------
    struct LoginPanelSim {
        /// Dumps served before the panel exists. Models Gateway still building it.
        dumps_before_panel: usize,
        dumps_served: std::sync::atomic::AtomicUsize,
        /// false = Live (submit reads "Log In"), true = Paper ("Paper Log In").
        paper_selected: std::sync::atomic::AtomicBool,
        clicked: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl LoginPanelSim {
        fn new(dumps_before_panel: usize) -> Self {
            Self {
                dumps_before_panel,
                dumps_served: std::sync::atomic::AtomicUsize::new(0),
                paper_selected: std::sync::atomic::AtomicBool::new(false),
                clicked: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        /// Whether the panel has been built yet. Does NOT consume a dump.
        fn panel_present(&self) -> bool {
            self.dumps_served.load(Ordering::Relaxed) >= self.dumps_before_panel
        }

        fn buttons(&self) -> Vec<String> {
            if !self.panel_present() {
                return Vec::new();
            }
            let submit = if self.paper_selected.load(Ordering::Relaxed) {
                "Paper Log In"
            } else {
                "Log In"
            };
            ["IB API", "Live Trading", "Paper Trading", submit]
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        }
    }

    impl AgentApi for LoginPanelSim {
        async fn health(&self) -> Result<bool, AgentError> {
            Ok(true)
        }
        async fn list_windows(
            &self,
        ) -> Result<Vec<WindowInfo>, AgentError> {
            Ok(Vec::new())
        }
        async fn click_button(
            &self,
            _: WindowId,
            label: &str,
        ) -> Result<bool, AgentError> {
            self.clicked.lock().unwrap().push(label.to_string());
            // A click can only land on a button that is actually on screen — the
            // property MockAgent cannot express and this whole test depends on.
            if !self.buttons().iter().any(|b| b == label) {
                return Ok(false);
            }
            if label == "Paper Trading" {
                self.paper_selected.store(true, Ordering::Relaxed);
            } else if label == "Live Trading" {
                self.paper_selected.store(false, Ordering::Relaxed);
            }
            Ok(true)
        }
        async fn type_text(
            &self,
            _: WindowId,
            _: usize,
            _: &str,
        ) -> Result<bool, AgentError> {
            Ok(self.panel_present())
        }
        async fn dump_components(
            &self,
            _: WindowId,
        ) -> Result<serde_json::Value, AgentError> {
            self.dumps_served
                .fetch_add(1, Ordering::Relaxed);
            Ok(serde_json::json!({
                "buttons": self
                    .buttons()
                    .iter()
                    .map(|b| serde_json::json!({"text": b}))
                    .collect::<Vec<_>>(),
                "textfields": if self.panel_present() {
                    serde_json::json!([{"index": 0}, {"index": 1}])
                } else {
                    serde_json::json!([])
                },
            }))
        }
        async fn click_menu(
            &self,
            _: WindowId,
            _: &str,
        ) -> Result<bool, AgentError> {
            Ok(false)
        }
        async fn set_checkbox(
            &self,
            _: WindowId,
            _: &str,
            _: Option<bool>,
        ) -> Result<CheckboxOutcome, AgentError> {
            Ok(CheckboxOutcome::default())
        }
        async fn select_list_item(
            &self,
            _: WindowId,
            _: &str,
        ) -> Result<bool, AgentError> {
            Ok(false)
        }
        async fn click_at(
            &self,
            _: WindowId,
            _: i32,
            _: i32,
        ) -> Result<bool, AgentError> {
            Ok(false)
        }
        async fn select_tree_node(
            &self,
            _: WindowId,
            _: &str,
        ) -> Result<bool, AgentError> {
            Ok(false)
        }
        async fn list_clients(
            &self,
            _: WindowId,
        ) -> Result<serde_json::Value, AgentError> {
            Ok(serde_json::json!({}))
        }
        async fn send_key(
            &self,
            _: WindowId,
            _: &str,
        ) -> Result<bool, AgentError> {
            Ok(false)
        }
    }
    /// Regression guard: do_connected's popup-
    /// reconciliation sweep dispatches every handler against every window,
    /// every tick, forever, purely to auto-dismiss popups. LoginHandler's
    /// title-only `can_handle()` matches the MAIN, already-connected window
    /// just as readily as an actual login form, so it kept getting
    /// dispatched there — and, now that a miss is honestly reported instead
    /// of silently claimed as success, kept failing loudly, forever, on a
    /// perfectly healthy Connected session.
    #[test]
    fn mark_login_complete_stops_matching_the_main_window() {
        let handler = paper_handler();
        let main_window = WindowInfo {
            id: WindowId(1),
            title: "IBKR Gateway [PAPER]".to_string(),
            class: "ibgateway.aw".to_string(),
            bounds: None,
            visible: true,
        };

        assert!(
            handler.can_handle(&main_window),
            "sanity: the title-only predicate does match the main window              (that's the bug) before mark_login_complete is ever called"
        );

        handler.mark_login_complete();

        assert!(
            !handler.can_handle(&main_window),
            "after mark_login_complete, the main window must never be              offered to LoginHandler again"
        );
    }

    /// `reset()` re-arms the handler for a genuinely fresh login cycle (a
    /// real restart), and must undo mark_login_complete's effect — otherwise
    /// a warm restart that never calls handle() at all would leave the flag
    /// permanently stuck.
    #[test]
    fn reset_after_mark_login_complete_re_arms_the_handler() {
        let handler = paper_handler();
        let main_window = WindowInfo {
            id: WindowId(1),
            title: "IBKR Gateway [PAPER]".to_string(),
            class: "ibgateway.aw".to_string(),
            bounds: None,
            visible: true,
        };

        handler.mark_login_complete();
        handler.reset();

        assert!(
            handler.can_handle(&main_window),
            "reset() must re-arm the handler for the next login cycle"
        );
    }
}
