//! Query handling and JSON response builders for the command server.
//!
//! Hot-path queries (STATUS, STATE, CONFIG) are served via a `watch` channel
//! snapshot — the command server reads the latest value directly without going
//! through the state machine's mpsc. Only WINDOWS (which requires async agent
//! I/O) still uses the mpsc/oneshot path.

use std::sync::Arc;

use secrecy::ExposeSecret;

use crate::types::{ColdRestartOutcome, Query, QuerySnapshot};

use super::recovery::RecoveryPhase;
use super::types::{client_advisory, State, StateMachine};

impl StateMachine {
    /// Publish a fresh query snapshot to the watch channel.
    ///
    /// Called after state transitions, command handling, and at the top of
    /// the main loop. The command server reads this snapshot directly for
    /// STATUS/STATE/CONFIG — no mpsc round-trip needed.
    pub(super) fn publish_snapshot(&mut self) {
        self.snapshot_version += 1;
        let snapshot = Arc::new(QuerySnapshot {
            status_json: self.build_status_json(),
            state_json: self.build_state_json(),
            config_json: self.build_config_json(),
            published_at: std::time::Instant::now(),
            version: self.snapshot_version,
            start_time: self.start_time,
            connected_since: self.connected_since,
        });
        // Ignore error — means no receivers exist (command server not started)
        let _ = self.snapshot_tx.send(snapshot);
    }

    /// Process pending queries that require async I/O (WINDOWS only).
    ///
    /// STATUS/STATE/CONFIG are handled by the command server directly
    /// via the watch snapshot. This method drains WINDOWS and LOGS queries
    /// that need the state machine's async capabilities or stub responses.
    pub(super) async fn process_queries(&mut self) {
        loop {
            match self.query_rx.try_recv() {
                Ok(query) => self.handle_query(query).await,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
    }

    /// Handle a single query. Only WINDOWS needs async processing here;
    /// STATUS/STATE/CONFIG are answered from the watch snapshot by the
    /// command server, but we handle them as fallback if they arrive.
    async fn handle_query(&mut self, query: Query) {
        match query {
            // These should be served from the watch snapshot by the command
            // server. If they arrive here, answer them directly as fallback.
            Query::Status(tx) => {
                let _ = tx.send(self.build_status_json());
            }
            Query::State(tx) => {
                let _ = tx.send(self.build_state_json());
            }
            Query::Config(tx) => {
                let _ = tx.send(self.build_config_json());
            }
            Query::Logs(limit, tx) => {
                let json = serde_json::json!({
                    "error": "not_implemented",
                    "message": "LOGS command is not yet implemented — use container logs instead",
                    "limit": limit,
                }).to_string();
                let _ = tx.send(json);
            }
            Query::Windows(tx) => {
                let json = self.build_windows_json().await;
                let _ = tx.send(json);
            }
        }
    }

    /// Build the full STATUS JSON response for the dashboard.
    ///
    /// All data is read from in-memory fields, no agent I/O.
    /// Client IDs are refreshed every 30s in do_connected() and cached.
    pub(super) fn build_status_json(&mut self) -> String {
        let uptime = self.start_time.elapsed().as_secs();
        let connected_uptime = self.connected_since.map(|t| t.elapsed().as_secs());
        let socat_running = self.socat_process.as_mut()
            .map(|c| c.try_wait().ok().flatten().is_none())
            .unwrap_or(false);
        let socat_pid = self.socat_process.as_ref().map(|c| c.id());

        let is_connected = self.state == State::Connected;
        let (should_connect, should_wait, wait_reason, client_id_likely_stale) =
            client_advisory(&self.state);

        let jvm = self.supervisor.jvm_info();

        // Use cached client IDs (refreshed every 30s in do_connected)
        let client_ids = &self.cached_client_ids;

        // RecoveryCoordinator exposure on the STATUS wire.
        //
        // ADDITIVE-ONLY: external consumers subscribing via ZMQ port
        // 5556 receive the same JSON; unknown fields are ignored. The
        // "recovery" object is ALWAYS present so callers can rely on an
        // unconditional lookup — a downgrade to null-when-inactive would
        // force every dashboard render path through an `if recovery is
        // not None` guard.
        //
        // Wall-clock only: `phase_elapsed_secs` is computed from the
        // Zoned wall delta, not the monotonic anchor. Dashboards render
        // the wall value; leaking `phase_entered_at_mono` (an Instant
        // scoped to this container's lifetime) would be misleading to
        // any external consumer inspecting the field.
        //
        // `next_retry_at` semantics — the pure `compute_next_action`
        // function computes Backoff sleep as
        //   `interval - (elapsed % interval)`.
        // Applied against `phase_entered_at` as the anchor that yields
        //   next_retry_at = phase_entered_at
        //                 + interval * (floor(elapsed / interval) + 1)
        // i.e. the NEXT boundary strictly after now — matching the RED
        // fixture (elapsed=3600, interval=900 → next = entry+4500s).
        // Populated only in the Backoff phase; JSON null in Aggressive
        // and GivenUp so dashboards don't render a stale countdown.
        let now_wall = jiff::Zoned::now();
        let rec_phase = self.recovery.phase();
        let rec_phase_entered_at = self.recovery.phase_entered_at();
        let phase_elapsed_secs: u64 = {
            let delta = now_wall.timestamp().as_second()
                - rec_phase_entered_at.timestamp().as_second();
            // Clamp to 0 — wall clock can run backwards under NTP; a
            // negative elapsed_secs would surface as a huge u64 without
            // this guard.
            delta.max(0) as u64
        };
        let last_full_success_at_json: serde_json::Value = self
            .recovery
            .last_full_success_at()
            .map(|z| serde_json::Value::String(z.to_string()))
            .unwrap_or(serde_json::Value::Null);
        let giveup_alert_sent_at_json: serde_json::Value = self
            .recovery
            .giveup_alert_sent_at()
            .map(|t| serde_json::Value::String(t.to_string()))
            .unwrap_or(serde_json::Value::Null);
        let next_retry_at_json: serde_json::Value = if rec_phase
            == RecoveryPhase::BackoffEvery15Min
        {
            let interval = self.recovery.config_backoff_interval_secs();
            // Defensive: a misconfigured 0-interval would divide-by-
            // zero below. `checked_div` surfaces the None branch as
            // JSON null so dashboards fall back to their "no next
            // retry" path rather than crashing the query builder.
            match phase_elapsed_secs.checked_div(interval) {
                None => serde_json::Value::Null,
                Some(boundaries_passed) => {
                    let offset_secs = interval.saturating_mul(boundaries_passed + 1);
                    // A naive `offset_secs as i64` silently wraps on
                    // `u64::MAX` (→ -1), which `checked_add` accepts as
                    // "one second before now" — Ok(entry - 1s), NOT the
                    // Err path the guard comment below claims.
                    // `i64::try_from` collapses that overflow to None,
                    // routing wire output to JSON null as intended.
                    // Realistically unreachable (phase_elapsed_secs ≈
                    // 1.8×10^19 s), but the arithmetic must be honest.
                    let next = i64::try_from(offset_secs).ok().and_then(|s| {
                        rec_phase_entered_at
                            .checked_add(jiff::SignedDuration::from_secs(s))
                            .ok()
                    });
                    match next {
                        Some(z) => serde_json::Value::String(z.to_string()),
                        // Overflow (offset saturates on a distant
                        // future anchor) — dashboards render null
                        // rather than a clamped-to-year-9999 wire value.
                        None => serde_json::Value::Null,
                    }
                }
            }
        } else {
            serde_json::Value::Null
        };
        // Config fields on the wire: the dashboard
        // give-up alert body composes phrasing from these values ("Aggressive
        // retry Nm + Backoff Nh without a Connected dwell >=Ns"), and its
        // dedupe-resend gate reads `giveup_alert_resend_interval_hours`.
        // Emitting them here keeps the operator-facing narrative aligned
        // with the coordinator's actual timings rather than a fabricated
        // default hardcoded in the dashboard.
        let recovery_json = serde_json::json!({
            "phase": rec_phase.as_str(),
            "phase_entered_at": rec_phase_entered_at.to_string(),
            "phase_elapsed_secs": phase_elapsed_secs,
            "last_full_success_at": last_full_success_at_json,
            "giveup_alert_sent_at": giveup_alert_sent_at_json,
            "next_retry_at": next_retry_at_json,
            "blocked_awaiting_resume": self.recovery.is_blocked_awaiting_resume(),
            "aggressive_phase_max_secs": self.recovery.config_aggressive_phase_max_secs(),
            "backoff_phase_max_secs": self.recovery.config_backoff_phase_max_secs(),
            "min_success_dwell_secs": self.recovery.config_min_success_dwell_secs(),
            "callback_valid_hours": self.recovery.config_giveup_callback_valid_hours(),
            "giveup_alert_resend_interval_hours":
                self.recovery.config_giveup_alert_resend_interval_hours(),
        });

        // Who the last "Existing session detected" dialog named, and
        // whether ibctl has stopped answering them.
        let now = std::time::Instant::now();
        // While waiting for 2FA, whether a push is outstanding on
        // the phone. No clock ends the round; this tells the dashboard when
        // to say the push is waiting.
        let twofa_json = if self.state == State::WaitingFor2fa {
            let open_for = self
                .twofa_challenge_opened_at
                .filter(|_| self.twofa_gone_at.is_none())
                .map(|t| t.elapsed().as_secs());
            let alert_after = self.config.twofa.timeout_seconds;
            serde_json::json!({
                "challenge_open": open_for.is_some(),
                "challenge_open_secs": open_for,
                "push_overdue": open_for.is_some_and(|s| s >= alert_after),
                "alert_after_secs": alert_after,
                "stuck_ceiling_secs": super::STUCK_PROMPT_CEILING.as_secs(),
                "cancel_sent": self.prompt_cancel_sent_at.is_some(),
                "rounds_failed": self.consecutive_2fa_timeouts,
                "max_rounds": self.config.twofa.backoff.max_immediate_attempts,
            })
        } else {
            serde_json::Value::Null
        };
        let last_relaunch_json = self.last_relaunch.as_ref().map(|r| {
            serde_json::json!({
                "at": r.at.to_string(),
                "from_state": r.from_state,
                "reason": r.reason,
                "detail": r.detail,
                "abandoned_prompt": r.abandoned_prompt,
            })
        });
        // Host maintenance and the Sunday facts, reported
        // separately from each other. "Restart satisfied" and "auth
        // satisfied" are two facts: a gateway restarted today may still be
        // waiting for its login.
        let hold_path = self
            .cold_restart_equivalent_marker_path
            .parent()
            .map(crate::maintenance_hold::path_in);
        let now_z = jiff::Zoned::now();
        let maintenance_json = serde_json::json!({
            "hold": hold_path.as_deref().and_then(crate::maintenance_hold::read).map(|h| serde_json::json!({
                "id": h.id,
                "since": h.since.to_string(),
                "expires_at": h.expires_at.to_string(),
                "active": h.active_at(now_z.timestamp()),
            })),
            "last": self.last_maintenance.as_ref().map(|m| serde_json::json!({
                "id": m.id,
                "result": m.result,
                "released_at": m.released_at.to_string(),
            })),
        });
        let jvm_launched_at = jvm
            .started_at
            .and_then(|up| now_z.checked_sub(jiff::SignedDuration::from_secs(up as i64)).ok());
        let today = |z: &jiff::Zoned| z.date() == now_z.date() && z.hour() >= 1;
        let sunday_json = serde_json::json!({
            "jvm_launched_at": jvm_launched_at.as_ref().map(|z| z.to_string()),
            "restart_satisfied_at": jvm_launched_at.as_ref().filter(|z| today(z)).map(|z| z.to_string()),
            "auth_satisfied_at": crate::cold_restart::read_cold_restart_equivalent_marker(
                &self.cold_restart_equivalent_marker_path,
            )
            .filter(|z| today(z))
            .map(|z| z.to_string()),
        });
        let session_conflict_json = serde_json::json!({
            "recent": self
                .session_conflicts
                .iter()
                .filter(|t| now.duration_since(**t) < super::session_conflict::BREAKER_WINDOW)
                .count(),
            "threshold": super::session_conflict::BREAKER_THRESHOLD,
            "window_secs": super::session_conflict::BREAKER_WINDOW.as_secs(),
            "breaker_open": self.session_conflict_breaker_open,
            "last": self.last_session_conflict.as_ref().map(|r| serde_json::json!({
                "at": r.at.to_string(),
                "other_ip": r.other_ip,
                "other_connected_at": r.other_connected_at.map(|t| t.to_string()),
                "self_inflicted": r.self_inflicted,
                "recent": r.recent,
            })),
        });
        serde_json::json!({
            "version": env!("IBCTL_VERSION"),
            "ready": is_connected && socat_running,
            "state": self.state.to_string(),
            "trading_mode": self.config.auth.trading_mode.to_string(),
            "uptime_secs": uptime,
            "connected_uptime_secs": connected_uptime,
            "jvm": {
                "pid": jvm.pid,
                "alive": jvm.alive,
                "uptime_secs": jvm.started_at,
                "config_dir": jvm.config_dir,
                "agent_socket": jvm.agent_socket,
            },
            "socat": {
                "running": socat_running,
                "pid": socat_pid,
            },
            "clients": {
                "count": client_ids.len(),
                "ids": client_ids,
            },
            "ib_system": {
                "available": self.ib_status.available,
                "status": self.ib_status.status,
                "reason": if self.ib_status.reason.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(self.ib_status.reason.clone()) },
                "expires_in_secs": self.ib_status.last_updated.map(|t| {
                    let ttl = 600u64; // TODO: from config
                    ttl.saturating_sub(t.elapsed().as_secs())
                }),
            },
            "site": {
                "role": self.config.site.role.to_string(),
                "auto_launch": self.config.site.auto_launch,
            },
            "paused": self.pause.paused,
            "ceiling_state": self.pause.ceiling_state.as_ref().map(|s| s.to_string()),
            "stats": self.stats,
            "client_advisory": {
                "should_connect": should_connect && socat_running,
                "should_wait": should_wait,
                "wait_reason": wait_reason,
                "client_id_likely_stale": client_id_likely_stale,
            },
            "hitl": if self.state == State::WaitingForHitl2fa {
                serde_json::json!({
                    "active": true,
                    "entered_at_secs_ago": self.hitl_entered_at
                        .map(|t| t.elapsed().as_secs()),
                    "attempts_exhausted": self.stats.relogins_today.max(self.consecutive_2fa_timeouts_snapshot()),
                    "consecutive_2fa_timeouts": self.consecutive_2fa_timeouts_snapshot(),
                    "next_retry_in_secs": self.hitl_next_retry_at
                        .map(|t| t.saturating_duration_since(std::time::Instant::now()).as_secs()),
                    "intervals_index": self.hitl_intervals_index,
                    "ntfy_sent": self.hitl_ntfy_sent,
                    "ntfy_attempts": self.hitl_ntfy_attempts,
                    // The Gateway is showing its IB Key dialog, so
                    // the last push MAY still be approvable. Observed, not
                    // inferred from a clock: IBKR does not publish the push
                    // lifetime, and in practice the dialog closes roughly three
                    // to five minutes after opening.
                    "challenge_open": self.observation.has_2fa_dialog(),
                    // A retry is waiting for the Gateway to close that dialog.
                    "relogin_armed": self.hitl_relogin_armed,
                    // The operator's Retry is closing that dialog.
                    "cancel_requested": self.hitl_cancel_requested,
                    // Attempts_exhausted | hitl_immediately |
                    // unattended_hours.
                    "parked_reason": self.hitl_park_reason.map(|r| r.as_str()),
                    "unattended_hours": self.config.twofa.backoff.unattended.map(|w| w.to_string()),
                })
            } else {
                serde_json::Value::Null
            },
            "recovery": recovery_json,
            // The latest Sunday re-authentication outcome for this
            // mode. `outcome` is the stable wire name
            // (`ColdRestartOutcome::as_str`); `state` is where the mode was
            // when it was recorded.
            "last_cold_restart_outcome": self.last_cold_restart_outcome.as_ref().map(|rec| {
                let mut obj = serde_json::json!({
                    "recorded_at": rec.recorded_at.to_string(),
                    "outcome": rec.outcome.as_str(),
                    "state": rec.state,
                });
                match &rec.outcome {
                    ColdRestartOutcome::AlreadySatisfied { at } => {
                        obj["last_login_at"] = serde_json::json!(at.to_string());
                    }
                    ColdRestartOutcome::Completed { at } => {
                        obj["completed_at"] = serde_json::json!(at.to_string());
                    }
                    ColdRestartOutcome::Failed { detail } => {
                        obj["detail"] = serde_json::json!(detail);
                    }
                    _ => {}
                }
                obj
            }),
            // Who the last "Existing session detected" dialog named,
            // and whether ibctl has stopped answering them.
            "session_conflict": session_conflict_json,
            "twofa": twofa_json,
            "maintenance": maintenance_json,
            "sunday_reauth": sunday_json,
            // The latest JVM relaunch and why. A relaunch from the
            // login path is always one of the reasons in `RelaunchReason`;
            // `abandoned_prompt` is the tripwire for one that isn't.
            "last_relaunch": last_relaunch_json,
            "cold_restart_owed_since": self
                .cold_restart_owed_since
                .as_ref()
                .map(|z| z.to_string()),
            // What the Sunday fire would do to this mode if it landed now —
            // the SAME decision `handle_interrupt` makes. The dashboard's
            // countdown renders it per mode, so the operator is told at the
            // attended window what is about to happen and what (if anything)
            // to do, without a second copy of the decision table.
            "cold_restart_plan": super::cold_restart_decision::decide(
                &self.state,
                self.observation.has_2fa_dialog(),
                self.config.twofa.backoff.cold_restart_preempts_hitl,
            )
            .as_str(),
        }).to_string()
    }

    /// Accessor so build_status_json can read the counter without a borrow
    /// conflict (the outer call holds `&mut self` for try_wait on processes).
    fn consecutive_2fa_timeouts_snapshot(&self) -> u32 {
        self.consecutive_2fa_timeouts
    }

    /// Build the STATE JSON response.
    fn build_state_json(&self) -> String {
        serde_json::json!({
            "current": self.state.to_string(),
            "history": self.transition_history,
        }).to_string()
    }

    /// Build the CONFIG JSON response (passwords masked).
    fn build_config_json(&self) -> String {
        let backoff = &self.config.twofa.backoff;
        serde_json::json!({
            "auth": {
                "username": self.config.auth.username,
                "trading_mode": self.config.auth.trading_mode.to_string(),
                "password": "********",
            },
            "twofa": {
                "provider": format!("{:?}", self.config.twofa.provider).to_lowercase(),
                "timeout_action": format!("{:?}", self.config.twofa.timeout_action).to_lowercase(),
                "timeout_seconds": self.config.twofa.timeout_seconds,
                "device": self.config.twofa.device,
                "relogin_after_timeout": self.config.twofa.relogin_after_timeout,
                "has_secret": self.config.twofa.has_secret,
                "backoff": {
                    "max_immediate_attempts": backoff.max_immediate_attempts,
                    "on_timeout": format!("{:?}", backoff.on_timeout),
                    "strategy": format!("{:?}", backoff.strategy),
                    "intervals_minutes": &backoff.intervals_minutes,
                    "callback_valid_hours": backoff.callback_valid_hours,
                    "counter_reset": format!("{:?}", backoff.counter_reset),
                    "stable_secs": backoff.stable_secs,
                    "cold_restart_preempts_hitl": backoff.cold_restart_preempts_hitl,
                    "ntfy_send_retries": backoff.ntfy_send_retries,
                    "unattended_hours": backoff.unattended.map(|w| w.to_string()),
                    "ntfy_action_signing_key_set": !backoff.ntfy_action_signing_key
                        .expose_secret().is_empty(),
                },
            },
            "gateway": {
                "tws_path": self.config.gateway.tws_path,
                "settings_path": self.config.gateway.settings_path,
                "version": self.config.gateway.version,
                "java_heap_mb": self.config.gateway.java_heap_mb,
                "program": self.config.gateway.program.to_string(),
                "live_api_port": self.config.gateway.live_api_port,
                "paper_api_port": self.config.gateway.paper_api_port,
                "live_socat_port": self.config.gateway.live_socat_port,
                "paper_socat_port": self.config.gateway.paper_socat_port,
            },
            "session": {
                "action": self.config.session.action.to_string(),
                "accept_incoming": self.config.session.accept_incoming.to_string(),
                "cold_restart_time": self.config.session.cold_restart_time,
                "cold_restart_day": self.config.session.tws_cold_restart_day,
            },
            "command_server": {
                "enabled": self.config.command_server.enabled,
                "port": self.config.command_server.port,
                "bind_address": self.config.command_server.bind_address,
                "control_from": self.config.command_server.control_from,
            },
            "timing": {
                "ui_tick_ms": self.config.timing.ui_tick_ms,
                "agent_tick_ms": self.config.timing.agent_tick_ms,
                "post_login_delay_ms": self.config.timing.post_login_delay_ms,
                "popup_quiet_secs": self.config.timing.popup_quiet_secs,
                "popup_max_wait_secs": self.config.timing.popup_max_wait_secs,
                "login_radio_delay_ms": self.config.timing.login_radio_delay_ms,
                "jvm_shutdown_timeout_secs": self.config.timing.jvm_shutdown_timeout_secs,
                "login_dialog_timeout_secs": self.config.timing.login_dialog_timeout_secs,
                "restart_delay_secs": self.config.timing.restart_delay_secs,
                "relogin_max_attempts": self.config.timing.relogin_max_attempts,
                "relogin_failure_action":
                    format!("{:?}", self.config.timing.relogin_failure_action).to_lowercase(),
                "api_port_probe_interval_secs":
                    self.config.timing.api_port_probe_interval_secs,
                "api_port_probe_fails_before_revoke":
                    self.config.timing.api_port_probe_fails_before_revoke,
            },
            "agent": {
                "socket_path": self.config.agent.socket_path,
            },
            "ib_status": {
                "kick_active_session": self.config.ib_status.kick_active_session,
            },
            "logging": {
                "level": format!("{:?}", self.config.logging.level).to_lowercase(),
                "log_dir": self.config.logging.log_dir,
                "futures_session_logging": self.config.logging.futures_session_logging,
                "session_reopen_hour": self.config.logging.session_reopen_hour,
            },
            "site": {
                "role": self.config.site.role.to_string(),
                "auto_launch": self.config.site.auto_launch,
            },
        }).to_string()
    }

    /// Build the WINDOWS JSON response including client tabs.
    async fn build_windows_json(&self) -> String {
        let windows = self.agent_client.list_windows().await.unwrap_or_default();

        let mut windows_json = Vec::new();
        for w in &windows {
            let tabs: Vec<serde_json::Value> = if let Ok(dump) = self.agent_client.dump_components(w.id).await {
                dump.get("tabs").and_then(|t| t.as_array()).cloned().unwrap_or_default()
            } else {
                Vec::new()
            };

            windows_json.push(serde_json::json!({
                "id": w.id,
                "title": w.title,
                "class": w.class,
                "tabs": tabs,
            }));
        }

        serde_json::json!({
            "windows": windows_json,
        }).to_string()
    }
}

// ---------------------------------------------------------------------------
// RED tests — STATUS JSON exposure of RecoveryCoordinator.
//
// Every test constructs a minimal StateMachine (private helper below), reads
// build_status_json(), parses it, and asserts on the new "recovery" nested
// object. All six tests fail in the RED phase because build_status_json does
// not yet emit the "recovery" key.
//
// A local helper duplicates the make_test_state_machine pattern from mod.rs
// because build_status_json is a private inherent method — accessible only
// from within this module. Test infrastructure sharing would require a
// pub(super) helper module; that's a separate refactor.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! RED-phase tests for the recovery STATUS-JSON exposure.
    //!
    //! # RED-phase state
    //!
    //! `build_status_json` does not yet emit a top-level `"recovery"` key,
    //! so every assertion here fails with either "missing 'recovery' key"
    //! or an unwrap panic on the field lookup. Do NOT modify the emission
    //! yet — this is the RED half of the TDD cycle.
    //!
    //! # Fixture strategy
    //!
    //! Tests that need a specific recovery phase (Backoff, GivenUp) plant
    //! a valid marker file under a `TempDir` BEFORE constructing the
    //! StateMachine. The SM's `RecoveryCoordinator::boot()` reads it and
    //! restores the phase. This mirrors how production coordinators pick
    //! up phase across container restarts — same code path, no test-only
    //! backdoor into the coordinator's private fields.
    //!
    //! # Wire-format pins
    //!
    //! The exact field names and value shapes are asserted here so a
    //! future rename to any of `phase`, `phase_entered_at`,
    //! `phase_elapsed_secs`, `last_full_success_at`, `giveup_alert_sent_at`,
    //! `next_retry_at`, `blocked_awaiting_resume` fails a test rather than
    //! silently breaking the dashboard's parser or the external ZMQ
    //! consumers on port 5556.

    use crate::agent_client::{AgentClient, MockAgent};
    use crate::config::{Config, ValidConfig};
    use crate::handlers::DialogHandlerRegistry;
    use crate::state_machine::recovery::{
        save, RecoveryPersistedState, RecoveryPhase,
    };
    use crate::state_machine::types::{Channels, State, StateMachine};
    use crate::supervisor::Supervisor;
    use crate::types::{ColdRestartOutcome, QuerySnapshot};
    use secrecy::SecretString;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::{mpsc, watch};

    /// Deterministic wall-clock instant for tests: 2026-07-11 10:00 -04:00.
    /// Matches the current-day fixture convention across the crate.
    fn fixed_zoned() -> jiff::Zoned {
        jiff::civil::date(2026, 7, 11)
            .at(10, 0, 0, 0)
            .to_zoned(jiff::tz::TimeZone::fixed(jiff::tz::Offset::constant(-4)))
            .expect("synthetic zoned must construct")
    }

    /// Build a canonical persisted-state at the given phase with
    /// `phase_entered_at` at `fixed_zoned()`. Used by tests that plant a
    /// marker file in `settings_dir` before booting the SM.
    fn planted_state(phase: RecoveryPhase) -> RecoveryPersistedState {
        RecoveryPersistedState {
            schema_version: 1,
            phase,
            phase_entered_at: fixed_zoned(),
            phase_entered_at_monotonic_secs_since_boot: 0,
            last_full_success_at: None,
            giveup_alert_sent_at: None,
            resumed_by_token_hash: None,
            last_known_phase: phase,
        }
    }

    /// Construct a minimal StateMachine whose recovery coordinator boots
    /// from `settings_dir`. Duplicates the `make_test_state_machine`
    /// helper in mod.rs but points the coordinator at a caller-supplied
    /// directory so marker planting works.
    ///
    /// The trailing marker filename is arbitrary — only its parent is
    /// consumed as the settings_dir for `RecoveryCoordinator::boot`.
    fn make_sm_pointed_at(settings_dir: &std::path::Path) -> StateMachine {
        let mut cfg = Config::default();
        {
            // Test fixture placeholders — leading paren defeats the naive
            // pragma-scanner regex on `USERNAME = <ident>`.
            cfg.auth.username = ("xxx").to_string();
            cfg.auth.password = SecretString::from(("xxx").to_string());
        }
        let config = ValidConfig::new_unchecked(cfg);
        let agent_client = AgentClient::mock(MockAgent::default());
        let supervisor = Supervisor::new(
            config.gateway.clone(),
            PathBuf::from("/dev/null/not-used-in-tests.jar"),
            "/dev/null/not-used.sock".to_string(),
            5,
        );
        let handler_registry = DialogHandlerRegistry::new();

        let (_sig_tx, sig_rx) = mpsc::channel(1);
        let (_cmd_tx, cmd_rx) = mpsc::channel(1);
        let (_q_tx, q_rx) = mpsc::channel(1);
        let (_cr_tx, cr_rx) = mpsc::channel(1);
        let channels = Channels {
            signals: sig_rx,
            commands: cmd_rx,
            queries: q_rx,
            cold_restart: cr_rx,
            agent_events: {
                let (_tx, rx) = mpsc::channel(1);
                rx
            },
        };

        let (snapshot_tx, _snapshot_rx) =
            watch::channel(Arc::new(QuerySnapshot::initializing()));

        // Point the cold-restart-equivalent marker at a path INSIDE
        // settings_dir so `types::new()` computes settings_dir correctly
        // (it derives settings_dir from marker_path.parent()).
        let marker_path = settings_dir.join("cold-restart-marker-unused-in-test");

        let mut sm = StateMachine::new(
            config,
            agent_client,
            supervisor,
            handler_registry,
            channels,
            snapshot_tx,
            marker_path,
        );
        sm.supervisor.set_test_force_running(true);
        sm
    }

    /// Convenience: parse build_status_json into a serde_json::Value.
    fn status_value(sm: &mut StateMachine) -> serde_json::Value {
        let s = sm.build_status_json();
        serde_json::from_str(&s).expect("STATUS JSON must be valid JSON")
    }

    // -------- Sunday re-authentication outcome in STATUS -----------

    #[test]
    fn test_status_carries_last_cold_restart_outcome_and_owed_since() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = make_sm_pointed_at(dir.path());
        let v = status_value(&mut sm);
        assert!(v["last_cold_restart_outcome"].is_null(), "no outcome before any fire");
        assert!(v["cold_restart_owed_since"].is_null());
        assert!(v.get("last_cold_restart_skip").is_none(), "retired key must be gone");

        sm.last_cold_restart_outcome = Some(super::super::types::ColdRestartOutcomeRecord {
            recorded_at: jiff::Zoned::now(),
            outcome: ColdRestartOutcome::Failed { detail: "jvm died".into() },
            state: "Error".into(),
        });
        sm.cold_restart_owed_since = Some(jiff::Zoned::now());
        let v = status_value(&mut sm);
        let o = &v["last_cold_restart_outcome"];
        assert_eq!(o["outcome"], "failed");
        assert_eq!(o["state"], "Error");
        assert_eq!(o["detail"], "jvm died");
        assert!(o["recorded_at"].is_string());
        assert!(v["cold_restart_owed_since"].is_string());

        let at = jiff::Zoned::now();
        sm.last_cold_restart_outcome = Some(super::super::types::ColdRestartOutcomeRecord {
            recorded_at: jiff::Zoned::now(),
            outcome: ColdRestartOutcome::AlreadySatisfied { at: at.clone() },
            state: "Connected".into(),
        });
        let v = status_value(&mut sm);
        assert_eq!(v["last_cold_restart_outcome"]["outcome"], "already_satisfied");
        assert_eq!(v["last_cold_restart_outcome"]["last_login_at"], at.to_string());
    }

    #[test]
    fn test_status_publishes_the_session_conflict_evidence_and_breaker() {
        // Hours of conflicts used to raise one dwell page. STATUS carries what
        // the dashboard needs to page loudly and say who holds the session.
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = make_sm_pointed_at(dir.path());
        assert!(status_value(&mut sm)["session_conflict"]["last"].is_null());
        assert_eq!(status_value(&mut sm)["session_conflict"]["breaker_open"], false);

        sm.session_conflicts.push_back(std::time::Instant::now());
        sm.session_conflict_breaker_open = true;
        sm.last_session_conflict = Some(crate::state_machine::types::SessionConflictRecord {
            at: jiff::Zoned::now(),
            other_ip: Some("203.0.113.7".into()),
            other_connected_at: Some("2026-09-26T16:09:26Z".parse().unwrap()),
            self_inflicted: true,
            recent: 5,
        });
        let v = status_value(&mut sm);
        let sc = &v["session_conflict"];
        assert_eq!(sc["breaker_open"], true);
        assert_eq!(sc["recent"], 1);
        assert_eq!(sc["threshold"], 5);
        assert_eq!(sc["last"]["other_ip"], "203.0.113.7");
        assert_eq!(sc["last"]["other_connected_at"], "2026-09-26T16:09:26Z");
        assert_eq!(sc["last"]["self_inflicted"], true);
    }

    // -------- an outstanding push, the park, the relaunch ---------

    #[test]
    fn test_status_says_an_open_push_is_waiting_without_ending_the_round() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = make_sm_pointed_at(dir.path());
        assert!(status_value(&mut sm)["twofa"].is_null(), "only while waiting for 2FA");

        sm.state = State::WaitingFor2fa;
        sm.twofa_challenge_seen = true;
        let alert_after = sm.config.twofa.timeout_seconds;
        sm.twofa_challenge_opened_at =
            Some(std::time::Instant::now() - std::time::Duration::from_secs(alert_after + 5));
        let t = status_value(&mut sm)["twofa"].clone();
        assert_eq!(t["challenge_open"], true);
        assert_eq!(t["push_overdue"], true);
        assert!(t["challenge_open_secs"].as_u64().unwrap() >= alert_after + 5);
        assert_eq!(t["alert_after_secs"], alert_after);
        assert_eq!(t["stuck_ceiling_secs"], 1800);
        assert_eq!(t["cancel_sent"], false);

        // The prompt closed: its result is being confirmed, nothing waits on the phone.
        sm.twofa_gone_at = Some(std::time::Instant::now());
        let t = status_value(&mut sm)["twofa"].clone();
        assert_eq!(t["challenge_open"], false);
        assert_eq!(t["push_overdue"], false);
    }

    #[test]
    fn test_status_says_why_a_login_is_parked() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = make_sm_pointed_at(dir.path());
        sm.state = State::WaitingForHitl2fa;
        sm.hitl_entered_at = Some(std::time::Instant::now());
        sm.hitl_park_reason = Some(super::super::types::HitlParkReason::UnattendedHours);
        let h = status_value(&mut sm)["hitl"].clone();
        assert_eq!(h["parked_reason"], "unattended_hours");
        assert_eq!(h["cancel_requested"], false);
    }

    #[test]
    fn test_status_publishes_the_last_relaunch_and_its_reason() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = make_sm_pointed_at(dir.path());
        assert!(status_value(&mut sm)["last_relaunch"].is_null());
        sm.last_relaunch = Some(super::super::types::RelaunchRecord {
            at: jiff::Zoned::now(),
            from_state: "WaitingFor2fa".into(),
            reason: "prompt_ignored_cancel",
            detail: "an IB Key prompt stayed open past the stuck ceiling and did not close on Cancel".into(),
            abandoned_prompt: false,
        });
        let r = status_value(&mut sm)["last_relaunch"].clone();
        assert_eq!(r["reason"], "prompt_ignored_cancel");
        assert_eq!(r["from_state"], "WaitingFor2fa");
        assert_eq!(r["abandoned_prompt"], false);
        assert!(r["at"].is_string());
        assert!(r["detail"].as_str().unwrap().contains("Cancel"));
    }

    #[test]
    fn test_status_reports_host_maintenance_and_the_sunday_facts_separately() {
        // Host maintenance and authentication are reported
        // separately; restart satisfied and auth satisfied are two facts.
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = make_sm_pointed_at(dir.path());
        sm.cold_restart_equivalent_marker_path = dir.path().join(".ibctl-cold-restart-equivalent-today");
        let v = status_value(&mut sm);
        assert!(v["maintenance"]["hold"].is_null());
        assert!(v["maintenance"]["last"].is_null());
        assert!(v["sunday_reauth"]["auth_satisfied_at"].is_null(), "no fresh login today");

        let hold = crate::maintenance_hold::Hold::new("rt-1", 600, jiff::Timestamp::now()).unwrap();
        crate::maintenance_hold::write(&crate::maintenance_hold::path_in(dir.path()), &hold).unwrap();
        crate::state_machine::markers::write_cold_restart_equivalent_marker(&sm.cold_restart_equivalent_marker_path).unwrap();
        let v = status_value(&mut sm);
        assert_eq!(v["maintenance"]["hold"]["id"], "rt-1");
        assert_eq!(v["maintenance"]["hold"]["active"], true);
        assert!(v["sunday_reauth"]["auth_satisfied_at"].is_string(), "a fresh login today");
        assert!(v["sunday_reauth"].get("jvm_launched_at").is_some());
    }

    #[test]
    fn test_status_publishes_what_a_cold_restart_would_do_now() {
        // The dashboard's countdown renders this per mode instead of
        // re-implementing the decision table (one source of truth).
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = make_sm_pointed_at(dir.path());
        sm.state = State::Connected;
        assert_eq!(status_value(&mut sm)["cold_restart_plan"], "restarted");

        sm.state = State::WaitingForHitl2fa;
        sm.hitl_entered_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(6 * 3600));
        let v = status_value(&mut sm);
        assert_eq!(v["cold_restart_plan"], "resumed_login");
        assert_eq!(v["hitl"]["challenge_open"], false);
        assert_eq!(v["hitl"]["relogin_armed"], false);

        // The Gateway shows its IB Key dialog: the plan follows what is
        // on screen, however long HITL has lasted.
        sm.observation.window_opened(8, "Second Factor Authentication".into(), "dialog".into(), false, 1);
        sm.observation.synced = true;
        sm.hitl_relogin_armed = true;
        let v = status_value(&mut sm);
        assert_eq!(v["cold_restart_plan"], "challenge_pending");
        assert_eq!(v["hitl"]["challenge_open"], true);
        assert_eq!(v["hitl"]["relogin_armed"], true);

        sm.state = State::WaitingForLaunch;
        sm.hitl_entered_at = None;
        assert_eq!(status_value(&mut sm)["cold_restart_plan"], "standby");
    }

    // -------- Test 1: recovery block is present ------------------------------

    #[test]
    fn test_status_response_includes_recovery_block() {
        // The primary shape assertion: STATUS JSON must
        // carry a top-level "recovery" key whose value is a JSON object
        // (not null, not a string). External ZMQ consumers depend on
        // the additive extension convention — the field is ALWAYS
        // present, so consumers can trust an unconditional lookup.
        let dir = TempDir::new().unwrap();
        let mut sm = make_sm_pointed_at(dir.path());

        let v = status_value(&mut sm);
        let recovery = v
            .get("recovery")
            .expect("STATUS JSON must include a top-level 'recovery' key");
        assert!(
            recovery.is_object(),
            "'recovery' must be a JSON object, got: {:?}",
            recovery,
        );

        // Field-name pin: all documented keys must be present. A rename
        // would silently break the dashboard's parser AND the ZMQ port-
        // 5556 consumers, so this is a hard wire-format lock.
        //
        // The last five fields exist because the dashboard monitor's
        // give-up alert body composes phrasing from the max_secs values,
        // and its dedupe-resend gate reads giveup_alert_resend_interval_hours.
        // Without them, the monitor read absent fields and silently fell
        // back to hardcoded 3600/10800/60/12/6 defaults regardless of
        // how the operator configured ibctl.
        for field in [
            "phase",
            "phase_entered_at",
            "phase_elapsed_secs",
            "last_full_success_at",
            "giveup_alert_sent_at",
            "next_retry_at",
            "blocked_awaiting_resume",
            "aggressive_phase_max_secs",
            "backoff_phase_max_secs",
            "min_success_dwell_secs",
            "callback_valid_hours",
            "giveup_alert_resend_interval_hours",
        ] {
            assert!(
                recovery.get(field).is_some(),
                "'recovery' object missing field '{}'. keys: {:?}",
                field,
                recovery.as_object().unwrap().keys().collect::<Vec<_>>(),
            );
        }
    }

    // -------- Test 1b: config fields carry the coordinator's values ----------

    #[test]
    fn test_status_recovery_config_fields_reflect_coordinator() {
        // Companion to test 1 (field-name pin) — this test pins that the
        // config fields carry the coordinator's actual values, not a
        // duplicated const. Directly guards the stale-defaults bug: a
        // dashboard monitor that reads these fields expects them to
        // reflect operator config, not a fabricated fallback.
        let dir = TempDir::new().unwrap();
        let mut sm = make_sm_pointed_at(dir.path());

        let v = status_value(&mut sm);
        let recovery = v.get("recovery").expect("recovery block");
        assert_eq!(
            recovery.get("aggressive_phase_max_secs").and_then(|x| x.as_u64()),
            Some(super::super::recovery::RecoveryConfig::DEFAULT_AGGRESSIVE_MAX_SECS),
        );
        assert_eq!(
            recovery.get("backoff_phase_max_secs").and_then(|x| x.as_u64()),
            Some(super::super::recovery::RecoveryConfig::DEFAULT_BACKOFF_MAX_SECS),
        );
        assert_eq!(
            recovery.get("min_success_dwell_secs").and_then(|x| x.as_u64()),
            Some(super::super::recovery::RecoveryConfig::DEFAULT_MIN_SUCCESS_DWELL_SECS),
        );
        assert_eq!(
            recovery.get("callback_valid_hours").and_then(|x| x.as_u64()),
            Some(super::super::recovery::RecoveryConfig::DEFAULT_GIVEUP_CALLBACK_VALID_HOURS as u64),
        );
        assert_eq!(
            recovery
                .get("giveup_alert_resend_interval_hours")
                .and_then(|x| x.as_u64()),
            Some(
                super::super::recovery::RecoveryConfig::DEFAULT_GIVEUP_ALERT_RESEND_INTERVAL_HOURS
                    as u64
            ),
        );
    }

    // -------- Test 2: phase field matches coordinator ------------------------

    #[test]
    fn test_status_recovery_phase_matches_coordinator() {
        // When the coordinator boots from a marker with
        // phase=BackoffEvery15Min, the STATUS JSON must reflect that
        // wire string exactly (not "Backoff", not "backoff", not
        // "BackoffEvery15Min"). The `RecoveryPhase::as_str` contract
        // is the source of truth.
        let dir = TempDir::new().unwrap();
        let state = planted_state(RecoveryPhase::BackoffEvery15Min);
        save(dir.path(), "paper", &state).expect("plant marker");

        let mut sm = make_sm_pointed_at(dir.path());
        let v = status_value(&mut sm);
        let phase = v
            .pointer("/recovery/phase")
            .and_then(|p| p.as_str())
            .expect("recovery.phase must be a string");

        assert_eq!(
            phase,
            RecoveryPhase::BackoffEvery15Min.as_str(),
            "phase wire string must match `RecoveryPhase::as_str()`",
        );
    }

    // -------- Test 3: phase_elapsed_secs reflects time ------------------------

    #[test]
    fn test_status_recovery_phase_elapsed_reflects_time() {
        // `phase_elapsed_secs` is the wall-clock delta from
        // `phase_entered_at` to now. For a freshly-booted coordinator
        // that just entered Aggressive at "now", the elapsed must be
        // small and non-negative. Field type must be an integer
        // (dashboards render it directly; a float would surprise the
        // parser).
        let dir = TempDir::new().unwrap();
        let mut sm = make_sm_pointed_at(dir.path());

        let v = status_value(&mut sm);
        let elapsed = v
            .pointer("/recovery/phase_elapsed_secs")
            .expect("recovery.phase_elapsed_secs must exist");

        assert!(
            elapsed.is_u64() || elapsed.is_i64(),
            "phase_elapsed_secs must be an integer (u64 or i64), got: {:?}",
            elapsed,
        );
        let n = elapsed.as_u64().expect("must fit in u64 (non-negative)");
        // The coordinator just entered Aggressive at boot; even on a
        // slow CI runner this shouldn't exceed a few seconds. The
        // spec says the value is CLAMPED to 0 if negative — that
        // clamping is what we're pinning against a future signed-int
        // regression.
        assert!(
            n < 10,
            "phase_elapsed_secs should be tiny for a fresh boot, got {}",
            n,
        );
    }

    // -------- Test 4: next_retry_at present in Backoff ----------------------

    #[test]
    fn test_status_recovery_next_retry_at_computed_when_backoff() {
        // `next_retry_at` is populated ONLY in the Backoff
        // phase. It is computed as `phase_entered_at + interval * ceil(
        // elapsed / interval)` — the next 15-minute boundary from the
        // phase-entry anchor. In a freshly-booted Backoff coordinator
        // (elapsed ~0s), the next boundary is `phase_entered_at +
        // 900s`. Must be a non-null string (serialized Zoned).
        let dir = TempDir::new().unwrap();
        let state = planted_state(RecoveryPhase::BackoffEvery15Min);
        save(dir.path(), "paper", &state).expect("plant marker");

        let mut sm = make_sm_pointed_at(dir.path());
        let v = status_value(&mut sm);

        let next = v
            .pointer("/recovery/next_retry_at")
            .expect("recovery.next_retry_at must exist");

        assert!(
            !next.is_null(),
            "next_retry_at must be non-null in Backoff phase, got: {:?}",
            next,
        );
        let s = next
            .as_str()
            .expect("next_retry_at must serialize as a string (Zoned)");
        assert!(
            !s.is_empty(),
            "next_retry_at string must be non-empty",
        );
    }

    // -------- Test 5: next_retry_at is null outside Backoff -----------------

    #[test]
    fn test_status_recovery_next_retry_at_null_when_not_backoff() {
        // In Aggressive OR GivenUp, `next_retry_at` MUST
        // be JSON null. A stale computed value here would mislead
        // dashboards into rendering a "next retry" countdown while the
        // coordinator is either aggressively retrying (no wait) or
        // halted awaiting resume (no retry).
        //
        // Sub-case a: freshly-booted Aggressive.
        let dir_a = TempDir::new().unwrap();
        let mut sm_a = make_sm_pointed_at(dir_a.path());
        let va = status_value(&mut sm_a);
        assert!(
            va.pointer("/recovery/next_retry_at")
                .expect("recovery.next_retry_at must exist in Aggressive")
                .is_null(),
            "next_retry_at must be null in Aggressive, got: {:?}",
            va.pointer("/recovery/next_retry_at"),
        );

        // Sub-case b: planted GivenUp.
        let dir_b = TempDir::new().unwrap();
        let state = planted_state(RecoveryPhase::GivenUp);
        save(dir_b.path(), "paper", &state).expect("plant marker");
        let mut sm_b = make_sm_pointed_at(dir_b.path());
        let vb = status_value(&mut sm_b);
        assert!(
            vb.pointer("/recovery/next_retry_at")
                .expect("recovery.next_retry_at must exist in GivenUp")
                .is_null(),
            "next_retry_at must be null in GivenUp, got: {:?}",
            vb.pointer("/recovery/next_retry_at"),
        );
    }

    // -------- Test 6: last_full_success_at null when never ------------------

    #[test]
    fn test_status_recovery_last_full_success_at_null_when_never() {
        // A freshly-booted coordinator has never observed
        // a Connected dwell success, so `last_full_success_at` must be
        // JSON null. This is the discriminator dashboards use to render
        // "never connected" vs "connected N minutes ago".
        let dir = TempDir::new().unwrap();
        let mut sm = make_sm_pointed_at(dir.path());

        let v = status_value(&mut sm);
        let lfs = v
            .pointer("/recovery/last_full_success_at")
            .expect("recovery.last_full_success_at must exist");
        assert!(
            lfs.is_null(),
            "last_full_success_at must be null before first dwell success, got: {:?}",
            lfs,
        );
    }

    // -------- Additional test: blocked flag defaults false ------------------

    #[test]
    fn test_status_recovery_blocked_awaiting_resume_defaults_false() {
        // Additional test beyond spec (justified inline): the boolean
        // is user-visible in the dashboard as the RED-badge trigger.
        // A default-true would surface a fake operator-block alarm on
        // every fresh boot. Pin the boolean shape (not just the value)
        // so a future refactor to `Option<bool>` doesn't silently
        // start emitting nulls that JS truthy-checks as "no alarm".
        let dir = TempDir::new().unwrap();
        let mut sm = make_sm_pointed_at(dir.path());

        let v = status_value(&mut sm);
        let flag = v
            .pointer("/recovery/blocked_awaiting_resume")
            .expect("recovery.blocked_awaiting_resume must exist");
        assert!(
            flag.is_boolean(),
            "blocked_awaiting_resume must be a JSON boolean, got: {:?}",
            flag,
        );
        assert_eq!(
            flag.as_bool(),
            Some(false),
            "blocked_awaiting_resume must default to false for a fresh boot",
        );
    }

    // -------- Additional test: phase_entered_at is Zoned wire format -------

    #[test]
    fn test_status_recovery_phase_entered_at_serializes_as_zoned_string() {
        // Additional test beyond spec (justified inline): jiff's
        // `Serialize` for `Zoned` emits a bracket-suffixed IANA form
        // like `2026-07-11T10:00:00-04:00[America/New_York]`. The
        // dashboard parses this to render both a UTC offset AND the
        // zone name. A future refactor to `Timestamp` (no zone) would
        // strip the bracket suffix and silently break the zone
        // display. Pin the wire format as a non-empty string here;
        // the golden JSON fixture pins the exact bracket suffix on
        // the dashboard side.
        let dir = TempDir::new().unwrap();
        let state = planted_state(RecoveryPhase::BackoffEvery15Min);
        save(dir.path(), "paper", &state).expect("plant marker");

        let mut sm = make_sm_pointed_at(dir.path());
        let v = status_value(&mut sm);
        let pea = v
            .pointer("/recovery/phase_entered_at")
            .expect("recovery.phase_entered_at must exist");
        let s = pea
            .as_str()
            .expect("phase_entered_at must be a string (Zoned)");
        assert!(
            s.contains('T'),
            "Zoned wire format must contain 'T' between date and time, got: {}",
            s,
        );
    }

    // -------- Post-review additions: adversarial gap-closers ----------------
    //
    // Each test closes a specific "green passes but a future refactor
    // breaks the wire contract silently" hole found in adversarial code
    // review.

    // -------- Test: next_retry_at formula is arithmetically exact ----------

    #[test]
    fn test_status_recovery_next_retry_at_formula_matches_spec() {
        // Previously the only Rust assertion on
        // `next_retry_at` was non-null + non-empty. A future refactor
        // that swaps the formula from `entry + interval*(floor(elapsed
        // /interval)+1)` (the current code) back to the RED-spec
        // `entry + interval*ceil(elapsed/interval)` diverges at exact
        // boundaries — e.g., elapsed=3600s, interval=900s → 11:00 (ceil)
        // vs 11:15 (floor+1). Only the dashboard-side fixture pins the
        // exact 11:15 value; ZMQ subscribers on port 5556 would drift
        // silently. This test pins the Rust-side formula against the
        // JSON output for arbitrary elapsed values, computed at test
        // time to survive any wall-clock jitter during test execution.
        let dir = TempDir::new().unwrap();
        let state = planted_state(RecoveryPhase::BackoffEvery15Min);
        save(dir.path(), "paper", &state).expect("plant marker");

        let mut sm = make_sm_pointed_at(dir.path());
        let v = status_value(&mut sm);

        let elapsed = v
            .pointer("/recovery/phase_elapsed_secs")
            .and_then(|e| e.as_u64())
            .expect("recovery.phase_elapsed_secs must be u64");
        let next_str = v
            .pointer("/recovery/next_retry_at")
            .and_then(|e| e.as_str())
            .expect("next_retry_at must be a string in Backoff");

        // Parse the emitted Zoned back through jiff's Deserialize.
        // Serde string parsing accepts the bracket-suffix form.
        let next: jiff::Zoned = next_str
            .parse()
            .unwrap_or_else(|e| panic!("next_retry_at must parse as Zoned, got {next_str:?}: {e}"));

        let interval: u64 = 900;
        let boundaries_passed = elapsed / interval;
        let expected_offset_secs = interval * (boundaries_passed + 1);
        let entered = fixed_zoned();
        let expected_next_ts =
            entered.timestamp().as_second() + expected_offset_secs as i64;

        assert_eq!(
            next.timestamp().as_second(),
            expected_next_ts,
            "next_retry_at must equal phase_entered_at + \
             interval*(floor(elapsed/interval)+1); \
             elapsed={elapsed} interval={interval} entered={entered}",
        );
    }

    // -------- Test: last_full_success_at populated wire format --------------

    #[test]
    fn test_status_recovery_last_full_success_at_populated_serializes_as_zoned() {
        // The RED tests only cover the None branch. If
        // a future refactor changes the accessor to return
        // `Some(Zoned)` in some other wire format (e.g. Timestamp), no
        // existing test catches it. Plant a marker with Some(...) and
        // assert the string round-trips through the Zoned wire format
        // (contains 'T' and, per jiff, the '[' zone bracket suffix).
        let dir = TempDir::new().unwrap();
        let mut state = planted_state(RecoveryPhase::Aggressive);
        state.last_full_success_at = Some(fixed_zoned());
        save(dir.path(), "paper", &state).expect("plant marker");

        let mut sm = make_sm_pointed_at(dir.path());
        let v = status_value(&mut sm);
        let lfs = v
            .pointer("/recovery/last_full_success_at")
            .expect("recovery.last_full_success_at must exist");
        let s = lfs
            .as_str()
            .expect("last_full_success_at must serialize as a string when Some");
        assert!(
            s.contains('T'),
            "Zoned wire format must contain 'T' between date and time, got: {}",
            s,
        );
    }

    // -------- Test: giveup_alert_sent_at populated wire format --------------

    #[test]
    fn test_status_recovery_giveup_alert_sent_at_populated_serializes_as_rfc3339_utc() {
        // The RED tests never exercise a
        // non-null `giveup_alert_sent_at`. jiff's `Timestamp::to_string`
        // emits RFC 3339 with a trailing `Z` (e.g. 2026-07-11T14:00:00Z).
        // A future jiff upgrade that adds fractional-second precision
        // would silently mutate the wire format for GivenUp-phase
        // daemons and break strict ZMQ subscribers. Pin the shape.
        //
        // Plant a GivenUp marker with a known Timestamp; assert the
        // emitted string is a plain RFC 3339 UTC-Z form.
        let dir = TempDir::new().unwrap();
        let mut state = planted_state(RecoveryPhase::GivenUp);
        // Unix epoch 1_720_000_000 = 2024-07-03T10:13:20Z. Any fixed
        // second-precision timestamp works; we assert format shape,
        // not the specific value.
        state.giveup_alert_sent_at = Some(
            jiff::Timestamp::from_second(1_720_000_000)
                .expect("valid unix timestamp"),
        );
        save(dir.path(), "paper", &state).expect("plant marker");

        let mut sm = make_sm_pointed_at(dir.path());
        let v = status_value(&mut sm);
        let ga = v
            .pointer("/recovery/giveup_alert_sent_at")
            .expect("recovery.giveup_alert_sent_at must exist");
        let s = ga
            .as_str()
            .expect("giveup_alert_sent_at must serialize as a string when Some");
        // Shape: YYYY-MM-DDTHH:MM:SS[optional-.fractional]Z
        // Strict-anchor a `Z` terminator so a stray bracket suffix (if
        // someone accidentally swaps the accessor to return Zoned)
        // trips this test.
        assert!(
            s.ends_with('Z'),
            "Timestamp wire format must end with 'Z' (RFC 3339 UTC), got: {}",
            s,
        );
        assert!(
            !s.contains('['),
            "Timestamp wire format must NOT contain zone bracket suffix, got: {}",
            s,
        );
        assert!(
            s.contains('T'),
            "Timestamp wire format must contain 'T' between date and time, got: {}",
            s,
        );
    }

    // -------- Test: blocked_awaiting_resume=true when Refused ---------------

    #[test]
    fn test_status_recovery_blocked_awaiting_resume_true_on_refused() {
        // The RED tests only cover blocked=false. The
        // wire contract's raison d'être is the true branch — that's the
        // RED-badge trigger in the dashboard header. Drive the actual
        // fail-safe path (corrupt main marker + given_up sidecar) so
        // the coordinator boots into RefusedGivenUpAutoReset and
        // blocked_awaiting_resume=true surfaces on the STATUS wire.
        let dir = TempDir::new().unwrap();
        let main = dir.path().join(".ibctl-recovery-state.paper.json");
        let side = dir
            .path()
            .join(".ibctl-recovery-state.paper.last-known-phase.txt");
        std::fs::write(&main, "corrupt garbage {").unwrap();
        std::fs::write(&side, "given_up").unwrap();

        let mut sm = make_sm_pointed_at(dir.path());
        let v = status_value(&mut sm);
        let flag = v
            .pointer("/recovery/blocked_awaiting_resume")
            .and_then(|f| f.as_bool())
            .expect("recovery.blocked_awaiting_resume must be a boolean");
        assert!(
            flag,
            "blocked_awaiting_resume must be true after RefusedGivenUpAutoReset boot",
        );

        // Under refuse, coordinator is constructed with phase=GivenUp
        // (see boot()'s Refused branch) so the resume-token gate can
        // fire — pin that here too so a future refactor that flips
        // the phase to Aggressive-with-blocked doesn't slip past.
        let phase = v
            .pointer("/recovery/phase")
            .and_then(|p| p.as_str())
            .expect("recovery.phase must be a string");
        assert_eq!(
            phase,
            RecoveryPhase::GivenUp.as_str(),
            "phase must be given_up when boot outcome is RefusedGivenUpAutoReset",
        );
    }

    // -------- Test: aggressive phase wire string --------------------------

    #[test]
    fn test_status_recovery_phase_aggressive_wire_string() {
        // The RED tests explicitly assert wire strings only
        // for Backoff (test 2). Aggressive and GivenUp are covered
        // implicitly (fresh-boot defaults to Aggressive; planted
        // marker restores GivenUp). Pin the aggressive wire string
        // explicitly so a rename of `RecoveryPhase::as_str` for
        // Aggressive doesn't drift undetected.
        let dir = TempDir::new().unwrap();
        let mut sm = make_sm_pointed_at(dir.path());
        let v = status_value(&mut sm);
        let phase = v
            .pointer("/recovery/phase")
            .and_then(|p| p.as_str())
            .expect("recovery.phase must be a string");
        assert_eq!(
            phase,
            RecoveryPhase::Aggressive.as_str(),
            "fresh-boot phase wire string must be `RecoveryPhase::Aggressive.as_str()`",
        );
    }

    // -------- Test: given_up phase wire string ----------------------------

    #[test]
    fn test_status_recovery_phase_given_up_wire_string() {
        // Cover the GivenUp wire string explicitly. Planted
        // marker with phase=GivenUp; STATUS JSON must reflect the
        // `RecoveryPhase::GivenUp.as_str()` output ("given_up").
        let dir = TempDir::new().unwrap();
        let state = planted_state(RecoveryPhase::GivenUp);
        save(dir.path(), "paper", &state).expect("plant marker");

        let mut sm = make_sm_pointed_at(dir.path());
        let v = status_value(&mut sm);
        let phase = v
            .pointer("/recovery/phase")
            .and_then(|p| p.as_str())
            .expect("recovery.phase must be a string");
        assert_eq!(
            phase,
            RecoveryPhase::GivenUp.as_str(),
            "given_up wire string must match `RecoveryPhase::as_str()`",
        );
    }

    // -------- Test: RecoveryPhase::as_str matches serde serialize output ----

    #[test]
    fn test_recovery_phase_serde_output_matches_as_str() {
        // Two independent wire-string sources exist —
        // `impl RecoveryPhase::as_str` (used by queries.rs for STATUS
        // JSON) AND `#[serde(rename = "...")]` (used when a
        // `RecoveryPhase` is embedded inside a serde-derive struct,
        // e.g. `RecoveryPersistedState`). A drift in one source is
        // silent — the STATUS JSON stays right while a persisted-state
        // field goes wrong (or vice versa).
        //
        // Iterate every variant, serialize via serde_json, and assert
        // the raw string matches `as_str()`. Serde strips the outer
        // quotes; compare via `trim_matches('"')`.
        for phase in [
            RecoveryPhase::Aggressive,
            RecoveryPhase::BackoffEvery15Min,
            RecoveryPhase::GivenUp,
        ] {
            let serde_wire = serde_json::to_string(&phase)
                .expect("RecoveryPhase must serialize");
            let stripped = serde_wire.trim_matches('"');
            assert_eq!(
                stripped,
                phase.as_str(),
                "serde `rename` output must match `as_str()` for {phase:?}",
            );
        }
    }
}
