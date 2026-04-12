//! Sunday cold restart timer.
//!
//! IBKR requires a full shutdown and re-login once a week (Sundays).
//! Gateway does NOT have a built-in cold restart — this is an IBC feature
//! that ibctl must replicate.
//!
//! How IBC handles it:
//! 1. IBC's Java code runs a timer checking for Sunday + ColdRestartTime
//! 2. When timer fires, creates COLDRESTART marker file
//! 3. Shuts down the Gateway JVM
//! 4. ibcstart.sh's while loop detects exit, finds marker, clears autorestart
//! 5. Relaunches JVM without autorestart flag → forces full re-auth + 2FA
//!
//! How ibctl handles it:
//! 1. Rust background task checks every 30s for Sunday + configured time
//! 2. Only fires if current time matches the target within a 1-minute window
//!    (never fires if started after the scheduled time — waits for next Sunday)
//! 3. Writes marker file to settings dir (survives container restart if volume-mounted)
//! 4. Sends signal to state machine which kills JVM and does full re-auth
//!
//! Timezone: respects the TZ env var (jiff uses system timezone)

use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

use crate::types::ColdRestartSignal;

/// Parse a cold restart time like "09:00" (24h format).
pub fn parse_cold_restart_time(time_str: &str) -> Option<(u32, u32)> {
    let time_str = time_str.trim();
    if time_str.is_empty() {
        return None;
    }

    let parts: Vec<&str> = time_str.split(':').collect();
    if parts.len() != 2 {
        log::warn!("Invalid cold restart time format '{}' — expected HH:MM", time_str);
        return None;
    }

    let hour: u32 = parts[0].parse().ok()?;
    let minute: u32 = parts[1].parse().ok()?;

    if hour > 23 || minute > 59 {
        log::warn!("Invalid cold restart time '{}' — hour/minute out of range", time_str);
        return None;
    }

    Some((hour, minute))
}

/// Check if cold restart already fired for the given date.
/// Marker file contains "YYYY-DDD" (year-day_of_year).
fn already_fired(marker_path: &Path, year: i32, day_of_year: u32) -> bool {
    if let Ok(contents) = std::fs::read_to_string(marker_path) {
        let today = format!("{}-{}", year, day_of_year);
        return contents.trim() == today;
    }
    false
}

/// Write marker recording that cold restart fired for this date.
fn write_marker(marker_path: &Path, year: i32, day_of_year: u32) {
    let today = format!("{}-{}", year, day_of_year);
    if let Err(e) = std::fs::write(marker_path, &today) {
        log::warn!("Failed to write cold restart marker to {}: {}", marker_path.display(), e);
    } else {
        log::info!("Cold restart marker written to {}", marker_path.display());
    }
}

/// Create the cold restart timer future.
///
/// Returns `None` if cold restart is not configured (empty time string).
/// The returned future should be spawned via a `JoinSet` for structured
/// concurrency — the caller owns the task lifetime.
///
/// - Only fires on Sunday at the exact configured minute (not if past)
/// - Tracks startup time to distinguish "started before scheduled time" from
///   "started after scheduled time" (the latter waits for next Sunday)
/// - Persists via marker file in TWS_SETTINGS_PATH (volume-mounted)
const DAY_NAMES: [&str; 7] = [
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
];

pub fn cold_restart_scheduler(
    cold_restart_time: String,
    cold_restart_day: u8,
    tx: mpsc::Sender<ColdRestartSignal>,
) -> Option<impl std::future::Future<Output = ()>> {
    let (target_hour, target_minute) = match parse_cold_restart_time(&cold_restart_time) {
        Some(t) => t,
        None => {
            log::info!("Cold restart not configured (TWS_COLD_RESTART not set)");
            return None;
        }
    };

    // Marker file: stored in settings dir so it survives container restart
    // if the settings dir is volume-mounted
    let settings_dir = std::env::var("TWS_SETTINGS_PATH")
        .unwrap_or_else(|_| "/home/ibgateway/Jts".to_string());
    let marker_path = PathBuf::from(&settings_dir).join(".ibctl-cold-restart-marker");

    let target_day = cold_restart_day.min(6) as u32;
    let day_name = DAY_NAMES[target_day as usize];
    let tz = std::env::var("TZ").unwrap_or_else(|_| "(system default)".to_string());
    log::info!(
        "Cold restart timer active: {}s at {:02}:{:02} (TZ={}, marker={})",
        day_name, target_hour, target_minute, tz, marker_path.display()
    );

    // Record the minute we started so we can detect "started after target time"
    let startup_time = get_local_time();

    Some(async move {
        use std::time::Duration;

        // Determine if we started AFTER the target time on a Sunday
        // If so, we must NOT fire — wait for next Sunday
        let started_past_target = if let Some(ref now) = startup_time {
            now.weekday == target_day
                && (now.hour > target_hour
                    || (now.hour == target_hour && now.minute > target_minute))
        } else {
            false
        };

        if started_past_target {
            log::info!(
                "Cold restart: started after target time — will fire next {} at {:02}:{:02}",
                day_name, target_hour, target_minute
            );
        }

        let mut fired_this_startup = false;

        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            if fired_this_startup {
                // Already fired once this process lifetime, sleep until tomorrow
                tokio::time::sleep(Duration::from_secs(3600)).await;
                continue;
            }

            let now = match get_local_time() {
                Some(t) => t,
                None => continue,
            };

            // Only fire on the configured day
            if now.weekday != target_day {
                continue;
            }

            // Check marker — already fired today?
            if already_fired(&marker_path, now.year, now.day_of_year) {
                continue;
            }

            // If we started after the target time today, skip this Sunday
            if started_past_target {
                continue;
            }

            // Fire only when current time matches target (within the current minute)
            if now.hour == target_hour && now.minute == target_minute {
                log::warn!(
                    "Cold restart PENDING — {} {:02}:{:02} — firing in 30 seconds (2FA will be required)",
                    day_name, target_hour, target_minute
                );

                // Phase 1: Wait 30 seconds (gives time for ntfy alert delivery + phone pickup)
                tokio::time::sleep(Duration::from_secs(30)).await;

                log::info!(
                    "Cold restart firing now ({} {:02}:{:02})",
                    day_name, target_hour, target_minute
                );

                // Write marker before sending signal
                write_marker(&marker_path, now.year, now.day_of_year);
                fired_this_startup = true;

                if tx.send(ColdRestartSignal).await.is_err() {
                    log::warn!("Cold restart signal channel closed");
                    return;
                }
            }
        }
    })
}

struct LocalTime {
    weekday: u32,
    hour: u32,
    minute: u32,
    day_of_year: u32,
    year: i32,
}

fn get_local_time() -> Option<LocalTime> {
    let now = jiff::Zoned::now();
    Some(LocalTime {
        weekday: now.weekday().to_sunday_zero_offset() as u32,
        hour: now.hour() as u32,
        minute: now.minute() as u32,
        day_of_year: now.day_of_year() as u32,
        year: now.year() as i32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cold_restart_time() {
        assert_eq!(parse_cold_restart_time("09:00"), Some((9, 0)));
        assert_eq!(parse_cold_restart_time("13:30"), Some((13, 30)));
        assert_eq!(parse_cold_restart_time("00:00"), Some((0, 0)));
        assert_eq!(parse_cold_restart_time("23:59"), Some((23, 59)));
        assert_eq!(parse_cold_restart_time(""), None);
        assert_eq!(parse_cold_restart_time("invalid"), None);
        assert_eq!(parse_cold_restart_time("25:00"), None);
        assert_eq!(parse_cold_restart_time("12:60"), None);
        assert_eq!(parse_cold_restart_time("9:00"), Some((9, 0)));
        assert_eq!(parse_cold_restart_time("0900"), None);
    }

    #[test]
    fn test_already_fired() {
        let dir = std::env::temp_dir().join("ibctl_test_marker");
        let marker = dir.join("cold_restart_marker");
        let _ = std::fs::create_dir_all(&dir);

        // No marker file — not fired
        let _ = std::fs::remove_file(&marker);
        assert!(!already_fired(&marker, 2026, 88));

        // Write today's marker
        std::fs::write(&marker, "2026-88").unwrap();
        assert!(already_fired(&marker, 2026, 88));

        // Different day — not fired
        assert!(!already_fired(&marker, 2026, 89));

        // Cleanup
        let _ = std::fs::remove_file(&marker);
        let _ = std::fs::remove_dir(&dir);
    }
}
