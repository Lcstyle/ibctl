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
//! Timezone: respects the TZ env var (libc::localtime_r uses system timezone)

use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct ColdRestartSignal;

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

/// Spawn the cold restart timer.
///
/// - Only fires on Sunday at the exact configured minute (not if past)
/// - Tracks startup time to distinguish "started before scheduled time" from
///   "started after scheduled time" (the latter waits for next Sunday)
/// - Persists via marker file in TWS_SETTINGS_PATH (volume-mounted)
pub fn spawn_cold_restart_scheduler(
    cold_restart_time: String,
    tx: mpsc::Sender<ColdRestartSignal>,
) -> Option<tokio::task::JoinHandle<()>> {
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

    let tz = std::env::var("TZ").unwrap_or_else(|_| "(system default)".to_string());
    log::info!(
        "Cold restart timer active: Sundays at {:02}:{:02} (TZ={}, marker={})",
        target_hour, target_minute, tz, marker_path.display()
    );

    // Record the minute we started so we can detect "started after target time"
    let startup_time = get_local_time();

    let handle = tokio::spawn(async move {
        use std::time::Duration;

        // Determine if we started AFTER the target time on a Sunday
        // If so, we must NOT fire — wait for next Sunday
        let started_past_target = if let Some(ref now) = startup_time {
            now.weekday == 0  // Sunday
                && (now.hour > target_hour
                    || (now.hour == target_hour && now.minute > target_minute))
        } else {
            false
        };

        if started_past_target {
            log::info!(
                "Cold restart: started after target time on Sunday — will fire next Sunday at {:02}:{:02}",
                target_hour, target_minute
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

            // Only fire on Sunday
            if now.weekday != 0 {
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
                log::info!(
                    "Cold restart firing now (Sunday {:02}:{:02})",
                    target_hour, target_minute
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
    });

    Some(handle)
}

struct LocalTime {
    weekday: u32,
    hour: u32,
    minute: u32,
    day_of_year: u32,
    year: i32,
}

fn get_local_time() -> Option<LocalTime> {
    unsafe {
        let mut now: libc::time_t = 0;
        libc::time(&mut now);
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return None;
        }
        Some(LocalTime {
            weekday: tm.tm_wday as u32,
            hour: tm.tm_hour as u32,
            minute: tm.tm_min as u32,
            day_of_year: tm.tm_yday as u32,
            year: tm.tm_year + 1900,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cold_restart_time() {
        assert_eq!(parse_cold_restart_time("09:00"), Some((9, 0)));
        assert_eq!(parse_cold_restart_time("13:30"), Some((13, 30)));
        assert_eq!(parse_cold_restart_time(""), None);
        assert_eq!(parse_cold_restart_time("invalid"), None);
        assert_eq!(parse_cold_restart_time("25:00"), None);
    }
}
