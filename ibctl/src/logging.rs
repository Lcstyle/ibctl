//! Configurable log file rotation alongside stdout.
//!
//! Supports two modes:
//! - **Calendar mode** (default): rotates at midnight local time, files named by calendar date.
//! - **Futures session mode**: rotates at the configured session reopen hour (default 6 PM ET),
//!   files named by the trading session date (the date when the session ends).
//!
//! Mode is controlled by `LoggingConfig::futures_session_logging`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use jiff::tz::TimeZone;
use jiff::Zoned;

/// Compute the log date string (YYYY-MM-DD) for the current moment.
///
/// - `futures_session`: if true, use futures market session boundary.
/// - `session_reopen_hour`: hour (0-23, US/Eastern) when the next session starts.
///   Default 18 (6 PM ET). Only used when `futures_session` is true.
///
/// In futures mode, after the reopen hour, the log date is tomorrow (the session's
/// end date). Before the reopen hour, the log date is today.
///
/// In calendar mode, returns today's date in the local timezone.
pub fn log_date(futures_session: bool, session_reopen_hour: u8) -> String {
    if futures_session {
        let tz = TimeZone::get("America/New_York").unwrap_or(TimeZone::UTC);
        let now = Zoned::now().with_time_zone(tz);
        // jiff::Zoned::hour() returns i8; session_reopen_hour is u8 (0-23), safe cast
        let date = if now.hour() >= session_reopen_hour as i8 {
            now.date().tomorrow().unwrap_or(now.date())
        } else {
            now.date()
        };
        date.to_string()
    } else {
        // Calendar mode: local date
        let now = Zoned::now();
        now.date().to_string()
    }
}

/// Shared state for the tee writer (behind a mutex for interior mutability).
struct TeeState {
    log_dir: PathBuf,
    prefix: String,
    current_date: String,
    file: Option<File>,
    futures_session: bool,
    session_reopen_hour: u8,
}

impl TeeState {
    fn maybe_rotate(&mut self) {
        let new_date = log_date(self.futures_session, self.session_reopen_hour);
        if self.current_date != new_date {
            if let Ok(f) = open_log_file(&self.log_dir, &self.prefix, &new_date) {
                self.file = Some(f);
                self.current_date = new_date;
            }
        }
    }
}

/// A writer that tees output to stdout and a rotating log file.
/// Implements `Write + Send` so it can be used with `env_logger::Target::Pipe`.
pub struct TeeWriter {
    state: Mutex<TeeState>,
}

impl TeeWriter {
    /// Create a new TeeWriter. Creates the log directory if needed.
    ///
    /// `prefix` is used in the filename: `{prefix}-{date}.log`.
    /// In dual mode, use "ibctl-live" / "ibctl-paper" to separate log streams.
    pub fn new(
        log_dir: &str,
        prefix: &str,
        futures_session: bool,
        session_reopen_hour: u8,
    ) -> io::Result<Self> {
        let path = Path::new(log_dir);
        fs::create_dir_all(path)?;
        let date = log_date(futures_session, session_reopen_hour);
        let file = open_log_file(path, prefix, &date)?;
        Ok(Self {
            state: Mutex::new(TeeState {
                log_dir: path.to_path_buf(),
                prefix: prefix.to_string(),
                current_date: date,
                file: Some(file),
                futures_session,
                session_reopen_hour,
            }),
        })
    }
}

impl Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Always write to stdout
        let n = io::stdout().write(buf)?;
        // Tee to file if available
        if let Ok(mut state) = self.state.lock() {
            state.maybe_rotate();
            if let Some(ref mut f) = state.file {
                let _ = f.write_all(&buf[..n]);
            }
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()?;
        if let Ok(mut state) = self.state.lock() {
            if let Some(ref mut f) = state.file {
                let _ = f.flush();
            }
        }
        Ok(())
    }
}

fn open_log_file(dir: &Path, prefix: &str, date: &str) -> io::Result<File> {
    let path = dir.join(format!("{prefix}-{date}.log"));
    OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calendar_mode_returns_valid_date() {
        let date = log_date(false, 18);
        assert_eq!(date.len(), 10, "Expected YYYY-MM-DD, got: {}", date);
        assert!(date.contains('-'));
    }

    #[test]
    fn test_futures_mode_returns_valid_date() {
        let date = log_date(true, 18);
        assert_eq!(date.len(), 10, "Expected YYYY-MM-DD, got: {}", date);
        assert!(date.contains('-'));
    }
}
