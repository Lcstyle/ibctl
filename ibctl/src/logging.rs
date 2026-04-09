//! Market-day-aware file logging alongside stdout.
//!
//! When `log_dir` is configured, writes JSON Lines logs to both stdout (for
//! `docker logs`) and a dated file: `ibctl-{YYYY-MM-DD}.log`. The date follows
//! the CME futures trading day boundary: 6 PM US/Eastern starts the next day's
//! log file. This matches the ibkr-ec logging convention.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use jiff::tz::TimeZone;
use jiff::Zoned;

/// Market day boundary: 6 PM Eastern (18:00).
const MARKET_DAY_START_HOUR: i8 = 18;

/// Compute the market-day date string (YYYY-MM-DD) for the current moment.
///
/// Market day runs 6 PM ET → 5 PM ET next day.
/// Returns the date when the market day *ends* (the trading session date).
pub fn market_day_date() -> String {
    let tz = TimeZone::get("America/New_York").unwrap_or(TimeZone::UTC);
    let now = Zoned::now().with_time_zone(tz);
    let date = if now.hour() >= MARKET_DAY_START_HOUR {
        now.date().tomorrow().unwrap_or(now.date())
    } else {
        now.date()
    };
    date.to_string()
}

/// Shared state for the tee writer (behind a mutex for interior mutability).
struct TeeState {
    log_dir: PathBuf,
    prefix: String,
    current_date: String,
    file: Option<File>,
}

impl TeeState {
    fn maybe_rotate(&mut self) {
        let new_date = market_day_date();
        if self.current_date != new_date {
            if let Ok(f) = open_log_file(&self.log_dir, &self.prefix, &new_date) {
                self.file = Some(f);
                self.current_date = new_date;
            }
        }
    }
}

/// A writer that tees output to stdout and a market-day-rotating log file.
/// Implements `Write + Send` so it can be used with `env_logger::Target::Pipe`.
pub struct TeeWriter {
    state: Mutex<TeeState>,
}

impl TeeWriter {
    /// Create a new TeeWriter. Creates the log directory if needed.
    ///
    /// `prefix` is used in the filename: `{prefix}-{date}.log`.
    /// In dual mode, use "ibctl-live" / "ibctl-paper" to separate log streams.
    /// In single mode, use "ibctl".
    pub fn new(log_dir: &str, prefix: &str) -> io::Result<Self> {
        let path = Path::new(log_dir);
        fs::create_dir_all(path)?;
        let date = market_day_date();
        let file = open_log_file(path, prefix, &date)?;
        Ok(Self {
            state: Mutex::new(TeeState {
                log_dir: path.to_path_buf(),
                prefix: prefix.to_string(),
                current_date: date,
                file: Some(file),
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
    fn test_market_day_date_returns_valid_date() {
        let date = market_day_date();
        assert!(date.len() == 10, "Expected YYYY-MM-DD, got: {}", date);
        assert!(date.contains('-'));
    }
}
