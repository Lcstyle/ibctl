//! Marker file writers for the state machine.
//!
//! Specifically `write_cold_restart_equivalent_marker` records the
//! wall-clock moment a true cold-restart-equivalent completed: arrival
//! into Connected via a credential-gathering state AFTER a 2FA challenge
//! was answered successfully during this JVM lifecycle (see
//! `State::is_credential_gathering` and `StateMachine::cold_restart_equivalent_pending`).
//!
//! The Sunday cold-restart scheduler consults this marker and SKIPS its
//! scheduled fire if a real cold-restart-equivalent already happened
//! earlier today — including the legitimate case where a HITL demote
//! (cf. `WaitingForHitl2fa` handler) probed the JVM back to
//! WaitingForApiReady and the next login cycle succeeded shortly before
//! 09:00 Sunday. That's not a flap — the operator just 2FA'd recently
//! and shouldn't be dragged through it again.
//!
//! Warm restarts (IBC's daily -Drestart= pattern) do NOT cross
//! WaitingFor2fa or WaitingForHitl2fa, so they never set the
//! cold-restart-equivalent flag and the marker is not written.
//!
//! Marker format is ISO 8601 (`jiff::Zoned::to_string()`), one line, no
//! framing. Parsing lives in `cold_restart::read_cold_restart_equivalent_marker`;
//! unparseable contents are treated as a missing marker (None) — fail-safe
//! toward re-firing.

use std::io;
use std::path::Path;

/// Write the current wall-clock instant to the cold-restart-equivalent
/// marker file.
///
/// The format is ISO 8601 (`jiff::Zoned::to_string()`). Atomic write via
/// temp file + rename so a concurrent reader (the cold-restart scheduler
/// running in another task) cannot observe a torn or empty file mid-write.
/// Callers should log any I/O error and continue — a failed write doesn't
/// break the state machine, it just means the next scheduled cold restart
/// won't be skipped (fail-safe direction).
pub fn write_cold_restart_equivalent_marker(path: &Path) -> io::Result<()> {
    let now = jiff::Zoned::now();
    atomic_write(path, now.to_string().as_bytes())
}

/// Best-effort atomic file write via temp file + rename.
///
/// Same-directory rename is POSIX-atomic and POSIX-durable enough for our
/// purposes (the scheduler reads, parses; an unparseable read is treated as
/// "no marker" and fail-safes toward firing). The temp file lives next to
/// the target so the rename never crosses filesystems.
fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "marker path has no file name"))?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = parent.join(tmp_name);

    {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all().ok(); // best-effort flush; rename is the durability point
    }
    std::fs::rename(&tmp_path, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tempfile::TempDir;

    #[test]
    fn test_write_marker_creates_parseable_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".ibctl-cold-restart-equivalent-today");

        write_cold_restart_equivalent_marker(&path).unwrap();
        let raw = std::fs::read_to_string(&path).expect("file must exist after write");
        let parsed = jiff::Zoned::from_str(raw.trim()).expect("must round-trip ISO 8601");
        assert_eq!(parsed.date(), jiff::Zoned::now().date());
    }

    #[test]
    fn test_write_marker_overwrites_existing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".ibctl-cold-restart-equivalent-today");
        std::fs::write(&path, "stale junk that will be replaced").unwrap();

        write_cold_restart_equivalent_marker(&path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed = jiff::Zoned::from_str(raw.trim()).expect("must parse after overwrite");
        assert_eq!(parsed.date(), jiff::Zoned::now().date());
    }

    #[test]
    fn test_write_marker_leaves_no_orphan_temp_file() {
        // Atomic-write contract: the rename consumes the temp file. After
        // a successful write, only the target marker remains in the dir.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".ibctl-cold-restart-equivalent-today");

        write_cold_restart_equivalent_marker(&path).unwrap();

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "exactly one file expected (no orphan temp), found {:?}",
            entries
        );
    }

    #[test]
    fn test_write_marker_concurrent_reader_never_sees_empty_or_partial() {
        // Torn-read mitigation. With std::fs::write a concurrent reader
        // could see an empty file mid-write. With atomic rename, every
        // observation is either the previous content or the new content —
        // never empty. Drive 50 concurrent reads against 50 sequential
        // writes; assert no read ever returned an unparseable result.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".ibctl-cold-restart-equivalent-today");
        // Seed so the very first read has parseable content.
        write_cold_restart_equivalent_marker(&path).unwrap();

        let path_for_reader = path.clone();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_for_reader = stop.clone();
        let reader = std::thread::spawn(move || {
            let mut bad_reads: usize = 0;
            while !stop_for_reader.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(raw) = std::fs::read_to_string(&path_for_reader) {
                    if jiff::Zoned::from_str(raw.trim()).is_err() {
                        bad_reads += 1;
                    }
                }
            }
            bad_reads
        });

        for _ in 0..50 {
            write_cold_restart_equivalent_marker(&path).unwrap();
        }

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let bad_reads = reader.join().unwrap();
        assert_eq!(
            bad_reads, 0,
            "concurrent reader observed {} unparseable reads — atomic write contract broken",
            bad_reads
        );
    }
}
