//! Host maintenance hold.
//!
//! A host doing its own maintenance near ibctl's scheduled weekly restart
//! makes that one maintenance event with two owners: the host owns packages
//! and Docker, ibctl owns the gateway and its authentication. While the host
//! updates the container runtime, ibctl must not fire its own scheduled
//! restart — the two would race, and the gateway would be restarted twice,
//! each time with a fresh login (for LIVE, an IB Key push to approve).
//!
//! The host's maintenance coordinator sends `MAINT_HOLD <id> <ttl_secs>` to
//! each mode, does its work, then `MAINT_RELEASE <id> <result>`. The hold
//! lives in a file in the mode's settings directory (on the persistent
//! volume), so it survives the container restart it exists to cover. It
//! expires by itself: a coordinator that dies cannot keep the weekly re-auth
//! from ever running.
//!
//! After the hold ends, the scheduler decides on what it observes then —
//! a gateway the maintenance already restarted and re-authenticated is not
//! restarted again.

use std::path::{Path, PathBuf};

/// Longest hold a coordinator may ask for. A runtime update plus the
/// containers coming back takes minutes; an hour is a generous ceiling that
/// still lets the weekly re-auth run soon after if the coordinator dies
/// holding it.
pub const MAX_TTL_SECS: u64 = 3600;

const FILE_NAME: &str = ".ibctl-maintenance-hold";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hold {
    pub id: String,
    pub since: jiff::Timestamp,
    pub expires_at: jiff::Timestamp,
}

impl Hold {
    pub fn new(id: &str, ttl_secs: u64, now: jiff::Timestamp) -> Result<Self, String> {
        if !valid_id(id) {
            return Err(format!(
                "maintenance id '{id}' is not 1-64 characters of [A-Za-z0-9._:-]"
            ));
        }
        if ttl_secs == 0 || ttl_secs > MAX_TTL_SECS {
            return Err(format!("hold TTL {ttl_secs}s is outside 1..={MAX_TTL_SECS}s"));
        }
        let expires_at = now
            .checked_add(jiff::SignedDuration::from_secs(ttl_secs as i64))
            .map_err(|e| e.to_string())?;
        Ok(Self { id: id.to_string(), since: now, expires_at })
    }

    pub fn active_at(&self, now: jiff::Timestamp) -> bool {
        now < self.expires_at
    }
}

pub fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
}

/// The hold file for a mode's settings directory.
pub fn path_in(settings_dir: &Path) -> PathBuf {
    settings_dir.join(FILE_NAME)
}

/// The hold on disk, if there is a readable one. A missing, unreadable or
/// corrupt file is no hold: failing toward the weekly re-auth running is
/// the safe direction (the TTL is the same idea for a dead coordinator).
pub fn read(path: &Path) -> Option<Hold> {
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("Maintenance hold {} is unreadable ({e}) — ignoring it", path.display());
            return None;
        }
    };
    let field = |k: &str| v.get(k).and_then(|x| x.as_str());
    let hold = Hold {
        id: field("id")?.to_string(),
        since: field("since")?.parse().ok()?,
        expires_at: field("expires_at")?.parse().ok()?,
    };
    valid_id(&hold.id).then_some(hold)
}

pub fn write(path: &Path, hold: &Hold) -> std::io::Result<()> {
    let body = serde_json::json!({
        "id": hold.id,
        "since": hold.since.to_string(),
        "expires_at": hold.expires_at.to_string(),
    });
    crate::cold_restart::atomic_write(path, body.to_string().as_bytes())
}

pub fn clear(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> jiff::Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn a_hold_round_trips_through_its_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let p = path_in(dir.path());
        let h = Hold::new("hold-1", 1200, t("2026-10-04T12:58:00Z")).unwrap();
        write(&p, &h).unwrap();
        assert_eq!(read(&p), Some(h));
        clear(&p).unwrap();
        assert_eq!(read(&p), None);
        clear(&p).unwrap();
    }

    #[test]
    fn a_hold_ends_by_itself() {
        let h = Hold::new("m1", 600, t("2026-10-04T12:58:00Z")).unwrap();
        assert!(h.active_at(t("2026-10-04T13:07:59Z")));
        assert!(!h.active_at(t("2026-10-04T13:08:00Z")), "a dead coordinator cannot block Sunday");
    }

    #[test]
    fn bad_ids_and_ttls_are_refused() {
        let now = t("2026-10-04T12:58:00Z");
        for id in ["", "has space", "semi;colon", &"x".repeat(65)] {
            assert!(Hold::new(id, 60, now).is_err(), "{id:?} accepted");
        }
        assert!(Hold::new("m1", 0, now).is_err());
        assert!(Hold::new("m1", MAX_TTL_SECS + 1, now).is_err());
        assert!(Hold::new("m1", MAX_TTL_SECS, now).is_ok());
    }

    #[test]
    fn a_corrupt_hold_file_is_no_hold() {
        let dir = tempfile::TempDir::new().unwrap();
        let p = path_in(dir.path());
        std::fs::write(&p, "{not json").unwrap();
        assert_eq!(read(&p), None);
        std::fs::write(&p, r#"{"id":"bad id","since":"2026-10-04T12:58:00Z","expires_at":"2026-10-04T13:18:00Z"}"#).unwrap();
        assert_eq!(read(&p), None);
    }
}
