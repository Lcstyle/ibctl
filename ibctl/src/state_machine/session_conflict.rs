//! "Existing session detected": the evidence in the dialog, and the loop
//! breaker.
//!
//! A gateway can click "Reconnect This Session" thousands of times in a few
//! hours. Every dialog names the other session — `IP 203.0.113.7 connected at
//! 16:09:26 09/26/2026 GMT.` — and when that IP is the host's own and the
//! time is the moment of ibctl's own previous click, the Gateway is fighting
//! itself. That goes unnoticed unless something reads the text and counts the
//! clicks.
//!
//! Pure: no clock reads, no I/O.

use std::time::Duration;

/// Conflicts within `BREAKER_WINDOW` at which ibctl stops clicking and leaves
/// the dialog for a human. A genuine takeover resolves in one click; a stale
/// server-side session in a handful (seen settling in ~2 min).
pub(super) const BREAKER_THRESHOLD: usize = 5;
pub(super) const BREAKER_WINDOW: Duration = Duration::from_secs(10 * 60);

/// How close after one of our own login actions (credentials submitted, or a
/// "Reconnect This Session" click) the other session's login time must fall
/// to be that action's own session. The dialog shows whole seconds, so the
/// time can read up to 1 s before the action; a submitted login can take
/// ~10 s to register (16:09:06.6 submit → "connected at 16:09:17").
const SELF_BEFORE: Duration = Duration::from_secs(1);
const SELF_AFTER: Duration = Duration::from_secs(15);

/// Who the dialog says holds the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ConflictEvidence {
    pub other_ip: String,
    pub other_connected_at: jiff::Timestamp,
}

/// Parse the dialog's message, e.g.
/// `IP 203.0.113.7 connected at 16:09:26 09/26/2026 GMT.` (sometimes
/// wrapped in HTML). `None` when the text doesn't have that shape.
pub(super) fn parse_evidence(message: &str) -> Option<ConflictEvidence> {
    let after_ip = &message[message.find("IP ")? + 3..];
    let other_ip: String = after_ip
        .chars()
        .take_while(|c| c.is_ascii_hexdigit() || *c == '.' || *c == ':')
        .collect();
    if other_ip.is_empty() {
        return None;
    }
    let after_at = &message[message.find("connected at ")? + "connected at ".len()..];
    let mut parts = after_at.split_whitespace();
    let time = parts.next()?; // HH:MM:SS
    let date = parts.next()?; // MM/DD/YYYY
    let mut t = time.split(':').map(|p| p.parse::<i8>());
    let (h, m, s) = (t.next()?.ok()?, t.next()?.ok()?, t.next()?.ok()?);
    let mut d = date.split('/');
    let month = d.next()?.parse::<i8>().ok()?;
    let day = d.next()?.parse::<i8>().ok()?;
    let year = d.next()?.trim_end_matches(|c: char| !c.is_ascii_digit()).parse::<i16>().ok()?;
    let civil = jiff::civil::date(year, month, day).at(h, m, s, 0);
    let other_connected_at = civil.to_zoned(jiff::tz::TimeZone::UTC).ok()?.timestamp();
    Some(ConflictEvidence { other_ip, other_connected_at })
}

/// Does the other session's login time match one of our own login actions?
/// Then the "other session" is this Gateway's own — it is fighting itself.
pub(super) fn looks_self_inflicted(
    other_connected_at: jiff::Timestamp,
    our_last_login_action: Option<jiff::Timestamp>,
) -> bool {
    let Some(ours) = our_last_login_action else {
        return false;
    };
    let before = jiff::SignedDuration::try_from(SELF_BEFORE).unwrap_or_default();
    let after = jiff::SignedDuration::try_from(SELF_AFTER).unwrap_or_default();
    let delta = other_connected_at.duration_since(ours);
    delta >= -before && delta <= after
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> jiff::Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn reads_ip_and_time_from_the_dialog() {
        let e = parse_evidence("IP 203.0.113.7 connected at 16:09:26 09/26/2026 GMT.").unwrap();
        assert_eq!(e.other_ip, "203.0.113.7");
        assert_eq!(e.other_connected_at, ts("2026-09-26T16:09:26Z"));
    }

    #[test]
    fn reads_it_through_html_and_without_the_trailing_dot() {
        let e = parse_evidence(
            "<html><body>IP 198.51.100.23 connected at 13:00:54 04/19/2026 GMT</body></html>",
        )
        .unwrap();
        assert_eq!(e.other_ip, "198.51.100.23");
        assert_eq!(e.other_connected_at, ts("2026-04-19T13:00:54Z"));
    }

    #[test]
    fn other_shapes_are_not_evidence() {
        assert_eq!(parse_evidence("Existing session detected"), None);
        assert_eq!(parse_evidence("IP  connected at 16:09:26 09/26/2026 GMT"), None);
        assert_eq!(parse_evidence("IP 192.0.2.4 connected at noon"), None);
    }

    #[test]
    fn a_session_from_our_own_last_action_is_self_inflicted() {
        // Click at 16:09:26.641, next dialog "connected at 16:09:26".
        assert!(looks_self_inflicted(ts("2026-09-26T16:09:26Z"), Some(ts("2026-09-26T16:09:26.641Z"))));
        // Submit at 16:09:06.632, first dialog "connected at 16:09:17".
        assert!(looks_self_inflicted(ts("2026-09-26T16:09:17Z"), Some(ts("2026-09-26T16:09:06.632Z"))));
    }

    #[test]
    fn a_session_unrelated_to_our_actions_is_not() {
        // A session from another host, 6 s BEFORE our submit.
        assert!(!looks_self_inflicted(ts("2026-04-19T13:00:54Z"), Some(ts("2026-04-19T13:00:58Z"))));
        assert!(!looks_self_inflicted(ts("2026-09-26T16:09:40Z"), Some(ts("2026-09-26T16:09:06Z"))));
        assert!(!looks_self_inflicted(ts("2026-09-26T16:09:17Z"), None));
    }
}
