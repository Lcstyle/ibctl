//! Unattended hours: the part of the day nobody answers an IB Key
//! push. A 2FA round that fails in this window parks the login for the
//! operator instead of sending another push. A parked login stays parked
//! until the operator's Retry or the Sunday re-auth: no HITL auto-retry
//! fires inside the window, and none fires because it ended.
//!
//! Wall-clock times in the process's time zone (`TZ`), like the Sunday
//! cold-restart time. `"22:00-08:00"` wraps midnight.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnattendedHours {
    start: jiff::civil::Time,
    end: jiff::civil::Time,
}

impl UnattendedHours {
    /// Parse `"HH:MM-HH:MM"`. Empty or `off` means no unattended hours.
    pub fn parse(s: &str) -> Result<Option<Self>, String> {
        let s = s.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("off") {
            return Ok(None);
        }
        let (a, b) = s
            .split_once('-')
            .ok_or_else(|| format!("'{s}' is not HH:MM-HH:MM"))?;
        let start = parse_hh_mm(a).ok_or_else(|| format!("'{a}' in '{s}' is not HH:MM"))?;
        let end = parse_hh_mm(b).ok_or_else(|| format!("'{b}' in '{s}' is not HH:MM"))?;
        if start == end {
            return Err(format!("'{s}' starts and ends at the same time"));
        }
        Ok(Some(Self { start, end }))
    }

    pub fn contains(&self, t: jiff::civil::Time) -> bool {
        if self.start < self.end {
            self.start <= t && t < self.end
        } else {
            t >= self.start || t < self.end
        }
    }
}

impl fmt::Display for UnattendedHours {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02}:{:02}-{:02}:{:02}",
            self.start.hour(),
            self.start.minute(),
            self.end.hour(),
            self.end.minute()
        )
    }
}

fn parse_hh_mm(s: &str) -> Option<jiff::civil::Time> {
    let (h, m) = s.trim().split_once(':')?;
    if h.len() != 2 || m.len() != 2 {
        return None;
    }
    let (h, m): (i8, i8) = (h.parse().ok()?, m.parse().ok()?);
    jiff::civil::Time::new(h, m, 0, 0).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(h: i8, m: i8) -> jiff::civil::Time {
        jiff::civil::Time::new(h, m, 0, 0).unwrap()
    }

    #[test]
    fn parses_and_prints_the_window() {
        let w = UnattendedHours::parse("22:00-08:00").unwrap().unwrap();
        assert_eq!(w.to_string(), "22:00-08:00");
        assert_eq!(UnattendedHours::parse("  ").unwrap(), None, "empty: no unattended hours");
        assert_eq!(UnattendedHours::parse("off").unwrap(), None);
    }

    #[test]
    fn rejects_what_is_not_a_window() {
        for bad in ["22:00", "22-08", "24:00-08:00", "22:00-08:60", "8:00-9:00", "09:00-09:00"] {
            assert!(UnattendedHours::parse(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn a_window_across_midnight_contains_both_ends_of_the_night() {
        let w = UnattendedHours::parse("22:00-08:00").unwrap().unwrap();
        assert!(w.contains(t(22, 0)));
        assert!(w.contains(t(3, 10)), "the Sunday 03:10 re-auth is unattended");
        assert!(!w.contains(t(8, 0)));
        assert!(!w.contains(t(9, 0)), "the Sunday 09:00 fire is attended");
        assert!(!w.contains(t(21, 59)));
    }

    #[test]
    fn a_daytime_window_is_contained_in_the_day() {
        let w = UnattendedHours::parse("01:00-05:00").unwrap().unwrap();
        assert!(w.contains(t(1, 0)) && w.contains(t(4, 59)));
        assert!(!w.contains(t(5, 0)) && !w.contains(t(0, 59)));
    }
}
