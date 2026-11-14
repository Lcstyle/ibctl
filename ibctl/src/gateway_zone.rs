//! The Gateway's session time zone.
//!
//! IB Gateway decides which time zone its session runs in from the
//! `[Logon] TimeZone` line of the `jts.ini` in its settings directory: the
//! login window preselects that zone, and the session follows it. It does not
//! look at the container's `TZ`, which only sets the clock zone of the container
//! and the JVM. A Gateway whose `jts.ini` was created without a usable zone
//! falls back to the first entry of the login window's list, `Africa/Abidjan`
//! (UTC+0), and saves that.
//!
//! This module owns three things:
//!
//! - reading and writing that line, keeping the file's line endings, so the
//!   zone a user declares is the zone the Gateway starts with;
//! - working out which zone a session actually runs in, for reporting;
//! - turning the configured daily restart time, written in the container's
//!   zone, into the clock time the Gateway's own zone needs. The Gateway stores
//!   a bare time of day, so the conversion has to be redone at every login: a
//!   value converted once goes wrong at the next daylight-saving change.

use std::io;
use std::path::Path;

use jiff::tz::TimeZone;
use jiff::Timestamp;

/// The zone a Gateway uses when nothing declares one.
pub const DEFAULT_GATEWAY_ZONE: &str = "UTC";

/// What [`enforce_time_zone`] found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enforced {
    /// There was no `jts.ini`; one holding only the zone was written.
    Created,
    /// The line held another value (or none) and was rewritten.
    Changed { from: Option<String> },
    /// The line already held the zone; the file was left untouched.
    AlreadySet,
}

fn line_body(line: &str) -> &str {
    line.trim_end_matches(['\r', '\n'])
}

fn line_ending(line: &str) -> &str {
    &line[line_body(line).len()..]
}

/// The section name of an INI header line (`[Logon]` gives `Logon`).
fn section_of(line: &str) -> Option<&str> {
    let body = line_body(line).trim();
    body.strip_prefix('[')?.strip_suffix(']')
}

/// `Some(value)` when `line` is a `TimeZone=` entry.
fn time_zone_value(line: &str) -> Option<&str> {
    let (key, value) = line_body(line).split_once('=')?;
    (key.trim() == "TimeZone").then(|| value.trim())
}

/// The `[Logon] TimeZone` value in a `jts.ini`, if it has one.
pub fn read_logon_time_zone(content: &str) -> Option<String> {
    let mut in_logon = false;
    for line in content.split_inclusive('\n') {
        if let Some(section) = section_of(line) {
            in_logon = section == "Logon";
        } else if in_logon {
            if let Some(value) = time_zone_value(line) {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// `content` with its `[Logon] TimeZone` line set to `zone`. Everything else,
/// including each line's own ending (the Gateway writes `\r\n`), is kept as is.
/// A missing line, or a missing section, is added.
pub fn set_logon_time_zone(content: &str, zone: &str) -> String {
    let eol = content
        .split_inclusive('\n')
        .map(line_ending)
        .find(|e| !e.is_empty())
        .unwrap_or("\n");
    let mut out = String::with_capacity(content.len() + zone.len() + 24);
    let mut in_logon = false;
    let mut saw_logon = false;
    let mut wrote = false;

    for line in content.split_inclusive('\n') {
        if let Some(section) = section_of(line) {
            if in_logon && !wrote {
                // Leaving [Logon] without a TimeZone line: add one at its end.
                out.push_str(&format!("TimeZone={zone}{eol}"));
                wrote = true;
            }
            in_logon = section == "Logon";
            saw_logon |= in_logon;
            out.push_str(line);
            if in_logon && line_ending(line).is_empty() {
                out.push_str(eol); // a header on the file's last line, no newline yet
            }
        } else if in_logon && time_zone_value(line).is_some() {
            out.push_str(&format!("TimeZone={zone}{}", line_ending(line)));
            wrote = true;
        } else {
            out.push_str(line);
        }
    }
    if in_logon && !wrote {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push_str(eol);
        }
        out.push_str(&format!("TimeZone={zone}{eol}"));
    } else if !saw_logon {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push_str(eol);
        }
        out.push_str(&format!("[Logon]{eol}TimeZone={zone}{eol}"));
    }
    out
}

/// Make the `[Logon] TimeZone` line of the `jts.ini` at `path` say `zone`.
///
/// Only that line changes, and the file is rewritten only when the value
/// differs, so an unchanged file keeps its modification time. The write goes to
/// a temporary file next to the target and is renamed over it, so a reader never
/// sees a half-written file.
pub fn enforce_time_zone(path: &Path, zone: &str) -> io::Result<Enforced> {
    let existing = match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let (outcome, updated) = match &existing {
        None => (Enforced::Created, set_logon_time_zone("", zone)),
        Some(text) => {
            let current = read_logon_time_zone(text);
            if current.as_deref() == Some(zone) {
                return Ok(Enforced::AlreadySet);
            }
            (Enforced::Changed { from: current }, set_logon_time_zone(text, zone))
        }
    };

    let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let temp = path.with_file_name(format!(".{file_name}.ibctl-tmp"));
    std::fs::write(&temp, updated)?;
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&temp, meta.permissions());
    }
    if let Err(e) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }
    Ok(outcome)
}

/// Apply the declared zone to `<settings_dir>/jts.ini` before a launch.
///
/// `declared` empty means "leave the file alone" (nothing is read or written).
/// An unknown name is refused, since the Gateway treats an unusable zone as no
/// zone at all. The caller logs the result and launches regardless: a Gateway
/// on the wrong zone is better than none.
pub fn prepare_launch(settings_dir: &Path, declared: &str) -> Result<Option<Enforced>, String> {
    if declared.is_empty() {
        return Ok(None);
    }
    if !is_known_zone(declared) {
        return Err(format!("{declared:?} is not a time zone this system knows; jts.ini left as it is"));
    }
    enforce_time_zone(&settings_dir.join("jts.ini"), declared)
        .map(Some)
        .map_err(|e| format!("cannot write the time zone into {}: {e}", settings_dir.join("jts.ini").display()))
}

/// Whether `name` is a time zone this system knows. Only a known name is ever
/// written into a `jts.ini`: the Gateway treats an unusable one as no zone at all.
pub fn is_known_zone(name: &str) -> bool {
    !name.is_empty() && TimeZone::get(name).is_ok()
}

/// The zone name a session runs in: what the `jts.ini` holds (the Gateway
/// rewrites it at login, so after a login it is the truth), else the declared
/// zone, else [`DEFAULT_GATEWAY_ZONE`].
pub fn effective_zone_name(declared: Option<&str>, jts_ini: Option<&str>) -> String {
    jts_ini
        .and_then(read_logon_time_zone)
        .filter(|z| !z.is_empty())
        .or_else(|| declared.filter(|z| !z.is_empty()).map(str::to_string))
        .unwrap_or_else(|| DEFAULT_GATEWAY_ZONE.to_string())
}

/// What ibctl knows about the zone of a session, for STATUS.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ZoneReport {
    /// The zone ibctl was told to enforce, if any.
    pub declared: Option<String>,
    /// What the `jts.ini` held when this was taken (after a login, the session's own zone).
    pub in_jts_ini: Option<String>,
    /// The zone times are converted into.
    pub effective: String,
    /// Whether the file agrees with the declaration; `None` when nothing is declared.
    pub matches_declared: Option<bool>,
}

/// Build the report from the declared zone and the `jts.ini`'s text.
pub fn zone_report(declared: &str, jts_ini: Option<&str>) -> ZoneReport {
    let declared_opt = (!declared.is_empty()).then(|| declared.to_string());
    let in_jts_ini = jts_ini.and_then(read_logon_time_zone);
    ZoneReport {
        matches_declared: declared_opt.as_ref().map(|d| in_jts_ini.as_ref() == Some(d)),
        effective: effective_zone_name(declared_opt.as_deref(), jts_ini),
        declared: declared_opt,
        in_jts_ini,
    }
}

/// The restart time to type into a Gateway whose session runs in `effective`,
/// from `configured` in the container's own zone `local`.
pub fn restart_time_to_type(
    configured: &str,
    effective: &str,
    local: &TimeZone,
    now: Timestamp,
) -> Result<String, String> {
    let gateway = TimeZone::get(effective).map_err(|e| format!("the Gateway's zone {effective:?} is not known: {e}"))?;
    restart_time_for_gateway(configured, local, &gateway, now)
}

/// Parse `5:05 PM` or `05:05 pm` into a 24-hour (hour, minute).
fn parse_clock_time(input: &str) -> Result<(i8, i8), String> {
    let bad = || format!("expected a time like \"5:05 PM\", got {input:?}");
    let mut parts = input.split_whitespace();
    let (clock, suffix) = match (parts.next(), parts.next(), parts.next()) {
        (Some(clock), Some(suffix), None) => (clock, suffix),
        _ => return Err(bad()),
    };
    let (hour, minute) = clock.split_once(':').ok_or_else(bad)?;
    let hour: i8 = hour.parse().map_err(|_| bad())?;
    let minute: i8 = minute.parse().map_err(|_| bad())?;
    if !(1..=12).contains(&hour) || !(0..=59).contains(&minute) {
        return Err(bad());
    }
    let pm = match suffix.to_ascii_uppercase().as_str() {
        "AM" => false,
        "PM" => true,
        _ => return Err(bad()),
    };
    Ok((hour % 12 + if pm { 12 } else { 0 }, minute))
}

/// The clock time to type into a Gateway that runs in `gateway`, so that it
/// restarts at the next moment the clock in `local` reads `configured`.
///
/// The next occurrence is the one converted, not today's: a login on the day
/// before a daylight-saving change must already use the offset in force when the
/// restart happens. Returns `h:mm AM|PM`, the form the Gateway's field takes.
pub fn restart_time_for_gateway(
    configured: &str,
    local: &TimeZone,
    gateway: &TimeZone,
    now: Timestamp,
) -> Result<String, String> {
    let (hour, minute) = parse_clock_time(configured)?;
    let today = now.to_zoned(local.clone()).date();
    let mut occurrence = today
        .at(hour, minute, 0, 0)
        .to_zoned(local.clone())
        .map_err(|e| format!("{configured:?} on {today} in the container's zone: {e}"))?;
    if occurrence.timestamp() <= now {
        let tomorrow = today.tomorrow().map_err(|e| e.to_string())?;
        occurrence = tomorrow
            .at(hour, minute, 0, 0)
            .to_zoned(local.clone())
            .map_err(|e| format!("{configured:?} on {tomorrow} in the container's zone: {e}"))?;
    }
    let there = occurrence.with_time_zone(gateway.clone());
    Ok(format_clock_time(there.hour(), there.minute()))
}

/// `h:mm AM|PM` for a 24-hour clock reading.
fn format_clock_time(hour24: i8, minute: i8) -> String {
    let suffix = if hour24 >= 12 { "PM" } else { "AM" };
    let hour12 = match hour24 % 12 {
        0 => 12,
        h => h,
    };
    format!("{hour12}:{minute:02} {suffix}")
}

/// Whether `input` is a restart time the Gateway's field takes: `h:mm AM|PM`.
pub fn is_restart_time(input: &str) -> bool {
    parse_clock_time(input).is_ok()
}

/// The clock time that makes the Gateway restart itself as soon as it can, in
/// the Gateway's own zone: the start of the next minute, or of the minute after
/// that when fewer than two seconds of this one remain (the field takes whole
/// minutes and the Gateway needs a moment to notice the change). This is how
/// IBC implements its `RESTART` for a Gateway.
pub fn next_restart_minute(now: Timestamp, gateway: &TimeZone) -> String {
    let here = now.to_zoned(gateway.clone());
    let minutes_ahead: i64 = if here.second() < 58 { 1 } else { 2 };
    let target = here.timestamp() + jiff::SignedDuration::from_mins(minutes_ahead);
    let there = target.to_zoned(gateway.clone());
    format_clock_time(there.hour(), there.minute())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GATEWAY_FILE: &str = "[IBGateway]\r\nWriteDebug=false\r\nTrustedIPs=127.0.0.1\r\n\r\n[Logon]\r\nLocale=en\r\nTimeZone=Africa/Abidjan\r\ndisplayedproxymsg=1\r\n\r\n[Communication]\r\nPort=4002\r\n";

    // ── reading and writing the line ────────────────────────────────────

    #[test]
    fn the_logon_zone_is_read() {
        assert_eq!(read_logon_time_zone(GATEWAY_FILE).as_deref(), Some("Africa/Abidjan"));
    }

    #[test]
    fn a_time_zone_line_in_another_section_is_not_the_logon_zone() {
        let text = "[Other]\nTimeZone=Asia/Tokyo\n[Logon]\nLocale=en\n";
        assert_eq!(read_logon_time_zone(text), None);
    }

    #[test]
    fn setting_the_zone_changes_that_line_and_keeps_every_line_ending() {
        let updated = set_logon_time_zone(GATEWAY_FILE, "America/New_York");

        let expected = GATEWAY_FILE.replace("TimeZone=Africa/Abidjan", "TimeZone=America/New_York");
        assert_eq!(updated, expected);
        assert!(updated.contains("TimeZone=America/New_York\r\n"));
    }

    #[test]
    fn a_zone_with_a_slash_is_written_literally() {
        // The value's own '/' must not act as a separator.
        let updated = set_logon_time_zone("[Logon]\nTimeZone=UTC\n", "America/Argentina/Buenos_Aires");
        assert_eq!(updated, "[Logon]\nTimeZone=America/Argentina/Buenos_Aires\n");
    }

    #[test]
    fn a_missing_line_is_added_at_the_end_of_the_logon_section() {
        let text = "[IBGateway]\nApiOnly=true\n[Logon]\nLocale=en\n[Communication]\nPort=1\n";

        let updated = set_logon_time_zone(text, "UTC");

        assert_eq!(updated, "[IBGateway]\nApiOnly=true\n[Logon]\nLocale=en\nTimeZone=UTC\n[Communication]\nPort=1\n");
    }

    #[test]
    fn a_logon_section_at_the_end_of_a_file_without_a_final_newline_gets_the_line() {
        assert_eq!(set_logon_time_zone("[Logon]\r\nLocale=en", "UTC"), "[Logon]\r\nLocale=en\r\nTimeZone=UTC\r\n");
        assert_eq!(set_logon_time_zone("[Logon]", "UTC"), "[Logon]\nTimeZone=UTC\n");
    }

    #[test]
    fn a_missing_section_is_added_in_the_files_own_line_ending() {
        let updated = set_logon_time_zone("[IBGateway]\r\nApiOnly=true\r\n", "UTC");
        assert_eq!(updated, "[IBGateway]\r\nApiOnly=true\r\n[Logon]\r\nTimeZone=UTC\r\n");
    }

    #[test]
    fn an_empty_file_becomes_just_the_zone() {
        assert_eq!(set_logon_time_zone("", "UTC"), "[Logon]\nTimeZone=UTC\n");
    }

    #[test]
    fn setting_the_zone_twice_changes_nothing_the_second_time() {
        let once = set_logon_time_zone(GATEWAY_FILE, "America/New_York");
        assert_eq!(set_logon_time_zone(&once, "America/New_York"), once);
    }

    // ── enforce_time_zone ───────────────────────────────────────────────

    #[test]
    fn enforcing_rewrites_a_different_zone_and_reports_what_it_replaced() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("jts.ini");
        std::fs::write(&path, GATEWAY_FILE).unwrap();

        let outcome = enforce_time_zone(&path, "America/New_York").unwrap();

        assert_eq!(outcome, Enforced::Changed { from: Some("Africa/Abidjan".to_string()) });
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            GATEWAY_FILE.replace("Africa/Abidjan", "America/New_York")
        );
        assert!(!dir.path().join(".jts.ini.ibctl-tmp").exists(), "no temporary file is left behind");
    }

    #[test]
    fn enforcing_a_zone_already_set_leaves_the_file_untouched() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("jts.ini");
        std::fs::write(&path, GATEWAY_FILE).unwrap();
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));

        let outcome = enforce_time_zone(&path, "Africa/Abidjan").unwrap();

        assert_eq!(outcome, Enforced::AlreadySet);
        assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), before);
    }

    #[test]
    fn enforcing_creates_a_missing_file_and_keeps_the_mode_of_an_existing_one() {
        let dir = tempfile::TempDir::new().unwrap();
        let created = dir.path().join("new.ini");
        assert_eq!(enforce_time_zone(&created, "UTC").unwrap(), Enforced::Created);
        assert_eq!(std::fs::read_to_string(&created).unwrap(), "[Logon]\nTimeZone=UTC\n");

        let existing = dir.path().join("jts.ini");
        std::fs::write(&existing, GATEWAY_FILE).unwrap();
        std::fs::set_permissions(&existing, std::os::unix::fs::PermissionsExt::from_mode(0o640)).unwrap();
        enforce_time_zone(&existing, "UTC").unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&existing).unwrap().permissions());
        assert_eq!(mode & 0o777, 0o640);
    }

    #[test]
    fn only_a_zone_the_system_knows_is_known() {
        assert!(is_known_zone("America/New_York"));
        assert!(is_known_zone("UTC"));
        assert!(!is_known_zone(""));
        assert!(!is_known_zone("America/Nowhere"));
        assert!(!is_known_zone("${TIME_ZONE:-America/New_York}"));
    }

    #[test]
    fn preparing_a_launch_with_no_declared_zone_touches_nothing() {
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(prepare_launch(dir.path(), ""), Ok(None));
        assert!(!dir.path().join("jts.ini").exists());
    }

    #[test]
    fn preparing_a_launch_refuses_an_unknown_zone_and_leaves_the_file_alone() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("jts.ini"), GATEWAY_FILE).unwrap();

        let err = prepare_launch(dir.path(), "America/Nowhere").unwrap_err();

        assert!(err.contains("America/Nowhere"), "{err}");
        assert_eq!(std::fs::read_to_string(dir.path().join("jts.ini")).unwrap(), GATEWAY_FILE);
    }

    #[test]
    fn preparing_a_launch_writes_a_known_zone() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("jts.ini"), GATEWAY_FILE).unwrap();

        let outcome = prepare_launch(dir.path(), "America/New_York").unwrap();

        assert_eq!(outcome, Some(Enforced::Changed { from: Some("Africa/Abidjan".into()) }));
        assert_eq!(read_logon_time_zone(&std::fs::read_to_string(dir.path().join("jts.ini")).unwrap()).as_deref(), Some("America/New_York"));
    }

    // ── effective_zone_name ─────────────────────────────────────────────

    #[test]
    fn the_file_is_the_zone_then_the_declaration_then_utc() {
        // After a login the file is what the session runs in, whatever was declared.
        assert_eq!(effective_zone_name(Some("America/New_York"), Some(GATEWAY_FILE)), "Africa/Abidjan");
        assert_eq!(effective_zone_name(None, Some(GATEWAY_FILE)), "Africa/Abidjan");
        assert_eq!(effective_zone_name(Some("America/New_York"), None), "America/New_York");
        assert_eq!(effective_zone_name(Some("America/New_York"), Some("[Logon]\nLocale=en\n")), "America/New_York");
        assert_eq!(effective_zone_name(Some(""), None), "UTC");
        assert_eq!(effective_zone_name(None, None), "UTC");
    }

    #[test]
    fn the_report_says_whether_the_file_agrees_with_the_declaration() {
        let ny = "[Logon]\nTimeZone=America/New_York\n";

        let agree = zone_report("America/New_York", Some(ny));
        assert_eq!(agree.matches_declared, Some(true));
        assert_eq!(agree.effective, "America/New_York");

        let differ = zone_report("America/New_York", Some(GATEWAY_FILE));
        assert_eq!(differ.matches_declared, Some(false));
        assert_eq!(differ.in_jts_ini.as_deref(), Some("Africa/Abidjan"));
        assert_eq!(differ.effective, "Africa/Abidjan");

        let undeclared = zone_report("", Some(GATEWAY_FILE));
        assert_eq!(undeclared.declared, None);
        assert_eq!(undeclared.matches_declared, None);

        let no_file = zone_report("America/New_York", None);
        assert_eq!(no_file.matches_declared, Some(false));
        assert_eq!(no_file.effective, "America/New_York");
    }

    #[test]
    fn the_restart_time_to_type_follows_the_zone_the_session_runs_in() {
        let ny = tz("America/New_York");
        let now = at("2026-11-13T10:00:00Z");
        assert_eq!(restart_time_to_type("5:05 PM", "Africa/Abidjan", &ny, now).unwrap(), "10:05 PM");
        assert_eq!(restart_time_to_type("5:05 PM", "America/New_York", &ny, now).unwrap(), "5:05 PM");
        assert!(restart_time_to_type("5:05 PM", "Nowhere/Land", &ny, now).unwrap_err().contains("Nowhere/Land"));
    }

    // ── restart_time_for_gateway ────────────────────────────────────────

    fn tz(name: &str) -> TimeZone {
        TimeZone::get(name).unwrap()
    }

    fn at(rfc3339: &str) -> Timestamp {
        rfc3339.parse().unwrap()
    }

    fn convert(configured: &str, local: &str, gateway: &str, now: &str) -> Result<String, String> {
        restart_time_for_gateway(configured, &tz(local), &tz(gateway), at(now))
    }

    #[test]
    fn a_local_evening_time_is_converted_to_a_utc_gateway_in_winter() {
        // 17:05 in New York is 22:05 UTC in standard time.
        assert_eq!(convert("5:05 PM", "America/New_York", "UTC", "2026-11-13T10:00:00Z").unwrap(), "10:05 PM");
        assert_eq!(convert("05:05 PM", "America/New_York", "UTC", "2026-11-13T10:00:00Z").unwrap(), "10:05 PM");
    }

    #[test]
    fn a_time_that_has_passed_today_is_converted_for_tomorrow() {
        // 22:06 UTC is 17:06 New York: today's 17:05 is gone, so the restart is tomorrow's.
        assert_eq!(convert("5:05 PM", "America/New_York", "UTC", "2026-11-13T22:06:00Z").unwrap(), "10:05 PM");
    }

    #[test]
    fn the_day_before_a_spring_forward_already_uses_the_summer_offset() {
        // Saturday 2027-03-13 17:06 EST has passed 17:05; the next 17:05 is Sunday's, in EDT
        // (UTC-4), which is 21:05 UTC, not the 22:05 UTC today's offset would give.
        assert_eq!(convert("5:05 PM", "America/New_York", "UTC", "2027-03-13T22:06:00Z").unwrap(), "9:05 PM");
    }

    #[test]
    fn the_day_before_a_fall_back_already_uses_the_winter_offset() {
        // Saturday 2026-10-31 17:06 EDT has passed 17:05; Sunday's 17:05 is in EST: 22:05 UTC.
        assert_eq!(convert("5:05 PM", "America/New_York", "UTC", "2026-10-31T21:06:00Z").unwrap(), "10:05 PM");
    }

    #[test]
    fn a_gateway_in_the_same_zone_needs_no_conversion() {
        assert_eq!(convert("5:05 PM", "America/New_York", "America/New_York", "2026-11-13T10:00:00Z").unwrap(), "5:05 PM");
        assert_eq!(convert("5:05 PM", "America/New_York", "America/New_York", "2027-03-13T22:06:00Z").unwrap(), "5:05 PM");
    }

    #[test]
    fn a_utc_container_with_a_new_york_gateway_converts_the_other_way() {
        assert_eq!(convert("10:05 PM", "UTC", "America/New_York", "2026-11-13T10:00:00Z").unwrap(), "5:05 PM");
    }

    #[test]
    fn midnight_and_noon_use_twelve() {
        assert_eq!(convert("12:00 AM", "UTC", "UTC", "2026-11-13T10:00:00Z").unwrap(), "12:00 AM");
        assert_eq!(convert("12:30 PM", "UTC", "UTC", "2026-11-13T10:00:00Z").unwrap(), "12:30 PM");
        assert_eq!(convert("11:59 PM", "UTC", "UTC", "2026-11-13T10:00:00Z").unwrap(), "11:59 PM");
    }

    #[test]
    fn the_next_restart_minute_is_the_next_whole_minute_or_the_one_after_near_its_end() {
        let utc = tz("UTC");
        assert_eq!(next_restart_minute(at("2026-11-13T10:00:30Z"), &utc), "10:01 AM");
        assert_eq!(next_restart_minute(at("2026-11-13T10:00:00Z"), &utc), "10:01 AM");
        assert_eq!(next_restart_minute(at("2026-11-13T10:00:57Z"), &utc), "10:01 AM");
        assert_eq!(next_restart_minute(at("2026-11-13T10:00:58Z"), &utc), "10:02 AM");
        assert_eq!(next_restart_minute(at("2026-11-13T10:00:59Z"), &utc), "10:02 AM");
    }

    #[test]
    fn the_next_restart_minute_rolls_over_noon_and_midnight_and_follows_the_gateway_zone() {
        let utc = tz("UTC");
        assert_eq!(next_restart_minute(at("2026-11-13T11:59:30Z"), &utc), "12:00 PM");
        assert_eq!(next_restart_minute(at("2026-11-13T23:59:30Z"), &utc), "12:00 AM");
        assert_eq!(next_restart_minute(at("2026-11-13T23:59:59Z"), &utc), "12:01 AM");
        // 22:00 UTC is 17:00 in New York in November.
        assert_eq!(next_restart_minute(at("2026-11-13T22:00:10Z"), &tz("America/New_York")), "5:01 PM");
    }

    #[test]
    fn a_restart_time_is_valid_only_in_the_gateways_h_mm_am_pm_form() {
        assert!(is_restart_time("5:05 PM"));
        assert!(is_restart_time("05:05 pm"));
        assert!(!is_restart_time("17:05"));
        assert!(!is_restart_time(""));
    }

    #[test]
    fn a_time_that_is_not_hh_mm_am_pm_is_an_error() {
        for bad in ["", "17:05", "5:05", "5:05 XM", "13:05 PM", "0:30 AM", "5:75 PM", "5 PM", "5:05 PM extra"] {
            assert!(convert(bad, "UTC", "UTC", "2026-11-13T10:00:00Z").is_err(), "{bad:?} should be rejected");
        }
    }
}
