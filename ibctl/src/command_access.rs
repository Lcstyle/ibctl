//! Which TCP commands ibctl accepts: `command_server.allowed_commands`.
//!
//! One list, shared by LIVE and PAPER, that sits above every caller: TCP
//! clients, the dashboard's buttons and anything the dashboard fronts for
//! token holders. A command that is not in the list is refused and logged.
//! Queries (`STATUS`, `STATE`, `CONFIG`, `LOGS`, `WINDOWS`, `SUBSCRIBE`) only
//! read, so they are always allowed. The localhost-only rule for privileged
//! commands still applies on top of this list.

use crate::types::Command;

/// Every action command ibctl's TCP server accepts, by wire name. The default
/// for `allowed_commands`.
pub const ACTION_COMMANDS: &[&str] = &[
    "STOP",
    "START",
    "RESTART",
    "RECONNECTDATA",
    "RECONNECTACCOUNT",
    "ENABLEAPI",
    "EXIT",
    "RESTARTSOCAT",
    "PAUSE",
    "RESUME",
    "HITL_RESUME",
    "RESUME_RECONNECT",
    "MAINT_HOLD",
    "MAINT_RELEASE",
    "SETSTATE",
    "IBSTATUS",
    "SETRESTART",
];

/// The wire name of an action command. The match has no wildcard on purpose:
/// a new command can't be added without deciding what it is called here, and
/// so what the allow-list calls it.
#[must_use]
pub fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Stop => "STOP",
        Command::Start => "START",
        Command::Restart => "RESTART",
        Command::ReconnectData => "RECONNECTDATA",
        Command::ReconnectAccount => "RECONNECTACCOUNT",
        Command::EnableApi => "ENABLEAPI",
        Command::Exit => "EXIT",
        Command::RestartSocat => "RESTARTSOCAT",
        Command::Pause | Command::PauseAt(_) => "PAUSE",
        Command::Resume => "RESUME",
        Command::HitlResume => "HITL_RESUME",
        Command::ResumeReconnect(_) => "RESUME_RECONNECT",
        Command::MaintHold { .. } => "MAINT_HOLD",
        Command::MaintRelease { .. } => "MAINT_RELEASE",
        Command::SetState(_) => "SETSTATE",
        Command::IbStatus(..) => "IBSTATUS",
        Command::SetRestartTime(_) | Command::SetRestartNow => "SETRESTART",
    }
}

/// The default list: every command accepted today.
#[must_use]
pub fn default_allowed() -> Vec<String> {
    ACTION_COMMANDS.iter().map(|name| (*name).to_string()).collect()
}

/// Names as they are compared: trimmed, upper-cased, no empties, no repeats,
/// in the order given.
#[must_use]
pub fn normalize(names: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in names {
        let name = name.trim().to_uppercase();
        if !name.is_empty() && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// Names in `names` that are not an ibctl action command, for a startup
/// warning. A typo here would otherwise block a command with no explanation.
#[must_use]
pub fn unknown_names(names: &[String]) -> Vec<String> {
    normalize(names).into_iter().filter(|name| !ACTION_COMMANDS.contains(&name.as_str())).collect()
}

/// The effective allow-list.
#[derive(Debug, Clone)]
pub struct CommandAccess {
    allowed: Vec<String>,
}

impl CommandAccess {
    /// An empty list means the default (every command), so a blank setting
    /// can't lock the server out of everything by accident.
    #[must_use]
    pub fn new(configured: &[String]) -> Self {
        let allowed = normalize(configured);
        Self { allowed: if allowed.is_empty() { default_allowed() } else { allowed } }
    }

    #[must_use]
    pub fn allows(&self, command: &Command) -> bool {
        self.allowed.iter().any(|name| name == command_name(command))
    }

    #[must_use]
    pub fn allowed(&self) -> &[String] {
        &self.allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_command() -> Vec<Command> {
        vec![
            Command::Stop,
            Command::Start,
            Command::Restart,
            Command::ReconnectData,
            Command::ReconnectAccount,
            Command::EnableApi,
            Command::Exit,
            Command::RestartSocat,
            Command::Pause,
            Command::PauseAt("WaitingForLogin".into()),
            Command::Resume,
            Command::SetState("Connected".into()),
            Command::IbStatus("available".into(), String::new()),
            Command::SetRestartTime("5:05 PM".into()),
            Command::SetRestartNow,
            Command::HitlResume,
            Command::ResumeReconnect("token".into()),
            Command::MaintHold { id: "x".into(), ttl_secs: 60 },
            Command::MaintRelease { id: "x".into(), result: "ok".into() },
        ]
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn every_command_has_a_name_in_the_action_list() {
        for command in every_command() {
            assert!(ACTION_COMMANDS.contains(&command_name(&command)), "{command:?}");
        }
    }

    #[test]
    fn every_name_in_the_action_list_belongs_to_a_command() {
        let used: Vec<&str> = every_command().iter().map(command_name).collect();
        for name in ACTION_COMMANDS {
            assert!(used.contains(name), "{name} names no command");
        }
    }

    #[test]
    fn the_wire_parser_and_the_names_agree() {
        // The name a command goes by in the allow-list is the word a client types.
        for (line, name) in [
            ("STOP", "STOP"),
            ("pause", "PAUSE"),
            ("PAUSE WaitingForLogin", "PAUSE"),
            ("SETRESTART", "SETRESTART"),
            ("SETRESTART 5:05 PM", "SETRESTART"),
            ("RESUME_RECONNECT abc", "RESUME_RECONNECT"),
            ("MAINT_HOLD id 60", "MAINT_HOLD"),
            ("IBSTATUS available", "IBSTATUS"),
        ] {
            let Some(crate::command_server::ParsedCommand::Action(command)) = crate::command_server::parse_command(line)
            else {
                panic!("{line} should parse to an action");
            };
            assert_eq!(command_name(&command), name, "{line}");
        }
    }

    #[test]
    fn the_default_list_allows_every_command() {
        let access = CommandAccess::new(&default_allowed());
        for command in every_command() {
            assert!(access.allows(&command), "{command:?}");
        }
    }

    #[test]
    fn a_command_outside_the_list_is_refused() {
        let access = CommandAccess::new(&names(&["SETRESTART", "RECONNECTDATA"]));

        assert!(access.allows(&Command::SetRestartNow));
        assert!(access.allows(&Command::SetRestartTime("5:05 PM".into())));
        assert!(access.allows(&Command::ReconnectData));
        assert!(!access.allows(&Command::Stop));
        assert!(!access.allows(&Command::Restart));
        assert!(!access.allows(&Command::Exit));
        assert!(!access.allows(&Command::Pause));
        assert!(!access.allows(&Command::PauseAt("X".into())));
    }

    #[test]
    fn one_name_covers_every_form_of_its_command() {
        let access = CommandAccess::new(&names(&["PAUSE"]));
        assert!(access.allows(&Command::Pause));
        assert!(access.allows(&Command::PauseAt("Connected".into())));
        assert!(!access.allows(&Command::SetRestartNow));
    }

    #[test]
    fn names_match_without_regard_to_case_or_padding() {
        let access = CommandAccess::new(&names(&["  stop ", "Start"]));
        assert!(access.allows(&Command::Stop));
        assert!(access.allows(&Command::Start));
        assert_eq!(access.allowed(), ["STOP", "START"]);
    }

    #[test]
    fn a_blank_list_means_the_default_not_nothing() {
        for configured in [names(&[]), names(&[""]), names(&["  ", ""])] {
            let access = CommandAccess::new(&configured);
            assert_eq!(access.allowed().len(), ACTION_COMMANDS.len());
            assert!(access.allows(&Command::Stop));
        }
    }

    #[test]
    fn repeats_are_dropped_and_order_is_kept() {
        assert_eq!(normalize(&names(&["start", "STOP", "Start", ""])), ["START", "STOP"]);
    }

    #[test]
    fn a_name_that_is_not_a_command_is_reported_and_allows_nothing() {
        let configured = names(&["STOP", "STPO", "status"]);
        assert_eq!(unknown_names(&configured), ["STPO", "STATUS"]);

        // Queries are always allowed and are not in the list; naming one is a mistake.
        let access = CommandAccess::new(&configured);
        assert!(access.allows(&Command::Stop));
        assert!(!access.allows(&Command::Start));
    }

    #[test]
    fn no_unknown_names_in_the_default() {
        assert!(unknown_names(&default_allowed()).is_empty());
    }
}
