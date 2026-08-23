//! In-process `self wait-on`.
//!
//! Wraps `chanvoy wait`. This process completing is not proof that the harness
//! started a model turn. Receipts keep those facts separate.

use std::process::Command;

/// Arguments for an in-process wait.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WaitOnSpec {
    /// Mattermost channel name or `team/channel`.
    pub channel: String,
    /// Exclusive `--after` cursor, when the caller has one.
    pub after: Option<String>,
    /// Deadman duration understood by `chanvoy wait`.
    pub timeout: String,
    /// Optional Mattermost team slug.
    pub team: Option<String>,
}

/// How the waiter process ended. Not a harness-turn claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitResult {
    /// Child reported a matching peer event.
    Matched,
    /// Child reported a clean timeout.
    Timeout,
    /// Child missing, crashed, or other failure.
    Error,
}

impl WaitResult {
    /// Stable token for the local receipt face.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }

    /// Map a Unix-style wait exit: 0 matched, 1 timeout, anything else error.
    #[must_use]
    pub const fn from_code(code: i32) -> Self {
        match code {
            0 => Self::Matched,
            1 => Self::Timeout,
            _ => Self::Error,
        }
    }
}

/// Build the `chanvoy wait` argv (without the program name).
#[must_use]
pub fn chanvoy_wait_args(spec: &WaitOnSpec) -> Vec<String> {
    let mut args = vec!["wait".to_owned()];
    if let Some(team) = &spec.team {
        args.push("--team".to_owned());
        args.push(team.clone());
    }
    args.push(spec.channel.clone());
    if let Some(after) = &spec.after {
        args.push("--after".to_owned());
        args.push(after.clone());
    }
    args.push("--timeout".to_owned());
    args.push(spec.timeout.clone());
    args.push("--json".to_owned());
    args
}

/// Render a paste-safe receipt. `turn_started` stays unknown.
#[must_use]
pub fn render_wait_receipt(
    spec: &WaitOnSpec,
    result: WaitResult,
    chanvoy_exit: Option<i32>,
) -> String {
    format!(
        "\
gearwit self wait-on
channel: {channel}
after: {after}
timeout: {timeout}
durability: in_process
waiter_completed: true  (self_declared)
wait_result: {wait_result}
chanvoy_exit: {chanvoy_exit}
turn_started: unknown
reachability: unknown
wake_plan: unknown
",
        channel = spec.channel,
        after = spec.after.as_deref().unwrap_or("unknown"),
        timeout = spec.timeout,
        wait_result = result.as_str(),
        chanvoy_exit = chanvoy_exit.map_or_else(|| "unknown".to_owned(), |code| code.to_string()),
    )
}

/// Run `chanvoy wait` and print a receipt. Returns the process exit code.
#[must_use]
pub fn run_wait_on(spec: &WaitOnSpec) -> i32 {
    let args = chanvoy_wait_args(spec);
    let spawn = Command::new("chanvoy").args(&args).status();
    match spawn {
        Ok(status) => {
            let code = status.code().unwrap_or(2);
            let result = WaitResult::from_code(code);
            eprint!("{}", render_wait_receipt(spec, result, Some(code)));
            code
        }
        Err(error) => {
            let result = WaitResult::Error;
            eprint!("{}", render_wait_receipt(spec, result, None));
            eprintln!("gearwit: failed to exec chanvoy: {error}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{WaitOnSpec, WaitResult, chanvoy_wait_args};

    fn spec() -> WaitOnSpec {
        WaitOnSpec {
            channel: "november-team".to_owned(),
            after: Some("cursor1".to_owned()),
            timeout: "20m".to_owned(),
            team: None,
        }
    }

    #[test]
    fn wait_args_are_exclusive_after_and_json() {
        let args = chanvoy_wait_args(&spec());
        assert_eq!(
            args,
            [
                "wait",
                "november-team",
                "--after",
                "cursor1",
                "--timeout",
                "20m",
                "--json"
            ]
        );
    }

    #[test]
    fn team_flag_follows_the_wait_verb() {
        let mut spec = spec();
        spec.team = Some("org-lanytehq".to_owned());
        let args = chanvoy_wait_args(&spec);
        assert_eq!(args[0], "wait");
        assert_eq!(args[1], "--team");
        assert_eq!(args[2], "org-lanytehq");
        assert_eq!(args[3], "november-team");
    }

    #[test]
    fn exit_codes_do_not_claim_a_turn() {
        assert_eq!(WaitResult::from_code(0), WaitResult::Matched);
        assert_eq!(WaitResult::from_code(1), WaitResult::Timeout);
        assert_eq!(WaitResult::from_code(2), WaitResult::Error);
    }

    #[test]
    fn receipt_keeps_turn_started_unknown() {
        let text = super::render_wait_receipt(&spec(), WaitResult::Matched, Some(0));
        assert!(text.contains("wait_result: matched"));
        assert!(text.contains("turn_started: unknown"));
        assert!(text.contains("durability: in_process"));
        assert!(!text.contains("completion_doorbell"));
    }
}
