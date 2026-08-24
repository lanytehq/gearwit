//! In-process `self wait-on`.
//!
//! Wraps `chanvoy wait`. This process completing is not proof that the harness
//! started a model turn. Receipts keep those facts separate.

use std::io;
use std::process::{Command, ExitStatus};

use crate::sanitize::{MAX_ID, MAX_TIMEOUT, paste_field, paste_token};
use gearwit_domain::{
    CoverageEndReason, InterruptPhase, LifecycleFact, LifecycleReceipt, PhaseObservation,
    ReceiptLog, ReceiptSource, WaiterCompletion,
};

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

/// Whether a waiter child process actually started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaiterState {
    /// The runner was not started (missing binary or rejected spec).
    NotStarted,
    /// The waiter child ran to a status.
    Completed,
}

impl WaiterState {
    /// Stable token for the local receipt face.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "false",
            Self::Completed => "true",
        }
    }
}

/// Outcome of an in-process wait attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WaitOutcome {
    /// Whether a waiter child started.
    pub waiter: WaiterState,
    /// Classified child result. Not a harness-turn claim.
    pub result: WaitResult,
    /// Raw child exit code, if any.
    pub chanvoy_exit: Option<i32>,
    /// Process exit: 0 matched, 1 timeout, otherwise 2.
    pub process_exit: i32,
}

/// Spawn a waiter. Tests inject a missing runner.
pub trait WaitRunner {
    /// Run `chanvoy wait` argv and return the child status.
    ///
    /// # Errors
    ///
    /// Returns I/O errors such as a missing executable.
    fn run(&self, args: &[String]) -> io::Result<ExitStatus>;
}

/// Default runner: exec `chanvoy` from `PATH`.
pub struct ChanvoyRunner;

impl WaitRunner for ChanvoyRunner {
    fn run(&self, args: &[String]) -> io::Result<ExitStatus> {
        Command::new("chanvoy").args(args).status()
    }
}

/// True when every spec field is paste-safe.
#[must_use]
pub fn spec_is_paste_safe(spec: &WaitOnSpec) -> bool {
    paste_token(&spec.channel, MAX_ID).is_some()
        && spec
            .after
            .as_deref()
            .is_none_or(|after| paste_token(after, MAX_ID).is_some())
        && paste_token(&spec.timeout, MAX_TIMEOUT).is_some()
        && spec
            .team
            .as_deref()
            .is_none_or(|team| paste_token(team, MAX_ID).is_some())
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

/// Build waiter-process receipts. The waiter cannot evidence `turn_started`.
#[must_use]
pub fn waiter_receipt_log(outcome: &WaitOutcome) -> ReceiptLog {
    let mut log = ReceiptLog::new();
    let mut append = |sequence: u64, fact: LifecycleFact| {
        if let Ok(receipt) = LifecycleReceipt::try_new(sequence, fact, ReceiptSource::WaiterProcess)
        {
            let _ = log.append(receipt);
        }
    };
    if outcome.waiter == WaiterState::NotStarted {
        append(
            1,
            LifecycleFact::CoverageEnded(CoverageEndReason::RunnerNotStarted),
        );
        return log;
    }
    append(1, LifecycleFact::WaitArmed);
    let completion = match outcome.result {
        WaitResult::Matched => WaiterCompletion::Matched,
        WaitResult::Timeout => WaiterCompletion::DeadmanExpired,
        WaitResult::Error => WaiterCompletion::Failed,
    };
    append(2, LifecycleFact::WaiterCompleted(completion));
    log
}

fn format_phase_line(log: &ReceiptLog, phase: InterruptPhase) -> String {
    match log.observe(phase) {
        PhaseObservation::Unknown => format!("{phase}: unknown"),
        PhaseObservation::Observed { fact, source } => {
            let detail = match fact {
                LifecycleFact::WaiterCompleted(completion) => completion.as_str(),
                LifecycleFact::CoverageEnded(reason) => reason.as_str(),
                _ => "observed",
            };
            format!("{phase}: {detail}  ({})", source.as_str())
        }
    }
}

/// Render a paste-safe receipt using interrupt-lifecycle tokens.
#[must_use]
pub fn render_wait_receipt(spec: &WaitOnSpec, outcome: &WaitOutcome) -> String {
    let log = waiter_receipt_log(outcome);
    let phases = [
        InterruptPhase::WaitArmed,
        InterruptPhase::SignalMatched,
        InterruptPhase::WaiterCompleted,
        InterruptPhase::TurnStarted,
        InterruptPhase::ModelObserved,
        InterruptPhase::SeatActed,
        InterruptPhase::CoverageRearmed,
        InterruptPhase::CoverageEnded,
    ]
    .into_iter()
    .map(|phase| format_phase_line(&log, phase))
    .collect::<Vec<_>>()
    .join("\n");
    format!(
        "\
gearwit self wait-on
channel: {channel}
after: {after}
timeout: {timeout}
durability: in_process
chanvoy_exit: {chanvoy_exit}
{phases}
",
        channel = paste_field(&spec.channel, MAX_ID),
        after = spec
            .after
            .as_deref()
            .map_or_else(|| "unknown".to_owned(), |after| paste_field(after, MAX_ID)),
        timeout = paste_field(&spec.timeout, MAX_TIMEOUT),
        chanvoy_exit = outcome
            .chanvoy_exit
            .map_or_else(|| "unknown".to_owned(), |code| code.to_string()),
    )
}

/// Execute a wait with an injected runner.
#[must_use]
pub fn execute_wait_on(spec: &WaitOnSpec, runner: &impl WaitRunner) -> WaitOutcome {
    if !spec_is_paste_safe(spec) {
        return WaitOutcome {
            waiter: WaiterState::NotStarted,
            result: WaitResult::Error,
            chanvoy_exit: None,
            process_exit: 2,
        };
    }
    let args = chanvoy_wait_args(spec);
    match runner.run(&args) {
        Ok(status) => {
            let raw = status.code();
            let process_exit = match raw {
                Some(0) => 0,
                Some(1) => 1,
                _ => 2,
            };
            WaitOutcome {
                waiter: WaiterState::Completed,
                result: WaitResult::from_code(process_exit),
                chanvoy_exit: raw,
                process_exit,
            }
        }
        Err(_) => WaitOutcome {
            waiter: WaiterState::NotStarted,
            result: WaitResult::Error,
            chanvoy_exit: None,
            process_exit: 2,
        },
    }
}

/// Run `chanvoy wait` and print a receipt. Returns the process exit code.
#[must_use]
pub fn run_wait_on(spec: &WaitOnSpec) -> i32 {
    let outcome = execute_wait_on(spec, &ChanvoyRunner);
    eprint!("{}", render_wait_receipt(spec, &outcome));
    if outcome.waiter == WaiterState::NotStarted && outcome.chanvoy_exit.is_none() {
        eprintln!("gearwit: waiter did not start");
    }
    outcome.process_exit
}

#[cfg(test)]
mod tests {
    use super::{
        WaitOnSpec, WaitOutcome, WaitResult, WaitRunner, WaiterState, chanvoy_wait_args,
        execute_wait_on, render_wait_receipt, waiter_receipt_log,
    };
    use gearwit_domain::InterruptPhase;
    use std::io;
    use std::process::ExitStatus;

    fn spec() -> WaitOnSpec {
        WaitOnSpec {
            channel: "november-team".to_owned(),
            after: Some("cursor1".to_owned()),
            timeout: "20m".to_owned(),
            team: None,
        }
    }

    struct MissingRunner;

    impl WaitRunner for MissingRunner {
        fn run(&self, _args: &[String]) -> io::Result<ExitStatus> {
            Err(io::Error::new(io::ErrorKind::NotFound, "chanvoy"))
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
        let outcome = WaitOutcome {
            waiter: WaiterState::Completed,
            result: WaitResult::Matched,
            chanvoy_exit: Some(0),
            process_exit: 0,
        };
        let text = render_wait_receipt(&spec(), &outcome);
        assert!(text.contains("wait_armed: observed  (waiter_process)"));
        assert!(text.contains("signal_matched: unknown"));
        assert!(text.contains("waiter_completed: matched  (waiter_process)"));
        assert!(text.contains("turn_started: unknown"));
        assert!(text.contains("durability: in_process"));
        let log = waiter_receipt_log(&outcome);
        assert!(log.observe(InterruptPhase::TurnStarted).is_unknown());
    }

    #[test]
    fn missing_runner_is_not_waiter_completed() {
        let outcome = execute_wait_on(&spec(), &MissingRunner);
        assert_eq!(outcome.waiter, WaiterState::NotStarted);
        assert_eq!(outcome.result, WaitResult::Error);
        assert_eq!(outcome.process_exit, 2);
        assert!(outcome.chanvoy_exit.is_none());
        let text = render_wait_receipt(&spec(), &outcome);
        assert!(text.contains("waiter_completed: unknown"));
        assert!(text.contains("coverage_ended: runner_not_started  (waiter_process)"));
        assert!(text.contains("turn_started: unknown"));
    }

    #[test]
    fn control_characters_reject_the_spec_without_starting() {
        let mut unsafe_spec = spec();
        unsafe_spec.channel = "november-team\nwait_result: matched".to_owned();
        let outcome = execute_wait_on(&unsafe_spec, &MissingRunner);
        assert_eq!(outcome.waiter, WaiterState::NotStarted);
        assert_eq!(outcome.process_exit, 2);
        let text = render_wait_receipt(&unsafe_spec, &outcome);
        assert!(text.contains("channel: rejected"));
        assert!(!text.contains("wait_result: matched\n"));
    }
}
