//! In-process `self wait-on`.
//!
//! Wraps `chanvoy wait`. This process completing is not proof that the harness
//! started a model turn. Receipts keep those facts separate.

use std::io;
use std::process::{Command, ExitStatus};

use crate::sanitize::{MAX_ID, MAX_TIMEOUT, paste_field, paste_token};
use gearwit_domain::{
    CoverageEndReason, DeliveryRoute, InterruptPhase, LifecycleFact, LifecycleReceipt,
    PhaseObservation, ReceiptError, ReceiptLog, ReceiptSource, WaiterCompletion,
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
    /// Interrupt source token (`chanvoy` first).
    pub source: String,
    /// Declared return route. Not proof that a model turn started.
    pub return_route: DeliveryRoute,
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
    /// Provider posts observed after the exclusive arm baseline.
    pub drained_ids: Vec<String>,
    /// Newest observed post id from that drain, if any.
    pub newest_observed: Option<String>,
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

fn append_fact(
    log: &mut ReceiptLog,
    sequence: u64,
    fact: LifecycleFact,
    source: ReceiptSource,
) -> Result<u64, ReceiptError> {
    log.append(LifecycleReceipt::try_new(sequence, fact, source)?)?;
    Ok(sequence + 1)
}

/// Build lifecycle receipts for one in-process wait. Fail closed on invariant errors.
///
/// # Errors
///
/// Returns [`ReceiptError`] if a fact/source pair is illegal or a sequence
/// cannot be appended. Callers must not invent a partial log.
pub fn waiter_receipt_log(outcome: &WaitOutcome) -> Result<ReceiptLog, ReceiptError> {
    let mut log = ReceiptLog::new();
    let mut sequence = 1;
    if outcome.waiter == WaiterState::NotStarted {
        append_fact(
            &mut log,
            sequence,
            LifecycleFact::CoverageEnded(CoverageEndReason::RunnerNotStarted),
            ReceiptSource::ControlPlane,
        )?;
        return Ok(log);
    }
    match outcome.result {
        WaitResult::Matched => {
            sequence = append_fact(
                &mut log,
                sequence,
                LifecycleFact::WaitArmed,
                ReceiptSource::WaiterProcess,
            )?;
            append_fact(
                &mut log,
                sequence,
                LifecycleFact::WaiterCompleted(WaiterCompletion::Matched),
                ReceiptSource::WaiterProcess,
            )?;
        }
        WaitResult::Timeout => {
            sequence = append_fact(
                &mut log,
                sequence,
                LifecycleFact::WaitArmed,
                ReceiptSource::WaiterProcess,
            )?;
            sequence = append_fact(
                &mut log,
                sequence,
                LifecycleFact::WaiterCompleted(WaiterCompletion::DeadmanExpired),
                ReceiptSource::WaiterProcess,
            )?;
            append_fact(
                &mut log,
                sequence,
                LifecycleFact::CoverageEnded(CoverageEndReason::DeadmanExpired),
                ReceiptSource::WaiterProcess,
            )?;
        }
        WaitResult::Error => {
            sequence = append_fact(
                &mut log,
                sequence,
                LifecycleFact::WaiterCompleted(WaiterCompletion::Failed),
                ReceiptSource::WaiterProcess,
            )?;
            append_fact(
                &mut log,
                sequence,
                LifecycleFact::CoverageEnded(CoverageEndReason::ProviderFailed),
                ReceiptSource::WaiterProcess,
            )?;
        }
    }
    Ok(log)
}

/// Combine waiter facts with a provider drain. Never records handled cursor.
///
/// # Errors
///
/// Returns [`ReceiptError`] if drain facts cannot be appended.
pub fn lifecycle_log(outcome: &WaitOutcome) -> Result<ReceiptLog, ReceiptError> {
    let mut log = waiter_receipt_log(outcome)?;
    if outcome.result == WaitResult::Matched && !outcome.drained_ids.is_empty() {
        let sequence = u64::try_from(log.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let event_count = u32::try_from(outcome.drained_ids.len()).unwrap_or(u32::MAX);
        append_fact(
            &mut log,
            sequence,
            LifecycleFact::EventsDrained { event_count },
            ReceiptSource::Provider,
        )?;
    }
    Ok(log)
}

fn format_phase_line(log: &ReceiptLog, phase: InterruptPhase) -> String {
    match log.observe(phase) {
        PhaseObservation::Unknown => format!("{phase}: unknown"),
        PhaseObservation::Observed { fact, source } => {
            let detail = match fact {
                LifecycleFact::WaiterCompleted(completion) => completion.as_str().to_owned(),
                LifecycleFact::CoverageEnded(reason) => reason.as_str().to_owned(),
                LifecycleFact::EventsDrained { event_count } => event_count.to_string(),
                _ => "observed".to_owned(),
            };
            format!("{phase}: {detail}  ({})", source.as_str())
        }
    }
}

/// Render a paste-safe receipt using interrupt-lifecycle tokens.
#[must_use]
pub fn render_wait_receipt(spec: &WaitOnSpec, outcome: &WaitOutcome) -> String {
    let log = match lifecycle_log(outcome) {
        Ok(log) => log,
        Err(error) => {
            return format!(
                "\
gearwit self wait-on
channel: {channel}
after: {after}
timeout: {timeout}
durability: in_process
receipt_error: {error}
wait_armed: unknown
signal_matched: unknown
waiter_completed: unknown
turn_started: unknown
model_observed: unknown
seat_acted: unknown
coverage_rearmed: unknown
coverage_ended: unknown
",
                channel = paste_field(&spec.channel, MAX_ID),
                after = spec
                    .after
                    .as_deref()
                    .map_or_else(|| "unknown".to_owned(), |after| paste_field(after, MAX_ID)),
                timeout = paste_field(&spec.timeout, MAX_TIMEOUT),
            );
        }
    };
    let phases = [
        InterruptPhase::WaitArmed,
        InterruptPhase::SignalMatched,
        InterruptPhase::WaiterCompleted,
        InterruptPhase::EventsDrained,
        InterruptPhase::TurnStarted,
        InterruptPhase::ModelObserved,
        InterruptPhase::SeatActed,
        InterruptPhase::HandledCursorRecorded,
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
source: {source}
channel: {channel}
after: {after}
timeout: {timeout}
return: {return_route}  (self_declared)
durability: in_process
chanvoy_exit: {chanvoy_exit}
drained_count: {drained_count}
newest_observed: {newest_observed}
{phases}
",
        source = paste_field(&spec.source, MAX_ID),
        channel = paste_field(&spec.channel, MAX_ID),
        after = spec
            .after
            .as_deref()
            .map_or_else(|| "unknown".to_owned(), |after| paste_field(after, MAX_ID)),
        timeout = paste_field(&spec.timeout, MAX_TIMEOUT),
        return_route = spec.return_route.as_str(),
        chanvoy_exit = outcome
            .chanvoy_exit
            .map_or_else(|| "unknown".to_owned(), |code| code.to_string()),
        drained_count = outcome.drained_ids.len(),
        newest_observed = outcome
            .newest_observed
            .as_deref()
            .map_or_else(|| "unknown".to_owned(), |id| paste_field(id, MAX_ID),),
    )
}

/// Parse post ids from `chanvoy read --json` (object with `messages` or a bare array).
#[must_use]
pub fn parse_drained_ids(json: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let messages = value
        .get("messages")
        .and_then(serde_json::Value::as_array)
        .or_else(|| value.as_array());
    let Some(messages) = messages else {
        return Vec::new();
    };
    messages
        .iter()
        .filter_map(|message| {
            message
                .get("id")
                .and_then(serde_json::Value::as_str)
                .and_then(|id| paste_token(id, MAX_ID).map(ToOwned::to_owned))
        })
        .collect()
}

/// Drain provider posts after the exclusive arm baseline.
pub trait EventDrain {
    /// Return observed post ids, oldest-first.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from the provider CLI.
    fn drain_after(&self, spec: &WaitOnSpec) -> io::Result<Vec<String>>;
}

/// Default drain: `chanvoy read --json --after`.
pub struct ChanvoyDrain;

impl EventDrain for ChanvoyDrain {
    fn drain_after(&self, spec: &WaitOnSpec) -> io::Result<Vec<String>> {
        let mut command = Command::new("chanvoy");
        command.arg("read");
        if let Some(team) = &spec.team {
            command.arg("--team").arg(team);
        }
        command.arg(&spec.channel);
        if let Some(after) = &spec.after {
            command.arg("--after").arg(after);
        }
        command.arg("--json");
        let output = command.output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_drained_ids(&stdout))
    }
}

/// Fill drain fields after a matched waiter. Timeouts and errors skip drain.
pub fn attach_drain(
    mut outcome: WaitOutcome,
    spec: &WaitOnSpec,
    drain: &impl EventDrain,
) -> WaitOutcome {
    if outcome.result != WaitResult::Matched {
        return outcome;
    }
    if let Ok(ids) = drain.drain_after(spec) {
        outcome.newest_observed = ids.last().cloned();
        outcome.drained_ids = ids;
    } else {
        outcome.drained_ids.clear();
        outcome.newest_observed = None;
    }
    outcome
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
            drained_ids: Vec::new(),
            newest_observed: None,
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
                drained_ids: Vec::new(),
                newest_observed: None,
            }
        }
        Err(_) => WaitOutcome {
            waiter: WaiterState::NotStarted,
            result: WaitResult::Error,
            chanvoy_exit: None,
            process_exit: 2,
            drained_ids: Vec::new(),
            newest_observed: None,
        },
    }
}

/// Run `chanvoy wait` and print a receipt. Returns the process exit code.
#[must_use]
pub fn run_wait_on(spec: &WaitOnSpec) -> i32 {
    let outcome = attach_drain(execute_wait_on(spec, &ChanvoyRunner), spec, &ChanvoyDrain);
    let receipt = render_wait_receipt(spec, &outcome);
    eprint!("{receipt}");
    if let Err(error) = crate::check::store_last_receipt(&receipt) {
        eprintln!("gearwit: could not store last receipt: {error}");
    }
    if outcome.waiter == WaiterState::NotStarted && outcome.chanvoy_exit.is_none() {
        eprintln!("gearwit: waiter did not start");
    }
    outcome.process_exit
}

#[cfg(test)]
mod tests {
    use super::{
        EventDrain, WaitOnSpec, WaitOutcome, WaitResult, WaitRunner, WaiterState, attach_drain,
        chanvoy_wait_args, execute_wait_on, lifecycle_log, parse_drained_ids, render_wait_receipt,
        waiter_receipt_log,
    };
    use gearwit_domain::InterruptPhase;
    use std::io;
    use std::process::{Command, ExitStatus};

    fn spec() -> WaitOnSpec {
        WaitOnSpec {
            channel: "november-team".to_owned(),
            after: Some("cursor1".to_owned()),
            timeout: "20m".to_owned(),
            team: None,
            source: "chanvoy".to_owned(),
            return_route: gearwit_domain::DeliveryRoute::ReturnForeground,
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
            drained_ids: vec!["post-a".to_owned(), "post-b".to_owned()],
            newest_observed: Some("post-b".to_owned()),
        };
        let text = render_wait_receipt(&spec(), &outcome);
        assert!(text.contains("source: chanvoy"));
        assert!(text.contains("return: return_foreground  (self_declared)"));
        assert!(text.contains("wait_armed: observed  (waiter_process)"));
        assert!(text.contains("signal_matched: unknown"));
        assert!(text.contains("waiter_completed: matched  (waiter_process)"));
        assert!(text.contains("turn_started: unknown"));
        assert!(text.contains("durability: in_process"));
        assert!(text.contains("drained_count: 2"));
        assert!(text.contains("newest_observed: post-b"));
        let log = waiter_receipt_log(&outcome).expect("matched receipts");
        assert_eq!(log.len(), 2);
        assert!(log.observe(InterruptPhase::TurnStarted).is_unknown());
        assert!(!log.observe(InterruptPhase::WaitArmed).is_unknown());
    }

    #[test]
    fn missing_runner_is_not_waiter_completed() {
        let outcome = execute_wait_on(&spec(), &MissingRunner);
        assert_eq!(outcome.waiter, WaiterState::NotStarted);
        assert_eq!(outcome.result, WaitResult::Error);
        assert_eq!(outcome.process_exit, 2);
        assert!(outcome.chanvoy_exit.is_none());
        let text = render_wait_receipt(&spec(), &outcome);
        assert!(text.contains("wait_armed: unknown"));
        assert!(text.contains("waiter_completed: unknown"));
        assert!(text.contains("coverage_ended: runner_not_started  (control_plane)"));
        assert!(text.contains("turn_started: unknown"));
        assert!(!text.contains("waiter_process"));
    }

    struct ExitCodeRunner(i32);

    impl WaitRunner for ExitCodeRunner {
        fn run(&self, _args: &[String]) -> io::Result<ExitStatus> {
            Command::new("sh")
                .args(["-c", &format!("exit {}", self.0)])
                .status()
        }
    }

    #[test]
    fn started_child_exit_2_does_not_prove_wait_armed() {
        let outcome = execute_wait_on(&spec(), &ExitCodeRunner(2));
        assert_eq!(outcome.waiter, WaiterState::Completed);
        assert_eq!(outcome.result, WaitResult::Error);
        let text = render_wait_receipt(&spec(), &outcome);
        assert!(text.contains("wait_armed: unknown"));
        assert!(text.contains("waiter_completed: failed  (waiter_process)"));
        assert!(text.contains("coverage_ended: provider_failed  (waiter_process)"));
        let log = waiter_receipt_log(&outcome).expect("failed receipts");
        assert!(log.observe(InterruptPhase::WaitArmed).is_unknown());
    }

    #[test]
    fn timeout_ends_in_process_coverage_as_deadman() {
        let outcome = execute_wait_on(&spec(), &ExitCodeRunner(1));
        assert_eq!(outcome.result, WaitResult::Timeout);
        let text = render_wait_receipt(&spec(), &outcome);
        assert!(text.contains("wait_armed: observed  (waiter_process)"));
        assert!(text.contains("waiter_completed: deadman_expired  (waiter_process)"));
        assert!(text.contains("coverage_ended: deadman_expired  (waiter_process)"));
        assert!(text.contains("signal_matched: unknown"));
        let log = waiter_receipt_log(&outcome).expect("deadman receipts");
        assert_eq!(log.len(), 3);
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

    #[test]
    fn parse_two_posts_oldest_first() {
        let json = r#"{"messages":[{"id":"aaa"},{"id":"bbb"}]}"#;
        assert_eq!(parse_drained_ids(json), ["aaa", "bbb"]);
    }

    struct FixedDrain(Vec<String>);

    impl EventDrain for FixedDrain {
        fn drain_after(&self, _spec: &WaitOnSpec) -> io::Result<Vec<String>> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn matched_wait_drains_beyond_first_match() {
        let outcome = attach_drain(
            execute_wait_on(&spec(), &ExitCodeRunner(0)),
            &spec(),
            &FixedDrain(vec!["first".to_owned(), "second".to_owned()]),
        );
        assert_eq!(outcome.drained_ids, ["first", "second"]);
        assert_eq!(outcome.newest_observed.as_deref(), Some("second"));
        let text = render_wait_receipt(&spec(), &outcome);
        assert!(text.contains("newest_observed: second"));
        assert!(text.contains("drained_count: 2"));
        assert!(text.contains("events_drained: 2  (provider)"));
        assert!(text.contains("handled_cursor_recorded: unknown"));
        let log = lifecycle_log(&outcome).expect("lifecycle");
        assert!(
            log.observe(InterruptPhase::HandledCursorRecorded)
                .is_unknown()
        );
    }
}
