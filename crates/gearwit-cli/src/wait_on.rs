//! In-process `self wait-on`.
//!
//! Wraps `chanvoy wait`. This process completing is not proof that the harness
//! started a model turn. Receipts keep those facts separate.

use std::fmt::Write as _;
use std::io;
use std::process::{Command, ExitStatus};

use crate::sanitize::{
    BodyPrepareError, LocalBodyLoss, MAX_ID, MAX_TIMEOUT, paste_field, paste_token, prepare_body,
};
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
    /// If true, re-arm coverage from `newest_observed` after a match or the same
    /// cursor after a deadman. This is daemon coverage, not a handled cursor.
    pub follow: bool,
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
    pub drained_events: Vec<DrainedEvent>,
    /// Newest observed post id from that drain, if any.
    pub newest_observed: Option<String>,
    /// Drain failed closed after a waiter match.
    pub drain_error: Option<DrainError>,
}

/// One validated provider event from a post-match drain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainedEvent {
    /// Provider event id.
    pub id: String,
    /// Username when present and paste-safe.
    pub username: String,
    /// Body, with locally measured loss disclosed when required.
    pub message: String,
    /// Process-local diagnostic; never sent as waiter-link status metadata.
    pub local_loss: Option<LocalBodyLoss>,
}

/// Why a post-match drain failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DrainError {
    /// Exclusive `--after` was missing.
    MissingBaseline,
    /// Provider CLI exited nonzero.
    NonZeroExit,
    /// JSON shape or required fields were invalid.
    Malformed,
    /// Match succeeded but drain returned no events.
    Empty,
    /// Duplicate event ids in one drain.
    DuplicateId,
    /// Provider CLI could not be started or read.
    Io,
    /// Local loss could not be disclosed within both body limits.
    AdvisoryCannotFit {
        /// Provider ref for the page that could not carry a visible advisory.
        event_ref: String,
        /// Disallowed controls measured before any display transform.
        controls_removed: usize,
        /// Scalars that would be omitted to fit the advisory safely.
        scalars_clipped: usize,
    },
}

impl DrainError {
    /// Stable token for the local receipt face.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MissingBaseline => "missing_baseline",
            Self::NonZeroExit => "nonzero_exit",
            Self::Malformed => "malformed",
            Self::Empty => "empty",
            Self::DuplicateId => "duplicate_id",
            Self::Io => "io",
            Self::AdvisoryCannotFit { .. } => "advisory_cannot_fit",
        }
    }

    fn advisory_failure(&self) -> Option<(&str, usize, usize)> {
        match self {
            Self::AdvisoryCannotFit {
                event_ref,
                controls_removed,
                scalars_clipped,
            } => Some((event_ref, *controls_removed, *scalars_clipped)),
            _ => None,
        }
    }
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
            .is_some_and(|after| paste_token(after, MAX_ID).is_some())
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
    let sequence = u64::try_from(log.len())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    if outcome.drain_error.is_some() {
        append_fact(
            &mut log,
            sequence,
            LifecycleFact::CoverageEnded(CoverageEndReason::ProviderFailed),
            ReceiptSource::ControlPlane,
        )?;
    } else if outcome.result == WaitResult::Matched && !outcome.drained_events.is_empty() {
        let event_count = u32::try_from(outcome.drained_events.len()).unwrap_or(u32::MAX);
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
drain_error: {drain_error}
drain_diagnostic_json: {drain_diagnostic}
drain_failure_disposition: {drain_disposition}
drained_count: {drained_count}
newest_observed: {newest_observed}
{events}
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
        drain_error = outcome
            .drain_error
            .as_ref()
            .map_or("none", DrainError::as_str),
        drain_diagnostic = render_drain_diagnostic(outcome.drain_error.as_ref()),
        drain_disposition = if outcome.drain_error.is_some() {
            "withheld_before_claim_or_dispatch; cursor_not_advanced"
        } else {
            "none"
        },
        drained_count = outcome.drained_events.len(),
        newest_observed = outcome
            .newest_observed
            .as_deref()
            .map_or_else(|| "unknown".to_owned(), |id| paste_field(id, MAX_ID)),
        events = render_drained_events(&outcome.drained_events),
    )
}

fn render_drained_events(events: &[DrainedEvent]) -> String {
    if events.is_empty() {
        return "drained_events: none".to_owned();
    }
    let mut out = String::from("drained_events:");
    for event in events {
        let body_json = serde_json::to_string(&event.message)
            .unwrap_or_else(|_| "\"<unavailable>\"".to_owned());
        let _ = write!(
            out,
            "\n- id={id} user={user}\n  body_json: {body}",
            id = paste_field(&event.id, MAX_ID),
            user = paste_field(&event.username, MAX_ID),
            body = body_json,
        );
        let _ = write!(
            out,
            "\n  body_notice_trust: untrusted-provider-text; the source may mimic this notice"
        );
        if let Some(loss) = event.local_loss {
            let _ = write!(
                out,
                "\n  local_body_loss: controls_removed={} scalars_clipped={} displayed_bytes={}",
                loss.controls_removed, loss.scalars_clipped, loss.displayed_bytes
            );
        }
    }
    out
}

fn render_drain_diagnostic(error: Option<&DrainError>) -> String {
    let Some((event_ref, controls_removed, scalars_clipped)) =
        error.and_then(DrainError::advisory_failure)
    else {
        return "none".to_owned();
    };
    serde_json::json!({
        "reason": "advisory_cannot_fit",
        "event_ref": event_ref,
        "controls_removed": controls_removed,
        "scalars_clipped": scalars_clipped,
    })
    .to_string()
}

/// Parse a full `chanvoy read --json` object. Rejects partial or duplicate sets.
///
/// # Errors
///
/// Returns [`DrainError`] when JSON is not a chanvoy 0.3.0 message array (or
/// a `messages` object), any event is invalid, the set is empty, or ids are
/// duplicated.
pub fn parse_drained_events(json: &str) -> Result<Vec<DrainedEvent>, DrainError> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|_| DrainError::Malformed)?;
    let messages = if let Some(array) = value.as_array() {
        array
    } else if let Some(array) = value.get("messages").and_then(serde_json::Value::as_array) {
        array
    } else {
        return Err(DrainError::Malformed);
    };
    if messages.is_empty() {
        return Err(DrainError::Empty);
    }
    let mut events = Vec::with_capacity(messages.len());
    let mut seen = std::collections::BTreeSet::new();
    for message in messages {
        let id = message
            .get("id")
            .and_then(serde_json::Value::as_str)
            .and_then(|id| paste_token(id, MAX_ID))
            .ok_or(DrainError::Malformed)?;
        if !seen.insert(id.to_owned()) {
            return Err(DrainError::DuplicateId);
        }
        let username = message
            .get("username")
            .and_then(serde_json::Value::as_str)
            .and_then(|name| paste_token(name, MAX_ID))
            .unwrap_or("unknown");
        let body = message
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let prepared = prepare_body(body).map_err(|error: BodyPrepareError| {
            DrainError::AdvisoryCannotFit {
                event_ref: id.to_owned(),
                controls_removed: error.controls_removed,
                scalars_clipped: error.scalars_clipped,
            }
        })?;
        events.push(DrainedEvent {
            id: id.to_owned(),
            username: username.to_owned(),
            message: prepared.body,
            local_loss: prepared.local_loss,
        });
    }
    Ok(events)
}

/// Drain provider posts after the exclusive arm baseline.
pub trait EventDrain {
    /// Return validated events, oldest-first.
    ///
    /// # Errors
    ///
    /// Returns [`DrainError`] when the provider output cannot be trusted.
    fn drain_after(&self, spec: &WaitOnSpec) -> Result<Vec<DrainedEvent>, DrainError>;
}

/// Default drain: `chanvoy read --json --after`.
pub struct ChanvoyDrain;

impl EventDrain for ChanvoyDrain {
    fn drain_after(&self, spec: &WaitOnSpec) -> Result<Vec<DrainedEvent>, DrainError> {
        let after = spec.after.as_deref().ok_or(DrainError::MissingBaseline)?;
        let mut command = Command::new("chanvoy");
        command.arg("read");
        if let Some(team) = &spec.team {
            command.arg("--team").arg(team);
        }
        command.arg(&spec.channel);
        command.arg("--after").arg(after);
        command.arg("--json");
        let output = command.output().map_err(|_| DrainError::Io)?;
        if !output.status.success() {
            return Err(DrainError::NonZeroExit);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_drained_events(&stdout)
    }
}

/// Fill drain fields after a matched waiter. Fail closed on drain errors.
#[must_use]
pub fn attach_drain(
    mut outcome: WaitOutcome,
    spec: &WaitOnSpec,
    drain: &impl EventDrain,
) -> WaitOutcome {
    if outcome.result != WaitResult::Matched {
        return outcome;
    }
    if spec.after.is_none() {
        outcome.drain_error = Some(DrainError::MissingBaseline);
        outcome.process_exit = 2;
        return outcome;
    }
    match drain.drain_after(spec) {
        Ok(events) => {
            outcome.newest_observed = events.last().map(|event| event.id.clone());
            outcome.drained_events = events;
            outcome.drain_error = None;
        }
        Err(error) => {
            outcome.drained_events.clear();
            outcome.newest_observed = None;
            outcome.drain_error = Some(error);
            outcome.process_exit = 2;
        }
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
            drained_events: Vec::new(),
            newest_observed: None,
            drain_error: None,
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
                drained_events: Vec::new(),
                newest_observed: None,
                drain_error: None,
            }
        }
        Err(_) => WaitOutcome {
            waiter: WaiterState::NotStarted,
            result: WaitResult::Error,
            chanvoy_exit: None,
            process_exit: 2,
            drained_events: Vec::new(),
            newest_observed: None,
            drain_error: None,
        },
    }
}

/// Run one wait interval, print and store a receipt.
#[must_use]
pub fn run_wait_on_once(spec: &WaitOnSpec) -> WaitOutcome {
    let outcome = attach_drain(execute_wait_on(spec, &ChanvoyRunner), spec, &ChanvoyDrain);
    let mut receipt = render_wait_receipt(spec, &outcome);
    if spec.follow {
        receipt = format!("{receipt}coverage_mode: follow_newest_observed\n");
        eprint!("{receipt}");
    } else {
        eprint!("{receipt}");
    }
    if let Err(error) = crate::check::store_last_receipt(&receipt) {
        eprintln!("gearwit: could not store last receipt: {error}");
    }
    if outcome.waiter == WaiterState::NotStarted && outcome.chanvoy_exit.is_none() {
        eprintln!("gearwit: waiter did not start");
    }
    outcome
}

/// Run `chanvoy wait` and print a receipt. Returns the process exit code.
#[must_use]
pub fn run_wait_on(spec: &WaitOnSpec) -> i32 {
    if spec.follow {
        return run_watch_loop(spec.clone());
    }
    run_wait_on_once(spec).process_exit
}

/// How coverage should continue after one daemon interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoverageAdvance {
    /// Re-arm with this exclusive cursor.
    Continue {
        /// Next `--after` baseline.
        after: String,
    },
    /// Stop the watcher.
    Stop {
        /// Process exit code.
        exit: i32,
    },
}

/// One-interval coverage transition. Does not claim a handled cursor.
#[must_use]
pub fn coverage_advance(outcome: &WaitOutcome, current_after: &str) -> CoverageAdvance {
    match outcome.result {
        WaitResult::Matched => match outcome.newest_observed.as_deref() {
            Some(newest) => CoverageAdvance::Continue {
                after: newest.to_owned(),
            },
            None => CoverageAdvance::Stop { exit: 2 },
        },
        WaitResult::Timeout => CoverageAdvance::Continue {
            after: current_after.to_owned(),
        },
        WaitResult::Error => CoverageAdvance::Stop {
            exit: if outcome.process_exit == 0 {
                2
            } else {
                outcome.process_exit
            },
        },
    }
}

/// Coverage loop: re-arm from newest observed after match, same cursor after deadman.
#[must_use]
pub fn run_watch_loop(mut spec: WaitOnSpec) -> i32 {
    spec.follow = true;
    spec.return_route = DeliveryRoute::NotifyOperator;
    loop {
        let current_after = spec.after.clone().unwrap_or_default();
        let outcome = run_wait_on_once(&spec);
        match coverage_advance(&outcome, &current_after) {
            CoverageAdvance::Continue { after } => spec.after = Some(after),
            CoverageAdvance::Stop { exit } => return exit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CoverageAdvance, DrainError, DrainedEvent, EventDrain, WaitOnSpec, WaitOutcome, WaitResult,
        WaitRunner, WaiterState, attach_drain, chanvoy_wait_args, coverage_advance,
        execute_wait_on, parse_drained_events, render_wait_receipt, waiter_receipt_log,
    };
    use crate::sanitize::MAX_BODY;
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
            follow: false,
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
            drained_events: vec![
                DrainedEvent {
                    id: "post-a".to_owned(),
                    username: "peer".to_owned(),
                    message: "first".to_owned(),
                    local_loss: None,
                },
                DrainedEvent {
                    id: "post-b".to_owned(),
                    username: "peer".to_owned(),
                    message: "second".to_owned(),
                    local_loss: None,
                },
            ],
            newest_observed: Some("post-b".to_owned()),
            drain_error: None,
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

    fn event(id: &str, body: &str) -> DrainedEvent {
        DrainedEvent {
            id: id.to_owned(),
            username: "peer".to_owned(),
            message: body.to_owned(),
            local_loss: None,
        }
    }

    #[test]
    fn parse_two_posts_oldest_first_with_bodies() {
        let json = r#"[{"id":"aaa","username":"ux","message":"one"},{"id":"bbb","username":"dv","message":"two"}]"#;
        let events = parse_drained_events(json).expect("parsed");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, "aaa");
        assert_eq!(events[0].message, "one");
        assert_eq!(events[1].id, "bbb");
        assert_eq!(events[1].message, "two");
    }

    #[test]
    fn parse_preserves_tabs_and_discloses_local_control_loss() {
        let json = r#"[{"id":"aaa","username":"peer","message":"left\tright\u001b"}]"#;
        let events = parse_drained_events(json).expect("loss can be disclosed");
        assert_eq!(
            events[0].message,
            "left\tright\n\nPartial body; full post at source."
        );
        let loss = events[0].local_loss.expect("local loss diagnostic");
        assert_eq!(loss.controls_removed, 1);
        assert_eq!(loss.scalars_clipped, 0);
        assert_eq!(loss.displayed_bytes, events[0].message.len());
        let rendered = super::render_drained_events(&events);
        assert!(
            rendered.contains(r#"body_json: "left\tright\n\nPartial body; full post at source.""#)
        );
        assert!(rendered.contains(
            "body_notice_trust: untrusted-provider-text; the source may mimic this notice"
        ));
        assert!(rendered.contains("local_body_loss: controls_removed=1 scalars_clipped=0"));
    }

    #[test]
    fn parse_refuses_when_a_single_grapheme_cannot_fit_with_the_warning() {
        let body = "\u{301}".repeat(MAX_BODY);
        let json = serde_json::json!([{"id":"aaa","message":body}]).to_string();
        assert_eq!(
            parse_drained_events(&json).unwrap_err(),
            DrainError::AdvisoryCannotFit {
                event_ref: "aaa".to_owned(),
                controls_removed: 0,
                scalars_clipped: MAX_BODY,
            }
        );
    }

    #[test]
    fn parse_rejects_malformed_partial_and_duplicates() {
        assert_eq!(parse_drained_events("[]").unwrap_err(), DrainError::Empty);
        let chanvoy = r#"[{"id":"aaa","username":"ux","message":"one"},{"id":"bbb","username":"dv","message":"two"}]"#;
        let from_array = parse_drained_events(chanvoy).expect("chanvoy 0.3.0 array");
        assert_eq!(from_array[1].id, "bbb");
        assert_eq!(from_array[1].message, "two");
        assert_eq!(
            parse_drained_events(r#"{"messages":[{"username":"x"}]}"#).unwrap_err(),
            DrainError::Malformed
        );
        assert_eq!(
            parse_drained_events(r#"{"messages":[{"id":"aaa"},{"id":"aaa"}]}"#).unwrap_err(),
            DrainError::DuplicateId
        );
        assert_eq!(
            parse_drained_events(r#"{"messages":[]}"#).unwrap_err(),
            DrainError::Empty
        );
    }

    struct FixedDrain(Result<Vec<DrainedEvent>, DrainError>);

    impl EventDrain for FixedDrain {
        fn drain_after(&self, _spec: &WaitOnSpec) -> Result<Vec<DrainedEvent>, DrainError> {
            self.0.clone()
        }
    }

    #[test]
    fn matched_wait_drains_burst_bodies_not_only_ids() {
        let outcome = attach_drain(
            execute_wait_on(&spec(), &ExitCodeRunner(0)),
            &spec(),
            &FixedDrain(Ok(vec![event("first", "alpha"), event("second", "beta")])),
        );
        assert_eq!(outcome.process_exit, 0);
        assert_eq!(outcome.newest_observed.as_deref(), Some("second"));
        let text = render_wait_receipt(&spec(), &outcome);
        assert!(text.contains("newest_observed: second"));
        assert!(text.contains("alpha"));
        assert!(text.contains("beta"));
        assert!(text.contains("events_drained: 2  (provider)"));
        assert!(text.contains("handled_cursor_recorded: unknown"));
        assert!(text.contains("drain_error: none"));
    }

    #[test]
    fn empty_or_failed_drain_fails_closed() {
        let empty = attach_drain(
            execute_wait_on(&spec(), &ExitCodeRunner(0)),
            &spec(),
            &FixedDrain(Err(DrainError::Empty)),
        );
        assert_eq!(empty.process_exit, 2);
        assert_eq!(empty.drain_error, Some(DrainError::Empty));
        let text = render_wait_receipt(&spec(), &empty);
        assert!(text.contains("drain_error: empty"));
        assert!(text.contains("events_drained: unknown"));
        assert!(text.contains("coverage_ended: provider_failed  (control_plane)"));

        let mut no_after = spec();
        no_after.after = None;
        let missing = attach_drain(
            execute_wait_on(&spec(), &ExitCodeRunner(0)),
            &no_after,
            &FixedDrain(Ok(vec![event("x", "y")])),
        );
        assert_eq!(missing.drain_error, Some(DrainError::MissingBaseline));
        assert_eq!(missing.process_exit, 2);
    }

    #[test]
    fn undisclosable_loss_stops_follow_without_cursor_advance() {
        let outcome = attach_drain(
            execute_wait_on(&spec(), &ExitCodeRunner(0)),
            &spec(),
            &FixedDrain(Err(DrainError::AdvisoryCannotFit {
                event_ref: "source-post".to_owned(),
                controls_removed: 1,
                scalars_clipped: MAX_BODY,
            })),
        );
        assert_eq!(outcome.newest_observed, None);
        assert_eq!(outcome.drained_events, []);
        assert_eq!(
            coverage_advance(&outcome, "cursor1"),
            CoverageAdvance::Stop { exit: 2 }
        );
        let receipt = render_wait_receipt(&spec(), &outcome);
        assert!(receipt.contains("drain_diagnostic_json: {\"controls_removed\":1"));
        assert!(receipt.contains("\"event_ref\":\"source-post\""));
        assert!(receipt.contains("withheld_before_claim_or_dispatch; cursor_not_advanced"));
    }

    #[test]
    fn coverage_match_rearms_at_newest_observed() {
        let outcome = WaitOutcome {
            waiter: WaiterState::Completed,
            result: WaitResult::Matched,
            chanvoy_exit: Some(0),
            process_exit: 0,
            drained_events: vec![event("first", "a"), event("second", "b")],
            newest_observed: Some("second".to_owned()),
            drain_error: None,
        };
        assert_eq!(
            coverage_advance(&outcome, "arm"),
            CoverageAdvance::Continue {
                after: "second".to_owned()
            }
        );
    }

    #[test]
    fn coverage_timeout_keeps_the_same_cursor() {
        let outcome = WaitOutcome {
            waiter: WaiterState::Completed,
            result: WaitResult::Timeout,
            chanvoy_exit: Some(1),
            process_exit: 1,
            drained_events: Vec::new(),
            newest_observed: None,
            drain_error: None,
        };
        assert_eq!(
            coverage_advance(&outcome, "arm"),
            CoverageAdvance::Continue {
                after: "arm".to_owned()
            }
        );
    }

    #[test]
    fn coverage_errors_and_missing_newest_stop() {
        let mut failed = WaitOutcome {
            waiter: WaiterState::Completed,
            result: WaitResult::Error,
            chanvoy_exit: Some(2),
            process_exit: 2,
            drained_events: Vec::new(),
            newest_observed: None,
            drain_error: Some(DrainError::Empty),
        };
        assert_eq!(
            coverage_advance(&failed, "arm"),
            CoverageAdvance::Stop { exit: 2 }
        );
        failed.result = WaitResult::Matched;
        failed.process_exit = 0;
        failed.newest_observed = None;
        assert_eq!(
            coverage_advance(&failed, "arm"),
            CoverageAdvance::Stop { exit: 2 }
        );
    }
}
