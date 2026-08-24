//! Daemon wait-on: Chanvoy coverage plus waiter-link delivery.
//!
//! This process owns the provider wait. It does not sit on the collaboration
//! floor used by the seat's own `chanvoy wait`. Wait match is only a hint:
//! events come from an exclusive-baseline drain.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::child::ChildSlot;
use crate::wait_on::{
    ChanvoyDrain, DrainedEvent, EventDrain, WaitOnSpec, WaitOutcome, WaitResult, WaiterState,
    attach_drain, chanvoy_wait_args,
};
use gearwit_domain::DeliveryRoute;
use gearwit_host::{
    AckRearm, AckStore, AdmittedLink, DeliveryAttempt, DeliveryLedger, GearwitPaths, KnownArm,
    LinkError, LinkSession, LinkTable, ServeAttach, commit_prepared_attach, drop_session,
    prepare_attach, prepare_delivery, read_incoming, read_waiter_link, record_ack,
    record_delivery_result, redeliver_pending, send_delivery, split_stream, write_handled,
    write_prepared_attach,
};
use gearwit_protocol::{Incoming, ProviderEvent, WaiterLink};
use ipcprims::frame::FrameError;
use ipcprims::transport::UnixDomainSocket;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Map drained provider posts to waiter-link events, preserving drain order.
#[must_use]
pub fn provider_events_from_drain(
    events: &[DrainedEvent],
    observed_at: &str,
) -> Vec<ProviderEvent> {
    events
        .iter()
        .map(|event| ProviderEvent {
            provider: "mattermost".to_owned(),
            event_ref: event.id.clone(),
            actor: (!event.username.is_empty()).then(|| event.username.clone()),
            observed_at: observed_at.to_owned(),
            body: event.message.clone(),
        })
        .collect()
}

/// One `(arm, generation, signal)` claim for a drained batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalClaim {
    /// Arm id.
    pub arm_id: String,
    /// Arm generation.
    pub generation: u64,
    /// Stable signal id for this batch.
    pub signal_id: String,
    /// Oldest-first event refs.
    pub event_refs: Vec<String>,
    /// Bounded events held until a waiter can take them.
    pub events: Vec<ProviderEvent>,
}

/// Why a second claim was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimError {
    /// A different batch is already claimed on this arm generation.
    OccupiedDifferent,
}

/// Coverage after one daemon interval. Does not record a handled cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaemonCoverage {
    /// No claim yet; re-arm Chanvoy from this exclusive cursor.
    Rearm {
        /// Next `--after` baseline.
        after: String,
    },
    /// A claim is live and unhandled; do not re-arm provider coverage.
    Pause,
    /// Fail closed and shut down.
    Halt {
        /// Process exit code.
        exit: i32,
    },
}

/// Result of one matched-interval ingest. Never sets `turn_started`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngestOutcome {
    /// Coverage transition. Does not record a handled cursor.
    pub coverage: DaemonCoverage,
    /// Current claim, if any.
    pub claim: Option<SignalClaim>,
    /// Ledger delivery id when a link has prepared a batch.
    pub delivery_id: Option<String>,
    /// True only after a successful `deliver_events` write.
    pub delivery_attempted: bool,
    /// Waiter result token when one was recorded.
    pub result_outcome: Option<String>,
    /// Whether an attached link was present for this ingest.
    pub waiter_attached: bool,
}

/// Send and receive on the current waiter link.
pub trait DeliveryIo {
    /// Write one `deliver_events` frame.
    ///
    /// # Errors
    ///
    /// Returns a static reason when the frame cannot be written.
    fn send(&mut self, message: &WaiterLink) -> Result<(), &'static str>;
    /// Read one `delivery_result` frame.
    ///
    /// # Errors
    ///
    /// Returns a static reason when the result cannot be read.
    fn recv_result(&mut self) -> Result<WaiterLink, &'static str>;
}

/// Claim `events` once for this arm generation.
///
/// # Errors
///
/// Returns [`ClaimError::OccupiedDifferent`] when another batch is live.
pub fn claim_or_reuse(
    current: &mut Option<SignalClaim>,
    arm: &KnownArm,
    events: &[ProviderEvent],
    mint_id: String,
) -> Result<SignalClaim, ClaimError> {
    let event_refs: Vec<String> = events.iter().map(|event| event.event_ref.clone()).collect();
    if let Some(existing) = current {
        if existing.arm_id == arm.arm_id
            && existing.generation == arm.generation
            && existing.events == events
        {
            return Ok(existing.clone());
        }
        return Err(ClaimError::OccupiedDifferent);
    }
    let claim = SignalClaim {
        arm_id: arm.arm_id.clone(),
        generation: arm.generation,
        signal_id: mint_id,
        event_refs,
        events: events.to_vec(),
    };
    *current = Some(claim.clone());
    Ok(claim)
}

fn delivery_id_of(message: &WaiterLink) -> Option<String> {
    match message {
        WaiterLink::DeliverEvents { delivery_id, .. } => Some(delivery_id.clone()),
        _ => None,
    }
}

/// True when `incoming` is the live table session.
///
/// An existing writer blocks it only while that writer still owns `current`.
#[must_use]
pub fn retain_live_attach(
    incoming: &ServeAttach,
    table: &LinkTable,
    existing: Option<&ServeAttach>,
) -> bool {
    let Some(session) = incoming.session.as_ref() else {
        return false;
    };
    let Some(current) = table.current() else {
        return false;
    };
    if current.link_id != session.link_id
        || current.arm_id != session.arm_id
        || current.generation != session.generation
    {
        return false;
    }
    if let Some(existing) = existing
        && let Some(held) = existing.session.as_ref()
        && held.link_id == current.link_id
        && held.arm_id == current.arm_id
        && held.generation == current.generation
    {
        return false;
    }
    true
}

/// How a waiter `delivery_result` should affect the live session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultApply {
    /// Leave the writer in place.
    Keep,
    /// Revoke this session as loss; the batch stays pending.
    RevokeLost,
    /// Revoke this session; the batch is delivered-not-handled.
    RevokeTerminal,
}

/// Record a waiter result. Uncorrelated outcomes are treated as loss.
#[must_use]
pub fn apply_waiter_result(pipe: &mut DaemonPipe, result: &WaiterLink) -> ResultApply {
    if record_delivery_result(&mut pipe.ledger, result).is_ok() {
        match result {
            WaiterLink::DeliveryResult { outcome, .. } if outcome == "link_lost" => {
                pipe.attempted = false;
                ResultApply::RevokeLost
            }
            WaiterLink::DeliveryResult { outcome, .. }
                if outcome == "return_completed" || outcome == "return_failed" =>
            {
                ResultApply::RevokeTerminal
            }
            _ => ResultApply::Keep,
        }
    } else {
        pipe.attempted = false;
        ResultApply::RevokeLost
    }
}

/// Mark the current attempt lost without consuming the batch, then drop `session`.
pub fn on_transport_loss(
    pipe: &mut DaemonPipe,
    table: &mut LinkTable,
    session: Option<&LinkSession>,
    now: OffsetDateTime,
) {
    if pipe.attempted
        && let Some(pending) = pipe.ledger.pending()
        && matches!(pending.attempt, DeliveryAttempt::Awaiting)
        && let WaiterLink::DeliverEvents {
            delivery_id,
            link_id,
            signal_id,
            ..
        } = &pending.message
    {
        let lost = WaiterLink::DeliveryResult {
            schema: gearwit_protocol::SCHEMA.to_owned(),
            delivery_id: delivery_id.clone(),
            link_id: link_id.clone(),
            signal_id: signal_id.clone(),
            outcome: "link_lost".to_owned(),
            observed_at: now
                .format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
        };
        let _ = record_delivery_result(&mut pipe.ledger, &lost);
    }
    pipe.attempted = false;
    if let Some(session) = session {
        drop_session(table, session);
    }
}

/// True when `now` is at or past the admitted lease.
#[must_use]
pub fn lease_expired(lease_until: OffsetDateTime, now: OffsetDateTime) -> bool {
    now >= lease_until
}

fn poll_timeout(lease_until: OffsetDateTime, now: OffsetDateTime) -> Option<Duration> {
    if lease_expired(lease_until, now) {
        return None;
    }
    let remain = lease_until - now;
    let millis = remain.whole_milliseconds().clamp(1, 50);
    let millis = u64::try_from(millis).unwrap_or(50);
    Some(Duration::from_millis(millis))
}

/// Inputs for one wait-interval ingest. Wait match is only a hint.
pub struct IngestRequest<'a, D: EventDrain> {
    /// Coverage spec, including the exclusive `--after` baseline.
    pub spec: &'a WaitOnSpec,
    /// Child wait result. `Matched` triggers drain; other results do not.
    pub wait: WaitResult,
    /// Provider drain used after a match.
    pub drain: &'a D,
    /// Arm currently covered.
    pub arm: &'a KnownArm,
    /// Live waiter, if any.
    pub link: Option<&'a AdmittedLink>,
    /// Clock for `observed_at` / `attempted_at`.
    pub now: OffsetDateTime,
}

/// Ledger, claim, and attempt flag mutated by ingest.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DaemonPipe {
    /// Pending `deliver_events` batch.
    pub ledger: DeliveryLedger,
    /// Current `(arm, generation, signal)` claim.
    pub claim: Option<SignalClaim>,
    /// True after a successful delivery write for the pending batch.
    pub attempted: bool,
}

impl DaemonPipe {
    fn snapshot(&self, coverage: DaemonCoverage, waiter_attached: bool) -> IngestOutcome {
        IngestOutcome {
            coverage,
            claim: self.claim.clone(),
            delivery_id: self
                .ledger
                .pending()
                .map(|pending| pending.delivery_id.clone()),
            delivery_attempted: self.attempted,
            result_outcome: None,
            waiter_attached,
        }
    }
}

fn daemon_coverage(wait: WaitResult, current_after: &str) -> DaemonCoverage {
    match wait {
        WaitResult::Timeout => DaemonCoverage::Rearm {
            after: current_after.to_owned(),
        },
        WaitResult::Error => DaemonCoverage::Halt { exit: 2 },
        WaitResult::Matched => DaemonCoverage::Pause,
    }
}

/// Drain from the exclusive wait baseline, claim once, optionally deliver.
///
/// A wait match is only a hint: events always come from `drain`.
/// `note_claimed` runs on a new stable claim; `note_delivered` runs only
/// after a successful delivery write.
#[must_use]
pub fn ingest_match<D: EventDrain, I: DeliveryIo>(
    request: &IngestRequest<'_, D>,
    pipe: &mut DaemonPipe,
    acks: &mut AckStore,
    io: Option<&mut I>,
    mint_signal: impl FnOnce() -> String,
) -> IngestOutcome {
    let current_after = request.spec.after.clone().unwrap_or_default();
    let waiter_attached = request.link.is_some();
    if request.wait != WaitResult::Matched {
        return pipe.snapshot(
            daemon_coverage(request.wait, &current_after),
            waiter_attached,
        );
    }

    let hinted = WaitOutcome {
        waiter: WaiterState::Completed,
        result: WaitResult::Matched,
        chanvoy_exit: Some(0),
        process_exit: 0,
        drained_events: Vec::new(),
        newest_observed: None,
        drain_error: None,
    };
    let drained = attach_drain(hinted, request.spec, request.drain);
    if drained.drain_error.is_some() || drained.newest_observed.is_none() {
        return pipe.snapshot(DaemonCoverage::Halt { exit: 2 }, waiter_attached);
    }

    let observed = request
        .now
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
    let events = provider_events_from_drain(&drained.drained_events, &observed);
    let is_new = pipe.claim.is_none();
    match claim_or_reuse(&mut pipe.claim, request.arm, &events, mint_signal()) {
        Ok(live) => {
            if is_new && acks.note_claimed(live.signal_id.clone()).is_err() {
                return pipe.snapshot(DaemonCoverage::Halt { exit: 2 }, waiter_attached);
            }
            deliver_claimed(
                live,
                request.link,
                pipe,
                acks,
                request.now,
                io,
                DaemonCoverage::Pause,
            )
        }
        Err(ClaimError::OccupiedDifferent) => pipe.snapshot(DaemonCoverage::Pause, waiter_attached),
    }
}

fn deliver_claimed<I: DeliveryIo>(
    live: SignalClaim,
    link: Option<&AdmittedLink>,
    pipe: &mut DaemonPipe,
    acks: &mut AckStore,
    now: OffsetDateTime,
    io: Option<&mut I>,
    coverage: DaemonCoverage,
) -> IngestOutcome {
    let waiter_attached = link.is_some();
    let Some(link) = link else {
        return IngestOutcome {
            coverage,
            claim: Some(live),
            delivery_id: None,
            delivery_attempted: false,
            result_outcome: None,
            waiter_attached: false,
        };
    };

    let message = if pipe.ledger.should_redeliver() {
        redeliver_pending(&mut pipe.ledger, link, now)
    } else {
        prepare_delivery(
            &mut pipe.ledger,
            link,
            live.signal_id.clone(),
            live.events.clone(),
            now,
        )
    };
    let Ok(message) = message else {
        return pipe.snapshot(coverage, waiter_attached);
    };

    let delivery_id = delivery_id_of(&message);
    let Some(io) = io else {
        pipe.attempted = false;
        return IngestOutcome {
            coverage,
            claim: Some(live),
            delivery_id,
            delivery_attempted: false,
            result_outcome: None,
            waiter_attached,
        };
    };

    if pipe.attempted
        && pipe
            .ledger
            .pending()
            .is_some_and(|pending| matches!(pending.attempt, DeliveryAttempt::Awaiting))
    {
        return IngestOutcome {
            coverage,
            claim: Some(live),
            delivery_id,
            delivery_attempted: true,
            result_outcome: None,
            waiter_attached,
        };
    }

    if io.send(&message).is_err() {
        pipe.attempted = false;
        return IngestOutcome {
            coverage,
            claim: Some(live),
            delivery_id,
            delivery_attempted: false,
            result_outcome: None,
            waiter_attached,
        };
    }
    let delivered = match &message {
        WaiterLink::DeliverEvents { events, .. } => events
            .iter()
            .map(|event| event.event_ref.clone())
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    if acks
        .note_delivered(live.signal_id.clone(), delivered, &live.event_refs)
        .is_err()
    {
        return pipe.snapshot(DaemonCoverage::Halt { exit: 2 }, waiter_attached);
    }
    pipe.attempted = true;
    let mut result_outcome = None;
    if let Ok(result) = io.recv_result()
        && record_delivery_result(&mut pipe.ledger, &result).is_ok()
        && let WaiterLink::DeliveryResult { outcome, .. } = &result
    {
        result_outcome = Some(outcome.clone());
        if outcome == "link_lost" {
            pipe.attempted = false;
        }
    }
    IngestOutcome {
        coverage,
        claim: pipe.claim.clone().or(Some(live)),
        delivery_id,
        delivery_attempted: pipe.attempted || result_outcome.is_some(),
        result_outcome,
        waiter_attached,
    }
}

fn seat_id() -> String {
    std::env::var("LANYTE_AGENT_ROLE")
        .ok()
        .filter(|role| {
            let bytes = role.as_bytes();
            (1..=63).contains(&bytes.len())
                && bytes[0].is_ascii_lowercase()
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        })
        .unwrap_or_else(|| "gearwit-seat".to_owned())
}

struct LinkIo<'a> {
    served: &'a mut ServeAttach,
}

impl DeliveryIo for LinkIo<'_> {
    fn send(&mut self, message: &WaiterLink) -> Result<(), &'static str> {
        send_delivery(&mut self.served.writer, message).map_err(|_| "send")
    }

    fn recv_result(&mut self) -> Result<WaiterLink, &'static str> {
        Err("deferred")
    }
}

/// Report from tearing down coverage, the child, and the session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownReport {
    /// Child was killed/reaped or the slot was already empty.
    pub child_reaped: bool,
    /// Live waiter link after drop.
    pub link_live: bool,
}

/// Wake and join the accept worker, then kill the child and drop the live session.
///
/// Stop/wake/join happen before any table lock so an in-flight accept cannot deadlock.
///
/// # Errors
///
/// Returns child kill/wait errors. The accept worker is still joined.
pub fn shutdown_daemon(
    table: &mut LinkTable,
    children: &mut ChildSlot,
    stop: &AtomicBool,
    socket: Option<&std::path::Path>,
    accept: &mut Option<thread::JoinHandle<()>>,
) -> std::io::Result<ShutdownReport> {
    stop.store(true, Ordering::SeqCst);
    if let Some(path) = socket {
        let _ = UnixDomainSocket::connect(path);
    }
    if let Some(handle) = accept.take() {
        let _ = handle.join();
    }
    let child = children.kill_and_reap()?;
    if let Some(current) = table.current() {
        let session = LinkSession {
            link_id: current.link_id.clone(),
            arm_id: current.arm_id.clone(),
            generation: current.generation,
        };
        drop_session(table, &session);
    }
    table.drop_current();
    Ok(ShutdownReport {
        child_reaped: child.reaped || !children.occupied(),
        link_live: table.current().is_some(),
    })
}

enum DaemonEvent {
    Attached(Box<ServeAttach>),
    CoverageRearm(AckRearm),
}

fn lock_table(table: &Mutex<LinkTable>) -> std::sync::MutexGuard<'_, LinkTable> {
    table
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock_acks(acks: &Mutex<AckStore>) -> std::sync::MutexGuard<'_, AckStore> {
    acks.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Apply a first-accepted ACK to coverage. Returns false when already applied.
#[must_use]
pub fn take_coverage_rearm(
    spec: &mut WaitOnSpec,
    arm: &mut KnownArm,
    pipe: &mut DaemonPipe,
    rearm: &AckRearm,
) -> bool {
    if arm.generation == rearm.generation
        && spec.after.as_deref() == Some(rearm.after.as_str())
        && pipe.claim.is_none()
        && pipe.ledger.pending().is_none()
    {
        return false;
    }
    arm.generation = rearm.generation;
    spec.after = Some(rearm.after.clone());
    pipe.claim = None;
    pipe.ledger = DeliveryLedger::default();
    pipe.attempted = false;
    true
}

fn revoke_older_generation(
    served: &mut Option<ServeAttach>,
    table: &mut LinkTable,
    generation: u64,
) {
    let old = served.as_ref().and_then(|served| served.session.clone());
    if old
        .as_ref()
        .is_some_and(|session| session.generation < generation)
    {
        let session = served.take().and_then(|served| served.session);
        if let Some(session) = session.as_ref() {
            drop_session(table, session);
        }
    }
    if table
        .current()
        .is_some_and(|current| current.generation < generation)
    {
        table.drop_current();
    }
}

/// Child spawn/reap used when an accepted ACK rearms coverage.
pub trait CoverageChild {
    /// Kill the live coverage child if any.
    ///
    /// # Errors
    ///
    /// Returns `2` when reap fails.
    fn kill_and_reap(&mut self) -> Result<(), i32>;
    /// Start exactly one successor from `spec`.
    ///
    /// # Errors
    ///
    /// Returns `2` when spawn fails.
    fn spawn(&mut self, spec: &WaitOnSpec) -> Result<(), i32>;
}

impl CoverageChild for ChildSlot {
    fn kill_and_reap(&mut self) -> Result<(), i32> {
        ChildSlot::kill_and_reap(self).map(|_| ()).map_err(|_| 2)
    }

    fn spawn(&mut self, spec: &WaitOnSpec) -> Result<(), i32> {
        spawn_chanvoy(self, spec).map(|_| ())
    }
}

/// Record-then-rearm coverage: one reap and one spawn, or neither on replay.
///
/// # Errors
///
/// Returns `2` when child kill or spawn fails. Kill is not followed by spawn
/// on kill failure.
pub fn restart_after_ack<C: CoverageChild>(
    rearm: &AckRearm,
    spec: &mut WaitOnSpec,
    arm: &mut KnownArm,
    pipe: &mut DaemonPipe,
    served: &mut Option<ServeAttach>,
    table: &mut LinkTable,
    children: &mut C,
) -> Result<(), i32> {
    if !take_coverage_rearm(spec, arm, pipe, rearm) {
        return Ok(());
    }
    revoke_older_generation(served, table, rearm.generation);
    children.kill_and_reap()?;
    children.spawn(spec)
}

fn halt(
    table: &Mutex<LinkTable>,
    children: &mut ChildSlot,
    stop: &AtomicBool,
    socket: &std::path::Path,
    accept: &mut Option<thread::JoinHandle<()>>,
    code: i32,
) -> i32 {
    stop.store(true, Ordering::SeqCst);
    let _ = UnixDomainSocket::connect(socket);
    if let Some(handle) = accept.take() {
        let _ = handle.join();
    }
    let child = children.kill_and_reap();
    {
        let mut table = lock_table(table);
        if let Some(current) = table.current() {
            let session = LinkSession {
                link_id: current.link_id.clone(),
                arm_id: current.arm_id.clone(),
                generation: current.generation,
            };
            drop_session(&mut table, &session);
        }
        table.drop_current();
    }
    if child.is_err() { 2 } else { code }
}

fn spawn_chanvoy(slot: &mut ChildSlot, spec: &WaitOnSpec) -> Result<u32, i32> {
    slot.spawn("chanvoy", &chanvoy_wait_args(spec))
        .map_err(|error| {
            eprintln!("gearwit: chanvoy child: {error}");
            2
        })
}

fn current_link(table: &Mutex<LinkTable>) -> Option<AdmittedLink> {
    lock_table(table).current().cloned()
}

fn set_poll_timeout(
    served: &mut ServeAttach,
    lease_until: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), LinkError> {
    let timeout = poll_timeout(lease_until, now).ok_or(LinkError::Message(
        gearwit_protocol::WaiterLinkError::Semantic("lease expired"),
    ))?;
    served
        .reader
        .get_mut()
        .set_read_timeout(Some(timeout))
        .map_err(|_| {
            LinkError::Message(gearwit_protocol::WaiterLinkError::Semantic("timeout setup"))
        })
}

fn is_read_idle(error: &LinkError) -> bool {
    matches!(
        error,
        LinkError::Frame(FrameError::Io(io))
            if io.kind() == std::io::ErrorKind::TimedOut
                || io.kind() == std::io::ErrorKind::WouldBlock
    )
}

fn flush_attached(
    served: &mut ServeAttach,
    link: Option<&AdmittedLink>,
    pipe: &mut DaemonPipe,
    acks: &mut AckStore,
    now: OffsetDateTime,
) -> bool {
    if pipe
        .ledger
        .pending()
        .is_some_and(|pending| matches!(pending.attempt, DeliveryAttempt::Terminal(_)))
    {
        return false;
    }
    let Some(live) = pipe.claim.clone() else {
        return false;
    };
    let Some(link) = link else {
        return false;
    };
    if lease_expired(link.lease_until, now) {
        return true;
    }
    let mut io = LinkIo { served };
    let outcome = deliver_claimed(
        live,
        Some(link),
        pipe,
        acks,
        now,
        Some(&mut io),
        DaemonCoverage::Pause,
    );
    outcome.delivery_id.is_some() && !outcome.delivery_attempted
}

fn revoke_exact(
    served: &mut Option<ServeAttach>,
    table: &Mutex<LinkTable>,
    pipe: &mut DaemonPipe,
    now: OffsetDateTime,
    mark_lost: bool,
) {
    let session = served.as_ref().and_then(|served| served.session.clone());
    let mut table = lock_table(table);
    if mark_lost {
        on_transport_loss(pipe, &mut table, session.as_ref(), now);
    } else if let Some(session) = session.as_ref() {
        drop_session(&mut table, session);
    }
    drop(table);
    *served = None;
}

fn poll_result(
    served: &mut Option<ServeAttach>,
    table: &Mutex<LinkTable>,
    pipe: &mut DaemonPipe,
    now: OffsetDateTime,
) {
    if served.is_none() {
        return;
    }
    let session = served.as_ref().and_then(|served| served.session.clone());
    let lease_until = {
        let locked = lock_table(table);
        locked.current().and_then(|link| {
            session.as_ref().and_then(|session| {
                (link.link_id == session.link_id
                    && link.arm_id == session.arm_id
                    && link.generation == session.generation)
                    .then_some(link.lease_until)
            })
        })
    };
    if let Some(lease_until) = lease_until {
        if lease_expired(lease_until, now) {
            revoke_exact(served, table, pipe, now, true);
            return;
        }
        let timeout_failed = served
            .as_mut()
            .is_some_and(|current| set_poll_timeout(current, lease_until, now).is_err());
        if timeout_failed {
            revoke_exact(served, table, pipe, now, true);
            return;
        }
    } else if session.is_some() {
        revoke_exact(served, table, pipe, now, true);
        return;
    }
    let read = served
        .as_mut()
        .map(|current| read_waiter_link(&mut current.reader));
    match read {
        Some(Ok(result)) => match apply_waiter_result(pipe, &result) {
            ResultApply::Keep => {}
            ResultApply::RevokeLost => revoke_exact(served, table, pipe, now, true),
            ResultApply::RevokeTerminal => revoke_exact(served, table, pipe, now, false),
        },
        Some(Err(error)) if is_read_idle(&error) => {}
        Some(Err(_)) | None => revoke_exact(served, table, pipe, now, true),
    }
}

fn spawn_accept(
    listener: gearwit_host::BoundListener,
    table: Arc<Mutex<LinkTable>>,
    acks: Arc<Mutex<AckStore>>,
    stop: Arc<AtomicBool>,
    tx: mpsc::Sender<DaemonEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            let Ok(stream) = listener.accept() else {
                break;
            };
            if stop.load(Ordering::SeqCst) {
                break;
            }
            let started = Instant::now();
            let instant = OffsetDateTime::now_utc();
            let Ok((mut reader, mut writer)) = split_stream(stream) else {
                continue;
            };
            let Ok(incoming) = read_incoming(&mut reader) else {
                continue;
            };
            match incoming {
                Incoming::Waiter(request) => {
                    let arms: Vec<KnownArm> = lock_acks(&acks).arm().cloned().into_iter().collect();
                    let prepared = {
                        let mut table = lock_table(&table);
                        prepare_attach(&mut table, request, instant, started, &arms)
                    };
                    let Ok(prepared) = prepared else {
                        continue;
                    };
                    let write_ok =
                        write_prepared_attach(&mut reader, &mut writer, &prepared).is_ok();
                    let served = {
                        let mut table = lock_table(&table);
                        commit_prepared_attach(&mut table, prepared, reader, writer, write_ok)
                    };
                    if let Some(served) = served
                        && tx.send(DaemonEvent::Attached(Box::new(served))).is_err()
                    {
                        break;
                    }
                }
                Incoming::Handled(request) => {
                    let served = {
                        let mut acks = lock_acks(&acks);
                        record_ack(&mut acks, request, instant)
                    };
                    let Ok(served) = served else {
                        continue;
                    };
                    let _ = write_handled(&mut writer, &served.reply);
                    if let Some(rearm) = served.rearm
                        && tx.send(DaemonEvent::CoverageRearm(rearm)).is_err()
                    {
                        break;
                    }
                }
            }
        }
    })
}

fn ingest_child_exit(
    status: std::process::ExitStatus,
    spec: &WaitOnSpec,
    arm: &KnownArm,
    link: Option<&AdmittedLink>,
    pipe: &mut DaemonPipe,
    acks: &mut AckStore,
) -> DaemonCoverage {
    ingest_match(
        &IngestRequest {
            spec,
            wait: WaitResult::from_code(status.code().unwrap_or(2)),
            drain: &ChanvoyDrain,
            arm,
            link,
            now: OffsetDateTime::now_utc(),
        },
        pipe,
        acks,
        None::<&mut LinkIo>,
        || ulid::Ulid::new().to_string(),
    )
    .coverage
}

fn bind_runtime() -> Result<(gearwit_host::BoundListener, std::path::PathBuf, KnownArm), i32> {
    let paths = GearwitPaths::user_default().map_err(|error| {
        eprintln!("gearwit: {error}");
        2
    })?;
    let listener = paths.bind().map_err(|error| {
        eprintln!("gearwit: {error}");
        2
    })?;
    let socket = paths.socket_path();
    let now = OffsetDateTime::now_utc();
    let arm = KnownArm {
        arm_id: ulid::Ulid::new().to_string(),
        generation: 1,
        seat_id: seat_id(),
        route: DeliveryRoute::CompleteBackgroundTool.as_str().to_owned(),
        coverage_until: now + time::Duration::minutes(20),
    };
    eprintln!(
        "gearwit daemon wait-on\nsocket: {}\narm_id: {}\ngeneration: {}\nseat_id: {}\nroute: {}\n",
        socket.display(),
        arm.arm_id,
        arm.generation,
        arm.seat_id,
        arm.route
    );
    Ok((listener, socket, arm))
}

/// Bind the waiter-link, print arm coordinates, cover Chanvoy, deliver to an attached waiter.
#[must_use]
pub fn run_daemon_wait(spec: WaitOnSpec) -> i32 {
    let (listener, socket, arm) = match bind_runtime() {
        Ok(bound) => bound,
        Err(code) => return code,
    };

    let table = Arc::new(Mutex::new(LinkTable::default()));
    let acks = Arc::new(Mutex::new(AckStore::with_arm(arm.clone())));
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let mut accept = Some(spawn_accept(
        listener,
        Arc::clone(&table),
        Arc::clone(&acks),
        Arc::clone(&stop),
        tx,
    ));

    let mut spec = spec;
    spec.follow = true;
    let mut children = ChildSlot::new();
    let mut pipe = DaemonPipe::default();
    let mut arm = arm;
    let mut served: Option<ServeAttach> = None;
    if spawn_chanvoy(&mut children, &spec).is_err() {
        return halt(&table, &mut children, &stop, &socket, &mut accept, 2);
    }

    loop {
        let now = OffsetDateTime::now_utc();
        if now >= arm.coverage_until {
            return halt(&table, &mut children, &stop, &socket, &mut accept, 1);
        }
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(DaemonEvent::Attached(next)) => {
                adopt_attached(next, &mut served, &table, &mut pipe, &acks, now);
            }
            Ok(DaemonEvent::CoverageRearm(rearm)) => {
                let result = {
                    let mut locked = lock_table(&table);
                    restart_after_ack(
                        &rearm,
                        &mut spec,
                        &mut arm,
                        &mut pipe,
                        &mut served,
                        &mut locked,
                        &mut children,
                    )
                };
                if let Err(code) = result {
                    return halt(&table, &mut children, &stop, &socket, &mut accept, code);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return halt(&table, &mut children, &stop, &socket, &mut accept, 2);
            }
        }
        poll_result(&mut served, &table, &mut pipe, now);
        if let Some(code) = poll_chanvoy(
            &mut LoopIo {
                children: &mut children,
                spec: &mut spec,
                arm: &arm,
                table: &table,
                pipe: &mut pipe,
                acks: &acks,
                served: &mut served,
            },
            now,
        ) {
            return halt(&table, &mut children, &stop, &socket, &mut accept, code);
        }
    }
}

struct LoopIo<'a> {
    children: &'a mut ChildSlot,
    spec: &'a mut WaitOnSpec,
    arm: &'a KnownArm,
    table: &'a Mutex<LinkTable>,
    pipe: &'a mut DaemonPipe,
    acks: &'a Mutex<AckStore>,
    served: &'a mut Option<ServeAttach>,
}

fn adopt_attached(
    next: Box<ServeAttach>,
    served: &mut Option<ServeAttach>,
    table: &Mutex<LinkTable>,
    pipe: &mut DaemonPipe,
    acks: &Mutex<AckStore>,
    now: OffsetDateTime,
) {
    let keep = {
        let locked = lock_table(table);
        retain_live_attach(&next, &locked, served.as_ref())
    };
    if !keep {
        return;
    }
    if let Some(old) = served.take() {
        let old_session = old.session.clone();
        drop(old);
        if let Some(old_session) = old_session {
            let mut locked = lock_table(table);
            on_transport_loss(pipe, &mut locked, Some(&old_session), now);
        }
    }
    let mut next = *next;
    let lease_until = lock_table(table).current().map(|link| link.lease_until);
    let timeout_failed = match lease_until {
        Some(lease_until) => {
            set_poll_timeout(&mut next, lease_until, now).is_err()
                || lease_expired(lease_until, now)
        }
        None => false,
    };
    *served = Some(next);
    if timeout_failed || flush_current(served, table, pipe, acks, now) {
        revoke_exact(served, table, pipe, now, true);
    }
}

fn poll_chanvoy(io: &mut LoopIo<'_>, now: OffsetDateTime) -> Option<i32> {
    match io.children.try_wait() {
        Ok(Some(status)) => {
            let coverage = {
                let link = current_link(io.table);
                let mut acks = lock_acks(io.acks);
                ingest_child_exit(status, io.spec, io.arm, link.as_ref(), io.pipe, &mut acks)
            };
            match coverage {
                DaemonCoverage::Rearm { after } => {
                    io.spec.after = Some(after);
                    spawn_chanvoy(io.children, io.spec).err()
                }
                DaemonCoverage::Pause => {
                    if flush_current(io.served, io.table, io.pipe, io.acks, now) {
                        revoke_exact(io.served, io.table, io.pipe, now, true);
                    }
                    None
                }
                DaemonCoverage::Halt { exit } => Some(exit),
            }
        }
        Ok(None) => None,
        Err(error) => {
            eprintln!("gearwit: chanvoy child: {error}");
            Some(2)
        }
    }
}

fn flush_current(
    served: &mut Option<ServeAttach>,
    table: &Mutex<LinkTable>,
    pipe: &mut DaemonPipe,
    acks: &Mutex<AckStore>,
    now: OffsetDateTime,
) -> bool {
    let link = current_link(table);
    served.as_mut().is_some_and(|current| {
        let mut acks = lock_acks(acks);
        flush_attached(current, link.as_ref(), pipe, &mut acks, now)
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ClaimError, CoverageChild, DaemonCoverage, DeliveryIo, IngestOutcome, ResultApply,
        apply_waiter_result, claim_or_reuse, ingest_match, lease_expired, on_transport_loss,
        provider_events_from_drain, restart_after_ack, retain_live_attach, shutdown_daemon,
        spawn_accept, take_coverage_rearm,
    };
    use crate::child::ChildSlot;
    use crate::wait_on::{DrainError, DrainedEvent, EventDrain, WaitOnSpec, WaitResult};
    use gearwit_host::{
        AckRearm, AckStore, DeliveryAttempt, GearwitPaths, KnownArm, LinkSession, LinkTable,
        admit_attach,
    };
    use gearwit_protocol::{ProviderEvent, SCHEMA, WaiterLink, parse_waiter_link};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use time::format_description::well_known::Rfc3339;
    use time::{Duration as TimeDuration, OffsetDateTime};

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-01-15T12:05:00Z", &Rfc3339).expect("now")
    }

    fn arm() -> KnownArm {
        KnownArm {
            arm_id: "01J00000000000000000000010".to_owned(),
            generation: 1,
            seat_id: "example-devrev".to_owned(),
            route: "complete_background_tool".to_owned(),
            coverage_until: now() + TimeDuration::minutes(20),
        }
    }

    fn spec() -> WaitOnSpec {
        WaitOnSpec {
            channel: "gearwit-e2e".to_owned(),
            after: Some("cursor1".to_owned()),
            timeout: "20m".to_owned(),
            team: Some("org-lanytehq".to_owned()),
            source: "chanvoy".to_owned(),
            return_route: gearwit_domain::DeliveryRoute::NotifyOperator,
            follow: true,
        }
    }

    fn event(id: &str, body: &str) -> DrainedEvent {
        DrainedEvent {
            id: id.to_owned(),
            username: "peer".to_owned(),
            message: body.to_owned(),
        }
    }

    fn fixture_attach() -> WaiterLink {
        parse_waiter_link(include_str!(
            "../../gearwit-protocol/fixtures/waiter-link/conforming/attach-waiter.json"
        ))
        .expect("fixture")
    }

    fn admitted() -> (LinkTable, gearwit_host::AdmittedLink) {
        let instant = now();
        let mut table = LinkTable::default();
        admit_attach(&mut table, fixture_attach(), instant, &[arm()]).expect("admit");
        let link = table.current().expect("link").clone();
        (table, link)
    }

    struct FixedDrain {
        after: Mutex<Option<String>>,
        result: Result<Vec<DrainedEvent>, DrainError>,
    }

    impl EventDrain for FixedDrain {
        fn drain_after(&self, spec: &WaitOnSpec) -> Result<Vec<DrainedEvent>, DrainError> {
            *self.after.lock().expect("drain after") = spec.after.clone();
            self.result.clone()
        }
    }

    struct ScriptedIo {
        fail_send: bool,
        sent: Option<WaiterLink>,
        complete: bool,
    }

    impl DeliveryIo for ScriptedIo {
        fn send(&mut self, message: &WaiterLink) -> Result<(), &'static str> {
            if self.fail_send {
                return Err("write");
            }
            self.sent = Some(message.clone());
            Ok(())
        }

        fn recv_result(&mut self) -> Result<WaiterLink, &'static str> {
            let WaiterLink::DeliverEvents {
                delivery_id,
                link_id,
                signal_id,
                ..
            } = self.sent.as_ref().ok_or("no send")?
            else {
                return Err("type");
            };
            if !self.complete {
                return Err("disconnected");
            }
            Ok(WaiterLink::DeliveryResult {
                schema: SCHEMA.to_owned(),
                delivery_id: delivery_id.clone(),
                link_id: link_id.clone(),
                signal_id: signal_id.clone(),
                outcome: "return_completed".to_owned(),
                observed_at: "2026-01-15T12:05:03Z".to_owned(),
            })
        }
    }

    fn provider(id: &str) -> ProviderEvent {
        ProviderEvent {
            provider: "mattermost".to_owned(),
            event_ref: id.to_owned(),
            actor: Some("peer".to_owned()),
            observed_at: "2026-01-15T12:05:00Z".to_owned(),
            body: "body".to_owned(),
        }
    }

    fn ingest(
        wait: WaitResult,
        drain: &FixedDrain,
        link: Option<&gearwit_host::AdmittedLink>,
        pipe: &mut super::DaemonPipe,
        io: Option<&mut ScriptedIo>,
        mint: &str,
    ) -> IngestOutcome {
        let mut acks = AckStore::with_arm(arm());
        ingest_with_acks(wait, drain, link, pipe, &mut acks, io, mint)
    }

    fn ingest_with_acks(
        wait: WaitResult,
        drain: &FixedDrain,
        link: Option<&gearwit_host::AdmittedLink>,
        pipe: &mut super::DaemonPipe,
        acks: &mut AckStore,
        io: Option<&mut ScriptedIo>,
        mint: &str,
    ) -> IngestOutcome {
        ingest_match(
            &super::IngestRequest {
                spec: &spec(),
                wait,
                drain,
                arm: &arm(),
                link,
                now: now(),
            },
            pipe,
            acks,
            io,
            || mint.to_owned(),
        )
    }

    #[test]
    fn drain_maps_oldest_first_bodies() {
        let events = vec![
            event("post02", "first bounded event"),
            DrainedEvent {
                id: "post03".to_owned(),
                username: String::new(),
                message: "second bounded event".to_owned(),
            },
        ];
        let mapped = provider_events_from_drain(&events, "2026-01-15T12:05:00Z");
        assert_eq!(mapped[0].event_ref, "post02");
        assert_eq!(mapped[0].body, "first bounded event");
        assert_eq!(mapped[1].event_ref, "post03");
        assert!(mapped[1].actor.is_none());
    }

    #[test]
    fn wait_match_is_hint_drain_uses_exclusive_baseline() {
        let drain = FixedDrain {
            after: Mutex::new(None),
            result: Ok(vec![event("post02", "one"), event("post03", "two")]),
        };
        let mut pipe = super::DaemonPipe::default();
        let outcome = ingest(
            WaitResult::Matched,
            &drain,
            None,
            &mut pipe,
            None,
            "01J00000000000000000000021",
        );
        assert_eq!(
            drain.after.lock().expect("after").as_deref(),
            Some("cursor1")
        );
        assert_eq!(
            pipe.claim.as_ref().map(|claim| claim.event_refs.clone()),
            Some(vec!["post02".to_owned(), "post03".to_owned()])
        );
        assert!(!outcome.delivery_attempted);
        assert!(outcome.delivery_id.is_none());
        assert!(!outcome.waiter_attached);
        assert_eq!(outcome.coverage, DaemonCoverage::Pause);
    }

    #[test]
    fn no_waiter_keeps_claimed_batch_pending() {
        let drain = FixedDrain {
            after: Mutex::new(None),
            result: Ok(vec![event("post02", "one")]),
        };
        let mut pipe = super::DaemonPipe::default();
        let outcome = ingest(
            WaitResult::Matched,
            &drain,
            None,
            &mut pipe,
            None,
            "01J00000000000000000000021",
        );
        assert!(pipe.claim.is_some());
        assert!(pipe.ledger.pending().is_none());
        assert!(!outcome.delivery_attempted);
        assert_eq!(
            pipe.claim.as_ref().map(|c| c.signal_id.as_str()),
            Some("01J00000000000000000000021")
        );
        let same = pipe.claim.as_ref().expect("claim").events.clone();
        let again = claim_or_reuse(
            &mut pipe.claim,
            &arm(),
            &same,
            "01J00000000000000000000099".to_owned(),
        )
        .expect("reuse");
        assert_eq!(again.signal_id, "01J00000000000000000000021");
        assert!(matches!(
            claim_or_reuse(
                &mut pipe.claim,
                &arm(),
                &[provider("post02")],
                "01J00000000000000000000098".to_owned(),
            ),
            Err(ClaimError::OccupiedDifferent)
        ));
    }

    #[test]
    fn write_failure_leaves_same_delivery_pending() {
        let (_table, link) = admitted();
        let drain = FixedDrain {
            after: Mutex::new(None),
            result: Ok(vec![event("post02", "one")]),
        };
        let mut pipe = super::DaemonPipe::default();
        let mut io = ScriptedIo {
            fail_send: true,
            sent: None,
            complete: false,
        };
        let first = ingest(
            WaitResult::Matched,
            &drain,
            Some(&link),
            &mut pipe,
            Some(&mut io),
            "01J00000000000000000000021",
        );
        let id = first.delivery_id.clone().expect("id");
        assert!(!first.delivery_attempted);
        assert!(pipe.ledger.should_redeliver());
        assert!(matches!(
            pipe.ledger.pending().map(|pending| &pending.attempt),
            Some(DeliveryAttempt::Awaiting)
        ));
        io.fail_send = false;
        io.complete = false;
        let second = ingest(
            WaitResult::Matched,
            &drain,
            Some(&link),
            &mut pipe,
            Some(&mut io),
            "01J00000000000000000000099",
        );
        assert_eq!(second.delivery_id.as_deref(), Some(id.as_str()));
        assert!(second.delivery_attempted);
        assert!(second.result_outcome.is_none());
        assert!(pipe.ledger.should_redeliver());
    }

    #[test]
    fn successful_write_is_attempted_result_does_not_start_turn() {
        let (_table, link) = admitted();
        let drain = FixedDrain {
            after: Mutex::new(None),
            result: Ok(vec![event("post02", "one")]),
        };
        let mut pipe = super::DaemonPipe::default();
        let mut acks = AckStore::with_arm(arm());
        let mut io = ScriptedIo {
            fail_send: false,
            sent: None,
            complete: true,
        };
        let outcome = ingest_with_acks(
            WaitResult::Matched,
            &drain,
            Some(&link),
            &mut pipe,
            &mut acks,
            Some(&mut io),
            "01J00000000000000000000021",
        );
        assert!(outcome.delivery_attempted);
        assert_eq!(outcome.result_outcome.as_deref(), Some("return_completed"));
        assert!(!pipe.ledger.should_redeliver());
        assert!(pipe.claim.is_some());
        assert_eq!(outcome.coverage, DaemonCoverage::Pause);
        let sent = io.sent.expect("sent");
        assert!(matches!(sent, WaiterLink::DeliverEvents { .. }));
        let accepted = gearwit_host::record_handled(
            &mut acks,
            gearwit_protocol::parse_handled_cursor(include_str!(
                "../../gearwit-protocol/fixtures/handled-cursor/conforming/request-prefix.json"
            ))
            .expect("request"),
            now(),
        )
        .expect("ack");
        assert!(matches!(
            accepted,
            gearwit_protocol::HandledCursor::Accepted { ref cursor, .. } if cursor == "post02"
        ));
    }

    #[test]
    fn write_failure_does_not_admit_delivery_for_ack() {
        let (_table, link) = admitted();
        let drain = FixedDrain {
            after: Mutex::new(None),
            result: Ok(vec![event("post02", "one")]),
        };
        let mut pipe = super::DaemonPipe::default();
        let mut acks = AckStore::with_arm(arm());
        let mut io = ScriptedIo {
            fail_send: true,
            sent: None,
            complete: false,
        };
        ingest_with_acks(
            WaitResult::Matched,
            &drain,
            Some(&link),
            &mut pipe,
            &mut acks,
            Some(&mut io),
            "01J00000000000000000000021",
        );
        let reply = gearwit_host::record_handled(
            &mut acks,
            gearwit_protocol::parse_handled_cursor(include_str!(
                "../../gearwit-protocol/fixtures/handled-cursor/conforming/request-prefix.json"
            ))
            .expect("request"),
            now(),
        )
        .expect("ack before delivery");
        assert!(matches!(
            reply,
            gearwit_protocol::HandledCursor::Rejected { code, .. } if code == "ack_before_delivery"
        ));
    }

    #[test]
    fn prefix_coverage_rearm_is_idempotent_and_clears_claim() {
        let mut spec = spec();
        let mut live = arm();
        let mut pipe = super::DaemonPipe {
            claim: Some(super::SignalClaim {
                arm_id: live.arm_id.clone(),
                generation: 1,
                signal_id: "01J00000000000000000000021".to_owned(),
                event_refs: vec!["post02".to_owned(), "post03".to_owned()],
                events: vec![provider("post02"), provider("post03")],
            }),
            attempted: true,
            ..super::DaemonPipe::default()
        };
        let rearm = AckRearm {
            after: "post02".to_owned(),
            generation: 2,
            signal_id: "01J00000000000000000000021".to_owned(),
        };
        assert!(take_coverage_rearm(&mut spec, &mut live, &mut pipe, &rearm));
        assert_eq!(spec.after.as_deref(), Some("post02"));
        assert_eq!(live.generation, 2);
        assert!(pipe.claim.is_none());
        assert!(!pipe.attempted);
        assert!(!take_coverage_rearm(
            &mut spec, &mut live, &mut pipe, &rearm
        ));
        assert_eq!(live.generation, 2);
    }

    #[derive(Default)]
    struct ScriptedChild {
        kills: usize,
        spawns: Vec<Option<String>>,
        fail_kill: bool,
        fail_spawn: bool,
    }

    impl CoverageChild for ScriptedChild {
        fn kill_and_reap(&mut self) -> Result<(), i32> {
            if self.fail_kill {
                return Err(2);
            }
            self.kills += 1;
            Ok(())
        }

        fn spawn(&mut self, spec: &WaitOnSpec) -> Result<(), i32> {
            if self.fail_spawn {
                return Err(2);
            }
            self.spawns.push(spec.after.clone());
            Ok(())
        }
    }

    fn ack_rearm() -> AckRearm {
        AckRearm {
            after: "post02".to_owned(),
            generation: 2,
            signal_id: "01J00000000000000000000021".to_owned(),
        }
    }

    fn claimed_pipe() -> super::DaemonPipe {
        super::DaemonPipe {
            claim: Some(super::SignalClaim {
                arm_id: arm().arm_id,
                generation: 1,
                signal_id: "01J00000000000000000000021".to_owned(),
                event_refs: vec!["post02".to_owned(), "post03".to_owned()],
                events: vec![provider("post02"), provider("post03")],
            }),
            attempted: true,
            ..super::DaemonPipe::default()
        }
    }

    #[test]
    fn restart_after_ack_reaps_once_and_spawns_after_cursor() {
        let mut spec = spec();
        let mut live = arm();
        let mut pipe = claimed_pipe();
        let mut table = LinkTable::default();
        admit_attach(&mut table, fixture_attach(), now(), &[arm()]).expect("gen1");
        assert_eq!(table.current().expect("live").generation, 1);
        let mut children = ScriptedChild::default();
        let mut served = None;
        restart_after_ack(
            &ack_rearm(),
            &mut spec,
            &mut live,
            &mut pipe,
            &mut served,
            &mut table,
            &mut children,
        )
        .expect("rearm");
        assert_eq!(spec.after.as_deref(), Some("post02"));
        assert_eq!(children.kills, 1);
        assert_eq!(children.spawns, vec![Some("post02".to_owned())]);
        assert!(table.current().is_none());
        restart_after_ack(
            &ack_rearm(),
            &mut spec,
            &mut live,
            &mut pipe,
            &mut served,
            &mut table,
            &mut children,
        )
        .expect("replay");
        assert_eq!(children.kills, 1);
        assert_eq!(children.spawns.len(), 1);
    }

    #[test]
    fn restart_after_ack_keeps_queued_generation_two() {
        let mut spec = spec();
        let mut live = arm();
        let mut pipe = claimed_pipe();
        let mut table = LinkTable::default();
        admit_attach(&mut table, fixture_attach(), now(), &[arm()]).expect("gen1");
        table.drop_current();
        let mut gen2 = fixture_attach();
        if let WaiterLink::AttachWaiter {
            request_id,
            generation,
            ..
        } = &mut gen2
        {
            *request_id = "01J00000000000000000000098".to_owned();
            *generation = 2;
        }
        let mut successor_arm = arm();
        successor_arm.generation = 2;
        admit_attach(&mut table, gen2, now(), &[successor_arm]).expect("gen2");
        assert_eq!(table.current().expect("live").generation, 2);
        let mut children = ScriptedChild::default();
        let mut served = None;
        restart_after_ack(
            &ack_rearm(),
            &mut spec,
            &mut live,
            &mut pipe,
            &mut served,
            &mut table,
            &mut children,
        )
        .expect("rearm");
        assert_eq!(table.current().expect("kept").generation, 2);
        assert_eq!(children.kills, 1);
        assert_eq!(children.spawns, vec![Some("post02".to_owned())]);
    }

    #[test]
    fn restart_after_ack_kill_failure_does_not_spawn() {
        let mut spec = spec();
        let mut live = arm();
        let mut pipe = claimed_pipe();
        let mut table = LinkTable::default();
        let mut children = ScriptedChild {
            fail_kill: true,
            ..ScriptedChild::default()
        };
        let mut served = None;
        let error = restart_after_ack(
            &ack_rearm(),
            &mut spec,
            &mut live,
            &mut pipe,
            &mut served,
            &mut table,
            &mut children,
        )
        .expect_err("kill");
        assert_eq!(error, 2);
        assert!(children.spawns.is_empty());
    }

    #[test]
    fn restart_after_ack_spawn_failure_after_kill() {
        let mut spec = spec();
        let mut live = arm();
        let mut pipe = claimed_pipe();
        let mut table = LinkTable::default();
        let mut children = ScriptedChild {
            fail_spawn: true,
            ..ScriptedChild::default()
        };
        let mut served = None;
        let error = restart_after_ack(
            &ack_rearm(),
            &mut spec,
            &mut live,
            &mut pipe,
            &mut served,
            &mut table,
            &mut children,
        )
        .expect_err("spawn");
        assert_eq!(error, 2);
        assert_eq!(children.kills, 1);
        assert!(children.spawns.is_empty());
    }

    #[test]
    fn prefix_rearm_then_ingest_recovers_suffix() {
        let mut spec = spec();
        let mut live = arm();
        let mut pipe = claimed_pipe();
        let mut table = LinkTable::default();
        let mut children = ScriptedChild::default();
        let mut served = None;
        restart_after_ack(
            &ack_rearm(),
            &mut spec,
            &mut live,
            &mut pipe,
            &mut served,
            &mut table,
            &mut children,
        )
        .expect("rearm");
        let drain = FixedDrain {
            after: Mutex::new(None),
            result: Ok(vec![event("post03", "suffix")]),
        };
        let mut next = super::DaemonPipe::default();
        let outcome = ingest_match(
            &super::IngestRequest {
                spec: &spec,
                wait: WaitResult::Matched,
                drain: &drain,
                arm: &live,
                link: None,
                now: now(),
            },
            &mut next,
            &mut AckStore::with_arm(live.clone()),
            None::<&mut ScriptedIo>,
            || "01J00000000000000000000022".to_owned(),
        );
        assert_eq!(
            drain.after.lock().expect("after").as_deref(),
            Some("post02")
        );
        assert_eq!(
            next.claim.as_ref().map(|claim| claim.event_refs.clone()),
            Some(vec!["post03".to_owned()])
        );
        assert_eq!(outcome.coverage, DaemonCoverage::Pause);
        assert_eq!(live.generation, 2);
    }

    #[test]
    fn stalled_ack_does_not_block_active_flush() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let listener = paths.bind().expect("bind");
        let socket = paths.socket_path();
        let table = Arc::new(Mutex::new(LinkTable::default()));
        let acks = Arc::new(Mutex::new(AckStore::with_arm(arm())));
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        let handle = spawn_accept(
            listener,
            Arc::clone(&table),
            Arc::clone(&acks),
            Arc::clone(&stop),
            tx,
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
        let _stalled = ipcprims::transport::UnixDomainSocket::connect(&socket).expect("stalled");
        std::thread::sleep(std::time::Duration::from_millis(30));
        let started = std::time::Instant::now();
        let link = table.lock().expect("table").current().cloned();
        drop(link);
        let _acks = acks.lock().expect("acks");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "flush must not wait on a stalled ACK read"
        );
        let mut children = ChildSlot::new();
        let mut accept = Some(handle);
        let mut dummy = LinkTable::default();
        shutdown_daemon(&mut dummy, &mut children, &stop, Some(&socket), &mut accept)
            .expect("shutdown");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn failed_drain_does_not_claim() {
        let drain = FixedDrain {
            after: Mutex::new(None),
            result: Err(DrainError::Empty),
        };
        let mut pipe = super::DaemonPipe::default();
        let outcome = ingest(
            WaitResult::Matched,
            &drain,
            None,
            &mut pipe,
            None,
            "01J00000000000000000000021",
        );
        assert!(pipe.claim.is_none());
        assert_eq!(outcome.coverage, DaemonCoverage::Halt { exit: 2 });
    }

    #[test]
    fn timeout_does_not_drain_or_claim() {
        let drain = FixedDrain {
            after: Mutex::new(None),
            result: Ok(vec![event("post02", "one")]),
        };
        let mut pipe = super::DaemonPipe::default();
        let outcome = ingest(
            WaitResult::Timeout,
            &drain,
            None,
            &mut pipe,
            None,
            "01J00000000000000000000021",
        );
        assert!(drain.after.lock().expect("after").is_none());
        assert!(pipe.claim.is_none());
        assert_eq!(
            outcome.coverage,
            DaemonCoverage::Rearm {
                after: "cursor1".to_owned()
            }
        );
    }

    fn temp_root() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "gearwit-cli-daemon-{}-{}",
            std::process::id(),
            UNIQUE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn shutdown_drops_session_socket_and_child() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let listener = paths.bind().expect("bind");
        let socket = paths.socket_path();
        let mut table = LinkTable::default();
        admit_attach(&mut table, fixture_attach(), now(), &[arm()]).expect("admit");
        assert!(table.current().is_some());
        let mut children = ChildSlot::new();
        children.spawn("sleep", &["30".to_owned()]).expect("child");
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        let handle = spawn_accept(
            listener,
            Arc::new(Mutex::new(LinkTable::default())),
            Arc::new(Mutex::new(AckStore::with_arm(arm()))),
            Arc::clone(&stop),
            tx,
        );
        let mut accept = Some(handle);
        let started = std::time::Instant::now();
        let report = shutdown_daemon(&mut table, &mut children, &stop, Some(&socket), &mut accept)
            .expect("shutdown");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert!(report.child_reaped);
        assert!(!report.link_live);
        assert!(!children.occupied());
        let again = paths.bind().expect("rebind after shutdown");
        drop(again);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stalled_admission_shutdown_completes_within_admission_bound() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let listener = paths.bind().expect("bind");
        let socket = paths.socket_path();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        let mut live_arm = arm();
        live_arm.coverage_until = OffsetDateTime::now_utc() + TimeDuration::minutes(20);
        let handle = spawn_accept(
            listener,
            Arc::new(Mutex::new(LinkTable::default())),
            Arc::new(Mutex::new(AckStore::with_arm(live_arm))),
            Arc::clone(&stop),
            tx,
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
        let _stalled = ipcprims::transport::UnixDomainSocket::connect(&socket).expect("stalled");
        std::thread::sleep(std::time::Duration::from_millis(50));
        let started = std::time::Instant::now();
        let mut children = ChildSlot::new();
        let mut accept = Some(handle);
        let mut dummy = LinkTable::default();
        shutdown_daemon(&mut dummy, &mut children, &stop, Some(&socket), &mut accept)
            .expect("shutdown");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(6),
            "in-flight admission is bounded by the 5s attach read timeout"
        );
        let again = paths.bind().expect("rebind");
        drop(again);
        let _ = std::fs::remove_dir_all(&root);
    }

    fn attach_with(request_id: &str) -> WaiterLink {
        let mut message = fixture_attach();
        if let WaiterLink::AttachWaiter { request_id: id, .. } = &mut message {
            *id = request_id.to_owned();
        }
        message
    }

    fn ipc_frame(payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::from([0x49, 0x50]);
        let len = u32::try_from(payload.len()).expect("len");
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&ipcprims::frame::COMMAND.to_le_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn rejected_attach_does_not_steal_live_writer() {
        use std::io::Write as _;
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let listener = paths.bind().expect("bind");
        let socket = paths.socket_path();
        let table = Arc::new(Mutex::new(LinkTable::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        let mut live_arm = arm();
        live_arm.coverage_until = OffsetDateTime::now_utc() + TimeDuration::minutes(20);
        let handle = spawn_accept(
            listener,
            Arc::clone(&table),
            Arc::new(Mutex::new(AckStore::with_arm(live_arm))),
            Arc::clone(&stop),
            tx,
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut first = ipcprims::transport::UnixDomainSocket::connect(&socket).expect("first");
        first
            .write_all(&ipc_frame(
                &gearwit_protocol::encode_payload(&fixture_attach()).expect("p"),
            ))
            .expect("write");
        let first_served = match rx.recv_timeout(std::time::Duration::from_secs(2)) {
            Ok(super::DaemonEvent::Attached(served)) => served,
            Ok(super::DaemonEvent::CoverageRearm(_)) => panic!("first attach got rearm"),
            Err(error) => panic!("first attach {error}"),
        };
        {
            let table = table.lock().expect("table");
            assert!(retain_live_attach(&first_served, &table, None));
        }
        let mut second = ipcprims::transport::UnixDomainSocket::connect(&socket).expect("second");
        second
            .write_all(&ipc_frame(
                &gearwit_protocol::encode_payload(&attach_with("01J00000000000000000000099"))
                    .expect("p"),
            ))
            .expect("write");
        let second_served = match rx.recv_timeout(std::time::Duration::from_secs(2)) {
            Ok(super::DaemonEvent::Attached(served)) => served,
            Ok(super::DaemonEvent::CoverageRearm(_)) => panic!("second attach got rearm"),
            Err(error) => panic!("second attach {error}"),
        };
        {
            let table = table.lock().expect("table");
            assert!(!retain_live_attach(
                &second_served,
                &table,
                Some(&first_served)
            ));
            assert!(retain_live_attach(&first_served, &table, None));
        }
        {
            let mut table = table.lock().expect("table");
            table.drop_current();
        }
        let mut successor = ipcprims::transport::UnixDomainSocket::connect(&socket).expect("succ");
        successor
            .write_all(&ipc_frame(
                &gearwit_protocol::encode_payload(&attach_with("01J00000000000000000000098"))
                    .expect("p"),
            ))
            .expect("write");
        let successor_served = match rx.recv_timeout(std::time::Duration::from_secs(2)) {
            Ok(super::DaemonEvent::Attached(served)) => served,
            Ok(super::DaemonEvent::CoverageRearm(_)) => panic!("successor attach got rearm"),
            Err(error) => panic!("successor attach {error}"),
        };
        {
            let table = table.lock().expect("table");
            assert!(retain_live_attach(
                &successor_served,
                &table,
                Some(&first_served)
            ));
        }
        drop(successor);
        drop(first);
        drop(second);
        let mut children = ChildSlot::new();
        let mut accept = Some(handle);
        let mut dummy = LinkTable::default();
        let _ = shutdown_daemon(&mut dummy, &mut children, &stop, Some(&socket), &mut accept);
        let again = paths.bind().expect("rebind");
        drop(again);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn transport_loss_before_send_keeps_claim() {
        let (mut table, _link) = admitted();
        let drain = FixedDrain {
            after: Mutex::new(None),
            result: Ok(vec![event("post02", "one")]),
        };
        let mut pipe = super::DaemonPipe::default();
        let _ = ingest(
            WaitResult::Matched,
            &drain,
            None,
            &mut pipe,
            None,
            "01J00000000000000000000021",
        );
        assert!(pipe.claim.is_some());
        assert!(pipe.ledger.pending().is_none());
        let session = LinkSession {
            link_id: table.current().expect("link").link_id.clone(),
            arm_id: table.current().expect("link").arm_id.clone(),
            generation: table.current().expect("link").generation,
        };
        on_transport_loss(&mut pipe, &mut table, Some(&session), now());
        assert!(table.current().is_none());
        assert!(pipe.claim.is_some());
        assert!(!pipe.attempted);
    }

    #[test]
    fn transport_loss_after_send_redelivers_same_id() {
        let (mut table, link) = admitted();
        let drain = FixedDrain {
            after: Mutex::new(None),
            result: Ok(vec![event("post02", "one")]),
        };
        let mut pipe = super::DaemonPipe::default();
        let mut io = ScriptedIo {
            fail_send: false,
            sent: None,
            complete: false,
        };
        let first = ingest(
            WaitResult::Matched,
            &drain,
            Some(&link),
            &mut pipe,
            Some(&mut io),
            "01J00000000000000000000021",
        );
        let id = first.delivery_id.clone().expect("id");
        assert!(first.delivery_attempted);
        let session = LinkSession {
            link_id: table.current().expect("link").link_id.clone(),
            arm_id: table.current().expect("link").arm_id.clone(),
            generation: table.current().expect("link").generation,
        };
        on_transport_loss(&mut pipe, &mut table, Some(&session), now());
        assert!(table.current().is_none());
        assert!(pipe.ledger.should_redeliver());
        assert!(!pipe.attempted);
        assert_eq!(
            pipe.ledger
                .pending()
                .map(|pending| pending.delivery_id.as_str()),
            Some(id.as_str())
        );
        let WaiterLink::DeliverEvents {
            delivery_id,
            link_id,
            signal_id,
            ..
        } = io.sent.expect("sent")
        else {
            panic!("deliver");
        };
        for (bad_delivery, bad_link, bad_signal) in [
            (
                "01J00000000000000000000099",
                link_id.as_str(),
                signal_id.as_str(),
            ),
            (
                delivery_id.as_str(),
                "01J00000000000000000000098",
                signal_id.as_str(),
            ),
            (
                delivery_id.as_str(),
                link_id.as_str(),
                "01J00000000000000000000097",
            ),
        ] {
            let forged = WaiterLink::DeliveryResult {
                schema: SCHEMA.to_owned(),
                delivery_id: bad_delivery.to_owned(),
                link_id: bad_link.to_owned(),
                signal_id: bad_signal.to_owned(),
                outcome: "return_completed".to_owned(),
                observed_at: "2026-01-15T12:05:03Z".to_owned(),
            };
            pipe.attempted = true;
            assert_eq!(
                apply_waiter_result(&mut pipe, &forged),
                ResultApply::RevokeLost
            );
            assert!(pipe.ledger.should_redeliver());
            assert!(!pipe.attempted);
        }
    }

    #[test]
    fn stale_loss_does_not_revoke_successor() {
        let (mut table, first) = admitted();
        let old = LinkSession {
            link_id: first.link_id,
            arm_id: first.arm_id,
            generation: first.generation,
        };
        table.drop_current();
        admit_attach(
            &mut table,
            attach_with("01J00000000000000000000098"),
            now(),
            &[arm()],
        )
        .expect("successor");
        let successor = table.current().expect("live").link_id.clone();
        let mut pipe = super::DaemonPipe::default();
        on_transport_loss(&mut pipe, &mut table, Some(&old), now());
        assert_eq!(table.current().expect("still live").link_id, successor);
    }

    #[test]
    fn expired_lease_drops_session_and_allows_successor() {
        let (mut table, link) = admitted();
        assert!(!lease_expired(link.lease_until, now()));
        let later = now() + TimeDuration::minutes(11);
        assert!(lease_expired(link.lease_until, later));
        let session = LinkSession {
            link_id: link.link_id,
            arm_id: link.arm_id,
            generation: link.generation,
        };
        let mut pipe = super::DaemonPipe::default();
        on_transport_loss(&mut pipe, &mut table, Some(&session), later);
        assert!(table.current().is_none());
        admit_attach(
            &mut table,
            attach_with("01J00000000000000000000098"),
            later,
            &[arm()],
        )
        .expect("successor after expiry");
        assert!(table.current().is_some());
    }

    #[test]
    fn ingest_outcome_never_implies_turn() {
        let outcome = IngestOutcome {
            coverage: DaemonCoverage::Pause,
            claim: None,
            delivery_id: None,
            delivery_attempted: true,
            result_outcome: Some("return_completed".to_owned()),
            waiter_attached: true,
        };
        assert_ne!(outcome.result_outcome.as_deref(), Some("turn_started"));
    }
}
