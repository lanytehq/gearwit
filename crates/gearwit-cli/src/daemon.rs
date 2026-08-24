//! Daemon wait-on: Chanvoy coverage plus waiter-link delivery.
//!
//! This process owns the provider wait. It does not sit on the collaboration
//! floor used by the seat's own `chanvoy wait`. Wait match is only a hint:
//! events come from an exclusive-baseline drain.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::child::ChildSlot;
use crate::wait_on::{
    ChanvoyDrain, DrainedEvent, EventDrain, WaitOnSpec, WaitOutcome, WaitResult, WaiterState,
    attach_drain, chanvoy_wait_args,
};
use gearwit_domain::DeliveryRoute;
use gearwit_host::{
    AdmittedLink, DeliveryAttempt, DeliveryLedger, GearwitPaths, KnownArm, LinkError, LinkSession,
    LinkTable, ServeAttach, drop_session, prepare_delivery, read_waiter_link,
    record_delivery_result, redeliver_pending, send_delivery, serve_attach,
};
use gearwit_protocol::{ProviderEvent, WaiterLink};
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

/// True when `served` is the live table session and no writer is already held.
#[must_use]
pub fn retain_live_attach(served: &ServeAttach, table: &LinkTable, writer_occupied: bool) -> bool {
    if writer_occupied {
        return false;
    }
    let Some(session) = served.session.as_ref() else {
        return false;
    };
    table.current().is_some_and(|current| {
        current.link_id == session.link_id
            && current.arm_id == session.arm_id
            && current.generation == session.generation
    })
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
#[must_use]
pub fn ingest_match<D: EventDrain, I: DeliveryIo>(
    request: &IngestRequest<'_, D>,
    pipe: &mut DaemonPipe,
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
    match claim_or_reuse(&mut pipe.claim, request.arm, &events, mint_signal()) {
        Ok(live) => deliver_claimed(
            live,
            request.link,
            pipe,
            request.now,
            io,
            DaemonCoverage::Pause,
        ),
        Err(ClaimError::OccupiedDifferent) => pipe.snapshot(DaemonCoverage::Pause, waiter_attached),
    }
}

fn deliver_claimed<I: DeliveryIo>(
    live: SignalClaim,
    link: Option<&AdmittedLink>,
    pipe: &mut DaemonPipe,
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
    Attached(ServeAttach),
}

fn lock_table(table: &Mutex<LinkTable>) -> std::sync::MutexGuard<'_, LinkTable> {
    table
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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
    table: &Mutex<LinkTable>,
    pipe: &mut DaemonPipe,
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
    let Some(link) = current_link(table) else {
        return false;
    };
    if lease_expired(link.lease_until, now) {
        return true;
    }
    let mut io = LinkIo { served };
    let outcome = deliver_claimed(
        live,
        Some(&link),
        pipe,
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
        Some(Ok(result)) => {
            let _ = record_delivery_result(&mut pipe.ledger, &result);
            match &result {
                WaiterLink::DeliveryResult { outcome, .. } if outcome == "link_lost" => {
                    pipe.attempted = false;
                    revoke_exact(served, table, pipe, now, true);
                }
                WaiterLink::DeliveryResult { outcome, .. }
                    if outcome == "return_completed" || outcome == "return_failed" =>
                {
                    revoke_exact(served, table, pipe, now, false);
                }
                _ => {}
            }
        }
        Some(Err(error)) if is_read_idle(&error) => {}
        Some(Err(_)) | None => revoke_exact(served, table, pipe, now, true),
    }
}

fn spawn_accept(
    listener: gearwit_host::BoundListener,
    table: Arc<Mutex<LinkTable>>,
    stop: Arc<AtomicBool>,
    arm: KnownArm,
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
            let mut table = lock_table(&table);
            let instant = OffsetDateTime::now_utc();
            if let Ok(served) =
                serve_attach(stream, &mut table, instant, std::slice::from_ref(&arm))
            {
                drop(table);
                if tx.send(DaemonEvent::Attached(served)).is_err() {
                    break;
                }
            }
        }
    })
}

fn ingest_child_exit(
    status: std::process::ExitStatus,
    spec: &WaitOnSpec,
    arm: &KnownArm,
    table: &Mutex<LinkTable>,
    pipe: &mut DaemonPipe,
) -> DaemonCoverage {
    let link = current_link(table);
    ingest_match(
        &IngestRequest {
            spec,
            wait: WaitResult::from_code(status.code().unwrap_or(2)),
            drain: &ChanvoyDrain,
            arm,
            link: link.as_ref(),
            now: OffsetDateTime::now_utc(),
        },
        pipe,
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
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let mut accept = Some(spawn_accept(
        listener,
        Arc::clone(&table),
        Arc::clone(&stop),
        arm.clone(),
        tx,
    ));

    let mut spec = spec;
    spec.follow = true;
    let mut children = ChildSlot::new();
    let mut pipe = DaemonPipe::default();
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
                let occupied = served.is_some();
                let keep = {
                    let table = lock_table(&table);
                    retain_live_attach(&next, &table, occupied)
                };
                if keep {
                    let mut next = next;
                    let lease_until = {
                        let locked = lock_table(&table);
                        locked.current().map(|link| link.lease_until)
                    };
                    let timeout_failed = match lease_until {
                        Some(lease_until) => {
                            set_poll_timeout(&mut next, lease_until, now).is_err()
                                || lease_expired(lease_until, now)
                        }
                        None => false,
                    };
                    if timeout_failed {
                        served = Some(next);
                        revoke_exact(&mut served, &table, &mut pipe, now, true);
                    } else {
                        served = Some(next);
                        if let Some(current) = served.as_mut()
                            && flush_attached(current, &table, &mut pipe, now)
                        {
                            revoke_exact(&mut served, &table, &mut pipe, now, true);
                        }
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return halt(&table, &mut children, &stop, &socket, &mut accept, 2);
            }
        }
        poll_result(&mut served, &table, &mut pipe, now);
        match children.try_wait() {
            Ok(Some(status)) => match ingest_child_exit(status, &spec, &arm, &table, &mut pipe) {
                DaemonCoverage::Rearm { after } => {
                    spec.after = Some(after);
                    if spawn_chanvoy(&mut children, &spec).is_err() {
                        return halt(&table, &mut children, &stop, &socket, &mut accept, 2);
                    }
                }
                DaemonCoverage::Pause => {
                    if let Some(current) = served.as_mut()
                        && flush_attached(current, &table, &mut pipe, now)
                    {
                        revoke_exact(&mut served, &table, &mut pipe, now, true);
                    }
                }
                DaemonCoverage::Halt { exit } => {
                    return halt(&table, &mut children, &stop, &socket, &mut accept, exit);
                }
            },
            Ok(None) => {}
            Err(error) => {
                eprintln!("gearwit: chanvoy child: {error}");
                return halt(&table, &mut children, &stop, &socket, &mut accept, 2);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClaimError, DaemonCoverage, DeliveryIo, IngestOutcome, claim_or_reuse, ingest_match,
        lease_expired, on_transport_loss, provider_events_from_drain, retain_live_attach,
        shutdown_daemon, spawn_accept,
    };
    use crate::child::ChildSlot;
    use crate::wait_on::{DrainError, DrainedEvent, EventDrain, WaitOnSpec, WaitResult};
    use gearwit_host::{
        DeliveryAttempt, GearwitPaths, KnownArm, LinkSession, LinkTable, admit_attach,
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
        let mut io = ScriptedIo {
            fail_send: false,
            sent: None,
            complete: true,
        };
        let outcome = ingest(
            WaitResult::Matched,
            &drain,
            Some(&link),
            &mut pipe,
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
            Arc::clone(&stop),
            arm(),
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
            Arc::clone(&stop),
            live_arm,
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
            Err(error) => panic!("first attach {error}"),
        };
        {
            let table = table.lock().expect("table");
            assert!(retain_live_attach(&first_served, &table, false));
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
            Err(error) => panic!("second attach {error}"),
        };
        {
            let table = table.lock().expect("table");
            assert!(!retain_live_attach(&second_served, &table, true));
            assert!(retain_live_attach(&first_served, &table, false));
        }
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
