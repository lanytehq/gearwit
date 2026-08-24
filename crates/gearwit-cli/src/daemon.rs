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
    ChanvoyDrain, CoverageAdvance, DrainedEvent, EventDrain, WaitOnSpec, WaitOutcome, WaitResult,
    WaiterState, attach_drain, chanvoy_wait_args, coverage_advance,
};
use gearwit_domain::DeliveryRoute;
use gearwit_host::{
    AdmittedLink, DeliveryAttempt, DeliveryLedger, GearwitPaths, KnownArm, LinkSession, LinkTable,
    ServeAttach, drop_session, prepare_delivery, read_waiter_link, record_delivery_result,
    redeliver_pending, send_delivery, serve_attach,
};
use gearwit_protocol::{ProviderEvent, WaiterLink};
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

/// Result of one matched-interval ingest. Never sets `turn_started`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngestOutcome {
    /// Coverage transition. Does not record a handled cursor.
    pub coverage: CoverageAdvance,
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
            && existing.event_refs == event_refs
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

fn clear_terminal_claim(pipe: &mut DaemonPipe) {
    if pipe
        .ledger
        .pending()
        .is_some_and(|pending| matches!(pending.attempt, DeliveryAttempt::Terminal(_)))
    {
        pipe.claim = None;
        pipe.attempted = false;
    }
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
    fn snapshot(&self, coverage: CoverageAdvance, waiter_attached: bool) -> IngestOutcome {
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
        let coverage = coverage_advance(
            &WaitOutcome {
                waiter: WaiterState::Completed,
                result: request.wait,
                chanvoy_exit: None,
                process_exit: match request.wait {
                    WaitResult::Matched => 0,
                    WaitResult::Timeout => 1,
                    WaitResult::Error => 2,
                },
                drained_events: Vec::new(),
                newest_observed: None,
                drain_error: None,
            },
            &current_after,
        );
        return pipe.snapshot(coverage, waiter_attached);
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
        return pipe.snapshot(CoverageAdvance::Stop { exit: 2 }, waiter_attached);
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
            coverage_advance(&drained, &current_after),
        ),
        Err(ClaimError::OccupiedDifferent) => pipe.snapshot(
            CoverageAdvance::Continue {
                after: current_after,
            },
            waiter_attached,
        ),
    }
}

fn deliver_claimed<I: DeliveryIo>(
    live: SignalClaim,
    link: Option<&AdmittedLink>,
    pipe: &mut DaemonPipe,
    now: OffsetDateTime,
    io: Option<&mut I>,
    coverage: CoverageAdvance,
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
        clear_terminal_claim(pipe);
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
        read_waiter_link(&mut self.served.reader).map_err(|_| "recv")
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

/// Kill the Chanvoy child, drop the live session, and leave the socket droppable.
#[must_use]
pub fn shutdown_daemon(
    table: &mut LinkTable,
    children: &mut ChildSlot,
    stop: &AtomicBool,
    socket: Option<&std::path::Path>,
) -> ShutdownReport {
    stop.store(true, Ordering::SeqCst);
    if let Some(path) = socket {
        let _ = UnixDomainSocket::connect(path);
    }
    let child = children.kill_and_reap().unwrap_or(crate::child::KillReap {
        killed: false,
        reaped: false,
    });
    if let Some(current) = table.current() {
        let session = LinkSession {
            link_id: current.link_id.clone(),
            arm_id: current.arm_id.clone(),
            generation: current.generation,
        };
        drop_session(table, &session);
    }
    table.drop_current();
    ShutdownReport {
        child_reaped: child.reaped || !children.occupied(),
        link_live: table.current().is_some(),
    }
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
    code: i32,
) -> i32 {
    let mut table = lock_table(table);
    let _ = shutdown_daemon(&mut table, children, stop, Some(socket));
    code
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

fn flush_attached(
    served: &mut ServeAttach,
    table: &Mutex<LinkTable>,
    pipe: &mut DaemonPipe,
    spec: &WaitOnSpec,
    now: OffsetDateTime,
) {
    let Some(live) = pipe.claim.clone() else {
        return;
    };
    let Some(link) = current_link(table) else {
        return;
    };
    let mut io = LinkIo { served };
    let _ = deliver_claimed(
        live,
        Some(&link),
        pipe,
        now,
        Some(&mut io),
        CoverageAdvance::Continue {
            after: spec.after.clone().unwrap_or_default(),
        },
    );
}

fn spawn_accept(
    listener: gearwit_host::BoundListener,
    table: Arc<Mutex<LinkTable>>,
    stop: Arc<AtomicBool>,
    arm: KnownArm,
    tx: mpsc::Sender<DaemonEvent>,
) {
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
    });
}

#[allow(clippy::too_many_arguments)]
fn handle_child_exit(
    status: std::process::ExitStatus,
    spec: &mut WaitOnSpec,
    arm: &KnownArm,
    table: &Mutex<LinkTable>,
    pipe: &mut DaemonPipe,
    served: &mut Option<ServeAttach>,
    children: &mut ChildSlot,
    stop: &AtomicBool,
    socket: &std::path::Path,
) -> Option<i32> {
    let link = current_link(table);
    let mut io_slot = served.as_mut().map(|served| LinkIo { served });
    let outcome = ingest_match(
        &IngestRequest {
            spec,
            wait: WaitResult::from_code(status.code().unwrap_or(2)),
            drain: &ChanvoyDrain,
            arm,
            link: link.as_ref(),
            now: OffsetDateTime::now_utc(),
        },
        pipe,
        io_slot.as_mut(),
        || ulid::Ulid::new().to_string(),
    );
    match outcome.coverage {
        CoverageAdvance::Continue { after } => {
            spec.after = Some(after);
            spawn_chanvoy(children, spec)
                .err()
                .map(|code| halt(table, children, stop, socket, code))
        }
        CoverageAdvance::Stop { exit } => Some(halt(table, children, stop, socket, exit)),
    }
}

/// Bind the waiter-link, print arm coordinates, cover Chanvoy, deliver to an attached waiter.
#[must_use]
pub fn run_daemon_wait(spec: WaitOnSpec) -> i32 {
    let paths = match GearwitPaths::user_default() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gearwit: {error}");
            return 2;
        }
    };
    let listener = match paths.bind() {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("gearwit: {error}");
            return 2;
        }
    };
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

    let table = Arc::new(Mutex::new(LinkTable::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    spawn_accept(
        listener,
        Arc::clone(&table),
        Arc::clone(&stop),
        arm.clone(),
        tx,
    );

    let mut spec = spec;
    spec.follow = true;
    let mut children = ChildSlot::new();
    let mut pipe = DaemonPipe::default();
    let mut served: Option<ServeAttach> = None;
    if spawn_chanvoy(&mut children, &spec).is_err() {
        return halt(&table, &mut children, &stop, &socket, 2);
    }

    loop {
        let now = OffsetDateTime::now_utc();
        if now >= arm.coverage_until {
            return halt(&table, &mut children, &stop, &socket, 1);
        }
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(DaemonEvent::Attached(next)) => {
                served = Some(next);
                if let Some(current) = served.as_mut() {
                    flush_attached(current, &table, &mut pipe, &spec, now);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return halt(&table, &mut children, &stop, &socket, 2);
            }
        }
        match children.try_wait() {
            Ok(Some(status)) => {
                if let Some(code) = handle_child_exit(
                    status,
                    &mut spec,
                    &arm,
                    &table,
                    &mut pipe,
                    &mut served,
                    &mut children,
                    &stop,
                    &socket,
                ) {
                    return code;
                }
            }
            Ok(None) => {}
            Err(error) => {
                eprintln!("gearwit: chanvoy child: {error}");
                return halt(&table, &mut children, &stop, &socket, 2);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClaimError, DeliveryIo, IngestOutcome, claim_or_reuse, ingest_match,
        provider_events_from_drain, shutdown_daemon,
    };
    use crate::child::{ChildSlot, pid_is_alive};
    use crate::wait_on::{
        CoverageAdvance, DrainError, DrainedEvent, EventDrain, WaitOnSpec, WaitResult,
    };
    use gearwit_host::{DeliveryAttempt, GearwitPaths, KnownArm, LinkTable, admit_attach};
    use gearwit_protocol::{ProviderEvent, SCHEMA, WaiterLink, parse_waiter_link};
    use std::path::PathBuf;
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
        assert_eq!(
            outcome.coverage,
            CoverageAdvance::Continue {
                after: "post03".to_owned()
            }
        );
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
        let again = claim_or_reuse(
            &mut pipe.claim,
            &arm(),
            &[provider("post02")],
            "01J00000000000000000000099".to_owned(),
        )
        .expect("reuse");
        assert_eq!(again.signal_id, "01J00000000000000000000021");
        assert!(matches!(
            claim_or_reuse(
                &mut pipe.claim,
                &arm(),
                &[provider("post99")],
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
        assert!(pipe.claim.is_none());
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
        assert_eq!(outcome.coverage, CoverageAdvance::Stop { exit: 2 });
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
            CoverageAdvance::Continue {
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
        let pid = children.spawn("sleep", &["30".to_owned()]).expect("child");
        let stop = AtomicBool::new(false);
        let report = shutdown_daemon(&mut table, &mut children, &stop, Some(&socket));
        assert!(report.child_reaped);
        assert!(!report.link_live);
        assert!(!children.occupied());
        assert!(!pid_is_alive(pid));
        drop(listener);
        let again = paths.bind().expect("rebind after shutdown");
        drop(again);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ingest_outcome_never_implies_turn() {
        let outcome = IngestOutcome {
            coverage: CoverageAdvance::Continue {
                after: "post02".to_owned(),
            },
            claim: None,
            delivery_id: None,
            delivery_attempted: true,
            result_outcome: Some("return_completed".to_owned()),
            waiter_attached: true,
        };
        assert_ne!(outcome.result_outcome.as_deref(), Some("turn_started"));
    }
}
