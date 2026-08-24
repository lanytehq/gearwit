//! Semantic persistence port for gearwitd authority.
//!
//! Defines the operational contract for durable claim admission, monotonic
//! transition recording, and restart recovery. Backends implement this port;
//! the daemon treats it as the single durability boundary.

use crate::controller::ManagedCapability;
use gearwit_protocol::{ProviderEvent, WaiterLinkError};
use std::collections::BTreeMap;
use time::OffsetDateTime;

/// A generation-stamped, durably recorded claim for a stable event batch.
///
/// Identity is defined by `request_id` alone; content equality includes
/// arm, generation, `signal_id`, `event_refs`, event bodies, provider,
/// actor, and `observed_at`. The server-minted `claimed_at` timestamp is
/// excluded from content equality so that an exact replay at a later
/// wall-clock time matches.
#[derive(Clone, Debug)]
pub struct DurableClaim {
    /// Stable claim request id.
    pub request_id: String,
    /// Arm id.
    pub arm_id: String,
    /// Generation resolved at claim time under authority lock.
    pub generation: u64,
    /// Stable signal id.
    pub signal_id: String,
    /// Oldest-first event refs.
    pub event_refs: Vec<String>,
    /// Bounded events.
    pub events: Vec<ProviderEvent>,
    /// Timestamp the claim was recorded.
    pub claimed_at: time::OffsetDateTime,
}

impl DurableClaim {
    /// Content identity: same `request_id`, arm, generation, `signal_id`,
    /// `event_refs`, event bodies, provider, actor, and `observed_at`.
    /// Excludes `claimed_at`.
    #[must_use]
    pub fn content_eq(&self, other: &Self) -> bool {
        self.request_id == other.request_id
            && self.arm_id == other.arm_id
            && self.generation == other.generation
            && self.signal_id == other.signal_id
            && self.event_refs == other.event_refs
            && self.events.len() == other.events.len()
            && self.events.iter().zip(other.events.iter()).all(|(a, b)| {
                a.body == b.body
                    && a.provider == b.provider
                    && a.actor == b.actor
                    && a.observed_at == b.observed_at
            })
    }
}

impl PartialEq for DurableClaim {
    fn eq(&self, other: &Self) -> bool {
        self.content_eq(other)
    }
}

impl Eq for DurableClaim {}

/// Transition the host can record beyond public lifecycle receipts.
///
/// These are private authority transitions with a defined monotonic order:
/// `ClaimRecorded → DispatchPrepared`. From `DispatchPrepared` the path may
/// go through `NativeAccepted → ExactTurnStart → ExactTurnTerminal`, or to
/// `ReconciliationRequired` (ambiguous) or `ControllerLost` (link/process
/// loss). `ReconciliationRequired` may also follow `NativeAccepted` instead
/// of `ExactTurnStart`. `ReconciliationResolved` follows
/// `ReconciliationRequired` (or `NativeAccepted` after an accepted
/// reconciliation).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Transition {
    /// Durable claim recorded (generation-stamped, idempotency-checked).
    ClaimRecorded = 0,
    /// Controller dispatch attempt prepared.
    DispatchPrepared = 1,
    /// Native request accepted (private provider correlation).
    NativeAccepted = 2,
    /// Exact turn started.
    ExactTurnStart = 3,
    /// Exact turn terminal.
    ExactTurnTerminal = 4,
    /// Reconciliation required (ambiguous acceptance).
    ReconciliationRequired = 5,
    /// Reconciliation resolved.
    ReconciliationResolved = 6,
    /// Controller lost — some controller lifecycle transitions may follow but
    /// further delivery is not guaranteed active.
    ControllerLost = 7,
}

/// Validate a candidate transition against the recorded history for one
/// attempt. Shared by `record_transition`, `record_prepared`, and
/// `record_reconciliation` so every transition write goes through the same
/// monotonic validator.
fn validate_transition(
    existing: Option<&[Transition]>,
    transition: Transition,
) -> Result<(), WaiterLinkError> {
    match existing {
        None => {
            if transition != Transition::ClaimRecorded {
                return Err(WaiterLinkError::Semantic(
                    "first transition must be ClaimRecorded",
                ));
            }
        }
        Some(entry) => {
            if entry.contains(&transition) {
                return Err(WaiterLinkError::Semantic("duplicate transition"));
            }
            let last = *entry.last().expect("entry is non-empty");
            let valid = match transition {
                Transition::ReconciliationRequired => {
                    matches!(
                        last,
                        Transition::DispatchPrepared
                            | Transition::NativeAccepted
                            | Transition::ReconciliationResolved
                    )
                }
                Transition::ReconciliationResolved => {
                    matches!(
                        last,
                        Transition::ReconciliationRequired | Transition::NativeAccepted
                    )
                }
                Transition::NativeAccepted => {
                    last == Transition::DispatchPrepared
                        || last == Transition::ReconciliationRequired
                }
                Transition::ControllerLost => {
                    matches!(
                        last,
                        Transition::DispatchPrepared
                            | Transition::NativeAccepted
                            | Transition::ExactTurnStart
                    )
                }
                _ => transition as u8 == last as u8 + 1,
            };
            if !valid {
                return Err(WaiterLinkError::Semantic("regressive transition"));
            }
        }
    }
    Ok(())
}

/// Disposition of a reconciliation attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationState {
    /// Proven not accepted.
    ProvenNotAccepted,
    /// Accepted.
    Accepted,
    /// Terminal.
    Terminal,
    /// Still unknown.
    Unknown,
}

/// What the caller should do after persisting a claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimOutcome {
    /// Claim accepted; proceed to dispatch.
    Admitted,
    /// Exact replay of a previously recorded claim.
    Replay,
}

/// Why a claim was rejected or failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimError {
    /// A different batch is claimed on this (arm, generation).
    OccupiedDifferent,
    /// Generation resolved at claim time is stale.
    StaleGeneration,
    /// Signed-off batch conflicts with the recorded claim.
    Conflict,
    /// Storage unavailable or I/O failure.
    StorageFailure(String),
}

/// Durability class the backend has proven.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurabilityClass {
    /// Claim is durable: flushed + fsynced before dispatch.
    Durable,
    /// Best-effort; backend cannot prove durability.
    BestEffort,
}

/// Full arm policy durably persisted for recovery.
///
/// Reconstruction of a usable fresh authority must not require the caller
/// to re-register arms; every policy dimension the live authority uses is
/// persisted here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedArm {
    /// Arm id.
    pub arm_id: String,
    /// Current generation.
    pub generation: u64,
    /// Seat token.
    pub seat_id: String,
    /// Attached route the arm admits.
    pub route: String,
    /// Closed capability granted to controller dispatches.
    pub capability: ManagedCapability,
    /// Coverage end.
    pub coverage_until: OffsetDateTime,
}

/// Non-bearer attachment state durably persisted for recovery.
///
/// Carries the exact minted record: seat, arm, generation, route, closed
/// capability, lease, verifier reference, and revocation. No credential or
/// proof material is persisted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedAttachment {
    /// Stable attempt id.
    pub attempt_id: String,
    /// Arm id.
    pub arm_id: String,
    /// Arm generation at claim time.
    pub generation: u64,
    /// Seat token.
    pub seat_id: String,
    /// Capability route.
    pub route: String,
    /// Closed capability granted.
    pub capability: ManagedCapability,
    /// Lease end.
    pub lease_until: OffsetDateTime,
    /// Opaque verifier reference.
    pub verifier_ref: String,
    /// Whether the attachment is revoked.
    pub revoked: bool,
}

/// Result of recovery after daemon restart.
#[derive(Clone, Debug, Default)]
pub struct RecoverySnapshot {
    /// Durable claims that were live at shutdown.
    pub claims: Vec<DurableClaim>,
    /// Transitions recorded per `signal_id:attempt_id`.
    pub transitions: BTreeMap<String, Vec<Transition>>,
    /// Recorded dispatch dispositions keyed by attempt id.
    pub dispositions: BTreeMap<String, crate::controller::DispatchDisposition>,
    /// Claim `request_id` → `attempt_id` mapping for replay.
    pub attempt_map: BTreeMap<String, String>,
    /// Full arm policy records for authority reconstruction.
    pub arms: Vec<PersistedArm>,
    /// Attachment records for authority reconstruction.
    pub attachments: Vec<PersistedAttachment>,
    /// Exact persisted `attempt_id` → `signal_id` binding.
    pub attempt_signals: BTreeMap<String, String>,
    /// Reconciliation resolutions keyed by attempt id.
    pub reconciliations: BTreeMap<String, ReconciliationState>,
    /// Durably prepared attempts.
    pub prepared_set: BTreeMap<String, bool>,
    /// Durably consumed (concluded) attempts.
    pub concluded_set: BTreeMap<String, bool>,
    /// Handled cursor positions per arm.
    pub handled_cursors: BTreeMap<String, String>,
    /// Re-arm flags per arm.
    pub rearm_positions: BTreeMap<String, bool>,
    /// Verifier refs per `request_id` (for attachment reconstruction).
    pub verifier_refs: BTreeMap<String, String>,
    /// Monotonic attempt counter for new claim admissions after restart.
    pub attempt_seq: u64,
}

/// Record produced by atomic claim admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionRecord {
    /// The admission outcome.
    pub outcome: ClaimOutcome,
    /// The attempt id (recorded on first admission; returned on replay).
    pub attempt_id: String,
    /// Opaque verifier ref (newly minted on admission; returned on replay).
    pub verifier_ref: String,
}

/// Semantic persistence port.
///
/// # Contract
///
/// - `admit_claim` must durably record the claim, the authority-minted
///   attachment, the exact attempt→signal binding, and `ClaimRecorded` in
///   one atomic operation before the caller dispatches any external I/O.
/// - `record_transition` must be monotonic — reject duplicate, stale,
///   regressive, or conflicting transitions. Transitions are scoped to an
///   attempt: different attempts on the same signal may progress
///   independently.
/// - `record_disposition` must durably record the dispatch disposition
///   keyed by `attempt_id` for replay on restart.
/// - `record_prepared` must atomically append `DispatchPrepared` and mark
///   the attempt prepared — either both appear or neither does.
/// - `record_conclusion` must atomically record the disposition, the first
///   post-send transition, and the durable consumption marker — either all
///   appear or none does. Durable single consumption covers restart.
/// - `record_reconciliation` must persist the resolution enum keyed to the
///   attempt and its transitions atomically, failing closed when the
///   attempt→signal binding is absent or mismatched.
/// - `recover` must return live claims, transitions, dispositions,
///   attachments, arm policy, bindings, resolutions, handled cursors, and
///   re-arm positions after restart.
/// - `durability` must report the backend's proven class, not a weaker
///   fallback.
/// - No bearer capability, proof material, credential, or controller
///   secret may be persisted.
pub trait Persist {
    /// Atomically admit one generation-fenced claim: durably record the
    /// claim, mint the attempt identity, store the authority-produced
    /// attachment, record the exact attempt→signal binding, record
    /// `ClaimRecorded`, and store an opaque verifier reference — all as
    /// one operation.
    ///
    /// `attachment` is the authority-minted attachment for a new
    /// admission; on exact replay it is ignored and the previously
    /// recorded attempt/verifier state is returned.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError`] when the claim is stale, conflicts, or
    /// storage is unavailable.
    fn admit_claim(
        &mut self,
        claim: &DurableClaim,
        attachment: Option<&PersistedAttachment>,
    ) -> Result<AdmissionRecord, ClaimError>;

    /// Append a monotonic lifecycle transition for an attempt. The
    /// transition must be strictly after the last recorded transition
    /// for this attempt.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] on duplicate, stale,
    /// regressive, or conflicting transitions.
    fn record_transition(
        &mut self,
        signal_id: &str,
        attempt_id: &str,
        transition: Transition,
    ) -> Result<(), WaiterLinkError>;

    /// Record a dispatch disposition keyed by `attempt_id` for replay
    /// on restart.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] if a different disposition
    /// is already recorded for this `attempt_id`.
    fn record_disposition(
        &mut self,
        attempt_id: &str,
        disposition: &crate::controller::DispatchDisposition,
    ) -> Result<(), WaiterLinkError>;

    /// Report the backend's proven durability class.
    fn durability(&self) -> DurabilityClass;

    /// Report backend identity for diagnostics.
    fn backend_identity(&self) -> &'static str;

    /// Recover state after daemon restart.
    ///
    /// Returns claims, transitions, dispositions, attempt mappings,
    /// arm policy, attachments, attempt→signal bindings, reconciliation
    /// resolutions, handled cursors, and re-arm positions for full
    /// authority reconstruction.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError::StorageFailure`] when the backend is
    /// unavailable or corrupt.
    fn recover(&mut self) -> Result<RecoverySnapshot, ClaimError>;

    /// Atomically record a dispatch prepare: append `DispatchPrepared`
    /// and mark the attempt prepared in one semantic commit.
    ///
    /// Fails closed when there is no persisted attempt→signal binding,
    /// when the supplied `signal_id` does not match the persisted
    /// binding, or when the attempt was already prepared or concluded.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] if any part fails.
    fn record_prepared(&mut self, signal_id: &str, attempt_id: &str)
    -> Result<(), WaiterLinkError>;

    /// Atomically record a dispatch conclusion: disposition plus the
    /// first required post-send transition plus the durable consumption
    /// marker in one semantic commit.
    ///
    /// The implementation must stage/validate all writes and commit
    /// them together. No partial write may be observable — either the
    /// disposition, transition, and consumption marker all appear or
    /// none of them does.
    ///
    /// For `Accepted`, this is disposition + `NativeAccepted`.
    /// For `Ambiguous`, this is disposition + `ReconciliationRequired`.
    /// For `Rejected`, this is disposition only (no transition).
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] if any part of the atomic
    /// write fails or the attempt was already concluded.
    fn record_conclusion(
        &mut self,
        attempt_id: &str,
        signal_id: &str,
        disposition: &crate::controller::DispatchDisposition,
        first_transition: Option<Transition>,
    ) -> Result<(), WaiterLinkError>;

    /// True if the attempt has been durably consumed by a conclusion.
    /// Checked before conclusion to enforce the durable single-conclusion
    /// invariant.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] when the check fails.
    fn has_concluded(&self, attempt_id: &str) -> Result<bool, WaiterLinkError>;

    /// Persist the full arm policy (`arm_id`, generation, seat, route,
    /// capability, coverage) for recovery after restart.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] when persistence fails.
    fn persist_arm_state(&mut self, arm: &PersistedArm) -> Result<(), WaiterLinkError>;

    /// Durably mark an attempt's attachment revoked.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] when persistence fails or no
    /// attachment is persisted for the attempt.
    fn persist_attachment_revoked(&mut self, attempt_id: &str) -> Result<(), WaiterLinkError>;

    /// Persist a handled cursor position for recovery after restart.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] when persistence fails.
    fn persist_handled_cursor(&mut self, arm_id: &str, cursor: &str)
    -> Result<(), WaiterLinkError>;

    /// Persist a re-arm flag for recovery after restart.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] when persistence fails.
    fn persist_rearmed(&mut self, arm_id: &str) -> Result<(), WaiterLinkError>;

    /// The durable claim bound to an `attempt_id`, if recorded at
    /// admission. The authority rehydrates dispatch identity from this
    /// record, not from caller-carried data.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] when the lookup fails.
    fn claim_for_attempt(&self, attempt_id: &str) -> Result<Option<DurableClaim>, WaiterLinkError>;

    /// The exact persisted `signal_id` for an `attempt_id`, if the
    /// binding was durably recorded at admission.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] when the lookup fails.
    fn attempt_signal(&self, attempt_id: &str) -> Result<Option<String>, WaiterLinkError>;

    /// The persisted reconciliation resolution for an attempt, if any.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] when the lookup fails.
    fn reconciliation_recorded(
        &self,
        attempt_id: &str,
    ) -> Result<Option<ReconciliationState>, WaiterLinkError>;

    /// Durably record a reconciliation resolution for an attempt.
    ///
    /// Persists the resolution enum keyed to the attempt and appends the
    /// completed resolution transitions atomically. Fails closed when the
    /// persisted attempt→signal binding is absent or mismatched, when the
    /// attempt has no prior `ReconciliationRequired` transition, or when a
    /// conflicting resolution is already recorded. Repeating the same
    /// resolution is idempotent and appends no duplicate transitions.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] when any part fails.
    fn record_reconciliation(
        &mut self,
        attempt_id: &str,
        signal_id: &str,
        state: ReconciliationState,
    ) -> Result<(), WaiterLinkError>;
}

// ---------------------------------------------------------------------------
// Deterministic fake for unit tests
// ---------------------------------------------------------------------------

/// Deterministic in-memory fake that implements [`Persist`].
#[derive(Clone, Debug, Default)]
pub struct FakePersist {
    /// Claims keyed by `request_id`.
    pub claims: BTreeMap<String, DurableClaim>,
    /// Transitions keyed by (`signal_id`, `attempt_id`).
    pub transitions: BTreeMap<(String, String), Vec<Transition>>,
    /// Dispositions keyed by `attempt_id`.
    pub dispositions: BTreeMap<String, crate::controller::DispatchDisposition>,
    /// Attempt id per `request_id` (for replay lookups).
    pub claim_attempts: BTreeMap<String, String>,
    /// Verifier ref per `request_id`.
    pub verifier_refs: BTreeMap<String, String>,
    /// Full arm policy keyed by `arm_id`.
    pub persisted_arms: BTreeMap<String, PersistedArm>,
    /// Attachment records keyed by `attempt_id`.
    pub persisted_attachments: BTreeMap<String, PersistedAttachment>,
    /// Exact attempt→signal bindings keyed by `attempt_id`.
    pub attempt_signals: BTreeMap<String, String>,
    /// Reconciliation resolutions keyed by `attempt_id`.
    pub reconciliations: BTreeMap<String, ReconciliationState>,
    /// Set of durably prepared `attempt_ids`.
    pub prepared_set: BTreeMap<String, bool>,
    /// Set of durably concluded `attempt_ids`.
    pub concluded_set: BTreeMap<String, bool>,
    /// Monotonic attempt counter.
    pub attempt_seq: u64,
    /// When set, `admit_claim` returns `StorageFailure` with this message
    /// instead of succeeding.
    pub next_claim_error: Option<String>,
    /// When set, `record_transition` returns an error with this message.
    pub next_transition_error: Option<String>,
    /// When set, `record_disposition` returns an error with this message.
    pub next_disposition_error: Option<String>,
    /// When set, `record_prepared` returns an error with this message.
    pub next_prepare_error: Option<String>,
    /// When set, `record_conclusion` fails atomically with this message.
    pub next_conclusion_error: Option<String>,
    /// When set, `persist_arm_state` returns an error with this message.
    pub next_arm_persist_error: Option<String>,
    /// When set, `persist_attachment_revoked` returns an error with this
    /// message.
    pub next_revoke_error: Option<String>,
    /// When set, `persist_handled_cursor` returns an error with this message.
    pub next_cursor_error: Option<String>,
    /// When set, `persist_rearmed` returns an error with this message.
    pub next_rearm_error: Option<String>,
    /// When set, `record_reconciliation` returns an error with this message.
    pub next_reconciliation_error: Option<String>,
    /// Counter: how many `record_transition` calls to allow before injecting error.
    pub transition_allow_count: usize,
    /// Tracks how many `record_transition` calls have been made.
    pub transition_call_count: usize,
    /// Handled cursors to return on recovery.
    pub handled_cursors: BTreeMap<String, String>,
    /// Re-arm positions to return on recovery.
    pub rearm_positions: BTreeMap<String, bool>,
}

impl FakePersist {
    /// Number of claims recorded.
    #[must_use]
    pub fn claim_count(&self) -> usize {
        self.claims.len()
    }

    /// Look up a persisted claim by request id.
    #[must_use]
    pub fn get_claim(&self, request_id: &str) -> Option<&DurableClaim> {
        self.claims.get(request_id)
    }

    /// Transitions recorded for a (`signal_id`, `attempt_id`).
    #[must_use]
    pub fn get_transitions(&self, signal_id: &str, attempt_id: &str) -> &[Transition] {
        self.transitions
            .get(&(signal_id.to_owned(), attempt_id.to_owned()))
            .map_or(&[], Vec::as_slice)
    }

    /// Disposition recorded for an `attempt_id`.
    #[must_use]
    pub fn get_disposition(
        &self,
        attempt_id: &str,
    ) -> Option<&crate::controller::DispatchDisposition> {
        self.dispositions.get(attempt_id)
    }
}

impl Persist for FakePersist {
    fn admit_claim(
        &mut self,
        claim: &DurableClaim,
        attachment: Option<&PersistedAttachment>,
    ) -> Result<AdmissionRecord, ClaimError> {
        if let Some(msg) = self.next_claim_error.take() {
            return Err(ClaimError::StorageFailure(msg));
        }
        // Replay: return previously recorded attempt/verifier
        if let Some(existing) = self.claims.get(&claim.request_id) {
            if existing.content_eq(claim) {
                let attempt_id = self
                    .claim_attempts
                    .get(&claim.request_id)
                    .cloned()
                    .expect("attempt must exist for replayed claim");
                let verifier_ref = self
                    .verifier_refs
                    .get(&claim.request_id)
                    .cloned()
                    .expect("verifier must exist for replayed claim");
                return Ok(AdmissionRecord {
                    outcome: ClaimOutcome::Replay,
                    attempt_id,
                    verifier_ref,
                });
            }
            // Same request_id, different content = conflict
            return Err(ClaimError::Conflict);
        }
        // Check if this (arm_id, generation) is already occupied by a different request
        for existing in self.claims.values() {
            if existing.arm_id == claim.arm_id
                && existing.generation == claim.generation
                && existing.request_id != claim.request_id
            {
                return Err(ClaimError::OccupiedDifferent);
            }
        }
        let attachment = attachment
            .ok_or_else(|| ClaimError::StorageFailure("missing attachment".to_owned()))?;
        // Atomic admission: store claim, attempt map, attachment, exact
        // attempt→signal binding, verifier ref, and ClaimRecorded together.
        if let Some(seq) = attachment
            .attempt_id
            .strip_prefix("attempt-")
            .and_then(|s| s.parse::<u64>().ok())
        {
            self.attempt_seq = self.attempt_seq.max(seq);
        }
        self.claim_attempts
            .insert(claim.request_id.clone(), attachment.attempt_id.clone());
        self.verifier_refs
            .insert(claim.request_id.clone(), attachment.verifier_ref.clone());
        self.claims.insert(claim.request_id.clone(), claim.clone());
        self.persisted_attachments
            .insert(attachment.attempt_id.clone(), attachment.clone());
        self.attempt_signals
            .insert(attachment.attempt_id.clone(), claim.signal_id.clone());
        // Record ClaimRecorded atomically
        let key = (claim.signal_id.clone(), attachment.attempt_id.clone());
        self.transitions
            .entry(key)
            .or_default()
            .push(Transition::ClaimRecorded);
        Ok(AdmissionRecord {
            outcome: ClaimOutcome::Admitted,
            attempt_id: attachment.attempt_id.clone(),
            verifier_ref: attachment.verifier_ref.clone(),
        })
    }

    fn record_transition(
        &mut self,
        signal_id: &str,
        attempt_id: &str,
        transition: Transition,
    ) -> Result<(), WaiterLinkError> {
        self.transition_call_count += 1;
        if self.transition_call_count > self.transition_allow_count
            && let Some(msg) = self.next_transition_error.take()
        {
            return Err(WaiterLinkError::Semantic(Box::leak(msg.into_boxed_str())));
        }
        let key = (signal_id.to_owned(), attempt_id.to_owned());
        validate_transition(self.transitions.get(&key).map(Vec::as_slice), transition)?;
        self.transitions.entry(key).or_default().push(transition);
        Ok(())
    }

    fn record_disposition(
        &mut self,
        attempt_id: &str,
        disposition: &crate::controller::DispatchDisposition,
    ) -> Result<(), WaiterLinkError> {
        if let Some(msg) = self.next_disposition_error.take() {
            return Err(WaiterLinkError::Semantic(Box::leak(msg.into_boxed_str())));
        }
        if self
            .dispositions
            .get(attempt_id)
            .is_some_and(|existing| existing != disposition)
        {
            return Err(WaiterLinkError::Semantic(
                "conflicting disposition for attempt_id",
            ));
        }
        self.dispositions
            .insert(attempt_id.to_owned(), disposition.clone());
        Ok(())
    }

    fn record_prepared(
        &mut self,
        signal_id: &str,
        attempt_id: &str,
    ) -> Result<(), WaiterLinkError> {
        // ---- Stage: validate everything before any mutation ----
        if let Some(msg) = self.next_prepare_error.take() {
            return Err(WaiterLinkError::Semantic(Box::leak(msg.into_boxed_str())));
        }
        if self.prepared_set.contains_key(attempt_id) {
            return Err(WaiterLinkError::Semantic(
                "attempt already prepared — duplicate prepare",
            ));
        }
        if self.concluded_set.contains_key(attempt_id) {
            return Err(WaiterLinkError::Semantic(
                "attempt already concluded — cannot prepare",
            ));
        }
        let Some(bound_signal) = self.attempt_signals.get(attempt_id) else {
            return Err(WaiterLinkError::Semantic(
                "no persisted attempt→signal binding for this attempt",
            ));
        };
        if bound_signal != signal_id {
            return Err(WaiterLinkError::Semantic(
                "signal_id does not match persisted attempt→signal binding",
            ));
        }
        let key = (signal_id.to_owned(), attempt_id.to_owned());
        validate_transition(
            self.transitions.get(&key).map(Vec::as_slice),
            Transition::DispatchPrepared,
        )?;
        // ---- Commit ----
        self.transitions
            .entry(key)
            .or_default()
            .push(Transition::DispatchPrepared);
        self.prepared_set.insert(attempt_id.to_owned(), true);
        Ok(())
    }

    fn record_conclusion(
        &mut self,
        attempt_id: &str,
        signal_id: &str,
        disposition: &crate::controller::DispatchDisposition,
        first_transition: Option<Transition>,
    ) -> Result<(), WaiterLinkError> {
        // ---- Stage: validate both writes before any mutation ----
        if let Some(msg) = self.next_disposition_error.take() {
            return Err(WaiterLinkError::Semantic(Box::leak(msg.into_boxed_str())));
        }
        if self
            .dispositions
            .get(attempt_id)
            .is_some_and(|existing| existing != disposition)
        {
            return Err(WaiterLinkError::Semantic(
                "conflicting disposition for attempt_id",
            ));
        }
        if self.concluded_set.contains_key(attempt_id) {
            return Err(WaiterLinkError::Semantic(
                "attempt already concluded — durable single consumption",
            ));
        }
        if let Some(transition) = first_transition {
            let key = (signal_id.to_owned(), attempt_id.to_owned());
            validate_transition(self.transitions.get(&key).map(Vec::as_slice), transition)?;
        }
        if let Some(msg) = self.next_conclusion_error.take() {
            return Err(WaiterLinkError::Semantic(Box::leak(msg.into_boxed_str())));
        }

        // ---- Commit: all three writes together ----
        self.dispositions
            .insert(attempt_id.to_owned(), disposition.clone());
        if let Some(transition) = first_transition {
            let key = (signal_id.to_owned(), attempt_id.to_owned());
            self.transitions.entry(key).or_default().push(transition);
        }
        self.concluded_set.insert(attempt_id.to_owned(), true);
        Ok(())
    }

    fn has_concluded(&self, attempt_id: &str) -> Result<bool, WaiterLinkError> {
        Ok(self.concluded_set.contains_key(attempt_id))
    }

    fn persist_arm_state(&mut self, arm: &PersistedArm) -> Result<(), WaiterLinkError> {
        if let Some(msg) = self.next_arm_persist_error.take() {
            return Err(WaiterLinkError::Semantic(Box::leak(msg.into_boxed_str())));
        }
        self.persisted_arms.insert(arm.arm_id.clone(), arm.clone());
        Ok(())
    }

    fn persist_attachment_revoked(&mut self, attempt_id: &str) -> Result<(), WaiterLinkError> {
        if let Some(msg) = self.next_revoke_error.take() {
            return Err(WaiterLinkError::Semantic(Box::leak(msg.into_boxed_str())));
        }
        let stored =
            self.persisted_attachments
                .get_mut(attempt_id)
                .ok_or(WaiterLinkError::Semantic(
                    "no persisted attachment for this attempt",
                ))?;
        stored.revoked = true;
        Ok(())
    }

    fn persist_handled_cursor(
        &mut self,
        arm_id: &str,
        cursor: &str,
    ) -> Result<(), WaiterLinkError> {
        if let Some(msg) = self.next_cursor_error.take() {
            return Err(WaiterLinkError::Semantic(Box::leak(msg.into_boxed_str())));
        }
        self.handled_cursors
            .insert(arm_id.to_owned(), cursor.to_owned());
        Ok(())
    }

    fn persist_rearmed(&mut self, arm_id: &str) -> Result<(), WaiterLinkError> {
        if let Some(msg) = self.next_rearm_error.take() {
            return Err(WaiterLinkError::Semantic(Box::leak(msg.into_boxed_str())));
        }
        self.rearm_positions.insert(arm_id.to_owned(), true);
        Ok(())
    }

    fn claim_for_attempt(&self, attempt_id: &str) -> Result<Option<DurableClaim>, WaiterLinkError> {
        let Some(request_id) = self
            .claim_attempts
            .iter()
            .find(|(_, aid)| *aid == attempt_id)
            .map(|(rid, _)| rid.clone())
        else {
            return Ok(None);
        };
        Ok(self.claims.get(&request_id).cloned())
    }

    fn attempt_signal(&self, attempt_id: &str) -> Result<Option<String>, WaiterLinkError> {
        Ok(self.attempt_signals.get(attempt_id).cloned())
    }

    fn reconciliation_recorded(
        &self,
        attempt_id: &str,
    ) -> Result<Option<ReconciliationState>, WaiterLinkError> {
        Ok(self.reconciliations.get(attempt_id).copied())
    }

    fn record_reconciliation(
        &mut self,
        attempt_id: &str,
        signal_id: &str,
        state: ReconciliationState,
    ) -> Result<(), WaiterLinkError> {
        // ---- Stage: validate before any mutation ----
        if let Some(msg) = self.next_reconciliation_error.take() {
            return Err(WaiterLinkError::Semantic(Box::leak(msg.into_boxed_str())));
        }
        // Fail closed on the exact persisted attempt→signal binding.
        let Some(bound_signal) = self.attempt_signals.get(attempt_id) else {
            return Err(WaiterLinkError::Semantic(
                "no persisted attempt→signal binding for this attempt",
            ));
        };
        if bound_signal != signal_id {
            return Err(WaiterLinkError::Semantic(
                "signal_id does not match persisted attempt→signal binding",
            ));
        }
        let key = (signal_id.to_owned(), attempt_id.to_owned());
        let prior = self.transitions.get(&key).cloned().unwrap_or_default();
        if !prior.contains(&Transition::ReconciliationRequired) {
            return Err(WaiterLinkError::Semantic(
                "no prior ReconciliationRequired transition for this attempt",
            ));
        }
        // Idempotent repeat of the same resolution appends no transitions.
        if let Some(existing) = self.reconciliations.get(attempt_id) {
            if *existing == state {
                return Ok(());
            }
            return Err(WaiterLinkError::Semantic(
                "conflicting reconciliation resolution for attempt",
            ));
        }

        // ---- Stage transitions through the shared monotonic validator ----
        let mut staged = prior;
        match state {
            ReconciliationState::Accepted => {
                if !staged.contains(&Transition::NativeAccepted) {
                    validate_transition(Some(&staged), Transition::NativeAccepted)?;
                    staged.push(Transition::NativeAccepted);
                }
                if !staged.contains(&Transition::ReconciliationResolved) {
                    validate_transition(Some(&staged), Transition::ReconciliationResolved)?;
                    staged.push(Transition::ReconciliationResolved);
                }
            }
            ReconciliationState::ProvenNotAccepted | ReconciliationState::Terminal => {
                if !staged.contains(&Transition::ReconciliationResolved) {
                    validate_transition(Some(&staged), Transition::ReconciliationResolved)?;
                    staged.push(Transition::ReconciliationResolved);
                }
            }
            ReconciliationState::Unknown => {}
        }

        // ---- Commit ----
        self.transitions.insert(key, staged);
        self.reconciliations.insert(attempt_id.to_owned(), state);
        Ok(())
    }

    fn durability(&self) -> DurabilityClass {
        DurabilityClass::BestEffort
    }

    fn backend_identity(&self) -> &'static str {
        "fake-deterministic"
    }

    fn recover(&mut self) -> Result<RecoverySnapshot, ClaimError> {
        let mut transitions_map: BTreeMap<String, Vec<Transition>> = BTreeMap::new();
        for ((signal_id, attempt_id), ts) in &self.transitions {
            let key = format!("{signal_id}:{attempt_id}");
            transitions_map.insert(key, ts.clone());
        }
        Ok(RecoverySnapshot {
            claims: self.claims.values().cloned().collect(),
            transitions: transitions_map,
            dispositions: self.dispositions.clone(),
            attempt_map: self.claim_attempts.clone(),
            arms: self.persisted_arms.values().cloned().collect(),
            attachments: self.persisted_attachments.values().cloned().collect(),
            attempt_signals: self.attempt_signals.clone(),
            reconciliations: self.reconciliations.clone(),
            prepared_set: self.prepared_set.clone(),
            concluded_set: self.concluded_set.clone(),
            handled_cursors: self.handled_cursors.clone(),
            rearm_positions: self.rearm_positions.clone(),
            verifier_refs: self.verifier_refs.clone(),
            attempt_seq: self.attempt_seq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::DispatchDisposition;
    use gearwit_protocol::ProviderEvent;
    use time::macros::datetime;

    fn sample_claim(signal_id: &str, generation: u64, request_id: &str) -> DurableClaim {
        DurableClaim {
            request_id: request_id.to_owned(),
            arm_id: "01J00000000000000000000010".to_owned(),
            generation,
            signal_id: signal_id.to_owned(),
            event_refs: vec!["post01".to_owned()],
            events: vec![ProviderEvent {
                provider: "test".to_owned(),
                event_ref: "post01".to_owned(),
                actor: Some("example-devlead".to_owned()),
                observed_at: "2026-01-15T12:00:00Z".to_owned(),
                body: "test event".to_owned(),
            }],
            claimed_at: datetime!(2026-01-15 12:00:00 UTC),
        }
    }

    fn sample_claim_different_metadata(
        signal_id: &str,
        generation: u64,
        request_id: &str,
    ) -> DurableClaim {
        DurableClaim {
            request_id: request_id.to_owned(),
            arm_id: "01J00000000000000000000010".to_owned(),
            generation,
            signal_id: signal_id.to_owned(),
            event_refs: vec!["post01".to_owned()],
            events: vec![ProviderEvent {
                provider: "other-provider".to_owned(),
                event_ref: "post01".to_owned(),
                actor: Some("different-actor".to_owned()),
                observed_at: "2026-01-15T13:00:00Z".to_owned(),
                body: "test event".to_owned(),
            }],
            claimed_at: datetime!(2026-01-15 12:00:00 UTC),
        }
    }

    fn sample_attachment(attempt_id: &str, _signal_id: &str) -> PersistedAttachment {
        PersistedAttachment {
            attempt_id: attempt_id.to_owned(),
            arm_id: "01J00000000000000000000010".to_owned(),
            generation: 1,
            seat_id: "example-devrev".to_owned(),
            route: ManagedCapability::MANAGED_TURN_START_ROUTE.to_owned(),
            capability: ManagedCapability::ManagedTurnStart,
            lease_until: datetime!(2026-02-15 12:00:00 UTC),
            verifier_ref: format!("vrf:{attempt_id}"),
            revoked: false,
        }
    }

    fn sample_arm() -> PersistedArm {
        PersistedArm {
            arm_id: "01J00000000000000000000010".to_owned(),
            generation: 1,
            seat_id: "example-devrev".to_owned(),
            route: ManagedCapability::MANAGED_TURN_START_ROUTE.to_owned(),
            capability: ManagedCapability::ManagedTurnStart,
            coverage_until: datetime!(2026-02-15 12:00:00 UTC),
        }
    }

    /// Admit a claim with the standard sample attachment.
    fn admit(persist: &mut FakePersist, claim: &DurableClaim, attempt_id: &str) -> AdmissionRecord {
        let attachment = sample_attachment(attempt_id, &claim.signal_id);
        persist
            .admit_claim(claim, Some(&attachment))
            .expect("admit")
    }

    #[test]
    fn first_claim_is_admitted() {
        let mut persist = FakePersist::default();
        let claim = sample_claim("01J00000000000000000000021", 1, "req-1");
        let record = admit(&mut persist, &claim, "attempt-1");
        assert_eq!(record.outcome, ClaimOutcome::Admitted);
        assert_eq!(persist.claim_count(), 1);
        // Admission is atomic across all families.
        assert!(persist.persisted_attachments.contains_key("attempt-1"));
        assert_eq!(
            persist.attempt_signals.get("attempt-1"),
            Some(&"01J00000000000000000000021".to_owned())
        );
        assert_eq!(persist.attempt_seq, 1);
    }

    #[test]
    fn exact_replay_is_idempotent() {
        let mut persist = FakePersist::default();
        let claim = sample_claim("01J00000000000000000000021", 1, "req-1");
        let record = admit(&mut persist, &claim, "attempt-1");
        assert_eq!(record.outcome, ClaimOutcome::Admitted);
        let record = persist.admit_claim(&claim, None).expect("replay");
        assert_eq!(record.outcome, ClaimOutcome::Replay);
        assert_eq!(record.attempt_id, "attempt-1");
    }

    #[test]
    fn later_time_replay_is_idempotent() {
        let mut persist = FakePersist::default();
        let claim = sample_claim("01J00000000000000000000021", 1, "req-1");
        admit(&mut persist, &claim, "attempt-1");
        let later = DurableClaim {
            claimed_at: datetime!(2026-01-15 13:00:00 UTC),
            ..claim.clone()
        };
        let record = persist.admit_claim(&later, None).expect("replay");
        assert_eq!(record.outcome, ClaimOutcome::Replay);
    }

    #[test]
    fn replay_ignores_supplied_attachment() {
        let mut persist = FakePersist::default();
        let claim = sample_claim("01J00000000000000000000021", 1, "req-1");
        admit(&mut persist, &claim, "attempt-1");
        // A bogus attachment on replay must not be persisted.
        let bogus = sample_attachment("attempt-99", "wrong");
        let record = persist.admit_claim(&claim, Some(&bogus)).expect("replay");
        assert_eq!(record.outcome, ClaimOutcome::Replay);
        assert!(!persist.persisted_attachments.contains_key("attempt-99"));
        assert!(!persist.attempt_signals.contains_key("attempt-99"));
    }

    #[test]
    fn same_request_id_different_body_is_conflict() {
        let mut persist = FakePersist::default();
        let first = sample_claim("01J00000000000000000000021", 1, "req-1");
        admit(&mut persist, &first, "attempt-1");
        let mut second = first.clone();
        second.events[0].body = "different".to_owned();
        assert_eq!(
            persist.admit_claim(&second, None),
            Err(ClaimError::Conflict)
        );
    }

    #[test]
    fn changed_metadata_is_not_exact_replay() {
        // Different provider/actor/observed_at with same body and request_id
        // should be detected as a conflict, not an exact replay.
        let mut persist = FakePersist::default();
        let first = sample_claim("01J00000000000000000000021", 1, "req-1");
        admit(&mut persist, &first, "attempt-1");
        let changed = sample_claim_different_metadata("01J00000000000000000000021", 1, "req-1");
        assert_eq!(
            persist.admit_claim(&changed, None),
            Err(ClaimError::Conflict)
        );
    }

    #[test]
    fn different_request_id_same_signal_allows_new_claim() {
        let mut persist = FakePersist::default();
        let first = sample_claim("01J00000000000000000000021", 1, "req-1");
        admit(&mut persist, &first, "attempt-1");
        // Different request_id with same signal_id but different generation
        let second = sample_claim("01J00000000000000000000021", 2, "req-2");
        let record = admit(&mut persist, &second, "attempt-2");
        assert_eq!(record.outcome, ClaimOutcome::Admitted);
    }

    #[test]
    fn storage_failure_is_returned() {
        let mut persist = FakePersist {
            next_claim_error: Some("disk full".to_owned()),
            ..Default::default()
        };
        let claim = sample_claim("01J00000000000000000000021", 1, "req-1");
        assert!(matches!(
            persist.admit_claim(&claim, None),
            Err(ClaimError::StorageFailure(_))
        ));
        assert_eq!(persist.claim_count(), 0);
    }

    #[test]
    fn occupied_arm_generation_rejects_new_request() {
        let mut persist = FakePersist::default();
        let first = sample_claim("01J00000000000000000000021", 1, "req-1");
        admit(&mut persist, &first, "attempt-1");
        assert_eq!(
            persist.admit_claim(
                &sample_claim("01J00000000000000000000022", 1, "req-2"),
                Some(&sample_attachment(
                    "attempt-2",
                    "01J00000000000000000000022"
                )),
            ),
            Err(ClaimError::OccupiedDifferent)
        );
    }

    #[test]
    fn different_generation_allows_new_claim() {
        let mut persist = FakePersist::default();
        let first = sample_claim("01J00000000000000000000021", 1, "req-1");
        admit(&mut persist, &first, "attempt-1");
        let record = admit(
            &mut persist,
            &sample_claim("01J00000000000000000000022", 2, "req-2"),
            "attempt-2",
        );
        assert_eq!(record.outcome, ClaimOutcome::Admitted);
    }

    #[test]
    fn duplicate_transition_is_rejected() {
        let mut persist = FakePersist::default();
        assert!(
            persist
                .record_transition("sig-1", "attempt-1", Transition::ClaimRecorded)
                .is_ok()
        );
        assert!(
            persist
                .record_transition("sig-1", "attempt-1", Transition::ClaimRecorded)
                .is_err()
        );
    }

    #[test]
    fn regressive_transition_is_rejected() {
        let mut persist = FakePersist::default();
        persist
            .record_transition("sig-1", "attempt-1", Transition::ClaimRecorded)
            .expect("claim");
        persist
            .record_transition("sig-1", "attempt-1", Transition::DispatchPrepared)
            .expect("dispatch");
        // ClaimRecorded after DispatchPrepared is regressive
        assert!(
            persist
                .record_transition("sig-1", "attempt-1", Transition::ClaimRecorded)
                .is_err()
        );
    }

    #[test]
    fn first_transition_must_be_claim_recorded() {
        let mut persist = FakePersist::default();
        assert!(
            persist
                .record_transition("sig-1", "attempt-1", Transition::DispatchPrepared)
                .is_err()
        );
    }

    #[test]
    fn different_attempts_allow_independent_transitions() {
        // Same signal_id, different attempt_id → independent state machines
        let mut persist = FakePersist::default();
        persist
            .record_transition("sig-1", "attempt-1", Transition::ClaimRecorded)
            .expect("claim a1");
        persist
            .record_transition("sig-1", "attempt-1", Transition::DispatchPrepared)
            .expect("dispatch a1");
        // Different attempt, starts fresh
        persist
            .record_transition("sig-1", "attempt-2", Transition::ClaimRecorded)
            .expect("claim a2");
    }

    #[test]
    fn reconciliation_after_native_accepted_is_valid() {
        let mut persist = FakePersist::default();
        persist
            .record_transition("sig-1", "attempt-1", Transition::ClaimRecorded)
            .expect("claim");
        persist
            .record_transition("sig-1", "attempt-1", Transition::DispatchPrepared)
            .expect("dispatch");
        persist
            .record_transition("sig-1", "attempt-1", Transition::NativeAccepted)
            .expect("accepted");
        persist
            .record_transition("sig-1", "attempt-1", Transition::ReconciliationRequired)
            .expect("reconciliation required");
        persist
            .record_transition("sig-1", "attempt-1", Transition::ReconciliationResolved)
            .expect("reconciliation resolved");
    }

    #[test]
    fn accepted_reconciliation_transitions_are_valid() {
        // The accepted-resolution shape: RR → NativeAccepted → Resolved.
        let mut persist = FakePersist::default();
        let claim = sample_claim("sig-1", 1, "req-1");
        admit(&mut persist, &claim, "attempt-1");
        persist
            .record_transition("sig-1", "attempt-1", Transition::DispatchPrepared)
            .expect("dispatch");
        persist
            .record_reconciliation("attempt-1", "sig-1", ReconciliationState::Accepted)
            .expect_err("no prior ReconciliationRequired");
        persist
            .record_transition("sig-1", "attempt-1", Transition::ReconciliationRequired)
            .expect("required");
        persist
            .record_reconciliation("attempt-1", "sig-1", ReconciliationState::Accepted)
            .expect("accepted resolution");
        {
            let ts = persist.get_transitions("sig-1", "attempt-1");
            assert!(
                ts.contains(&Transition::NativeAccepted)
                    && ts.contains(&Transition::ReconciliationResolved)
            );
        }
        assert_eq!(
            persist.reconciliations.get("attempt-1"),
            Some(&ReconciliationState::Accepted)
        );
        // Idempotent repeat appends nothing.
        let len_before = persist.get_transitions("sig-1", "attempt-1").len();
        persist
            .record_reconciliation("attempt-1", "sig-1", ReconciliationState::Accepted)
            .expect("idempotent repeat");
        assert_eq!(
            persist.get_transitions("sig-1", "attempt-1").len(),
            len_before
        );
        // Conflicting resolution is rejected.
        assert!(
            persist
                .record_reconciliation("attempt-1", "sig-1", ReconciliationState::Terminal)
                .is_err()
        );
    }

    #[test]
    fn reconciliation_signal_binding_fails_closed() {
        let mut persist = FakePersist::default();
        let claim = sample_claim("sig-1", 1, "req-1");
        admit(&mut persist, &claim, "attempt-1");
        persist
            .record_transition("sig-1", "attempt-1", Transition::DispatchPrepared)
            .expect("dispatch");
        persist
            .record_transition("sig-1", "attempt-1", Transition::ReconciliationRequired)
            .expect("required");
        // Wrong signal id → fail closed, no resolution recorded.
        assert!(
            persist
                .record_reconciliation("attempt-1", "sig-99", ReconciliationState::Terminal)
                .is_err()
        );
        assert!(persist.reconciliations.is_empty());
        // Unknown attempt → fail closed.
        assert!(
            persist
                .record_reconciliation("attempt-99", "sig-1", ReconciliationState::Terminal)
                .is_err()
        );
    }

    #[test]
    fn record_prepared_is_atomic_and_binding_checked() {
        let mut persist = FakePersist::default();
        let claim = sample_claim("sig-1", 1, "req-1");
        admit(&mut persist, &claim, "attempt-1");
        // Wrong binding fails closed — no transition, no marker.
        assert!(persist.record_prepared("sig-99", "attempt-1").is_err());
        assert!(!persist.prepared_set.contains_key("attempt-1"));
        assert!(persist.get_transitions("sig-1", "attempt-1").len() == 1);
        // Correct prep records both atomically.
        persist
            .record_prepared("sig-1", "attempt-1")
            .expect("prepare");
        assert!(persist.prepared_set.contains_key("attempt-1"));
        assert_eq!(persist.get_transitions("sig-1", "attempt-1").len(), 2);
        // Duplicate prepare is rejected without mutating.
        assert!(persist.record_prepared("sig-1", "attempt-1").is_err());
        assert_eq!(persist.get_transitions("sig-1", "attempt-1").len(), 2);
    }

    #[test]
    fn record_prepare_error_injection_is_atomic() {
        let mut persist = FakePersist {
            next_prepare_error: Some("prepare failed".to_owned()),
            ..Default::default()
        };
        let claim = sample_claim("sig-1", 1, "req-1");
        admit(&mut persist, &claim, "attempt-1");
        assert!(persist.record_prepared("sig-1", "attempt-1").is_err());
        assert!(!persist.prepared_set.contains_key("attempt-1"));
        assert_eq!(persist.get_transitions("sig-1", "attempt-1").len(), 1);
    }

    #[test]
    fn record_conclusion_is_fully_atomic() {
        let mut persist = FakePersist::default();
        let claim = sample_claim("sig-1", 1, "req-1");
        admit(&mut persist, &claim, "attempt-1");
        persist
            .record_prepared("sig-1", "attempt-1")
            .expect("prepare");
        let conclusion = crate::controller::DispatchDisposition::Ambiguous;
        persist
            .record_conclusion(
                "attempt-1",
                "sig-1",
                &conclusion,
                Some(Transition::ReconciliationRequired),
            )
            .expect("conclusion");
        assert_eq!(
            persist.get_disposition("attempt-1"),
            Some(&crate::controller::DispatchDisposition::Ambiguous)
        );
        assert!(persist.concluded_set.contains_key("attempt-1"));
        assert!(
            persist
                .get_transitions("sig-1", "attempt-1")
                .contains(&Transition::ReconciliationRequired)
        );
    }

    #[test]
    fn record_conclusion_failure_commits_nothing() {
        for injection in ["disposition", "commit"] {
            let mut persist = FakePersist::default();
            if injection == "disposition" {
                persist.next_disposition_error = Some("disposition failed".to_owned());
            } else {
                persist.next_conclusion_error = Some("commit failed".to_owned());
            }
            let claim = sample_claim("sig-1", 1, "req-1");
            admit(&mut persist, &claim, "attempt-1");
            persist
                .record_prepared("sig-1", "attempt-1")
                .expect("prepare");
            let outcome = persist.record_conclusion(
                "attempt-1",
                "sig-1",
                &DispatchDisposition::Accepted {
                    correlation: "c".to_owned(),
                },
                Some(Transition::NativeAccepted),
            );
            assert!(outcome.is_err(), "injection={injection}");
            // Nothing observable: no disposition, no transition, no marker.
            assert!(persist.get_disposition("attempt-1").is_none());
            assert!(!persist.concluded_set.contains_key("attempt-1"));
            assert_eq!(persist.get_transitions("sig-1", "attempt-1").len(), 2);
        }
    }

    #[test]
    fn transition_failure_is_atomic_within_conclusion() {
        // A regressive first transition must fail the entire conclusion.
        let mut persist = FakePersist::default();
        let claim = sample_claim("sig-1", 1, "req-1");
        admit(&mut persist, &claim, "attempt-1");
        persist
            .record_prepared("sig-1", "attempt-1")
            .expect("prepare");
        // ClaimRecorded is regressive here — conclusion must fail everywhere.
        assert!(
            persist
                .record_conclusion(
                    "attempt-1",
                    "sig-1",
                    &DispatchDisposition::Rejected,
                    Some(Transition::ClaimRecorded),
                )
                .is_err()
        );
        assert!(persist.get_disposition("attempt-1").is_none());
        assert!(!persist.concluded_set.contains_key("attempt-1"));
        assert_eq!(persist.get_transitions("sig-1", "attempt-1").len(), 2);
    }

    #[test]
    fn transitions_are_ordered() {
        let mut persist = FakePersist::default();
        persist
            .record_transition("sig-1", "attempt-1", Transition::ClaimRecorded)
            .expect("claim");
        persist
            .record_transition("sig-1", "attempt-1", Transition::DispatchPrepared)
            .expect("dispatch");
        persist
            .record_transition("sig-1", "attempt-1", Transition::NativeAccepted)
            .expect("accepted");
        persist
            .record_transition("sig-1", "attempt-1", Transition::ExactTurnStart)
            .expect("start");
        persist
            .record_transition("sig-1", "attempt-1", Transition::ExactTurnTerminal)
            .expect("terminal");
        assert_eq!(
            persist.get_transitions("sig-1", "attempt-1"),
            &[
                Transition::ClaimRecorded,
                Transition::DispatchPrepared,
                Transition::NativeAccepted,
                Transition::ExactTurnStart,
                Transition::ExactTurnTerminal,
            ]
        );
    }

    #[test]
    fn recover_returns_claims_transitions_and_dispositions() {
        let mut persist = FakePersist::default();
        let claim = sample_claim("01J00000000000000000000021", 1, "req-1");
        admit(&mut persist, &claim, "attempt-1");
        // The admission already recorded ClaimRecorded for
        // (01J…21, attempt-1); a duplicate is rejected.
        persist
            .record_transition(
                "01J00000000000000000000021",
                "attempt-1",
                Transition::ClaimRecorded,
            )
            .expect_err("duplicate ClaimRecorded from admission");
        persist
            .record_disposition(
                "attempt-1",
                &DispatchDisposition::Accepted {
                    correlation: "turn-X".to_owned(),
                },
            )
            .expect("disp");
        persist.persist_arm_state(&sample_arm()).expect("arm");
        let snapshot = persist.recover().expect("recover");
        assert_eq!(snapshot.claims.len(), 1);
        assert!(
            snapshot
                .transitions
                .contains_key("01J00000000000000000000021:attempt-1")
        );
        assert!(snapshot.dispositions.contains_key("attempt-1"));
        assert_eq!(snapshot.arms.len(), 1);
        assert_eq!(snapshot.attachments.len(), 1);
        assert_eq!(
            snapshot.attempt_signals.get("attempt-1"),
            Some(&"01J00000000000000000000021".to_owned())
        );
    }

    #[test]
    fn record_disposition_is_idempotent() {
        let mut persist = FakePersist::default();
        let d = DispatchDisposition::Accepted {
            correlation: "turn-X".to_owned(),
        };
        persist.record_disposition("attempt-1", &d).expect("first");
        // Same disposition, same attempt_id = ok (idempotent)
        persist.record_disposition("attempt-1", &d).expect("replay");
    }

    #[test]
    fn conflicting_disposition_is_rejected() {
        let mut persist = FakePersist::default();
        persist
            .record_disposition(
                "attempt-1",
                &DispatchDisposition::Accepted {
                    correlation: "turn-X".to_owned(),
                },
            )
            .expect("first");
        assert!(
            persist
                .record_disposition("attempt-1", &DispatchDisposition::Rejected,)
                .is_err()
        );
    }

    #[test]
    fn storage_failure_on_transition_is_returned() {
        let mut persist = FakePersist {
            next_transition_error: Some("transition write failed".to_owned()),
            ..Default::default()
        };
        assert!(
            persist
                .record_transition("sig-1", "attempt-1", Transition::ClaimRecorded)
                .is_err()
        );
    }

    #[test]
    fn storage_failure_on_disposition_is_returned() {
        let mut persist = FakePersist {
            next_disposition_error: Some("disposition write failed".to_owned()),
            ..Default::default()
        };
        assert!(
            persist
                .record_disposition(
                    "attempt-1",
                    &DispatchDisposition::Accepted {
                        correlation: "turn-X".to_owned(),
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn arm_persist_is_full_policy() {
        let mut persist = FakePersist::default();
        persist.persist_arm_state(&sample_arm()).expect("persist");
        let snapshot = persist.recover().expect("recover");
        let arm = snapshot.arms.first().expect("arm");
        assert_eq!(arm.seat_id, "example-devrev");
        assert_eq!(arm.capability, ManagedCapability::ManagedTurnStart);
        assert_eq!(arm.coverage_until, datetime!(2026-02-15 12:00:00 UTC));
    }

    #[test]
    fn fake_identity_is_correct() {
        let persist = FakePersist::default();
        assert_eq!(persist.backend_identity(), "fake-deterministic");
        assert_eq!(persist.durability(), DurabilityClass::BestEffort);
    }
}
