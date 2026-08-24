//! Daemon authority: single-writer exclusive &mut self boundary for
//! claim admission, dispatch orchestration, and recovery.
//!
//! `DaemonAuthority<P>` owns the live arm/generation registry, the
//! long-lived `Persist` store, claim/attempt state, and attachment
//! verifier/lease/revocation state. Callers supply only claim requests
//! and events; they never supply arm, generation, attempt id, store,
//! or attachment.
//!
//! Generation mutations — including handled-cursor re-arm — occur
//! behind the same exclusive `&mut self` boundary.
//!
//! Crucible v0 contracts are preserved; this module does not alter
//! merged schemas.

use crate::controller::{
    Controller, DispatchDisposition, LifecycleObservation, ReconciliationDisposition, SignalAction,
};
use crate::persist::{ClaimError, ClaimOutcome, DurableClaim, Persist, Transition};
use crate::{KnownArm, RecoverySnapshot};
use std::collections::BTreeMap;
use time::OffsetDateTime;

// -- Minted attachment --------------------------------------------------

/// Host-minted controller attachment bound to exact seat, arm,
/// generation, managed-turn capability, route, attempt, controller/
/// verifier reference, revocation state, and unexpired lease.
///
/// Fields are private — callers cannot mutate dimensions
/// independently. Lease, seat, and route are derived from
/// authority policy at mint time via `ClaimRequest`. The
/// attachment is validated by dispatch preparation against the
/// complete stored authority record, not only the verifier ref.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintedAttachment {
    attempt_id: String,
    arm_id: String,
    generation: u64,
    seat_id: String,
    route: String,
    lease_until: OffsetDateTime,
    verifier_ref: String,
    revoked: bool,
}

impl MintedAttachment {
    /// The attempt id.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// The arm id.
    #[must_use]
    pub fn arm_id(&self) -> &str {
        &self.arm_id
    }

    /// The arm generation at claim time.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The opaque verifier reference for recovery.
    #[must_use]
    pub fn verifier_ref(&self) -> &str {
        &self.verifier_ref
    }

    /// Whether this attachment is still valid (not revoked, not expired).
    #[must_use]
    pub fn is_valid(&self, now: OffsetDateTime) -> bool {
        !self.revoked && self.lease_until > now
    }

    /// Revoke this attachment.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

// -- Dispatch state machine layers --------------------------------------

/// Result of preparing a dispatch under authority.
///
/// Opaque, non-Clone, single-use token. The authority lock is released
/// after this is returned; the caller performs native I/O and then
/// passes this by value back into `conclude_dispatch`. Duplicate
/// conclusion is a durable authority invariant, not only move semantics.
#[derive(Debug)]
pub struct PreparedDispatch {
    attempt_id: String,
    signal_id: String,
    /// Action for native I/O — the only public field.
    pub action: SignalAction,
    /// Opaque consumed marker — authority sets this on first conclusion.
    consumed: bool,
}

impl PreparedDispatch {
    /// The signal action for native I/O the caller must execute.
    /// Only method accessible to callers outside the authority.
    #[must_use]
    pub fn action(&self) -> &SignalAction {
        &self.action
    }
}

/// Result of concluding a dispatch after native I/O and observations.
///
/// All fields represent facts that have been durably persisted.
/// `reconciliation_required` and `controller_lost` are derived from
/// disposition and observations; external callers cannot construct
/// contradictory evidence states.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchConclusion {
    /// The disposition recorded.
    pub disposition: DispatchDisposition,
    /// Observations recorded (empty for ambiguous/rejected).
    pub observations: Vec<LifecycleObservation>,
    // Whether reconciliation is required — derived from disposition.
    reconciliation_required: bool,
    // Whether the controller was lost — derived from observations.
    controller_lost: bool,
}

impl DispatchConclusion {
    /// Whether reconciliation is required (derived from disposition).
    #[must_use]
    pub fn reconciliation_required(&self) -> bool {
        matches!(self.disposition, DispatchDisposition::Ambiguous)
    }

    /// Whether the controller was lost (derived from observations).
    #[must_use]
    pub fn controller_lost(&self) -> bool {
        self.observations
            .iter()
            .any(|o| matches!(o, LifecycleObservation::ControllerLost))
    }

    /// The strongest lifecycle conclusion durably recorded.
    #[must_use]
    pub fn durable_outcome(&self) -> DurableOutcome {
        if self.reconciliation_required() {
            DurableOutcome::Ambiguous
        } else if self.controller_lost() {
            DurableOutcome::ControllerLost
        } else {
            match &self.disposition {
                DispatchDisposition::Rejected => DurableOutcome::Rejected,
                DispatchDisposition::Ambiguous => DurableOutcome::Ambiguous,
                DispatchDisposition::Accepted { .. } => {
                    if self
                        .observations
                        .iter()
                        .any(|o| matches!(o, LifecycleObservation::TurnTerminal(..)))
                    {
                        DurableOutcome::Terminal
                    } else if self
                        .observations
                        .iter()
                        .any(|o| matches!(o, LifecycleObservation::TurnStarted(_)))
                    {
                        DurableOutcome::Started
                    } else {
                        DurableOutcome::Accepted
                    }
                }
            }
        }
    }
}

/// Strongest lifecycle conclusion durably persisted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableOutcome {
    /// Controller rejected the dispatch.
    Rejected,
    /// Controller accepted; no observations yet.
    Accepted,
    /// Controller accepted and turn started; not yet terminal.
    Started,
    /// Turn reached terminal state.
    Terminal,
    /// Acceptance is ambiguous; reconciliation needed.
    Ambiguous,
    /// Controller was lost.
    ControllerLost,
}

// -- DaemonAuthority ----------------------------------------------------

/// Single-writer daemon authority for claim admission, dispatch
/// orchestration, and recovery.
///
/// Type parameter `P` is the persistence backend. The authority owns
/// the live arm registry, the store, and all claim/attempt state.
pub struct DaemonAuthority<P: Persist> {
    /// Persistence backend.
    persist: P,
    /// Live arms keyed by `arm_id`.
    arms: BTreeMap<String, KnownArm>,
    /// Minted attachments keyed by `attempt_id`.
    attachments: BTreeMap<String, MintedAttachment>,
    /// Current time source (injectable for tests).
    now: OffsetDateTime,
    /// Monotonic attempt counter.
    attempt_seq: u64,
    /// Handled cursor position per `arm_id`.
    handled_cursors: BTreeMap<String, String>,
    /// Whether each arm is re-arming.
    rearm_positions: BTreeMap<String, bool>,
}

impl<P: Persist + Default> Default for DaemonAuthority<P> {
    fn default() -> Self {
        Self {
            persist: P::default(),
            arms: BTreeMap::new(),
            attachments: BTreeMap::new(),
            now: OffsetDateTime::now_utc(),
            attempt_seq: 0,
            handled_cursors: BTreeMap::new(),
            rearm_positions: BTreeMap::new(),
        }
    }
}

/// Input for claim admission — external identifiers and events only.
/// Seat, capability route, and lease are derived from the registered
/// `KnownArm` and host policy; callers do not supply them.
#[derive(Clone, Debug)]
pub struct ClaimRequest {
    /// Arm to resolve generation for.
    pub arm_id: String,
    /// Stable idempotency key.
    pub request_id: String,
    /// Stable signal id.
    pub signal_id: String,
    /// Bounded event batch.
    pub events: Vec<ProviderEvent>,
}

impl<P: Persist> DaemonAuthority<P> {
    /// Create a new authority with the given persistence backend and
    /// fixed time (for deterministic tests).
    #[must_use]
    pub fn new(persist: P, now: OffsetDateTime) -> Self {
        Self {
            persist,
            arms: BTreeMap::new(),
            attachments: BTreeMap::new(),
            now,
            attempt_seq: 0,
            handled_cursors: BTreeMap::new(),
            rearm_positions: BTreeMap::new(),
        }
    }

    /// Register a known arm.
    pub fn register_arm(&mut self, arm: KnownArm) {
        self.arms.insert(arm.arm_id.clone(), arm);
    }

    /// Advance generation for an arm — the production re-arm path.
    ///
    /// Bumps the arm's generation by 1, invalidating all previously minted
    /// attachments that carry the old generation. Returns the new generation.
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError::UnknownArm` when the arm is not registered.
    pub fn advance_generation(&mut self, arm_id: &str) -> Result<u64, AdmissionError> {
        let arm = self
            .arms
            .get_mut(arm_id)
            .ok_or(AdmissionError::UnknownArm)?;
        arm.generation += 1;
        Ok(arm.generation)
    }

    /// Current time (injectable for tests).
    #[must_use]
    pub fn now(&self) -> OffsetDateTime {
        self.now
    }

    /// Advance time for tests.
    pub fn set_now(&mut self, now: OffsetDateTime) {
        self.now = now;
    }

    // -- Claim admission --------------------------------------------------

    /// Atomically resolve arm generation, durably admit the claim
    /// (including `ClaimRecorded` transition as one atomic operation),
    /// and mint a controller attachment — all under the exclusive
    /// `&mut self` authority boundary.
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError` when the arm is unknown, generation is
    /// stale, claim is occupied, storage fails, or `ClaimRecorded` cannot
    /// be persisted.
    pub fn admit_claim(&mut self, req: &ClaimRequest) -> Result<AdmissionResult, AdmissionError> {
        // 1. Resolve arm under authority
        let arm = self
            .arms
            .get(&req.arm_id)
            .ok_or(AdmissionError::UnknownArm)?
            .clone();

        // 2. Build durable claim
        let event_refs: Vec<String> = req.events.iter().map(|e| e.event_ref.clone()).collect();
        let claim = DurableClaim {
            request_id: req.request_id.clone(),
            arm_id: arm.arm_id.clone(),
            generation: arm.generation,
            signal_id: req.signal_id.clone(),
            event_refs,
            events: req.events.clone(),
            claimed_at: self.now,
        };

        // 3. Atomically admit claim + ClaimRecorded + attempt + verifier
        let record = self.persist.admit_claim(&claim).map_err(|e| match e {
            ClaimError::OccupiedDifferent | ClaimError::StaleGeneration => AdmissionError::Occupied,
            ClaimError::Conflict => AdmissionError::Conflict,
            ClaimError::StorageFailure(msg) => AdmissionError::Storage(msg),
        })?;

        let attempt_id = record.attempt_id.clone();
        let is_replay = matches!(record.outcome, ClaimOutcome::Replay);

        // 4. Mint attachment (only for new claims — replay gets no
        //    dispatch-capable attachment per cxotech ruling).
        let minted_attachment = if is_replay {
            None
        } else {
            // Derive lease from arm coverage_until (host policy),
            // seat and route from registered arm.
            let lease_until = arm.coverage_until;
            let attachment = MintedAttachment {
                attempt_id: attempt_id.clone(),
                arm_id: arm.arm_id.clone(),
                generation: arm.generation,
                seat_id: arm.seat_id.clone(),
                route: arm.route.clone(),
                lease_until,
                verifier_ref: record.verifier_ref.clone(),
                revoked: false,
            };
            self.attachments
                .insert(attempt_id.clone(), attachment.clone());
            // Sync attempt_seq past the backend-minted id
            self.attempt_seq = self.attempt_seq.max(
                attempt_id
                    .strip_prefix("attempt-")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(self.attempt_seq),
            );
            Some(attachment)
        };

        // 5. Return result
        let claim_ref = ClaimedSignal {
            arm_id: claim.arm_id.clone(),
            generation: claim.generation,
            signal_id: claim.signal_id.clone(),
            request_id: claim.request_id.clone(),
            event_refs: claim.event_refs.clone(),
            events: claim.events.clone(),
        };

        Ok(AdmissionResult {
            outcome: record.outcome,
            claim: claim_ref,
            attachment: minted_attachment,
            attempt_id,
        })
    }

    // -- Dispatch preparation --------------------------------------------

    /// Prepare a dispatch: validate the minted attachment, durably
    /// record `DispatchPrepared`, and return a `PreparedDispatch` for
    /// native I/O. The authority lock is released after this call.
    ///
    /// # Errors
    ///
    /// Returns `DispatchError::PreSend` when the attachment is invalid
    /// or preparation cannot be persisted. The controller is never
    /// called in this case.
    pub fn prepare_dispatch(
        &mut self,
        claim: &ClaimedSignal,
        attachment: &MintedAttachment,
    ) -> Result<PreparedDispatch, DispatchError> {
        // 1. Validate attachment against authority state
        self.validate_attachment(attachment, claim)?;

        // 2. Record DispatchPrepared
        self.persist
            .record_transition(
                &claim.signal_id,
                &attachment.attempt_id,
                Transition::DispatchPrepared,
            )
            .map_err(|e| DispatchError::PreSend(format!("DispatchPrepared failed: {e:?}")))?;

        // 3. Return prepared dispatch for native I/O
        let action = SignalAction {
            signal_id: claim.signal_id.clone(),
            provider: "mattermost".to_owned(),
            event_count: claim.events.len(),
        };

        Ok(PreparedDispatch {
            attempt_id: attachment.attempt_id.clone(),
            signal_id: claim.signal_id.clone(),
            action,
            consumed: false,
        })
    }

    /// Record lifecycle observations as durable transitions.
    fn record_observations(
        &mut self,
        signal_id: &str,
        attempt_id: &str,
        observations: &[LifecycleObservation],
    ) -> Result<(), DispatchError> {
        for obs in observations {
            match obs {
                LifecycleObservation::TurnStarted(_) => {
                    self.persist
                        .record_transition(signal_id, attempt_id, Transition::ExactTurnStart)
                        .map_err(|e| {
                            DispatchError::PostSend(format!(
                                "ExactTurnStart transition failed: {e:?}"
                            ))
                        })?;
                }
                LifecycleObservation::TurnTerminal(..) => {
                    self.persist
                        .record_transition(signal_id, attempt_id, Transition::ExactTurnTerminal)
                        .map_err(|e| {
                            DispatchError::PostSend(format!(
                                "ExactTurnTerminal transition failed: {e:?}"
                            ))
                        })?;
                }
                LifecycleObservation::ControllerLost => {
                    self.persist
                        .record_transition(signal_id, attempt_id, Transition::ControllerLost)
                        .map_err(|e| {
                            DispatchError::PostSend(format!(
                                "ControllerLost transition failed: {e:?}"
                            ))
                        })?;
                }
            }
        }
        Ok(())
    }

    /// Re-enter authority after native I/O: record the dispatch
    /// disposition and polled observations.
    ///
    /// Post-send failures return `DispatchError::PostSend` — a typed
    /// result distinct from `PreSend`, indicating the dispatch may
    /// have been accepted. Recovery derives reconciliation-required
    /// from `DispatchPrepared` without a durable conclusion.
    ///
    /// # Errors
    ///
    /// Returns `DispatchError::PostSend` when the disposition or
    /// observations cannot be persisted after native I/O.
    /// Returns `DispatchError::PreSend` when the prepared token has
    /// already been consumed — duplicate conclusion is a durable
    /// authority invariant.
    pub fn conclude_dispatch(
        &mut self,
        mut prepared: PreparedDispatch,
        disposition: DispatchDisposition,
        observations: Vec<LifecycleObservation>,
    ) -> Result<DispatchConclusion, DispatchError> {
        // 0. Reject already-consumed token (durable invariant)
        if prepared.consumed {
            return Err(DispatchError::PreSend(
                "prepared token already consumed".to_owned(),
            ));
        }
        prepared.consumed = true;

        // 1. Atomically record disposition + first required transition
        let first_transition = match &disposition {
            DispatchDisposition::Accepted { .. } => Some(Transition::NativeAccepted),
            DispatchDisposition::Ambiguous => Some(Transition::ReconciliationRequired),
            DispatchDisposition::Rejected => None,
        };
        self.persist
            .record_conclusion(
                &prepared.attempt_id,
                &prepared.signal_id,
                &disposition,
                first_transition,
            )
            .map_err(|e| DispatchError::PostSend(format!("conclusion write failed: {e:?}")))?;

        // 2. Record lifecycle transitions based on disposition
        match &disposition {
            DispatchDisposition::Rejected => {
                return Ok(DispatchConclusion {
                    disposition,
                    observations: Vec::new(),
                    reconciliation_required: false,
                    controller_lost: false,
                });
            }
            DispatchDisposition::Ambiguous => {
                return Ok(DispatchConclusion {
                    disposition,
                    observations: Vec::new(),
                    reconciliation_required: true,
                    controller_lost: false,
                });
            }
            DispatchDisposition::Accepted { .. } => {
                // Record observations via helper
                self.record_observations(&prepared.signal_id, &prepared.attempt_id, &observations)?;
            }
        }

        // 3. Derive controller_lost from observations, not a parallel boolean
        let controller_lost = observations
            .iter()
            .any(|o| matches!(o, LifecycleObservation::ControllerLost));

        Ok(DispatchConclusion {
            disposition,
            observations,
            reconciliation_required: false,
            controller_lost,
        })
    }

    // -- Attachment validation -------------------------------------------

    /// Validate the complete stored attachment record against the caller-supplied
    /// attachment. Every dimension is compared: `arm_id`, generation, `attempt_id`,
    /// `seat_id`, route, `verifier_ref`, lease expiry, and revocation.
    fn validate_attachment(
        &self,
        attachment: &MintedAttachment,
        claim: &ClaimedSignal,
    ) -> Result<(), DispatchError> {
        // Verify attachment was minted by this authority
        let stored = self
            .attachments
            .get(&attachment.attempt_id)
            .ok_or(DispatchError::PreSend(
                "attachment not minted by this authority".to_owned(),
            ))?;
        // Validate every dimension against stored record
        if attachment.arm_id != stored.arm_id {
            return Err(DispatchError::PreSend("arm_id mismatch".to_owned()));
        }
        if attachment.generation != stored.generation {
            return Err(DispatchError::PreSend("generation mismatch".to_owned()));
        }
        if attachment.verifier_ref != stored.verifier_ref {
            return Err(DispatchError::PreSend(
                "verifier_ref mismatch — attachment may be forged".to_owned(),
            ));
        }
        if attachment.seat_id != stored.seat_id {
            return Err(DispatchError::PreSend("seat_id mismatch".to_owned()));
        }
        if attachment.route != stored.route {
            return Err(DispatchError::PreSend("route mismatch".to_owned()));
        }
        if attachment.lease_until != stored.lease_until {
            return Err(DispatchError::PreSend(
                "lease_until mismatch — attachment may have been extended".to_owned(),
            ));
        }
        if attachment.attempt_id != stored.attempt_id {
            return Err(DispatchError::PreSend("attempt_id mismatch".to_owned()));
        }
        // Check revocation and lease against stored record
        if stored.revoked {
            return Err(DispatchError::PreSend("attachment is revoked".to_owned()));
        }
        if stored.lease_until <= self.now {
            return Err(DispatchError::PreSend(
                "attachment lease expired".to_owned(),
            ));
        }
        // Validate against claim
        if attachment.arm_id != claim.arm_id {
            return Err(DispatchError::PreSend(
                "arm_id mismatch with claim".to_owned(),
            ));
        }
        if attachment.generation != claim.generation {
            return Err(DispatchError::PreSend(
                "generation mismatch with claim".to_owned(),
            ));
        }
        // Validate seat/route match the registered arm
        if let Some(arm) = self.arms.get(&claim.arm_id) {
            if stored.seat_id != arm.seat_id {
                return Err(DispatchError::PreSend(
                    "seat_id mismatch with arm".to_owned(),
                ));
            }
            if stored.route != arm.route {
                return Err(DispatchError::PreSend("route mismatch with arm".to_owned()));
            }
            // Validate generation against live arm — stale attachments
            // from before a re-arm must be rejected.
            if stored.generation != arm.generation {
                return Err(DispatchError::PreSend(
                    "attachment generation is stale — arm has been re-armed".to_owned(),
                ));
            }
        }
        Ok(())
    }

    // -- Reconciliation --------------------------------------------------

    /// Reconcile after an ambiguous dispatch.
    #[must_use]
    pub fn reconcile(
        &self,
        controller: &dyn Controller,
        attempt_id: &str,
    ) -> ReconciliationDisposition {
        controller.reconcile(attempt_id)
    }

    // -- Recovery --------------------------------------------------------

    /// Recover authoritative state after daemon restart.
    ///
    /// Returns the persistence snapshot enriched with live arms,
    /// attachment verifier state, derivable ambiguous work, handled
    /// cursors, and re-arm positions — all reconstructed from
    /// persisted data, not current in-memory state.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError`] when the backend is unavailable or
    /// corrupt.
    pub fn recover(&mut self) -> Result<AuthorityRecovery, ClaimError> {
        let snapshot = self.persist.recover()?;

        // Reconstruct arms from persisted arm states
        for (arm_id, generation) in &snapshot.arm_states {
            if let Some(arm) = self.arms.get_mut(arm_id) {
                arm.generation = *generation;
            }
        }

        // Clone snapshot fields before moving snapshot itself
        let handled_cursors = snapshot.handled_cursors.clone();
        let rearm_positions = snapshot.rearm_positions.clone();
        let claims = snapshot.claims.clone();
        let attempt_map = snapshot.attempt_map.clone();
        let verifier_refs = snapshot.verifier_refs.clone();
        let attempt_seq = snapshot.attempt_seq;

        // Restore in-memory authority state from persisted data
        self.attempt_seq = attempt_seq;
        self.handled_cursors = handled_cursors.clone();
        self.rearm_positions = rearm_positions.clone();

        // Reconstruct attachments from attempt_map + persisted verifier refs
        let attachments: BTreeMap<String, MintedAttachment> = attempt_map
            .iter()
            .filter_map(|(request_id, attempt_id)| {
                let verifier_ref = verifier_refs.get(request_id)?.clone();
                let claim = claims.iter().find(|c| &c.request_id == request_id)?;
                Some((
                    attempt_id.clone(),
                    MintedAttachment {
                        attempt_id: attempt_id.clone(),
                        arm_id: claim.arm_id.clone(),
                        generation: claim.generation,
                        seat_id: String::new(),
                        route: String::new(),
                        lease_until: OffsetDateTime::now_utc(),
                        verifier_ref,
                        revoked: false,
                    },
                ))
            })
            .collect();

        Ok(AuthorityRecovery {
            snapshot,
            arms: self.arms.clone(),
            attachments,
            handled_cursors,
            rearm_positions,
        })
    }

    /// Record a handled cursor for an arm.
    pub fn record_handled_cursor(&mut self, arm_id: &str, cursor: &str) {
        self.handled_cursors
            .insert(arm_id.to_owned(), cursor.to_owned());
    }

    /// Mark an arm as re-armed.
    pub fn set_rearmed(&mut self, arm_id: &str) {
        self.rearm_positions.insert(arm_id.to_owned(), true);
    }

    /// Access the inner persistence for tests.
    #[must_use]
    pub fn persist(&self) -> &P {
        &self.persist
    }

    /// Mutable access to persistence for tests.
    pub fn persist_mut(&mut self) -> &mut P {
        &mut self.persist
    }

    /// Look up a minted attachment by `attempt_id`.
    #[must_use]
    pub fn get_attachment(&self, attempt_id: &str) -> Option<&MintedAttachment> {
        self.attachments.get(attempt_id)
    }

    /// Revoke an attachment by `attempt_id`. Returns `true` if found and revoked.
    pub fn revoke_attachment(&mut self, attempt_id: &str) -> bool {
        if let Some(att) = self.attachments.get_mut(attempt_id) {
            att.revoke();
            true
        } else {
            false
        }
    }
}

// -- Supporting types ---------------------------------------------------

use gearwit_protocol::ProviderEvent;

/// In-memory signal claim reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedSignal {
    /// Arm id.
    pub arm_id: String,
    /// Generation resolved and stamped at claim time.
    pub generation: u64,
    /// Stable signal id.
    pub signal_id: String,
    /// Stable request id.
    pub request_id: String,
    /// Oldest-first event refs.
    pub event_refs: Vec<String>,
    /// Bounded events.
    pub events: Vec<ProviderEvent>,
}

/// Result of claim admission.
#[derive(Clone, Debug)]
pub struct AdmissionResult {
    /// Admission outcome.
    pub outcome: ClaimOutcome,
    /// In-memory claim reference.
    pub claim: ClaimedSignal,
    /// Minted attachment (None on exact replay).
    pub attachment: Option<MintedAttachment>,
    /// Attempt id.
    pub attempt_id: String,
}

/// Why claim admission failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    /// Arm not found.
    UnknownArm,
    /// Arm+generation already occupied.
    Occupied,
    /// Same `request_id`, different body.
    Conflict,
    /// Storage unavailable.
    Storage(String),
}

/// Dispatch error, split into pre-send (safe retry) and post-send
/// (uncertain, must not retry).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchError {
    /// Error before native I/O — safe to retry.
    PreSend(String),
    /// Error after native I/O — do not retry; reconcile.
    PostSend(String),
}

/// Enriched recovery state including authority metadata.
#[derive(Clone, Debug)]
pub struct AuthorityRecovery {
    /// Raw persistence snapshot.
    pub snapshot: RecoverySnapshot,
    /// Live arms at shutdown.
    pub arms: BTreeMap<String, KnownArm>,
    /// Minted attachment state (verifier refs only — no bearer material).
    pub attachments: BTreeMap<String, MintedAttachment>,
    /// Handled cursors per arm.
    pub handled_cursors: BTreeMap<String, String>,
    /// Re-arm positions per arm.
    pub rearm_positions: BTreeMap<String, bool>,
}

impl AuthorityRecovery {
    /// Derive ambiguous dispatches:
    /// 1. `DispatchPrepared` without any conclusion (no disposition,
    ///    no `NativeAccepted`, no `ReconciliationRequired`, no `ControllerLost`).
    /// 2. A disposition exists but `NativeAccepted` is missing (partial
    ///    post-send write — disposition succeeded, transition failed).
    #[must_use]
    pub fn derivable_ambiguous_attempts(&self) -> Vec<String> {
        let mut ambiguous = Vec::new();
        for (key, transitions) in &self.snapshot.transitions {
            let Some(attempt_id) = key.split(':').nth(1) else {
                continue;
            };

            // Case 1: DispatchPrepared without any known conclusion
            // and no stored disposition (no disposition = never concluded).
            if transitions.contains(&Transition::DispatchPrepared)
                && !transitions.contains(&Transition::NativeAccepted)
                && !transitions.contains(&Transition::ReconciliationRequired)
                && !transitions.contains(&Transition::ControllerLost)
                && !self.snapshot.dispositions.contains_key(attempt_id)
            {
                ambiguous.push(attempt_id.to_owned());
                continue;
            }

            // Case 2: Accepted disposition exists but NativeAccepted missing
            // (partial post-send write: disposition recorded, transition failed).
            // Rejected dispositions are clean terminals — not ambiguous.
            if transitions.contains(&Transition::DispatchPrepared)
                && !transitions.contains(&Transition::NativeAccepted)
                && !transitions.contains(&Transition::ReconciliationRequired)
                && self
                    .snapshot
                    .dispositions
                    .get(attempt_id)
                    .is_some_and(|d| matches!(d, DispatchDisposition::Accepted { .. }))
            {
                ambiguous.push(attempt_id.to_owned());
                continue;
            }

            // Case 3: Ambiguous disposition recorded but ReconciliationRequired
            // missing (partial record_conclusion for Ambiguous disposition).
            if transitions.contains(&Transition::DispatchPrepared)
                && !transitions.contains(&Transition::ReconciliationRequired)
                && self
                    .snapshot
                    .dispositions
                    .get(attempt_id)
                    .is_some_and(|d| matches!(d, DispatchDisposition::Ambiguous))
            {
                ambiguous.push(attempt_id.to_owned());
            }
        }
        ambiguous
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::{FakeController, ReconciliationDisposition};
    use crate::persist::FakePersist;
    use gearwit_protocol::ProviderEvent;

    fn sample_event(body: &str) -> ProviderEvent {
        ProviderEvent {
            provider: "test".to_owned(),
            event_ref: format!("event-{body}"),
            actor: Some("example-devlead".to_owned()),
            observed_at: "2026-01-15T12:00:00Z".to_owned(),
            body: body.to_owned(),
        }
    }

    fn sample_arm() -> KnownArm {
        KnownArm {
            arm_id: "arm-01".to_owned(),
            generation: 1,
            seat_id: "example-devrev".to_owned(),
            route: "complete_background_tool".to_owned(),
            coverage_until: time::macros::datetime!(2026-02-15 12:00:00 UTC),
        }
    }

    fn sample_authority() -> DaemonAuthority<FakePersist> {
        let now = time::macros::datetime!(2026-01-15 12:00:00 UTC);
        let mut auth = DaemonAuthority::new(FakePersist::default(), now);
        auth.register_arm(sample_arm());
        auth
    }

    fn sample_authority_with_persist(persist: FakePersist) -> DaemonAuthority<FakePersist> {
        let now = time::macros::datetime!(2026-01-15 12:00:00 UTC);
        let mut auth = DaemonAuthority::new(persist, now);
        auth.register_arm(sample_arm());
        auth
    }

    fn claim_req(arm_id: &str, rid: &str, sid: &str, events: Vec<ProviderEvent>) -> ClaimRequest {
        ClaimRequest {
            arm_id: arm_id.to_owned(),
            request_id: rid.to_owned(),
            signal_id: sid.to_owned(),
            events,
        }
    }

    fn std_req() -> ClaimRequest {
        claim_req("arm-01", "req-1", "sig-1", vec![sample_event("hello")])
    }

    #[test]
    fn first_claim_admits_and_mints_attachment() {
        let mut auth = sample_authority();
        let ev = vec![sample_event("hello")];
        let req = claim_req("arm-01", "req-1", "sig-1", ev);
        let result = auth.admit_claim(&req).expect("admit");
        assert!(matches!(result.outcome, ClaimOutcome::Admitted));
        assert!(result.attachment.is_some());
        let att = result.attachment.as_ref().unwrap();
        assert_eq!(att.arm_id, "arm-01");
        assert_eq!(att.generation, 1);
        assert_eq!(att.seat_id, "example-devrev");
        assert_eq!(att.route, "complete_background_tool");
        assert!(!att.verifier_ref.is_empty());
        let ts = auth.persist().get_transitions("sig-1", &result.attempt_id);
        assert!(ts.contains(&Transition::ClaimRecorded));
    }

    #[test]
    fn unknown_arm_rejects_claim() {
        let mut auth = sample_authority();
        let ev = vec![sample_event("hello")];
        let req = claim_req("nonexistent", "req-1", "sig-1", ev);
        let err = auth.admit_claim(&req).expect_err("unknown arm");
        assert!(matches!(err, AdmissionError::UnknownArm));
    }

    #[test]
    fn occupied_arm_rejects_second_claim() {
        let mut auth = sample_authority();
        let ev1 = vec![sample_event("hello")];
        let req1 = claim_req("arm-01", "req-1", "sig-1", ev1);
        auth.admit_claim(&req1).expect("first");
        let ev2 = vec![sample_event("world")];
        let req2 = claim_req("arm-01", "req-2", "sig-2", ev2);
        let err = auth.admit_claim(&req2).expect_err("occupied");
        assert!(matches!(err, AdmissionError::Occupied));
    }

    #[test]
    fn exact_replay_returns_replay_without_attachment() {
        let mut auth = sample_authority();
        let ev = vec![sample_event("hello")];
        let req = claim_req("arm-01", "req-1", "sig-1", ev.clone());
        let first = auth.admit_claim(&req).expect("first");
        assert!(first.attachment.is_some());
        assert!(matches!(first.outcome, ClaimOutcome::Admitted));
        let req2 = claim_req("arm-01", "req-1", "sig-1", ev);
        let replay = auth.admit_claim(&req2).expect("replay");
        assert!(matches!(replay.outcome, ClaimOutcome::Replay));
        assert!(
            replay.attachment.is_none(),
            "replay must not mint attachment"
        );
        assert_eq!(replay.claim, first.claim);
    }

    #[test]
    fn generation_advance_under_authority_produces_new_generation_claim() {
        let mut auth = sample_authority();
        let ev = vec![sample_event("hello")];
        let req = claim_req("arm-01", "req-1", "sig-1", ev);
        let first = auth.admit_claim(&req).expect("first");
        assert_eq!(first.claim.generation, 1);

        // Advance generation through production re-arm path (not direct field mutation).
        let new_gen = auth
            .advance_generation("arm-01")
            .expect("advance generation");
        assert_eq!(new_gen, 2);

        let ev2 = vec![sample_event("world")];
        let req2 = claim_req("arm-01", "req-2", "sig-2", ev2);
        let second = auth.admit_claim(&req2).expect("generation advanced");
        assert_eq!(second.claim.generation, 2);
        assert!(second.attachment.is_some());
        assert_eq!(second.attachment.unwrap().generation, 2);
    }

    #[test]
    fn stale_generation_rejects_prepare_after_rearm() {
        // Daemon-level harness: advance generation through production
        // re-arm path, then prove a stale gen-1 attachment is rejected
        // during attempted prepare (not after two completes).
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit gen 1");
        let stale_attachment = admission.attachment.expect("gen-1 attachment");

        // Re-arm: advance generation through production path.
        auth.advance_generation("arm-01").expect("advance");

        // Attempt to prepare with the stale gen-1 attachment — must be rejected.
        let err = auth
            .prepare_dispatch(&admission.claim, &stale_attachment)
            .expect_err("stale generation must reject prepare");
        assert!(
            matches!(&err, DispatchError::PreSend(msg) if msg.contains("generation")),
            "expected generation mismatch, got {err:?}"
        );

        // Verify a new claim at gen 2 produces a fresh attachment.
        let ev2 = vec![sample_event("world")];
        let req2 = claim_req("arm-01", "req-2", "sig-2", ev2);
        let fresh = auth.admit_claim(&req2).expect("fresh claim at gen 2");
        assert_eq!(fresh.claim.generation, 2);
        assert!(fresh.attachment.is_some());
    }

    #[test]
    fn claim_recorded_failure_prevents_slot_publication() {
        let now = time::macros::datetime!(2026-01-15 12:00:00 UTC);

        // Inject atomic admission failure — claim, attempt, verifier,
        // and ClaimRecorded must not persist.
        let backend = FakePersist {
            next_claim_error: Some("write failed".to_owned()),
            ..Default::default()
        };
        let mut auth = DaemonAuthority::new(backend.clone(), now);
        auth.register_arm(sample_arm());
        let req = claim_req("arm-01", "req-1", "sig-1", vec![sample_event("hello")]);
        let err = auth.admit_claim(&req).expect_err("storage failure");
        assert!(matches!(err, AdmissionError::Storage(_)));

        // Prove the failed backend has no partial state in all four families.
        assert!(
            auth.persist().claims.is_empty(),
            "no claims after failed admission"
        );
        assert!(
            auth.persist().claim_attempts.is_empty(),
            "no attempt map after failed admission"
        );
        assert!(
            auth.persist().verifier_refs.is_empty(),
            "no verifier refs after failed admission"
        );
        assert!(
            auth.persist().transitions.is_empty(),
            "no transitions after failed admission"
        );

        // Retry on the same backend: must produce Admitted (not Replay).
        auth.persist_mut().next_claim_error = None;
        let admission = auth.admit_claim(&req).expect("retry on same backend");
        assert_eq!(
            admission.outcome,
            ClaimOutcome::Admitted,
            "retry must admit, not replay"
        );
        let recorded_attempt = admission.attempt_id.clone();
        assert!(admission.attachment.is_some(), "must mint attachment");

        // Exact replay: same request, same backend — must return Replay.
        let replay = auth.admit_claim(&req).expect("exact replay");
        assert_eq!(
            replay.outcome,
            ClaimOutcome::Replay,
            "exact replay must return Replay"
        );
        assert_eq!(
            replay.attempt_id, recorded_attempt,
            "replay must return recorded attempt id"
        );
        assert!(
            replay.attachment.is_none(),
            "replay must not mint a fresh attachment"
        );

        // Prove exactly one ClaimRecorded transition was recorded.
        let transitions = auth.persist().get_transitions("sig-1", &recorded_attempt);
        assert_eq!(
            transitions.len(),
            1,
            "exactly one ClaimRecorded expected, got {transitions:?}"
        );
        assert_eq!(transitions[0], Transition::ClaimRecorded);
    }

    #[test]
    fn prepare_dispatch_validates_attachment() {
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        assert_eq!(prepared.attempt_id, admission.attempt_id);
        let forged = MintedAttachment {
            generation: 99,
            arm_id: att.arm_id.clone(),
            attempt_id: att.attempt_id.clone(),
            seat_id: att.seat_id.clone(),
            route: att.route.clone(),
            lease_until: att.lease_until,
            verifier_ref: att.verifier_ref.clone(),
            revoked: false,
        };
        let err = auth
            .prepare_dispatch(&admission.claim, &forged)
            .expect_err("forged");
        assert!(matches!(err, DispatchError::PreSend(_)));
    }

    #[test]
    fn attachment_not_minted_by_authority_fails() {
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let mut auth2 = sample_authority();
        let err = auth2
            .prepare_dispatch(&admission.claim, &att)
            .expect_err("foreign authority");
        assert!(matches!(err, DispatchError::PreSend(_)));
    }

    #[test]
    fn revoked_attachment_fails_prepare() {
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        auth.revoke_attachment(&att.attempt_id);
        let err = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect_err("revoked");
        assert!(matches!(err, DispatchError::PreSend(_)));
    }

    #[test]
    fn expired_lease_fails_prepare() {
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let mut att = admission.attachment.expect("attachment");
        att.lease_until = time::macros::datetime!(2020-01-01 00:00:00 UTC);
        let err = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect_err("expired");
        assert!(matches!(err, DispatchError::PreSend(_)));
    }

    #[test]
    fn lease_extension_mutation_fails_prepare() {
        // Extending the lease beyond the stored record must be rejected.
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let mut att = admission.attachment.expect("attachment");
        // Extend lease by one hour — mismatches stored record.
        att.lease_until =
            time::macros::datetime!(2026-01-15 12:00:00 UTC) + time::Duration::hours(10);
        let err = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect_err("lease extension");
        assert!(
            matches!(&err, DispatchError::PreSend(msg) if msg.contains("lease_until")),
            "expected lease_until mismatch, got {err:?}"
        );
    }

    #[test]
    fn attempt_id_substitution_fails_prepare() {
        // Mutating the attempt_id in the attachment must be rejected.
        // This causes the authority lookup to fail because no attachment
        // is stored under the substituted id.
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let mut att = admission.attachment.expect("attachment");
        att.attempt_id = "attempt-999".to_owned();
        let err = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect_err("attempt_id substitution");
        assert!(
            matches!(&err, DispatchError::PreSend(msg) if msg.contains("not minted")),
            "expected 'not minted by this authority', got {err:?}"
        );
    }

    #[test]
    fn arm_id_substitution_fails_prepare() {
        // Mutating the arm_id in the attachment must be rejected.
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let mut att = admission.attachment.expect("attachment");
        att.arm_id = "arm-02".to_owned();
        let err = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect_err("arm_id substitution");
        assert!(
            matches!(&err, DispatchError::PreSend(_)),
            "expected PreSend error for arm_id mismatch, got {err:?}"
        );
    }

    #[test]
    fn verifier_ref_forgery_fails_prepare() {
        // Changing the verifier_ref must be rejected — attachment is forged.
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let mut att = admission.attachment.expect("attachment");
        att.verifier_ref = "vrf:forged".to_owned();
        let err = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect_err("verifier ref forgery");
        assert!(
            matches!(&err, DispatchError::PreSend(msg) if msg.contains("forged")),
            "expected forgery rejection, got {err:?}"
        );
    }

    #[test]
    fn conclude_accepted_with_observations() {
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let attempt_id = prepared.attempt_id.clone();
        let conclusion = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "turn-X".to_owned(),
                },
                vec![
                    LifecycleObservation::TurnStarted("T1".to_owned()),
                    LifecycleObservation::TurnTerminal("T1".to_owned(), true),
                ],
            )
            .expect("conclude");
        assert!(!conclusion.reconciliation_required());
        assert!(!conclusion.controller_lost());
        assert_eq!(conclusion.observations.len(), 2);
        assert_eq!(conclusion.durable_outcome(), DurableOutcome::Terminal);
        let ts = auth.persist().get_transitions("sig-1", &attempt_id);
        assert!(ts.contains(&Transition::DispatchPrepared));
        assert!(ts.contains(&Transition::NativeAccepted));
        assert!(ts.contains(&Transition::ExactTurnStart));
        assert!(ts.contains(&Transition::ExactTurnTerminal));
    }

    #[test]
    fn conclude_ambiguous_records_reconciliation_required() {
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let attempt_id = prepared.attempt_id.clone();
        let conclusion = auth
            .conclude_dispatch(prepared, DispatchDisposition::Ambiguous, vec![])
            .expect("conclude");
        assert!(conclusion.reconciliation_required());
        assert_eq!(conclusion.durable_outcome(), DurableOutcome::Ambiguous);
        let ts = auth.persist().get_transitions("sig-1", &attempt_id);
        assert!(ts.contains(&Transition::ReconciliationRequired));
    }

    #[test]
    fn conclude_controller_lost_persists_transition() {
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let attempt_id = prepared.attempt_id.clone();
        let conclusion = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "turn-X".to_owned(),
                },
                vec![LifecycleObservation::ControllerLost],
            )
            .expect("conclude");
        assert!(conclusion.controller_lost());
        assert_eq!(conclusion.durable_outcome(), DurableOutcome::ControllerLost);
        let ts = auth.persist().get_transitions("sig-1", &attempt_id);
        assert!(ts.contains(&Transition::ControllerLost));
    }

    #[test]
    fn conclude_rejected_no_observations() {
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let conclusion = auth
            .conclude_dispatch(prepared, DispatchDisposition::Rejected, vec![])
            .expect("conclude");
        assert!(!conclusion.reconciliation_required());
        assert!(conclusion.observations.is_empty());
        assert_eq!(conclusion.durable_outcome(), DurableOutcome::Rejected);
    }

    #[test]
    fn conclude_accepted_with_started_returns_started_outcome() {
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let conclusion = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "turn-X".to_owned(),
                },
                vec![LifecycleObservation::TurnStarted("T1".to_owned())],
            )
            .expect("conclude");
        assert!(!conclusion.reconciliation_required());
        assert!(!conclusion.controller_lost());
        assert_eq!(conclusion.durable_outcome(), DurableOutcome::Started);
    }

    #[test]
    fn durable_outcome_exhaustivity_covers_all_six_variants() {
        // Rejected
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let dc = auth
            .conclude_dispatch(prepared, DispatchDisposition::Rejected, vec![])
            .expect("conclude");
        assert_eq!(dc.durable_outcome(), DurableOutcome::Rejected);

        // Accepted (no observations)
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let dc = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "turn-X".to_owned(),
                },
                vec![],
            )
            .expect("conclude");
        assert_eq!(dc.durable_outcome(), DurableOutcome::Accepted);

        // Started (TurnStarted only)
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let dc = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "turn-X".to_owned(),
                },
                vec![LifecycleObservation::TurnStarted("T1".to_owned())],
            )
            .expect("conclude");
        assert_eq!(dc.durable_outcome(), DurableOutcome::Started);

        // Terminal (TurnStarted + TurnTerminal)
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let dc = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "turn-X".to_owned(),
                },
                vec![
                    LifecycleObservation::TurnStarted("T1".to_owned()),
                    LifecycleObservation::TurnTerminal("T1".to_owned(), true),
                ],
            )
            .expect("conclude");
        assert_eq!(dc.durable_outcome(), DurableOutcome::Terminal);

        // ControllerLost (has ControllerLost observation)
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let dc = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "turn-X".to_owned(),
                },
                vec![LifecycleObservation::ControllerLost],
            )
            .expect("conclude");
        assert!(dc.controller_lost());
        assert_eq!(dc.durable_outcome(), DurableOutcome::ControllerLost);

        // Ambiguous
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let dc = auth
            .conclude_dispatch(prepared, DispatchDisposition::Ambiguous, vec![])
            .expect("conclude");
        assert!(dc.reconciliation_required());
        assert_eq!(dc.durable_outcome(), DurableOutcome::Ambiguous);
    }

    #[test]
    fn recovery_derives_ambiguous_from_dispatch_prepared_without_conclusion() {
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let _prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let recovery = auth.recover().expect("recover");
        let ambiguous = recovery.derivable_ambiguous_attempts();
        assert!(
            ambiguous.contains(&admission.attempt_id),
            "DispatchPrepared without conclusion must be derivable as ambiguous"
        );
    }

    #[test]
    fn post_send_disposition_failure_returns_post_send_error() {
        let mut auth = sample_authority_with_persist(FakePersist {
            next_disposition_error: Some("disk full".to_owned()),
            ..Default::default()
        });
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let err = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "corr-1".to_owned(),
                },
                vec![],
            )
            .expect_err("disposition write failure");
        assert!(
            matches!(err, DispatchError::PostSend(_)),
            "expected PostSend error, got {err:?}"
        );
    }

    #[test]
    fn partial_post_send_write_is_derivable_as_ambiguous() {
        // Disposition succeeds but NativeAccepted transition fails:
        // a partial post-send write that must surface as ambiguous.
        // transition_allow_count=1 lets DispatchPrepared through;
        // NativeAccepted (call 2) triggers next_transition_error.
        let mut auth = sample_authority_with_persist(FakePersist {
            next_transition_error: Some("transition write failed".to_owned()),
            transition_allow_count: 1,
            ..Default::default()
        });
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let err = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "corr-1".to_owned(),
                },
                vec![],
            )
            .expect_err("NativeAccepted transition failure");
        assert!(
            matches!(err, DispatchError::PostSend(_)),
            "expected PostSend error, got {err:?}"
        );

        // Propagate live arm state then recover
        let arm_id = auth.arms.keys().next().unwrap().clone();
        let arm_gen = auth.arms.get(&arm_id).unwrap().generation;
        auth.persist_mut().arm_states.push((arm_id, arm_gen));
        let recovery = auth.recover().expect("recover");
        let ambiguous = recovery.derivable_ambiguous_attempts();
        assert!(
            ambiguous.contains(&admission.attempt_id),
            "partial post-send write (disposition ok, NativeAccepted failed) must be derivable as ambiguous"
        );
    }

    #[test]
    fn rejected_disposition_is_not_ambiguous() {
        let mut auth = sample_authority();
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let conclusion = auth
            .conclude_dispatch(prepared, DispatchDisposition::Rejected, vec![])
            .expect("conclude");
        assert_eq!(conclusion.durable_outcome(), DurableOutcome::Rejected);

        let arm_id = auth.arms.keys().next().unwrap().clone();
        let arm_gen = auth.arms.get(&arm_id).unwrap().generation;
        auth.persist_mut().arm_states.push((arm_id, arm_gen));
        let recovery = auth.recover().expect("recover");
        assert!(
            recovery.derivable_ambiguous_attempts().is_empty(),
            "Rejected disposition must not be derivable as ambiguous"
        );
    }

    #[test]
    fn reconcile_delegates_to_controller() {
        let controller =
            FakeController::new(vec![]).with_reconciliation(ReconciliationDisposition::Accepted);
        assert_eq!(
            controller.reconcile("attempt-1"),
            ReconciliationDisposition::Accepted
        );
    }

    // -- c5: post-send boundary failure coverage -------------------------

    #[test]
    fn ambiguous_conclusion_partial_write_is_derivable_as_ambiguous() {
        // Disposition writes but ReconciliationRequired transition fails
        // (partial record_conclusion for Ambiguous disposition).
        let mut auth = sample_authority_with_persist(FakePersist {
            next_transition_error: Some("transition write failed".to_owned()),
            transition_allow_count: 1, // DispatchPrepared passes; ReconciliationRequired fails
            ..Default::default()
        });
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let err = auth
            .conclude_dispatch(prepared, DispatchDisposition::Ambiguous, vec![])
            .expect_err("ReconciliationRequired failure");
        assert!(
            matches!(err, DispatchError::PostSend(_)),
            "expected PostSend, got {err:?}"
        );

        // Disposition recorded, ReconciliationRequired missing → derivable ambiguous
        let arm_id = auth.arms.keys().next().unwrap().clone();
        let arm_gen = auth.arms.get(&arm_id).unwrap().generation;
        auth.persist_mut().arm_states.push((arm_id, arm_gen));
        let recovery = auth.recover().expect("recover");
        let ambiguous = recovery.derivable_ambiguous_attempts();
        assert!(
            ambiguous.contains(&admission.attempt_id),
            "Ambiguous partial write (disposition ok, ReconciliationRequired failed) must be derivable"
        );
    }

    #[test]
    fn observation_exact_turn_start_failure_after_conclusion_is_post_send() {
        // record_conclusion succeeds (disposition + NativeAccepted)
        // but ExactTurnStart observation write fails.
        let mut auth = sample_authority_with_persist(FakePersist {
            next_transition_error: Some("ExactTurnStart failed".to_owned()),
            transition_allow_count: 2, // DispatchPrepared + NativeAccepted pass
            ..Default::default()
        });
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let err = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "corr-1".to_owned(),
                },
                vec![LifecycleObservation::TurnStarted("T1".to_owned())],
            )
            .expect_err("ExactTurnStart failure");
        assert!(
            matches!(err, DispatchError::PostSend(_)),
            "expected PostSend for observation failure, got {err:?}"
        );

        // Recover: NativeAccepted present, ExactTurnStart missing
        let arm_id = auth.arms.keys().next().unwrap().clone();
        let arm_gen = auth.arms.get(&arm_id).unwrap().generation;
        auth.persist_mut().arm_states.push((arm_id, arm_gen));
        let _recovery = auth.recover().expect("recover");
        let ts = auth
            .persist()
            .get_transitions("sig-1", &admission.attempt_id);
        assert!(
            ts.contains(&Transition::NativeAccepted),
            "NativeAccepted must be durable after record_conclusion"
        );
        assert!(
            !ts.contains(&Transition::ExactTurnStart),
            "ExactTurnStart must not be present after failed observation write"
        );
    }

    #[test]
    fn observation_exact_turn_terminal_failure_after_conclusion_is_post_send() {
        // record_conclusion + ExactTurnStart succeed, ExactTurnTerminal fails.
        let mut auth = sample_authority_with_persist(FakePersist {
            next_transition_error: Some("ExactTurnTerminal failed".to_owned()),
            transition_allow_count: 3, // DispatchPrepared + NativeAccepted + ExactTurnStart pass
            ..Default::default()
        });
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let err = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "corr-1".to_owned(),
                },
                vec![
                    LifecycleObservation::TurnStarted("T1".to_owned()),
                    LifecycleObservation::TurnTerminal("T1".to_owned(), true),
                ],
            )
            .expect_err("ExactTurnTerminal failure");
        assert!(
            matches!(err, DispatchError::PostSend(_)),
            "expected PostSend for ExactTurnTerminal failure, got {err:?}"
        );

        // ExactTurnStart durable, ExactTurnTerminal missing
        let ts = auth
            .persist()
            .get_transitions("sig-1", &admission.attempt_id);
        assert!(ts.contains(&Transition::NativeAccepted));
        assert!(ts.contains(&Transition::ExactTurnStart));
        assert!(!ts.contains(&Transition::ExactTurnTerminal));
    }

    #[test]
    fn observation_controller_lost_failure_after_conclusion_is_post_send() {
        // record_conclusion succeeds, ControllerLost observation write fails.
        let mut auth = sample_authority_with_persist(FakePersist {
            next_transition_error: Some("ControllerLost failed".to_owned()),
            transition_allow_count: 2, // DispatchPrepared + NativeAccepted pass
            ..Default::default()
        });
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let err = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "corr-1".to_owned(),
                },
                vec![LifecycleObservation::ControllerLost],
            )
            .expect_err("ControllerLost failure");
        assert!(
            matches!(err, DispatchError::PostSend(_)),
            "expected PostSend for ControllerLost failure, got {err:?}"
        );

        // NativeAccepted durable, ControllerLost missing
        let ts = auth
            .persist()
            .get_transitions("sig-1", &admission.attempt_id);
        assert!(ts.contains(&Transition::NativeAccepted));
        assert!(!ts.contains(&Transition::ControllerLost));
    }

    #[test]
    fn restart_after_post_send_failure_no_replay_grant() {
        // After a post-send conclusion failure, a new claim admission
        // for the same arm at the same generation must return Occupied
        // (the arm is still occupied by the failed attempt).
        // Replay of the same request_id works normally.
        let now = time::macros::datetime!(2026-01-15 12:00:00 UTC);
        let mut auth = sample_authority_with_persist(FakePersist {
            next_disposition_error: Some("post-send write failed".to_owned()),
            ..Default::default()
        });
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let att = admission.attachment.expect("attachment");
        let prepared = auth
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        let _err = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "corr-1".to_owned(),
                },
                vec![],
            )
            .expect_err("post-send failure");

        // Propagate arm state for recovery
        let arm_id = auth.arms.keys().next().unwrap().clone();
        let arm_gen = auth.arms.get(&arm_id).unwrap().generation;
        auth.persist_mut().arm_states.push((arm_id, arm_gen));

        // Session 2: fresh authority from same persist backend
        let mut auth2 = DaemonAuthority::new(auth.persist().clone(), now);
        auth2.register_arm(sample_arm());
        let _recovery = auth2.recover().expect("recover");

        // Replay of the same request_id must still work
        let replay = auth2.admit_claim(&std_req()).expect("replay after failure");
        assert_eq!(
            replay.outcome,
            ClaimOutcome::Replay,
            "replay must work after post-send failure"
        );
        assert_eq!(replay.attempt_id, admission.attempt_id);

        // A new claim on the same arm at same generation must be Occupied
        let ev2 = vec![sample_event("new-claim")];
        let new_req = claim_req("arm-01", "req-2", "sig-2", ev2);
        let occupied = auth2.admit_claim(&new_req).expect_err("must be occupied");
        assert!(
            matches!(occupied, AdmissionError::Occupied),
            "new claim must be Occupied after post-send failure, got {occupied:?}"
        );

        // After re-arm, a new claim at the new generation must succeed
        auth2.advance_generation("arm-01").expect("re-arm");
        let ev3 = vec![sample_event("rearmed-claim")];
        let rearmed_req = claim_req("arm-01", "req-3", "sig-3", ev3);
        let fresh = auth2.admit_claim(&rearmed_req).expect("fresh after re-arm");
        assert_eq!(
            fresh.claim.generation, 2,
            "fresh claim must be at generation 2 after re-arm"
        );
        assert!(fresh.attachment.is_some(), "must mint attachment");
    }

    #[test]
    fn full_post_send_failure_boundary_matrix() {
        // Exercise every PostSend failure boundary and verify the
        // correct partial state is persisted for recovery.

        // -- Boundary 1: disposition write fails (entire conclusion lost) --
        {
            let mut auth = sample_authority_with_persist(FakePersist {
                next_disposition_error: Some("disk full".to_owned()),
                ..Default::default()
            });
            let admission = auth.admit_claim(&std_req()).expect("admit");
            let att = admission.attachment.expect("attachment");
            let prepared = auth
                .prepare_dispatch(&admission.claim, &att)
                .expect("prepare");
            let _err = auth
                .conclude_dispatch(
                    prepared,
                    DispatchDisposition::Accepted {
                        correlation: "corr-1".to_owned(),
                    },
                    vec![],
                )
                .expect_err("disposition failure");

            let ts = auth
                .persist()
                .get_transitions("sig-1", &admission.attempt_id);
            assert!(ts.contains(&Transition::DispatchPrepared));
            assert!(
                !ts.contains(&Transition::NativeAccepted),
                "NativeAccepted must not exist when disposition write failed"
            );
            assert!(
                auth.persist()
                    .get_disposition(&admission.attempt_id)
                    .is_none(),
                "no disposition stored"
            );
        }

        // -- Boundary 2: Ambiguous + ReconciliationRequired transition fails --
        {
            let mut auth = sample_authority_with_persist(FakePersist {
                next_transition_error: Some("ReconciliationRequired failed".to_owned()),
                transition_allow_count: 1,
                ..Default::default()
            });
            let admission = auth.admit_claim(&std_req()).expect("admit");
            let att = admission.attachment.expect("attachment");
            let prepared = auth
                .prepare_dispatch(&admission.claim, &att)
                .expect("prepare");
            let _err = auth
                .conclude_dispatch(prepared, DispatchDisposition::Ambiguous, vec![])
                .expect_err("ReconciliationRequired failure");

            // Disposition exists, ReconciliationRequired missing
            assert!(
                auth.persist()
                    .get_disposition(&admission.attempt_id)
                    .is_some(),
                "disposition must be recorded (partial write)"
            );
            let ts = auth
                .persist()
                .get_transitions("sig-1", &admission.attempt_id);
            assert!(!ts.contains(&Transition::ReconciliationRequired));
        }

        // -- Boundary 3: NativeAccepted fails (Accepted partial write) --
        {
            let mut auth = sample_authority_with_persist(FakePersist {
                next_transition_error: Some("NativeAccepted failed".to_owned()),
                transition_allow_count: 1,
                ..Default::default()
            });
            let admission = auth.admit_claim(&std_req()).expect("admit");
            let att = admission.attachment.expect("attachment");
            let prepared = auth
                .prepare_dispatch(&admission.claim, &att)
                .expect("prepare");
            let _err = auth
                .conclude_dispatch(
                    prepared,
                    DispatchDisposition::Accepted {
                        correlation: "corr-1".to_owned(),
                    },
                    vec![],
                )
                .expect_err("NativeAccepted failure");

            assert!(
                auth.persist()
                    .get_disposition(&admission.attempt_id)
                    .is_some(),
                "disposition must be recorded (partial write)"
            );
            let ts = auth
                .persist()
                .get_transitions("sig-1", &admission.attempt_id);
            assert!(!ts.contains(&Transition::NativeAccepted));
        }
    }

    #[test]
    fn fresh_authority_restart_reconstructs_full_semantic_packet() {
        let now = time::macros::datetime!(2026-01-15 12:00:00 UTC);

        // Session 1: admit claims, record handled cursors, set re-arm positions.
        let mut auth1 = DaemonAuthority::new(FakePersist::default(), now);
        auth1.register_arm(sample_arm());
        auth1.register_arm(KnownArm {
            arm_id: "arm-02".to_owned(),
            generation: 1,
            seat_id: "dev".to_owned(),
            route: "test".to_owned(),
            coverage_until: now + time::Duration::hours(24),
        });

        let admission = auth1.admit_claim(&std_req()).expect("admit claim");
        let att = admission.attachment.expect("attachment");
        let prepared = auth1
            .prepare_dispatch(&admission.claim, &att)
            .expect("prepare");
        auth1
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "corr-1".to_owned(),
                },
                vec![],
            )
            .expect("conclude");

        auth1.record_handled_cursor("arm-01", "cursor-42");
        auth1.set_rearmed("arm-01");

        // Propagate live authority metadata to the fake persist backend for recovery.
        let arm_states: Vec<(String, u64)> = auth1
            .arms
            .iter()
            .map(|(id, arm)| (id.clone(), arm.generation))
            .collect();
        let cursors = auth1.handled_cursors.clone();
        let rearmed = auth1.rearm_positions.clone();
        {
            let p = auth1.persist_mut();
            for (arm_id, generation) in arm_states {
                p.arm_states.push((arm_id, generation));
            }
            p.handled_cursors = cursors;
            p.rearm_positions = rearmed;
        }

        // Session 2: fresh authority (different instance) recovers from persist.
        let mut auth2 = DaemonAuthority::new(auth1.persist().clone(), now);
        auth2.register_arm(sample_arm());
        let recovery = auth2.recover().expect("recover after restart");

        // Verify full semantic packet reconstructed from persisted data.
        assert_eq!(recovery.arms.len(), 1); // arm-02 not in persisted arm_states
        assert!(
            recovery.arms.contains_key("arm-01"),
            "persisted arm must be reconstructed"
        );
        assert!(
            !recovery.arms.contains_key("arm-02"),
            "arm-02 was not persisted and should not appear"
        );
        assert!(
            !recovery.attachments.is_empty(),
            "attachments must be present"
        );
        assert_eq!(
            recovery.handled_cursors.get("arm-01").map(String::as_str),
            Some("cursor-42"),
            "handled cursor must survive restart"
        );
        assert_eq!(
            recovery.rearm_positions.get("arm-01"),
            Some(&true),
            "re-arm position must survive restart"
        );

        // Verify derivable ambiguous: none, since our only attempt was cleanly concluded.
        let ambiguous = recovery.derivable_ambiguous_attempts();
        assert!(
            ambiguous.is_empty(),
            "no ambiguous work expected for cleanly concluded attempt"
        );

        // Verify claim replay returns recorded attempt_id, not a fresh one.
        let replay = auth2.admit_claim(&std_req()).expect("replay after restart");
        assert_eq!(
            replay.outcome,
            ClaimOutcome::Replay,
            "recovery must replay, not re-admit"
        );
        assert_eq!(
            replay.attempt_id, admission.attempt_id,
            "replay must return recorded attempt_id"
        );
        assert!(
            replay.attachment.is_none(),
            "replay must not mint a new dispatch-capable attachment"
        );
    }
}
