//! Daemon authority: single-writer exclusive &mut self boundary for
//! claim admission, dispatch orchestration, split-phase reconciliation,
//! and recovery.
//!
//! `DaemonAuthority<P>` owns the live arm/generation registry, the
//! long-lived `Persist` store, claim/attempt state, and attachment
//! verifier/lease/revocation state. Callers supply only claim requests
//! and events; they never supply arm, generation, attempt id, store,
//! or attachment. Every authority-bearing mutation is durable: state in
//! RAM changes only after the persistence port confirms the write.
//!
//! Crucible v0 contracts are preserved; this module does not alter
//! merged schemas.

use crate::admit::KnownArm;
use crate::controller::{
    ControllerAttachment, ControllerCommand, DispatchDisposition, LifecycleObservation,
    ManagedCapability, ReconciliationDisposition, SignalAction,
};
use crate::persist::{
    ClaimError, ClaimOutcome, DurableClaim, Persist, PersistedArm, PersistedAttachment,
    ReconciliationState, RecoverySnapshot, Transition,
};
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;

// -- Minted attachment --------------------------------------------------

/// Host-minted controller attachment bound to exact seat, arm,
/// generation, capability, route, attempt, controller/verifier
/// reference, revocation state, and unexpired lease.
///
/// Fields are private — callers cannot mutate dimensions
/// independently and cannot construct attachments. Lease, seat, route,
/// and capability are derived from authority policy at mint time via
/// `ClaimRequest` + registered `KnownArm`. The attachment is validated
/// by dispatch preparation against the complete stored authority
/// record, not only the verifier ref.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintedAttachment {
    attempt_id: String,
    arm_id: String,
    generation: u64,
    seat_id: String,
    route: String,
    capability: ManagedCapability,
    lease_until: OffsetDateTime,
    verifier_ref: String,
    revoked: bool,
}

impl From<&PersistedAttachment> for MintedAttachment {
    fn from(a: &PersistedAttachment) -> Self {
        Self {
            attempt_id: a.attempt_id.clone(),
            arm_id: a.arm_id.clone(),
            generation: a.generation,
            seat_id: a.seat_id.clone(),
            route: a.route.clone(),
            capability: a.capability,
            lease_until: a.lease_until,
            verifier_ref: a.verifier_ref.clone(),
            revoked: a.revoked,
        }
    }
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

    /// The seat token.
    #[must_use]
    pub fn seat_id(&self) -> &str {
        &self.seat_id
    }

    /// The capability route.
    #[must_use]
    pub fn route(&self) -> &str {
        &self.route
    }

    /// The closed capability granted.
    #[must_use]
    pub fn capability(&self) -> ManagedCapability {
        self.capability
    }

    /// The lease end.
    #[must_use]
    pub fn lease_until(&self) -> OffsetDateTime {
        self.lease_until
    }

    /// The opaque verifier reference for recovery.
    #[must_use]
    pub fn verifier_ref(&self) -> &str {
        &self.verifier_ref
    }

    /// Whether this attachment is revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Whether this attachment is still valid (not revoked, not expired).
    #[must_use]
    pub fn is_valid(&self, now: OffsetDateTime) -> bool {
        !self.revoked && self.lease_until > now
    }
}

// -- Dispatch state machine layers --------------------------------------

/// Result of preparing a dispatch under authority.
///
/// Opaque, non-Clone, single-use token consumed by value in phase 4 by
/// `conclude_dispatch`. The authority emits a separate sealed
/// `ControllerCommand` for phase 2; this token cannot be inspected or
/// replayed.
#[derive(Debug)]
pub struct PreparedDispatch {
    attempt_id: String,
    signal_id: String,
}

/// Opaque, non-Clone handle to an admitted claim.
///
/// Minted at admission under authority; consumed by value at
/// `prepare_dispatch`. Fields are private — the authority rehydrates
/// and verifies the full claim identity (signal, request, body batch)
/// from its own stored state at prepare time, never from
/// caller-carried data.
#[derive(Debug)]
pub struct AdmissionReceipt {
    attempt_id: String,
    claim: DurableClaim,
}

impl AdmissionReceipt {
    /// The opaque attempt id.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }
}

/// Pre-send preparation failure with the receipt retained for retry.
#[derive(Debug)]
pub struct PrepareDispatchError {
    /// The exact admission receipt supplied to the failed preparation.
    pub receipt: Box<AdmissionReceipt>,
    /// Why preparation failed before any native controller I/O.
    pub error: DispatchError,
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

/// Opaque reconciliation work produced by the authority before the
/// provider probe. Fields are private; `commit_reconciliation`
/// consumes it by value after the provider probe completes outside
/// the authority.
#[derive(Debug)]
pub struct ReconciliationWork {
    attempt_id: String,
    signal_id: String,
}

impl ReconciliationWork {
    /// The attempt id, for the provider probe.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }
}

// -- DaemonAuthority ----------------------------------------------------

/// Single-writer daemon authority for claim admission, dispatch
/// orchestration, split-phase reconciliation, and recovery.
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
    /// Admitted durable claims keyed by `attempt_id` (rehydration source).
    admitted_claims: BTreeMap<String, DurableClaim>,
    /// Current time source (injectable for tests).
    now: OffsetDateTime,
    /// Monotonic attempt counter — the authority mints attempt ids.
    attempt_seq: u64,
    /// Handled cursor position per `arm_id`.
    handled_cursors: BTreeMap<String, String>,
    /// Whether each arm is re-arming.
    rearm_positions: BTreeMap<String, bool>,
    /// Admitted attempts recovered before any durable prepare marker.
    recoverable_attempts: BTreeSet<String>,
}

impl<P: Persist + Default> Default for DaemonAuthority<P> {
    fn default() -> Self {
        Self {
            persist: P::default(),
            arms: BTreeMap::new(),
            attachments: BTreeMap::new(),
            admitted_claims: BTreeMap::new(),
            now: OffsetDateTime::now_utc(),
            attempt_seq: 0,
            handled_cursors: BTreeMap::new(),
            rearm_positions: BTreeMap::new(),
            recoverable_attempts: BTreeSet::new(),
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
    pub events: Vec<gearwit_protocol::ProviderEvent>,
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
            admitted_claims: BTreeMap::new(),
            now,
            attempt_seq: 0,
            handled_cursors: BTreeMap::new(),
            rearm_positions: BTreeMap::new(),
            recoverable_attempts: BTreeSet::new(),
        }
    }

    /// Register a known arm. Full arm policy is durably persisted before
    /// the live registry is updated; on storage failure the live state is
    /// unchanged (fail closed).
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError::Storage` when the arm policy cannot be
    /// persisted.
    pub fn register_arm(&mut self, arm: KnownArm) -> Result<(), AdmissionError> {
        self.persist
            .persist_arm_state(&PersistedArm {
                arm_id: arm.arm_id.clone(),
                generation: arm.generation,
                seat_id: arm.seat_id.clone(),
                route: arm.route.clone(),
                capability: arm.capability,
                coverage_until: arm.coverage_until,
            })
            .map_err(|e| AdmissionError::Storage(format!("persist_arm_state failed: {e:?}")))?;
        self.arms.insert(arm.arm_id.clone(), arm);
        Ok(())
    }

    /// Advance generation for an arm — the production re-arm path.
    ///
    /// Persists the full arm policy at the new generation before the
    /// live generation changes; on storage failure or overflow the live
    /// generation is unchanged (fail closed). Returns the new generation.
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError::UnknownArm` when the arm is not
    /// registered, `AdmissionError::GenerationOverflow` on checked
    /// increment overflow, and `AdmissionError::Storage` when the new
    /// policy cannot be persisted.
    pub fn advance_generation(&mut self, arm_id: &str) -> Result<u64, AdmissionError> {
        let arm = self
            .arms
            .get(arm_id)
            .cloned()
            .ok_or(AdmissionError::UnknownArm)?;
        let new_generation = arm
            .generation
            .checked_add(1)
            .ok_or(AdmissionError::GenerationOverflow)?;
        self.persist
            .persist_arm_state(&PersistedArm {
                arm_id: arm.arm_id.clone(),
                generation: new_generation,
                seat_id: arm.seat_id.clone(),
                route: arm.route.clone(),
                capability: arm.capability,
                coverage_until: arm.coverage_until,
            })
            .map_err(|e| AdmissionError::Storage(format!("persist_arm_state failed: {e:?}")))?;
        // RAM mutation only after the durable write succeeded.
        let live = self
            .arms
            .get_mut(arm_id)
            .ok_or(AdmissionError::UnknownArm)?;
        live.generation = new_generation;
        Ok(new_generation)
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

    /// Record a handled cursor for an arm. Persisted before the live
    /// cursor changes; fail closed on storage failure.
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError::Storage` when persistence fails.
    pub fn record_handled_cursor(
        &mut self,
        arm_id: &str,
        cursor: &str,
    ) -> Result<(), AdmissionError> {
        self.persist
            .persist_handled_cursor(arm_id, cursor)
            .map_err(|e| {
                AdmissionError::Storage(format!("persist_handled_cursor failed: {e:?}"))
            })?;
        self.handled_cursors
            .insert(arm_id.to_owned(), cursor.to_owned());
        Ok(())
    }

    /// Mark an arm as re-armed. Persisted before the live flag changes;
    /// fail closed on storage failure.
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError::Storage` when persistence fails.
    pub fn set_rearmed(&mut self, arm_id: &str) -> Result<(), AdmissionError> {
        self.persist
            .persist_rearmed(arm_id)
            .map_err(|e| AdmissionError::Storage(format!("persist_rearmed failed: {e:?}")))?;
        self.rearm_positions.insert(arm_id.to_owned(), true);
        Ok(())
    }

    /// Revoke an attachment by `attempt_id`. Persisted before the live
    /// flag changes; fail closed on storage failure.
    ///
    /// # Errors
    ///
    /// Returns `DispatchError::PreSend` when persistence fails.
    /// Returns `Ok(false)` when no attachment is found for the attempt.
    pub fn revoke_attachment(&mut self, attempt_id: &str) -> Result<bool, DispatchError> {
        if !self.attachments.contains_key(attempt_id) {
            return Ok(false);
        }
        self.persist
            .persist_attachment_revoked(attempt_id)
            .map_err(|e| {
                DispatchError::PreSend(format!("persist_attachment_revoked failed: {e:?}"))
            })?;
        let att = self
            .attachments
            .get_mut(attempt_id)
            .ok_or_else(|| DispatchError::PreSend("attachment vanished mid-revoke".to_owned()))?;
        att.revoked = true;
        Ok(true)
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

    // -- Claim admission --------------------------------------------------

    /// Atomically resolve arm generation, durably admit the claim
    /// (including the authority-minted attempt id, attachment, exact
    /// attempt→signal binding, verifier ref, and `ClaimRecorded`
    /// transition as one atomic operation), and return an opaque
    /// admission receipt — all under the exclusive `&mut self`
    /// authority boundary.
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError` when the arm is unknown, the claim is
    /// occupied, storage fails, or the attempt counter overflows.
    pub fn admit_claim(&mut self, req: &ClaimRequest) -> Result<AdmissionResult, AdmissionError> {
        // 1. Resolve arm under authority
        let arm = self
            .arms
            .get(&req.arm_id)
            .cloned()
            .ok_or(AdmissionError::UnknownArm)?;

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

        // 3. Authority mints attempt identity and attachment; the backend
        //    records everything atomically (or replays).
        let seq = self
            .attempt_seq
            .checked_add(1)
            .ok_or(AdmissionError::GenerationOverflow)?;
        let attempt_id = format!("attempt-{seq}");
        let verifier_ref = format!("vrf:{attempt_id}:{}", ulid::Ulid::new());
        let pending_attachment = PersistedAttachment {
            attempt_id: attempt_id.clone(),
            arm_id: arm.arm_id.clone(),
            generation: arm.generation,
            seat_id: arm.seat_id.clone(),
            route: arm.route.clone(),
            capability: arm.capability,
            lease_until: arm.coverage_until,
            verifier_ref: verifier_ref.clone(),
            revoked: false,
        };

        let record = self
            .persist
            .admit_claim(&claim, Some(&pending_attachment))
            .map_err(|e| match e {
                ClaimError::OccupiedDifferent | ClaimError::StaleGeneration => {
                    AdmissionError::Occupied
                }
                ClaimError::Conflict => AdmissionError::Conflict,
                ClaimError::StorageFailure(msg) => AdmissionError::Storage(msg),
            })?;

        // 4. Replay: no dispatch state and no receipt. A replayed older
        //    record must never lower the live counter or make an attempt id
        //    reusable.
        if matches!(record.outcome, ClaimOutcome::Replay) {
            if let Some(seq) = record
                .attempt_id
                .strip_prefix("attempt-")
                .and_then(|s| s.parse::<u64>().ok())
            {
                self.attempt_seq = self.attempt_seq.max(seq);
            }
            return Ok(AdmissionResult {
                outcome: record.outcome,
                attempt_id: record.attempt_id,
                receipt: None,
            });
        }

        // 5. Authoritative admission: commit the minted counter slot and
        //    install live state only after the durable admission succeeded.
        self.attempt_seq = seq;
        self.attachments.insert(
            pending_attachment.attempt_id.clone(),
            MintedAttachment::from(&pending_attachment),
        );
        self.admitted_claims
            .insert(pending_attachment.attempt_id.clone(), claim.clone());

        let receipt = AdmissionReceipt {
            attempt_id: pending_attachment.attempt_id.clone(),
            claim: claim.clone(),
        };
        Ok(AdmissionResult {
            outcome: record.outcome,
            attempt_id: record.attempt_id,
            receipt: Some(receipt),
        })
    }

    // -- Dispatch preparation --------------------------------------------

    /// Prepare a dispatch: rehydrate the admitted claim and minted
    /// attachment from stored authority state, validate every
    /// dimension against the live arm policy, durably record
    /// `DispatchPrepared` + the prepared marker atomically, and return
    /// a sealed `ControllerCommand` (authority-produced bounded work
    /// for phase 2 native I/O) plus the opaque `PreparedDispatch`
    /// token for phase 4. The authority lock is released after this
    /// call.
    ///
    /// # Errors
    ///
    /// Returns [`PrepareDispatchError`] when rehydration, validation, or
    /// persistence fails. The controller is never called and the caller
    /// retains the receipt for a safe retry.
    #[allow(clippy::needless_pass_by_value)]
    pub fn prepare_dispatch(
        &mut self,
        receipt: AdmissionReceipt,
    ) -> Result<(PreparedDispatch, ControllerCommand), PrepareDispatchError> {
        match self.prepare_dispatch_inner(&receipt) {
            Ok(prepared) => {
                self.recoverable_attempts.remove(receipt.attempt_id());
                Ok(prepared)
            }
            Err(error) => Err(PrepareDispatchError {
                receipt: Box::new(receipt),
                error,
            }),
        }
    }

    /// Prepare one attempt discovered during recovery before it was ever
    /// marked prepared. The authority reconstructs the receipt from its
    /// durable claim record, so no caller-held receipt is required after a
    /// daemon crash.
    ///
    /// # Errors
    ///
    /// Returns `DispatchError::PreSend` when the attempt was not recovered as
    /// admitted-but-unprepared or when atomic preparation fails. Failed
    /// preparation remains recoverable for a later retry.
    pub fn prepare_recovered(
        &mut self,
        attempt_id: &str,
    ) -> Result<(PreparedDispatch, ControllerCommand), DispatchError> {
        if !self.recoverable_attempts.contains(attempt_id) {
            return Err(DispatchError::PreSend(
                "attempt is not recoverable for preparation".to_owned(),
            ));
        }
        let claim = self
            .admitted_claims
            .get(attempt_id)
            .cloned()
            .ok_or_else(|| DispatchError::PreSend("no recovered claim for attempt".to_owned()))?;
        let prepared = self.prepare_dispatch_inner(&AdmissionReceipt {
            attempt_id: attempt_id.to_owned(),
            claim,
        })?;
        self.recoverable_attempts.remove(attempt_id);
        Ok(prepared)
    }

    fn prepare_dispatch_inner(
        &mut self,
        receipt: &AdmissionReceipt,
    ) -> Result<(PreparedDispatch, ControllerCommand), DispatchError> {
        // 1. Rehydrate stored claim and stored attachment under authority;
        //    never trust caller-carried dimensions.
        let stored_claim = self
            .admitted_claims
            .get(&receipt.attempt_id)
            .ok_or_else(|| {
                DispatchError::PreSend("no admitted claim for this attempt".to_owned())
            })?;
        let stored_attachment = self.attachments.get(&receipt.attempt_id).ok_or_else(|| {
            DispatchError::PreSend("attachment not minted by this authority".to_owned())
        })?;

        // 2. Verify receipt identity against the in-memory authority
        //    record — exact signal/request/body identity.
        if !receipt.claim.content_eq(stored_claim) {
            return Err(DispatchError::PreSend(
                "claim identity does not match stored claim".to_owned(),
            ));
        }

        // 2b. Verify against the durable backend record — the stored
        //     state of record for rehydration. A backend divergence
        //     fails closed.
        let durable = self
            .persist
            .claim_for_attempt(&receipt.attempt_id)
            .map_err(|e| DispatchError::PreSend(format!("durable claim lookup failed: {e:?}")))?
            .ok_or_else(|| {
                DispatchError::PreSend("no durable claim for this attempt".to_owned())
            })?;
        if !receipt.claim.content_eq(&durable) {
            return Err(DispatchError::PreSend(
                "claim identity does not match stored claim".to_owned(),
            ));
        }
        if durable.events.is_empty() {
            return Err(DispatchError::PreSend("empty event batch".to_owned()));
        }

        // 3. Validate the closed capability independently: the recorded
        //    route must parse back to the recorded capability.
        if ManagedCapability::parse(&stored_attachment.route) != Some(stored_attachment.capability)
        {
            return Err(DispatchError::PreSend(
                "route does not parse to the granted capability".to_owned(),
            ));
        }

        // 4. Validate against the registered arm policy.
        let arm = self.arms.get(&receipt.claim.arm_id).ok_or_else(|| {
            DispatchError::PreSend("arm not registered by this authority".to_owned())
        })?;
        if stored_attachment.generation != arm.generation {
            return Err(DispatchError::PreSend(
                "attachment generation is stale — arm has been re-armed".to_owned(),
            ));
        }
        if stored_attachment.seat_id != arm.seat_id {
            return Err(DispatchError::PreSend(
                "seat_id mismatch with arm".to_owned(),
            ));
        }
        if stored_attachment.route != arm.route {
            return Err(DispatchError::PreSend("route mismatch with arm".to_owned()));
        }
        if stored_attachment.capability != arm.capability {
            return Err(DispatchError::PreSend(
                "capability mismatch with arm".to_owned(),
            ));
        }

        // 5. Lease and revocation against authority state.
        if stored_attachment.revoked {
            return Err(DispatchError::PreSend("attachment is revoked".to_owned()));
        }
        if stored_attachment.lease_until <= self.now {
            return Err(DispatchError::PreSend(
                "attachment lease expired".to_owned(),
            ));
        }

        // 6. Atomic durable prepare: DispatchPrepared + prepared marker,
        //    bound-checked against the exact persisted attempt→signal
        //    binding.
        self.persist
            .record_prepared(&durable.signal_id, &stored_attachment.attempt_id)
            .map_err(|e| DispatchError::PreSend(format!("record_prepared failed: {e:?}")))?;

        // 7. Build the sealed authority-produced controller command,
        //    rehydrated from the durable stored claim.
        let cmd = ControllerCommand::new(
            ControllerAttachment::new(
                stored_attachment.attempt_id.clone(),
                stored_attachment.arm_id.clone(),
                stored_attachment.generation,
                stored_attachment.seat_id.clone(),
                stored_attachment.route.clone(),
                stored_attachment.capability,
                stored_attachment.lease_until,
            ),
            SignalAction::new(
                durable.signal_id.clone(),
                durable.events[0].provider.clone(),
                durable.events.len(),
            ),
            stored_attachment.attempt_id.clone(),
        );

        // 8. Return the opaque phase-4 token + sealed phase-2 command.
        Ok((
            PreparedDispatch {
                attempt_id: stored_attachment.attempt_id.clone(),
                signal_id: durable.signal_id.clone(),
            },
            cmd,
        ))
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

    /// Re-enter authority after native I/O: atomically record the
    /// dispatch disposition, its first required transition, and the
    /// durable consumption marker. The prepared token is consumed by
    /// value — a second conclusion with the same token is impossible.
    ///
    /// Post-send failures return `DispatchError::PostSend` — a typed
    /// result distinct from `PreSend`, indicating the dispatch may
    /// have been accepted. Recovery derives reconciliation-required
    /// survivors from `DispatchPrepared` without a durable conclusion.
    ///
    /// # Errors
    ///
    /// Returns `DispatchError::PostSend` when the atomic conclusion
    /// cannot be persisted. Returns `DispatchError::PreSend` when the
    /// attempt has already been consumed — duplicate conclusion is a
    /// durable authority invariant checked against persisted state.
    // By-value consumption is deliberate: the prepared token is
    // single-use and durably consumed by the atomic conclusion.
    #[allow(clippy::needless_pass_by_value)]
    pub fn conclude_dispatch(
        &mut self,
        prepared: PreparedDispatch,
        disposition: DispatchDisposition,
        observations: Vec<LifecycleObservation>,
    ) -> Result<DispatchConclusion, DispatchError> {
        // 0. Reject already-consumed attempts (durable invariant)
        if self
            .persist
            .has_concluded(&prepared.attempt_id)
            .map_err(|e| DispatchError::PostSend(format!("conclusion check failed: {e:?}")))?
        {
            return Err(DispatchError::PreSend(
                "attempt has already been concluded — duplicate conclusion is a durable authority invariant".to_owned(),
            ));
        }

        // 1. One atomic conclusion: disposition + first transition +
        //    durable consumption marker. Nothing is observable on failure.
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

        // 2. Record lifecycle evidence based on disposition. A failure
        //    here surfaces as missing evidence in recovery; the attempt
        //    is already durably consumed (single consumption).
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
                // Record observations via helper (PostSend on failure)
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

    // -- Split-phase reconciliation --------------------------------------

    /// Authority phase 1: produce reconciliation work after validating
    /// the attempt exists (exact persisted attempt→signal binding) and
    /// is not already resolved. No provider I/O happens while the
    /// authority is borrowed — the caller probes the controller between
    /// this call and `commit_reconciliation`.
    ///
    /// # Errors
    ///
    /// Returns `DispatchError::PostSend` when the attempt has no
    /// persisted binding or is already resolved. Fail closed: no
    /// fallback identity.
    pub fn prepare_reconciliation(
        &mut self,
        attempt_id: &str,
    ) -> Result<ReconciliationWork, DispatchError> {
        let signal_id = self
            .persist
            .attempt_signal(attempt_id)
            .map_err(|e| DispatchError::PostSend(format!("attempt→signal lookup failed: {e:?}")))?
            .ok_or_else(|| {
                DispatchError::PostSend(
                    "no persisted attempt→signal binding for this attempt".to_owned(),
                )
            })?;
        if self
            .persist
            .reconciliation_recorded(attempt_id)
            .map_err(|e| DispatchError::PostSend(format!("reconciliation lookup failed: {e:?}")))?
            .is_some_and(|state| !matches!(state, ReconciliationState::Unknown))
        {
            return Err(DispatchError::PostSend(
                "attempt already reconciled".to_owned(),
            ));
        }
        Ok(ReconciliationWork {
            attempt_id: attempt_id.to_owned(),
            signal_id,
        })
    }

    /// Authority phase 3: durably commit the provider probe's
    /// resolution. The resolution enum is persisted keyed to the
    /// attempt; the exact attempt→signal binding is verified against
    /// persisted state (fail closed, no fallback).
    ///
    /// # Errors
    ///
    /// Returns `DispatchError::PostSend` when the resolution cannot be
    /// persisted, conflicts with a prior resolution, or the attempt has
    /// no prior `ReconciliationRequired` transition.
    // By-value consumption is deliberate: the reconciliation work
    // handle is single-use between the two authority phases.
    #[allow(clippy::needless_pass_by_value)]
    pub fn commit_reconciliation(
        &mut self,
        work: ReconciliationWork,
        disposition: ReconciliationDisposition,
    ) -> Result<ReconciliationDisposition, DispatchError> {
        let state = match disposition {
            ReconciliationDisposition::Accepted => ReconciliationState::Accepted,
            ReconciliationDisposition::ProvenNotAccepted => ReconciliationState::ProvenNotAccepted,
            ReconciliationDisposition::Terminal => ReconciliationState::Terminal,
            ReconciliationDisposition::Unknown => ReconciliationState::Unknown,
        };
        self.persist
            .record_reconciliation(&work.attempt_id, &work.signal_id, state)
            .map_err(|e| {
                DispatchError::PostSend(format!("failed to record reconciliation: {e:?}"))
            })?;
        Ok(disposition)
    }

    // -- Recovery --------------------------------------------------------

    /// Recover authoritative state after daemon restart, from the
    /// backend alone.
    ///
    /// Reconstructs and installs the full semantic packet: arms
    /// (complete policy — seat, route, capability, coverage), minted
    /// attachments (seat, route, capability, exact persisted lease,
    /// verifier ref, revocation), admitted claims, handled cursors,
    /// re-arm positions, and the attempt counter. No caller
    /// pre-registration or skeleton state is required.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError`] when the backend is unavailable or
    /// corrupt.
    pub fn recover(&mut self) -> Result<AuthorityRecovery, ClaimError> {
        let snapshot = self.persist.recover()?;

        let arms: BTreeMap<String, KnownArm> = snapshot
            .arms
            .iter()
            .map(|a| {
                (
                    a.arm_id.clone(),
                    KnownArm {
                        arm_id: a.arm_id.clone(),
                        generation: a.generation,
                        seat_id: a.seat_id.clone(),
                        route: a.route.clone(),
                        capability: a.capability,
                        coverage_until: a.coverage_until,
                    },
                )
            })
            .collect();

        let attachments: BTreeMap<String, MintedAttachment> = snapshot
            .attachments
            .iter()
            .map(|a| (a.attempt_id.clone(), MintedAttachment::from(a)))
            .collect();

        let admitted_claims: BTreeMap<String, DurableClaim> = snapshot
            .claims
            .iter()
            .filter_map(|c| {
                snapshot
                    .attempt_map
                    .iter()
                    .find(|(rid, _)| *rid == &c.request_id)
                    .map(|(_, attempt_id)| (attempt_id.clone(), c.clone()))
            })
            .collect();
        let recoverable_attempts: BTreeSet<String> = snapshot
            .attempt_map
            .values()
            .filter(|attempt_id| {
                !snapshot.prepared_set.contains_key(*attempt_id)
                    && !snapshot.concluded_set.contains_key(*attempt_id)
                    && admitted_claims.contains_key(*attempt_id)
                    && attachments.contains_key(*attempt_id)
            })
            .cloned()
            .collect();

        self.arms = arms.clone();
        self.attachments = attachments.clone();
        self.admitted_claims = admitted_claims;
        self.handled_cursors = snapshot.handled_cursors.clone();
        self.rearm_positions = snapshot.rearm_positions.clone();
        self.attempt_seq = snapshot.attempt_seq;
        self.recoverable_attempts.clone_from(&recoverable_attempts);

        Ok(AuthorityRecovery {
            snapshot,
            arms,
            attachments,
            handled_cursors: self.handled_cursors.clone(),
            rearm_positions: self.rearm_positions.clone(),
            recoverable_prepare_attempts: recoverable_attempts.into_iter().collect(),
        })
    }
}

// -- Supporting types ---------------------------------------------------

/// Result of claim admission.
#[derive(Debug)]
pub struct AdmissionResult {
    /// Admission outcome.
    pub outcome: ClaimOutcome,
    /// Attempt id.
    pub attempt_id: String,
    /// Opaque admission receipt (None on exact replay).
    receipt: Option<AdmissionReceipt>,
}

impl AdmissionResult {
    /// Take the opaque admission receipt, if this admission minted one.
    #[must_use]
    pub fn into_receipt(self) -> Option<AdmissionReceipt> {
        self.receipt
    }
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
    /// The attempt counter or arm generation overflowed.
    GenerationOverflow,
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
    /// Live arms reconstructed from persisted policy.
    pub arms: BTreeMap<String, KnownArm>,
    /// Minted attachment state (verifier refs only — no bearer material).
    pub attachments: BTreeMap<String, MintedAttachment>,
    /// Handled cursors per arm.
    pub handled_cursors: BTreeMap<String, String>,
    /// Re-arm positions per arm.
    pub rearm_positions: BTreeMap<String, bool>,
    /// Admitted attempts recoverable for one authority-owned preparation.
    pub recoverable_prepare_attempts: Vec<String>,
}

impl AuthorityRecovery {
    /// Derive ambiguous dispatches that survived restart:
    ///
    /// 1. `ReconciliationRequired` without a final resolution
    ///    (`Accepted`, `ProvenNotAccepted`, `Terminal`) — a properly
    ///    recorded ambiguous conclusion stays derivable until resolved.
    /// 2. `DispatchPrepared` with no durable conclusion and no
    ///    `ControllerLost` — the dispatch may or may not have been
    ///    sent.
    #[must_use]
    pub fn derivable_ambiguous_attempts(&self) -> Vec<String> {
        let mut ambiguous = Vec::new();
        let mut seen = BTreeSet::new();
        for (key, transitions) in &self.snapshot.transitions {
            let Some(attempt_id) = key.split(':').nth(1) else {
                continue;
            };
            if !seen.insert(attempt_id.to_owned()) {
                continue;
            }
            if !transitions.contains(&Transition::DispatchPrepared) {
                continue;
            }
            // Resolved reconciliations are not ambiguous.
            if matches!(
                self.snapshot.reconciliations.get(attempt_id),
                Some(
                    ReconciliationState::Accepted
                        | ReconciliationState::ProvenNotAccepted
                        | ReconciliationState::Terminal
                )
            ) {
                continue;
            }
            // Unresolved ReconciliationRequired stays derivable.
            if transitions.contains(&Transition::ReconciliationRequired) {
                ambiguous.push(attempt_id.to_owned());
                continue;
            }
            if transitions.contains(&Transition::ControllerLost) {
                continue;
            }
            // Cleanly consumed attempts (rejected / accepted-and-proven)
            // are not ambiguous.
            if self.snapshot.concluded_set.get(attempt_id) == Some(&true) {
                continue;
            }
            ambiguous.push(attempt_id.to_owned());
        }
        ambiguous
    }

    /// Derive accepted dispatches whose lifecycle evidence is
    /// incomplete: durably consumed with `NativeAccepted` but no exact
    /// turn observation recorded. Such attempts need operator
    /// attention after an observation write failed post-send.
    #[must_use]
    pub fn missing_evidence_attempts(&self) -> Vec<String> {
        let mut missing = Vec::new();
        let mut seen = BTreeSet::new();
        for (key, transitions) in &self.snapshot.transitions {
            let Some(attempt_id) = key.split(':').nth(1) else {
                continue;
            };
            if !seen.insert(attempt_id.to_owned()) {
                continue;
            }
            if !transitions.contains(&Transition::NativeAccepted) {
                continue;
            }
            if transitions.contains(&Transition::ReconciliationRequired)
                || self.snapshot.concluded_set.get(attempt_id) != Some(&true)
            {
                continue;
            }
            // Accepted but no evidence of an exact turn having been
            // observed — the observation write was never durable.
            if !transitions.contains(&Transition::ExactTurnStart)
                && !transitions.contains(&Transition::ExactTurnTerminal)
                && !transitions.contains(&Transition::ControllerLost)
            {
                missing.push(attempt_id.to_owned());
            }
        }
        missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::{Controller, FakeController};
    use crate::persist::FakePersist;
    use gearwit_protocol::ProviderEvent;
    use time::Duration as TimeDuration;

    fn now() -> OffsetDateTime {
        time::macros::datetime!(2026-01-15 12:00:00 UTC)
    }

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
            route: ManagedCapability::MANAGED_TURN_START_ROUTE.to_owned(),
            capability: ManagedCapability::ManagedTurnStart,
            coverage_until: now() + TimeDuration::hours(24),
        }
    }

    fn sample_arm_with_coverage(coverage_until: OffsetDateTime) -> KnownArm {
        KnownArm {
            coverage_until,
            ..sample_arm()
        }
    }

    fn sample_authority() -> DaemonAuthority<FakePersist> {
        let mut auth = DaemonAuthority::new(FakePersist::default(), now());
        auth.register_arm(sample_arm()).expect("register");
        auth
    }

    fn sample_authority_with_persist(persist: FakePersist) -> DaemonAuthority<FakePersist> {
        let mut auth = DaemonAuthority::new(persist, now());
        auth.register_arm(sample_arm()).expect("register");
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

    /// Fresh authority over a clone of the backend — the production
    /// restart shape. No arm registration, no map copying.
    fn restarted(persist: &FakePersist) -> DaemonAuthority<FakePersist> {
        DaemonAuthority::new(persist.clone(), now())
    }

    /// Admit the standard claim and return the attempt id + receipt.
    fn admitted(auth: &mut DaemonAuthority<FakePersist>) -> (String, AdmissionReceipt) {
        let admission = auth.admit_claim(&std_req()).expect("admit");
        let attempt_id = admission.attempt_id.clone();
        let receipt = admission.into_receipt().expect("receipt");
        (attempt_id, receipt)
    }

    /// Admit + prepare; return attempt id, prepared token, and command.
    fn admitted_prepared(
        auth: &mut DaemonAuthority<FakePersist>,
    ) -> (String, PreparedDispatch, ControllerCommand) {
        let (attempt_id, receipt) = admitted(auth);
        let (prepared, cmd) = auth.prepare_dispatch(receipt).expect("prepare");
        (attempt_id, prepared, cmd)
    }

    // -- Admission ---------------------------------------------------------

    #[test]
    fn first_claim_admits_and_mints_attachment() {
        let mut auth = sample_authority();
        let (attempt_id, _receipt) = admitted(&mut auth);
        let att = auth.get_attachment(&attempt_id).expect("attachment");
        assert_eq!(att.arm_id(), "arm-01");
        assert_eq!(att.generation(), 1);
        assert_eq!(att.seat_id(), "example-devrev");
        assert_eq!(att.route(), ManagedCapability::MANAGED_TURN_START_ROUTE);
        assert_eq!(att.capability(), ManagedCapability::ManagedTurnStart);
        assert!(!att.verifier_ref().is_empty());
        let ts = auth.persist().get_transitions("sig-1", &attempt_id);
        assert!(ts.contains(&Transition::ClaimRecorded));
    }

    #[test]
    fn admission_is_atomic_and_retry_admits_not_replays() {
        let mut auth = sample_authority_with_persist(FakePersist {
            next_claim_error: Some("write failed".to_owned()),
            ..Default::default()
        });
        let req = std_req();
        let err = auth.admit_claim(&req).expect_err("storage failure");
        assert!(matches!(err, AdmissionError::Storage(_)));
        // No partial state in any persisted family.
        assert!(auth.persist().claims.is_empty());
        assert!(auth.persist().claim_attempts.is_empty());
        assert!(auth.persist().verifier_refs.is_empty());
        assert!(auth.persist().transitions.is_empty());
        assert!(auth.persist().persisted_attachments.is_empty());
        assert!(auth.persist().attempt_signals.is_empty());

        // Retry on the same backend must produce Admitted, not Replay.
        auth.persist_mut().next_claim_error = None;
        let admission = auth.admit_claim(&req).expect("retry on same backend");
        assert_eq!(admission.outcome, ClaimOutcome::Admitted);
        let recorded_attempt = admission.attempt_id.clone();
        assert!(admission.into_receipt().is_some());
        let ts = auth.persist().get_transitions("sig-1", &recorded_attempt);
        assert_eq!(ts, &[Transition::ClaimRecorded]);

        // Exact replay: Replay, same attempt id, no receipt.
        let replay = auth.admit_claim(&req).expect("exact replay");
        assert_eq!(replay.outcome, ClaimOutcome::Replay);
        assert_eq!(replay.attempt_id, recorded_attempt);
        assert!(replay.into_receipt().is_none());
    }

    #[test]
    fn unknown_arm_rejects_claim() {
        let mut auth = sample_authority();
        let req = claim_req("nonexistent", "req-1", "sig-1", vec![sample_event("hello")]);
        let err = auth.admit_claim(&req).expect_err("unknown arm");
        assert!(matches!(err, AdmissionError::UnknownArm));
    }

    #[test]
    fn occupied_arm_rejects_second_claim() {
        let mut auth = sample_authority();
        admitted(&mut auth);
        let req2 = claim_req("arm-01", "req-2", "sig-2", vec![sample_event("world")]);
        let err = auth.admit_claim(&req2).expect_err("occupied");
        assert!(matches!(err, AdmissionError::Occupied));
    }

    #[test]
    fn exact_replay_returns_replay_without_receipt() {
        let mut auth = sample_authority();
        let (first_attempt, _) = admitted(&mut auth);
        let replay = auth.admit_claim(&std_req()).expect("replay");
        assert_eq!(replay.outcome, ClaimOutcome::Replay);
        assert_eq!(replay.attempt_id, first_attempt);
        assert!(replay.into_receipt().is_none(), "replay mints no receipt");
    }

    #[test]
    fn generation_advance_produces_new_generation_claim() {
        let mut auth = sample_authority();
        let (_, _rcpt1) = admitted(&mut auth);
        let new_gen = auth.advance_generation("arm-01").expect("advance");
        assert_eq!(new_gen, 2);
        let req2 = claim_req("arm-01", "req-2", "sig-2", vec![sample_event("world")]);
        let admission = auth.admit_claim(&req2).expect("admit gen 2");
        assert_eq!(admission.attempt_id, "attempt-2");
        let att = auth.get_attachment("attempt-2").expect("attachment");
        assert_eq!(att.generation(), 2);
    }

    #[test]
    fn advance_generation_overflow_fails_closed() {
        let mut auth = DaemonAuthority::new(FakePersist::default(), now());
        auth.register_arm(KnownArm {
            generation: u64::MAX,
            ..sample_arm()
        })
        .expect("register");
        let err = auth.advance_generation("arm-01").expect_err("overflow");
        assert!(
            matches!(err, AdmissionError::GenerationOverflow),
            "got {err:?}"
        );
        let arm = auth.persist().persisted_arms.get("arm-01").expect("arm");
        assert_eq!(arm.generation, u64::MAX, "persisted generation unchanged");
    }

    #[test]
    fn advance_generation_storage_failure_leaves_live_generation_unchanged() {
        let mut auth = sample_authority();
        auth.persist_mut().next_arm_persist_error = Some("disk full".to_owned());
        let err = auth.advance_generation("arm-01").expect_err("storage");
        assert!(matches!(err, AdmissionError::Storage(_)));
        let live = auth.arms.get("arm-01").expect("arm");
        assert_eq!(live.generation, 1, "live generation unchanged on failure");
        let persisted = auth.persist().persisted_arms.get("arm-01").expect("arm");
        assert_eq!(persisted.generation, 1);
        // Clearing the fault lets the re-arm through.
        auth.persist_mut().next_arm_persist_error = None;
        assert_eq!(auth.advance_generation("arm-01").expect("advance"), 2);
    }

    #[test]
    fn stale_generation_rejects_prepare_after_rearm() {
        let mut auth = sample_authority();
        let (_attempt, receipt) = admitted(&mut auth);
        auth.advance_generation("arm-01").expect("advance");
        let err = auth
            .prepare_dispatch(receipt)
            .expect_err("stale generation must reject prepare");
        assert!(
            matches!(&err.error, DispatchError::PreSend(msg) if msg.contains("stale")),
            "expected stale-generation rejection, got {err:?}"
        );
    }

    #[test]
    fn prepare_rehydrates_claim_identity_from_stored_state() {
        let mut auth = sample_authority();
        let (attempt_id, receipt) = admitted(&mut auth);
        // Tamper with the durable claim body behind the authority's back.
        auth.persist_mut()
            .claims
            .get_mut("req-1")
            .expect("claim")
            .events[0]
            .body = "tampered".to_owned();
        let err = auth
            .prepare_dispatch(receipt)
            .expect_err("tampered body must be rejected");
        assert!(
            matches!(&err.error, DispatchError::PreSend(msg) if msg.contains("does not match stored claim")),
            "got {err:?}"
        );
        assert!(
            !auth.persist().prepared_set.contains_key(&attempt_id),
            "no prepare marker after rejection"
        );
    }

    #[test]
    fn prepare_verifies_persisted_attempt_signal_binding() {
        let mut auth = sample_authority();
        let (attempt_id, receipt) = admitted(&mut auth);
        auth.persist_mut()
            .attempt_signals
            .insert(attempt_id.clone(), "sig-retarget".to_owned());
        let err = auth
            .prepare_dispatch(receipt)
            .expect_err("binding retarget must be rejected");
        assert!(
            matches!(&err.error, DispatchError::PreSend(msg) if msg.contains("record_prepared")),
            "got {err:?}"
        );
        assert!(!auth.persist().prepared_set.contains_key(&attempt_id));
        assert!(
            auth.persist()
                .get_transitions("sig-1", &attempt_id)
                .iter()
                .all(|t| *t != Transition::DispatchPrepared)
        );
    }

    #[test]
    fn closed_capability_is_validated_independently() {
        let mut auth = DaemonAuthority::new(FakePersist::default(), now());
        auth.register_arm(KnownArm {
            route: "not_a_capability".to_owned(),
            ..sample_arm()
        })
        .expect("register");
        let (_attempt, receipt) = admitted(&mut auth);
        let err = auth
            .prepare_dispatch(receipt)
            .expect_err("unparseable route must be rejected");
        assert!(
            matches!(&err.error, DispatchError::PreSend(msg) if msg.contains("capability")),
            "got {err:?}"
        );
    }

    #[test]
    fn prepare_records_transition_and_marker_atomically() {
        let mut auth = sample_authority();
        let (attempt_id, receipt) = admitted(&mut auth);
        auth.prepare_dispatch(receipt).expect("prepare");
        let ts = auth.persist().get_transitions("sig-1", &attempt_id);
        assert!(ts.contains(&Transition::DispatchPrepared));
        assert!(auth.persist().prepared_set.get(&attempt_id) == Some(&true));
    }

    #[test]
    fn duplicate_prepare_is_rejected_durably() {
        let mut auth = sample_authority();
        let (attempt_id, receipt) = admitted(&mut auth);
        auth.prepare_dispatch(receipt).expect("prepare");
        // Build a second receipt for the same attempt (module-level
        // adversarial construction; callers cannot do this).
        let claim = DurableClaim {
            request_id: "req-1".to_owned(),
            arm_id: "arm-01".to_owned(),
            generation: 1,
            signal_id: "sig-1".to_owned(),
            event_refs: vec!["event-hello".to_owned()],
            events: vec![sample_event("hello")],
            claimed_at: now(),
        };
        let second_receipt = AdmissionReceipt {
            attempt_id: attempt_id.clone(),
            claim,
        };
        let err = auth
            .prepare_dispatch(second_receipt)
            .expect_err("duplicate prepare");
        assert!(
            matches!(&err.error, DispatchError::PreSend(msg) if msg.contains("record_prepared")),
            "got {err:?}"
        );
        assert_eq!(
            auth.persist()
                .get_transitions("sig-1", &attempt_id)
                .iter()
                .filter(|t| **t == Transition::DispatchPrepared)
                .count(),
            1,
            "exactly one DispatchPrepared"
        );
    }

    #[test]
    fn prepare_atomic_failure_leaves_no_partial_state() {
        let mut auth = sample_authority();
        let (attempt_id, receipt) = admitted(&mut auth);
        auth.persist_mut().next_prepare_error = Some("prepare failed".to_owned());
        let err = auth
            .prepare_dispatch(receipt)
            .expect_err("atomic prepare failure");
        assert!(matches!(err.error, DispatchError::PreSend(_)));
        assert!(!auth.persist().prepared_set.contains_key(&attempt_id));
        assert!(
            !auth
                .persist()
                .get_transitions("sig-1", &attempt_id)
                .contains(&Transition::DispatchPrepared)
        );
    }

    #[test]
    fn revoked_attachment_fails_prepare_and_survives_restart() {
        let mut auth = sample_authority();
        let (attempt_id, receipt) = admitted(&mut auth);
        assert!(auth.revoke_attachment(&attempt_id).expect("revoke"));
        let err = auth
            .prepare_dispatch(receipt)
            .expect_err("revoked attachment must not prepare");
        assert!(matches!(&err.error, DispatchError::PreSend(msg) if msg.contains("revoked")));

        // Fresh restart: revocation is reconstructed exactly.
        let mut auth2 = restarted(auth.persist());
        let recovery = auth2.recover().expect("recover");
        let att = recovery.attachments.get(&attempt_id).expect("attachment");
        assert!(att.is_revoked(), "revocation must survive restart");
        assert!(!att.is_valid(now()));
        assert!(
            auth2
                .get_attachment(&attempt_id)
                .expect("installed")
                .is_revoked()
        );
    }

    #[test]
    fn revocation_storage_failure_leaves_live_attachment_valid() {
        let mut auth = sample_authority();
        let (attempt_id, _receipt) = admitted(&mut auth);
        auth.persist_mut().next_revoke_error = Some("revoke failed".to_owned());
        let err = auth
            .revoke_attachment(&attempt_id)
            .expect_err("revocation persistence failure");
        assert!(matches!(err, DispatchError::PreSend(_)));
        assert!(
            !auth
                .get_attachment(&attempt_id)
                .expect("attachment")
                .is_revoked(),
            "live attachment must remain unrevoked after durable failure"
        );
        // And the persisted record is unchanged too.
        assert!(
            !auth
                .persist()
                .persisted_attachments
                .get(&attempt_id)
                .expect("attachment")
                .revoked
        );
        // A clean revoke then works.
        assert!(auth.revoke_attachment(&attempt_id).expect("revoke"));
        assert!(
            auth.get_attachment(&attempt_id)
                .expect("attachment")
                .is_revoked()
        );
    }

    #[test]
    fn expired_lease_fails_prepare() {
        let mut auth = DaemonAuthority::new(FakePersist::default(), now());
        let short = sample_arm_with_coverage(now() + TimeDuration::hours(1));
        auth.register_arm(short).expect("register");
        let (_attempt, receipt) = admitted(&mut auth);
        auth.set_now(now() + TimeDuration::hours(2));
        let err = auth
            .prepare_dispatch(receipt)
            .expect_err("expired lease must fail");
        assert!(
            matches!(&err.error, DispatchError::PreSend(msg) if msg.contains("lease")),
            "got {err:?}"
        );
    }

    // -- Conclusion --------------------------------------------------------

    #[test]
    fn conclude_accepted_with_observations() {
        let mut auth = sample_authority();
        let (attempt_id, prepared, _cmd) = admitted_prepared(&mut auth);
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
        assert_eq!(conclusion.durable_outcome(), DurableOutcome::Terminal);
        let ts = auth.persist().get_transitions("sig-1", &attempt_id);
        for expected in [
            Transition::DispatchPrepared,
            Transition::NativeAccepted,
            Transition::ExactTurnStart,
            Transition::ExactTurnTerminal,
        ] {
            assert!(ts.contains(&expected), "missing {expected:?}");
        }
        assert!(auth.persist().concluded_set.contains_key(&attempt_id));
    }

    #[test]
    fn conclude_ambiguous_records_reconciliation_required() {
        let mut auth = sample_authority();
        let (attempt_id, prepared, _cmd) = admitted_prepared(&mut auth);
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
        let (attempt_id, prepared, _cmd) = admitted_prepared(&mut auth);
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
        assert!(
            auth.persist()
                .get_transitions("sig-1", &attempt_id)
                .contains(&Transition::ControllerLost)
        );
    }

    #[test]
    fn conclusion_is_atomic_nothing_recorded_on_failure() {
        for injection in ["disposition", "commit"] {
            let mut persist = FakePersist::default();
            if injection == "disposition" {
                persist.next_disposition_error = Some("disposition failed".to_owned());
            } else {
                persist.next_conclusion_error = Some("commit failed".to_owned());
            }
            let mut auth = sample_authority_with_persist(persist);
            let (attempt_id, prepared, _cmd) = admitted_prepared(&mut auth);
            let err = auth
                .conclude_dispatch(
                    prepared,
                    DispatchDisposition::Accepted {
                        correlation: "corr-1".to_owned(),
                    },
                    vec![],
                )
                .expect_err("atomic conclusion failure");
            assert!(
                matches!(err, DispatchError::PostSend(_)),
                "injection={injection}, got {err:?}"
            );
            // Nothing observable anywhere.
            assert!(
                auth.persist().get_disposition(&attempt_id).is_none(),
                "injection={injection}"
            );
            assert!(
                !auth.persist().concluded_set.contains_key(&attempt_id),
                "injection={injection}"
            );
            assert!(
                !auth
                    .persist()
                    .get_transitions("sig-1", &attempt_id)
                    .contains(&Transition::NativeAccepted),
                "injection={injection}"
            );
            // Fresh restart: the attempt is derivable as ambiguous and
            // stays unconsumed.
            let mut auth2 = restarted(auth.persist());
            let recovery = auth2.recover().expect("recover");
            assert!(
                recovery
                    .derivable_ambiguous_attempts()
                    .contains(&attempt_id),
                "injection={injection}: attempt must survive restart as ambiguous"
            );
        }
    }

    #[test]
    fn duplicate_conclusion_blocked_durably() {
        let mut auth = sample_authority();
        let (attempt_id, prepared, _cmd) = admitted_prepared(&mut auth);
        auth.conclude_dispatch(
            prepared,
            DispatchDisposition::Accepted {
                correlation: "c".to_owned(),
            },
            vec![],
        )
        .expect("conclude");
        // A second conclusion token for the same attempt (module-level
        // adversarial construction) is rejected by the durable marker.
        let second = PreparedDispatch {
            attempt_id: attempt_id.clone(),
            signal_id: "sig-1".to_owned(),
        };
        let err = auth
            .conclude_dispatch(second, DispatchDisposition::Rejected, vec![])
            .expect_err("duplicate conclusion");
        assert!(
            matches!(&err, DispatchError::PreSend(msg) if msg.contains("already been concluded")),
            "got {err:?}"
        );
    }

    #[test]
    fn durable_outcome_exhaustivity_covers_all_six_variants() {
        // Each of the six outcomes takes one independent fresh authority.
        let mut rejected = sample_authority();
        let (_a, p, _c) = admitted_prepared(&mut rejected);
        let dc = rejected
            .conclude_dispatch(p, DispatchDisposition::Rejected, vec![])
            .expect("conclude");
        assert_eq!(dc.durable_outcome(), DurableOutcome::Rejected);

        let mut accepted = sample_authority();
        let (_a, p, _c) = admitted_prepared(&mut accepted);
        let dc = accepted
            .conclude_dispatch(
                p,
                DispatchDisposition::Accepted {
                    correlation: "c".to_owned(),
                },
                vec![],
            )
            .expect("conclude");
        assert_eq!(dc.durable_outcome(), DurableOutcome::Accepted);

        let mut started = sample_authority();
        let (_a, p, _c) = admitted_prepared(&mut started);
        let dc = started
            .conclude_dispatch(
                p,
                DispatchDisposition::Accepted {
                    correlation: "c".to_owned(),
                },
                vec![LifecycleObservation::TurnStarted("T1".to_owned())],
            )
            .expect("conclude");
        assert_eq!(dc.durable_outcome(), DurableOutcome::Started);

        let mut terminal = sample_authority();
        let (_a, p, _c) = admitted_prepared(&mut terminal);
        let dc = terminal
            .conclude_dispatch(
                p,
                DispatchDisposition::Accepted {
                    correlation: "c".to_owned(),
                },
                vec![
                    LifecycleObservation::TurnStarted("T1".to_owned()),
                    LifecycleObservation::TurnTerminal("T1".to_owned(), true),
                ],
            )
            .expect("conclude");
        assert_eq!(dc.durable_outcome(), DurableOutcome::Terminal);

        let mut lost = sample_authority();
        let (_a, p, _c) = admitted_prepared(&mut lost);
        let dc = lost
            .conclude_dispatch(
                p,
                DispatchDisposition::Accepted {
                    correlation: "c".to_owned(),
                },
                vec![LifecycleObservation::ControllerLost],
            )
            .expect("conclude");
        assert!(dc.controller_lost());
        assert_eq!(dc.durable_outcome(), DurableOutcome::ControllerLost);

        let mut ambiguous = sample_authority();
        let (_a, p, _c) = admitted_prepared(&mut ambiguous);
        let dc = ambiguous
            .conclude_dispatch(p, DispatchDisposition::Ambiguous, vec![])
            .expect("conclude");
        assert!(dc.reconciliation_required());
        assert_eq!(dc.durable_outcome(), DurableOutcome::Ambiguous);
    }

    // -- Post-send observation boundaries + fresh restart ----------------

    #[test]
    fn observation_turn_start_failure_surfaces_missing_evidence_after_restart() {
        let mut auth = sample_authority_with_persist(FakePersist {
            next_transition_error: Some("ExactTurnStart failed".to_owned()),
            transition_allow_count: 0,
            ..Default::default()
        });
        let (attempt_id, prepared, _cmd) = admitted_prepared(&mut auth);
        let err = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "corr-1".to_owned(),
                },
                vec![LifecycleObservation::TurnStarted("T1".to_owned())],
            )
            .expect_err("observation failure");
        assert!(matches!(err, DispatchError::PostSend(_)));
        // NativeAccepted is durable (atomic conclusion), observation absent.
        let ts = auth.persist().get_transitions("sig-1", &attempt_id);
        assert!(ts.contains(&Transition::NativeAccepted));
        assert!(!ts.contains(&Transition::ExactTurnStart));

        // Fresh restart: the accepted attempt surfaces as missing evidence.
        let mut auth2 = restarted(auth.persist());
        let recovery = auth2.recover().expect("recover");
        assert!(
            recovery.missing_evidence_attempts().contains(&attempt_id),
            "accepted-without-evidence must be visible after restart"
        );
        assert!(
            !recovery
                .derivable_ambiguous_attempts()
                .contains(&attempt_id),
            "not ambiguous — the acceptance is durably known"
        );
    }

    #[test]
    fn observation_terminal_failure_keeps_started_evidence() {
        let mut auth = sample_authority_with_persist(FakePersist {
            next_transition_error: Some("ExactTurnTerminal failed".to_owned()),
            transition_allow_count: 1,
            ..Default::default()
        });
        let (attempt_id, prepared, _cmd) = admitted_prepared(&mut auth);
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
            .expect_err("terminal failure");
        assert!(matches!(err, DispatchError::PostSend(_)));
        let ts = auth.persist().get_transitions("sig-1", &attempt_id);
        assert!(ts.contains(&Transition::ExactTurnStart));
        assert!(!ts.contains(&Transition::ExactTurnTerminal));
        // Started evidence is present — not in the missing-evidence set.
        let mut auth2 = restarted(auth.persist());
        let recovery = auth2.recover().expect("recover");
        assert!(!recovery.missing_evidence_attempts().contains(&attempt_id));
    }

    #[test]
    fn observation_controller_lost_failure_is_post_send() {
        let mut auth = sample_authority_with_persist(FakePersist {
            next_transition_error: Some("ControllerLost failed".to_owned()),
            transition_allow_count: 0,
            ..Default::default()
        });
        let (attempt_id, prepared, _cmd) = admitted_prepared(&mut auth);
        let err = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "corr-1".to_owned(),
                },
                vec![LifecycleObservation::ControllerLost],
            )
            .expect_err("observation failure");
        assert!(matches!(err, DispatchError::PostSend(_)));
        let ts = auth.persist().get_transitions("sig-1", &attempt_id);
        assert!(ts.contains(&Transition::NativeAccepted));
        assert!(!ts.contains(&Transition::ControllerLost));
    }

    #[test]
    fn restart_after_post_send_failure_blocks_new_grant_until_rearm() {
        let mut auth = sample_authority_with_persist(FakePersist {
            next_disposition_error: Some("post-send write failed".to_owned()),
            ..Default::default()
        });
        let (attempt_id, prepared, _cmd) = admitted_prepared(&mut auth);
        let _err = auth
            .conclude_dispatch(
                prepared,
                DispatchDisposition::Accepted {
                    correlation: "corr-1".to_owned(),
                },
                vec![],
            )
            .expect_err("post-send failure");

        // Full production restart — no registration, no map copying.
        let mut auth2 = restarted(auth.persist());
        let _recovery = auth2.recover().expect("recover");

        // Replay works, returns the same attempt id.
        let replay = auth2.admit_claim(&std_req()).expect("replay after failure");
        assert_eq!(replay.outcome, ClaimOutcome::Replay);
        assert_eq!(replay.attempt_id, attempt_id);
        assert!(replay.into_receipt().is_none());

        // A new claim on the same arm/generation is Occupied until re-arm.
        let req2 = claim_req("arm-01", "req-2", "sig-2", vec![sample_event("new")]);
        let occupied = auth2.admit_claim(&req2).expect_err("must be occupied");
        assert!(matches!(occupied, AdmissionError::Occupied));

        // Re-arm on the recovered authority → new claim at gen 2.
        auth2.advance_generation("arm-01").expect("re-arm");
        let req3 = claim_req("arm-01", "req-3", "sig-3", vec![sample_event("fresh")]);
        let fresh = auth2.admit_claim(&req3).expect("fresh after re-arm");
        assert_eq!(fresh.attempt_id, "attempt-2", "counter must have survived");
        assert!(fresh.into_receipt().is_some());
    }

    // -- Full semantic packet recovery -----------------------------------

    #[test]
    fn recovery_reconstructs_full_semantic_packet_from_backend_alone() {
        // Session 1: production ops only — no FakePersist field copying.
        let mut auth1 = DaemonAuthority::new(FakePersist::default(), now());
        auth1.register_arm(sample_arm()).expect("register arm-01");
        auth1
            .register_arm(KnownArm {
                arm_id: "arm-02".to_owned(),
                seat_id: "dev".to_owned(),
                route: "managed_turn_start".to_owned(),
                coverage_until: now() + TimeDuration::hours(5),
                ..sample_arm()
            })
            .expect("register arm-02");
        auth1.advance_generation("arm-01").expect("advance");

        let admission = auth1
            .admit_claim(&claim_req(
                "arm-01",
                "req-1",
                "sig-1",
                vec![sample_event("hello")],
            ))
            .expect("admit");
        let attempt_id = admission.attempt_id.clone();
        let receipt = admission.into_receipt().expect("receipt");
        let (prepared, _cmd) = auth1.prepare_dispatch(receipt).expect("prepare");
        auth1
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
            .expect("conclude");

        auth1
            .record_handled_cursor("arm-01", "cursor-42")
            .expect("cursor");
        auth1.set_rearmed("arm-01").expect("rearm");

        // Session 2: fresh authority from the backend alone. No
        // register_arm before recover.
        let mut auth2 = restarted(auth1.persist());
        let recovery = auth2.recover().expect("recover after restart");

        // Arms: full policy, not skeletons.
        let arm = recovery.arms.get("arm-01").expect("arm-01");
        assert_eq!(arm.generation, 2, "advanced generation must survive");
        assert_eq!(arm.seat_id, "example-devrev");
        assert_eq!(arm.capability, ManagedCapability::ManagedTurnStart);
        assert_eq!(arm.coverage_until, sample_arm().coverage_until);
        let arm2 = recovery.arms.get("arm-02").expect("arm-02");
        assert_eq!(arm2.seat_id, "dev");
        assert_eq!(arm2.route, "managed_turn_start");

        // Attachments: installed, exact persisted lease (not wall clock).
        let att = recovery.attachments.get(&attempt_id).expect("attachment");
        assert_eq!(att.seat_id(), "example-devrev");
        assert_eq!(att.capability(), ManagedCapability::ManagedTurnStart);
        assert_eq!(att.lease_until(), sample_arm().coverage_until);
        assert!(!att.is_revoked());
        assert!(!att.verifier_ref().is_empty());
        assert!(
            auth2.get_attachment(&attempt_id).is_some(),
            "attachment must be installed into live authority state"
        );

        assert_eq!(
            recovery.handled_cursors.get("arm-01").map(String::as_str),
            Some("cursor-42")
        );
        assert_eq!(recovery.rearm_positions.get("arm-01"), Some(&true));

        // Replay returns the recorded attempt; no fresh receipt.
        let replay = auth2.admit_claim(&std_req()).expect("replay after restart");
        assert_eq!(replay.outcome, ClaimOutcome::Replay);
        assert_eq!(replay.attempt_id, attempt_id);
        assert!(replay.into_receipt().is_none());

        // The recovered authority serves a complete fresh cycle.
        auth2.advance_generation("arm-01").expect("re-arm");
        let req2 = claim_req("arm-01", "req-4", "sig-4", vec![sample_event("next")]);
        let admission2 = auth2.admit_claim(&req2).expect("fresh admit");
        let receipt2 = admission2.into_receipt().expect("receipt");
        let (prepared2, _cmd2) = auth2.prepare_dispatch(receipt2).expect("prepare");
        auth2
            .conclude_dispatch(prepared2, DispatchDisposition::Rejected, vec![])
            .expect("conclude");
    }

    #[test]
    fn recovery_attempt_counter_continues_monotonically() {
        let mut auth1 = sample_authority();
        let (first, _rcpt) = admitted(&mut auth1);
        assert_eq!(first, "attempt-1");
        let mut auth2 = restarted(auth1.persist());
        auth2.recover().expect("recover");
        let req2 = claim_req("arm-01", "req-2", "sig-2", vec![sample_event("next")]);
        auth2.advance_generation("arm-01").expect("advance");
        let admission = auth2.admit_claim(&req2).expect("admit");
        assert_eq!(admission.attempt_id, "attempt-2");
    }

    #[test]
    fn replay_interleaves_with_new_generations_without_reusing_attempt_ids() {
        let mut auth = sample_authority();
        let mut arm2 = sample_arm();
        arm2.arm_id = "arm-02".to_owned();
        arm2.generation = 2;
        auth.register_arm(arm2)
            .expect("register generation two arm");
        let mut arm3 = sample_arm();
        arm3.arm_id = "arm-03".to_owned();
        arm3.generation = 3;
        auth.register_arm(arm3)
            .expect("register generation three arm");
        assert_eq!(admitted(&mut auth).0, "attempt-1");
        let req2 = claim_req("arm-02", "req-2", "sig-2", vec![sample_event("two")]);
        assert_eq!(
            auth.admit_claim(&req2).expect("admit second").attempt_id,
            "attempt-2"
        );
        let req3 = claim_req("arm-03", "req-3", "sig-3", vec![sample_event("three")]);
        assert_eq!(
            auth.admit_claim(&req3).expect("admit third").attempt_id,
            "attempt-3"
        );

        // An old exact replay must not roll attempt_seq back from three to
        // one, even with live claims at three registered generations.
        assert_eq!(
            auth.admit_claim(&std_req())
                .expect("replay first")
                .attempt_id,
            "attempt-1"
        );

        // The same invariant holds after recovery when another older replay
        // is interleaved before a fresh generation.
        let mut recovered = restarted(auth.persist());
        recovered.recover().expect("recover");
        assert_eq!(
            recovered
                .admit_claim(&req2)
                .expect("replay second")
                .attempt_id,
            "attempt-2"
        );
        let mut arm4 = sample_arm();
        arm4.arm_id = "arm-04".to_owned();
        arm4.generation = 4;
        recovered
            .register_arm(arm4)
            .expect("register generation four arm");
        let req4 = claim_req("arm-04", "req-4", "sig-4", vec![sample_event("four")]);
        assert_eq!(
            recovered
                .admit_claim(&req4)
                .expect("admit fourth")
                .attempt_id,
            "attempt-4"
        );
    }

    // -- Split-phase reconciliation --------------------------------------

    fn admit_prepare_ambiguous(auth: &mut DaemonAuthority<FakePersist>) -> String {
        let (attempt_id, receipt) = admitted(auth);
        let (prepared, _cmd) = auth.prepare_dispatch(receipt).expect("prepare");
        auth.conclude_dispatch(prepared, DispatchDisposition::Ambiguous, vec![])
            .expect("conclude");
        attempt_id
    }

    #[test]
    fn unreconciled_ambiguous_attempt_is_derivable_after_restart() {
        // Key fix: a properly recorded ambiguous conclusion must be
        // discoverable for reconciliation after restart.
        let mut auth = sample_authority();
        let attempt_id = admit_prepare_ambiguous(&mut auth);
        let mut auth2 = restarted(auth.persist());
        let recovery = auth2.recover().expect("recover");
        assert!(
            recovery
                .derivable_ambiguous_attempts()
                .contains(&attempt_id),
            "unreconciled ambiguous attempt must be derivable after restart"
        );
    }

    #[test]
    fn split_phase_reconcile_commits_resolution_durably() {
        let mut auth = sample_authority();
        let attempt_id = admit_prepare_ambiguous(&mut auth);

        // Phase 1: authority produces work; no controller borrowed.
        let work = auth
            .prepare_reconciliation(&attempt_id)
            .expect("prepare_reconciliation");
        assert_eq!(work.attempt_id(), attempt_id);

        // Provider probe happens strictly outside authority.
        let controller = FakeController::new(vec![])
            .with_reconciliation(crate::controller::ReconciliationDisposition::ProvenNotAccepted);
        let disposition = controller.reconcile(work.attempt_id());

        // Phase 2: authority commits the probe result.
        let result = auth
            .commit_reconciliation(work, disposition)
            .expect("commit_reconciliation");
        assert_eq!(
            result,
            crate::controller::ReconciliationDisposition::ProvenNotAccepted
        );

        let ts = auth.persist().get_transitions("sig-1", &attempt_id);
        assert!(ts.contains(&Transition::ReconciliationResolved), "{ts:?}");
        assert!(!ts.contains(&Transition::NativeAccepted));
        assert_eq!(
            auth.persist().reconciliations.get(&attempt_id),
            Some(&ReconciliationState::ProvenNotAccepted)
        );

        // Restart: resolved attempts are no longer derivable.
        let mut auth2 = restarted(auth.persist());
        let recovery = auth2.recover().expect("recover");
        assert!(
            !recovery
                .derivable_ambiguous_attempts()
                .contains(&attempt_id)
        );
    }

    #[test]
    fn split_phase_reconcile_accepted_records_native_accepted() {
        let mut auth = sample_authority();
        let attempt_id = admit_prepare_ambiguous(&mut auth);
        let work = auth
            .prepare_reconciliation(&attempt_id)
            .expect("prepare_reconciliation");
        let controller = FakeController::new(vec![])
            .with_reconciliation(crate::controller::ReconciliationDisposition::Accepted);
        let disposition = controller.reconcile(work.attempt_id());
        auth.commit_reconciliation(work, disposition)
            .expect("commit");
        let ts = auth.persist().get_transitions("sig-1", &attempt_id);
        assert!(ts.contains(&Transition::NativeAccepted));
        assert!(ts.contains(&Transition::ReconciliationResolved));
        assert_eq!(
            auth.persist().reconciliations.get(&attempt_id),
            Some(&ReconciliationState::Accepted)
        );
    }

    #[test]
    fn reconcile_unknown_stays_derivable_after_restart() {
        let mut auth = sample_authority();
        let attempt_id = admit_prepare_ambiguous(&mut auth);
        let work = auth
            .prepare_reconciliation(&attempt_id)
            .expect("prepare_reconciliation");
        let controller = FakeController::new(vec![])
            .with_reconciliation(crate::controller::ReconciliationDisposition::Unknown);
        let disposition = controller.reconcile(work.attempt_id());
        auth.commit_reconciliation(work, disposition)
            .expect("commit");
        // The Unknown probe result is persisted but does not resolve.
        assert_eq!(
            auth.persist().reconciliations.get(&attempt_id),
            Some(&ReconciliationState::Unknown)
        );
        let mut auth2 = restarted(auth.persist());
        let recovery = auth2.recover().expect("recover");
        assert!(
            recovery
                .derivable_ambiguous_attempts()
                .contains(&attempt_id),
            "Unknown resolution must stay derivable"
        );

        // Unknown is provisional: a later probe can atomically resolve the
        // same attempt, after which recovery no longer derives it.
        let work = auth2
            .prepare_reconciliation(&attempt_id)
            .expect("prepare after unknown");
        auth2
            .commit_reconciliation(work, crate::controller::ReconciliationDisposition::Terminal)
            .expect("terminal resolution after unknown");
        let mut auth3 = restarted(auth2.persist());
        let recovery = auth3.recover().expect("recover terminal resolution");
        assert!(
            !recovery
                .derivable_ambiguous_attempts()
                .contains(&attempt_id),
            "a terminal upgrade from Unknown must resolve the attempt"
        );
    }

    #[test]
    fn repeated_same_resolution_is_idempotent_conflicting_fails() {
        let mut auth = sample_authority();
        let attempt_id = admit_prepare_ambiguous(&mut auth);
        let controller = FakeController::new(vec![])
            .with_reconciliation(crate::controller::ReconciliationDisposition::Terminal);
        let work = auth
            .prepare_reconciliation(&attempt_id)
            .expect("prepare_reconciliation");
        let disposition = controller.reconcile(work.attempt_id());
        auth.commit_reconciliation(work, disposition)
            .expect("first resolution");

        // After resolution, prepare refuses — no second probe cycle.
        let err = auth
            .prepare_reconciliation(&attempt_id)
            .expect_err("already resolved — prepare must refuse");
        assert!(matches!(err, DispatchError::PostSend(_)));

        // Durable state has exactly one Resolved transition.
        let ts = auth.persist().get_transitions("sig-1", &attempt_id);
        assert_eq!(
            ts.iter()
                .filter(|t| **t == Transition::ReconciliationResolved)
                .count(),
            1
        );
    }

    #[test]
    fn reconciliation_requires_prior_ambiguity() {
        let mut auth = sample_authority();
        let (attempt_id, prepared, _cmd) = admitted_prepared(&mut auth);
        auth.conclude_dispatch(
            prepared,
            DispatchDisposition::Accepted {
                correlation: "corr-1".to_owned(),
            },
            vec![],
        )
        .expect("conclude");
        // Not ambiguous: the commit of any resolution refuses to run
        // because no ReconciliationRequired transition exists.
        let work = auth
            .prepare_reconciliation(&attempt_id)
            .expect("binding exists");
        let disposition = crate::controller::ReconciliationDisposition::Accepted;
        let err = auth
            .commit_reconciliation(work, disposition)
            .expect_err("no prior ReconciliationRequired");
        assert!(matches!(err, DispatchError::PostSend(_)));
    }

    #[test]
    fn reconciliation_unknown_attempt_fails_closed_without_fallback() {
        let mut auth = sample_authority();
        admit_prepare_ambiguous(&mut auth);
        let err = auth
            .prepare_reconciliation("attempt-99")
            .expect_err("unknown attempt must fail closed");
        assert!(
            matches!(&err, DispatchError::PostSend(msg) if msg.contains("binding")),
            "got {err:?}"
        );
    }

    #[test]
    fn reconciliation_binding_tamper_fails_closed() {
        let mut auth = sample_authority();
        let attempt_id = admit_prepare_ambiguous(&mut auth);
        auth.persist_mut()
            .attempt_signals
            .insert(attempt_id.clone(), "sig-retarget".to_owned());
        // The commit must fail closed — no fallback to attempt_id.
        let work = auth
            .prepare_reconciliation(&attempt_id)
            .expect("prepare reads the (tampered) binding");
        let disposition = crate::controller::ReconciliationDisposition::Terminal;
        let err = auth
            .commit_reconciliation(work, disposition)
            .expect_err("tampered binding");
        assert!(matches!(err, DispatchError::PostSend(_)));
    }

    // -- Fail-closed cursor / re-arm --------------------------------------

    #[test]
    fn handled_cursor_and_rearm_persist_and_recover() {
        let mut auth = sample_authority();
        auth.record_handled_cursor("arm-01", "cursor-7")
            .expect("cursor");
        auth.set_rearmed("arm-01").expect("rearm");
        let persist = auth.persist();
        assert_eq!(
            persist.handled_cursors.get("arm-01"),
            Some(&"cursor-7".to_owned())
        );
        assert_eq!(persist.rearm_positions.get("arm-01"), Some(&true));

        let mut auth2 = restarted(auth.persist());
        let recovery = auth2.recover().expect("recover");
        assert_eq!(
            recovery.handled_cursors.get("arm-01").map(String::as_str),
            Some("cursor-7")
        );
        assert_eq!(recovery.rearm_positions.get("arm-01"), Some(&true));
    }

    #[test]
    fn cursor_and_rearm_storage_failures_leave_live_state_unchanged() {
        let mut auth = sample_authority();
        auth.persist_mut().next_cursor_error = Some("cursor failed".to_owned());
        assert!(matches!(
            auth.record_handled_cursor("arm-01", "cursor-7"),
            Err(AdmissionError::Storage(_))
        ));
        assert!(!auth.persist().handled_cursors.contains_key("arm-01"));
        auth.persist_mut().next_rearm_error = Some("rearm failed".to_owned());
        assert!(matches!(
            auth.set_rearmed("arm-01"),
            Err(AdmissionError::Storage(_))
        ));
        assert!(!auth.persist().rearm_positions.contains_key("arm-01"));
        // Clearing the fault lets both records land.
        auth.persist_mut().next_cursor_error = None;
        auth.persist_mut().next_rearm_error = None;
        auth.record_handled_cursor("arm-01", "cursor-7")
            .expect("cursor ok");
        auth.set_rearmed("arm-01").expect("rearm ok");
    }
}
