//! Semantic persistence port for gearwitd authority.
//!
//! Defines the operational contract for durable claim admission, monotonic
//! transition recording, and restart recovery. Backends implement this port;
//! the daemon treats it as the single durability boundary.

use gearwit_protocol::{ProviderEvent, WaiterLinkError};
use std::collections::BTreeMap;

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
/// `ReconciliationRequired`.
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
    /// Signal id was already used with a different body.
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

/// Result of recovery after daemon restart.
#[derive(Clone, Debug, Default)]
pub struct RecoverySnapshot {
    /// Durable claims that were live at shutdown.
    pub claims: Vec<DurableClaim>,
    /// Transitions recorded per claim request id.
    pub transitions: BTreeMap<String, Vec<Transition>>,
    /// Recorded dispatch dispositions keyed by attempt id.
    pub dispositions: BTreeMap<String, crate::controller::DispatchDisposition>,
    /// Claim `request_id` → `attempt_id` mapping for replay.
    pub attempt_map: BTreeMap<String, String>,
    /// Live arm IDs and generations for authority reconstruction.
    pub arm_states: Vec<(String, u64)>,
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
/// - `admit_claim` must durably record the claim and return the outcome
///   before the caller dispatches any external I/O.
/// - `record_transition` must be monotonic — reject duplicate, stale,
///   regressive, or conflicting transitions. Transitions are scoped to an
///   attempt: different attempts on the same signal may progress
///   independently.
/// - `record_disposition` must durably record the dispatch disposition
///   keyed by `attempt_id` for replay on restart.
/// - `recover` must return live claims, transitions, and dispositions
///   after restart.
/// - `durability` must report the backend's proven class, not a weaker
///   fallback.
/// - No bearer capability, proof material, credential, or controller
///   secret may be persisted.
pub trait Persist {
    /// Atomically admit one generation-fenced claim: durably record the
    /// claim, mint (or replay) attempt identity, record `ClaimRecorded`,
    /// and store an opaque verifier reference — all as one operation.
    /// Content identity is determined by `request_id`; exact replay
    /// returns the previously recorded attempt/verifier state.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError`] when the claim is stale, conflicts, or
    /// storage is unavailable.
    fn admit_claim(&mut self, claim: &DurableClaim) -> Result<AdmissionRecord, ClaimError>;

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
    /// arm states, handled cursors, and re-arm positions for full
    /// authority reconstruction.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError::StorageFailure`] when the backend is
    /// unavailable or corrupt.
    fn recover(&mut self) -> Result<RecoverySnapshot, ClaimError>;

    /// Atomically record a dispatch conclusion: disposition plus the
    /// first required post-send transition in one semantic commit.
    ///
    /// The implementation must stage/validate both writes and commit
    /// them together. No partial write may be observable — either both
    /// the disposition and transition appear, or neither does.
    ///
    /// For `Accepted`, this is disposition + `NativeAccepted`.
    /// For `Ambiguous`, this is disposition + `ReconciliationRequired`.
    /// For `Rejected`, this is disposition only (no transition).
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] if any part of the atomic
    /// write fails.
    fn record_conclusion(
        &mut self,
        attempt_id: &str,
        signal_id: &str,
        disposition: &crate::controller::DispatchDisposition,
        first_transition: Option<Transition>,
    ) -> Result<(), WaiterLinkError>;

    /// Durably record that an attempt has been prepared for dispatch.
    /// Used to detect duplicate conclusion on restart.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] when persistence fails.
    fn record_prepared(&mut self, attempt_id: &str) -> Result<(), WaiterLinkError>;

    /// True if the attempt has been durably concluded.
    /// Checked before conclusion to enforce the durable single-conclusion
    /// invariant.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] when the check fails.
    fn has_concluded(&self, attempt_id: &str) -> Result<bool, WaiterLinkError>;

    /// Durably mark an attempt as concluded.
    /// Called after a successful conclusion to prevent duplicate
    /// conclusion on restart.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] when persistence fails.
    fn record_concluded(&mut self, attempt_id: &str) -> Result<(), WaiterLinkError>;

    /// Persist an arm's state (`arm_id`, generation) for recovery after restart.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] when persistence fails.
    fn persist_arm_state(&mut self, arm_id: &str, generation: u64) -> Result<(), WaiterLinkError>;

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

    /// Durably record a reconciliation resolution for an attempt.
    ///
    /// Records the `ReconciliationResolved` transition durably so
    /// that a fresh restart does not re-derive reconciliation-required
    /// work for an already-resolved attempt.
    ///
    /// # Errors
    ///
    /// Returns [`WaiterLinkError::Semantic`] when persistence fails
    /// or when the attempt has no prior `ReconciliationRequired` transition.
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
    /// Monotonic attempt counter.
    pub attempt_seq: u64,
    /// When set, `admit_claim` returns `StorageFailure` with this message
    /// instead of succeeding.
    pub next_claim_error: Option<String>,
    /// When set, `record_transition` returns an error with this message.
    pub next_transition_error: Option<String>,
    /// When set, `record_disposition` returns an error with this message.
    pub next_disposition_error: Option<String>,
    /// Counter: how many `record_transition` calls to allow before injecting error.
    pub transition_allow_count: usize,
    /// Tracks how many `record_transition` calls have been made.
    pub transition_call_count: usize,
    /// Arm states to return on recovery.
    pub arm_states: Vec<(String, u64)>,
    /// Handled cursors to return on recovery.
    pub handled_cursors: BTreeMap<String, String>,
    /// Re-arm positions to return on recovery.
    pub rearm_positions: BTreeMap<String, bool>,
    /// Set of durably prepared `attempt_ids`.
    pub prepared_set: BTreeMap<String, bool>,
    /// Set of durably concluded `attempt_ids`.
    pub concluded_set: BTreeMap<String, bool>,
    /// When set, `record_prepared` returns an error with this message.
    pub next_record_prepared_error: Option<String>,
    /// When set, `record_conclusion` uses two-phase commit:
    /// stage validates and returns Ok; commit applies the writes.
    pub conclusion_commit_error: Option<String>,
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
    fn admit_claim(&mut self, claim: &DurableClaim) -> Result<AdmissionRecord, ClaimError> {
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
        // Atomic admission: store claim, mint attempt, mint verifier, record ClaimRecorded
        self.claim_attempts.insert(
            claim.request_id.clone(),
            format!("attempt-{}", self.attempt_seq + 1),
        );
        self.attempt_seq += 1;
        let attempt_id = self
            .claim_attempts
            .get(&claim.request_id)
            .cloned()
            .expect("just stored");
        let verifier_ref = format!(
            "vrf:{}:{}:{}:{}",
            claim.arm_id, claim.generation, attempt_id, self.attempt_seq
        );
        self.verifier_refs
            .insert(claim.request_id.clone(), verifier_ref.clone());
        self.claims.insert(claim.request_id.clone(), claim.clone());
        // Record ClaimRecorded atomically
        let key = (claim.signal_id.clone(), attempt_id.clone());
        self.transitions
            .entry(key)
            .or_default()
            .push(Transition::ClaimRecorded);
        Ok(AdmissionRecord {
            outcome: ClaimOutcome::Admitted,
            attempt_id,
            verifier_ref,
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
        let entry = self.transitions.entry(key).or_default();
        if entry.contains(&transition) {
            return Err(WaiterLinkError::Semantic("duplicate transition"));
        }
        // Enforce monotonic order
        if let Some(last) = entry.last() {
            let valid = match transition {
                Transition::ReconciliationRequired => {
                    *last == Transition::DispatchPrepared
                        || *last == Transition::NativeAccepted
                        || *last == Transition::ReconciliationResolved
                }
                Transition::ReconciliationResolved => *last == Transition::ReconciliationRequired,
                Transition::ControllerLost => {
                    *last == Transition::DispatchPrepared
                        || *last == Transition::NativeAccepted
                        || *last == Transition::ExactTurnStart
                }
                _ => transition as u8 == *last as u8 + 1,
            };
            if !valid {
                return Err(WaiterLinkError::Semantic("regressive transition"));
            }
        } else if transition != Transition::ClaimRecorded {
            return Err(WaiterLinkError::Semantic(
                "first transition must be ClaimRecorded",
            ));
        }
        entry.push(transition);
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
        if let Some(existing) = self.dispositions.get(attempt_id) {
            if *existing != *disposition {
                return Err(WaiterLinkError::Semantic(
                    "conflicting disposition for attempt_id",
                ));
            }
            return Ok(());
        }
        self.dispositions
            .insert(attempt_id.to_owned(), disposition.clone());
        Ok(())
    }

    fn record_conclusion(
        &mut self,
        attempt_id: &str,
        signal_id: &str,
        disposition: &crate::controller::DispatchDisposition,
        first_transition: Option<Transition>,
    ) -> Result<(), WaiterLinkError> {
        // Two-phase atomic commit: stage, validate, then commit.
        // Phase 1: Validate both writes can succeed without mutations.
        // Check that disposition write would succeed
        if self.next_disposition_error.is_some() {
            let msg = self.next_disposition_error.take().unwrap();
            return Err(WaiterLinkError::Semantic(Box::leak(msg.into_boxed_str())));
        }
        // Check that transition write would succeed
        if let Some(_transition) = first_transition {
            self.transition_call_count += 1;
            if self.transition_call_count > self.transition_allow_count
                && self.next_transition_error.is_some()
            {
                // Reset the call count since we're aborting
                self.transition_call_count -= 1;
                let msg = self.next_transition_error.take().unwrap();
                return Err(WaiterLinkError::Semantic(Box::leak(msg.into_boxed_str())));
            }
        }
        // Check for commit failure injection
        if let Some(msg) = self.conclusion_commit_error.take() {
            return Err(WaiterLinkError::Semantic(Box::leak(msg.into_boxed_str())));
        }

        // Phase 2: Commit — write disposition
        if let Some(existing) = self.dispositions.get(attempt_id) {
            if *existing != *disposition {
                return Err(WaiterLinkError::Semantic(
                    "conflicting disposition for attempt_id",
                ));
            }
        } else {
            self.dispositions
                .insert(attempt_id.to_owned(), disposition.clone());
        }

        // Commit — write transition
        if let Some(transition) = first_transition {
            let key = (signal_id.to_owned(), attempt_id.to_owned());
            let entry = self.transitions.entry(key).or_default();
            if entry.contains(&transition) {
                return Err(WaiterLinkError::Semantic("duplicate transition"));
            }
            entry.push(transition);
        }

        Ok(())
    }

    fn record_prepared(&mut self, attempt_id: &str) -> Result<(), WaiterLinkError> {
        if let Some(msg) = self.next_record_prepared_error.take() {
            return Err(WaiterLinkError::Semantic(Box::leak(msg.into_boxed_str())));
        }
        self.prepared_set.insert(attempt_id.to_owned(), true);
        Ok(())
    }

    fn has_concluded(&self, attempt_id: &str) -> Result<bool, WaiterLinkError> {
        Ok(self.concluded_set.contains_key(attempt_id))
    }

    fn record_concluded(&mut self, attempt_id: &str) -> Result<(), WaiterLinkError> {
        self.concluded_set.insert(attempt_id.to_owned(), true);
        Ok(())
    }

    fn persist_arm_state(&mut self, arm_id: &str, generation: u64) -> Result<(), WaiterLinkError> {
        // Replace existing entry if present, otherwise append.
        if let Some(existing) = self.arm_states.iter_mut().find(|(id, _)| id == arm_id) {
            existing.1 = generation;
        } else {
            self.arm_states.push((arm_id.to_owned(), generation));
        }
        Ok(())
    }

    fn persist_handled_cursor(
        &mut self,
        arm_id: &str,
        cursor: &str,
    ) -> Result<(), WaiterLinkError> {
        self.handled_cursors
            .insert(arm_id.to_owned(), cursor.to_owned());
        Ok(())
    }

    fn persist_rearmed(&mut self, arm_id: &str) -> Result<(), WaiterLinkError> {
        self.rearm_positions.insert(arm_id.to_owned(), true);
        Ok(())
    }

    fn record_reconciliation(
        &mut self,
        attempt_id: &str,
        signal_id: &str,
        state: ReconciliationState,
    ) -> Result<(), WaiterLinkError> {
        // Validate: ReconciliationResolved requires a prior ReconciliationRequired.
        let key = (signal_id.to_owned(), attempt_id.to_owned());
        let prior = self.transitions.get(&key);
        let has_required = prior.is_some_and(|ts| ts.contains(&Transition::ReconciliationRequired));
        if !has_required {
            return Err(WaiterLinkError::Semantic(
                "no prior ReconciliationRequired transition for this attempt",
            ));
        }
        // Record the resolution transition.
        match state {
            ReconciliationState::ProvenNotAccepted | ReconciliationState::Terminal => {
                // Resolved: record ReconciliationResolved transition.
                let entry = self.transitions.entry(key).or_default();
                entry.push(Transition::ReconciliationResolved);
            }
            ReconciliationState::Accepted => {
                // Accepted: record NativeAccepted (the dispatch was actually accepted).
                let entry = self.transitions.entry(key).or_default();
                entry.push(Transition::NativeAccepted);
                entry.push(Transition::ReconciliationResolved);
            }
            ReconciliationState::Unknown => {
                // Still unknown — do not resolve; this is not an error.
            }
        }
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
            arm_states: self.arm_states.clone(),
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

    #[test]
    fn first_claim_is_admitted() {
        let mut persist = FakePersist::default();
        let claim = sample_claim("01J00000000000000000000021", 1, "req-1");
        let record = persist.admit_claim(&claim).expect("admit");
        assert_eq!(record.outcome, ClaimOutcome::Admitted);
        assert_eq!(persist.claim_count(), 1);
    }

    #[test]
    fn exact_replay_is_idempotent() {
        let mut persist = FakePersist::default();
        let claim = sample_claim("01J00000000000000000000021", 1, "req-1");
        persist.admit_claim(&claim).expect("first");
        let record = persist.admit_claim(&claim).expect("replay");
        assert_eq!(record.outcome, ClaimOutcome::Replay);
    }

    #[test]
    fn later_time_replay_is_idempotent() {
        let mut persist = FakePersist::default();
        let claim = sample_claim("01J00000000000000000000021", 1, "req-1");
        persist.admit_claim(&claim).expect("first");
        let later = DurableClaim {
            claimed_at: datetime!(2026-01-15 13:00:00 UTC),
            ..claim.clone()
        };
        let record = persist.admit_claim(&later).expect("replay");
        assert_eq!(record.outcome, ClaimOutcome::Replay);
    }

    #[test]
    fn same_request_id_different_body_is_conflict() {
        let mut persist = FakePersist::default();
        let first = sample_claim("01J00000000000000000000021", 1, "req-1");
        persist.admit_claim(&first).expect("first");
        let mut second = first.clone();
        second.events[0].body = "different".to_owned();
        assert_eq!(persist.admit_claim(&second), Err(ClaimError::Conflict));
    }

    #[test]
    fn changed_metadata_is_not_exact_replay() {
        // Different provider/actor/observed_at with same body and request_id
        // should be detected as a conflict, not an exact replay.
        let mut persist = FakePersist::default();
        let first = sample_claim("01J00000000000000000000021", 1, "req-1");
        persist.admit_claim(&first).expect("first");
        let changed = sample_claim_different_metadata("01J00000000000000000000021", 1, "req-1");
        assert_eq!(persist.admit_claim(&changed), Err(ClaimError::Conflict));
    }

    #[test]
    fn different_request_id_same_signal_allows_new_claim() {
        let mut persist = FakePersist::default();
        let first = sample_claim("01J00000000000000000000021", 1, "req-1");
        persist.admit_claim(&first).expect("first");
        // Different request_id with same signal_id but different generation
        let second = sample_claim("01J00000000000000000000021", 2, "req-2");
        let record = persist.admit_claim(&second).expect("admit");
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
            persist.admit_claim(&claim),
            Err(ClaimError::StorageFailure(_))
        ));
        assert_eq!(persist.claim_count(), 0);
    }

    #[test]
    fn occupied_arm_generation_rejects_new_request() {
        let mut persist = FakePersist::default();
        persist
            .admit_claim(&sample_claim("01J00000000000000000000021", 1, "req-1"))
            .expect("first");
        assert_eq!(
            persist.admit_claim(&sample_claim("01J00000000000000000000022", 1, "req-2",)),
            Err(ClaimError::OccupiedDifferent)
        );
    }

    #[test]
    fn different_generation_allows_new_claim() {
        let mut persist = FakePersist::default();
        persist
            .admit_claim(&sample_claim("01J00000000000000000000021", 1, "req-1"))
            .expect("first");
        let record = persist
            .admit_claim(&sample_claim("01J00000000000000000000022", 2, "req-2"))
            .expect("admit");
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
        persist
            .admit_claim(&sample_claim("01J00000000000000000000021", 1, "req-1"))
            .expect("claim");
        persist
            .record_transition("sig-1", "attempt-1", Transition::ClaimRecorded)
            .expect("trans");
        persist
            .record_disposition(
                "attempt-1",
                &DispatchDisposition::Accepted {
                    correlation: "turn-X".to_owned(),
                },
            )
            .expect("disp");
        let snapshot = persist.recover().expect("recover");
        assert_eq!(snapshot.claims.len(), 1);
        assert!(snapshot.transitions.contains_key("sig-1:attempt-1"));
        assert!(snapshot.dispositions.contains_key("attempt-1"));
        assert_eq!(
            snapshot.dispositions.get("attempt-1"),
            Some(&DispatchDisposition::Accepted {
                correlation: "turn-X".to_owned(),
            })
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
    fn fake_identity_is_correct() {
        let persist = FakePersist::default();
        assert_eq!(persist.backend_identity(), "fake-deterministic");
        assert_eq!(persist.durability(), DurabilityClass::BestEffort);
    }
}
