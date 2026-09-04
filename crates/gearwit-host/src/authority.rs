//! Single-writer authority for one birth-bound managed controller.

#![allow(clippy::missing_errors_doc)]

use crate::controller::{
    ActiveObservationProof, ArmId, AttemptId, ClaimRequestId, ControllerAttachment,
    ControllerBirthBinding, ControllerBirthId, ControllerCommand, ControllerIdleGuard,
    ControllerProbeError, ControllerReconcileError, ControllerWriteError, IdleProbeObservation,
    IdleProbeResult, IdleProbeScope, ManagedCapability, NativeTurnFact, NativeWriteDisposition,
    ObservationScope, PersistedTurnCorrelation, ProbeBinding, ReconciliationDisposition,
    ReconciliationScope, RequestNonce, SeatId, SignalAction, SignalId, ValidatedIdlePermit,
    VerifierRef,
};
use crate::persist::{
    ActiveHoldCommit, ClaimAdmission, ClaimOutcome, IdempotentWrite, NativeTurnFactCommit,
    NativeWriteEvidence, NativeWriteEvidenceCommit, Persist, PersistError, PersistedArm,
    PersistedClaimRecord, PersistedControllerAttachment, PersistedControllerBirth,
    PreWriteConclusion, PreWriteConclusionCommit, PreparedDispatchCommit, RecoverySnapshot,
    ReserveBirthOutcome, ThreadCreateCommit, ThreadCreateReservation, ThreadCreateResolution,
    ThreadOwnershipState, ValidatedAttachmentScope,
};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const MAX_CLAIM_EVENTS: usize = 64;
const MAX_EVENT_BODY_BYTES: usize = 4_096;
const MAX_AGGREGATE_BODY_BYTES: usize = 131_072;
const MAX_EVENT_REF_BYTES: usize = 256;
const MAX_PROVIDER_BYTES: usize = 64;
const MAX_ACTOR_BYTES: usize = 256;
const MAX_TIMESTAMP_BYTES: usize = 64;
const IDLE_PERMIT_WINDOW: Duration = Duration::seconds(5);

/// Input for generation-fenced claim admission.
#[derive(Clone, Debug)]
pub struct ClaimRequest {
    pub arm_id: String,
    pub request_id: String,
    pub signal_id: String,
    pub events: Vec<gearwit_protocol::ProviderEvent>,
}

/// Explicit managed-controller registration. Waiter-link routes never
/// construct this authority product.
#[derive(Clone, Debug)]
pub struct ManagedArmRegistration {
    pub arm_id: String,
    pub generation: u64,
    pub seat_id: String,
    pub coverage_until: OffsetDateTime,
}

fn validate_claim_events(events: &[gearwit_protocol::ProviderEvent]) -> Result<(), AuthorityError> {
    if events.is_empty() || events.len() > MAX_CLAIM_EVENTS {
        return Err(AuthorityError::Conflict);
    }

    let mut aggregate_body_bytes = 0_usize;
    let mut event_refs = BTreeSet::new();
    let mut previous_observed_at = None;
    for event in events {
        if !is_bounded_token(&event.event_ref, MAX_EVENT_REF_BYTES)
            || !event_refs.insert(event.event_ref.as_str())
            || !is_bounded_token(&event.provider, MAX_PROVIDER_BYTES)
            || event
                .actor
                .as_ref()
                .is_some_and(|actor| !is_bounded_token(actor, MAX_ACTOR_BYTES))
            || event.observed_at.len() > MAX_TIMESTAMP_BYTES
            || event.body.len() > MAX_EVENT_BODY_BYTES
        {
            return Err(AuthorityError::InvalidIdentifier);
        }
        let observed_at = OffsetDateTime::parse(&event.observed_at, &Rfc3339)
            .map_err(|_| AuthorityError::InvalidIdentifier)?;
        if previous_observed_at.is_some_and(|previous| observed_at < previous) {
            return Err(AuthorityError::Conflict);
        }
        previous_observed_at = Some(observed_at);
        aggregate_body_bytes = aggregate_body_bytes
            .checked_add(event.body.len())
            .ok_or(AuthorityError::Conflict)?;
    }
    if aggregate_body_bytes > MAX_AGGREGATE_BODY_BYTES {
        return Err(AuthorityError::Conflict);
    }
    Ok(())
}

fn is_bounded_token(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
}

/// Non-Clone reservation proving controller birth and create were persisted.
#[derive(Debug)]
pub struct ControllerBirthReservation {
    binding: ControllerBirthBinding,
    create_attempt_id: RequestNonce,
}

pub struct QuarantinedBirthReservation {
    birth_id: ControllerBirthId,
    create_attempt_id: RequestNonce,
}

#[allow(dead_code)] // Consumed by the private native-adapter integration boundary.
pub enum CreateResolution {
    Final(IdempotentWrite),
    Unknown {
        write: IdempotentWrite,
        reservation: QuarantinedBirthReservation,
    },
}

impl ControllerBirthReservation {
    pub(crate) fn binding(&self) -> (&ControllerBirthBinding, &RequestNonce) {
        (&self.binding, &self.create_attempt_id)
    }
}

impl QuarantinedBirthReservation {
    pub(crate) fn binding(&self) -> (&ControllerBirthId, &RequestNonce) {
        (&self.birth_id, &self.create_attempt_id)
    }
}

/// Opaque receipt for a newly admitted claim.
#[derive(Debug)]
pub struct AdmissionReceipt {
    attempt_id: AttemptId,
}

impl AdmissionReceipt {
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        self.attempt_id.as_str()
    }
}

#[derive(Debug)]
pub struct AdmissionResult {
    pub outcome: ClaimOutcome,
    pub attempt_id: String,
    receipt: Option<AdmissionReceipt>,
}

impl AdmissionResult {
    #[must_use]
    pub fn into_receipt(self) -> Option<AdmissionReceipt> {
        self.receipt
    }
}

/// Opaque work retained across probe and native-write phases.
#[derive(Debug)]
pub struct PreparedDispatch {
    attachment: PersistedControllerAttachment,
    correlation: PersistedTurnCorrelation,
    expected_probe_id: RequestNonce,
}

/// Authorized write products. Neither guard nor command is Clone.
#[derive(Debug)]
pub struct AuthorizedNativeWrite {
    prepared: PreparedDispatch,
    pub lane: ControllerIdleGuard,
    pub command: ControllerCommand,
}

impl AuthorizedNativeWrite {
    pub(crate) fn into_parts(self) -> (PreparedDispatch, ControllerIdleGuard, ControllerCommand) {
        (self.prepared, self.lane, self.command)
    }
}

/// Result of validating an exact controller probe.
#[derive(Debug)]
pub enum ProbeAuthorization {
    Ready(Box<AuthorizedNativeWrite>),
    HeldBeforeNativeWrite,
    IdleStateUnproven,
}

#[derive(Debug)]
pub(crate) enum ReconciliationPhase {
    Reconciling,
    Observing(Box<ObservationScope>),
    Closed,
}

pub(crate) struct ExactObservationRecord {
    pub(crate) write: IdempotentWrite,
    pub(crate) reconciliation: Option<ReconciliationScope>,
}

/// Post-write authority result with only exact sealed follow-up scopes.
#[derive(Debug)]
pub struct NativeWriteConclusion {
    pub disposition: NativeWriteDisposition,
    observation_scope: Option<ObservationScope>,
    reconciliation_scope: Option<ReconciliationScope>,
}

impl NativeWriteConclusion {
    #[must_use]
    pub fn into_observation_scope(self) -> Option<ObservationScope> {
        self.observation_scope
    }

    #[must_use]
    pub fn into_reconciliation_scope(self) -> Option<ReconciliationScope> {
        self.reconciliation_scope
    }

    pub(crate) fn into_scopes(self) -> (Option<ObservationScope>, Option<ReconciliationScope>) {
        (self.observation_scope, self.reconciliation_scope)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityError {
    UnknownArm,
    NoOwnedController,
    Conflict,
    Unauthorized,
    Storage,
    InvalidIdentifier,
    Entropy,
    ControllerProbe(ControllerProbeError),
}

impl From<PersistError> for AuthorityError {
    fn from(error: PersistError) -> Self {
        match error {
            PersistError::Conflict | PersistError::InvalidTransition => Self::Conflict,
            PersistError::Unauthorized => Self::Unauthorized,
            PersistError::StorageUnavailable => Self::Storage,
        }
    }
}

/// Single-writer authority. The persistence backend is private and cannot be
/// borrowed mutably by production callers.
pub struct DaemonAuthority<P: Persist> {
    persist: P,
    arms: BTreeMap<ArmId, PersistedArm>,
    births: BTreeMap<ControllerBirthId, PersistedControllerBirth>,
    ownership: BTreeMap<ControllerBirthId, ThreadOwnershipState>,
    claims: BTreeMap<AttemptId, PersistedClaimRecord>,
    attachments: BTreeMap<AttemptId, PersistedControllerAttachment>,
    attempt_seq: u64,
    now: OffsetDateTime,
}

impl<P: Persist> DaemonAuthority<P> {
    #[must_use]
    pub fn new(persist: P, now: OffsetDateTime) -> Self {
        Self {
            persist,
            arms: BTreeMap::new(),
            births: BTreeMap::new(),
            ownership: BTreeMap::new(),
            claims: BTreeMap::new(),
            attachments: BTreeMap::new(),
            attempt_seq: 0,
            now,
        }
    }

    pub fn set_now(&mut self, now: OffsetDateTime) {
        self.now = now;
    }

    pub fn register_managed_arm(
        &mut self,
        arm: ManagedArmRegistration,
    ) -> Result<(), AuthorityError> {
        let record = PersistedArm {
            arm_id: ArmId::new(arm.arm_id).map_err(|_| AuthorityError::InvalidIdentifier)?,
            generation: arm.generation,
            seat_id: SeatId::new(arm.seat_id).map_err(|_| AuthorityError::InvalidIdentifier)?,
            capability: ManagedCapability::HandleClaimedSignal,
            coverage_until: arm.coverage_until,
        };
        self.persist.persist_arm(&record)?;
        self.arms.insert(record.arm_id.clone(), record);
        Ok(())
    }

    /// Atomically reserve a controller birth and its sole native create.
    pub fn reserve_controller_birth(
        &mut self,
        arm_id: &str,
    ) -> Result<ControllerBirthReservation, AuthorityError> {
        let arm_id = ArmId::new(arm_id).map_err(|_| AuthorityError::InvalidIdentifier)?;
        let arm = self.arms.get(&arm_id).ok_or(AuthorityError::UnknownArm)?;
        if arm.coverage_until <= self.now {
            return Err(AuthorityError::Unauthorized);
        }
        if self
            .births
            .values()
            .any(|birth| birth.arm_id == arm_id && birth.generation == arm.generation)
        {
            return Err(AuthorityError::Conflict);
        }
        let birth_id = ControllerBirthId::random().map_err(|_| AuthorityError::Entropy)?;
        let create_attempt_id = RequestNonce::random().map_err(|_| AuthorityError::Entropy)?;
        let verifier_ref = VerifierRef::random().map_err(|_| AuthorityError::Entropy)?;
        let birth = PersistedControllerBirth {
            birth_id: birth_id.clone(),
            seat_id: arm.seat_id.clone(),
            arm_id: arm.arm_id.clone(),
            generation: arm.generation,
            capability: arm.capability,
            lease_until: arm.coverage_until,
            verifier_ref: verifier_ref.clone(),
            created_at: self.now,
            revoked: false,
        };
        let create = ThreadCreateReservation {
            birth_id: birth_id.clone(),
            create_attempt_id: create_attempt_id.clone(),
            reserved_at: self.now,
        };
        match self.persist.reserve_controller_birth(&birth, &create)? {
            ReserveBirthOutcome::Reserved => {}
            ReserveBirthOutcome::ExactReplay | ReserveBirthOutcome::Conflict => {
                return Err(AuthorityError::Conflict);
            }
        }
        let binding = ControllerBirthBinding {
            birth_id: birth_id.clone(),
            seat_id: birth.seat_id.clone(),
            arm_id: birth.arm_id.clone(),
            generation: birth.generation,
            capability: birth.capability,
            lease_until: birth.lease_until,
            verifier_ref,
        };
        self.births.insert(birth_id.clone(), birth);
        self.ownership.insert(
            birth_id.clone(),
            ThreadOwnershipState::Reserved {
                create_attempt_id: create_attempt_id.clone(),
            },
        );
        Ok(ControllerBirthReservation {
            binding,
            create_attempt_id,
        })
    }

    /// Resolve only the exact reserved create. Unknown never causes a resend.
    pub(crate) fn resolve_thread_create(
        &mut self,
        reservation: ControllerBirthReservation,
        resolution: ThreadCreateResolution,
    ) -> Result<CreateResolution, AuthorityError> {
        let unknown = matches!(resolution, ThreadCreateResolution::Unknown);
        let evidence_ref = VerifierRef::random().map_err(|_| AuthorityError::Entropy)?;
        let result = self.persist.resolve_thread_create(ThreadCreateCommit {
            birth_id: reservation.binding.birth_id.clone(),
            create_attempt_id: reservation.create_attempt_id.clone(),
            resolution,
            evidence_ref,
        })?;
        let state = self
            .persist
            .thread_ownership_state(&reservation.binding.birth_id)?;
        self.ownership
            .insert(reservation.binding.birth_id.clone(), state);
        Ok(if unknown {
            CreateResolution::Unknown {
                write: result,
                reservation: QuarantinedBirthReservation {
                    birth_id: reservation.binding.birth_id,
                    create_attempt_id: reservation.create_attempt_id,
                },
            }
        } else {
            CreateResolution::Final(result)
        })
    }

    pub(crate) fn resolve_quarantined_thread_create(
        &mut self,
        reservation: QuarantinedBirthReservation,
        resolution: ThreadCreateResolution,
    ) -> Result<IdempotentWrite, AuthorityError> {
        if matches!(resolution, ThreadCreateResolution::Unknown) {
            return Err(AuthorityError::Conflict);
        }
        let evidence_ref = VerifierRef::random().map_err(|_| AuthorityError::Entropy)?;
        let result = self.persist.resolve_thread_create(ThreadCreateCommit {
            birth_id: reservation.birth_id.clone(),
            create_attempt_id: reservation.create_attempt_id,
            resolution,
            evidence_ref,
        })?;
        let state = self.persist.thread_ownership_state(&reservation.birth_id)?;
        self.ownership.insert(reservation.birth_id, state);
        Ok(result)
    }

    pub fn admit_claim(
        &mut self,
        request: &ClaimRequest,
    ) -> Result<AdmissionResult, AuthorityError> {
        validate_claim_events(&request.events)?;
        let arm_id =
            ArmId::new(request.arm_id.clone()).map_err(|_| AuthorityError::InvalidIdentifier)?;
        let arm = self.arms.get(&arm_id).ok_or(AuthorityError::UnknownArm)?;
        let (birth_id, _) = self
            .births
            .iter()
            .find(|(birth_id, birth)| {
                birth.arm_id == arm_id
                    && birth.generation == arm.generation
                    && !birth.revoked
                    && birth.lease_until > self.now
                    && matches!(
                        self.ownership.get(*birth_id),
                        Some(ThreadOwnershipState::Owned { .. })
                    )
            })
            .ok_or(AuthorityError::NoOwnedController)?;
        let request_id = ClaimRequestId::new(request.request_id.clone())
            .map_err(|_| AuthorityError::InvalidIdentifier)?;
        let signal_id = SignalId::new(request.signal_id.clone())
            .map_err(|_| AuthorityError::InvalidIdentifier)?;
        let attempt_seq = self
            .attempt_seq
            .checked_add(1)
            .ok_or(AuthorityError::Conflict)?;
        let attempt_id = AttemptId::new(format!("attempt-{attempt_seq}"))
            .map_err(|_| AuthorityError::InvalidIdentifier)?;
        let verifier_ref = VerifierRef::random().map_err(|_| AuthorityError::Entropy)?;
        let attachment = PersistedControllerAttachment {
            attempt_id: attempt_id.clone(),
            birth_id: birth_id.clone(),
            seat_id: arm.seat_id.clone(),
            arm_id: arm.arm_id.clone(),
            generation: arm.generation,
            capability: ManagedCapability::HandleClaimedSignal,
            lease_until: arm.coverage_until,
            verifier_ref,
            revoked: false,
        };
        let claim = PersistedClaimRecord {
            attempt_id: attempt_id.clone(),
            request_id,
            arm_id: arm.arm_id.clone(),
            generation: arm.generation,
            signal_id,
            event_refs: request
                .events
                .iter()
                .map(|event| event.event_ref.clone())
                .collect(),
            claimed_at: self.now,
        };
        let record = self.persist.admit_claim(
            &ClaimAdmission {
                record: claim.clone(),
                events: request.events.clone(),
            },
            &attachment,
        )?;
        if record.outcome == ClaimOutcome::ExactReplay {
            return Ok(AdmissionResult {
                outcome: record.outcome,
                attempt_id: record.attempt_id.as_str().to_owned(),
                receipt: None,
            });
        }
        self.attempt_seq = attempt_seq;
        self.claims.insert(attempt_id.clone(), claim);
        self.attachments.insert(attempt_id.clone(), attachment);
        Ok(AdmissionResult {
            outcome: ClaimOutcome::Admitted,
            attempt_id: attempt_id.as_str().to_owned(),
            receipt: Some(AdmissionReceipt { attempt_id }),
        })
    }

    /// Record dispatch preparation and return only the exact probe scope.
    pub fn prepare_handle_claimed_signal(
        &mut self,
        receipt: AdmissionReceipt,
    ) -> Result<(PreparedDispatch, IdleProbeScope), AuthorityError> {
        let claim = self
            .claims
            .get(&receipt.attempt_id)
            .ok_or(AuthorityError::Conflict)?;
        let attachment = self
            .attachments
            .get(&receipt.attempt_id)
            .ok_or(AuthorityError::Unauthorized)?;
        self.validate_attachment(attachment)?;
        let thread_ref = match self.ownership.get(&attachment.birth_id) {
            Some(ThreadOwnershipState::Owned { thread_ref, .. }) => thread_ref.clone(),
            _ => return Err(AuthorityError::NoOwnedController),
        };
        let correlation = PersistedTurnCorrelation {
            attempt_id: receipt.attempt_id,
            signal_id: claim.signal_id.clone(),
            birth_id: attachment.birth_id.clone(),
            thread_ref: thread_ref.clone(),
            turn_write_id: RequestNonce::random().map_err(|_| AuthorityError::Entropy)?,
            turn_ref: None,
        };
        self.persist
            .record_dispatch_prepared(PreparedDispatchCommit {
                correlation: correlation.clone(),
            })?;
        let expected_probe_id = RequestNonce::random().map_err(|_| AuthorityError::Entropy)?;
        let scope = IdleProbeScope {
            binding: ProbeBinding {
                attachment: ControllerAttachment {
                    attempt_id: attachment.attempt_id.clone(),
                    birth_id: attachment.birth_id.clone(),
                    arm_id: attachment.arm_id.clone(),
                    generation: attachment.generation,
                    seat_id: attachment.seat_id.clone(),
                    capability: attachment.capability,
                    lease_until: attachment.lease_until,
                    verifier_ref: attachment.verifier_ref.clone(),
                },
                signal_id: correlation.signal_id.clone(),
                thread_ref,
                challenge_id: expected_probe_id.clone(),
            },
        };
        Ok((
            PreparedDispatch {
                attachment: attachment.clone(),
                correlation,
                expected_probe_id,
            },
            scope,
        ))
    }

    /// Validate an exact probe. Active and unproven paths only record sealed
    /// zero-write conclusions and never construct a command.
    pub fn authorize_probe(
        &mut self,
        prepared: PreparedDispatch,
        result: Result<IdleProbeResult, ControllerProbeError>,
    ) -> Result<ProbeAuthorization, AuthorityError> {
        self.validate_attachment(&prepared.attachment)?;
        let result = result.map_err(AuthorityError::ControllerProbe)?;
        match result {
            IdleProbeResult::Active(proof) => {
                self.validate_active_proof(&prepared, &proof)?;
                self.persist
                    .record_active_hold(ActiveHoldCommit { proof })?;
                Ok(ProbeAuthorization::HeldBeforeNativeWrite)
            }
            IdleProbeResult::Unproven(IdleProbeObservation::Unproven {
                binding,
                probe_id,
                observed_at,
            }) => {
                self.validate_probe_binding(&prepared, &binding, &probe_id, observed_at)?;
                self.persist
                    .record_prewrite_conclusion(PreWriteConclusionCommit {
                        attempt_id: prepared.correlation.attempt_id,
                        signal_id: prepared.correlation.signal_id,
                        conclusion: PreWriteConclusion::IdleStateUnproven,
                        recorded_at: observed_at,
                    })?;
                Ok(ProbeAuthorization::IdleStateUnproven)
            }
            IdleProbeResult::Idle {
                observation:
                    IdleProbeObservation::Idle {
                        binding,
                        probe_id,
                        epoch,
                        observed_at,
                    },
                lane,
            } => {
                self.validate_probe_binding(&prepared, &binding, &probe_id, observed_at)?;
                if lane.probe_id != probe_id
                    || lane.epoch != epoch
                    || epoch.birth_id != prepared.correlation.birth_id
                {
                    return Err(AuthorityError::Unauthorized);
                }
                let permit = ValidatedIdlePermit {
                    attempt_id: prepared.correlation.attempt_id.clone(),
                    signal_id: prepared.correlation.signal_id.clone(),
                    birth_id: prepared.correlation.birth_id.clone(),
                    thread_ref: prepared.correlation.thread_ref.clone(),
                    arm_id: prepared.attachment.arm_id.clone(),
                    generation: prepared.attachment.generation,
                    capability: prepared.attachment.capability,
                    verifier_ref: prepared.attachment.verifier_ref.clone(),
                    mutation_epoch: epoch,
                    probe_id,
                    observed_at,
                    valid_until: (observed_at + IDLE_PERMIT_WINDOW)
                        .min(prepared.attachment.lease_until),
                };
                let reservation = self
                    .persist
                    .reserve_native_turn_write(permit, &prepared.correlation)?;
                let command = ControllerCommand::from_reservation(
                    ControllerAttachment {
                        attempt_id: prepared.attachment.attempt_id.clone(),
                        birth_id: prepared.attachment.birth_id.clone(),
                        arm_id: prepared.attachment.arm_id.clone(),
                        generation: prepared.attachment.generation,
                        seat_id: prepared.attachment.seat_id.clone(),
                        capability: prepared.attachment.capability,
                        lease_until: prepared.attachment.lease_until,
                        verifier_ref: prepared.attachment.verifier_ref.clone(),
                    },
                    SignalAction {
                        signal_id: prepared.correlation.signal_id.clone(),
                    },
                    reservation,
                );
                Ok(ProbeAuthorization::Ready(Box::new(AuthorizedNativeWrite {
                    prepared,
                    lane,
                    command,
                })))
            }
            _ => Err(AuthorityError::Unauthorized),
        }
    }

    /// Persist the classified native boundary. Epoch invalidation is a
    /// pre-write conclusion, not ambiguous native acceptance.
    pub fn conclude_native_write(
        &mut self,
        prepared: PreparedDispatch,
        disposition: Result<NativeWriteDisposition, ControllerWriteError>,
    ) -> Result<NativeWriteConclusion, AuthorityError> {
        let disposition = disposition.map_err(|_| AuthorityError::Unauthorized)?;
        if let NativeWriteDisposition::IdleEpochInvalidated {
            probe_id,
            expected_epoch,
            observed_epoch,
        } = &disposition
        {
            self.persist
                .record_prewrite_conclusion(PreWriteConclusionCommit {
                    attempt_id: prepared.correlation.attempt_id,
                    signal_id: prepared.correlation.signal_id,
                    conclusion: PreWriteConclusion::IdleEpochInvalidated {
                        probe_id: probe_id.clone(),
                        expected_epoch: expected_epoch.clone(),
                        observed_epoch: observed_epoch.clone(),
                    },
                    recorded_at: self.now,
                })?;
            return Ok(NativeWriteConclusion {
                disposition,
                observation_scope: None,
                reconciliation_scope: None,
            });
        }

        let evidence = match &disposition {
            NativeWriteDisposition::ProvenNotAccepted => NativeWriteEvidence::ProvenNotAccepted,
            NativeWriteDisposition::Accepted { .. } => NativeWriteEvidence::WriterAccepted {
                write_id: prepared.correlation.turn_write_id.clone(),
            },
            NativeWriteDisposition::ExactResponse(fact) => {
                NativeWriteEvidence::ExactResponse { fact: fact.clone() }
            }
            NativeWriteDisposition::Unknown => NativeWriteEvidence::Unknown,
            NativeWriteDisposition::IdleEpochInvalidated { .. } => unreachable!(),
        };
        let evidence_ref = VerifierRef::random().map_err(|_| AuthorityError::Entropy)?;
        self.persist
            .record_native_write_evidence(NativeWriteEvidenceCommit {
                correlation: prepared.correlation.clone(),
                evidence,
                evidence_ref: evidence_ref.clone(),
            })?;
        let mut correlation = prepared.correlation;
        match &disposition {
            NativeWriteDisposition::Accepted { turn_ref }
            | NativeWriteDisposition::ExactResponse(
                NativeTurnFact::Accepted { turn_ref }
                | NativeTurnFact::Started { turn_ref }
                | NativeTurnFact::Terminal { turn_ref, .. },
            ) => correlation.turn_ref = Some(turn_ref.clone()),
            NativeWriteDisposition::ProvenNotAccepted
            | NativeWriteDisposition::ExactResponse(
                NativeTurnFact::DegradedTerminalObservation
                | NativeTurnFact::ControllerLost
                | NativeTurnFact::Unknown,
            )
            | NativeWriteDisposition::Unknown
            | NativeWriteDisposition::IdleEpochInvalidated { .. } => {}
        }
        let immediate_fact = match &disposition {
            NativeWriteDisposition::Accepted { turn_ref } => Some(NativeTurnFact::Accepted {
                turn_ref: turn_ref.clone(),
            }),
            NativeWriteDisposition::ExactResponse(fact) => Some(fact.clone()),
            NativeWriteDisposition::ProvenNotAccepted
            | NativeWriteDisposition::Unknown
            | NativeWriteDisposition::IdleEpochInvalidated { .. } => None,
        };
        if let Some(fact) = immediate_fact {
            self.persist.record_native_turn_fact(NativeTurnFactCommit {
                correlation: correlation.clone(),
                fact,
                evidence_ref: VerifierRef::random().map_err(|_| AuthorityError::Entropy)?,
            })?;
        }
        let observation_scope = matches!(
            disposition,
            NativeWriteDisposition::Accepted { .. } | NativeWriteDisposition::ExactResponse(_)
        )
        .then(|| ObservationScope {
            correlation: correlation.clone(),
            evidence_ref: evidence_ref.clone(),
        });
        let reconciliation_scope =
            matches!(disposition, NativeWriteDisposition::Unknown).then(|| ReconciliationScope {
                correlation,
                evidence_ref,
            });
        Ok(NativeWriteConclusion {
            disposition,
            observation_scope,
            reconciliation_scope,
        })
    }

    pub(crate) fn record_exact_observation(
        &mut self,
        scope: &ObservationScope,
        fact: NativeTurnFact,
    ) -> Result<ExactObservationRecord, AuthorityError> {
        let degraded = matches!(
            fact,
            NativeTurnFact::DegradedTerminalObservation
                | NativeTurnFact::ControllerLost
                | NativeTurnFact::Unknown
        );
        let evidence_ref = VerifierRef::random().map_err(|_| AuthorityError::Entropy)?;
        let write = self.persist.record_native_turn_fact(NativeTurnFactCommit {
            correlation: scope.correlation.clone(),
            fact,
            evidence_ref,
        })?;
        Ok(ExactObservationRecord {
            write,
            reconciliation: degraded.then(|| ReconciliationScope {
                correlation: scope.correlation.clone(),
                evidence_ref: scope.evidence_ref.clone(),
            }),
        })
    }

    pub(crate) fn record_reconciliation(
        &mut self,
        scope: &ReconciliationScope,
        disposition: Result<ReconciliationDisposition, ControllerReconcileError>,
    ) -> Result<(IdempotentWrite, ReconciliationPhase), AuthorityError> {
        let disposition = disposition.map_err(|_| AuthorityError::Unauthorized)?;
        let result = self
            .persist
            .record_reconciliation_fact(scope, &disposition)?;
        let phase = match &disposition {
            ReconciliationDisposition::Unknown => ReconciliationPhase::Reconciling,
            ReconciliationDisposition::ProvenNotAccepted => ReconciliationPhase::Closed,
            ReconciliationDisposition::Accepted { turn_ref } => {
                let mut correlation = scope.correlation.clone();
                correlation.turn_ref = Some(turn_ref.clone());
                self.persist.record_native_turn_fact(NativeTurnFactCommit {
                    correlation: correlation.clone(),
                    fact: NativeTurnFact::Accepted {
                        turn_ref: turn_ref.clone(),
                    },
                    evidence_ref: VerifierRef::random().map_err(|_| AuthorityError::Entropy)?,
                })?;
                ReconciliationPhase::Observing(Box::new(ObservationScope {
                    correlation,
                    evidence_ref: scope.evidence_ref.clone(),
                }))
            }
            ReconciliationDisposition::Terminal { turn_ref, class } => {
                let mut correlation = scope.correlation.clone();
                correlation.turn_ref = Some(turn_ref.clone());
                self.persist.record_native_turn_fact(NativeTurnFactCommit {
                    correlation,
                    fact: NativeTurnFact::Terminal {
                        turn_ref: turn_ref.clone(),
                        class: *class,
                    },
                    evidence_ref: VerifierRef::random().map_err(|_| AuthorityError::Entropy)?,
                })?;
                ReconciliationPhase::Closed
            }
        };
        Ok((result, phase))
    }

    pub fn revoke_attachment(
        &mut self,
        attempt_id: &str,
    ) -> Result<IdempotentWrite, AuthorityError> {
        let attachment = self
            .attachments
            .iter_mut()
            .find(|(id, _)| id.as_str() == attempt_id)
            .map(|(_, attachment)| attachment)
            .ok_or(AuthorityError::Unauthorized)?;
        let result = self
            .persist
            .revoke_controller_attachment(ValidatedAttachmentScope {
                attempt_id: attachment.attempt_id.clone(),
                birth_id: attachment.birth_id.clone(),
                arm_id: attachment.arm_id.clone(),
                generation: attachment.generation,
                verifier_ref: attachment.verifier_ref.clone(),
            })?;
        attachment.revoked = true;
        Ok(result)
    }

    /// Recover authority metadata only. No reservation is converted back into
    /// a permit, guard, command, or caller-held receipt.
    pub fn recover(&mut self) -> Result<AuthorityRecovery, AuthorityError> {
        let snapshot = self.persist.recover_authority_state()?;
        let (observation_scopes, reconciliation_scopes) = recovery_followup_scopes(&snapshot)?;
        let births: BTreeMap<_, _> = snapshot
            .controller_births
            .iter()
            .map(|birth| (birth.birth_id.clone(), birth.clone()))
            .collect();
        if births.len() != snapshot.controller_births.len() {
            return Err(AuthorityError::Conflict);
        }
        let ownership: BTreeMap<_, _> = snapshot
            .ownership
            .iter()
            .map(|record| (record.birth_id.clone(), record.state.clone()))
            .collect();
        if ownership.len() != snapshot.ownership.len()
            || ownership
                .keys()
                .any(|birth_id| !births.contains_key(birth_id))
        {
            return Err(AuthorityError::Conflict);
        }
        self.arms = snapshot
            .arms
            .iter()
            .map(|arm| (arm.arm_id.clone(), arm.clone()))
            .collect();
        self.births = births;
        self.ownership = ownership;
        self.claims = snapshot
            .claims
            .iter()
            .map(|claim| (claim.attempt_id.clone(), claim.clone()))
            .collect();
        self.attachments = snapshot
            .attachments
            .iter()
            .map(|attachment| (attachment.attempt_id.clone(), attachment.clone()))
            .collect();
        self.attempt_seq = snapshot.attempt_seq;
        Ok(AuthorityRecovery {
            snapshot,
            observation_scopes,
            reconciliation_scopes,
        })
    }

    fn validate_probe_binding(
        &self,
        prepared: &PreparedDispatch,
        binding: &ProbeBinding,
        probe_id: &RequestNonce,
        observed_at: OffsetDateTime,
    ) -> Result<(), AuthorityError> {
        if binding.attachment.attempt_id != prepared.correlation.attempt_id
            || binding.signal_id != prepared.correlation.signal_id
            || binding.attachment.birth_id != prepared.correlation.birth_id
            || binding.thread_ref != prepared.correlation.thread_ref
            || binding.challenge_id != prepared.expected_probe_id
            || probe_id != &prepared.expected_probe_id
            || binding.attachment.arm_id != prepared.attachment.arm_id
            || binding.attachment.generation != prepared.attachment.generation
            || binding.attachment.seat_id != prepared.attachment.seat_id
            || binding.attachment.capability != prepared.attachment.capability
            || binding.attachment.lease_until != prepared.attachment.lease_until
            || binding.attachment.verifier_ref != prepared.attachment.verifier_ref
            || observed_at > self.now
            || self.now - observed_at >= IDLE_PERMIT_WINDOW
        {
            return Err(AuthorityError::Unauthorized);
        }
        Ok(())
    }

    fn validate_active_proof(
        &self,
        prepared: &PreparedDispatch,
        proof: &ActiveObservationProof,
    ) -> Result<(), AuthorityError> {
        // Epoch sequence is evidence from the sealed controller TCB; durable
        // active replay binds it into the keyed fingerprint.
        let owned = self
            .ownership
            .get(&proof.birth_id)
            .ok_or(AuthorityError::Unauthorized)?;
        if proof.attempt_id != prepared.correlation.attempt_id
            || proof.signal_id != prepared.correlation.signal_id
            || proof.birth_id != prepared.correlation.birth_id
            || proof.thread_ref != prepared.correlation.thread_ref
            || proof.probe_id != prepared.expected_probe_id
            || proof.seat_id != prepared.attachment.seat_id
            || proof.arm_id != prepared.attachment.arm_id
            || proof.generation != prepared.attachment.generation
            || proof.capability != prepared.attachment.capability
            || proof.attachment_verifier_ref != prepared.attachment.verifier_ref
            || proof.lease_until != prepared.attachment.lease_until
            || proof.mutation_epoch.birth_id != proof.birth_id
            || proof.observed_at > self.now
            || self.now - proof.observed_at >= IDLE_PERMIT_WINDOW
            || proof.lease_until <= self.now
            || proof.producer_version != "codex-cli 0.152.1"
            || proof.producer_dialect != "thread/read-v2"
            || !matches!(
                owned,
                ThreadOwnershipState::Owned {
                    create_attempt_id,
                    thread_ref,
                } if create_attempt_id == &proof.create_attempt_id && thread_ref == &proof.thread_ref
            )
        {
            return Err(AuthorityError::Unauthorized);
        }
        Ok(())
    }

    fn validate_attachment(
        &self,
        attachment: &PersistedControllerAttachment,
    ) -> Result<(), AuthorityError> {
        let current = self
            .attachments
            .get(&attachment.attempt_id)
            .ok_or(AuthorityError::Unauthorized)?;
        let birth = self
            .births
            .get(&attachment.birth_id)
            .ok_or(AuthorityError::Unauthorized)?;
        let arm = self
            .arms
            .get(&attachment.arm_id)
            .ok_or(AuthorityError::UnknownArm)?;
        if current != attachment
            || current.revoked
            || attachment.revoked
            || birth.revoked
            || attachment.lease_until <= self.now
            || birth.lease_until <= self.now
            || attachment.seat_id != birth.seat_id
            || attachment.arm_id != birth.arm_id
            || attachment.generation != birth.generation
            || attachment.generation != arm.generation
            || attachment.capability != ManagedCapability::HandleClaimedSignal
        {
            return Err(AuthorityError::Unauthorized);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn inspect_persist(&self) -> &P {
        &self.persist
    }

    #[cfg(test)]
    pub(crate) fn attachment_verifier(&self, attempt_id: &str) -> Option<&VerifierRef> {
        self.attachments
            .iter()
            .find(|(id, _)| id.as_str() == attempt_id)
            .map(|(_, attachment)| &attachment.verifier_ref)
    }
}

fn recovery_followup_scopes(
    snapshot: &RecoverySnapshot,
) -> Result<(Vec<ObservationScope>, Vec<ReconciliationScope>), AuthorityError> {
    let reconciliations: BTreeMap<_, _> = snapshot
        .reconciliations
        .iter()
        .map(|record| (record.attempt_id.clone(), record.disposition.clone()))
        .collect();
    let turn_facts: BTreeMap<_, _> = snapshot
        .native_turn_facts
        .iter()
        .map(|record| (record.attempt_id.clone(), record.facts.as_slice()))
        .collect();
    if reconciliations.len() != snapshot.reconciliations.len()
        || turn_facts.len() != snapshot.native_turn_facts.len()
    {
        return Err(AuthorityError::Conflict);
    }

    let mut observing = Vec::new();
    let mut reconciling = Vec::new();
    for record in &snapshot.native_write_evidence {
        let facts = turn_facts
            .get(&record.correlation.attempt_id)
            .copied()
            .unwrap_or_default();
        if facts
            .iter()
            .any(|fact| matches!(fact, NativeTurnFact::Terminal { .. }))
        {
            continue;
        }
        match &record.evidence {
            NativeWriteEvidence::Unknown => {
                match reconciliations.get(&record.correlation.attempt_id) {
                    None | Some(ReconciliationDisposition::Unknown) => {
                        reconciling.push(ReconciliationScope {
                            correlation: record.correlation.clone(),
                            evidence_ref: record.evidence_ref.clone(),
                        });
                    }
                    Some(ReconciliationDisposition::Accepted { turn_ref }) => {
                        let mut correlation = record.correlation.clone();
                        correlation.turn_ref = Some(turn_ref.clone());
                        observing.push(ObservationScope {
                            correlation,
                            evidence_ref: record.evidence_ref.clone(),
                        });
                    }
                    Some(
                        ReconciliationDisposition::Terminal { .. }
                        | ReconciliationDisposition::ProvenNotAccepted,
                    ) => {}
                }
            }
            NativeWriteEvidence::WriterAccepted { .. }
            | NativeWriteEvidence::ExactResponse { .. } => {
                let turn_ref = facts.iter().find_map(|fact| match fact {
                    NativeTurnFact::Accepted { turn_ref }
                    | NativeTurnFact::Started { turn_ref } => Some(turn_ref.clone()),
                    NativeTurnFact::Terminal { .. }
                    | NativeTurnFact::DegradedTerminalObservation
                    | NativeTurnFact::ControllerLost
                    | NativeTurnFact::Unknown => None,
                });
                if let Some(turn_ref) = turn_ref {
                    let mut correlation = record.correlation.clone();
                    correlation.turn_ref = Some(turn_ref);
                    observing.push(ObservationScope {
                        correlation,
                        evidence_ref: record.evidence_ref.clone(),
                    });
                }
            }
            NativeWriteEvidence::ProvenNotAccepted => {}
        }
    }
    Ok((observing, reconciling))
}

#[derive(Debug)]
pub struct AuthorityRecovery {
    pub snapshot: RecoverySnapshot,
    observation_scopes: Vec<ObservationScope>,
    reconciliation_scopes: Vec<ReconciliationScope>,
}

impl AuthorityRecovery {
    #[must_use]
    pub(crate) fn into_followup_scopes(self) -> (Vec<ObservationScope>, Vec<ReconciliationScope>) {
        (self.observation_scopes, self.reconciliation_scopes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::{
        Controller, FakeController, FakeIdleState, PrivateNativeRef, SecretNativeCoordinate,
    };
    use crate::persist::FakePersist;

    fn now() -> OffsetDateTime {
        time::macros::datetime!(2026-01-15 12:00:00 UTC)
    }

    fn arm() -> ManagedArmRegistration {
        ManagedArmRegistration {
            arm_id: "arm-a".to_owned(),
            generation: 1,
            seat_id: "seat-a".to_owned(),
            coverage_until: now() + Duration::hours(1),
        }
    }

    fn event() -> gearwit_protocol::ProviderEvent {
        gearwit_protocol::ProviderEvent {
            provider: "example".to_owned(),
            event_ref: "event-a".to_owned(),
            actor: None,
            observed_at: "2026-01-15T12:00:00Z".to_owned(),
            body: "untrusted data".to_owned(),
        }
    }

    fn ready() -> DaemonAuthority<FakePersist> {
        ready_with(FakePersist::default())
    }

    fn ready_with(persist: FakePersist) -> DaemonAuthority<FakePersist> {
        let mut authority = DaemonAuthority::new(persist, now());
        authority.register_managed_arm(arm()).expect("arm");
        let reservation = authority.reserve_controller_birth("arm-a").expect("birth");
        authority
            .resolve_thread_create(
                reservation,
                ThreadCreateResolution::Owned {
                    thread_ref: PrivateNativeRef::fixture(7),
                },
            )
            .expect("owned");
        authority
    }

    fn prepare(authority: &mut DaemonAuthority<FakePersist>) -> (PreparedDispatch, IdleProbeScope) {
        let admission = authority
            .admit_claim(&ClaimRequest {
                arm_id: "arm-a".to_owned(),
                request_id: "claim-a".to_owned(),
                signal_id: "signal-a".to_owned(),
                events: vec![event()],
            })
            .expect("admit");
        authority
            .prepare_handle_claimed_signal(admission.into_receipt().expect("receipt"))
            .expect("prepare")
    }

    fn reserved_disposition(
        authority: &mut DaemonAuthority<FakePersist>,
        disposition: NativeWriteDisposition,
    ) -> (PreparedDispatch, NativeWriteDisposition) {
        let (prepared, scope) = prepare(authority);
        let mut controller =
            FakeController::new(vec![FakeIdleState::Idle(1)], vec![disposition]).with_now(now());
        let probe = controller.probe_idle(scope);
        let ProbeAuthorization::Ready(authorized) = authority
            .authorize_probe(prepared, probe)
            .expect("authorize")
        else {
            panic!("ready");
        };
        let (prepared, lane, command) = (*authorized).into_parts();
        let turn_scope = command.turn_scope();
        let disposition = controller
            .write_reserved_turn(lane, command)
            .expect("controller write");
        let mut sealed_turn = || {
            authority
                .persist
                .seal_native_coordinate(
                    &turn_scope,
                    &SecretNativeCoordinate::turn("authority-test-turn").expect("turn"),
                )
                .expect("seal accepted turn")
        };
        let disposition = match disposition {
            NativeWriteDisposition::Accepted { .. } => NativeWriteDisposition::Accepted {
                turn_ref: sealed_turn(),
            },
            NativeWriteDisposition::ExactResponse(NativeTurnFact::Accepted { .. }) => {
                NativeWriteDisposition::ExactResponse(NativeTurnFact::Accepted {
                    turn_ref: sealed_turn(),
                })
            }
            NativeWriteDisposition::ExactResponse(NativeTurnFact::Started { .. }) => {
                NativeWriteDisposition::ExactResponse(NativeTurnFact::Started {
                    turn_ref: sealed_turn(),
                })
            }
            NativeWriteDisposition::ExactResponse(NativeTurnFact::Terminal { class, .. }) => {
                NativeWriteDisposition::ExactResponse(NativeTurnFact::Terminal {
                    turn_ref: sealed_turn(),
                    class,
                })
            }
            disposition => disposition,
        };
        (prepared, disposition)
    }

    #[test]
    fn active_and_unproven_are_zero_write_and_claim_preserving() {
        for state in [FakeIdleState::Active, FakeIdleState::Unproven] {
            let mut authority = ready();
            let (prepared, scope) = prepare(&mut authority);
            let create_attempt_id = authority
                .ownership
                .values()
                .find_map(|ownership| match ownership {
                    ThreadOwnershipState::Owned {
                        create_attempt_id, ..
                    } => Some(create_attempt_id.clone()),
                    _ => None,
                })
                .expect("owned create");
            let mut controller = FakeController::new(vec![state], vec![])
                .with_now(now())
                .with_create_attempt_id(create_attempt_id);
            let result = controller.probe_idle(scope);
            let authorization = authority.authorize_probe(prepared, result).expect("record");
            assert!(matches!(
                authorization,
                ProbeAuthorization::HeldBeforeNativeWrite | ProbeAuthorization::IdleStateUnproven
            ));
            assert_eq!(controller.native_bytes(), 0);
            assert!(
                authority
                    .inspect_persist()
                    .prewrite_conclusion("attempt-1")
                    .is_some()
            );
        }
    }

    #[test]
    fn invalid_active_proof_records_no_conclusion() {
        let mut authority = ready();
        let (prepared, scope) = prepare(&mut authority);
        let create_attempt_id = authority
            .ownership
            .values()
            .find_map(|ownership| match ownership {
                ThreadOwnershipState::Owned {
                    create_attempt_id, ..
                } => Some(create_attempt_id.clone()),
                _ => None,
            })
            .expect("owned create");
        let mut controller = FakeController::new(vec![FakeIdleState::Active], vec![])
            .with_now(now())
            .with_create_attempt_id(create_attempt_id);
        let Ok(IdleProbeResult::Active(mut proof)) = controller.probe_idle(scope) else {
            panic!("active proof");
        };
        proof.producer_dialect = "unqualified-dialect".to_owned();
        assert_eq!(
            authority
                .authorize_probe(prepared, Ok(IdleProbeResult::Active(proof)))
                .expect_err("invalid proof"),
            AuthorityError::Unauthorized
        );
        assert!(
            authority
                .inspect_persist()
                .prewrite_conclusion("attempt-1")
                .is_none()
        );
        assert_eq!(controller.native_bytes(), 0);
    }

    #[test]
    fn active_evidence_storage_failure_records_no_conclusion() {
        let mut persist = FakePersist::default();
        persist.fail_next_active_hold();
        let mut authority = ready_with(persist);
        let (prepared, scope) = prepare(&mut authority);
        let create_attempt_id = authority
            .ownership
            .values()
            .find_map(|ownership| match ownership {
                ThreadOwnershipState::Owned {
                    create_attempt_id, ..
                } => Some(create_attempt_id.clone()),
                _ => None,
            })
            .expect("owned create");
        let mut controller = FakeController::new(vec![FakeIdleState::Active], vec![])
            .with_now(now())
            .with_create_attempt_id(create_attempt_id);
        let proof = controller.probe_idle(scope);
        assert_eq!(
            authority
                .authorize_probe(prepared, proof)
                .expect_err("storage failure"),
            AuthorityError::Storage
        );
        assert!(
            authority
                .inspect_persist()
                .prewrite_conclusion("attempt-1")
                .is_none()
        );
        assert_eq!(controller.native_bytes(), 0);
    }

    fn active_fixture() -> (
        DaemonAuthority<FakePersist>,
        PreparedDispatch,
        ActiveObservationProof,
    ) {
        let mut authority = ready();
        let (prepared, scope) = prepare(&mut authority);
        let create_attempt_id = authority
            .ownership
            .values()
            .find_map(|ownership| match ownership {
                ThreadOwnershipState::Owned {
                    create_attempt_id, ..
                } => Some(create_attempt_id.clone()),
                _ => None,
            })
            .expect("owned create");
        let mut controller = FakeController::new(vec![FakeIdleState::Active], vec![])
            .with_now(now())
            .with_create_attempt_id(create_attempt_id);
        let Ok(IdleProbeResult::Active(proof)) = controller.probe_idle(scope) else {
            panic!("active proof");
        };
        (authority, prepared, proof)
    }

    #[test]
    fn active_proof_field_substitutions_fail_without_conclusion() {
        for field in 0..14 {
            let (mut authority, prepared, mut proof) = active_fixture();
            match field {
                0 => proof.birth_id = ControllerBirthId::fixture(90),
                1 => proof.create_attempt_id = RequestNonce::fixture(90),
                2 => proof.thread_ref = PrivateNativeRef::fixture(90),
                3 => proof.attempt_id = AttemptId::new("attempt-other").expect("attempt"),
                4 => proof.signal_id = SignalId::new("signal-other").expect("signal"),
                5 => proof.probe_id = RequestNonce::fixture(90),
                6 => proof.mutation_epoch.birth_id = ControllerBirthId::fixture(90),
                7 => proof.producer_version = "codex-cli 0.152.2".to_owned(),
                8 => proof.producer_dialect = "thread/read-v3".to_owned(),
                9 => proof.seat_id = SeatId::new("seat-other").expect("seat"),
                10 => proof.arm_id = ArmId::new("arm-other").expect("arm"),
                11 => proof.generation = 2,
                12 => proof.attachment_verifier_ref = VerifierRef::fixture(90),
                13 => proof.lease_until = now() + Duration::minutes(30),
                _ => unreachable!(),
            }
            assert_eq!(
                authority
                    .authorize_probe(prepared, Ok(IdleProbeResult::Active(proof)))
                    .expect_err("substituted proof"),
                AuthorityError::Unauthorized
            );
            assert!(
                authority
                    .inspect_persist()
                    .prewrite_conclusion("attempt-1")
                    .is_none()
            );
        }
    }

    #[test]
    fn current_attachment_revocation_and_expiry_fence_idle_and_unproven() {
        for state in [FakeIdleState::Idle(1), FakeIdleState::Unproven] {
            let mut authority = ready();
            let (prepared, scope) = prepare(&mut authority);
            let attempt_id = prepared.correlation.attempt_id.as_str().to_owned();
            let mut controller = FakeController::new(vec![state], vec![]).with_now(now());
            let probe = controller.probe_idle(scope);
            authority
                .revoke_attachment(&attempt_id)
                .expect("revoke current attachment");
            assert_eq!(
                authority
                    .authorize_probe(prepared, probe)
                    .expect_err("revoked binding"),
                AuthorityError::Unauthorized
            );
            assert!(
                authority
                    .inspect_persist()
                    .prewrite_conclusion("attempt-1")
                    .is_none()
            );
        }
        for state in [FakeIdleState::Idle(1), FakeIdleState::Unproven] {
            let mut authority = ready();
            let (prepared, scope) = prepare(&mut authority);
            let mut controller = FakeController::new(vec![state], vec![]).with_now(now());
            let probe = controller.probe_idle(scope);
            authority.set_now(now() + Duration::hours(2));
            assert_eq!(
                authority
                    .authorize_probe(prepared, probe)
                    .expect_err("expired binding"),
                AuthorityError::Unauthorized
            );
            assert!(
                authority
                    .inspect_persist()
                    .prewrite_conclusion("attempt-1")
                    .is_none()
            );
        }
        let (mut authority, prepared, proof) = active_fixture();
        authority
            .revoke_attachment(prepared.correlation.attempt_id.as_str())
            .expect("revoke active attachment");
        assert_eq!(
            authority
                .authorize_probe(prepared, Ok(IdleProbeResult::Active(proof)))
                .expect_err("revoked active binding"),
            AuthorityError::Unauthorized
        );

        let (mut authority, prepared, proof) = active_fixture();
        authority.set_now(now() + Duration::hours(2));
        assert_eq!(
            authority
                .authorize_probe(prepared, Ok(IdleProbeResult::Active(proof)))
                .expect_err("expired active binding"),
            AuthorityError::Unauthorized
        );
    }

    #[test]
    fn controller_probe_rejection_cannot_be_persisted_as_unproven() {
        let mut authority = ready();
        let (prepared, _scope) = prepare(&mut authority);
        assert_eq!(
            authority
                .authorize_probe(prepared, Err(ControllerProbeError::BindingRejected))
                .expect_err("controller rejected binding"),
            AuthorityError::ControllerProbe(ControllerProbeError::BindingRejected)
        );
        assert!(
            authority
                .inspect_persist()
                .prewrite_conclusion("attempt-1")
                .is_none()
        );
    }

    #[test]
    fn intervening_epoch_invalidates_without_native_bytes() {
        let mut authority = ready();
        let (prepared, scope) = prepare(&mut authority);
        let mut controller =
            FakeController::new(vec![FakeIdleState::Idle(3)], vec![]).with_now(now());
        let probe = controller.probe_idle(scope);
        let ProbeAuthorization::Ready(authorized) = authority
            .authorize_probe(prepared, probe)
            .expect("authorize")
        else {
            panic!("ready");
        };
        controller.invalidate_epoch();
        let AuthorizedNativeWrite {
            prepared,
            lane,
            command,
        } = *authorized;
        let disposition = controller
            .write_reserved_turn(lane, command)
            .expect("controller write");
        assert!(matches!(
            disposition,
            NativeWriteDisposition::IdleEpochInvalidated { .. }
        ));
        authority
            .conclude_native_write(prepared, Ok(disposition.clone()))
            .expect("conclude");
        authority
            .persist
            .record_prewrite_conclusion(PreWriteConclusionCommit {
                attempt_id: AttemptId::new("attempt-1").expect("attempt"),
                signal_id: SignalId::new("signal-a").expect("signal"),
                conclusion: match disposition {
                    NativeWriteDisposition::IdleEpochInvalidated {
                        probe_id,
                        expected_epoch,
                        observed_epoch,
                    } => PreWriteConclusion::IdleEpochInvalidated {
                        probe_id,
                        expected_epoch,
                        observed_epoch,
                    },
                    _ => unreachable!(),
                },
                recorded_at: now(),
            })
            .expect("idempotent replay");
        assert_eq!(controller.native_bytes(), 0);
        assert!(
            authority
                .inspect_persist()
                .reservation_concluded("attempt-1")
        );
    }

    #[test]
    fn stale_probe_cannot_mint_a_reservation() {
        let mut authority = ready();
        let (prepared, scope) = prepare(&mut authority);
        let mut controller =
            FakeController::new(vec![FakeIdleState::Idle(1)], vec![]).with_now(now());
        let probe = controller.probe_idle(scope);
        authority.set_now(now() + IDLE_PERMIT_WINDOW);
        assert_eq!(
            authority
                .authorize_probe(prepared, probe)
                .expect_err("stale"),
            AuthorityError::Unauthorized
        );
        assert_eq!(controller.native_bytes(), 0);
    }

    #[test]
    fn cross_attempt_probe_binding_is_rejected() {
        let mut authority = ready();
        let (prepared, _) = prepare(&mut authority);
        let epoch = crate::controller::NativeMutationEpoch {
            birth_id: prepared.correlation.birth_id.clone(),
            sequence: 1,
        };
        let probe_id = prepared.expected_probe_id.clone();
        let result = IdleProbeResult::Idle {
            observation: IdleProbeObservation::Idle {
                binding: ProbeBinding {
                    attachment: ControllerAttachment {
                        attempt_id: AttemptId::new("attempt-other").expect("attempt"),
                        birth_id: prepared.attachment.birth_id.clone(),
                        arm_id: prepared.attachment.arm_id.clone(),
                        generation: prepared.attachment.generation,
                        seat_id: prepared.attachment.seat_id.clone(),
                        capability: prepared.attachment.capability,
                        lease_until: prepared.attachment.lease_until,
                        verifier_ref: prepared.attachment.verifier_ref.clone(),
                    },
                    signal_id: prepared.correlation.signal_id.clone(),
                    thread_ref: prepared.correlation.thread_ref.clone(),
                    challenge_id: probe_id.clone(),
                },
                probe_id: probe_id.clone(),
                epoch: epoch.clone(),
                observed_at: now(),
            },
            lane: ControllerIdleGuard { probe_id, epoch },
        };
        assert_eq!(
            authority
                .authorize_probe(prepared, Ok(result))
                .expect_err("cross-attempt probe"),
            AuthorityError::Unauthorized
        );
    }

    #[test]
    fn claim_payload_bounds_fail_before_admission() {
        let mut authority = ready();
        let request = |events| ClaimRequest {
            arm_id: "arm-a".to_owned(),
            request_id: "claim-a".to_owned(),
            signal_id: "signal-a".to_owned(),
            events,
        };

        assert_eq!(
            authority
                .admit_claim(&request(vec![event(); MAX_CLAIM_EVENTS + 1]))
                .expect_err("event count"),
            AuthorityError::Conflict
        );

        let mut oversized = event();
        oversized.body = "x".repeat(MAX_EVENT_BODY_BYTES + 1);
        assert_eq!(
            authority
                .admit_claim(&request(vec![oversized]))
                .expect_err("body bound"),
            AuthorityError::InvalidIdentifier
        );

        assert_eq!(
            authority
                .admit_claim(&request(vec![event(), event()]))
                .expect_err("duplicate event ref"),
            AuthorityError::InvalidIdentifier
        );

        let aggregate = (0..33)
            .map(|index| {
                let mut item = event();
                item.event_ref = format!("event-{index}");
                item.body = "x".repeat(MAX_EVENT_BODY_BYTES);
                item
            })
            .collect();
        assert_eq!(
            authority
                .admit_claim(&request(aggregate))
                .expect_err("aggregate bound"),
            AuthorityError::Conflict
        );

        let mut older = event();
        older.event_ref = "event-b".to_owned();
        older.observed_at = "2026-01-15T11:59:59Z".to_owned();
        assert_eq!(
            authority
                .admit_claim(&request(vec![event(), older]))
                .expect_err("oldest first"),
            AuthorityError::Conflict
        );
    }

    #[test]
    fn claim_replay_ignores_server_time_but_generation_stays_occupied() {
        let mut authority = ready();
        let request = ClaimRequest {
            arm_id: "arm-a".to_owned(),
            request_id: "claim-a".to_owned(),
            signal_id: "signal-a".to_owned(),
            events: vec![event()],
        };
        authority.admit_claim(&request).expect("admit");
        authority.set_now(now() + Duration::seconds(1));
        let replay = authority.admit_claim(&request).expect("exact replay");
        assert_eq!(replay.outcome, ClaimOutcome::ExactReplay);

        let different = ClaimRequest {
            request_id: "claim-b".to_owned(),
            signal_id: "signal-b".to_owned(),
            ..request
        };
        assert_eq!(
            authority
                .admit_claim(&different)
                .expect_err("occupied generation"),
            AuthorityError::Conflict
        );
    }

    #[test]
    fn replayed_idle_permit_is_rejected() {
        let mut authority = ready();
        let (prepared, _scope) = prepare(&mut authority);
        let epoch = crate::controller::NativeMutationEpoch {
            birth_id: prepared.correlation.birth_id.clone(),
            sequence: 1,
        };
        let probe_id = RequestNonce::fixture(44);
        let permit = || ValidatedIdlePermit {
            attempt_id: prepared.correlation.attempt_id.clone(),
            signal_id: prepared.correlation.signal_id.clone(),
            birth_id: prepared.correlation.birth_id.clone(),
            thread_ref: prepared.correlation.thread_ref.clone(),
            arm_id: prepared.attachment.arm_id.clone(),
            generation: prepared.attachment.generation,
            capability: prepared.attachment.capability,
            verifier_ref: prepared.attachment.verifier_ref.clone(),
            mutation_epoch: epoch.clone(),
            probe_id: probe_id.clone(),
            observed_at: now(),
            valid_until: now() + Duration::seconds(5),
        };
        authority
            .persist
            .reserve_native_turn_write(permit(), &prepared.correlation)
            .expect("first reservation");
        assert!(matches!(
            authority
                .persist
                .reserve_native_turn_write(permit(), &prepared.correlation),
            Err(PersistError::Unauthorized)
        ));
    }

    #[test]
    fn unknown_create_quarantines_the_only_birth() {
        let mut authority = DaemonAuthority::new(FakePersist::default(), now());
        authority.register_managed_arm(arm()).expect("arm");
        let reservation = authority.reserve_controller_birth("arm-a").expect("birth");
        authority
            .resolve_thread_create(reservation, ThreadCreateResolution::Unknown)
            .expect("unknown");
        assert_eq!(
            authority
                .reserve_controller_birth("arm-a")
                .expect_err("must not reserve a replacement create"),
            AuthorityError::Conflict
        );
        assert_eq!(
            authority
                .admit_claim(&ClaimRequest {
                    arm_id: "arm-a".to_owned(),
                    request_id: "claim-a".to_owned(),
                    signal_id: "signal-a".to_owned(),
                    events: vec![event()],
                })
                .expect_err("unknown ownership cannot dispatch"),
            AuthorityError::NoOwnedController
        );
    }

    #[test]
    fn recovery_never_remints_a_reserved_command() {
        let mut authority = ready();
        let (prepared, scope) = prepare(&mut authority);
        let mut controller =
            FakeController::new(vec![FakeIdleState::Idle(1)], vec![]).with_now(now());
        let probe = controller.probe_idle(scope);
        let ProbeAuthorization::Ready(_unresolved) =
            authority.authorize_probe(prepared, probe).expect("reserve")
        else {
            panic!("ready");
        };
        let backend = authority.persist.clone();
        let mut restarted = DaemonAuthority::new(backend, now());
        let recovered = restarted.recover().expect("recover");
        assert_eq!(recovered.snapshot.reservations.len(), 1);
        assert_eq!(recovered.snapshot.claims.len(), 1);
        assert!(
            recovered
                .snapshot
                .reservations
                .iter()
                .all(|item| item.concluded)
        );
        let (observing, reconciling) = recovered.into_followup_scopes();
        assert!(observing.is_empty());
        assert_eq!(reconciling.len(), 1);
    }

    #[test]
    fn reference_free_bound_observations_persist_after_acceptance() {
        let mut authority = ready();
        let turn_ref = PrivateNativeRef::fixture(70);
        let (prepared, disposition) = reserved_disposition(
            &mut authority,
            NativeWriteDisposition::Accepted {
                turn_ref: turn_ref.clone(),
            },
        );
        let scope = authority
            .conclude_native_write(prepared, Ok(disposition))
            .expect("accepted")
            .into_observation_scope()
            .expect("observation scope");
        for fact in [
            NativeTurnFact::ControllerLost,
            NativeTurnFact::DegradedTerminalObservation,
            NativeTurnFact::Unknown,
        ] {
            authority
                .record_exact_observation(&scope, fact)
                .expect("bounded fact");
        }
    }

    #[test]
    fn interrupted_fact_persistence_recovers_exact_or_unknown_without_rewrite() {
        let terminal_ref = PrivateNativeRef::fixture(71);
        let mut terminal_authority = ready();
        let (prepared, disposition) = reserved_disposition(
            &mut terminal_authority,
            NativeWriteDisposition::ExactResponse(NativeTurnFact::Terminal {
                turn_ref: terminal_ref,
                class: crate::controller::TerminalClass::Succeeded,
            }),
        );
        terminal_authority.persist.fail_next_turn_fact();
        assert_eq!(
            terminal_authority
                .conclude_native_write(prepared, Ok(disposition))
                .expect_err("fact persist failure"),
            AuthorityError::Storage
        );
        let mut restarted = DaemonAuthority::new(terminal_authority.persist.clone(), now());
        let recovery = restarted.recover().expect("recover exact response");
        assert!(matches!(
            recovery.snapshot.native_turn_facts[0].facts.as_slice(),
            [NativeTurnFact::Terminal { .. }]
        ));
        let (observing, reconciling) = recovery.into_followup_scopes();
        assert!(observing.is_empty());
        assert!(reconciling.is_empty());

        let accepted_ref = PrivateNativeRef::fixture(72);
        let mut accepted_authority = ready();
        let (prepared, disposition) = reserved_disposition(
            &mut accepted_authority,
            NativeWriteDisposition::Accepted {
                turn_ref: accepted_ref,
            },
        );
        accepted_authority.persist.fail_next_turn_fact();
        assert_eq!(
            accepted_authority
                .conclude_native_write(prepared, Ok(disposition))
                .expect_err("accepted fact persist failure"),
            AuthorityError::Storage
        );
        let mut restarted = DaemonAuthority::new(accepted_authority.persist.clone(), now());
        let recovery = restarted.recover().expect("recover writer accepted");
        assert!(matches!(
            recovery.snapshot.native_write_evidence[0].evidence,
            NativeWriteEvidence::Unknown
        ));
        let (observing, reconciling) = recovery.into_followup_scopes();
        assert!(observing.is_empty());
        assert_eq!(reconciling.len(), 1);
    }
}
