//! Sealed semantic persistence port for native-controller authority.

use crate::controller::{
    ActiveObservationEvidenceRef, ActiveObservationFingerprint, ActiveObservationProof, ActorName,
    ArmId, AttemptId, BoundedBody, BoundedToken, BoundedUsize, BoundedVec, CanonicalBodyDigest,
    ClaimDigest, ClaimPayloadRef, ClaimRequestId, ControllerBirthId, EventRef, ManagedCapability,
    NativeCoordinateKind, NativeCoordinateScope, NativeMutationEpoch, NativeTurnFact,
    NativeWriteReservation, OpenedNativeCoordinate, PersistedTurnCorrelation, PrivateNativeRef,
    ProducerLabel, ProviderName, ReconciliationDisposition, ReconciliationScope, RequestNonce,
    RetrievalId, SeatId, SecretNativeCoordinate, SignalId, ValidatedIdlePermit, VerifierRef,
};
use gearwit_protocol::ProviderEvent;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// Full arm policy required to reconstruct daemon authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedArm {
    pub arm_id: ArmId,
    pub generation: u64,
    pub seat_id: SeatId,
    pub capability: ManagedCapability,
    pub coverage_until: OffsetDateTime,
}

/// Metadata-only claim record used by general recovery. Content identity is
/// the immutable [`ClaimPayloadRef`]; the digest binds the canonical claim
/// encoding. `attempt_id` is a retained shipped extension (recovery keys
/// claims by attempt) beyond the frozen field set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedClaimRecord {
    pub attempt_id: AttemptId,
    pub request_id: ClaimRequestId,
    pub arm_id: ArmId,
    pub generation: u64,
    pub signal_id: SignalId,
    pub event_refs: BoundedVec<EventRef, 1, 64>,
    pub claim_digest: ClaimDigest,
    pub payload_ref: ClaimPayloadRef,
    pub claimed_at: OffsetDateTime,
}

/// One validated provider event inside a claimed batch. This is the bounded
/// host-side form of the wire [`ProviderEvent`]; conversion validates every
/// bound at the admission boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderEventRecord {
    pub(crate) event_ref: EventRef,
    pub(crate) provider: ProviderName,
    pub(crate) actor: Option<ActorName>,
    pub(crate) observed_at: OffsetDateTime,
    pub(crate) body: BoundedBody<4096>,
}

impl TryFrom<&ProviderEvent> for ProviderEventRecord {
    type Error = &'static str;

    fn try_from(event: &ProviderEvent) -> Result<Self, Self::Error> {
        if event.observed_at.len() > 64 {
            return Err("timestamp exceeds bound");
        }
        let observed_at = OffsetDateTime::parse(
            &event.observed_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| "timestamp is not RFC 3339")?;
        Ok(Self {
            event_ref: EventRef::new(event.event_ref.clone())?,
            provider: ProviderName::new(event.provider.clone())?,
            actor: event
                .actor
                .as_ref()
                .map(|actor| ActorName::new(actor.clone()))
                .transpose()?,
            observed_at,
            body: BoundedBody::new(event.body.clone())?,
        })
    }
}

/// Immutable bounded private claim payload: 1–64 validated events with at
/// most 131,072 aggregate body bytes. Stored once under its
/// [`ClaimPayloadRef`]; replay and retrieve resolve through the ref, never a
/// second body copy. Debug shows counts only; bodies stay redacted.
#[derive(Clone, Eq, PartialEq)]
pub struct BoundedClaimPayload {
    pub(crate) events: BoundedVec<ProviderEventRecord, 1, 64>,
    pub(crate) aggregate_body_bytes: BoundedUsize<0, 131_072>,
}

impl TryFrom<Vec<ProviderEventRecord>> for BoundedClaimPayload {
    type Error = &'static str;

    fn try_from(events: Vec<ProviderEventRecord>) -> Result<Self, Self::Error> {
        let aggregate: usize = events.iter().map(|event| event.body.as_str().len()).sum();
        Ok(Self {
            events: BoundedVec::try_from(events)?,
            aggregate_body_bytes: BoundedUsize::try_from(aggregate)?,
        })
    }
}

impl fmt::Debug for BoundedClaimPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedClaimPayload")
            .field("event_count", &self.events.as_slice().len())
            .field("aggregate_body_bytes", &self.aggregate_body_bytes.get())
            .finish()
    }
}

/// Admission input. Event content travels as one validated
/// [`BoundedClaimPayload`] and is stored under its [`ClaimPayloadRef`]; it
/// never appears in [`RecoverySnapshot`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimAdmission {
    pub(crate) request_id: ClaimRequestId,
    pub(crate) arm_id: ArmId,
    pub(crate) generation: u64,
    pub(crate) signal_id: SignalId,
    pub(crate) event_refs: BoundedVec<EventRef, 1, 64>,
    pub(crate) claim_digest: ClaimDigest,
    pub(crate) payload: BoundedClaimPayload,
    pub(crate) claimed_at: OffsetDateTime,
}

/// Canonical claim digest over the validated admission fields in fixed order.
/// The encoding is length-prefixed and unambiguous: domain tag, request id,
/// arm id, generation, signal id, ordered event refs, then the ordered event
/// records (ref, provider, actor presence + value, RFC 3339 time, body).
/// Any validated-field change yields a different digest; transport framing
/// never enters it.
pub(crate) fn canonical_claim_digest(
    request_id: &ClaimRequestId,
    arm_id: &ArmId,
    generation: u64,
    signal_id: &SignalId,
    event_refs: &BoundedVec<EventRef, 1, 64>,
    payload: &BoundedClaimPayload,
) -> ClaimDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"gearwit.claim-digest.v1\0");
    mac_field(&mut hasher, request_id.as_str().as_bytes());
    mac_field(&mut hasher, arm_id.as_str().as_bytes());
    mac_field(&mut hasher, &generation.to_le_bytes());
    mac_field(&mut hasher, signal_id.as_str().as_bytes());
    for event_ref in event_refs.as_slice() {
        mac_field(&mut hasher, event_ref.as_str().as_bytes());
    }
    for event in payload.events.as_slice() {
        mac_field(&mut hasher, event.event_ref.as_str().as_bytes());
        mac_field(&mut hasher, event.provider.as_str().as_bytes());
        match &event.actor {
            Some(actor) => {
                mac_field(&mut hasher, b"\x01");
                mac_field(&mut hasher, actor.as_str().as_bytes());
            }
            None => mac_field(&mut hasher, b"\x00"),
        }
        mac_field(
            &mut hasher,
            &event.observed_at.unix_timestamp_nanos().to_le_bytes(),
        );
        mac_field(&mut hasher, event.body.as_str().as_bytes());
    }
    ClaimDigest::from_bytes(*hasher.finalize().as_bytes())
}

/// Test-only admission constructor over validated wire events. Panics on
/// invalid fixture input; production admissions validate through authority.
#[cfg(test)]
pub(crate) fn claim_admission_fixture(
    request_id: &str,
    arm_id: ArmId,
    generation: u64,
    signal_id: SignalId,
    events: &[ProviderEvent],
    claimed_at: OffsetDateTime,
) -> ClaimAdmission {
    let records: Vec<ProviderEventRecord> = events
        .iter()
        .map(|event| ProviderEventRecord::try_from(event).expect("fixture event"))
        .collect();
    let event_refs = BoundedVec::try_from(
        records
            .iter()
            .map(|record| record.event_ref.clone())
            .collect::<Vec<_>>(),
    )
    .expect("fixture refs");
    let payload = BoundedClaimPayload::try_from(records).expect("fixture payload");
    let request_id = ClaimRequestId::new(request_id).expect("fixture request id");
    let claim_digest = canonical_claim_digest(
        &request_id,
        &arm_id,
        generation,
        &signal_id,
        &event_refs,
        &payload,
    );
    ClaimAdmission {
        request_id,
        arm_id,
        generation,
        signal_id,
        event_refs,
        claim_digest,
        payload,
        claimed_at,
    }
}

/// Durable attachment bound to one controller birth.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedControllerAttachment {
    pub attempt_id: AttemptId,
    pub birth_id: ControllerBirthId,
    pub seat_id: SeatId,
    pub arm_id: ArmId,
    pub generation: u64,
    pub capability: ManagedCapability,
    pub lease_until: OffsetDateTime,
    pub verifier_ref: VerifierRef,
    pub revoked: bool,
}

/// One durable controller birth.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedControllerBirth {
    pub birth_id: ControllerBirthId,
    pub seat_id: SeatId,
    pub arm_id: ArmId,
    pub generation: u64,
    pub capability: ManagedCapability,
    pub lease_until: OffsetDateTime,
    pub verifier_ref: VerifierRef,
    pub created_at: OffsetDateTime,
    pub revoked: bool,
}

/// Native thread creation reserved before any create write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadCreateReservation {
    pub birth_id: ControllerBirthId,
    pub create_attempt_id: RequestNonce,
    pub reserved_at: OffsetDateTime,
}

/// Exact creation resolution. Unknown remains quarantined.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ThreadCreateResolution {
    Owned { thread_ref: PrivateNativeRef },
    ProvenNotAccepted,
    Unknown,
}

/// Exact thread ownership state for a birth.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ThreadOwnershipState {
    Absent,
    Reserved {
        create_attempt_id: RequestNonce,
    },
    Unknown {
        create_attempt_id: RequestNonce,
    },
    ProvenNotAccepted {
        create_attempt_id: RequestNonce,
    },
    Owned {
        create_attempt_id: RequestNonce,
        thread_ref: PrivateNativeRef,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedThreadOwnership {
    pub birth_id: ControllerBirthId,
    pub state: ThreadOwnershipState,
}

/// Durable zero-write conclusion before native acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreWriteConclusion {
    HeldBeforeNativeWrite {
        active_evidence_ref: ActiveObservationEvidenceRef,
    },
    IdleStateUnproven,
    IdleEpochInvalidated {
        probe_id: RequestNonce,
        expected_epoch: NativeMutationEpoch,
        observed_epoch: NativeMutationEpoch,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedActiveObservationEvidence {
    pub evidence_ref: ActiveObservationEvidenceRef,
    pub birth_id: ControllerBirthId,
    pub create_attempt_id: RequestNonce,
    pub seat_id: SeatId,
    pub arm_id: ArmId,
    pub generation: u64,
    pub capability: ManagedCapability,
    pub attachment_verifier_ref: VerifierRef,
    pub lease_until: OffsetDateTime,
    pub attempt_id: AttemptId,
    pub signal_id: SignalId,
    pub probe_id: RequestNonce,
    pub mutation_epoch: NativeMutationEpoch,
    pub observed_at: OffsetDateTime,
    pub fingerprint: ActiveObservationFingerprint,
    pub producer_version: ProducerLabel,
    pub producer_dialect: ProducerLabel,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedPreWriteConclusion {
    pub attempt_id: AttemptId,
    pub signal_id: SignalId,
    pub conclusion: PreWriteConclusion,
    pub recorded_at: OffsetDateTime,
}

/// Durable native boundary evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeWriteEvidence {
    ProvenNotAccepted,
    WriterAccepted { write_id: RequestNonce },
    ExactResponse { fact: NativeTurnFact },
    Unknown,
}

/// Semantic operation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdempotentWrite {
    Recorded,
    ExactReplay,
}

/// Idempotent operation result carrying the recorded value. Exact replays
/// return the stored value, never a recomputed one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdempotentResult<T> {
    Recorded(T),
    ExactReplay(T),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReserveBirthOutcome {
    Reserved,
    ExactReplay,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionOutcome {
    Admitted,
    ExactReplay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionRecord {
    pub outcome: AdmissionOutcome,
    pub attempt_id: AttemptId,
    pub verifier_ref: VerifierRef,
    pub payload_ref: ClaimPayloadRef,
}

/// Sealed semantic commits. Callers cannot provide raw ids to mutate state.
#[derive(Debug)]
pub struct ThreadCreateCommit {
    pub(crate) birth_id: ControllerBirthId,
    pub(crate) create_attempt_id: RequestNonce,
    pub(crate) resolution: ThreadCreateResolution,
    pub(crate) evidence_ref: VerifierRef,
}

#[derive(Debug)]
pub struct PreparedDispatchCommit {
    pub(crate) correlation: PersistedTurnCorrelation,
}

/// Pre-write conclusions expressible without an active observation. Held is
/// deliberately unconstructible here: it is recorded only through
/// [`Persist::record_active_hold`] with its atomic evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NonActivePreWriteConclusion {
    IdleStateUnproven,
    IdleEpochInvalidated {
        probe_id: RequestNonce,
        expected_epoch: NativeMutationEpoch,
        observed_epoch: NativeMutationEpoch,
    },
}

impl From<NonActivePreWriteConclusion> for PreWriteConclusion {
    fn from(conclusion: NonActivePreWriteConclusion) -> Self {
        match conclusion {
            NonActivePreWriteConclusion::IdleStateUnproven => Self::IdleStateUnproven,
            NonActivePreWriteConclusion::IdleEpochInvalidated {
                probe_id,
                expected_epoch,
                observed_epoch,
            } => Self::IdleEpochInvalidated {
                probe_id,
                expected_epoch,
                observed_epoch,
            },
        }
    }
}

#[derive(Debug)]
pub struct PreWriteConclusionCommit {
    pub(crate) attempt_id: AttemptId,
    pub(crate) signal_id: SignalId,
    pub(crate) conclusion: NonActivePreWriteConclusion,
    /// Authority-stamped record time. The store has no clock; the stamp is
    /// carried on the commit as a retained shipped extension.
    pub(crate) recorded_at: OffsetDateTime,
}

pub struct ActiveHoldCommit {
    pub(crate) proof: ActiveObservationProof,
}

#[derive(Debug)]
pub struct NativeWriteEvidenceCommit {
    pub(crate) correlation: PersistedTurnCorrelation,
    pub(crate) evidence: NativeWriteEvidence,
    pub(crate) evidence_ref: VerifierRef,
}

#[derive(Debug)]
pub struct NativeTurnFactCommit {
    pub(crate) correlation: PersistedTurnCorrelation,
    pub(crate) fact: NativeTurnFact,
    pub(crate) evidence_ref: VerifierRef,
}

#[derive(Debug)]
pub struct ValidatedAttachmentScope {
    pub(crate) attempt_id: AttemptId,
    pub(crate) birth_id: ControllerBirthId,
    pub(crate) arm_id: ArmId,
    pub(crate) generation: u64,
    pub(crate) verifier_ref: VerifierRef,
}

/// Closed Gate-1 helper operation set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelperOperation {
    Retrieve,
    Acknowledge,
}

/// Operations granted to one helper binding. Closed to retrieve plus
/// acknowledge; no other operation is expressible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelperOperations {
    retrieve: bool,
    acknowledge: bool,
}

impl HelperOperations {
    #[must_use]
    pub(crate) const fn all() -> Self {
        Self {
            retrieve: true,
            acknowledge: true,
        }
    }

    #[must_use]
    pub(crate) const fn retrieve_only() -> Self {
        Self {
            retrieve: true,
            acknowledge: false,
        }
    }

    #[must_use]
    pub(crate) const fn allows(self, operation: HelperOperation) -> bool {
        match operation {
            HelperOperation::Retrieve => self.retrieve,
            HelperOperation::Acknowledge => self.acknowledge,
        }
    }
}

/// Reviewed helper executable identity bound at grant mint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelperExecutableIdentity {
    pub(crate) image_digest: [u8; 32],
    pub(crate) file_identity: BoundedToken<256>,
    pub(crate) build_identity: BoundedToken<256>,
}

/// Durable helper-grant verifier record. Only the keyed verifier digest is
/// persisted; raw grant material never crosses the port. The verifier
/// compares in fixed time and is redacted from debug output.
#[derive(Clone)]
pub struct PersistedHelperGrant {
    pub(crate) grant_verifier: [u8; 32],
    pub(crate) seat_id: SeatId,
    pub(crate) arm_id: ArmId,
    pub(crate) generation: u64,
    pub(crate) birth_id: ControllerBirthId,
    pub(crate) attempt_id: AttemptId,
    pub(crate) signal_id: SignalId,
    pub(crate) claim_digest: ClaimDigest,
    pub(crate) operations: HelperOperations,
    pub(crate) lease_until: OffsetDateTime,
    pub(crate) executable_identity: HelperExecutableIdentity,
    pub(crate) revoked: bool,
}

impl fmt::Debug for PersistedHelperGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedHelperGrant")
            .field("grant_verifier", &"[redacted]")
            .field("seat_id", &self.seat_id)
            .field("arm_id", &self.arm_id)
            .field("generation", &self.generation)
            .field("birth_id", &self.birth_id)
            .field("attempt_id", &self.attempt_id)
            .field("signal_id", &self.signal_id)
            .field("claim_digest", &self.claim_digest)
            .field("operations", &self.operations)
            .field("lease_until", &self.lease_until)
            .field("executable_identity", &"[redacted]")
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for PersistedHelperGrant {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.grant_verifier.ct_eq(&other.grant_verifier))
            && self.seat_id == other.seat_id
            && self.arm_id == other.arm_id
            && self.generation == other.generation
            && self.birth_id == other.birth_id
            && self.attempt_id == other.attempt_id
            && self.signal_id == other.signal_id
            && self.claim_digest == other.claim_digest
            && self.operations == other.operations
            && self.lease_until == other.lease_until
            && self.executable_identity == other.executable_identity
            && self.revoked == other.revoked
    }
}

impl Eq for PersistedHelperGrant {}

/// Validated live helper binding. Sealed, connection-bound, and non-Clone;
/// production construction is the claimed-batch face after authentication.
#[derive(Debug)]
pub struct ValidatedHelperBinding {
    pub(crate) grant_ref: VerifierRef,
    pub(crate) seat_id: SeatId,
    pub(crate) arm_id: ArmId,
    pub(crate) generation: u64,
    pub(crate) birth_id: ControllerBirthId,
    pub(crate) attempt_id: AttemptId,
    pub(crate) signal_id: SignalId,
    pub(crate) claim_digest: ClaimDigest,
    pub(crate) operations: HelperOperations,
    pub(crate) lease_until: OffsetDateTime,
}

/// One retrieve call: the validated binding plus the request nonce and the
/// canonical digest of the validated request body.
#[derive(Debug)]
pub struct RetrieveExchange {
    pub(crate) binding: ValidatedHelperBinding,
    pub(crate) request_id: RequestNonce,
    pub(crate) canonical_body_digest: CanonicalBodyDigest,
}

/// Content-free recorded retrieve result. Content resolves only through the
/// immutable [`ClaimPayloadRef`]; no body is duplicated here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedRetrieveResult {
    pub(crate) retrieval_id: RetrievalId,
    pub(crate) claim_payload_ref: ClaimPayloadRef,
    pub(crate) newest_event_ref: EventRef,
    pub(crate) event_count: u8,
    pub(crate) retrieved_at: OffsetDateTime,
}

/// One acknowledge call over an exact prior retrieval.
#[derive(Debug)]
pub struct AcknowledgeRequest {
    pub(crate) request_id: RequestNonce,
    pub(crate) retrieval_id: RetrievalId,
    pub(crate) cursor: EventRef,
    pub(crate) canonical_body_digest: CanonicalBodyDigest,
}

/// Content-free recorded acknowledgment with the daemon-stamped accept time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcknowledgeResult {
    pub(crate) attempt_id: AttemptId,
    pub(crate) signal_id: SignalId,
    pub(crate) cursor: EventRef,
    pub(crate) accepted_at: OffsetDateTime,
}

/// Sealed complete arm/generation/attempt/signal binding for the re-arm join.
#[derive(Debug)]
pub struct RearmJoinScope {
    pub(crate) arm_id: ArmId,
    pub(crate) generation: u64,
    pub(crate) attempt_id: AttemptId,
    pub(crate) signal_id: SignalId,
}

/// Sealed grant/controller/attempt binding for helper-grant revocation.
#[derive(Debug)]
pub struct HelperRevocationScope {
    pub(crate) grant_ref: VerifierRef,
    pub(crate) birth_id: ControllerBirthId,
    pub(crate) attempt_id: AttemptId,
}

/// Re-arm join outcome. Waiting branches name exactly which side is missing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RearmJoinResult {
    Rearmed,
    AlreadyRearmed,
    WaitingForHandled,
    WaitingForRecognizedTerminal,
}

/// Metadata for a reservation. Recovery can classify it but cannot remint its
/// consumed in-memory authority products.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedNativeReservation {
    pub correlation: PersistedTurnCorrelation,
    pub probe_id: RequestNonce,
    pub expected_epoch: NativeMutationEpoch,
    pub concluded: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedNativeWriteEvidence {
    pub correlation: PersistedTurnCorrelation,
    pub evidence: NativeWriteEvidence,
    pub evidence_ref: VerifierRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedNativeTurnFacts {
    pub attempt_id: AttemptId,
    pub facts: Vec<NativeTurnFact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedReconciliation {
    pub attempt_id: AttemptId,
    pub disposition: ReconciliationDisposition,
}

/// General recovery state contains authority metadata only.
#[derive(Clone, Debug, Default)]
pub struct RecoverySnapshot {
    pub arms: Vec<PersistedArm>,
    pub claims: Vec<PersistedClaimRecord>,
    pub attachments: Vec<PersistedControllerAttachment>,
    pub controller_births: Vec<PersistedControllerBirth>,
    pub ownership: Vec<PersistedThreadOwnership>,
    pub turn_correlations: Vec<PersistedTurnCorrelation>,
    pub reservations: Vec<PersistedNativeReservation>,
    pub native_write_evidence: Vec<PersistedNativeWriteEvidence>,
    pub native_turn_facts: Vec<PersistedNativeTurnFacts>,
    pub reconciliations: Vec<PersistedReconciliation>,
    pub prewrite_conclusions: Vec<PersistedPreWriteConclusion>,
    pub active_observations: Vec<PersistedActiveObservationEvidence>,
    pub attempt_seq: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistError {
    Conflict,
    InvalidTransition,
    Unauthorized,
    PayloadUnavailable,
    StorageUnavailable,
}

mod sealed {
    pub trait Sealed {}
}

/// Semantic host persistence port. There are no generic transition, raw
/// disposition, content-load, or backend escape-hatch methods.
///
/// ```compile_fail
/// use gearwit_host::Persist;
/// fn append_generic_transition<P: Persist>(persist: &mut P) {
///     persist.record_transition();
/// }
/// ```
#[allow(clippy::missing_errors_doc)]
pub trait Persist: sealed::Sealed {
    fn persist_arm(&mut self, arm: &PersistedArm) -> Result<(), PersistError>;
    fn admit_claim(
        &mut self,
        admission: &ClaimAdmission,
        attachment: &PersistedControllerAttachment,
    ) -> Result<AdmissionRecord, PersistError>;
    fn reserve_controller_birth(
        &mut self,
        birth: &PersistedControllerBirth,
        create: &ThreadCreateReservation,
    ) -> Result<ReserveBirthOutcome, PersistError>;
    fn resolve_thread_create(
        &mut self,
        commit: ThreadCreateCommit,
    ) -> Result<IdempotentWrite, PersistError>;
    fn thread_ownership_state(
        &self,
        birth_id: &ControllerBirthId,
    ) -> Result<ThreadOwnershipState, PersistError>;
    fn seal_native_coordinate(
        &mut self,
        scope: &NativeCoordinateScope,
        coordinate: &SecretNativeCoordinate,
    ) -> Result<PrivateNativeRef, PersistError>;
    fn open_native_coordinate(
        &self,
        scope: &NativeCoordinateScope,
        native_ref: &PrivateNativeRef,
    ) -> Result<OpenedNativeCoordinate, PersistError>;
    fn record_dispatch_prepared(
        &mut self,
        commit: PreparedDispatchCommit,
    ) -> Result<IdempotentWrite, PersistError>;
    fn record_prewrite_conclusion(
        &mut self,
        commit: PreWriteConclusionCommit,
    ) -> Result<IdempotentWrite, PersistError>;
    fn record_active_hold(
        &mut self,
        commit: ActiveHoldCommit,
    ) -> Result<IdempotentWrite, PersistError>;
    fn reserve_native_turn_write(
        &mut self,
        idle: ValidatedIdlePermit,
        correlation: &PersistedTurnCorrelation,
    ) -> Result<NativeWriteReservation, PersistError>;
    fn record_native_write_evidence(
        &mut self,
        commit: NativeWriteEvidenceCommit,
    ) -> Result<IdempotentWrite, PersistError>;
    fn record_native_turn_fact(
        &mut self,
        commit: NativeTurnFactCommit,
    ) -> Result<IdempotentWrite, PersistError>;
    fn record_reconciliation_fact(
        &mut self,
        scope: ReconciliationScope,
        disposition: &ReconciliationDisposition,
    ) -> Result<IdempotentWrite, PersistError>;
    fn revoke_controller_attachment(
        &mut self,
        scope: ValidatedAttachmentScope,
    ) -> Result<IdempotentWrite, PersistError>;
    fn recover_authority_state(&mut self) -> Result<RecoverySnapshot, PersistError>;
}

/// Deterministic semantic fake. Payload content is intentionally isolated from
/// all recovery and authority inspection records.
#[derive(Clone)]
struct RecoveryCoordinate {
    scope: NativeCoordinateScope,
    plaintext: Zeroizing<Vec<u8>>,
}

#[derive(Clone)]
pub struct FakePersist {
    arms: BTreeMap<ArmId, PersistedArm>,
    claims: BTreeMap<ClaimRequestId, PersistedClaimRecord>,
    payloads: BTreeMap<ClaimPayloadRef, BoundedClaimPayload>,
    claim_attempts: BTreeMap<ClaimRequestId, AttemptId>,
    attachments: BTreeMap<AttemptId, PersistedControllerAttachment>,
    births: BTreeMap<ControllerBirthId, PersistedControllerBirth>,
    creates: BTreeMap<ControllerBirthId, ThreadCreateReservation>,
    ownership: BTreeMap<ControllerBirthId, ThreadOwnershipState>,
    create_evidence_refs: BTreeMap<ControllerBirthId, VerifierRef>,
    private_recovery: BTreeMap<PrivateNativeRef, RecoveryCoordinate>,
    prepared: BTreeMap<AttemptId, PersistedTurnCorrelation>,
    reservations: BTreeMap<AttemptId, PersistedNativeReservation>,
    consumed_probes: BTreeSet<RequestNonce>,
    prewrite: BTreeMap<AttemptId, PersistedPreWriteConclusion>,
    active_observations: BTreeMap<AttemptId, PersistedActiveObservationEvidence>,
    active_mac_key: Zeroizing<[u8; 32]>,
    write_evidence: BTreeMap<AttemptId, NativeWriteEvidence>,
    write_evidence_refs: BTreeMap<AttemptId, VerifierRef>,
    turn_facts: BTreeMap<AttemptId, Vec<NativeTurnFact>>,
    reconciliations: BTreeMap<AttemptId, ReconciliationDisposition>,
    attempt_seq: u64,
    #[cfg(test)]
    fail_next_turn_fact: bool,
    #[cfg(test)]
    fail_next_active_hold: bool,
}

impl Default for FakePersist {
    fn default() -> Self {
        let mut active_mac_key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *active_mac_key).expect("OS entropy for semantic fake MAC key");
        Self {
            arms: BTreeMap::new(),
            claims: BTreeMap::new(),
            payloads: BTreeMap::new(),
            claim_attempts: BTreeMap::new(),
            attachments: BTreeMap::new(),
            births: BTreeMap::new(),
            creates: BTreeMap::new(),
            ownership: BTreeMap::new(),
            create_evidence_refs: BTreeMap::new(),
            private_recovery: BTreeMap::new(),
            prepared: BTreeMap::new(),
            reservations: BTreeMap::new(),
            consumed_probes: BTreeSet::new(),
            prewrite: BTreeMap::new(),
            active_observations: BTreeMap::new(),
            write_evidence: BTreeMap::new(),
            write_evidence_refs: BTreeMap::new(),
            turn_facts: BTreeMap::new(),
            reconciliations: BTreeMap::new(),
            active_mac_key,
            attempt_seq: 0,
            #[cfg(test)]
            fail_next_turn_fact: false,
            #[cfg(test)]
            fail_next_active_hold: false,
        }
    }
}

impl fmt::Debug for FakePersist {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FakePersist([redacted private recovery partition])")
    }
}

/// Cloneable test handle whose clones address one semantic fake store.
#[derive(Clone, Default)]
pub struct SharedFakePersist(Arc<Mutex<FakePersist>>);

impl fmt::Debug for SharedFakePersist {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SharedFakePersist([redacted shared store])")
    }
}

impl SharedFakePersist {
    fn with_store<T>(
        &self,
        operation: impl FnOnce(&mut FakePersist) -> Result<T, PersistError>,
    ) -> Result<T, PersistError> {
        let mut store = self
            .0
            .lock()
            .map_err(|_| PersistError::StorageUnavailable)?;
        operation(&mut store)
    }
}

impl sealed::Sealed for SharedFakePersist {}

impl Persist for SharedFakePersist {
    fn persist_arm(&mut self, arm: &PersistedArm) -> Result<(), PersistError> {
        self.with_store(|store| store.persist_arm(arm))
    }

    fn admit_claim(
        &mut self,
        admission: &ClaimAdmission,
        attachment: &PersistedControllerAttachment,
    ) -> Result<AdmissionRecord, PersistError> {
        self.with_store(|store| store.admit_claim(admission, attachment))
    }

    fn reserve_controller_birth(
        &mut self,
        birth: &PersistedControllerBirth,
        create: &ThreadCreateReservation,
    ) -> Result<ReserveBirthOutcome, PersistError> {
        self.with_store(|store| store.reserve_controller_birth(birth, create))
    }

    fn resolve_thread_create(
        &mut self,
        commit: ThreadCreateCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        self.with_store(|store| store.resolve_thread_create(commit))
    }

    fn thread_ownership_state(
        &self,
        birth_id: &ControllerBirthId,
    ) -> Result<ThreadOwnershipState, PersistError> {
        self.with_store(|store| store.thread_ownership_state(birth_id))
    }

    fn seal_native_coordinate(
        &mut self,
        scope: &NativeCoordinateScope,
        coordinate: &SecretNativeCoordinate,
    ) -> Result<PrivateNativeRef, PersistError> {
        self.with_store(|store| store.seal_native_coordinate(scope, coordinate))
    }

    fn open_native_coordinate(
        &self,
        scope: &NativeCoordinateScope,
        native_ref: &PrivateNativeRef,
    ) -> Result<OpenedNativeCoordinate, PersistError> {
        self.with_store(|store| store.open_native_coordinate(scope, native_ref))
    }

    fn record_dispatch_prepared(
        &mut self,
        commit: PreparedDispatchCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        self.with_store(|store| store.record_dispatch_prepared(commit))
    }

    fn record_prewrite_conclusion(
        &mut self,
        commit: PreWriteConclusionCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        self.with_store(|store| store.record_prewrite_conclusion(commit))
    }

    fn record_active_hold(
        &mut self,
        commit: ActiveHoldCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        self.with_store(|store| store.record_active_hold(commit))
    }

    fn reserve_native_turn_write(
        &mut self,
        idle: ValidatedIdlePermit,
        correlation: &PersistedTurnCorrelation,
    ) -> Result<NativeWriteReservation, PersistError> {
        self.with_store(|store| store.reserve_native_turn_write(idle, correlation))
    }

    fn record_native_write_evidence(
        &mut self,
        commit: NativeWriteEvidenceCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        self.with_store(|store| store.record_native_write_evidence(commit))
    }

    fn record_native_turn_fact(
        &mut self,
        commit: NativeTurnFactCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        self.with_store(|store| store.record_native_turn_fact(commit))
    }

    fn record_reconciliation_fact(
        &mut self,
        scope: ReconciliationScope,
        disposition: &ReconciliationDisposition,
    ) -> Result<IdempotentWrite, PersistError> {
        self.with_store(|store| store.record_reconciliation_fact(scope, disposition))
    }

    fn revoke_controller_attachment(
        &mut self,
        scope: ValidatedAttachmentScope,
    ) -> Result<IdempotentWrite, PersistError> {
        self.with_store(|store| store.revoke_controller_attachment(scope))
    }

    fn recover_authority_state(&mut self) -> Result<RecoverySnapshot, PersistError> {
        self.with_store(FakePersist::recover_authority_state)
    }
}

impl FakePersist {
    #[must_use]
    pub fn prewrite_conclusion(&self, attempt_id: &str) -> Option<&PreWriteConclusion> {
        self.prewrite
            .iter()
            .find(|(id, _)| id.as_str() == attempt_id)
            .map(|(_, record)| &record.conclusion)
    }

    #[must_use]
    pub fn reservation_concluded(&self, attempt_id: &str) -> bool {
        self.reservations
            .iter()
            .find(|(id, _)| id.as_str() == attempt_id)
            .is_some_and(|(_, reservation)| reservation.concluded)
    }

    #[cfg(test)]
    pub fn fail_next_turn_fact(&mut self) {
        self.fail_next_turn_fact = true;
    }

    #[cfg(test)]
    pub fn fail_next_active_hold(&mut self) {
        self.fail_next_active_hold = true;
    }

    #[cfg(test)]
    fn rekey_active_evidence(&mut self) {
        getrandom::fill(&mut *self.active_mac_key).expect("test MAC rekey entropy");
    }
}

impl sealed::Sealed for FakePersist {}

impl Persist for FakePersist {
    fn persist_arm(&mut self, arm: &PersistedArm) -> Result<(), PersistError> {
        self.arms.insert(arm.arm_id.clone(), arm.clone());
        Ok(())
    }

    fn admit_claim(
        &mut self,
        admission: &ClaimAdmission,
        attachment: &PersistedControllerAttachment,
    ) -> Result<AdmissionRecord, PersistError> {
        // The sealed port never trusts caller-supplied identity: recompute
        // the canonical digest and verify the ordered refs match the
        // bounded payload before any store mutation. The same validation
        // applies to future decoded-media recovery.
        let recomputed = canonical_claim_digest(
            &admission.request_id,
            &admission.arm_id,
            admission.generation,
            &admission.signal_id,
            &admission.event_refs,
            &admission.payload,
        );
        if recomputed != admission.claim_digest {
            return Err(PersistError::Conflict);
        }
        let refs_match_payload = admission.event_refs.as_slice().iter().eq(admission
            .payload
            .events
            .as_slice()
            .iter()
            .map(|record| &record.event_ref));
        if !refs_match_payload {
            return Err(PersistError::Conflict);
        }
        if let Some(existing) = self.claims.get(&admission.request_id) {
            let payload_matches = self
                .payloads
                .get(&existing.payload_ref)
                .is_some_and(|stored| stored == &admission.payload);
            if existing.arm_id == admission.arm_id
                && existing.generation == admission.generation
                && existing.signal_id == admission.signal_id
                && existing.event_refs == admission.event_refs
                && existing.claim_digest == admission.claim_digest
                && payload_matches
            {
                let attempt_id = self
                    .claim_attempts
                    .get(&admission.request_id)
                    .ok_or(PersistError::InvalidTransition)?;
                let stored = self
                    .attachments
                    .get(attempt_id)
                    .ok_or(PersistError::InvalidTransition)?;
                return Ok(AdmissionRecord {
                    outcome: AdmissionOutcome::ExactReplay,
                    attempt_id: attempt_id.clone(),
                    verifier_ref: stored.verifier_ref.clone(),
                    payload_ref: existing.payload_ref.clone(),
                });
            }
            return Err(PersistError::Conflict);
        }
        if self.claims.values().any(|claim| {
            claim.arm_id == admission.arm_id && claim.generation == admission.generation
        }) {
            return Err(PersistError::Conflict);
        }
        if self.attachments.contains_key(&attachment.attempt_id) {
            return Err(PersistError::Conflict);
        }
        let payload_ref =
            ClaimPayloadRef::random().map_err(|_| PersistError::StorageUnavailable)?;
        let record = PersistedClaimRecord {
            attempt_id: attachment.attempt_id.clone(),
            request_id: admission.request_id.clone(),
            arm_id: admission.arm_id.clone(),
            generation: admission.generation,
            signal_id: admission.signal_id.clone(),
            event_refs: admission.event_refs.clone(),
            claim_digest: admission.claim_digest.clone(),
            payload_ref: payload_ref.clone(),
            claimed_at: admission.claimed_at,
        };
        self.claims.insert(admission.request_id.clone(), record);
        self.payloads
            .insert(payload_ref.clone(), admission.payload.clone());
        self.claim_attempts
            .insert(admission.request_id.clone(), attachment.attempt_id.clone());
        self.attachments
            .insert(attachment.attempt_id.clone(), attachment.clone());
        self.attempt_seq = self.attempt_seq.saturating_add(1);
        Ok(AdmissionRecord {
            outcome: AdmissionOutcome::Admitted,
            attempt_id: attachment.attempt_id.clone(),
            verifier_ref: attachment.verifier_ref.clone(),
            payload_ref,
        })
    }

    fn reserve_controller_birth(
        &mut self,
        birth: &PersistedControllerBirth,
        create: &ThreadCreateReservation,
    ) -> Result<ReserveBirthOutcome, PersistError> {
        if let Some(existing) = self.births.get(&birth.birth_id) {
            return if existing == birth && self.creates.get(&birth.birth_id) == Some(create) {
                Ok(ReserveBirthOutcome::ExactReplay)
            } else {
                Ok(ReserveBirthOutcome::Conflict)
            };
        }
        if birth.birth_id != create.birth_id {
            return Err(PersistError::Conflict);
        }
        self.births.insert(birth.birth_id.clone(), birth.clone());
        self.creates.insert(birth.birth_id.clone(), create.clone());
        self.ownership.insert(
            birth.birth_id.clone(),
            ThreadOwnershipState::Reserved {
                create_attempt_id: create.create_attempt_id.clone(),
            },
        );
        Ok(ReserveBirthOutcome::Reserved)
    }

    fn resolve_thread_create(
        &mut self,
        commit: ThreadCreateCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        let create = self
            .creates
            .get(&commit.birth_id)
            .ok_or(PersistError::InvalidTransition)?;
        if create.create_attempt_id != commit.create_attempt_id {
            return Err(PersistError::Conflict);
        }
        let evidence_ref = commit.evidence_ref;
        let next = match commit.resolution {
            ThreadCreateResolution::Owned { thread_ref } => ThreadOwnershipState::Owned {
                create_attempt_id: commit.create_attempt_id,
                thread_ref,
            },
            ThreadCreateResolution::ProvenNotAccepted => ThreadOwnershipState::ProvenNotAccepted {
                create_attempt_id: commit.create_attempt_id,
            },
            ThreadCreateResolution::Unknown => ThreadOwnershipState::Unknown {
                create_attempt_id: commit.create_attempt_id,
            },
        };
        let current = self
            .ownership
            .get(&commit.birth_id)
            .ok_or(PersistError::InvalidTransition)?;
        if current == &next {
            return if self.create_evidence_refs.get(&commit.birth_id) == Some(&evidence_ref) {
                Ok(IdempotentWrite::ExactReplay)
            } else {
                Err(PersistError::Conflict)
            };
        }
        let valid_transition = matches!(current, ThreadOwnershipState::Reserved { .. })
            || (matches!(current, ThreadOwnershipState::Unknown { .. })
                && matches!(
                    next,
                    ThreadOwnershipState::Owned { .. }
                        | ThreadOwnershipState::ProvenNotAccepted { .. }
                ));
        if !valid_transition {
            return Err(PersistError::Conflict);
        }
        self.create_evidence_refs
            .insert(commit.birth_id.clone(), evidence_ref);
        self.ownership.insert(commit.birth_id, next);
        Ok(IdempotentWrite::Recorded)
    }

    fn thread_ownership_state(
        &self,
        birth_id: &ControllerBirthId,
    ) -> Result<ThreadOwnershipState, PersistError> {
        Ok(self
            .ownership
            .get(birth_id)
            .cloned()
            .unwrap_or(ThreadOwnershipState::Absent))
    }

    fn seal_native_coordinate(
        &mut self,
        scope: &NativeCoordinateScope,
        coordinate: &SecretNativeCoordinate,
    ) -> Result<PrivateNativeRef, PersistError> {
        if !matches!(
            (scope, coordinate.kind()),
            (
                NativeCoordinateScope::Thread { .. },
                NativeCoordinateKind::Thread
            ) | (
                NativeCoordinateScope::Turn { .. },
                NativeCoordinateKind::Turn
            )
        ) {
            return Err(PersistError::Unauthorized);
        }
        if let Some((native_ref, _)) = self.private_recovery.iter().find(|(_, stored)| {
            stored.scope == *scope && stored.plaintext.as_slice() == coordinate.as_bytes()
        }) {
            let native_ref = native_ref.clone();
            let replay_open = match scope {
                NativeCoordinateScope::Turn { attempt_id, .. } => {
                    self.reservations
                        .get(attempt_id)
                        .and_then(|reservation| reservation.correlation.turn_ref.as_ref())
                        == Some(&native_ref)
                }
                NativeCoordinateScope::Thread { birth_id, .. } => matches!(
                    self.ownership.get(birth_id),
                    Some(ThreadOwnershipState::Owned { thread_ref, .. }) if thread_ref == &native_ref
                ),
            };
            self.validate_coordinate_scope(scope, Some(&native_ref), replay_open)?;
            return Ok(native_ref);
        }
        self.validate_coordinate_scope(scope, None, false)?;
        let mut bytes = [0_u8; 32];
        loop {
            getrandom::fill(&mut bytes).map_err(|_| PersistError::StorageUnavailable)?;
            let native_ref = PrivateNativeRef(bytes);
            if !self.private_recovery.contains_key(&native_ref) {
                self.private_recovery.insert(
                    native_ref.clone(),
                    RecoveryCoordinate {
                        scope: scope.clone(),
                        plaintext: Zeroizing::new(coordinate.as_bytes().to_vec()),
                    },
                );
                bytes.fill(0);
                return Ok(native_ref);
            }
        }
    }

    fn open_native_coordinate(
        &self,
        scope: &NativeCoordinateScope,
        native_ref: &PrivateNativeRef,
    ) -> Result<OpenedNativeCoordinate, PersistError> {
        self.validate_coordinate_scope(scope, Some(native_ref), true)?;
        let coordinate = self
            .private_recovery
            .get(native_ref)
            .filter(|coordinate| &coordinate.scope == scope)
            .ok_or(PersistError::Unauthorized)?;
        Ok(OpenedNativeCoordinate::from_bytes(&coordinate.plaintext))
    }

    fn record_dispatch_prepared(
        &mut self,
        commit: PreparedDispatchCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        let id = commit.correlation.attempt_id.clone();
        if let Some(existing) = self.prepared.get(&id) {
            return if existing == &commit.correlation {
                Ok(IdempotentWrite::ExactReplay)
            } else {
                Err(PersistError::Conflict)
            };
        }
        self.prepared.insert(id, commit.correlation);
        Ok(IdempotentWrite::Recorded)
    }

    fn record_prewrite_conclusion(
        &mut self,
        commit: PreWriteConclusionCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        let record = PersistedPreWriteConclusion {
            attempt_id: commit.attempt_id.clone(),
            signal_id: commit.signal_id,
            conclusion: commit.conclusion.into(),
            recorded_at: commit.recorded_at,
        };
        if let Some(existing) = self.prewrite.get(&commit.attempt_id) {
            return if existing.conclusion == record.conclusion {
                Ok(IdempotentWrite::ExactReplay)
            } else {
                Err(PersistError::Conflict)
            };
        }
        if let Some(reservation) = self.reservations.get_mut(&commit.attempt_id) {
            reservation.concluded = true;
        }
        self.prewrite.insert(commit.attempt_id, record);
        Ok(IdempotentWrite::Recorded)
    }

    #[allow(clippy::too_many_lines)]
    fn record_active_hold(
        &mut self,
        commit: ActiveHoldCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        let proof = commit.proof;
        let attachment = self
            .attachments
            .get(&proof.attempt_id)
            .ok_or(PersistError::Unauthorized)?;
        let birth = self
            .births
            .get(&proof.birth_id)
            .ok_or(PersistError::Unauthorized)?;
        let claim = self
            .claims
            .values()
            .find(|claim| claim.attempt_id == proof.attempt_id)
            .ok_or(PersistError::Unauthorized)?;
        let prepared = self
            .prepared
            .get(&proof.attempt_id)
            .ok_or(PersistError::Unauthorized)?;
        if attachment.birth_id != proof.birth_id
            || attachment.seat_id != proof.seat_id
            || attachment.arm_id != proof.arm_id
            || attachment.generation != proof.generation
            || attachment.capability != proof.capability
            || attachment.verifier_ref != proof.attachment_verifier_ref
            || attachment.lease_until != proof.lease_until
            || attachment.revoked
            || birth.revoked
            || birth.seat_id != proof.seat_id
            || birth.arm_id != proof.arm_id
            || birth.generation != proof.generation
            || birth.capability != proof.capability
            || birth.lease_until < proof.observed_at
            || claim.signal_id != proof.signal_id
            || prepared.signal_id != proof.signal_id
            || prepared.birth_id != proof.birth_id
            || prepared.thread_ref != proof.thread_ref
            || proof.mutation_epoch.birth_id != proof.birth_id
            || proof.producer_version != "codex-cli 0.152.1"
            || proof.producer_dialect != "thread/read-v2"
            || !matches!(
                self.ownership.get(&proof.birth_id),
                Some(ThreadOwnershipState::Owned {
                    create_attempt_id,
                    thread_ref,
                }) if create_attempt_id == &proof.create_attempt_id && thread_ref == &proof.thread_ref
            )
        {
            return Err(PersistError::Unauthorized);
        }

        let mut mac = blake3::Hasher::new_keyed(&self.active_mac_key);
        mac.update(b"gearwit.active-observation.v1\0");
        mac_field(&mut mac, &proof.birth_id.0);
        mac_field(&mut mac, &proof.create_attempt_id.0);
        mac_field(&mut mac, &proof.thread_ref.0);
        mac_field(&mut mac, proof.seat_id.as_str().as_bytes());
        mac_field(&mut mac, proof.arm_id.as_str().as_bytes());
        mac_field(&mut mac, &proof.generation.to_le_bytes());
        mac_field(&mut mac, &[proof.capability as u8]);
        mac_field(&mut mac, proof.attachment_verifier_ref.bytes());
        mac_field(
            &mut mac,
            &proof.lease_until.unix_timestamp_nanos().to_le_bytes(),
        );
        mac_field(&mut mac, proof.attempt_id.as_str().as_bytes());
        mac_field(&mut mac, proof.signal_id.as_str().as_bytes());
        mac_field(&mut mac, &proof.probe_id.0);
        mac_field(&mut mac, &proof.mutation_epoch.sequence.to_le_bytes());
        mac_field(
            &mut mac,
            &proof.observed_at.unix_timestamp_nanos().to_le_bytes(),
        );
        mac_field(&mut mac, proof.prehash.bytes());
        mac_field(&mut mac, proof.producer_version.as_bytes());
        mac_field(&mut mac, proof.producer_dialect.as_bytes());
        let fingerprint = ActiveObservationFingerprint(*mac.finalize().as_bytes());
        let mut evidence_mac = blake3::Hasher::new_keyed(&self.active_mac_key);
        evidence_mac.update(b"gearwit.active-observation-ref.v1\0");
        evidence_mac.update(&fingerprint.0);
        let evidence_ref = ActiveObservationEvidenceRef(*evidence_mac.finalize().as_bytes());
        let record = PersistedActiveObservationEvidence {
            evidence_ref: evidence_ref.clone(),
            birth_id: proof.birth_id,
            create_attempt_id: proof.create_attempt_id,
            seat_id: proof.seat_id,
            arm_id: proof.arm_id,
            generation: proof.generation,
            capability: proof.capability,
            attachment_verifier_ref: proof.attachment_verifier_ref,
            lease_until: proof.lease_until,
            attempt_id: proof.attempt_id.clone(),
            signal_id: proof.signal_id.clone(),
            probe_id: proof.probe_id,
            mutation_epoch: proof.mutation_epoch,
            observed_at: proof.observed_at,
            fingerprint,
            producer_version: ProducerLabel::new(proof.producer_version)
                .map_err(|_| PersistError::InvalidTransition)?,
            producer_dialect: ProducerLabel::new(proof.producer_dialect)
                .map_err(|_| PersistError::InvalidTransition)?,
        };
        let conclusion = PersistedPreWriteConclusion {
            attempt_id: proof.attempt_id.clone(),
            signal_id: proof.signal_id,
            conclusion: PreWriteConclusion::HeldBeforeNativeWrite {
                active_evidence_ref: evidence_ref,
            },
            recorded_at: proof.observed_at,
        };
        if let Some(existing) = self.active_observations.get(&proof.attempt_id) {
            return if existing == &record
                && self.prewrite.get(&proof.attempt_id) == Some(&conclusion)
            {
                Ok(IdempotentWrite::ExactReplay)
            } else {
                Err(PersistError::Conflict)
            };
        }
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_active_hold) {
            return Err(PersistError::StorageUnavailable);
        }
        if self.prewrite.contains_key(&proof.attempt_id)
            || !self.consumed_probes.insert(record.probe_id.clone())
        {
            return Err(PersistError::Conflict);
        }
        self.active_observations
            .insert(proof.attempt_id.clone(), record);
        self.prewrite.insert(proof.attempt_id, conclusion);
        Ok(IdempotentWrite::Recorded)
    }

    fn reserve_native_turn_write(
        &mut self,
        idle: ValidatedIdlePermit,
        correlation: &PersistedTurnCorrelation,
    ) -> Result<NativeWriteReservation, PersistError> {
        if idle.observed_at >= idle.valid_until
            || idle.attempt_id != correlation.attempt_id
            || idle.signal_id != correlation.signal_id
            || idle.birth_id != correlation.birth_id
            || idle.thread_ref != correlation.thread_ref
            || idle.mutation_epoch.birth_id != idle.birth_id
            || self.consumed_probes.contains(&idle.probe_id)
            || self.reservations.contains_key(&idle.attempt_id)
        {
            return Err(PersistError::Unauthorized);
        }
        let attachment = self
            .attachments
            .get(&idle.attempt_id)
            .ok_or(PersistError::Unauthorized)?;
        if attachment.birth_id != idle.birth_id
            || attachment.arm_id != idle.arm_id
            || attachment.generation != idle.generation
            || attachment.capability != idle.capability
            || attachment.verifier_ref != idle.verifier_ref
            || attachment.revoked
        {
            return Err(PersistError::Unauthorized);
        }
        self.consumed_probes.insert(idle.probe_id.clone());
        self.reservations.insert(
            idle.attempt_id,
            PersistedNativeReservation {
                correlation: correlation.clone(),
                probe_id: idle.probe_id.clone(),
                expected_epoch: idle.mutation_epoch.clone(),
                concluded: false,
            },
        );
        Ok(NativeWriteReservation {
            correlation: correlation.clone(),
            probe_id: idle.probe_id,
            expected_epoch: idle.mutation_epoch,
        })
    }

    fn record_native_write_evidence(
        &mut self,
        commit: NativeWriteEvidenceCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        let id = commit.correlation.attempt_id.clone();
        let reservation = self
            .reservations
            .get(&id)
            .ok_or(PersistError::InvalidTransition)?;
        if reservation.correlation != commit.correlation {
            return Err(PersistError::Unauthorized);
        }
        if let Some(existing) = self.write_evidence.get(&id) {
            return if existing == &commit.evidence
                && self.write_evidence_refs.get(&id) == Some(&commit.evidence_ref)
            {
                Ok(IdempotentWrite::ExactReplay)
            } else {
                Err(PersistError::Conflict)
            };
        }
        self.write_evidence.insert(id.clone(), commit.evidence);
        self.write_evidence_refs
            .insert(id.clone(), commit.evidence_ref);
        if let Some(reservation) = self.reservations.get_mut(&id) {
            reservation.concluded = true;
        }
        Ok(IdempotentWrite::Recorded)
    }

    fn record_native_turn_fact(
        &mut self,
        commit: NativeTurnFactCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_turn_fact) {
            return Err(PersistError::StorageUnavailable);
        }
        let prepared = self
            .prepared
            .get(&commit.correlation.attempt_id)
            .ok_or(PersistError::Unauthorized)?;
        if prepared.signal_id != commit.correlation.signal_id
            || prepared.birth_id != commit.correlation.birth_id
            || prepared.thread_ref != commit.correlation.thread_ref
            || prepared.turn_write_id != commit.correlation.turn_write_id
        {
            return Err(PersistError::Unauthorized);
        }
        let fact_turn_ref = match &commit.fact {
            NativeTurnFact::Accepted { turn_ref }
            | NativeTurnFact::Started { turn_ref }
            | NativeTurnFact::Terminal { turn_ref, .. } => Some(turn_ref),
            NativeTurnFact::DegradedTerminalObservation
            | NativeTurnFact::ControllerLost
            | NativeTurnFact::Unknown => None,
        }
        .cloned();
        if fact_turn_ref.is_some() && fact_turn_ref.as_ref() != commit.correlation.turn_ref.as_ref()
        {
            return Err(PersistError::Unauthorized);
        }
        if let Some(turn_ref) = fact_turn_ref.as_ref() {
            let scope = NativeCoordinateScope::Turn {
                birth_id: commit.correlation.birth_id.clone(),
                attempt_id: commit.correlation.attempt_id.clone(),
                signal_id: commit.correlation.signal_id.clone(),
                turn_write_id: commit.correlation.turn_write_id.clone(),
            };
            let coordinate = self
                .private_recovery
                .get(turn_ref)
                .filter(|coordinate| coordinate.scope == scope)
                .ok_or(PersistError::Unauthorized)?;
            if coordinate.plaintext.is_empty() {
                return Err(PersistError::Unauthorized);
            }
            let reservation = self
                .reservations
                .get(&commit.correlation.attempt_id)
                .ok_or(PersistError::Unauthorized)?;
            if reservation.correlation.birth_id != commit.correlation.birth_id
                || reservation.correlation.signal_id != commit.correlation.signal_id
                || reservation.correlation.thread_ref != commit.correlation.thread_ref
                || reservation.correlation.turn_write_id != commit.correlation.turn_write_id
                || reservation
                    .correlation
                    .turn_ref
                    .as_ref()
                    .is_some_and(|existing| existing != turn_ref)
                || prepared
                    .turn_ref
                    .as_ref()
                    .is_some_and(|existing| existing != turn_ref)
            {
                return Err(PersistError::Unauthorized);
            }
        }
        let attempt_id = commit.correlation.attempt_id.clone();
        let facts = self.turn_facts.entry(attempt_id.clone()).or_default();
        if facts.contains(&commit.fact) {
            return Ok(IdempotentWrite::ExactReplay);
        }
        facts.push(commit.fact);
        if let Some(turn_ref) = fact_turn_ref.as_ref() {
            self.prepared
                .get_mut(&attempt_id)
                .expect("validated prepared correlation")
                .turn_ref = Some(turn_ref.clone());
            self.reservations
                .get_mut(&attempt_id)
                .expect("validated native reservation")
                .correlation
                .turn_ref = Some(turn_ref.clone());
        }
        if matches!(
            facts.last(),
            Some(
                NativeTurnFact::DegradedTerminalObservation
                    | NativeTurnFact::ControllerLost
                    | NativeTurnFact::Unknown
            )
        ) {
            self.write_evidence
                .insert(attempt_id, NativeWriteEvidence::Unknown);
        }
        Ok(IdempotentWrite::Recorded)
    }

    fn record_reconciliation_fact(
        &mut self,
        scope: ReconciliationScope,
        disposition: &ReconciliationDisposition,
    ) -> Result<IdempotentWrite, PersistError> {
        let id = scope.correlation.attempt_id.clone();
        let reservation = self
            .reservations
            .get(&id)
            .ok_or(PersistError::InvalidTransition)?;
        if reservation.correlation != scope.correlation
            || self.write_evidence.get(&id) != Some(&NativeWriteEvidence::Unknown)
            || self.write_evidence_refs.get(&id) != Some(&scope.native_write_evidence_ref)
        {
            return Err(PersistError::Unauthorized);
        }
        if let Some(existing) = self.reconciliations.get(&id) {
            return if existing == disposition {
                Ok(IdempotentWrite::ExactReplay)
            } else if matches!(existing, ReconciliationDisposition::Unknown) {
                self.reconciliations.insert(id, disposition.clone());
                Ok(IdempotentWrite::Recorded)
            } else {
                Err(PersistError::Conflict)
            };
        }
        self.reconciliations.insert(id, disposition.clone());
        Ok(IdempotentWrite::Recorded)
    }

    fn revoke_controller_attachment(
        &mut self,
        scope: ValidatedAttachmentScope,
    ) -> Result<IdempotentWrite, PersistError> {
        let attachment = self
            .attachments
            .get_mut(&scope.attempt_id)
            .ok_or(PersistError::Unauthorized)?;
        if attachment.birth_id != scope.birth_id
            || attachment.arm_id != scope.arm_id
            || attachment.generation != scope.generation
            || attachment.verifier_ref != scope.verifier_ref
        {
            return Err(PersistError::Unauthorized);
        }
        if attachment.revoked {
            return Ok(IdempotentWrite::ExactReplay);
        }
        attachment.revoked = true;
        Ok(IdempotentWrite::Recorded)
    }

    fn recover_authority_state(&mut self) -> Result<RecoverySnapshot, PersistError> {
        for state in self.ownership.values_mut() {
            if let ThreadOwnershipState::Reserved { create_attempt_id } = state {
                *state = ThreadOwnershipState::Unknown {
                    create_attempt_id: create_attempt_id.clone(),
                };
            }
        }
        let interrupted_facts: Vec<_> = self
            .write_evidence
            .iter()
            .filter(|(attempt_id, _)| !self.turn_facts.contains_key(*attempt_id))
            .map(|(attempt_id, evidence)| (attempt_id.clone(), evidence.clone()))
            .collect();
        for (attempt_id, evidence) in interrupted_facts {
            match evidence {
                NativeWriteEvidence::WriterAccepted { .. } => {
                    self.write_evidence
                        .insert(attempt_id, NativeWriteEvidence::Unknown);
                }
                NativeWriteEvidence::ExactResponse { fact } => {
                    self.turn_facts.insert(attempt_id, vec![fact]);
                }
                NativeWriteEvidence::ProvenNotAccepted | NativeWriteEvidence::Unknown => {}
            }
        }
        let unresolved: Vec<_> = self
            .reservations
            .iter()
            .filter(|(attempt_id, reservation)| {
                !reservation.concluded && !self.write_evidence.contains_key(*attempt_id)
            })
            .map(|(attempt_id, _)| attempt_id.clone())
            .collect();
        for attempt_id in unresolved {
            let evidence_ref =
                VerifierRef::random().map_err(|_| PersistError::StorageUnavailable)?;
            self.write_evidence
                .insert(attempt_id.clone(), NativeWriteEvidence::Unknown);
            self.write_evidence_refs
                .insert(attempt_id.clone(), evidence_ref);
            if let Some(reservation) = self.reservations.get_mut(&attempt_id) {
                reservation.concluded = true;
            }
        }
        Ok(RecoverySnapshot {
            arms: self.arms.values().cloned().collect(),
            claims: self.claims.values().cloned().collect(),
            attachments: self.attachments.values().cloned().collect(),
            controller_births: self.births.values().cloned().collect(),
            ownership: self
                .ownership
                .iter()
                .map(|(birth_id, state)| PersistedThreadOwnership {
                    birth_id: birth_id.clone(),
                    state: state.clone(),
                })
                .collect(),
            turn_correlations: self.prepared.values().cloned().collect(),
            reservations: self.reservations.values().cloned().collect(),
            native_write_evidence: self
                .write_evidence
                .iter()
                .filter_map(|(attempt_id, evidence)| {
                    Some(PersistedNativeWriteEvidence {
                        correlation: self.reservations.get(attempt_id)?.correlation.clone(),
                        evidence: evidence.clone(),
                        evidence_ref: self.write_evidence_refs.get(attempt_id)?.clone(),
                    })
                })
                .collect(),
            native_turn_facts: self
                .turn_facts
                .iter()
                .map(|(attempt_id, facts)| PersistedNativeTurnFacts {
                    attempt_id: attempt_id.clone(),
                    facts: facts.clone(),
                })
                .collect(),
            reconciliations: self
                .reconciliations
                .iter()
                .map(|(attempt_id, disposition)| PersistedReconciliation {
                    attempt_id: attempt_id.clone(),
                    disposition: disposition.clone(),
                })
                .collect(),
            prewrite_conclusions: self.prewrite.values().cloned().collect(),
            active_observations: self.active_observations.values().cloned().collect(),
            attempt_seq: self.attempt_seq,
        })
    }
}

impl FakePersist {
    fn validate_coordinate_scope(
        &self,
        scope: &NativeCoordinateScope,
        native_ref: Option<&PrivateNativeRef>,
        opening: bool,
    ) -> Result<(), PersistError> {
        match scope {
            NativeCoordinateScope::Thread {
                birth_id,
                create_attempt_id,
            } => {
                let create = self
                    .creates
                    .get(birth_id)
                    .ok_or(PersistError::Unauthorized)?;
                if create.create_attempt_id != *create_attempt_id {
                    return Err(PersistError::Unauthorized);
                }
                let birth = self
                    .births
                    .get(birth_id)
                    .filter(|birth| !birth.revoked)
                    .ok_or(PersistError::Unauthorized)?;
                if birth.birth_id != *birth_id {
                    return Err(PersistError::Unauthorized);
                }
                if !opening
                    && !matches!(
                        self.ownership.get(birth_id),
                        Some(
                            ThreadOwnershipState::Reserved {
                                create_attempt_id: reserved_create,
                            }
                            | ThreadOwnershipState::Unknown {
                                create_attempt_id: reserved_create,
                            }
                        ) if reserved_create == create_attempt_id
                    )
                {
                    return Err(PersistError::Unauthorized);
                }
                if opening
                    && !matches!(
                        self.ownership.get(birth_id),
                        Some(ThreadOwnershipState::Owned {
                            create_attempt_id: owned_create,
                            thread_ref,
                        }) if owned_create == create_attempt_id && Some(thread_ref) == native_ref
                    )
                {
                    return Err(PersistError::Unauthorized);
                }
            }
            NativeCoordinateScope::Turn {
                birth_id,
                attempt_id,
                signal_id,
                turn_write_id,
            } => {
                let correlation = self
                    .reservations
                    .get(attempt_id)
                    .map(|reservation| &reservation.correlation)
                    .ok_or(PersistError::Unauthorized)?;
                let attachment = self
                    .attachments
                    .get(attempt_id)
                    .filter(|attachment| !attachment.revoked)
                    .ok_or(PersistError::Unauthorized)?;
                let birth = self
                    .births
                    .get(birth_id)
                    .filter(|birth| !birth.revoked)
                    .ok_or(PersistError::Unauthorized)?;
                if correlation.birth_id != *birth_id
                    || correlation.attempt_id != *attempt_id
                    || correlation.signal_id != *signal_id
                    || correlation.turn_write_id != *turn_write_id
                    || attachment.birth_id != *birth_id
                    || attachment.arm_id != birth.arm_id
                    || attachment.generation != birth.generation
                    || attachment.seat_id != birth.seat_id
                    || attachment.capability != birth.capability
                    || (opening && correlation.turn_ref.as_ref() != native_ref)
                    || (!opening && correlation.turn_ref.is_some())
                {
                    return Err(PersistError::Unauthorized);
                }
            }
        }
        Ok(())
    }
}

fn mac_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn birth() -> (PersistedControllerBirth, ThreadCreateReservation) {
        let birth_id = ControllerBirthId::fixture(1);
        (
            PersistedControllerBirth {
                birth_id: birth_id.clone(),
                seat_id: SeatId::new("seat-a").expect("seat"),
                arm_id: ArmId::new("arm-a").expect("arm"),
                generation: 1,
                capability: ManagedCapability::HandleClaimedSignal,
                lease_until: OffsetDateTime::UNIX_EPOCH,
                verifier_ref: VerifierRef::fixture(3),
                created_at: OffsetDateTime::UNIX_EPOCH,
                revoked: false,
            },
            ThreadCreateReservation {
                birth_id,
                create_attempt_id: RequestNonce::fixture(2),
                reserved_at: OffsetDateTime::UNIX_EPOCH,
            },
        )
    }

    #[test]
    fn controller_birth_replay_and_conflict_are_exact() {
        let mut store = FakePersist::default();
        let (birth, create) = birth();
        assert_eq!(
            store.reserve_controller_birth(&birth, &create),
            Ok(ReserveBirthOutcome::Reserved)
        );
        assert_eq!(
            store.reserve_controller_birth(&birth, &create),
            Ok(ReserveBirthOutcome::ExactReplay)
        );
        let mut changed = create.clone();
        changed.create_attempt_id = RequestNonce::fixture(3);
        assert_eq!(
            store.reserve_controller_birth(&birth, &changed),
            Ok(ReserveBirthOutcome::Conflict)
        );
    }

    #[test]
    fn shared_fake_handles_observe_one_store() {
        let mut writer = SharedFakePersist::default();
        let reader = writer.clone();
        let (birth, create) = birth();
        writer
            .reserve_controller_birth(&birth, &create)
            .expect("reserve birth");
        assert_eq!(
            reader
                .thread_ownership_state(&birth.birth_id)
                .expect("shared ownership"),
            ThreadOwnershipState::Reserved {
                create_attempt_id: create.create_attempt_id,
            }
        );
    }

    #[test]
    fn recovery_quarantines_an_unresolved_create_reservation() {
        let mut store = FakePersist::default();
        let (birth, create) = birth();
        store
            .reserve_controller_birth(&birth, &create)
            .expect("reserve birth");
        let snapshot = store.recover_authority_state().expect("recover");
        assert!(matches!(
            snapshot.ownership.as_slice(),
            [PersistedThreadOwnership {
                state: ThreadOwnershipState::Unknown { create_attempt_id },
                ..
            }] if create_attempt_id == &create.create_attempt_id
        ));
    }

    #[test]
    fn unknown_create_cannot_be_replaced_by_another_attempt() {
        let mut store = FakePersist::default();
        let (birth, create) = birth();
        store
            .reserve_controller_birth(&birth, &create)
            .expect("reserve");
        store
            .resolve_thread_create(ThreadCreateCommit {
                birth_id: birth.birth_id.clone(),
                create_attempt_id: create.create_attempt_id.clone(),
                resolution: ThreadCreateResolution::Unknown,
                evidence_ref: VerifierRef::fixture(4),
            })
            .expect("unknown");
        let conflict = store.resolve_thread_create(ThreadCreateCommit {
            birth_id: birth.birth_id,
            create_attempt_id: RequestNonce::fixture(9),
            resolution: ThreadCreateResolution::Owned {
                thread_ref: PrivateNativeRef::fixture(8),
            },
            evidence_ref: VerifierRef::fixture(5),
        });
        assert_eq!(conflict, Err(PersistError::Conflict));
    }

    fn coordinate_store() -> (
        FakePersist,
        ControllerBirthId,
        RequestNonce,
        PersistedTurnCorrelation,
    ) {
        let mut store = FakePersist::default();
        let (birth, create) = birth();
        store
            .reserve_controller_birth(&birth, &create)
            .expect("reserve birth");
        let thread_scope = NativeCoordinateScope::Thread {
            birth_id: birth.birth_id.clone(),
            create_attempt_id: create.create_attempt_id.clone(),
        };
        let thread_ref = store
            .seal_native_coordinate(
                &thread_scope,
                &SecretNativeCoordinate::thread("native-thread-private").expect("secret"),
            )
            .expect("seal thread");
        store
            .resolve_thread_create(ThreadCreateCommit {
                birth_id: birth.birth_id.clone(),
                create_attempt_id: create.create_attempt_id.clone(),
                resolution: ThreadCreateResolution::Owned {
                    thread_ref: thread_ref.clone(),
                },
                evidence_ref: VerifierRef::fixture(5),
            })
            .expect("resolve owned");
        let correlation = PersistedTurnCorrelation {
            attempt_id: AttemptId::new("attempt-a").expect("attempt"),
            signal_id: SignalId::new("signal-a").expect("signal"),
            birth_id: birth.birth_id.clone(),
            thread_ref,
            turn_write_id: RequestNonce::fixture(6),
            turn_ref: None,
        };
        let attachment_verifier = VerifierRef::fixture(8);
        let admission = claim_admission_fixture(
            "claim-a",
            birth.arm_id.clone(),
            birth.generation,
            correlation.signal_id.clone(),
            &[ProviderEvent {
                provider: "test".to_owned(),
                event_ref: "event-a".to_owned(),
                actor: None,
                observed_at: "1970-01-01T00:00:00Z".to_owned(),
                body: "test".to_owned(),
            }],
            OffsetDateTime::UNIX_EPOCH,
        );
        store
            .admit_claim(
                &admission,
                &PersistedControllerAttachment {
                    attempt_id: correlation.attempt_id.clone(),
                    birth_id: birth.birth_id.clone(),
                    seat_id: birth.seat_id.clone(),
                    arm_id: birth.arm_id.clone(),
                    generation: birth.generation,
                    capability: birth.capability,
                    lease_until: birth.lease_until,
                    verifier_ref: attachment_verifier.clone(),
                    revoked: false,
                },
            )
            .expect("admit claim");
        store
            .record_dispatch_prepared(PreparedDispatchCommit {
                correlation: correlation.clone(),
            })
            .expect("prepare turn");
        store
            .reserve_native_turn_write(
                ValidatedIdlePermit {
                    attempt_id: correlation.attempt_id.clone(),
                    signal_id: correlation.signal_id.clone(),
                    birth_id: correlation.birth_id.clone(),
                    thread_ref: correlation.thread_ref.clone(),
                    arm_id: birth.arm_id.clone(),
                    generation: birth.generation,
                    capability: birth.capability,
                    verifier_ref: attachment_verifier,
                    mutation_epoch: NativeMutationEpoch {
                        birth_id: birth.birth_id.clone(),
                        sequence: 1,
                    },
                    probe_id: RequestNonce::fixture(9),
                    observed_at: OffsetDateTime::UNIX_EPOCH,
                    valid_until: OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
                },
                &correlation,
            )
            .expect("reserve write");
        (store, birth.birth_id, create.create_attempt_id, correlation)
    }

    fn active_proof(
        correlation: &PersistedTurnCorrelation,
        prehash: [u8; 32],
        epoch_sequence: u64,
    ) -> ActiveObservationProof {
        ActiveObservationProof {
            birth_id: correlation.birth_id.clone(),
            create_attempt_id: RequestNonce::fixture(2),
            thread_ref: correlation.thread_ref.clone(),
            seat_id: SeatId::new("seat-a").expect("seat"),
            arm_id: ArmId::new("arm-a").expect("arm"),
            generation: 1,
            capability: ManagedCapability::HandleClaimedSignal,
            attachment_verifier_ref: VerifierRef::fixture(8),
            lease_until: OffsetDateTime::UNIX_EPOCH,
            attempt_id: correlation.attempt_id.clone(),
            signal_id: correlation.signal_id.clone(),
            probe_id: RequestNonce::fixture(50),
            mutation_epoch: NativeMutationEpoch {
                birth_id: correlation.birth_id.clone(),
                sequence: epoch_sequence,
            },
            observed_at: OffsetDateTime::UNIX_EPOCH - time::Duration::seconds(1),
            prehash: crate::controller::ActiveObservationPrehash::new(prehash),
            producer_version: "codex-cli 0.152.1".to_owned(),
            producer_dialect: "thread/read-v2".to_owned(),
        }
    }

    #[test]
    fn active_evidence_replay_binds_prehash_epoch_and_store_key() {
        let (store, _, _, correlation) = coordinate_store();
        let mut first = store.clone();
        let mut second = store;
        second.rekey_active_evidence();
        assert_eq!(
            first.record_active_hold(ActiveHoldCommit {
                proof: active_proof(&correlation, [1; 32], 7),
            }),
            Ok(IdempotentWrite::Recorded)
        );
        assert_eq!(
            first.record_active_hold(ActiveHoldCommit {
                proof: active_proof(&correlation, [1; 32], 7),
            }),
            Ok(IdempotentWrite::ExactReplay)
        );
        assert_eq!(
            first.record_active_hold(ActiveHoldCommit {
                proof: active_proof(&correlation, [2; 32], 7),
            }),
            Err(PersistError::Conflict)
        );
        assert_eq!(
            first.record_active_hold(ActiveHoldCommit {
                proof: active_proof(&correlation, [1; 32], 8),
            }),
            Err(PersistError::Conflict)
        );
        second
            .record_active_hold(ActiveHoldCommit {
                proof: active_proof(&correlation, [1; 32], 7),
            })
            .expect("second store active evidence");
        let first_fingerprint = first
            .recover_authority_state()
            .expect("first snapshot")
            .active_observations[0]
            .fingerprint
            .clone();
        let second_fingerprint = second
            .recover_authority_state()
            .expect("second snapshot")
            .active_observations[0]
            .fingerprint
            .clone();
        assert_ne!(first_fingerprint, second_fingerprint);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn native_coordinate_scopes_reject_every_cross_binding_and_kind() {
        let (mut store, birth_id, create_attempt_id, correlation) = coordinate_store();
        let thread_scope = NativeCoordinateScope::Thread {
            birth_id: birth_id.clone(),
            create_attempt_id: create_attempt_id.clone(),
        };
        let ThreadOwnershipState::Owned {
            create_attempt_id: recovered_create,
            thread_ref,
        } = store.thread_ownership_state(&birth_id).expect("ownership")
        else {
            panic!("owned");
        };
        assert_eq!(recovered_create, create_attempt_id);
        assert_eq!(
            store
                .open_native_coordinate(&thread_scope, &thread_ref)
                .expect("open thread")
                .as_str(),
            Ok("native-thread-private")
        );
        assert_eq!(
            store
                .seal_native_coordinate(
                    &thread_scope,
                    &SecretNativeCoordinate::thread("native-thread-private").expect("secret")
                )
                .expect("replay thread seal"),
            thread_ref
        );
        assert_eq!(
            store.seal_native_coordinate(
                &thread_scope,
                &SecretNativeCoordinate::thread("different-thread").expect("secret")
            ),
            Err(PersistError::Unauthorized)
        );

        let turn_scope = NativeCoordinateScope::Turn {
            birth_id: birth_id.clone(),
            attempt_id: correlation.attempt_id.clone(),
            signal_id: correlation.signal_id.clone(),
            turn_write_id: correlation.turn_write_id.clone(),
        };
        let turn_ref = store
            .seal_native_coordinate(
                &turn_scope,
                &SecretNativeCoordinate::turn("native-turn-private").expect("secret"),
            )
            .expect("seal turn");
        assert!(matches!(
            store.open_native_coordinate(&turn_scope, &turn_ref),
            Err(PersistError::Unauthorized)
        ));
        let mut accepted = correlation.clone();
        accepted.turn_ref = Some(turn_ref.clone());
        store
            .record_native_turn_fact(NativeTurnFactCommit {
                correlation: accepted,
                fact: NativeTurnFact::Accepted {
                    turn_ref: turn_ref.clone(),
                },
                evidence_ref: VerifierRef::fixture(10),
            })
            .expect("commit accepted turn binding");
        assert_eq!(
            store
                .open_native_coordinate(&turn_scope, &turn_ref)
                .expect("open turn")
                .as_str(),
            Ok("native-turn-private")
        );
        assert_eq!(
            store
                .seal_native_coordinate(
                    &turn_scope,
                    &SecretNativeCoordinate::turn("native-turn-private").expect("secret")
                )
                .expect("replay turn seal"),
            turn_ref
        );
        assert_eq!(
            store.seal_native_coordinate(
                &turn_scope,
                &SecretNativeCoordinate::turn("different-turn").expect("secret")
            ),
            Err(PersistError::Unauthorized)
        );

        let wrong_thread_scopes = [
            NativeCoordinateScope::Thread {
                birth_id: birth_id.clone(),
                create_attempt_id: RequestNonce::fixture(99),
            },
            NativeCoordinateScope::Thread {
                birth_id: ControllerBirthId::fixture(99),
                create_attempt_id: create_attempt_id.clone(),
            },
        ];
        for scope in wrong_thread_scopes {
            assert_eq!(
                store.seal_native_coordinate(
                    &scope,
                    &SecretNativeCoordinate::thread("wrong").expect("secret")
                ),
                Err(PersistError::Unauthorized)
            );
            assert!(matches!(
                store.open_native_coordinate(&scope, &thread_ref),
                Err(PersistError::Unauthorized)
            ));
        }

        let wrong_turn_scopes = [
            NativeCoordinateScope::Turn {
                birth_id: ControllerBirthId::fixture(99),
                attempt_id: correlation.attempt_id.clone(),
                signal_id: correlation.signal_id.clone(),
                turn_write_id: correlation.turn_write_id.clone(),
            },
            NativeCoordinateScope::Turn {
                birth_id: birth_id.clone(),
                attempt_id: AttemptId::new("attempt-other").expect("attempt"),
                signal_id: correlation.signal_id.clone(),
                turn_write_id: correlation.turn_write_id.clone(),
            },
            NativeCoordinateScope::Turn {
                birth_id: birth_id.clone(),
                attempt_id: correlation.attempt_id.clone(),
                signal_id: SignalId::new("signal-other").expect("signal"),
                turn_write_id: correlation.turn_write_id.clone(),
            },
            NativeCoordinateScope::Turn {
                birth_id: birth_id.clone(),
                attempt_id: correlation.attempt_id.clone(),
                signal_id: correlation.signal_id.clone(),
                turn_write_id: RequestNonce::fixture(99),
            },
        ];
        for scope in wrong_turn_scopes {
            assert_eq!(
                store.seal_native_coordinate(
                    &scope,
                    &SecretNativeCoordinate::turn("wrong").expect("secret")
                ),
                Err(PersistError::Unauthorized)
            );
            assert!(matches!(
                store.open_native_coordinate(&scope, &turn_ref),
                Err(PersistError::Unauthorized)
            ));
        }
        assert!(matches!(
            store.open_native_coordinate(&turn_scope, &thread_ref),
            Err(PersistError::Unauthorized)
        ));
        assert!(matches!(
            store.open_native_coordinate(&thread_scope, &turn_ref),
            Err(PersistError::Unauthorized)
        ));
        assert_eq!(
            store.seal_native_coordinate(
                &turn_scope,
                &SecretNativeCoordinate::thread("wrong-kind").expect("secret")
            ),
            Err(PersistError::Unauthorized)
        );
        assert_eq!(
            store.seal_native_coordinate(
                &thread_scope,
                &SecretNativeCoordinate::turn("wrong-kind").expect("secret")
            ),
            Err(PersistError::Unauthorized)
        );

        let rendered = format!("{store:?}");
        assert!(!rendered.contains("native-thread-private"));
        assert!(!rendered.contains("native-turn-private"));
        let snapshot = store.recover_authority_state().expect("snapshot");
        let rendered = format!("{snapshot:?}");
        assert!(!rendered.contains("native-thread-private"));
        assert!(!rendered.contains("native-turn-private"));
    }

    fn wire_event(event_ref: &str, body: &str) -> ProviderEvent {
        ProviderEvent {
            provider: "test".to_owned(),
            event_ref: event_ref.to_owned(),
            actor: None,
            observed_at: "1970-01-01T00:00:00Z".to_owned(),
            body: body.to_owned(),
        }
    }

    #[test]
    fn canonical_claim_digest_deterministic_and_field_sensitive() {
        let admission = claim_admission_fixture(
            "claim-a",
            ArmId::new("arm-a").expect("arm"),
            1,
            SignalId::new("signal-a").expect("signal"),
            &[wire_event("event-a", "test")],
            OffsetDateTime::UNIX_EPOCH,
        );
        let digest_of = |admission: &ClaimAdmission| {
            canonical_claim_digest(
                &admission.request_id,
                &admission.arm_id,
                admission.generation,
                &admission.signal_id,
                &admission.event_refs,
                &admission.payload,
            )
        };
        let baseline = digest_of(&admission);
        assert_eq!(digest_of(&admission), baseline);

        let mut variant = admission.clone();
        variant.generation = 2;
        assert_ne!(digest_of(&variant), baseline);

        let mut variant = admission.clone();
        variant.signal_id = SignalId::new("signal-b").expect("signal");
        assert_ne!(digest_of(&variant), baseline);

        let changed_body = claim_admission_fixture(
            "claim-a",
            ArmId::new("arm-a").expect("arm"),
            1,
            SignalId::new("signal-a").expect("signal"),
            &[wire_event("event-a", "changed")],
            OffsetDateTime::UNIX_EPOCH,
        );
        assert_ne!(digest_of(&changed_body), baseline);
        assert_ne!(changed_body.claim_digest, admission.claim_digest);
    }

    #[test]
    fn admission_replay_returns_stored_ref_and_conflicts_on_changed_digest() {
        let mut store = FakePersist::default();
        let (birth, create) = birth();
        store
            .reserve_controller_birth(&birth, &create)
            .expect("reserve");
        let attachment = PersistedControllerAttachment {
            attempt_id: AttemptId::new("attempt-a").expect("attempt"),
            birth_id: birth.birth_id.clone(),
            seat_id: birth.seat_id.clone(),
            arm_id: birth.arm_id.clone(),
            generation: birth.generation,
            capability: birth.capability,
            lease_until: birth.lease_until,
            verifier_ref: VerifierRef::fixture(8),
            revoked: false,
        };
        let admission = claim_admission_fixture(
            "claim-a",
            birth.arm_id.clone(),
            birth.generation,
            SignalId::new("signal-a").expect("signal"),
            &[wire_event("event-a", "test")],
            OffsetDateTime::UNIX_EPOCH,
        );
        let first = store.admit_claim(&admission, &attachment).expect("admit");
        assert_eq!(first.outcome, AdmissionOutcome::Admitted);
        let replay = store.admit_claim(&admission, &attachment).expect("replay");
        assert_eq!(replay.outcome, AdmissionOutcome::ExactReplay);
        assert_eq!(replay.payload_ref, first.payload_ref);
        assert_eq!(replay.attempt_id, first.attempt_id);

        let changed = claim_admission_fixture(
            "claim-a",
            birth.arm_id.clone(),
            birth.generation,
            SignalId::new("signal-a").expect("signal"),
            &[wire_event("event-a", "changed")],
            OffsetDateTime::UNIX_EPOCH,
        );
        assert_eq!(
            store.admit_claim(&changed, &attachment),
            Err(PersistError::Conflict)
        );
    }

    #[test]
    fn admission_forged_digest_and_ref_mismatch_leave_no_state() {
        let mut store = FakePersist::default();
        let (birth, create) = birth();
        store
            .reserve_controller_birth(&birth, &create)
            .expect("reserve");
        let attachment = PersistedControllerAttachment {
            attempt_id: AttemptId::new("attempt-a").expect("attempt"),
            birth_id: birth.birth_id.clone(),
            seat_id: birth.seat_id.clone(),
            arm_id: birth.arm_id.clone(),
            generation: birth.generation,
            capability: birth.capability,
            lease_until: birth.lease_until,
            verifier_ref: VerifierRef::fixture(8),
            revoked: false,
        };
        let admission = claim_admission_fixture(
            "claim-a",
            birth.arm_id.clone(),
            birth.generation,
            SignalId::new("signal-a").expect("signal"),
            &[
                wire_event("event-a", "test-a"),
                wire_event("event-b", "test-b"),
            ],
            OffsetDateTime::UNIX_EPOCH,
        );
        // Forged digest over consistent refs/payload.
        let mut forged = admission.clone();
        let mut digest_bytes = forged.claim_digest.0;
        digest_bytes[0] ^= 0x01;
        forged.claim_digest = ClaimDigest::from_bytes(digest_bytes);
        assert_eq!(
            store.admit_claim(&forged, &attachment),
            Err(PersistError::Conflict)
        );
        // Reordered refs with a matching recomputed digest still fail the
        // ordered refs-vs-payload check.
        let mut reordered = admission.clone();
        let swapped: Vec<EventRef> = reordered
            .event_refs
            .as_slice()
            .iter()
            .rev()
            .cloned()
            .collect();
        reordered.event_refs = BoundedVec::try_from(swapped).expect("refs");
        reordered.claim_digest = canonical_claim_digest(
            &reordered.request_id,
            &reordered.arm_id,
            reordered.generation,
            &reordered.signal_id,
            &reordered.event_refs,
            &reordered.payload,
        );
        assert_eq!(
            store.admit_claim(&reordered, &attachment),
            Err(PersistError::Conflict)
        );
        // Dropped ref with a matching recomputed digest fails the same way.
        let mut dropped = admission.clone();
        let prefix: Vec<EventRef> = dropped.event_refs.as_slice()[..1].to_vec();
        dropped.event_refs = BoundedVec::try_from(prefix).expect("refs");
        dropped.claim_digest = canonical_claim_digest(
            &dropped.request_id,
            &dropped.arm_id,
            dropped.generation,
            &dropped.signal_id,
            &dropped.event_refs,
            &dropped.payload,
        );
        assert_eq!(
            store.admit_claim(&dropped, &attachment),
            Err(PersistError::Conflict)
        );
        // Zero state change: claims, attachments, payload map, request
        // index, and attempt sequence are all untouched, and the valid
        // admission still lands as a fresh write.
        assert!(store.claims.is_empty());
        assert!(store.attachments.is_empty());
        assert!(store.payloads.is_empty());
        assert!(store.claim_attempts.is_empty());
        assert_eq!(store.attempt_seq, 0);
        let snapshot = store.recover_authority_state().expect("snapshot");
        assert!(snapshot.claims.is_empty());
        let record = store
            .admit_claim(&admission, &attachment)
            .expect("valid admit");
        assert_eq!(record.outcome, AdmissionOutcome::Admitted);
    }

    #[test]
    fn provider_event_record_conversion_negatives() {
        let valid = ProviderEventRecord::try_from(&wire_event("event-a", "test")).expect("valid");
        assert_eq!(valid.event_ref.as_str(), "event-a");
        assert_eq!(valid.provider.as_str(), "test");
        assert!(valid.actor.is_none());

        let mut bad_time = wire_event("event-a", "test");
        bad_time.observed_at = "not-a-time".to_owned();
        assert!(ProviderEventRecord::try_from(&bad_time).is_err());

        let mut long_time = wire_event("event-a", "test");
        long_time.observed_at = "x".repeat(65);
        assert!(ProviderEventRecord::try_from(&long_time).is_err());

        assert!(ProviderEventRecord::try_from(&wire_event("", "test")).is_err());

        let mut long_provider = wire_event("event-a", "test");
        long_provider.provider = "x".repeat(65);
        assert!(ProviderEventRecord::try_from(&long_provider).is_err());

        let mut bad_actor = wire_event("event-a", "test");
        bad_actor.actor = Some("has\nnewline".to_owned());
        assert!(ProviderEventRecord::try_from(&bad_actor).is_err());

        let mut long_body = wire_event("event-a", "test");
        long_body.body = "x".repeat(4097);
        assert!(ProviderEventRecord::try_from(&long_body).is_err());
    }

    #[test]
    fn bounded_payload_aggregate_enforced() {
        let records = |count: usize| -> Vec<ProviderEventRecord> {
            (0..count)
                .map(|index| {
                    ProviderEventRecord::try_from(&wire_event(
                        &format!("event-{index}"),
                        &"x".repeat(4096),
                    ))
                    .expect("record")
                })
                .collect()
        };
        assert!(BoundedClaimPayload::try_from(records(32)).is_ok());
        assert!(BoundedClaimPayload::try_from(records(33)).is_err());
        assert!(BoundedClaimPayload::try_from(records(0)).is_err());

        let payload = BoundedClaimPayload::try_from(vec![
            ProviderEventRecord::try_from(&wire_event("event-a", "secret-marker")).expect("record"),
        ])
        .expect("payload");
        let rendered = format!("{payload:?}");
        assert!(!rendered.contains("secret-marker"), "{rendered}");
    }

    #[test]
    fn helper_operations_closed_set() {
        let all = HelperOperations::all();
        assert!(all.allows(HelperOperation::Retrieve));
        assert!(all.allows(HelperOperation::Acknowledge));
        let retrieve_only = HelperOperations::retrieve_only();
        assert!(retrieve_only.allows(HelperOperation::Retrieve));
        assert!(!retrieve_only.allows(HelperOperation::Acknowledge));
    }

    #[test]
    fn grant_verifier_redacted_and_compared() {
        let grant = PersistedHelperGrant {
            grant_verifier: [0x5a; 32],
            seat_id: SeatId::new("seat-a").expect("seat"),
            arm_id: ArmId::new("arm-a").expect("arm"),
            generation: 1,
            birth_id: ControllerBirthId::fixture(1),
            attempt_id: AttemptId::new("attempt-a").expect("attempt"),
            signal_id: SignalId::new("signal-a").expect("signal"),
            claim_digest: ClaimDigest::fixture(3),
            operations: HelperOperations::all(),
            lease_until: OffsetDateTime::UNIX_EPOCH,
            executable_identity: HelperExecutableIdentity {
                image_digest: [0x11; 32],
                file_identity: BoundedToken::new("gearwit-helper").expect("file"),
                build_identity: BoundedToken::new("build-1").expect("build"),
            },
            revoked: false,
        };
        assert_eq!(grant, grant.clone());
        let rendered = format!("{grant:?}");
        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains("5a"));
        assert!(!rendered.contains("gearwit-helper"), "{rendered}");
        assert!(!rendered.contains("build-1"), "{rendered}");
        let mut rotated = grant.clone();
        rotated.grant_verifier = [0x5b; 32];
        assert_ne!(grant, rotated);
    }

    #[test]
    fn non_active_conclusion_mapping() {
        assert_eq!(
            PreWriteConclusion::from(NonActivePreWriteConclusion::IdleStateUnproven),
            PreWriteConclusion::IdleStateUnproven
        );
        let invalidated = NonActivePreWriteConclusion::IdleEpochInvalidated {
            probe_id: RequestNonce::fixture(4),
            expected_epoch: NativeMutationEpoch {
                birth_id: ControllerBirthId::fixture(1),
                sequence: 1,
            },
            observed_epoch: NativeMutationEpoch {
                birth_id: ControllerBirthId::fixture(1),
                sequence: 2,
            },
        };
        assert_eq!(
            PreWriteConclusion::from(invalidated.clone()),
            PreWriteConclusion::IdleEpochInvalidated {
                probe_id: RequestNonce::fixture(4),
                expected_epoch: NativeMutationEpoch {
                    birth_id: ControllerBirthId::fixture(1),
                    sequence: 1,
                },
                observed_epoch: NativeMutationEpoch {
                    birth_id: ControllerBirthId::fixture(1),
                    sequence: 2,
                },
            }
        );
    }
}
