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
    pub(crate) coverage: Option<ClaimCoverageEvidence>,
    pub(crate) drain_witness: Option<ClaimDrainWitness>,
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
    pub(crate) coverage: Option<ClaimCoverageEvidence>,
    pub(crate) drain_witness: Option<ClaimDrainWitness>,
}

/// Test-only declared provider drain. Production coverage constructors stay
/// unavailable until drain integration is qualified. Event refs stay in
/// declared drain order; they are not sorted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimDrainWitness {
    pub(crate) provider: ProviderName,
    pub(crate) drain_filter_scope: BoundedToken<64>,
    pub(crate) event_refs: BoundedVec<EventRef, 1, 64>,
    pub(crate) source_evidence_id: [u8; 32],
}

/// Sealed, bounded claim-coverage proof. Presence or absence participates in
/// [`ClaimDigest`]. The event-batch digest is computed independently of this
/// record so coverage identity cannot be circular.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimCoverageEvidence {
    pub(crate) request_id: ClaimRequestId,
    pub(crate) arm_id: ArmId,
    pub(crate) generation: u64,
    pub(crate) signal_id: SignalId,
    pub(crate) provider: ProviderName,
    pub(crate) drain_filter_scope: BoundedToken<64>,
    pub(crate) drain_baseline: EventRef,
    pub(crate) event_batch_digest: [u8; 32],
    pub(crate) covered_through: EventRef,
    pub(crate) source_evidence_id: [u8; 32],
}

/// Independent digest of the ordered event-ref batch. Coverage evidence
/// stores this value; it is not derived from the coverage record itself.
pub(crate) fn canonical_event_batch_digest(event_refs: &BoundedVec<EventRef, 1, 64>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"gearwit.claim-event-batch.v1\0");
    for event_ref in event_refs.as_slice() {
        mac_field(&mut hasher, event_ref.as_str().as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn mac_coverage(hasher: &mut blake3::Hasher, coverage: Option<&ClaimCoverageEvidence>) {
    match coverage {
        None => mac_field(hasher, b"\x00"),
        Some(evidence) => {
            mac_field(hasher, b"\x01");
            mac_field(hasher, evidence.request_id.as_str().as_bytes());
            mac_field(hasher, evidence.arm_id.as_str().as_bytes());
            mac_field(hasher, &evidence.generation.to_le_bytes());
            mac_field(hasher, evidence.signal_id.as_str().as_bytes());
            mac_field(hasher, evidence.provider.as_str().as_bytes());
            mac_field(hasher, evidence.drain_filter_scope.as_str().as_bytes());
            mac_field(hasher, evidence.drain_baseline.as_str().as_bytes());
            mac_field(hasher, &evidence.event_batch_digest);
            mac_field(hasher, evidence.covered_through.as_str().as_bytes());
            mac_field(hasher, &evidence.source_evidence_id);
        }
    }
}

/// Canonical claim digest over the validated admission fields in fixed order.
/// The encoding is length-prefixed and unambiguous: domain tag, request id,
/// arm id, generation, signal id, ordered event refs, then the ordered event
/// records (ref, provider, actor presence + value, RFC 3339 time, body),
/// then coverage presence and fields. Any validated-field change yields a
/// different digest; transport framing never enters it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn canonical_claim_digest(
    request_id: &ClaimRequestId,
    arm_id: &ArmId,
    generation: u64,
    signal_id: &SignalId,
    event_refs: &BoundedVec<EventRef, 1, 64>,
    payload: &BoundedClaimPayload,
    coverage: Option<&ClaimCoverageEvidence>,
    drain_witness: Option<&ClaimDrainWitness>,
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
    mac_coverage(&mut hasher, coverage);
    mac_drain_witness(&mut hasher, drain_witness);
    ClaimDigest::from_bytes(*hasher.finalize().as_bytes())
}

fn mac_drain_witness(hasher: &mut blake3::Hasher, witness: Option<&ClaimDrainWitness>) {
    match witness {
        None => mac_field(hasher, b"\x00"),
        Some(drain) => {
            mac_field(hasher, b"\x01");
            mac_field(hasher, drain.provider.as_str().as_bytes());
            mac_field(hasher, drain.drain_filter_scope.as_str().as_bytes());
            for event_ref in drain.event_refs.as_slice() {
                mac_field(hasher, event_ref.as_str().as_bytes());
            }
            mac_field(hasher, &drain.source_evidence_id);
        }
    }
}

fn covered_drain_prefix<'a>(
    evidence: &ClaimCoverageEvidence,
    witness: &'a ClaimDrainWitness,
) -> Option<&'a [EventRef]> {
    let drain = witness.event_refs.as_slice();
    let baseline = drain.first()?;
    if baseline != &evidence.drain_baseline {
        return None;
    }
    let covered_at = drain
        .iter()
        .position(|event_ref| event_ref == &evidence.covered_through)?;
    Some(&drain[..=covered_at])
}

fn insert_unique<K: Ord, V>(
    map: &mut BTreeMap<K, V>,
    key: K,
    value: V,
) -> Result<(), PersistError> {
    match map.entry(key) {
        std::collections::btree_map::Entry::Vacant(slot) => {
            slot.insert(value);
            Ok(())
        }
        std::collections::btree_map::Entry::Occupied(_) => Err(PersistError::Conflict),
    }
}

fn claim_is_drain_prefix(claim_refs: &[EventRef], drain: &[EventRef]) -> bool {
    claim_refs.len() <= drain.len() && drain[..claim_refs.len()] == *claim_refs
}

#[allow(clippy::too_many_arguments)]
fn coverage_pair_invalid(
    evidence: Option<&ClaimCoverageEvidence>,
    witness: Option<&ClaimDrainWitness>,
    request_id: &ClaimRequestId,
    arm_id: &ArmId,
    generation: u64,
    signal_id: &SignalId,
    event_refs: &BoundedVec<EventRef, 1, 64>,
    payload: Option<&BoundedClaimPayload>,
) -> bool {
    match (evidence, witness) {
        (None, None) => false,
        (Some(evidence), Some(witness)) => {
            let prefix = covered_drain_prefix(evidence, witness);
            evidence.request_id != *request_id
                || evidence.arm_id != *arm_id
                || evidence.generation != generation
                || evidence.signal_id != *signal_id
                || evidence.provider != witness.provider
                || evidence.drain_filter_scope != witness.drain_filter_scope
                || evidence.source_evidence_id == [0; 32]
                || witness.source_evidence_id == [0; 32]
                || evidence.source_evidence_id != witness.source_evidence_id
                || evidence.event_batch_digest != canonical_event_batch_digest(event_refs)
                || prefix.is_none()
                || !claim_is_drain_prefix(event_refs.as_slice(), witness.event_refs.as_slice())
                || payload.is_some_and(|payload| {
                    payload
                        .events
                        .as_slice()
                        .iter()
                        .any(|event| event.provider != evidence.provider)
                })
        }
        (None, Some(_)) | (Some(_), None) => true,
    }
}

fn coverage_admission_invalid(admission: &ClaimAdmission) -> bool {
    coverage_pair_invalid(
        admission.coverage.as_ref(),
        admission.drain_witness.as_ref(),
        &admission.request_id,
        &admission.arm_id,
        admission.generation,
        &admission.signal_id,
        &admission.event_refs,
        Some(&admission.payload),
    )
}

fn proved_ack_index(
    claim: &PersistedClaimRecord,
    refs: &[EventRef],
    payload: Option<&BoundedClaimPayload>,
) -> Result<usize, PersistError> {
    match (claim.coverage.as_ref(), claim.drain_witness.as_ref()) {
        (None, None) => Ok(0),
        (Some(evidence), Some(witness)) => {
            if coverage_pair_invalid(
                Some(evidence),
                Some(witness),
                &claim.request_id,
                &claim.arm_id,
                claim.generation,
                &claim.signal_id,
                &claim.event_refs,
                payload,
            ) {
                return Err(PersistError::Unauthorized);
            }
            let prefix =
                covered_drain_prefix(evidence, witness).ok_or(PersistError::Unauthorized)?;
            let mut proved = None;
            for (index, event_ref) in refs.iter().enumerate() {
                if prefix.iter().any(|covered| covered == event_ref) {
                    proved = Some(index);
                } else {
                    break;
                }
            }
            proved.ok_or(PersistError::Unauthorized)
        }
        _ => Err(PersistError::Unauthorized),
    }
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
    let drain_witness = Some(synthetic_drain_witness(&payload, &event_refs));
    let coverage = Some(synthetic_claim_coverage(
        &request_id,
        &arm_id,
        generation,
        &signal_id,
        &event_refs,
        &payload,
        drain_witness.as_ref().expect("fixture drain"),
    ));
    let claim_digest = canonical_claim_digest(
        &request_id,
        &arm_id,
        generation,
        &signal_id,
        &event_refs,
        &payload,
        coverage.as_ref(),
        drain_witness.as_ref(),
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
        coverage,
        drain_witness,
    }
}

#[cfg(test)]
pub(crate) fn synthetic_drain_witness(
    payload: &BoundedClaimPayload,
    event_refs: &BoundedVec<EventRef, 1, 64>,
) -> ClaimDrainWitness {
    ClaimDrainWitness {
        provider: payload.events.as_slice()[0].provider.clone(),
        drain_filter_scope: BoundedToken::new("fixture-drain").expect("scope"),
        event_refs: event_refs.clone(),
        source_evidence_id: [0x42; 32],
    }
}

/// Test-only contiguous-prefix coverage through the newest admitted event.
#[cfg(test)]
pub(crate) fn synthetic_claim_coverage(
    request_id: &ClaimRequestId,
    arm_id: &ArmId,
    generation: u64,
    signal_id: &SignalId,
    event_refs: &BoundedVec<EventRef, 1, 64>,
    payload: &BoundedClaimPayload,
    drain: &ClaimDrainWitness,
) -> ClaimCoverageEvidence {
    ClaimCoverageEvidence {
        request_id: request_id.clone(),
        arm_id: arm_id.clone(),
        generation,
        signal_id: signal_id.clone(),
        provider: payload.events.as_slice()[0].provider.clone(),
        drain_filter_scope: drain.drain_filter_scope.clone(),
        drain_baseline: drain.event_refs.as_slice()[0].clone(),
        event_batch_digest: canonical_event_batch_digest(event_refs),
        covered_through: event_refs.as_slice()[event_refs.as_slice().len() - 1].clone(),
        source_evidence_id: drain.source_evidence_id,
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
    pub(crate) const fn acknowledge_only() -> Self {
        Self {
            retrieve: false,
            acknowledge: true,
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
///
/// `grant_ref` is the persisted grant-instance identity minted with the
/// grant: every live binding and revocation scope must present it exactly,
/// so rotation (new verifier plus new ref) fences stale bindings and
/// scopes. Connection multiplexing within one grant is face composition;
/// the store sees one ref per persisted grant.
#[derive(Clone)]
pub struct PersistedHelperGrant {
    pub(crate) grant_verifier: [u8; 32],
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
    pub(crate) executable_identity: HelperExecutableIdentity,
    pub(crate) revoked: bool,
}

impl fmt::Debug for PersistedHelperGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedHelperGrant")
            .field("grant_verifier", &"[redacted]")
            .field("grant_ref", &self.grant_ref)
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
            && self.grant_ref == other.grant_ref
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

/// Private provenance of a materialization permit. Fresh use revalidates
/// current generation/lease/lifecycle; exact replay alone receives the
/// frozen timing exception.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PermitProvenance {
    Fresh,
    ExactReplay,
}

/// Private, non-Clone, non-serializable permit minted only after store
/// validation. Recorded metadata never authorizes content access by itself.
#[derive(Debug, Eq, PartialEq)]
pub struct ClaimMaterializationPermit {
    grant_ref: VerifierRef,
    binding_digest: [u8; 32],
    request_id: RequestNonce,
    retrieval_id: RetrievalId,
    claim_digest: ClaimDigest,
    payload_ref: ClaimPayloadRef,
    provenance: PermitProvenance,
}

/// Recorded retrieve metadata paired with a consuming materialization permit.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthorizedRetrieve {
    pub recorded: RecordedRetrieveResult,
    pub permit: ClaimMaterializationPermit,
}

/// Retired grant identity. Rotation fences both the grant-ref and the
/// verifier; neither may be reintroduced as a live credential.
#[derive(Clone, Eq, PartialEq)]
pub struct PersistedRetiredGrant {
    pub(crate) grant_ref: VerifierRef,
    pub(crate) grant_verifier: [u8; 32],
}

impl fmt::Debug for PersistedRetiredGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedRetiredGrant")
            .field("grant_ref", &self.grant_ref)
            .field("grant_verifier", &"[redacted]")
            .finish()
    }
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

/// Content-free persisted retrieve replay metadata. No body is duplicated;
/// content resolves through the immutable [`ClaimPayloadRef`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedRetrieveReplay {
    pub(crate) request_id: RequestNonce,
    pub(crate) binding_digest: [u8; 32],
    pub(crate) canonical_body_digest: CanonicalBodyDigest,
    pub(crate) result: RecordedRetrieveResult,
}

/// Content-free persisted acknowledge replay metadata. The actual request
/// identity (retrieval plus cursor) is retained alongside the digests so a
/// reused or forged digest over changed fields cannot replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedAckReplay {
    pub(crate) request_id: RequestNonce,
    pub(crate) binding_digest: [u8; 32],
    pub(crate) canonical_body_digest: CanonicalBodyDigest,
    pub(crate) retrieval_id: RetrievalId,
    pub(crate) cursor: EventRef,
    pub(crate) result: AcknowledgeResult,
}

/// Content-free retrieval index row: which complete binding originated each
/// recorded retrieval. Materialization and acknowledgment must present the
/// originating binding identity, not just an equal claim reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedRetrievalRecord {
    pub(crate) retrieval_id: RetrievalId,
    pub(crate) binding_digest: [u8; 32],
    pub(crate) result: RecordedRetrieveResult,
}

/// Durable handled coverage for one attempt: the furthest contiguously
/// covered cursor and whether it reaches the claim's newest event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedHandledCoverage {
    pub(crate) attempt_id: AttemptId,
    pub(crate) signal_id: SignalId,
    pub(crate) cursor: EventRef,
    pub(crate) covered_through_newest: bool,
}

/// Durable re-arm join position: one atomic join per arm, generation,
/// attempt, and signal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedRearmJoin {
    pub(crate) arm_id: ArmId,
    pub(crate) generation: u64,
    pub(crate) attempt_id: AttemptId,
    pub(crate) signal_id: SignalId,
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
    pub helper_grants: Vec<PersistedHelperGrant>,
    pub retired_helper_grants: Vec<PersistedRetiredGrant>,
    pub retrieve_replays: Vec<PersistedRetrieveReplay>,
    pub retrieval_bindings: Vec<PersistedRetrievalRecord>,
    pub ack_replays: Vec<PersistedAckReplay>,
    pub handled_coverage: Vec<PersistedHandledCoverage>,
    pub rearmed_joins: Vec<PersistedRearmJoin>,
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
    fn persist_helper_grant(&mut self, grant: &PersistedHelperGrant) -> Result<(), PersistError>;
    fn revoke_helper_grant(
        &mut self,
        scope: HelperRevocationScope,
    ) -> Result<IdempotentWrite, PersistError>;
    fn record_retrieve_exchange(
        &mut self,
        exchange: &RetrieveExchange,
    ) -> Result<IdempotentResult<AuthorizedRetrieve>, PersistError>;
    fn materialize_claimed_batch(
        &self,
        binding: &ValidatedHelperBinding,
        permit: ClaimMaterializationPermit,
    ) -> Result<BoundedClaimPayload, PersistError>;
    fn acknowledge_retrieved_batch(
        &mut self,
        binding: &ValidatedHelperBinding,
        request: &AcknowledgeRequest,
    ) -> Result<IdempotentResult<AcknowledgeResult>, PersistError>;
    fn try_rearm_join(&mut self, scope: RearmJoinScope) -> Result<RearmJoinResult, PersistError>;
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
    grants: Vec<PersistedHelperGrant>,
    retired_grants: Vec<PersistedRetiredGrant>,
    retrieve_replays: BTreeMap<RequestNonce, PersistedRetrieveReplay>,
    ack_replays: BTreeMap<RequestNonce, PersistedAckReplay>,
    retrievals: BTreeMap<RetrievalId, PersistedRetrievalRecord>,
    handled: BTreeMap<AttemptId, PersistedHandledCoverage>,
    rearmed: BTreeSet<(ArmId, u64, AttemptId, SignalId)>,
    now: OffsetDateTime,
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
            grants: Vec::new(),
            retired_grants: Vec::new(),
            retrieve_replays: BTreeMap::new(),
            ack_replays: BTreeMap::new(),
            retrievals: BTreeMap::new(),
            handled: BTreeMap::new(),
            rearmed: BTreeSet::new(),
            now: OffsetDateTime::UNIX_EPOCH,
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

    fn persist_helper_grant(&mut self, grant: &PersistedHelperGrant) -> Result<(), PersistError> {
        self.with_store(|store| store.persist_helper_grant(grant))
    }

    fn revoke_helper_grant(
        &mut self,
        scope: HelperRevocationScope,
    ) -> Result<IdempotentWrite, PersistError> {
        self.with_store(|store| store.revoke_helper_grant(scope))
    }

    fn record_retrieve_exchange(
        &mut self,
        exchange: &RetrieveExchange,
    ) -> Result<IdempotentResult<AuthorizedRetrieve>, PersistError> {
        self.with_store(|store| store.record_retrieve_exchange(exchange))
    }

    fn materialize_claimed_batch(
        &self,
        binding: &ValidatedHelperBinding,
        permit: ClaimMaterializationPermit,
    ) -> Result<BoundedClaimPayload, PersistError> {
        self.with_store(|store| store.materialize_claimed_batch(binding, permit))
    }

    fn acknowledge_retrieved_batch(
        &mut self,
        binding: &ValidatedHelperBinding,
        request: &AcknowledgeRequest,
    ) -> Result<IdempotentResult<AcknowledgeResult>, PersistError> {
        self.with_store(|store| store.acknowledge_retrieved_batch(binding, request))
    }

    fn try_rearm_join(&mut self, scope: RearmJoinScope) -> Result<RearmJoinResult, PersistError> {
        self.with_store(|store| store.try_rearm_join(scope))
    }

    fn recover_authority_state(&mut self) -> Result<RecoverySnapshot, PersistError> {
        self.with_store(FakePersist::recover_authority_state)
    }
}

/// Canonical helper-binding digest for replay identity: the complete live
/// binding in fixed order. Same binding bytes always digest identically;
/// any bound-field change yields a different digest.
fn canonical_binding_digest(binding: &ValidatedHelperBinding) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"gearwit.helper-binding.v1\0");
    mac_field(&mut hasher, binding.grant_ref.bytes());
    mac_field(&mut hasher, binding.seat_id.as_str().as_bytes());
    mac_field(&mut hasher, binding.arm_id.as_str().as_bytes());
    mac_field(&mut hasher, &binding.generation.to_le_bytes());
    mac_field(&mut hasher, &binding.birth_id.0);
    mac_field(&mut hasher, binding.attempt_id.as_str().as_bytes());
    mac_field(&mut hasher, binding.signal_id.as_str().as_bytes());
    mac_field(&mut hasher, &binding.claim_digest.0);
    mac_field(
        &mut hasher,
        &[u8::from(
            binding.operations.allows(HelperOperation::Retrieve),
        )],
    );
    mac_field(
        &mut hasher,
        &[u8::from(
            binding.operations.allows(HelperOperation::Acknowledge),
        )],
    );
    mac_field(
        &mut hasher,
        &binding.lease_until.unix_timestamp_nanos().to_le_bytes(),
    );
    *hasher.finalize().as_bytes()
}

/// Canonical retrieve-request body digest over the authenticated binding
/// identity plus the request nonce. The operation is bound by the domain
/// tag, so a retrieve digest is never valid as an acknowledge digest. The
/// claimed-batch face computes the identical encoding; the sealed port
/// recomputes and compares before replay lookup or mutation.
pub(crate) fn canonical_retrieve_body_digest(
    binding_digest: &[u8; 32],
    request_id: &RequestNonce,
) -> CanonicalBodyDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"gearwit.retrieve-request.v1\0");
    mac_field(&mut hasher, binding_digest);
    mac_field(&mut hasher, &request_id.0);
    CanonicalBodyDigest::from_bytes(*hasher.finalize().as_bytes())
}

/// Canonical acknowledge-request body digest over the authenticated binding
/// identity plus the validated retrieval and cursor. Same domain-separation
/// and recompute discipline as retrieve.
pub(crate) fn canonical_ack_body_digest(
    binding_digest: &[u8; 32],
    request_id: &RequestNonce,
    retrieval_id: &RetrievalId,
    cursor: &EventRef,
) -> CanonicalBodyDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"gearwit.ack-request.v1\0");
    mac_field(&mut hasher, binding_digest);
    mac_field(&mut hasher, &request_id.0);
    mac_field(&mut hasher, &retrieval_id.0);
    mac_field(&mut hasher, cursor.as_str().as_bytes());
    CanonicalBodyDigest::from_bytes(*hasher.finalize().as_bytes())
}

/// Content-free helper snapshot sections: verifier records, replay
/// metadata, handled coverage, and join positions. No bodies included.
struct HelperSnapshotSections {
    grants: Vec<PersistedHelperGrant>,
    retired_grants: Vec<PersistedRetiredGrant>,
    retrieve_replays: Vec<PersistedRetrieveReplay>,
    retrieval_bindings: Vec<PersistedRetrievalRecord>,
    ack_replays: Vec<PersistedAckReplay>,
    handled_coverage: Vec<PersistedHandledCoverage>,
    rearmed_joins: Vec<PersistedRearmJoin>,
}

impl FakePersist {
    /// Test-controlled clock for helper timestamps and lease checks.
    /// Defaults to the Unix epoch; production backends read wall time.
    pub fn set_now(&mut self, now: OffsetDateTime) {
        self.now = now;
    }

    /// Content-free helper snapshot sections: verifier records, replay
    /// metadata, handled coverage, and join positions. No bodies included.
    fn helper_snapshot(&self) -> HelperSnapshotSections {
        HelperSnapshotSections {
            grants: self.grants.clone(),
            retired_grants: self.retired_grants.clone(),
            retrieve_replays: self.retrieve_replays.values().cloned().collect(),
            retrieval_bindings: self.retrievals.values().cloned().collect(),
            ack_replays: self.ack_replays.values().cloned().collect(),
            handled_coverage: self.handled.values().cloned().collect(),
            rearmed_joins: self
                .rearmed
                .iter()
                .map(
                    |(arm_id, generation, attempt_id, signal_id)| PersistedRearmJoin {
                        arm_id: arm_id.clone(),
                        generation: *generation,
                        attempt_id: attempt_id.clone(),
                        signal_id: signal_id.clone(),
                    },
                )
                .collect(),
        }
    }

    fn helper_grant(
        &self,
        birth_id: &ControllerBirthId,
        attempt_id: &AttemptId,
    ) -> Option<&PersistedHelperGrant> {
        self.grants
            .iter()
            .find(|grant| grant.birth_id == *birth_id && grant.attempt_id == *attempt_id)
    }

    fn helper_grant_mut(
        &mut self,
        birth_id: &ControllerBirthId,
        attempt_id: &AttemptId,
    ) -> Option<&mut PersistedHelperGrant> {
        self.grants
            .iter_mut()
            .find(|grant| grant.birth_id == *birth_id && grant.attempt_id == *attempt_id)
    }

    fn quarantine_reserved_ownership(&mut self) {
        for state in self.ownership.values_mut() {
            if let ThreadOwnershipState::Reserved { create_attempt_id } = state {
                *state = ThreadOwnershipState::Unknown {
                    create_attempt_id: create_attempt_id.clone(),
                };
            }
        }
    }

    fn validate_recovered_coverage(&self) -> Result<(), PersistError> {
        for claim in self.claims.values() {
            let payload = self.payloads.get(&claim.payload_ref);
            if coverage_pair_invalid(
                claim.coverage.as_ref(),
                claim.drain_witness.as_ref(),
                &claim.request_id,
                &claim.arm_id,
                claim.generation,
                &claim.signal_id,
                &claim.event_refs,
                payload,
            ) {
                return Err(PersistError::Conflict);
            }
            if let Some(payload) = payload {
                let refs_match = claim.event_refs.as_slice().iter().eq(payload
                    .events
                    .as_slice()
                    .iter()
                    .map(|record| &record.event_ref));
                if !refs_match {
                    return Err(PersistError::Conflict);
                }
                let digest = canonical_claim_digest(
                    &claim.request_id,
                    &claim.arm_id,
                    claim.generation,
                    &claim.signal_id,
                    &claim.event_refs,
                    payload,
                    claim.coverage.as_ref(),
                    claim.drain_witness.as_ref(),
                );
                if digest != claim.claim_digest {
                    return Err(PersistError::Conflict);
                }
            } else if claim.coverage.is_some() || claim.drain_witness.is_some() {
                return Err(PersistError::PayloadUnavailable);
            }
        }
        Ok(())
    }

    fn helper_request_nonce_collision(&self) -> bool {
        self.retrieve_replays
            .keys()
            .any(|nonce| self.ack_replays.contains_key(nonce))
    }

    fn grant_identity_retired(&self, grant: &PersistedHelperGrant) -> bool {
        self.retired_grants.iter().any(|retired| {
            retired.grant_ref == grant.grant_ref
                || bool::from(retired.grant_verifier.ct_eq(&grant.grant_verifier))
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_lines)]
    fn restore_from_snapshot(
        snapshot: RecoverySnapshot,
        payloads: BTreeMap<ClaimPayloadRef, BoundedClaimPayload>,
    ) -> Result<Self, PersistError> {
        let mut store = Self::default();
        for arm in snapshot.arms {
            insert_unique(&mut store.arms, arm.arm_id.clone(), arm)?;
        }
        for claim in snapshot.claims {
            insert_unique(
                &mut store.claim_attempts,
                claim.request_id.clone(),
                claim.attempt_id.clone(),
            )?;
            insert_unique(&mut store.claims, claim.request_id.clone(), claim)?;
        }
        store.payloads = payloads;
        for attachment in snapshot.attachments {
            insert_unique(
                &mut store.attachments,
                attachment.attempt_id.clone(),
                attachment,
            )?;
        }
        for birth in snapshot.controller_births {
            insert_unique(&mut store.births, birth.birth_id.clone(), birth)?;
        }
        for ownership in snapshot.ownership {
            insert_unique(
                &mut store.ownership,
                ownership.birth_id.clone(),
                ownership.state,
            )?;
        }
        for correlation in snapshot.turn_correlations {
            insert_unique(
                &mut store.prepared,
                correlation.attempt_id.clone(),
                correlation,
            )?;
        }
        for reservation in snapshot.reservations {
            insert_unique(
                &mut store.reservations,
                reservation.correlation.attempt_id.clone(),
                reservation,
            )?;
        }
        for evidence in snapshot.native_write_evidence {
            insert_unique(
                &mut store.write_evidence,
                evidence.correlation.attempt_id.clone(),
                evidence.evidence,
            )?;
            insert_unique(
                &mut store.write_evidence_refs,
                evidence.correlation.attempt_id.clone(),
                evidence.evidence_ref,
            )?;
        }
        for facts in snapshot.native_turn_facts {
            insert_unique(&mut store.turn_facts, facts.attempt_id.clone(), facts.facts)?;
        }
        for reconciliation in snapshot.reconciliations {
            insert_unique(
                &mut store.reconciliations,
                reconciliation.attempt_id.clone(),
                reconciliation.disposition,
            )?;
        }
        for conclusion in snapshot.prewrite_conclusions {
            insert_unique(
                &mut store.prewrite,
                conclusion.attempt_id.clone(),
                conclusion,
            )?;
        }
        for observation in snapshot.active_observations {
            insert_unique(
                &mut store.active_observations,
                observation.attempt_id.clone(),
                observation,
            )?;
        }
        store.grants = snapshot.helper_grants;
        store.retired_grants = snapshot.retired_helper_grants;
        for replay in snapshot.retrieve_replays {
            insert_unique(
                &mut store.retrieve_replays,
                replay.request_id.clone(),
                replay,
            )?;
        }
        for record in snapshot.retrieval_bindings {
            insert_unique(&mut store.retrievals, record.retrieval_id.clone(), record)?;
        }
        for replay in snapshot.ack_replays {
            insert_unique(&mut store.ack_replays, replay.request_id.clone(), replay)?;
        }
        for coverage in snapshot.handled_coverage {
            insert_unique(&mut store.handled, coverage.attempt_id.clone(), coverage)?;
        }
        for join in snapshot.rearmed_joins {
            let key = (
                join.arm_id.clone(),
                join.generation,
                join.attempt_id.clone(),
                join.signal_id.clone(),
            );
            if !store.rearmed.insert(key) {
                return Err(PersistError::Conflict);
            }
        }
        store.attempt_seq = snapshot.attempt_seq;
        if store.helper_request_nonce_collision() {
            return Err(PersistError::Conflict);
        }
        store.validate_recovered_coverage()?;
        store.validate_restored_helper_invariants()?;
        Ok(store)
    }

    #[cfg(test)]
    fn validate_restored_helper_invariants(&self) -> Result<(), PersistError> {
        let mut grant_keys = BTreeSet::new();
        for grant in &self.grants {
            if !grant_keys.insert((grant.birth_id.clone(), grant.attempt_id.clone())) {
                return Err(PersistError::Conflict);
            }
            if self.grant_identity_retired(grant) {
                return Err(PersistError::Conflict);
            }
        }
        for replay in self.retrieve_replays.values() {
            let stored = self
                .retrievals
                .get(&replay.result.retrieval_id)
                .ok_or(PersistError::Conflict)?;
            if stored.binding_digest != replay.binding_digest || stored.result != replay.result {
                return Err(PersistError::Conflict);
            }
        }
        for replay in self.ack_replays.values() {
            let stored = self
                .retrievals
                .get(&replay.retrieval_id)
                .ok_or(PersistError::Conflict)?;
            if stored.result.retrieval_id != replay.retrieval_id {
                return Err(PersistError::Conflict);
            }
        }
        for coverage in self.handled.values() {
            let claim = self
                .claim_for_attempt(&coverage.attempt_id)
                .ok_or(PersistError::Conflict)?;
            if !claim
                .event_refs
                .as_slice()
                .iter()
                .any(|event_ref| event_ref == &coverage.cursor)
            {
                return Err(PersistError::Conflict);
            }
        }
        for (arm_id, generation, attempt_id, signal_id) in &self.rearmed {
            let claim = self
                .claim_for_attempt(attempt_id)
                .ok_or(PersistError::Conflict)?;
            if claim.arm_id != *arm_id
                || claim.generation != *generation
                || claim.signal_id != *signal_id
            {
                return Err(PersistError::Conflict);
            }
        }
        Ok(())
    }

    fn mint_retrieve_permit(
        binding: &ValidatedHelperBinding,
        request_id: &RequestNonce,
        recorded: &RecordedRetrieveResult,
        provenance: PermitProvenance,
    ) -> ClaimMaterializationPermit {
        ClaimMaterializationPermit {
            grant_ref: binding.grant_ref.clone(),
            binding_digest: canonical_binding_digest(binding),
            request_id: request_id.clone(),
            retrieval_id: recorded.retrieval_id.clone(),
            claim_digest: binding.claim_digest.clone(),
            payload_ref: recorded.claim_payload_ref.clone(),
            provenance,
        }
    }

    fn claim_for_attempt(&self, attempt_id: &AttemptId) -> Option<&PersistedClaimRecord> {
        self.claims
            .values()
            .find(|claim| claim.attempt_id == *attempt_id)
    }

    /// Validate a grant mint or re-issue against complete current
    /// authority: the admitted claim tuple, a live matching controller
    /// attachment and birth, current arm generation, a future lease, no
    /// controller loss, and an attempt that is not helper-closed. Reads
    /// live store state only; recovered metadata never mints authority.
    fn validate_grant_mint(&self, grant: &PersistedHelperGrant) -> Result<(), PersistError> {
        let claim = self
            .claim_for_attempt(&grant.attempt_id)
            .ok_or(PersistError::Conflict)?;
        if claim.claim_digest != grant.claim_digest
            || claim.arm_id != grant.arm_id
            || claim.generation != grant.generation
            || claim.signal_id != grant.signal_id
        {
            return Err(PersistError::Conflict);
        }
        let attachment = self
            .attachments
            .get(&grant.attempt_id)
            .ok_or(PersistError::Conflict)?;
        if attachment.revoked
            || attachment.birth_id != grant.birth_id
            || attachment.seat_id != grant.seat_id
            || attachment.arm_id != grant.arm_id
        {
            return Err(PersistError::Conflict);
        }
        let birth = self
            .births
            .get(&grant.birth_id)
            .ok_or(PersistError::Conflict)?;
        if birth.revoked || birth.arm_id != grant.arm_id || birth.seat_id != grant.seat_id {
            return Err(PersistError::Conflict);
        }
        let arm = self.arms.get(&grant.arm_id).ok_or(PersistError::Conflict)?;
        if arm.generation != grant.generation
            || arm.seat_id != grant.seat_id
            || arm.capability != attachment.capability
            || arm.coverage_until <= self.now
        {
            return Err(PersistError::Conflict);
        }
        if attachment.generation != grant.generation || attachment.lease_until <= self.now {
            return Err(PersistError::Conflict);
        }
        if birth.generation != grant.generation
            || birth.capability != attachment.capability
            || birth.lease_until <= self.now
        {
            return Err(PersistError::Conflict);
        }
        if grant.lease_until <= self.now
            || grant.lease_until > attachment.lease_until
            || grant.lease_until > birth.lease_until
            || grant.lease_until > arm.coverage_until
        {
            return Err(PersistError::Conflict);
        }
        if self.attempt_lost(&grant.attempt_id)
            || self.handled_complete(&grant.attempt_id)
            || self.attempt_terminal(&grant.attempt_id)
        {
            return Err(PersistError::Conflict);
        }
        Ok(())
    }

    /// Authenticate a live helper binding against the persisted grant and
    /// admitted claim. This runs on every operation including exact replay:
    /// the grant exists, the presented ref equals the persisted grant ref,
    /// every bound field matches, both sides authorize the operation, and
    /// the binding digest matches the admitted claim. No lifecycle, timing,
    /// or revocation state is consulted here.
    fn authenticate_binding(
        &self,
        binding: &ValidatedHelperBinding,
        operation: HelperOperation,
    ) -> Result<&PersistedHelperGrant, PersistError> {
        let grant = self
            .helper_grant(&binding.birth_id, &binding.attempt_id)
            .ok_or(PersistError::Unauthorized)?;
        // VerifierRef equality is constant-time by construction.
        if grant.grant_ref != binding.grant_ref {
            return Err(PersistError::Unauthorized);
        }
        if grant.seat_id != binding.seat_id
            || grant.arm_id != binding.arm_id
            || grant.generation != binding.generation
            || grant.signal_id != binding.signal_id
            || grant.claim_digest != binding.claim_digest
            || grant.operations != binding.operations
            || grant.lease_until != binding.lease_until
            || !grant.operations.allows(operation)
        {
            return Err(PersistError::Unauthorized);
        }
        let claim = self
            .claim_for_attempt(&binding.attempt_id)
            .ok_or(PersistError::Unauthorized)?;
        if claim.claim_digest != binding.claim_digest
            || claim.arm_id != binding.arm_id
            || claim.generation != binding.generation
            || claim.signal_id != binding.signal_id
        {
            return Err(PersistError::Unauthorized);
        }
        Ok(grant)
    }

    /// Enforce sticky revocation for grant, controller attachment, and
    /// birth. Mandatory on every path including exact replay and
    /// re-presentation: revocation is trust, never lifecycle.
    fn enforce_unrevoked(&self, binding: &ValidatedHelperBinding) -> Result<(), PersistError> {
        let grant = self
            .helper_grant(&binding.birth_id, &binding.attempt_id)
            .ok_or(PersistError::Unauthorized)?;
        if grant.revoked {
            return Err(PersistError::Unauthorized);
        }
        let attachment = self
            .attachments
            .get(&binding.attempt_id)
            .ok_or(PersistError::Unauthorized)?;
        if attachment.revoked {
            return Err(PersistError::Unauthorized);
        }
        let birth = self
            .births
            .get(&binding.birth_id)
            .ok_or(PersistError::Unauthorized)?;
        if birth.revoked {
            return Err(PersistError::Unauthorized);
        }
        Ok(())
    }

    fn attempt_lost(&self, attempt_id: &AttemptId) -> bool {
        self.turn_facts.get(attempt_id).is_some_and(|facts| {
            facts
                .iter()
                .any(|fact| matches!(fact, NativeTurnFact::ControllerLost))
        })
    }

    fn attempt_terminal(&self, attempt_id: &AttemptId) -> bool {
        self.turn_facts.get(attempt_id).is_some_and(|facts| {
            facts
                .iter()
                .any(|fact| matches!(fact, NativeTurnFact::Terminal { .. }))
        })
    }

    fn handled_complete(&self, attempt_id: &AttemptId) -> bool {
        self.handled
            .get(attempt_id)
            .is_some_and(|coverage| coverage.covered_through_newest)
    }

    /// Authorize an unseen (non-replay) helper request against current
    /// authority and attempt lifecycle. Exact replay bypasses all of this;
    /// revocation is enforced separately and is never bypassed.
    ///
    /// Credential staleness (leases, generation currency, attachment/birth
    /// association) fails Unauthorized. Attempt-lifecycle closure (loss,
    /// handled completion, helper-closed retrieve) fails `InvalidTransition`:
    /// the request is well authenticated but the attempt no longer accepts
    /// fresh work of that kind.
    fn authorize_fresh_use(
        &self,
        binding: &ValidatedHelperBinding,
        operation: HelperOperation,
    ) -> Result<(), PersistError> {
        let grant = self
            .helper_grant(&binding.birth_id, &binding.attempt_id)
            .ok_or(PersistError::Unauthorized)?;
        if grant.operations != binding.operations || grant.lease_until != binding.lease_until {
            return Err(PersistError::Unauthorized);
        }
        if grant.lease_until <= self.now || binding.lease_until <= self.now {
            return Err(PersistError::Unauthorized);
        }
        let arm = self
            .arms
            .get(&binding.arm_id)
            .ok_or(PersistError::Unauthorized)?;
        if arm.generation != binding.generation
            || arm.seat_id != binding.seat_id
            || arm.coverage_until <= self.now
        {
            return Err(PersistError::Unauthorized);
        }
        let attachment = self
            .attachments
            .get(&binding.attempt_id)
            .ok_or(PersistError::Unauthorized)?;
        if attachment.birth_id != binding.birth_id
            || attachment.seat_id != binding.seat_id
            || attachment.arm_id != binding.arm_id
            || attachment.generation != binding.generation
            || attachment.capability != arm.capability
            || attachment.lease_until <= self.now
        {
            return Err(PersistError::Unauthorized);
        }
        let birth = self
            .births
            .get(&binding.birth_id)
            .ok_or(PersistError::Unauthorized)?;
        if birth.revoked
            || birth.arm_id != binding.arm_id
            || birth.seat_id != binding.seat_id
            || birth.generation != binding.generation
            || birth.capability != arm.capability
            || birth.lease_until <= self.now
        {
            return Err(PersistError::Unauthorized);
        }
        if grant.lease_until > attachment.lease_until
            || grant.lease_until > birth.lease_until
            || grant.lease_until > arm.coverage_until
        {
            return Err(PersistError::Unauthorized);
        }
        if self.attempt_lost(&binding.attempt_id)
            || self.handled_complete(&binding.attempt_id)
            || self.attempt_terminal(&binding.attempt_id)
        {
            return Err(PersistError::InvalidTransition);
        }
        let _ = operation;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn drop_payload(&mut self, payload_ref: &ClaimPayloadRef) -> bool {
        self.payloads.remove(payload_ref).is_some()
    }

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
            admission.coverage.as_ref(),
            admission.drain_witness.as_ref(),
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
        if coverage_admission_invalid(admission) {
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
                && existing.coverage == admission.coverage
                && existing.drain_witness == admission.drain_witness
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
            coverage: admission.coverage.clone(),
            drain_witness: admission.drain_witness.clone(),
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

    fn persist_helper_grant(&mut self, grant: &PersistedHelperGrant) -> Result<(), PersistError> {
        self.validate_grant_mint(grant)?;
        if self.grant_identity_retired(grant) {
            return Err(PersistError::Conflict);
        }
        if let Some(existing) = self.helper_grant(&grant.birth_id, &grant.attempt_id) {
            if existing == grant {
                return Ok(());
            }
            if existing.revoked {
                return Err(PersistError::Conflict);
            }
            // Recovery re-issue replaces the verifier, ref, and lease of a
            // live grant; the bound identity tuple must be identical or the
            // reissue is invalid.
            if existing.seat_id != grant.seat_id
                || existing.arm_id != grant.arm_id
                || existing.generation != grant.generation
                || existing.birth_id != grant.birth_id
                || existing.attempt_id != grant.attempt_id
                || existing.signal_id != grant.signal_id
                || existing.claim_digest != grant.claim_digest
                || existing.operations != grant.operations
                || existing.executable_identity != grant.executable_identity
            {
                return Err(PersistError::Conflict);
            }
            let same_ref = existing.grant_ref == grant.grant_ref;
            let same_verifier = bool::from(existing.grant_verifier.ct_eq(&grant.grant_verifier));
            if same_ref || same_verifier {
                return Err(PersistError::Conflict);
            }
            let retired = PersistedRetiredGrant {
                grant_ref: existing.grant_ref.clone(),
                grant_verifier: existing.grant_verifier,
            };
            if let Some(slot) = self.helper_grant_mut(&grant.birth_id, &grant.attempt_id) {
                *slot = grant.clone();
            }
            self.retired_grants.push(retired);
            return Ok(());
        }
        self.grants.push(grant.clone());
        Ok(())
    }

    fn revoke_helper_grant(
        &mut self,
        scope: HelperRevocationScope,
    ) -> Result<IdempotentWrite, PersistError> {
        // Revocation names the exact persisted grant instance: a stale
        // scope from before rotation cannot affect the replacement grant.
        let grant = self
            .helper_grant_mut(&scope.birth_id, &scope.attempt_id)
            .ok_or(PersistError::Unauthorized)?;
        if grant.grant_ref != scope.grant_ref {
            return Err(PersistError::Unauthorized);
        }
        if grant.revoked {
            return Ok(IdempotentWrite::ExactReplay);
        }
        grant.revoked = true;
        Ok(IdempotentWrite::Recorded)
    }

    fn record_retrieve_exchange(
        &mut self,
        exchange: &RetrieveExchange,
    ) -> Result<IdempotentResult<AuthorizedRetrieve>, PersistError> {
        // Mandatory on every call including replay: complete binding
        // authentication plus sticky revocation. Lifecycle/timing below
        // applies to unseen requests only.
        self.authenticate_binding(&exchange.binding, HelperOperation::Retrieve)?;
        self.enforce_unrevoked(&exchange.binding)?;
        let binding_digest = canonical_binding_digest(&exchange.binding);
        let recomputed = canonical_retrieve_body_digest(&binding_digest, &exchange.request_id);
        if recomputed != exchange.canonical_body_digest {
            return Err(PersistError::Conflict);
        }
        if self.ack_replays.contains_key(&exchange.request_id) {
            return Err(PersistError::Conflict);
        }
        if let Some(stored) = self.retrieve_replays.get(&exchange.request_id) {
            return if stored.binding_digest == binding_digest
                && stored.canonical_body_digest == exchange.canonical_body_digest
            {
                let permit = Self::mint_retrieve_permit(
                    &exchange.binding,
                    &exchange.request_id,
                    &stored.result,
                    PermitProvenance::ExactReplay,
                );
                Ok(IdempotentResult::ExactReplay(AuthorizedRetrieve {
                    recorded: stored.result.clone(),
                    permit,
                }))
            } else {
                Err(PersistError::Conflict)
            };
        }
        self.authorize_fresh_use(&exchange.binding, HelperOperation::Retrieve)?;
        let claim = self
            .claim_for_attempt(&exchange.binding.attempt_id)
            .ok_or(PersistError::Unauthorized)?
            .clone();
        if !self.payloads.contains_key(&claim.payload_ref) {
            return Err(PersistError::PayloadUnavailable);
        }
        let refs = claim.event_refs.as_slice();
        let newest = refs.last().ok_or(PersistError::InvalidTransition)?.clone();
        let result = RecordedRetrieveResult {
            retrieval_id: RetrievalId::random().map_err(|_| PersistError::StorageUnavailable)?,
            claim_payload_ref: claim.payload_ref.clone(),
            newest_event_ref: newest,
            event_count: u8::try_from(refs.len()).map_err(|_| PersistError::InvalidTransition)?,
            retrieved_at: self.now,
        };
        self.retrievals.insert(
            result.retrieval_id.clone(),
            PersistedRetrievalRecord {
                retrieval_id: result.retrieval_id.clone(),
                binding_digest,
                result: result.clone(),
            },
        );
        self.retrieve_replays.insert(
            exchange.request_id.clone(),
            PersistedRetrieveReplay {
                request_id: exchange.request_id.clone(),
                binding_digest,
                canonical_body_digest: exchange.canonical_body_digest.clone(),
                result: result.clone(),
            },
        );
        let permit = Self::mint_retrieve_permit(
            &exchange.binding,
            &exchange.request_id,
            &result,
            PermitProvenance::Fresh,
        );
        Ok(IdempotentResult::Recorded(AuthorizedRetrieve {
            recorded: result,
            permit,
        }))
    }

    fn materialize_claimed_batch(
        &self,
        binding: &ValidatedHelperBinding,
        permit: ClaimMaterializationPermit,
    ) -> Result<BoundedClaimPayload, PersistError> {
        self.authenticate_binding(binding, HelperOperation::Retrieve)?;
        self.enforce_unrevoked(binding)?;
        if permit.grant_ref != binding.grant_ref
            || permit.binding_digest != canonical_binding_digest(binding)
            || permit.claim_digest != binding.claim_digest
        {
            return Err(PersistError::Unauthorized);
        }
        let replay = self
            .retrieve_replays
            .get(&permit.request_id)
            .ok_or(PersistError::Unauthorized)?;
        let stored = self
            .retrievals
            .get(&permit.retrieval_id)
            .ok_or(PersistError::Unauthorized)?;
        let recomputed = canonical_retrieve_body_digest(&replay.binding_digest, &permit.request_id);
        if replay.request_id != permit.request_id
            || replay.binding_digest != permit.binding_digest
            || replay.canonical_body_digest != recomputed
            || replay.result.retrieval_id != permit.retrieval_id
            || replay.result != stored.result
            || stored.binding_digest != permit.binding_digest
            || stored.result.claim_payload_ref != permit.payload_ref
        {
            return Err(PersistError::Unauthorized);
        }
        let claim = self
            .claim_for_attempt(&binding.attempt_id)
            .ok_or(PersistError::Unauthorized)?;
        if claim.payload_ref != permit.payload_ref || claim.claim_digest != permit.claim_digest {
            return Err(PersistError::Unauthorized);
        }
        if permit.provenance == PermitProvenance::Fresh {
            self.authorize_fresh_use(binding, HelperOperation::Retrieve)?;
        }
        self.payloads
            .get(&permit.payload_ref)
            .cloned()
            .ok_or(PersistError::PayloadUnavailable)
    }

    fn acknowledge_retrieved_batch(
        &mut self,
        binding: &ValidatedHelperBinding,
        request: &AcknowledgeRequest,
    ) -> Result<IdempotentResult<AcknowledgeResult>, PersistError> {
        // Mandatory on every call including replay: complete binding
        // authentication plus sticky revocation. Lifecycle/timing below
        // applies to unseen requests only.
        self.authenticate_binding(binding, HelperOperation::Acknowledge)?;
        self.enforce_unrevoked(binding)?;
        let binding_digest = canonical_binding_digest(binding);
        let recomputed = canonical_ack_body_digest(
            &binding_digest,
            &request.request_id,
            &request.retrieval_id,
            &request.cursor,
        );
        if recomputed != request.canonical_body_digest {
            return Err(PersistError::Conflict);
        }
        if self.retrieve_replays.contains_key(&request.request_id) {
            return Err(PersistError::Conflict);
        }
        if let Some(stored) = self.ack_replays.get(&request.request_id) {
            return if stored.binding_digest == binding_digest
                && stored.canonical_body_digest == request.canonical_body_digest
                && stored.retrieval_id == request.retrieval_id
                && stored.cursor == request.cursor
            {
                Ok(IdempotentResult::ExactReplay(stored.result.clone()))
            } else {
                Err(PersistError::Conflict)
            };
        }
        self.authorize_fresh_use(binding, HelperOperation::Acknowledge)?;
        let retrieval = self
            .retrievals
            .get(&request.retrieval_id)
            .ok_or(PersistError::Unauthorized)?
            .clone();
        if retrieval.binding_digest != binding_digest {
            return Err(PersistError::Unauthorized);
        }
        let claim = self
            .claim_for_attempt(&binding.attempt_id)
            .ok_or(PersistError::Unauthorized)?
            .clone();
        if retrieval.result.claim_payload_ref != claim.payload_ref {
            return Err(PersistError::Unauthorized);
        }
        let refs = claim.event_refs.as_slice();
        let position = refs
            .iter()
            .position(|event_ref| event_ref == &request.cursor)
            .ok_or(PersistError::Unauthorized)?;
        let payload = self.payloads.get(&claim.payload_ref);
        let proved_through = proved_ack_index(&claim, refs, payload)?;
        if position > proved_through {
            return Err(PersistError::InvalidTransition);
        }
        let newest_position = refs
            .len()
            .checked_sub(1)
            .ok_or(PersistError::InvalidTransition)?;
        // Coverage advances monotonically: the durable cursor is the
        // furthest contiguously covered prefix, while the result echoes the
        // requested cursor.
        let mut furthest = position;
        if let Some(existing) = self.handled.get(&binding.attempt_id) {
            let old = refs
                .iter()
                .position(|event_ref| event_ref == &existing.cursor)
                .ok_or(PersistError::InvalidTransition)?;
            furthest = furthest.max(old);
        }
        let cursor = refs
            .get(furthest)
            .ok_or(PersistError::InvalidTransition)?
            .clone();
        self.handled.insert(
            binding.attempt_id.clone(),
            PersistedHandledCoverage {
                attempt_id: binding.attempt_id.clone(),
                signal_id: binding.signal_id.clone(),
                cursor,
                covered_through_newest: furthest == newest_position,
            },
        );
        let result = AcknowledgeResult {
            attempt_id: binding.attempt_id.clone(),
            signal_id: binding.signal_id.clone(),
            cursor: request.cursor.clone(),
            accepted_at: self.now,
        };
        self.ack_replays.insert(
            request.request_id.clone(),
            PersistedAckReplay {
                request_id: request.request_id.clone(),
                binding_digest,
                canonical_body_digest: request.canonical_body_digest.clone(),
                retrieval_id: request.retrieval_id.clone(),
                cursor: request.cursor.clone(),
                result: result.clone(),
            },
        );
        Ok(IdempotentResult::Recorded(result))
    }

    fn try_rearm_join(&mut self, scope: RearmJoinScope) -> Result<RearmJoinResult, PersistError> {
        let key = (
            scope.arm_id.clone(),
            scope.generation,
            scope.attempt_id.clone(),
            scope.signal_id.clone(),
        );
        if self.rearmed.contains(&key) {
            return Ok(RearmJoinResult::AlreadyRearmed);
        }
        let scope_matches_claim = self.claims.values().any(|claim| {
            claim.attempt_id == scope.attempt_id
                && claim.arm_id == scope.arm_id
                && claim.generation == scope.generation
                && claim.signal_id == scope.signal_id
        });
        let handled_through_newest = self.handled.get(&scope.attempt_id).is_some_and(|coverage| {
            coverage.signal_id == scope.signal_id && coverage.covered_through_newest
        });
        if !scope_matches_claim || !handled_through_newest {
            return Ok(RearmJoinResult::WaitingForHandled);
        }
        let recognized_terminal = self.turn_facts.get(&scope.attempt_id).is_some_and(|facts| {
            facts
                .iter()
                .any(|fact| matches!(fact, NativeTurnFact::Terminal { .. }))
        });
        if !recognized_terminal {
            return Ok(RearmJoinResult::WaitingForRecognizedTerminal);
        }
        self.rearmed.insert(key);
        Ok(RearmJoinResult::Rearmed)
    }

    fn recover_authority_state(&mut self) -> Result<RecoverySnapshot, PersistError> {
        self.quarantine_reserved_ownership();
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
        if self.helper_request_nonce_collision() {
            return Err(PersistError::Conflict);
        }
        self.validate_recovered_coverage()?;
        let helper_sections = self.helper_snapshot();
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
            helper_grants: helper_sections.grants,
            retired_helper_grants: helper_sections.retired_grants,
            retrieve_replays: helper_sections.retrieve_replays,
            retrieval_bindings: helper_sections.retrieval_bindings,
            ack_replays: helper_sections.ack_replays,
            handled_coverage: helper_sections.handled_coverage,
            rearmed_joins: helper_sections.rearmed_joins,
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
                admission.coverage.as_ref(),
                admission.drain_witness.as_ref(),
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
            reordered.coverage.as_ref(),
            reordered.drain_witness.as_ref(),
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
            dropped.coverage.as_ref(),
            dropped.drain_witness.as_ref(),
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
            grant_ref: VerifierRef::fixture(9),
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
        rotated.grant_ref = VerifierRef::fixture(10);
        assert_ne!(grant, rotated);
        let retired = PersistedRetiredGrant {
            grant_ref: VerifierRef::fixture(9),
            grant_verifier: [0x5a; 32],
        };
        let rendered_retired = format!("{retired:?}");
        assert!(rendered_retired.contains("[redacted]"));
        assert!(!rendered_retired.contains("5a"), "{rendered_retired}");
    }

    struct HelperSetup {
        store: FakePersist,
        birth: PersistedControllerBirth,
        binding: ValidatedHelperBinding,
        attempt_id: AttemptId,
        lease_until: OffsetDateTime,
    }

    fn helper_store() -> HelperSetup {
        helper_store_events(&[("event-a", "test-a"), ("event-b", "test-b")])
    }

    fn helper_store_events(events: &[(&str, &str)]) -> HelperSetup {
        let mut store = FakePersist::default();
        let (birth, create) = birth();
        let lease_until = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(60);
        let mut birth = birth;
        birth.lease_until = lease_until;
        store
            .reserve_controller_birth(&birth, &create)
            .expect("reserve");
        store
            .persist_arm(&PersistedArm {
                arm_id: birth.arm_id.clone(),
                generation: birth.generation,
                seat_id: birth.seat_id.clone(),
                capability: birth.capability,
                coverage_until: OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(600),
            })
            .expect("arm");
        let attempt_id = AttemptId::new("attempt-a").expect("attempt");
        let signal_id = SignalId::new("signal-a").expect("signal");
        let wire: Vec<ProviderEvent> = events
            .iter()
            .map(|(event_ref, body)| wire_event(event_ref, body))
            .collect();
        let admission = claim_admission_fixture(
            "claim-a",
            birth.arm_id.clone(),
            birth.generation,
            signal_id.clone(),
            &wire,
            OffsetDateTime::UNIX_EPOCH,
        );
        let attachment = PersistedControllerAttachment {
            attempt_id: attempt_id.clone(),
            birth_id: birth.birth_id.clone(),
            seat_id: birth.seat_id.clone(),
            arm_id: birth.arm_id.clone(),
            generation: birth.generation,
            capability: birth.capability,
            lease_until,
            verifier_ref: VerifierRef::fixture(8),
            revoked: false,
        };
        store.admit_claim(&admission, &attachment).expect("admit");
        let grant = PersistedHelperGrant {
            grant_verifier: [0x33; 32],
            grant_ref: VerifierRef::fixture(9),
            seat_id: birth.seat_id.clone(),
            arm_id: birth.arm_id.clone(),
            generation: birth.generation,
            birth_id: birth.birth_id.clone(),
            attempt_id: attempt_id.clone(),
            signal_id: signal_id.clone(),
            claim_digest: admission.claim_digest.clone(),
            operations: HelperOperations::all(),
            lease_until,
            executable_identity: HelperExecutableIdentity {
                image_digest: [0x11; 32],
                file_identity: BoundedToken::new("gearwit-helper").expect("file"),
                build_identity: BoundedToken::new("build-1").expect("build"),
            },
            revoked: false,
        };
        store.persist_helper_grant(&grant).expect("grant");
        let binding = ValidatedHelperBinding {
            grant_ref: VerifierRef::fixture(9),
            seat_id: birth.seat_id.clone(),
            arm_id: birth.arm_id.clone(),
            generation: birth.generation,
            birth_id: birth.birth_id.clone(),
            attempt_id: attempt_id.clone(),
            signal_id,
            claim_digest: admission.claim_digest.clone(),
            operations: HelperOperations::all(),
            lease_until,
        };
        HelperSetup {
            store,
            birth,
            binding,
            attempt_id,
            lease_until,
        }
    }

    fn expect_recorded_retrieve(
        result: Result<IdempotentResult<AuthorizedRetrieve>, PersistError>,
    ) -> AuthorizedRetrieve {
        match result.expect("retrieve") {
            IdempotentResult::Recorded(authorized) => authorized,
            IdempotentResult::ExactReplay(_) => panic!("first retrieve must record"),
        }
    }

    fn assert_retrieve_replay(
        result: Result<IdempotentResult<AuthorizedRetrieve>, PersistError>,
        expected: &RecordedRetrieveResult,
    ) {
        match result.expect("replay") {
            IdempotentResult::ExactReplay(authorized) => {
                assert_eq!(&authorized.recorded, expected);
            }
            IdempotentResult::Recorded(_) => panic!("expected exact retrieve replay"),
        }
    }

    fn retrieve_for(binding: &ValidatedHelperBinding, nonce: u8) -> RetrieveExchange {
        let cloned = ValidatedHelperBinding {
            grant_ref: binding.grant_ref.clone(),
            seat_id: binding.seat_id.clone(),
            arm_id: binding.arm_id.clone(),
            generation: binding.generation,
            birth_id: binding.birth_id.clone(),
            attempt_id: binding.attempt_id.clone(),
            signal_id: binding.signal_id.clone(),
            claim_digest: binding.claim_digest.clone(),
            operations: binding.operations,
            lease_until: binding.lease_until,
        };
        let request_id = RequestNonce::fixture(nonce);
        let canonical_body_digest =
            canonical_retrieve_body_digest(&canonical_binding_digest(&cloned), &request_id);
        RetrieveExchange {
            binding: cloned,
            request_id,
            canonical_body_digest,
        }
    }

    /// Field-by-field copy of a sealed binding for negative tests; the
    /// production type is intentionally non-Clone.
    fn mutated_binding(base: &ValidatedHelperBinding) -> ValidatedHelperBinding {
        ValidatedHelperBinding {
            grant_ref: base.grant_ref.clone(),
            seat_id: base.seat_id.clone(),
            arm_id: base.arm_id.clone(),
            generation: base.generation,
            birth_id: base.birth_id.clone(),
            attempt_id: base.attempt_id.clone(),
            signal_id: base.signal_id.clone(),
            claim_digest: base.claim_digest.clone(),
            operations: base.operations,
            lease_until: base.lease_until,
        }
    }

    #[test]
    fn helper_grant_lifecycle_sticky_revocation() {
        let mut setup = helper_store();
        let grant = setup
            .store
            .helper_grant(&setup.birth.birth_id, &setup.attempt_id)
            .expect("stored grant")
            .clone();
        // Idempotent re-persist of the identical grant.
        setup
            .store
            .persist_helper_grant(&grant)
            .expect("re-persist");
        let scope = HelperRevocationScope {
            grant_ref: VerifierRef::fixture(9),
            birth_id: setup.birth.birth_id.clone(),
            attempt_id: setup.attempt_id.clone(),
        };
        assert_eq!(
            setup.store.revoke_helper_grant(scope),
            Ok(IdempotentWrite::Recorded)
        );
        let again = HelperRevocationScope {
            grant_ref: VerifierRef::fixture(9),
            birth_id: setup.birth.birth_id.clone(),
            attempt_id: setup.attempt_id.clone(),
        };
        assert_eq!(
            setup.store.revoke_helper_grant(again),
            Ok(IdempotentWrite::ExactReplay)
        );
        // No re-issue after revocation, including with rotated verifier.
        let mut rotated = grant.clone();
        rotated.grant_verifier = [0x34; 32];
        assert_eq!(
            setup.store.persist_helper_grant(&rotated),
            Err(PersistError::Conflict)
        );
        // Unknown grant scope fails closed.
        let unknown = HelperRevocationScope {
            grant_ref: VerifierRef::fixture(7),
            birth_id: ControllerBirthId::fixture(77),
            attempt_id: setup.attempt_id.clone(),
        };
        assert_eq!(
            setup.store.revoke_helper_grant(unknown),
            Err(PersistError::Unauthorized)
        );
    }

    #[test]
    fn helper_grant_reissue_supersedes_live_and_checks_claim() {
        let mut setup = helper_store();
        let mut rotated = setup
            .store
            .helper_grant(&setup.birth.birth_id, &setup.attempt_id)
            .expect("stored grant")
            .clone();
        rotated.grant_verifier = [0x34; 32];
        rotated.grant_ref = VerifierRef::fixture(10);
        setup
            .store
            .persist_helper_grant(&rotated)
            .expect("re-issue");
        let current = setup
            .store
            .helper_grant(&setup.birth.birth_id, &setup.attempt_id)
            .expect("current grant");
        assert_eq!(current.grant_verifier, [0x34; 32]);
        assert_eq!(current.grant_ref, VerifierRef::fixture(10));

        // Grant for an unknown attempt conflicts.
        let mut orphan = rotated.clone();
        orphan.attempt_id = AttemptId::new("attempt-zzz").expect("attempt");
        assert_eq!(
            setup.store.persist_helper_grant(&orphan),
            Err(PersistError::Conflict)
        );
        // Grant digest must match the admitted claim.
        let mut mismatched = rotated.clone();
        mismatched.claim_digest = ClaimDigest::fixture(99);
        assert_eq!(
            setup.store.persist_helper_grant(&mismatched),
            Err(PersistError::Conflict)
        );
    }

    #[test]
    fn retrieve_happy_path_replay_and_conflict() {
        let mut setup = helper_store();
        let at = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(7);
        setup.store.set_now(at);
        let exchange = retrieve_for(&setup.binding, 21);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        assert_eq!(recorded.newest_event_ref.as_str(), "event-b");
        assert_eq!(recorded.event_count, 2);
        assert_eq!(recorded.retrieved_at, at);
        let claim = setup
            .store
            .claim_for_attempt(&setup.attempt_id)
            .expect("claim");
        assert_eq!(recorded.claim_payload_ref, claim.payload_ref);

        assert_retrieve_replay(setup.store.record_retrieve_exchange(&exchange), &recorded);

        // Same nonce, changed body digest conflicts.
        let mut conflict = retrieve_for(&setup.binding, 21);
        conflict.canonical_body_digest = CanonicalBodyDigest::fixture(22);
        assert_eq!(
            setup.store.record_retrieve_exchange(&conflict),
            Err(PersistError::Conflict)
        );
        // Same nonce, changed binding fails authentication before replay
        // lookup: lease identity must match the grant exactly.
        let mut rebound = retrieve_for(&setup.binding, 21);
        rebound.binding.lease_until += time::Duration::seconds(1);
        assert_eq!(
            setup.store.record_retrieve_exchange(&rebound),
            Err(PersistError::Unauthorized)
        );
        // Neither rejection mutated the replay registry.
        assert_eq!(setup.store.retrieve_replays.len(), 1);
    }

    #[test]
    fn retrieve_rejects_invalid_binding() {
        let mut setup = helper_store();
        // Wrong generation.
        let mut wrong = retrieve_for(&setup.binding, 31);
        wrong.binding.generation += 1;
        assert_eq!(
            setup.store.record_retrieve_exchange(&wrong),
            Err(PersistError::Unauthorized)
        );
        // Wrong operation set.
        let mut ack_only = retrieve_for(&setup.binding, 32);
        ack_only.binding.operations = HelperOperations::acknowledge_only();
        assert_eq!(
            setup.store.record_retrieve_exchange(&ack_only),
            Err(PersistError::Unauthorized)
        );
        // Expired lease.
        setup
            .store
            .set_now(setup.lease_until + time::Duration::seconds(1));
        let expired = retrieve_for(&setup.binding, 33);
        assert_eq!(
            setup.store.record_retrieve_exchange(&expired),
            Err(PersistError::Unauthorized)
        );
        // Revoked grant.
        setup.store.set_now(OffsetDateTime::UNIX_EPOCH);
        setup
            .store
            .revoke_helper_grant(HelperRevocationScope {
                grant_ref: VerifierRef::fixture(9),
                birth_id: setup.birth.birth_id.clone(),
                attempt_id: setup.attempt_id.clone(),
            })
            .expect("revoke");
        let revoked = retrieve_for(&setup.binding, 34);
        assert_eq!(
            setup.store.record_retrieve_exchange(&revoked),
            Err(PersistError::Unauthorized)
        );
    }

    #[test]
    fn retrieve_missing_payload_fails_closed() {
        let mut setup = helper_store();
        let payload_ref = setup
            .store
            .claim_for_attempt(&setup.attempt_id)
            .expect("claim")
            .payload_ref
            .clone();
        assert!(setup.store.drop_payload(&payload_ref));
        let exchange = retrieve_for(&setup.binding, 35);
        assert_eq!(
            setup.store.record_retrieve_exchange(&exchange),
            Err(PersistError::PayloadUnavailable)
        );
    }

    #[test]
    fn materialize_round_trip_and_mismatches() {
        let mut setup = helper_store();
        let exchange = retrieve_for(&setup.binding, 41);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        let payload = setup
            .store
            .materialize_claimed_batch(&setup.binding, authorized.permit)
            .expect("materialize");
        let bodies: Vec<&str> = payload
            .events
            .as_slice()
            .iter()
            .map(|event| event.body.as_str())
            .collect();
        assert_eq!(bodies, vec!["test-a", "test-b"]);

        // A substituted binding cannot consume the origin permit.
        let mut forged = mutated_binding(&setup.binding);
        forged.grant_ref = VerifierRef::fixture(10);
        let again = expect_recorded_retrieve(
            setup
                .store
                .record_retrieve_exchange(&retrieve_for(&setup.binding, 42)),
        );
        assert_eq!(
            setup.store.materialize_claimed_batch(&forged, again.permit),
            Err(PersistError::Unauthorized)
        );
        // Missing payload fails closed.
        let missing = expect_recorded_retrieve(
            setup
                .store
                .record_retrieve_exchange(&retrieve_for(&setup.binding, 43)),
        );
        assert!(setup.store.drop_payload(&recorded.claim_payload_ref));
        assert_eq!(
            setup
                .store
                .materialize_claimed_batch(&setup.binding, missing.permit),
            Err(PersistError::PayloadUnavailable)
        );
    }

    fn ack_for(
        binding: &ValidatedHelperBinding,
        retrieval_id: &RetrievalId,
        cursor: &str,
        nonce: u8,
    ) -> AcknowledgeRequest {
        let request_id = RequestNonce::fixture(nonce);
        let cursor = EventRef::new(cursor).expect("cursor");
        let canonical_body_digest = canonical_ack_body_digest(
            &canonical_binding_digest(binding),
            &request_id,
            retrieval_id,
            &cursor,
        );
        AcknowledgeRequest {
            request_id,
            retrieval_id: retrieval_id.clone(),
            cursor,
            canonical_body_digest,
        }
    }

    #[test]
    fn acknowledge_coverage_replay_and_conflict() {
        let mut setup = helper_store_events(&[
            ("event-a", "test-a"),
            ("event-b", "test-b"),
            ("event-c", "test-c"),
        ]);
        let at = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(9);
        setup.store.set_now(at);
        let exchange = retrieve_for(&setup.binding, 51);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        // Partial prefix coverage.
        let first = ack_for(&setup.binding, &recorded.retrieval_id, "event-a", 52);
        let accepted = match setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &first)
            .expect("ack")
        {
            IdempotentResult::Recorded(result) => result,
            IdempotentResult::ExactReplay(_) => panic!("first ack must record"),
        };
        assert_eq!(accepted.cursor.as_str(), "event-a");
        assert_eq!(accepted.accepted_at, at);
        let coverage = setup
            .store
            .handled
            .get(&setup.attempt_id)
            .expect("coverage");
        assert!(!coverage.covered_through_newest);

        // Exact replay returns the recorded result.
        let replay = setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &first)
            .expect("replay");
        assert_eq!(replay, IdempotentResult::ExactReplay(accepted.clone()));

        // Same nonce, changed cursor conflicts.
        let mut conflict = ack_for(&setup.binding, &recorded.retrieval_id, "event-b", 52);
        conflict.canonical_body_digest = CanonicalBodyDigest::fixture(53);
        assert_eq!(
            setup
                .store
                .acknowledge_retrieved_batch(&setup.binding, &conflict),
            Err(PersistError::Conflict)
        );

        // Advance to event-b; coverage is still partial.
        let second = ack_for(&setup.binding, &recorded.retrieval_id, "event-b", 54);
        setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &second)
            .expect("second ack");
        let coverage = setup
            .store
            .handled
            .get(&setup.attempt_id)
            .expect("coverage");
        assert_eq!(coverage.cursor.as_str(), "event-b");
        assert!(!coverage.covered_through_newest);

        // Regression while partial echoes the requested cursor; durable
        // coverage stays at its max.
        let regress = ack_for(&setup.binding, &recorded.retrieval_id, "event-a", 55);
        let regressed = match setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &regress)
            .expect("regression ack")
        {
            IdempotentResult::Recorded(result) => result,
            IdempotentResult::ExactReplay(_) => panic!("new request must record"),
        };
        assert_eq!(regressed.cursor.as_str(), "event-a");
        let coverage = setup
            .store
            .handled
            .get(&setup.attempt_id)
            .expect("coverage");
        assert_eq!(coverage.cursor.as_str(), "event-b");
        assert!(!coverage.covered_through_newest);
    }

    #[test]
    fn acknowledge_fresh_refused_after_full_closure_replay_survives() {
        let mut setup = helper_store_events(&[
            ("event-a", "test-a"),
            ("event-b", "test-b"),
            ("event-c", "test-c"),
        ]);
        let exchange = retrieve_for(&setup.binding, 58);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        let first = ack_for(&setup.binding, &recorded.retrieval_id, "event-a", 59);
        let accepted = match setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &first)
            .expect("ack")
        {
            IdempotentResult::Recorded(result) => result,
            IdempotentResult::ExactReplay(_) => panic!("first ack must record"),
        };
        // Full coverage through newest.
        let full = ack_for(&setup.binding, &recorded.retrieval_id, "event-c", 56);
        setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &full)
            .expect("full ack");
        let coverage = setup
            .store
            .handled
            .get(&setup.attempt_id)
            .expect("coverage");
        assert!(coverage.covered_through_newest);

        // A fresh nonce after full handled closure fails without mutation,
        // while the exact authenticated prior replay still returns its
        // recorded result.
        let replays_before = setup.store.ack_replays.len();
        let closed = ack_for(&setup.binding, &recorded.retrieval_id, "event-a", 57);
        assert_eq!(
            setup
                .store
                .acknowledge_retrieved_batch(&setup.binding, &closed),
            Err(PersistError::InvalidTransition)
        );
        assert_eq!(setup.store.ack_replays.len(), replays_before);
        let coverage = setup
            .store
            .handled
            .get(&setup.attempt_id)
            .expect("coverage");
        assert_eq!(coverage.cursor.as_str(), "event-c");
        let replay_after_close = setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &first)
            .expect("replay after close");
        assert_eq!(replay_after_close, IdempotentResult::ExactReplay(accepted));
    }

    #[test]
    fn acknowledge_rejects_unknown_cursor_retrieval_and_operation() {
        let mut setup = helper_store();
        let exchange = retrieve_for(&setup.binding, 61);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        // Cursor never delivered.
        let bad_cursor = ack_for(&setup.binding, &recorded.retrieval_id, "event-zzz", 62);
        assert_eq!(
            setup
                .store
                .acknowledge_retrieved_batch(&setup.binding, &bad_cursor),
            Err(PersistError::Unauthorized)
        );
        // Unknown retrieval with a correctly derived digest.
        let unknown_id = RetrievalId::fixture(99);
        let bad_retrieval = ack_for(&setup.binding, &unknown_id, "event-a", 63);
        assert_eq!(
            setup
                .store
                .acknowledge_retrieved_batch(&setup.binding, &bad_retrieval),
            Err(PersistError::Unauthorized)
        );
        // Binding without the acknowledge operation.
        let op = ack_for(&setup.binding, &recorded.retrieval_id, "event-a", 64);
        let narrowed = ValidatedHelperBinding {
            grant_ref: setup.binding.grant_ref.clone(),
            seat_id: setup.binding.seat_id.clone(),
            arm_id: setup.binding.arm_id.clone(),
            generation: setup.binding.generation,
            birth_id: setup.binding.birth_id.clone(),
            attempt_id: setup.binding.attempt_id.clone(),
            signal_id: setup.binding.signal_id.clone(),
            claim_digest: setup.binding.claim_digest.clone(),
            operations: HelperOperations::retrieve_only(),
            lease_until: setup.binding.lease_until,
        };
        assert_eq!(
            setup.store.acknowledge_retrieved_batch(&narrowed, &op),
            Err(PersistError::Unauthorized)
        );
    }

    #[test]
    fn rearm_join_matrix() {
        let mut setup = helper_store();
        let scope = RearmJoinScope {
            arm_id: setup.binding.arm_id.clone(),
            generation: setup.binding.generation,
            attempt_id: setup.attempt_id.clone(),
            signal_id: setup.binding.signal_id.clone(),
        };
        // Nothing durable yet.
        assert_eq!(
            setup.store.try_rearm_join(RearmJoinScope {
                arm_id: scope.arm_id.clone(),
                generation: scope.generation,
                attempt_id: scope.attempt_id.clone(),
                signal_id: scope.signal_id.clone(),
            }),
            Ok(RearmJoinResult::WaitingForHandled)
        );
        // Handled without newest and without terminal still waits for handled.
        let exchange = retrieve_for(&setup.binding, 71);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        let partial = ack_for(&setup.binding, &recorded.retrieval_id, "event-a", 72);
        setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &partial)
            .expect("partial ack");
        assert_eq!(
            setup.store.try_rearm_join(RearmJoinScope {
                arm_id: scope.arm_id.clone(),
                generation: scope.generation,
                attempt_id: scope.attempt_id.clone(),
                signal_id: scope.signal_id.clone(),
            }),
            Ok(RearmJoinResult::WaitingForHandled)
        );
        // Full handled coverage without terminal waits for terminal.
        let full = ack_for(&setup.binding, &recorded.retrieval_id, "event-b", 73);
        setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &full)
            .expect("full ack");
        assert_eq!(
            setup.store.try_rearm_join(RearmJoinScope {
                arm_id: scope.arm_id.clone(),
                generation: scope.generation,
                attempt_id: scope.attempt_id.clone(),
                signal_id: scope.signal_id.clone(),
            }),
            Ok(RearmJoinResult::WaitingForRecognizedTerminal)
        );
        // Recognized terminal completes the join exactly once.
        setup.store.turn_facts.insert(
            setup.attempt_id.clone(),
            vec![NativeTurnFact::Terminal {
                turn_ref: PrivateNativeRef::fixture(7),
                class: crate::controller::TerminalClass::Succeeded,
            }],
        );
        assert_eq!(
            setup.store.try_rearm_join(RearmJoinScope {
                arm_id: scope.arm_id.clone(),
                generation: scope.generation,
                attempt_id: scope.attempt_id.clone(),
                signal_id: scope.signal_id.clone(),
            }),
            Ok(RearmJoinResult::Rearmed)
        );
        assert_eq!(
            setup.store.try_rearm_join(scope),
            Ok(RearmJoinResult::AlreadyRearmed)
        );
    }

    #[test]
    fn rearm_join_rejects_mismatched_scope() {
        let mut setup = helper_store();
        let exchange = retrieve_for(&setup.binding, 81);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        let full = ack_for(&setup.binding, &recorded.retrieval_id, "event-b", 82);
        setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &full)
            .expect("full ack");
        setup.store.turn_facts.insert(
            setup.attempt_id.clone(),
            vec![NativeTurnFact::Terminal {
                turn_ref: PrivateNativeRef::fixture(7),
                class: crate::controller::TerminalClass::Failed,
            }],
        );
        // Wrong generation does not describe durable state.
        let wrong = RearmJoinScope {
            arm_id: setup.binding.arm_id.clone(),
            generation: setup.binding.generation + 1,
            attempt_id: setup.attempt_id.clone(),
            signal_id: setup.binding.signal_id.clone(),
        };
        assert_eq!(
            setup.store.try_rearm_join(wrong),
            Ok(RearmJoinResult::WaitingForHandled)
        );
        // Degraded completion is not a recognized terminal.
        setup.store.turn_facts.insert(
            setup.attempt_id.clone(),
            vec![NativeTurnFact::DegradedTerminalObservation],
        );
        let scope = RearmJoinScope {
            arm_id: setup.binding.arm_id.clone(),
            generation: setup.binding.generation,
            attempt_id: setup.attempt_id.clone(),
            signal_id: setup.binding.signal_id.clone(),
        };
        assert_eq!(
            setup.store.try_rearm_join(scope),
            Ok(RearmJoinResult::WaitingForRecognizedTerminal)
        );
    }

    #[test]
    fn snapshot_carries_helper_sections_without_bodies() {
        let mut setup = helper_store();
        let exchange = retrieve_for(&setup.binding, 91);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        let full = ack_for(&setup.binding, &recorded.retrieval_id, "event-b", 92);
        setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &full)
            .expect("full ack");
        let snapshot = setup.store.recover_authority_state().expect("snapshot");
        assert_eq!(snapshot.helper_grants.len(), 1);
        assert_eq!(snapshot.retrieve_replays.len(), 1);
        assert_eq!(snapshot.retrieval_bindings.len(), 1);
        assert_eq!(
            snapshot.retrieval_bindings[0].retrieval_id,
            recorded.retrieval_id
        );
        assert_eq!(snapshot.ack_replays.len(), 1);
        assert_eq!(snapshot.ack_replays[0].retrieval_id, recorded.retrieval_id);
        assert_eq!(snapshot.handled_coverage.len(), 1);
        assert!(snapshot.rearmed_joins.is_empty());
        let rendered = format!("{snapshot:?}");
        assert!(!rendered.contains("test-a"), "{rendered}");
        assert!(!rendered.contains("test-b"), "{rendered}");
    }

    #[test]
    fn helper_forged_grant_ref_rejected() {
        let mut setup = helper_store();
        let mut forged = mutated_binding(&setup.binding);
        forged.grant_ref = VerifierRef::fixture(10);
        let exchange = retrieve_for(&forged, 101);
        assert_eq!(
            setup.store.record_retrieve_exchange(&exchange),
            Err(PersistError::Unauthorized)
        );
        assert!(setup.store.retrieve_replays.is_empty());
        assert!(setup.store.retrievals.is_empty());
        // The forged ref also fails materialize and ack admission.
        let good = retrieve_for(&setup.binding, 102);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&good));
        let recorded = authorized.recorded.clone();
        assert_eq!(
            setup
                .store
                .materialize_claimed_batch(&forged, authorized.permit),
            Err(PersistError::Unauthorized)
        );
        let ack = ack_for(&forged, &recorded.retrieval_id, "event-a", 103);
        assert_eq!(
            setup.store.acknowledge_retrieved_batch(&forged, &ack),
            Err(PersistError::Unauthorized)
        );
        assert!(setup.store.ack_replays.is_empty());
    }

    #[test]
    fn helper_revoke_wrong_ref_rejected() {
        let mut setup = helper_store();
        let wrong = HelperRevocationScope {
            grant_ref: VerifierRef::fixture(10),
            birth_id: setup.birth.birth_id.clone(),
            attempt_id: setup.attempt_id.clone(),
        };
        assert_eq!(
            setup.store.revoke_helper_grant(wrong),
            Err(PersistError::Unauthorized)
        );
        // The live grant is unaffected: fresh work still records.
        let exchange = retrieve_for(&setup.binding, 104);
        assert!(matches!(
            setup.store.record_retrieve_exchange(&exchange),
            Ok(IdempotentResult::Recorded(_))
        ));
    }

    #[test]
    fn helper_rotation_fences_stale_binding_and_scope() {
        let mut setup = helper_store();
        let mut rotated = setup
            .store
            .helper_grant(&setup.birth.birth_id, &setup.attempt_id)
            .expect("stored grant")
            .clone();
        rotated.grant_verifier = [0x34; 32];
        rotated.grant_ref = VerifierRef::fixture(10);
        setup
            .store
            .persist_helper_grant(&rotated)
            .expect("re-issue");
        // A stale binding presenting the old ref fails on fresh work.
        let stale = retrieve_for(&setup.binding, 105);
        assert_eq!(
            setup.store.record_retrieve_exchange(&stale),
            Err(PersistError::Unauthorized)
        );
        // A stale revocation scope cannot affect the replacement grant.
        let stale_scope = HelperRevocationScope {
            grant_ref: VerifierRef::fixture(9),
            birth_id: setup.birth.birth_id.clone(),
            attempt_id: setup.attempt_id.clone(),
        };
        assert_eq!(
            setup.store.revoke_helper_grant(stale_scope),
            Err(PersistError::Unauthorized)
        );
        // The replacement binding works, and its scope revokes.
        let mut current = mutated_binding(&setup.binding);
        current.grant_ref = VerifierRef::fixture(10);
        let fresh = retrieve_for(&current, 106);
        assert!(matches!(
            setup.store.record_retrieve_exchange(&fresh),
            Ok(IdempotentResult::Recorded(_))
        ));
        let current_scope = HelperRevocationScope {
            grant_ref: VerifierRef::fixture(10),
            birth_id: setup.birth.birth_id.clone(),
            attempt_id: setup.attempt_id.clone(),
        };
        assert_eq!(
            setup.store.revoke_helper_grant(current_scope),
            Ok(IdempotentWrite::Recorded)
        );
        // Sticky: the replacement binding now fails too.
        let after = retrieve_for(&current, 107);
        assert_eq!(
            setup.store.record_retrieve_exchange(&after),
            Err(PersistError::Unauthorized)
        );
    }

    #[test]
    fn helper_grant_mint_validates_current_authority() {
        let mut setup = helper_store();
        let live = setup
            .store
            .helper_grant(&setup.birth.birth_id, &setup.attempt_id)
            .expect("stored grant")
            .clone();
        // Grant for an unknown attempt conflicts.
        let mut orphan = live.clone();
        orphan.attempt_id = AttemptId::new("attempt-zzz").expect("attempt");
        assert_eq!(
            setup.store.persist_helper_grant(&orphan),
            Err(PersistError::Conflict)
        );
        // Birth not bound to the attempt attachment conflicts.
        let mut stray = live.clone();
        stray.birth_id = ControllerBirthId::fixture(77);
        assert_eq!(
            setup.store.persist_helper_grant(&stray),
            Err(PersistError::Conflict)
        );
        // Expired lease conflicts.
        let mut expired = live.clone();
        expired.lease_until = OffsetDateTime::UNIX_EPOCH - time::Duration::seconds(1);
        assert_eq!(
            setup.store.persist_helper_grant(&expired),
            Err(PersistError::Conflict)
        );
        // Controller loss conflicts.
        setup.store.turn_facts.insert(
            setup.attempt_id.clone(),
            vec![NativeTurnFact::ControllerLost],
        );
        assert_eq!(
            setup.store.persist_helper_grant(&live),
            Err(PersistError::Conflict)
        );
        setup.store.turn_facts.remove(&setup.attempt_id);
        // Terminal alone, handled-only, or both each refuse mint.
        setup.store.turn_facts.insert(
            setup.attempt_id.clone(),
            vec![NativeTurnFact::Terminal {
                turn_ref: PrivateNativeRef::fixture(7),
                class: crate::controller::TerminalClass::Succeeded,
            }],
        );
        assert_eq!(
            setup.store.persist_helper_grant(&live),
            Err(PersistError::Conflict)
        );
        setup.store.turn_facts.remove(&setup.attempt_id);
        let exchange = retrieve_for(&setup.binding, 108);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        let full = ack_for(&setup.binding, &recorded.retrieval_id, "event-b", 109);
        setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &full)
            .expect("full ack");
        assert_eq!(
            setup.store.persist_helper_grant(&live),
            Err(PersistError::Conflict)
        );
        setup.store.turn_facts.insert(
            setup.attempt_id.clone(),
            vec![NativeTurnFact::Terminal {
                turn_ref: PrivateNativeRef::fixture(7),
                class: crate::controller::TerminalClass::Succeeded,
            }],
        );
        assert_eq!(
            setup.store.persist_helper_grant(&live),
            Err(PersistError::Conflict)
        );
        // Stale generation after arm advance conflicts.
        let advanced = PersistedArm {
            arm_id: setup.birth.arm_id.clone(),
            generation: setup.birth.generation + 1,
            seat_id: setup.birth.seat_id.clone(),
            capability: setup.birth.capability,
            coverage_until: OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(600),
        };
        setup.store.persist_arm(&advanced).expect("advance");
        assert_eq!(
            setup.store.persist_helper_grant(&live),
            Err(PersistError::Conflict)
        );
        // A reissue that narrows the operation set is not a valid
        // replacement even where mint validation passes.
        setup
            .store
            .persist_arm(&PersistedArm {
                arm_id: setup.birth.arm_id.clone(),
                generation: setup.birth.generation,
                seat_id: setup.birth.seat_id.clone(),
                capability: setup.birth.capability,
                coverage_until: OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(600),
            })
            .expect("restore arm");
        setup.store.turn_facts.remove(&setup.attempt_id);
        let mut narrowed = live.clone();
        narrowed.operations = HelperOperations::retrieve_only();
        assert_eq!(
            setup.store.persist_helper_grant(&narrowed),
            Err(PersistError::Conflict)
        );
    }

    #[test]
    fn controller_detach_expires_grant_without_replay_exception() {
        let mut setup = helper_store();
        let exchange = retrieve_for(&setup.binding, 111);
        match setup
            .store
            .record_retrieve_exchange(&exchange)
            .expect("retrieve")
        {
            IdempotentResult::Recorded(_) => {}
            IdempotentResult::ExactReplay(_) => panic!("first retrieve must record"),
        }
        setup
            .store
            .revoke_controller_attachment(ValidatedAttachmentScope {
                attempt_id: setup.attempt_id.clone(),
                birth_id: setup.birth.birth_id.clone(),
                arm_id: setup.birth.arm_id.clone(),
                generation: setup.birth.generation,
                verifier_ref: VerifierRef::fixture(8),
            })
            .expect("detach");
        // Exact replay is still refused: revocation is never bypassed.
        assert_eq!(
            setup.store.record_retrieve_exchange(&exchange),
            Err(PersistError::Unauthorized)
        );
        // Fresh work fails, and reissue is no longer eligible.
        let fresh = retrieve_for(&setup.binding, 112);
        assert_eq!(
            setup.store.record_retrieve_exchange(&fresh),
            Err(PersistError::Unauthorized)
        );
        let live = setup
            .store
            .helper_grant(&setup.birth.birth_id, &setup.attempt_id)
            .expect("stored grant")
            .clone();
        assert_eq!(
            setup.store.persist_helper_grant(&live),
            Err(PersistError::Conflict)
        );
    }

    #[test]
    fn exact_replay_bypasses_lifecycle_fresh_does_not() {
        let mut setup = helper_store();
        let exchange = retrieve_for(&setup.binding, 121);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        // Expiry: fresh fails, exact replay returns the recorded result.
        setup
            .store
            .set_now(setup.lease_until + time::Duration::seconds(1));
        let expired = retrieve_for(&setup.binding, 122);
        assert_eq!(
            setup.store.record_retrieve_exchange(&expired),
            Err(PersistError::Unauthorized)
        );
        assert_retrieve_replay(setup.store.record_retrieve_exchange(&exchange), &recorded);
        // Controller loss: fresh refused, replay survives.
        setup.store.set_now(OffsetDateTime::UNIX_EPOCH);
        setup.store.turn_facts.insert(
            setup.attempt_id.clone(),
            vec![NativeTurnFact::ControllerLost],
        );
        let lost = retrieve_for(&setup.binding, 123);
        assert_eq!(
            setup.store.record_retrieve_exchange(&lost),
            Err(PersistError::InvalidTransition)
        );
        assert_retrieve_replay(setup.store.record_retrieve_exchange(&exchange), &recorded);
        // Generation advance: fresh unauthorized, replay survives.
        setup.store.turn_facts.remove(&setup.attempt_id);
        setup
            .store
            .persist_arm(&PersistedArm {
                arm_id: setup.birth.arm_id.clone(),
                generation: setup.birth.generation + 1,
                seat_id: setup.birth.seat_id.clone(),
                capability: setup.birth.capability,
                coverage_until: OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(600),
            })
            .expect("advance");
        let advanced = retrieve_for(&setup.binding, 124);
        assert_eq!(
            setup.store.record_retrieve_exchange(&advanced),
            Err(PersistError::Unauthorized)
        );
        assert_retrieve_replay(setup.store.record_retrieve_exchange(&exchange), &recorded);
        assert_eq!(setup.store.retrieve_replays.len(), 1);
        // Revocation ends even replay.
        setup
            .store
            .persist_arm(&PersistedArm {
                arm_id: setup.birth.arm_id.clone(),
                generation: setup.birth.generation,
                seat_id: setup.birth.seat_id.clone(),
                capability: setup.birth.capability,
                coverage_until: OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(600),
            })
            .expect("restore arm");
        setup
            .store
            .revoke_helper_grant(HelperRevocationScope {
                grant_ref: VerifierRef::fixture(9),
                birth_id: setup.birth.birth_id.clone(),
                attempt_id: setup.attempt_id.clone(),
            })
            .expect("revoke");
        assert_eq!(
            setup.store.record_retrieve_exchange(&exchange),
            Err(PersistError::Unauthorized)
        );
    }

    #[test]
    fn retrieve_fresh_refused_after_handled_and_terminal() {
        let mut setup = helper_store();
        let exchange = retrieve_for(&setup.binding, 131);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        let full = ack_for(&setup.binding, &recorded.retrieval_id, "event-b", 132);
        setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &full)
            .expect("full ack");
        // Handled-only, terminal-only, and both each refuse fresh retrieve.
        let late = retrieve_for(&setup.binding, 133);
        assert_eq!(
            setup.store.record_retrieve_exchange(&late),
            Err(PersistError::InvalidTransition)
        );
        setup.store.handled.remove(&setup.attempt_id);
        setup.store.turn_facts.insert(
            setup.attempt_id.clone(),
            vec![NativeTurnFact::Terminal {
                turn_ref: PrivateNativeRef::fixture(7),
                class: crate::controller::TerminalClass::Succeeded,
            }],
        );
        let terminal_only = retrieve_for(&setup.binding, 134);
        assert_eq!(
            setup.store.record_retrieve_exchange(&terminal_only),
            Err(PersistError::InvalidTransition)
        );
        assert_eq!(setup.store.retrieve_replays.len(), 1);
        assert_retrieve_replay(setup.store.record_retrieve_exchange(&exchange), &recorded);
    }

    #[test]
    fn materialize_representation_cannot_mint_authority() {
        let mut setup = helper_store();
        let exchange = retrieve_for(&setup.binding, 141);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        setup
            .store
            .set_now(setup.lease_until + time::Duration::seconds(1));
        // A fresh permit revalidates lifecycle and fails after expiry.
        assert_eq!(
            setup
                .store
                .materialize_claimed_batch(&setup.binding, authorized.permit),
            Err(PersistError::Unauthorized)
        );
        let replay = match setup
            .store
            .record_retrieve_exchange(&exchange)
            .expect("replay")
        {
            IdempotentResult::ExactReplay(authorized) => authorized,
            IdempotentResult::Recorded(_) => panic!("expected exact retrieve replay"),
        };
        assert_eq!(replay.recorded, recorded);
        setup
            .store
            .materialize_claimed_batch(&setup.binding, replay.permit)
            .expect("exact-replay permit after expiry");
        let fresh = retrieve_for(&setup.binding, 142);
        assert_eq!(
            setup.store.record_retrieve_exchange(&fresh),
            Err(PersistError::Unauthorized)
        );
        setup.store.set_now(OffsetDateTime::UNIX_EPOCH);
        setup
            .store
            .revoke_helper_grant(HelperRevocationScope {
                grant_ref: VerifierRef::fixture(9),
                birth_id: setup.birth.birth_id.clone(),
                attempt_id: setup.attempt_id.clone(),
            })
            .expect("revoke");
        let after_revoke = match setup.store.record_retrieve_exchange(&exchange) {
            Err(PersistError::Unauthorized) => true,
            other => panic!("expected unauthorized replay after revoke, got {other:?}"),
        };
        assert!(after_revoke);
    }

    #[test]
    fn ack_fresh_refused_after_loss_replay_survives() {
        let mut setup = helper_store();
        let exchange = retrieve_for(&setup.binding, 151);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        let first = ack_for(&setup.binding, &recorded.retrieval_id, "event-a", 152);
        let accepted = match setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &first)
            .expect("ack")
        {
            IdempotentResult::Recorded(result) => result,
            IdempotentResult::ExactReplay(_) => panic!("first ack must record"),
        };
        setup.store.turn_facts.insert(
            setup.attempt_id.clone(),
            vec![NativeTurnFact::ControllerLost],
        );
        let lost = ack_for(&setup.binding, &recorded.retrieval_id, "event-b", 153);
        assert_eq!(
            setup
                .store
                .acknowledge_retrieved_batch(&setup.binding, &lost),
            Err(PersistError::InvalidTransition)
        );
        assert_eq!(setup.store.ack_replays.len(), 1);
        let coverage = setup
            .store
            .handled
            .get(&setup.attempt_id)
            .expect("coverage");
        assert_eq!(coverage.cursor.as_str(), "event-a");
        assert_eq!(
            setup
                .store
                .acknowledge_retrieved_batch(&setup.binding, &first),
            Ok(IdempotentResult::ExactReplay(accepted))
        );
    }

    #[test]
    fn second_binding_cannot_reuse_retrieval() {
        let mut setup = helper_store();
        let first = retrieve_for(&setup.binding, 161);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&first));
        let recorded = authorized.recorded.clone();
        let mut rotated = setup
            .store
            .helper_grant(&setup.birth.birth_id, &setup.attempt_id)
            .expect("stored grant")
            .clone();
        rotated.grant_verifier = [0x34; 32];
        rotated.grant_ref = VerifierRef::fixture(10);
        setup
            .store
            .persist_helper_grant(&rotated)
            .expect("re-issue");
        let mut second = mutated_binding(&setup.binding);
        second.grant_ref = VerifierRef::fixture(10);
        // Replacement binding is independently valid but cannot consume the
        // originating retrieval or its permit.
        let own = retrieve_for(&second, 162);
        assert!(matches!(
            setup.store.record_retrieve_exchange(&own),
            Ok(IdempotentResult::Recorded(_))
        ));
        assert_eq!(
            setup
                .store
                .materialize_claimed_batch(&second, authorized.permit),
            Err(PersistError::Unauthorized)
        );
        let cross = ack_for(&second, &recorded.retrieval_id, "event-a", 163);
        assert_eq!(
            setup.store.acknowledge_retrieved_batch(&second, &cross),
            Err(PersistError::Unauthorized)
        );
        // Origin binding is fenced by rotation.
        assert_eq!(
            setup.store.record_retrieve_exchange(&first),
            Err(PersistError::Unauthorized)
        );
    }

    #[test]
    fn ack_changed_fields_with_reused_digest_conflict() {
        let mut setup = helper_store();
        let exchange = retrieve_for(&setup.binding, 171);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        let first = ack_for(&setup.binding, &recorded.retrieval_id, "event-a", 172);
        let accepted = match setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &first)
            .expect("ack")
        {
            IdempotentResult::Recorded(result) => result,
            IdempotentResult::ExactReplay(_) => panic!("first ack must record"),
        };
        // The recorded digest reused over a changed cursor conflicts.
        let mut reused = ack_for(&setup.binding, &recorded.retrieval_id, "event-b", 172);
        reused.canonical_body_digest = first.canonical_body_digest.clone();
        assert_eq!(
            setup
                .store
                .acknowledge_retrieved_batch(&setup.binding, &reused),
            Err(PersistError::Conflict)
        );
        // A correctly recomputed digest over changed fields still
        // conflicts on the retained request identity.
        let rebound = ack_for(&setup.binding, &recorded.retrieval_id, "event-b", 172);
        assert_eq!(
            setup
                .store
                .acknowledge_retrieved_batch(&setup.binding, &rebound),
            Err(PersistError::Conflict)
        );
        // A changed retrieval likewise conflicts.
        let other = retrieve_for(&setup.binding, 173);
        let recorded_other =
            expect_recorded_retrieve(setup.store.record_retrieve_exchange(&other)).recorded;
        let swapped = ack_for(&setup.binding, &recorded_other.retrieval_id, "event-a", 172);
        assert_eq!(
            setup
                .store
                .acknowledge_retrieved_batch(&setup.binding, &swapped),
            Err(PersistError::Conflict)
        );
        // No mutation: one replay, coverage still at the first cursor.
        assert_eq!(setup.store.ack_replays.len(), 1);
        let coverage = setup
            .store
            .handled
            .get(&setup.attempt_id)
            .expect("coverage");
        assert_eq!(coverage.cursor.as_str(), "event-a");
        assert_eq!(
            setup
                .store
                .acknowledge_retrieved_batch(&setup.binding, &first),
            Ok(IdempotentResult::ExactReplay(accepted))
        );
    }

    #[test]
    fn retrieve_reused_nonce_over_changed_binding_conflicts() {
        let mut setup = helper_store();
        let exchange = retrieve_for(&setup.binding, 181);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        // Same nonce with a correctly derived digest for a changed
        // binding fails authentication (exact lease identity).
        let mut second = mutated_binding(&setup.binding);
        second.lease_until += time::Duration::seconds(30);
        let rebound = retrieve_for(&second, 181);
        assert_eq!(
            setup.store.record_retrieve_exchange(&rebound),
            Err(PersistError::Unauthorized)
        );
        assert_eq!(setup.store.retrieve_replays.len(), 1);
        // Shared nonce namespace: ACK cannot reuse a Retrieve nonce.
        let ack = ack_for(&setup.binding, &recorded.retrieval_id, "event-a", 181);
        assert_eq!(
            setup
                .store
                .acknowledge_retrieved_batch(&setup.binding, &ack),
            Err(PersistError::Conflict)
        );
        assert!(setup.store.ack_replays.is_empty());
        let ack_ok = ack_for(&setup.binding, &recorded.retrieval_id, "event-a", 182);
        setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &ack_ok)
            .expect("ack");
        let retrieve_reuse = retrieve_for(&setup.binding, 182);
        assert_eq!(
            setup.store.record_retrieve_exchange(&retrieve_reuse),
            Err(PersistError::Conflict)
        );
        assert_eq!(setup.store.retrieve_replays.len(), 1);
    }

    #[test]
    fn retired_grant_cannot_be_resurrected() {
        let mut setup = helper_store();
        let original = setup
            .store
            .helper_grant(&setup.birth.birth_id, &setup.attempt_id)
            .expect("stored grant")
            .clone();
        let mut rotated = original.clone();
        rotated.grant_verifier = [0x34; 32];
        rotated.grant_ref = VerifierRef::fixture(10);
        setup
            .store
            .persist_helper_grant(&rotated)
            .expect("rotate to B");
        assert_eq!(
            setup.store.persist_helper_grant(&original),
            Err(PersistError::Conflict)
        );
        let mut alias = original.clone();
        alias.grant_ref = VerifierRef::fixture(11);
        assert_eq!(
            setup.store.persist_helper_grant(&alias),
            Err(PersistError::Conflict)
        );
        setup
            .store
            .persist_helper_grant(&rotated)
            .expect("current grant remains idempotent");
        let snapshot = setup.store.recover_authority_state().expect("recover");
        assert_eq!(snapshot.retired_helper_grants.len(), 1);
        assert_eq!(
            snapshot.retired_helper_grants[0].grant_ref,
            VerifierRef::fixture(9)
        );
    }

    #[test]
    fn ack_refuses_unproven_newest_jump() {
        let mut setup = helper_store_events(&[
            ("event-a", "test-a"),
            ("event-b", "test-b"),
            ("event-c", "test-c"),
        ]);
        let claim_id = setup
            .store
            .claim_for_attempt(&setup.attempt_id)
            .expect("claim")
            .request_id
            .clone();
        if let Some(claim) = setup.store.claims.get_mut(&claim_id) {
            claim.coverage = None;
            claim.drain_witness = None;
        }
        let authorized = expect_recorded_retrieve(
            setup
                .store
                .record_retrieve_exchange(&retrieve_for(&setup.binding, 191)),
        );
        let jump = ack_for(
            &setup.binding,
            &authorized.recorded.retrieval_id,
            "event-c",
            192,
        );
        assert_eq!(
            setup
                .store
                .acknowledge_retrieved_batch(&setup.binding, &jump),
            Err(PersistError::InvalidTransition)
        );
        assert!(setup.store.handled.is_empty());
        let first = ack_for(
            &setup.binding,
            &authorized.recorded.retrieval_id,
            "event-a",
            193,
        );
        setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &first)
            .expect("first event without proof");
        assert_eq!(
            setup
                .store
                .handled
                .get(&setup.attempt_id)
                .expect("coverage")
                .cursor
                .as_str(),
            "event-a"
        );
    }

    #[test]
    fn coverage_rejects_swapped_and_sparse_drain() {
        let setup = helper_store_events(&[
            ("event-a", "test-a"),
            ("event-b", "test-b"),
            ("event-c", "test-c"),
        ]);
        let claim_id = setup
            .store
            .claim_for_attempt(&setup.attempt_id)
            .expect("claim")
            .request_id
            .clone();
        let mut claim = setup.store.claims.get(&claim_id).expect("claim").clone();
        let payload = setup
            .store
            .payloads
            .get(&claim.payload_ref)
            .expect("payload")
            .clone();
        claim.coverage.as_mut().expect("coverage").provider =
            ProviderName::new("other").expect("provider");
        assert!(coverage_pair_invalid(
            claim.coverage.as_ref(),
            claim.drain_witness.as_ref(),
            &claim.request_id,
            &claim.arm_id,
            claim.generation,
            &claim.signal_id,
            &claim.event_refs,
            Some(&payload),
        ));
        claim = setup.store.claims.get(&claim_id).expect("claim").clone();
        claim
            .coverage
            .as_mut()
            .expect("coverage")
            .drain_filter_scope = BoundedToken::new("other-drain").expect("scope");
        assert!(coverage_pair_invalid(
            claim.coverage.as_ref(),
            claim.drain_witness.as_ref(),
            &claim.request_id,
            &claim.arm_id,
            claim.generation,
            &claim.signal_id,
            &claim.event_refs,
            Some(&payload),
        ));
        claim = setup.store.claims.get(&claim_id).expect("claim").clone();
        claim.coverage.as_mut().expect("coverage").drain_baseline =
            EventRef::new("event-b").expect("ref");
        assert!(coverage_pair_invalid(
            claim.coverage.as_ref(),
            claim.drain_witness.as_ref(),
            &claim.request_id,
            &claim.arm_id,
            claim.generation,
            &claim.signal_id,
            &claim.event_refs,
            Some(&payload),
        ));
        claim = setup.store.claims.get(&claim_id).expect("claim").clone();
        claim
            .coverage
            .as_mut()
            .expect("coverage")
            .source_evidence_id = [0x43; 32];
        assert!(coverage_pair_invalid(
            claim.coverage.as_ref(),
            claim.drain_witness.as_ref(),
            &claim.request_id,
            &claim.arm_id,
            claim.generation,
            &claim.signal_id,
            &claim.event_refs,
            Some(&payload),
        ));
        claim = setup.store.claims.get(&claim_id).expect("claim").clone();
        let sparse = BoundedVec::try_from(vec![
            EventRef::new("event-a").expect("ref"),
            EventRef::new("event-c").expect("ref"),
        ])
        .expect("sparse");
        claim.drain_witness.as_mut().expect("drain").event_refs = sparse;
        assert!(coverage_pair_invalid(
            claim.coverage.as_ref(),
            claim.drain_witness.as_ref(),
            &claim.request_id,
            &claim.arm_id,
            claim.generation,
            &claim.signal_id,
            &claim.event_refs,
            Some(&payload),
        ));
    }

    #[test]
    fn coverage_partial_prefix_refuses_unproved_ack() {
        let mut setup = helper_store_events(&[
            ("event-a", "test-a"),
            ("event-b", "test-b"),
            ("event-c", "test-c"),
        ]);
        let claim_id = setup
            .store
            .claim_for_attempt(&setup.attempt_id)
            .expect("claim")
            .request_id
            .clone();
        if let Some(claim) = setup.store.claims.get_mut(&claim_id) {
            claim.coverage.as_mut().expect("coverage").covered_through =
                EventRef::new("event-b").expect("ref");
        }
        let authorized = expect_recorded_retrieve(
            setup
                .store
                .record_retrieve_exchange(&retrieve_for(&setup.binding, 201)),
        );
        let jump = ack_for(
            &setup.binding,
            &authorized.recorded.retrieval_id,
            "event-c",
            202,
        );
        assert_eq!(
            setup
                .store
                .acknowledge_retrieved_batch(&setup.binding, &jump),
            Err(PersistError::InvalidTransition)
        );
        let handled_before = setup.store.handled.clone();
        let prefix = ack_for(
            &setup.binding,
            &authorized.recorded.retrieval_id,
            "event-b",
            203,
        );
        setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &prefix)
            .expect("proved prefix");
        let regress = ack_for(
            &setup.binding,
            &authorized.recorded.retrieval_id,
            "event-a",
            204,
        );
        setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &regress)
            .expect("regression");
        assert_eq!(
            setup
                .store
                .handled
                .get(&setup.attempt_id)
                .expect("coverage")
                .cursor
                .as_str(),
            "event-b"
        );
        assert_eq!(handled_before.len(), 0);
    }

    #[test]
    fn grant_rotation_requires_both_identity_coordinates() {
        let mut setup = helper_store();
        let original = setup
            .store
            .helper_grant(&setup.birth.birth_id, &setup.attempt_id)
            .expect("grant")
            .clone();
        let grants_before = setup.store.grants.clone();
        let retired_before = setup.store.retired_grants.clone();
        let mut same_ref = original.clone();
        same_ref.grant_verifier = [0x34; 32];
        assert_eq!(
            setup.store.persist_helper_grant(&same_ref),
            Err(PersistError::Conflict)
        );
        let mut same_verifier = original.clone();
        same_verifier.grant_ref = VerifierRef::fixture(10);
        assert_eq!(
            setup.store.persist_helper_grant(&same_verifier),
            Err(PersistError::Conflict)
        );
        let mut lease_only = original.clone();
        lease_only.lease_until += time::Duration::seconds(1);
        assert_eq!(
            setup.store.persist_helper_grant(&lease_only),
            Err(PersistError::Conflict)
        );
        assert_eq!(setup.store.grants, grants_before);
        assert_eq!(setup.store.retired_grants, retired_before);
        let mut both = original.clone();
        both.grant_verifier = [0x34; 32];
        both.grant_ref = VerifierRef::fixture(10);
        setup.store.persist_helper_grant(&both).expect("rotate");
        let stale = HelperRevocationScope {
            grant_ref: VerifierRef::fixture(9),
            birth_id: setup.birth.birth_id.clone(),
            attempt_id: setup.attempt_id.clone(),
        };
        assert_eq!(
            setup.store.revoke_helper_grant(stale),
            Err(PersistError::Unauthorized)
        );
        let current = HelperRevocationScope {
            grant_ref: VerifierRef::fixture(10),
            birth_id: setup.birth.birth_id.clone(),
            attempt_id: setup.attempt_id.clone(),
        };
        assert_eq!(
            setup.store.revoke_helper_grant(current),
            Ok(IdempotentWrite::Recorded)
        );
    }

    #[test]
    fn restore_from_snapshot_revalidates_and_serves() {
        let mut setup = helper_store();
        let exchange = retrieve_for(&setup.binding, 211);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        let ack = ack_for(&setup.binding, &recorded.retrieval_id, "event-a", 212);
        setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &ack)
            .expect("ack");
        let payloads = setup.store.payloads.clone();
        let snapshot = setup.store.recover_authority_state().expect("snapshot");
        let rendered = format!("{snapshot:?}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
        let mut restored = FakePersist::restore_from_snapshot(snapshot.clone(), payloads.clone())
            .expect("restore");
        restored.set_now(setup.store.now);
        assert_retrieve_replay(restored.record_retrieve_exchange(&exchange), &recorded);
        let replayed = match restored
            .record_retrieve_exchange(&exchange)
            .expect("replay permit")
        {
            IdempotentResult::ExactReplay(authorized) => authorized,
            IdempotentResult::Recorded(_) => panic!("expected retrieve replay"),
        };
        restored
            .materialize_claimed_batch(&setup.binding, replayed.permit)
            .expect("restored materialize");
        assert!(matches!(
            restored.acknowledge_retrieved_batch(&setup.binding, &ack),
            Ok(IdempotentResult::ExactReplay(_))
        ));
        let mut swapped = snapshot.clone();
        swapped.claims[0]
            .coverage
            .as_mut()
            .expect("coverage")
            .provider = ProviderName::new("other").expect("provider");
        assert!(matches!(
            FakePersist::restore_from_snapshot(swapped, payloads.clone()),
            Err(PersistError::Conflict)
        ));
        let mut duplicate = snapshot.clone();
        duplicate.claims.push(duplicate.claims[0].clone());
        assert!(matches!(
            FakePersist::restore_from_snapshot(duplicate, payloads.clone()),
            Err(PersistError::Conflict)
        ));
        let mut overlap = snapshot.clone();
        overlap.retired_helper_grants.push(PersistedRetiredGrant {
            grant_ref: VerifierRef::fixture(9),
            grant_verifier: [0x33; 32],
        });
        assert!(matches!(
            FakePersist::restore_from_snapshot(overlap, payloads.clone()),
            Err(PersistError::Conflict)
        ));
        let mut shortened = snapshot.clone();
        shortened.claims[0].event_refs =
            BoundedVec::try_from(vec![EventRef::new("event-a").expect("ref")]).expect("refs");
        shortened.claims[0].claim_digest = canonical_claim_digest(
            &shortened.claims[0].request_id,
            &shortened.claims[0].arm_id,
            shortened.claims[0].generation,
            &shortened.claims[0].signal_id,
            &shortened.claims[0].event_refs,
            payloads
                .get(&shortened.claims[0].payload_ref)
                .expect("payload"),
            shortened.claims[0].coverage.as_ref(),
            shortened.claims[0].drain_witness.as_ref(),
        );
        assert!(matches!(
            FakePersist::restore_from_snapshot(shortened, payloads.clone()),
            Err(PersistError::Conflict)
        ));
        let mut swapped_replay = snapshot;
        swapped_replay.retrieve_replays[0].binding_digest = [0x11; 32];
        assert!(matches!(
            FakePersist::restore_from_snapshot(swapped_replay, payloads),
            Err(PersistError::Conflict)
        ));
    }

    #[test]
    fn restore_preserves_terminal_loss_and_rearm() {
        let mut setup = helper_store();
        let exchange = retrieve_for(&setup.binding, 221);
        let authorized = expect_recorded_retrieve(setup.store.record_retrieve_exchange(&exchange));
        let recorded = authorized.recorded.clone();
        let full = ack_for(&setup.binding, &recorded.retrieval_id, "event-b", 222);
        setup
            .store
            .acknowledge_retrieved_batch(&setup.binding, &full)
            .expect("full ack");
        setup.store.turn_facts.insert(
            setup.attempt_id.clone(),
            vec![NativeTurnFact::Terminal {
                turn_ref: PrivateNativeRef::fixture(7),
                class: crate::controller::TerminalClass::Succeeded,
            }],
        );
        let join = || RearmJoinScope {
            arm_id: setup.binding.arm_id.clone(),
            generation: setup.binding.generation,
            attempt_id: setup.attempt_id.clone(),
            signal_id: setup.binding.signal_id.clone(),
        };
        assert_eq!(
            setup.store.try_rearm_join(join()),
            Ok(RearmJoinResult::Rearmed)
        );
        let payloads = setup.store.payloads.clone();
        let snapshot = setup.store.recover_authority_state().expect("snapshot");
        let mut restored = FakePersist::restore_from_snapshot(snapshot, payloads).expect("restore");
        restored.set_now(setup.store.now);
        assert_eq!(
            restored.record_retrieve_exchange(&retrieve_for(&setup.binding, 223)),
            Err(PersistError::InvalidTransition)
        );
        assert_eq!(
            restored.acknowledge_retrieved_batch(
                &setup.binding,
                &ack_for(&setup.binding, &recorded.retrieval_id, "event-b", 224)
            ),
            Err(PersistError::InvalidTransition)
        );
        assert_retrieve_replay(restored.record_retrieve_exchange(&exchange), &recorded);
        assert_eq!(
            restored.try_rearm_join(join()),
            Ok(RearmJoinResult::AlreadyRearmed)
        );

        let mut lost = helper_store();
        let lost_exchange = retrieve_for(&lost.binding, 231);
        let lost_recorded =
            expect_recorded_retrieve(lost.store.record_retrieve_exchange(&lost_exchange)).recorded;
        lost.store.turn_facts.insert(
            lost.attempt_id.clone(),
            vec![NativeTurnFact::ControllerLost],
        );
        let lost_payloads = lost.store.payloads.clone();
        let lost_snapshot = lost.store.recover_authority_state().expect("snapshot");
        let mut lost_restored =
            FakePersist::restore_from_snapshot(lost_snapshot, lost_payloads).expect("restore");
        lost_restored.set_now(lost.store.now);
        assert_eq!(
            lost_restored.record_retrieve_exchange(&retrieve_for(&lost.binding, 232)),
            Err(PersistError::InvalidTransition)
        );
        assert_eq!(
            lost_restored.acknowledge_retrieved_batch(
                &lost.binding,
                &ack_for(&lost.binding, &lost_recorded.retrieval_id, "event-a", 233)
            ),
            Err(PersistError::InvalidTransition)
        );
        assert_retrieve_replay(
            lost_restored.record_retrieve_exchange(&lost_exchange),
            &lost_recorded,
        );
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
