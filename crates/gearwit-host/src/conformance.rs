//! Provider-neutral persistence conformance catalog.
//!
//! Each case has a stable id, a required semantic outcome, and evidence that
//! is either an executable check or an explicit gap. Gap evidence is
//! inconclusive: it is never a pass. The required outcome stays recorded
//! either way.
//!
//! Executable checks use the sealed persistence port or a test-only
//! fixture adapter for prepare, payload partition, and snapshot admission.
//! Only the deterministic fake adapter is implemented. The persistence port
//! gains no method. Waiter-link acknowledgment state is outside this catalog.

use crate::controller::{
    ArmId, AttemptId, BoundedToken, CanonicalBodyDigest, ClaimPayloadRef, ClaimRequestId,
    ControllerBirthId, EventRef, ManagedCapability, NativeTurnFact, PrivateNativeRef, RequestNonce,
    RetrievalId, SeatId, SignalId, TerminalClass, VerifierRef,
};
use crate::persist::{
    AcknowledgeRequest, AdmissionOutcome, BoundedClaimPayload, ClaimAdmission, FakePersist,
    HelperExecutableIdentity, HelperOperations, HelperRevocationScope, IdempotentResult,
    IdempotentWrite, Persist, PersistError, PersistedArm, PersistedClaimRecord,
    PersistedControllerAttachment, PersistedControllerBirth, PersistedHelperGrant,
    PersistedNativeTurnFacts, RearmJoinResult, RearmJoinScope, RecoverySnapshot,
    ReserveBirthOutcome, RetrieveExchange, ThreadCreateReservation, ThreadOwnershipState,
    ValidatedHelperBinding, canonical_ack_body_digest, canonical_binding_digest,
    canonical_claim_digest, canonical_retrieve_body_digest, claim_admission_fixture,
};
use gearwit_protocol::ProviderEvent;
use std::collections::BTreeMap;
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaseFamily {
    ClaimAdmission,
    ReplayIdentity,
    RecoverySnapshot,
    NativeWrite,
    Revocation,
    Materialization,
    AuditSequence,
    Durability,
    Custody,
    Retention,
}

/// Semantic result the case must eventually prove. Independent of whether
/// evidence exists in this slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequiredOutcome {
    ExactReplay,
    Conflict,
    InvalidTransition,
    Unauthorized,
    SectionsWithoutBodies,
    RetiredGrantRecorded,
    JoinAbsent,
    QuarantinedCreate,
    PayloadBoundToRetrieval,
    BothRecordsOrNeither,
    TornTailRefused,
    RollbackContinuityRefused,
    UnknownWithoutSecondCommand,
    FailClosed,
    StickyRevocation,
    VerifierRedacted,
    SameCatalogResults,
    NoPartialRecord,
    Recorded,
    Admitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaseEvidence {
    Port,
    SnapshotAdmission,
    Gap { owner: &'static str },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConformanceCase {
    pub id: &'static str,
    pub family: CaseFamily,
    pub required: RequiredOutcome,
    pub evidence: CaseEvidence,
    pub summary: &'static str,
}

const AUDIT: &str = "provider-independent audit sequence";
const REOPEN: &str = "reopened-media process-death fixtures";
const SQLITE: &str = "bundled sqlite baseline";
const CUSTODY: &str = "installation identity and encrypted private partition";
const RETENTION: &str = "migration compaction and retention";
const NATIVE: &str = "native reservation and write evidence";

macro_rules! port {
    ($id:literal, $family:ident, $required:ident, $summary:literal) => {
        ConformanceCase {
            id: $id,
            family: CaseFamily::$family,
            required: RequiredOutcome::$required,
            evidence: CaseEvidence::Port,
            summary: $summary,
        }
    };
}

macro_rules! snap {
    ($id:literal, $family:ident, $required:ident, $summary:literal) => {
        ConformanceCase {
            id: $id,
            family: CaseFamily::$family,
            required: RequiredOutcome::$required,
            evidence: CaseEvidence::SnapshotAdmission,
            summary: $summary,
        }
    };
}

macro_rules! gap {
    ($id:literal, $family:ident, $required:ident, $owner:expr, $summary:literal) => {
        ConformanceCase {
            id: $id,
            family: CaseFamily::$family,
            required: RequiredOutcome::$required,
            evidence: CaseEvidence::Gap { owner: $owner },
            summary: $summary,
        }
    };
}

/// Stable case inventory. Ids do not change when a provider is added.
pub(crate) fn catalog() -> &'static [ConformanceCase] {
    CATALOG
}

const CATALOG: &[ConformanceCase] = &[
    port!(
        "op.persist-arm",
        RecoverySnapshot,
        Recorded,
        "a persisted arm is recovered with its generation"
    ),
    port!(
        "op.admit-claim",
        ClaimAdmission,
        ExactReplay,
        "an identical claim admission replays; a forged digest conflicts and leaves the stored claim"
    ),
    port!(
        "op.reserve-controller-birth",
        RecoverySnapshot,
        ExactReplay,
        "an identical birth reservation replays and a changed create attempt conflicts"
    ),
    gap!(
        "op.resolve-thread-create",
        NativeWrite,
        ExactReplay,
        NATIVE,
        "thread-create resolution replays the owned, not-accepted, or unknown outcome exactly"
    ),
    port!(
        "op.thread-ownership-state",
        RecoverySnapshot,
        QuarantinedCreate,
        "an unresolved create reservation recovers as quarantined unknown ownership"
    ),
    gap!(
        "op.record-dispatch-prepared",
        NativeWrite,
        ExactReplay,
        NATIVE,
        "an identical prepared dispatch replays and a changed correlation conflicts"
    ),
    gap!(
        "op.record-prewrite-conclusion",
        NativeWrite,
        BothRecordsOrNeither,
        NATIVE,
        "a pre-write conclusion and its evidence commit together or not at all"
    ),
    gap!(
        "op.record-active-hold",
        NativeWrite,
        BothRecordsOrNeither,
        NATIVE,
        "an active hold and its observation proof commit together or not at all"
    ),
    gap!(
        "op.reserve-native-turn-write",
        NativeWrite,
        UnknownWithoutSecondCommand,
        NATIVE,
        "a native-write reservation crash yields zero writes or unknown, never a second command"
    ),
    gap!(
        "op.record-native-turn-fact",
        NativeWrite,
        ExactReplay,
        NATIVE,
        "an identical native turn fact replays and a conflicting fact is refused"
    ),
    gap!(
        "op.record-native-write-evidence",
        NativeWrite,
        UnknownWithoutSecondCommand,
        NATIVE,
        "ambiguous native acceptance stays unknown and does not mint another command"
    ),
    gap!(
        "op.record-reconciliation-fact",
        NativeWrite,
        ExactReplay,
        NATIVE,
        "reconciliation to not-accepted, accepted, terminal, or unknown replays exactly"
    ),
    gap!(
        "op.seal-native-coordinate",
        Custody,
        FailClosed,
        NATIVE,
        "a sealed coordinate is kind-tagged and its plaintext is erased on drop"
    ),
    gap!(
        "op.open-native-coordinate",
        Custody,
        FailClosed,
        NATIVE,
        "opening a coordinate requires the sealing scope and fails closed otherwise"
    ),
    port!(
        "op.persist-helper-grant",
        Revocation,
        RetiredGrantRecorded,
        "rotating a grant retires the prior ref and verifier and keeps one live grant"
    ),
    gap!(
        "op.revoke-controller-attachment",
        Revocation,
        StickyRevocation,
        NATIVE,
        "attachment revocation stays set across recovery and fences later use"
    ),
    port!(
        "op.revoke-helper-grant",
        Revocation,
        StickyRevocation,
        "helper-grant revocation stays set and a later fresh retrieve is unauthorized"
    ),
    port!(
        "op.record-retrieve-exchange",
        ReplayIdentity,
        ExactReplay,
        "a repeated retrieve returns the stored result"
    ),
    port!(
        "op.materialize-claimed-batch",
        Materialization,
        PayloadBoundToRetrieval,
        "materialization requires the sealed binding and retrieval permit"
    ),
    port!(
        "op.acknowledge-retrieved-batch",
        ReplayIdentity,
        ExactReplay,
        "a repeated acknowledgment returns the stored result"
    ),
    port!(
        "op.try-rearm-join",
        RecoverySnapshot,
        JoinAbsent,
        "re-arm waits and records no join until handled coverage exists"
    ),
    port!(
        "op.recover-authority-state",
        RecoverySnapshot,
        SectionsWithoutBodies,
        "grant, replay, retrieval, ack, and handled sections recover without payload bodies"
    ),
    port!(
        "replay.retrieve.changed-digest",
        ReplayIdentity,
        Conflict,
        "the same nonce with a different request digest conflicts and leaves one replay row"
    ),
    port!(
        "replay.ack.reused-digest",
        ReplayIdentity,
        Conflict,
        "a changed cursor presented with the previous digest conflicts"
    ),
    port!(
        "replay.fresh-refused-after-handled",
        ReplayIdentity,
        InvalidTransition,
        "fresh retrieve is refused after handled completion; the original retrieve still replays"
    ),
    port!(
        "grant.retired-identity-rejected",
        Revocation,
        Conflict,
        "a retired grant ref and verifier cannot be persisted again"
    ),
    snap!(
        "replay.restore.orphan-retrieval",
        ReplayIdentity,
        Conflict,
        "a retrieval index row with no retrieve replay is refused"
    ),
    snap!(
        "replay.restore.retrieval-id-mismatch",
        ReplayIdentity,
        Conflict,
        "a retrieval index id that differs from its result id is refused"
    ),
    snap!(
        "replay.restore.unswapped-pair",
        ReplayIdentity,
        Admitted,
        "two valid claims with unchanged retrieve and ack rows restore"
    ),
    snap!(
        "replay.restore.two-claim-substitution",
        ReplayIdentity,
        Conflict,
        "keeping A's request identity while pointing retrieve and ack results at B is refused"
    ),
    snap!(
        "replay.restore.forged-join",
        ReplayIdentity,
        Conflict,
        "a join without recognized terminal evidence is refused"
    ),
    snap!(
        "replay.restore.terminal-leaves-partial-rearm",
        ReplayIdentity,
        InvalidTransition,
        "a terminal fact does not close re-arm while handled coverage is partial, and fresh use is refused"
    ),
    gap!(
        "native.reservation-write-ambiguity",
        NativeWrite,
        UnknownWithoutSecondCommand,
        NATIVE,
        "reservation, write, and response crash windows do not emit a second command"
    ),
    gap!(
        "native.idle-permit-negatives",
        NativeWrite,
        Unauthorized,
        NATIVE,
        "missing, stale, replayed, mismatched, or restart-carried idle permits cannot reserve a write"
    ),
    gap!(
        "native.epoch-invalidation",
        NativeWrite,
        ExactReplay,
        NATIVE,
        "exact epoch invalidation replays; a changed epoch conflicts; restart keeps the zero-write conclusion"
    ),
    gap!(
        "native.active-hold-atomicity",
        NativeWrite,
        BothRecordsOrNeither,
        NATIVE,
        "active-observation proof and Held persist together, and a rejected proof records neither Held nor Unproven"
    ),
    gap!(
        "native.monotonic-lifecycle",
        NativeWrite,
        Conflict,
        NATIVE,
        "duplicate, regressive, and conflicting lifecycle transitions are refused"
    ),
    gap!(
        "native.recyclable-identity",
        NativeWrite,
        Unauthorized,
        NATIVE,
        "a recycled process, port, or socket identity cannot resolve controller authority"
    ),
    gap!(
        "audit.mutation-sequence",
        AuditSequence,
        BothRecordsOrNeither,
        AUDIT,
        "an authority mutation and its audit record commit together or not at all"
    ),
    gap!(
        "audit.torn-tail",
        AuditSequence,
        TornTailRefused,
        AUDIT,
        "a torn audit tail is refused on recovery"
    ),
    gap!(
        "audit.rollback-continuity",
        AuditSequence,
        RollbackContinuityRefused,
        AUDIT,
        "a rolled-back or gapped audit sequence is refused on recovery"
    ),
    gap!(
        "audit.conflicting-sequence",
        AuditSequence,
        Conflict,
        AUDIT,
        "a duplicate audit record with changed content, or a conflicting sequence, fails recovery"
    ),
    gap!(
        "snapshot.reopened-media",
        Durability,
        FailClosed,
        REOPEN,
        "process death and reopen from durable media must preserve the required outcomes"
    ),
    gap!(
        "crash.failure-windows",
        Durability,
        NoPartialRecord,
        REOPEN,
        "failure before append, during commit, after claim, before native send, or after possible acceptance leaves no partial authority"
    ),
    gap!(
        "restart.phase-matrix",
        Durability,
        ExactReplay,
        REOPEN,
        "restart from claimed, prepared, in-flight, ambiguous, terminal, and handled restores only the durable facts of that phase"
    ),
    gap!(
        "durability.sqlite-baseline",
        Durability,
        SameCatalogResults,
        SQLITE,
        "the bundled sqlite baseline passes this same catalog"
    ),
    gap!(
        "durability.disabled-remote",
        Durability,
        FailClosed,
        SQLITE,
        "a disabled remote configuration makes no network attempt"
    ),
    gap!(
        "custody.key-refusal",
        Custody,
        FailClosed,
        CUSTODY,
        "missing or incorrect key material refuses recovery and never writes plaintext"
    ),
    gap!(
        "custody.installation-identity",
        Custody,
        FailClosed,
        CUSTODY,
        "wrong installation identity, copied authority, or a second host resume is refused"
    ),
    gap!(
        "custody.redacted-export",
        Custody,
        FailClosed,
        CUSTODY,
        "redacted export and crash remnants contain no private-partition sentinel"
    ),
    gap!(
        "custody.root-permission",
        Custody,
        FailClosed,
        CUSTODY,
        "incorrect permissions or an unwritable data root fail closed"
    ),
    gap!(
        "retention.migration-compaction",
        Retention,
        FailClosed,
        RETENTION,
        "migration, compaction, and capacity refusal stay inside the declared budget and fail closed past it"
    ),
    port!(
        "grant.verifier-redacted",
        Revocation,
        VerifierRedacted,
        "recovered grant debug output redacts the verifier"
    ),
];

pub(crate) fn case(id: &str) -> Option<&'static ConformanceCase> {
    CATALOG.iter().find(|case| case.id == id)
}

/// Test-only boundary a later provider implements. Not a persistence-port method.
pub(crate) trait ConformanceFixture {
    type Store: Persist;

    fn empty() -> Self::Store;
    fn prepare() -> Prepared<Self::Store>;
    fn payloads(store: &Self::Store) -> BTreeMap<ClaimPayloadRef, BoundedClaimPayload>;
    fn admit_snapshot(
        snapshot: RecoverySnapshot,
        payloads: BTreeMap<ClaimPayloadRef, BoundedClaimPayload>,
    ) -> Result<Self::Store, PersistError>;
}

pub(crate) struct Prepared<S> {
    pub store: S,
    pub binding: ValidatedHelperBinding,
    pub admission: ClaimAdmission,
    pub attachment: PersistedControllerAttachment,
}

pub(crate) struct FakeFixture;

impl ConformanceFixture for FakeFixture {
    type Store = FakePersist;

    fn empty() -> Self::Store {
        FakePersist::default()
    }

    fn prepare() -> Prepared<Self::Store> {
        prepare_fake()
    }

    fn payloads(store: &Self::Store) -> BTreeMap<ClaimPayloadRef, BoundedClaimPayload> {
        store.claim_payloads()
    }

    fn admit_snapshot(
        snapshot: RecoverySnapshot,
        payloads: BTreeMap<ClaimPayloadRef, BoundedClaimPayload>,
    ) -> Result<Self::Store, PersistError> {
        FakePersist::restore_from_snapshot(snapshot, payloads)
    }
}

struct BirthParts {
    birth: PersistedControllerBirth,
    reservation: ThreadCreateReservation,
}

fn birth_parts() -> BirthParts {
    let birth_id = ControllerBirthId::fixture(1);
    let lease_until = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(60);
    BirthParts {
        birth: PersistedControllerBirth {
            birth_id: birth_id.clone(),
            seat_id: SeatId::new("seat-a").expect("seat"),
            arm_id: ArmId::new("arm-a").expect("arm"),
            generation: 1,
            capability: ManagedCapability::HandleClaimedSignal,
            lease_until,
            verifier_ref: VerifierRef::fixture(3),
            created_at: OffsetDateTime::UNIX_EPOCH,
            revoked: false,
        },
        reservation: ThreadCreateReservation {
            birth_id,
            create_attempt_id: RequestNonce::fixture(2),
            reserved_at: OffsetDateTime::UNIX_EPOCH,
        },
    }
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

fn prepare_fake() -> Prepared<FakePersist> {
    let mut store = FakePersist::default();
    let parts = birth_parts();
    let lease_until = parts.birth.lease_until;
    store
        .reserve_controller_birth(&parts.birth, &parts.reservation)
        .expect("reserve");
    store
        .persist_arm(&PersistedArm {
            arm_id: parts.birth.arm_id.clone(),
            generation: parts.birth.generation,
            seat_id: parts.birth.seat_id.clone(),
            capability: parts.birth.capability,
            coverage_until: OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(600),
        })
        .expect("arm");
    let attempt_id = AttemptId::new("attempt-a").expect("attempt");
    let signal_id = SignalId::new("signal-a").expect("signal");
    let events = [
        wire_event("event-a", "test-a"),
        wire_event("event-b", "test-b"),
    ];
    let admission = claim_admission_fixture(
        "claim-a",
        parts.birth.arm_id.clone(),
        parts.birth.generation,
        signal_id.clone(),
        &events,
        OffsetDateTime::UNIX_EPOCH,
    );
    let attachment = PersistedControllerAttachment {
        attempt_id: attempt_id.clone(),
        birth_id: parts.birth.birth_id.clone(),
        seat_id: parts.birth.seat_id.clone(),
        arm_id: parts.birth.arm_id.clone(),
        generation: parts.birth.generation,
        capability: parts.birth.capability,
        lease_until,
        verifier_ref: VerifierRef::fixture(8),
        revoked: false,
    };
    store.admit_claim(&admission, &attachment).expect("admit");
    let grant = PersistedHelperGrant {
        grant_verifier: [0x33; 32],
        grant_ref: VerifierRef::fixture(9),
        seat_id: parts.birth.seat_id.clone(),
        arm_id: parts.birth.arm_id.clone(),
        generation: parts.birth.generation,
        birth_id: parts.birth.birth_id.clone(),
        attempt_id,
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
        seat_id: parts.birth.seat_id.clone(),
        arm_id: parts.birth.arm_id.clone(),
        generation: parts.birth.generation,
        birth_id: parts.birth.birth_id.clone(),
        attempt_id: grant.attempt_id,
        signal_id,
        claim_digest: admission.claim_digest.clone(),
        operations: HelperOperations::all(),
        lease_until,
    };
    Prepared {
        store,
        binding,
        admission,
        attachment,
    }
}

fn copy_binding(binding: &ValidatedHelperBinding) -> ValidatedHelperBinding {
    ValidatedHelperBinding {
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
    }
}

fn retrieve_for(binding: &ValidatedHelperBinding, nonce: u8) -> RetrieveExchange {
    let binding = copy_binding(binding);
    let request_id = RequestNonce::fixture(nonce);
    let canonical_body_digest =
        canonical_retrieve_body_digest(&canonical_binding_digest(&binding), &request_id);
    RetrieveExchange {
        binding,
        request_id,
        canonical_body_digest,
    }
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

fn recorded_retrieve(
    store: &mut impl Persist,
    binding: &ValidatedHelperBinding,
    nonce: u8,
) -> crate::persist::AuthorizedRetrieve {
    match store
        .record_retrieve_exchange(&retrieve_for(binding, nonce))
        .expect("retrieve")
    {
        IdempotentResult::Recorded(authorized) => authorized,
        IdempotentResult::ExactReplay(_) => panic!("first retrieve must record"),
    }
}

fn join_scope(binding: &ValidatedHelperBinding) -> RearmJoinScope {
    RearmJoinScope {
        arm_id: binding.arm_id.clone(),
        generation: binding.generation,
        attempt_id: binding.attempt_id.clone(),
        signal_id: binding.signal_id.clone(),
    }
}

fn err(error: PersistError) -> String {
    format!("{error:?}")
}

fn inconclusive(id: &str) -> String {
    format!("inconclusive: {id}")
}

fn expect_conflict(result: Result<(), PersistError>, label: &str) -> Result<(), String> {
    match result {
        Err(PersistError::Conflict) => Ok(()),
        Err(other) => Err(format!("expected {label} conflict, got {other:?}")),
        Ok(()) => Err(format!("expected {label} conflict, admitted instead")),
    }
}

fn run_port<F: ConformanceFixture>(id: &str) -> Result<(), String> {
    match id {
        "op.persist-arm" => {
            let Prepared {
                mut store, binding, ..
            } = F::prepare();
            arm_recovered(&mut store, &binding)
        }
        "op.recover-authority-state" => {
            let Prepared {
                mut store, binding, ..
            } = F::prepare();
            sections_omit_bodies(&mut store, &binding)
        }
        "op.admit-claim" => {
            let Prepared {
                mut store,
                admission,
                attachment,
                ..
            } = F::prepare();
            admit_idempotent_and_forged(&mut store, &admission, &attachment)
        }
        "op.reserve-controller-birth" => reserve_birth_replays::<F>(),
        "op.thread-ownership-state" => unresolved_create_quarantined::<F>(),
        "op.persist-helper-grant" | "grant.retired-identity-rejected" => {
            let Prepared { mut store, .. } = F::prepare();
            if id == "op.persist-helper-grant" {
                grant_rotation_retires_prior_ref(&mut store)
            } else {
                retired_identity_rejected(&mut store)
            }
        }
        "op.revoke-helper-grant" => {
            let Prepared {
                mut store, binding, ..
            } = F::prepare();
            revocation_sticky(&mut store, &binding)
        }
        "op.record-retrieve-exchange" => {
            let Prepared {
                mut store, binding, ..
            } = F::prepare();
            retrieve_exact(&mut store, &binding)
        }
        "replay.retrieve.changed-digest" => {
            let Prepared {
                mut store, binding, ..
            } = F::prepare();
            retrieve_changed_digest(&mut store, &binding)
        }
        "op.materialize-claimed-batch" => {
            let Prepared {
                mut store, binding, ..
            } = F::prepare();
            materialize_requires_binding(&mut store, &binding)
        }
        "op.acknowledge-retrieved-batch" => {
            let Prepared {
                mut store, binding, ..
            } = F::prepare();
            ack_exact(&mut store, &binding)
        }
        "replay.ack.reused-digest" => {
            let Prepared {
                mut store, binding, ..
            } = F::prepare();
            ack_reused_digest(&mut store, &binding)
        }
        "replay.fresh-refused-after-handled" => {
            let Prepared {
                mut store, binding, ..
            } = F::prepare();
            fresh_refused_after_handled(&mut store, &binding)
        }
        "op.try-rearm-join" => {
            let Prepared {
                mut store, binding, ..
            } = F::prepare();
            rearm_join_absent(&mut store, &binding)
        }
        "grant.verifier-redacted" => {
            let Prepared { mut store, .. } = F::prepare();
            verifier_redacted(&mut store)
        }
        other => Err(format!("not a port case: {other}")),
    }
}

fn admit_idempotent_and_forged(
    store: &mut impl Persist,
    admission: &ClaimAdmission,
    attachment: &PersistedControllerAttachment,
) -> Result<(), String> {
    let replay = store.admit_claim(admission, attachment).map_err(err)?;
    if replay.outcome != AdmissionOutcome::ExactReplay {
        return Err(format!("expected exact admission replay, got {replay:?}"));
    }
    let mut forged = admission.clone();
    forged.claim_digest = crate::controller::ClaimDigest::fixture(9);
    match store.admit_claim(&forged, attachment) {
        Err(PersistError::Conflict) => {
            let snapshot = store.recover_authority_state().map_err(err)?;
            if snapshot.claims.len() == 1 {
                Ok(())
            } else {
                Err(format!(
                    "forged digest mutated claims: {}",
                    snapshot.claims.len()
                ))
            }
        }
        other => Err(format!("expected forged-digest conflict, got {other:?}")),
    }
}

fn reserve_birth_replays<F: ConformanceFixture>() -> Result<(), String> {
    let mut store = F::empty();
    let parts = birth_parts();
    if store
        .reserve_controller_birth(&parts.birth, &parts.reservation)
        .map_err(err)?
        != ReserveBirthOutcome::Reserved
    {
        return Err("first reservation must record".into());
    }
    if store
        .reserve_controller_birth(&parts.birth, &parts.reservation)
        .map_err(err)?
        != ReserveBirthOutcome::ExactReplay
    {
        return Err("identical reservation must replay".into());
    }
    let mut changed = parts.reservation.clone();
    changed.create_attempt_id = RequestNonce::fixture(4);
    if store
        .reserve_controller_birth(&parts.birth, &changed)
        .map_err(err)?
        != ReserveBirthOutcome::Conflict
    {
        return Err("changed create attempt must conflict".into());
    }
    Ok(())
}

fn unresolved_create_quarantined<F: ConformanceFixture>() -> Result<(), String> {
    let mut store = F::empty();
    let parts = birth_parts();
    store
        .reserve_controller_birth(&parts.birth, &parts.reservation)
        .map_err(err)?;
    let snapshot = store.recover_authority_state().map_err(err)?;
    match snapshot.ownership.as_slice() {
        [row]
            if row.birth_id == parts.birth.birth_id
                && row.state
                    == ThreadOwnershipState::Unknown {
                        create_attempt_id: parts.reservation.create_attempt_id,
                    } =>
        {
            Ok(())
        }
        other => Err(format!("expected quarantined ownership, got {other:?}")),
    }
}

fn retrieve_exact(
    store: &mut impl Persist,
    binding: &ValidatedHelperBinding,
) -> Result<(), String> {
    let exchange = retrieve_for(binding, 21);
    let recorded = match store.record_retrieve_exchange(&exchange).map_err(err)? {
        IdempotentResult::Recorded(authorized) => authorized.recorded,
        IdempotentResult::ExactReplay(_) => return Err("first retrieve recorded".into()),
    };
    match store.record_retrieve_exchange(&exchange).map_err(err)? {
        IdempotentResult::ExactReplay(authorized) if authorized.recorded == recorded => Ok(()),
        other => Err(format!("expected exact retrieve replay, got {other:?}")),
    }
}

fn retrieve_changed_digest(
    store: &mut impl Persist,
    binding: &ValidatedHelperBinding,
) -> Result<(), String> {
    let exchange = retrieve_for(binding, 21);
    store.record_retrieve_exchange(&exchange).map_err(err)?;
    let mut conflict = retrieve_for(binding, 21);
    conflict.canonical_body_digest = CanonicalBodyDigest::fixture(22);
    match store.record_retrieve_exchange(&conflict) {
        Err(PersistError::Conflict) => {
            let snapshot = store.recover_authority_state().map_err(err)?;
            if snapshot.retrieve_replays.len() == 1 {
                Ok(())
            } else {
                Err(format!("replay rows {}", snapshot.retrieve_replays.len()))
            }
        }
        other => Err(format!("expected conflict, got {other:?}")),
    }
}

fn ack_exact(store: &mut impl Persist, binding: &ValidatedHelperBinding) -> Result<(), String> {
    let authorized = recorded_retrieve(store, binding, 31);
    let request = ack_for(binding, &authorized.recorded.retrieval_id, "event-a", 32);
    let accepted = match store
        .acknowledge_retrieved_batch(binding, &request)
        .map_err(err)?
    {
        IdempotentResult::Recorded(result) => result,
        IdempotentResult::ExactReplay(_) => return Err("first ack recorded".into()),
    };
    match store
        .acknowledge_retrieved_batch(binding, &request)
        .map_err(err)?
    {
        IdempotentResult::ExactReplay(result) if result == accepted => Ok(()),
        other => Err(format!("expected exact ack replay, got {other:?}")),
    }
}

fn ack_reused_digest(
    store: &mut impl Persist,
    binding: &ValidatedHelperBinding,
) -> Result<(), String> {
    let authorized = recorded_retrieve(store, binding, 33);
    let mut request = ack_for(binding, &authorized.recorded.retrieval_id, "event-a", 34);
    let original_digest = request.canonical_body_digest.clone();
    request.cursor = EventRef::new("event-b").expect("cursor");
    request.canonical_body_digest = original_digest;
    match store.acknowledge_retrieved_batch(binding, &request) {
        Err(PersistError::Conflict) => Ok(()),
        other => Err(format!("expected reused-digest conflict, got {other:?}")),
    }
}

fn fresh_refused_after_handled(
    store: &mut impl Persist,
    binding: &ValidatedHelperBinding,
) -> Result<(), String> {
    let exchange = retrieve_for(binding, 41);
    let recorded = match store.record_retrieve_exchange(&exchange).map_err(err)? {
        IdempotentResult::Recorded(authorized) => authorized.recorded,
        IdempotentResult::ExactReplay(_) => return Err("first retrieve recorded".into()),
    };
    let full = ack_for(binding, &recorded.retrieval_id, "event-b", 42);
    store
        .acknowledge_retrieved_batch(binding, &full)
        .map_err(err)?;
    match store.record_retrieve_exchange(&retrieve_for(binding, 43)) {
        Err(PersistError::InvalidTransition) => {}
        other => return Err(format!("expected fresh refusal, got {other:?}")),
    }
    match store.record_retrieve_exchange(&exchange).map_err(err)? {
        IdempotentResult::ExactReplay(authorized) if authorized.recorded == recorded => Ok(()),
        other => Err(format!("original retrieve did not replay: {other:?}")),
    }
}

fn arm_recovered(store: &mut impl Persist, binding: &ValidatedHelperBinding) -> Result<(), String> {
    let snapshot = store.recover_authority_state().map_err(err)?;
    if snapshot.arms.len() == 1 && snapshot.arms[0].arm_id == binding.arm_id {
        Ok(())
    } else {
        Err(format!("arm missing from recovery: {snapshot:?}"))
    }
}

fn sections_omit_bodies(
    store: &mut impl Persist,
    binding: &ValidatedHelperBinding,
) -> Result<(), String> {
    let authorized = recorded_retrieve(store, binding, 51);
    let full = ack_for(binding, &authorized.recorded.retrieval_id, "event-b", 52);
    store
        .acknowledge_retrieved_batch(binding, &full)
        .map_err(err)?;
    let snapshot = store.recover_authority_state().map_err(err)?;
    if snapshot.arms.len() != 1
        || snapshot.helper_grants.len() != 1
        || snapshot.retrieve_replays.len() != 1
        || snapshot.retrieval_bindings.len() != 1
        || snapshot.ack_replays.len() != 1
        || snapshot.handled_coverage.len() != 1
    {
        return Err(format!("sections incomplete: {snapshot:?}"));
    }
    let rendered = format!("{snapshot:?}");
    if rendered.contains("test-a") || rendered.contains("test-b") {
        Err(format!("payload body leaked into snapshot: {rendered}"))
    } else {
        Ok(())
    }
}

fn grant_rotation_retires_prior_ref(store: &mut impl Persist) -> Result<(), String> {
    let before = store.recover_authority_state().map_err(err)?;
    let mut replacement = before.helper_grants[0].clone();
    let prior_ref = replacement.grant_ref.clone();
    replacement.grant_verifier = [0x34; 32];
    replacement.grant_ref = VerifierRef::fixture(10);
    store.persist_helper_grant(&replacement).map_err(err)?;
    let snapshot = store.recover_authority_state().map_err(err)?;
    let retired = snapshot
        .retired_helper_grants
        .iter()
        .any(|grant| grant.grant_ref == prior_ref);
    let live = snapshot
        .helper_grants
        .iter()
        .any(|grant| grant.grant_ref == replacement.grant_ref && !grant.revoked);
    if retired && live && snapshot.helper_grants.len() == 1 {
        Ok(())
    } else {
        Err(format!("rotation snapshot: {snapshot:?}"))
    }
}

fn retired_identity_rejected(store: &mut impl Persist) -> Result<(), String> {
    let before = store.recover_authority_state().map_err(err)?;
    let prior = before.helper_grants[0].clone();
    let mut replacement = prior.clone();
    replacement.grant_verifier = [0x34; 32];
    replacement.grant_ref = VerifierRef::fixture(10);
    store.persist_helper_grant(&replacement).map_err(err)?;
    match store.persist_helper_grant(&prior) {
        Err(PersistError::Conflict) => Ok(()),
        other => Err(format!("expected retired-grant conflict, got {other:?}")),
    }
}

fn revocation_sticky(
    store: &mut impl Persist,
    binding: &ValidatedHelperBinding,
) -> Result<(), String> {
    let scope = HelperRevocationScope {
        grant_ref: binding.grant_ref.clone(),
        birth_id: binding.birth_id.clone(),
        attempt_id: binding.attempt_id.clone(),
    };
    if store.revoke_helper_grant(scope).map_err(err)? != IdempotentWrite::Recorded {
        return Err("revocation must record".into());
    }
    match store.record_retrieve_exchange(&retrieve_for(binding, 71)) {
        Err(PersistError::Unauthorized) => {}
        other => return Err(format!("expected unauthorized retrieve, got {other:?}")),
    }
    let snapshot = store.recover_authority_state().map_err(err)?;
    if snapshot.helper_grants.iter().any(|grant| grant.revoked) {
        Ok(())
    } else {
        Err(format!("revocation missing from snapshot: {snapshot:?}"))
    }
}

fn materialize_requires_binding(
    store: &mut impl Persist,
    binding: &ValidatedHelperBinding,
) -> Result<(), String> {
    let authorized = recorded_retrieve(store, binding, 81);
    let payload = store
        .materialize_claimed_batch(binding, authorized.permit)
        .map_err(err)?;
    if payload.events.as_slice().len() != 2 {
        return Err(format!("expected both events, got {payload:?}"));
    }
    let again = recorded_retrieve_replay(store, binding, 81)?;
    let mut forged = copy_binding(binding);
    forged.grant_ref = VerifierRef::fixture(12);
    match store.materialize_claimed_batch(&forged, again) {
        Err(PersistError::Unauthorized) => Ok(()),
        other => Err(format!("expected binding refusal, got {other:?}")),
    }
}

fn recorded_retrieve_replay(
    store: &mut impl Persist,
    binding: &ValidatedHelperBinding,
    nonce: u8,
) -> Result<crate::persist::ClaimMaterializationPermit, String> {
    match store
        .record_retrieve_exchange(&retrieve_for(binding, nonce))
        .map_err(err)?
    {
        IdempotentResult::ExactReplay(authorized) => Ok(authorized.permit),
        IdempotentResult::Recorded(_) => Err("expected retrieve replay".into()),
    }
}

fn rearm_join_absent(
    store: &mut impl Persist,
    binding: &ValidatedHelperBinding,
) -> Result<(), String> {
    match store.try_rearm_join(join_scope(binding)).map_err(err)? {
        RearmJoinResult::WaitingForHandled => {}
        other => return Err(format!("expected waiting for handled, got {other:?}")),
    }
    let snapshot = store.recover_authority_state().map_err(err)?;
    if snapshot.rearmed_joins.is_empty() && snapshot.handled_coverage.is_empty() {
        Ok(())
    } else {
        Err(format!("join recorded early: {snapshot:?}"))
    }
}

fn verifier_redacted(store: &mut impl Persist) -> Result<(), String> {
    let snapshot = store.recover_authority_state().map_err(err)?;
    let rendered = format!("{snapshot:?}");
    if rendered.contains("33, 51") || rendered.contains("[51, 51") {
        Err(format!("verifier bytes visible: {rendered}"))
    } else if rendered.contains("[redacted]") {
        Ok(())
    } else {
        Err(format!("verifier redaction missing: {rendered}"))
    }
}

fn pair_claims<F: ConformanceFixture>(
    snapshot: &RecoverySnapshot,
    payloads: &BTreeMap<ClaimPayloadRef, BoundedClaimPayload>,
) -> Result<
    (
        RecoverySnapshot,
        BTreeMap<ClaimPayloadRef, BoundedClaimPayload>,
        PersistedClaimRecord,
    ),
    String,
> {
    let mut claim_b = snapshot.claims[0].clone();
    claim_b.request_id = ClaimRequestId::new("claim-b").expect("claim");
    claim_b.attempt_id = AttemptId::new("attempt-b").expect("attempt");
    claim_b.signal_id = SignalId::new("signal-b").expect("signal");
    claim_b.payload_ref = ClaimPayloadRef::random().expect("payload ref");
    if let Some(coverage) = claim_b.coverage.as_mut() {
        coverage.request_id = claim_b.request_id.clone();
        coverage.signal_id = claim_b.signal_id.clone();
    }
    let payload_a = payloads
        .get(&snapshot.claims[0].payload_ref)
        .ok_or("missing payload")?
        .clone();
    claim_b.claim_digest = canonical_claim_digest(
        &claim_b.request_id,
        &claim_b.arm_id,
        claim_b.generation,
        &claim_b.signal_id,
        &claim_b.event_refs,
        &payload_a,
        claim_b.coverage.as_ref(),
        claim_b.drain_witness.as_ref(),
    );
    let mut both = snapshot.clone();
    let mut both_payloads = payloads.clone();
    both_payloads.insert(claim_b.payload_ref.clone(), payload_a);
    both.claims.push(claim_b.clone());
    F::admit_snapshot(both.clone(), both_payloads.clone()).map_err(err)?;
    Ok((both, both_payloads, claim_b))
}

fn run_snapshot<F: ConformanceFixture>(id: &str) -> Result<(), String> {
    let Prepared {
        mut store, binding, ..
    } = F::prepare();
    let recorded = recorded_retrieve(&mut store, &binding, 61).recorded;
    let full = ack_for(&binding, &recorded.retrieval_id, "event-b", 62);
    store
        .acknowledge_retrieved_batch(&binding, &full)
        .map_err(err)?;
    let payloads = F::payloads(&store);
    let snapshot = store.recover_authority_state().map_err(err)?;
    match id {
        "replay.restore.orphan-retrieval" => {
            let mut orphan = snapshot;
            orphan.retrieve_replays.clear();
            expect_conflict(F::admit_snapshot(orphan, payloads).map(|_| ()), "orphan")
        }
        "replay.restore.retrieval-id-mismatch" => {
            let mut mismatched = snapshot;
            mismatched.retrieval_bindings[0].retrieval_id = RetrievalId::fixture(99);
            expect_conflict(
                F::admit_snapshot(mismatched, payloads).map(|_| ()),
                "id mismatch",
            )
        }
        "replay.restore.unswapped-pair" => {
            let (both, both_payloads, _) = pair_claims::<F>(&snapshot, &payloads)?;
            F::admit_snapshot(both, both_payloads)
                .map(|_| ())
                .map_err(err)
        }
        "replay.restore.two-claim-substitution" => {
            let (mut both, both_payloads, claim_b) = pair_claims::<F>(&snapshot, &payloads)?;
            both.retrieve_replays[0].result.claim_payload_ref = claim_b.payload_ref.clone();
            both.retrieval_bindings[0].result.claim_payload_ref = claim_b.payload_ref;
            both.ack_replays[0].result.attempt_id = claim_b.attempt_id;
            both.ack_replays[0].result.signal_id = claim_b.signal_id;
            expect_conflict(
                F::admit_snapshot(both, both_payloads).map(|_| ()),
                "substitution",
            )
        }
        "replay.restore.forged-join" => {
            let mut forged = snapshot;
            forged.handled_coverage[0].cursor = EventRef::new("event-b").expect("cursor");
            forged.handled_coverage[0].covered_through_newest = true;
            forged
                .rearmed_joins
                .push(crate::persist::PersistedRearmJoin {
                    arm_id: binding.arm_id.clone(),
                    generation: binding.generation,
                    attempt_id: binding.attempt_id.clone(),
                    signal_id: binding.signal_id.clone(),
                });
            expect_conflict(
                F::admit_snapshot(forged, payloads).map(|_| ()),
                "forged-join",
            )
        }
        "replay.restore.terminal-leaves-partial-rearm" => terminal_leaves_partial_rearm::<F>(),
        other => Err(format!("not a snapshot case: {other}")),
    }
}

fn terminal_leaves_partial_rearm<F: ConformanceFixture>() -> Result<(), String> {
    let Prepared {
        mut store, binding, ..
    } = F::prepare();
    let exchange = retrieve_for(&binding, 91);
    let recorded = match store.record_retrieve_exchange(&exchange).map_err(err)? {
        IdempotentResult::Recorded(authorized) => authorized.recorded,
        IdempotentResult::ExactReplay(_) => return Err("first retrieve recorded".into()),
    };
    let partial = ack_for(&binding, &recorded.retrieval_id, "event-a", 92);
    store
        .acknowledge_retrieved_batch(&binding, &partial)
        .map_err(err)?;
    let payloads = F::payloads(&store);
    let mut snapshot = store.recover_authority_state().map_err(err)?;
    snapshot.native_turn_facts = vec![PersistedNativeTurnFacts {
        attempt_id: binding.attempt_id.clone(),
        facts: vec![NativeTurnFact::Terminal {
            turn_ref: PrivateNativeRef::fixture(7),
            class: TerminalClass::Succeeded,
        }],
    }];
    let mut restored = F::admit_snapshot(snapshot, payloads).map_err(err)?;
    match restored.try_rearm_join(join_scope(&binding)).map_err(err)? {
        RearmJoinResult::WaitingForHandled => {}
        other => return Err(format!("expected partial re-arm to wait, got {other:?}")),
    }
    match restored.record_retrieve_exchange(&retrieve_for(&binding, 93)) {
        Err(PersistError::InvalidTransition) => Ok(()),
        other => Err(format!(
            "expected fresh refusal after terminal, got {other:?}"
        )),
    }
}

/// Run one executable case on `F`. Gap evidence returns inconclusive.
pub(crate) fn execute<F: ConformanceFixture>(id: &str) -> Result<(), String> {
    let case = case(id).ok_or_else(|| format!("unknown case {id}"))?;
    match case.evidence {
        CaseEvidence::Gap { .. } => Err(inconclusive(id)),
        CaseEvidence::Port => run_port::<F>(id),
        CaseEvidence::SnapshotAdmission => run_snapshot::<F>(id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED_IDS: &[&str] = &[
        "op.admit-claim",
        "op.thread-ownership-state",
        "native.reservation-write-ambiguity",
        "op.revoke-helper-grant",
        "op.materialize-claimed-batch",
        "audit.mutation-sequence",
        "audit.torn-tail",
        "audit.rollback-continuity",
        "snapshot.reopened-media",
        "durability.sqlite-baseline",
        "custody.installation-identity",
        "retention.migration-compaction",
    ];

    #[test]
    fn catalog_separates_outcome_from_evidence() {
        let mut ids = std::collections::BTreeSet::new();
        for case in catalog() {
            assert!(ids.insert(case.id), "duplicate {}", case.id);
            assert!(!case.summary.is_empty(), "{}", case.id);
            if let CaseEvidence::Gap { owner } = case.evidence {
                assert!(!owner.is_empty(), "{}", case.id);
            }
        }
        for id in REQUIRED_IDS {
            assert!(case(id).is_some(), "missing {id}");
        }
        let operations = [
            "op.persist-arm",
            "op.admit-claim",
            "op.reserve-controller-birth",
            "op.resolve-thread-create",
            "op.thread-ownership-state",
            "op.record-dispatch-prepared",
            "op.record-prewrite-conclusion",
            "op.record-active-hold",
            "op.reserve-native-turn-write",
            "op.record-native-turn-fact",
            "op.record-native-write-evidence",
            "op.record-reconciliation-fact",
            "op.seal-native-coordinate",
            "op.open-native-coordinate",
            "op.persist-helper-grant",
            "op.revoke-controller-attachment",
            "op.revoke-helper-grant",
            "op.record-retrieve-exchange",
            "op.materialize-claimed-batch",
            "op.acknowledge-retrieved-batch",
            "op.try-rearm-join",
            "op.recover-authority-state",
        ];
        for id in operations {
            assert!(case(id).is_some(), "missing operation {id}");
        }
    }

    #[test]
    fn every_executable_case_passes_on_the_fake() {
        for case in catalog() {
            if matches!(case.evidence, CaseEvidence::Gap { .. }) {
                continue;
            }
            execute::<FakeFixture>(case.id).unwrap_or_else(|error| panic!("{}: {error}", case.id));
        }
    }

    #[test]
    fn gaps_are_inconclusive_and_keep_their_outcome() {
        for case in catalog() {
            let CaseEvidence::Gap { .. } = case.evidence else {
                continue;
            };
            let error = execute::<FakeFixture>(case.id).expect_err(case.id);
            assert!(error.contains("inconclusive"), "{error}");
            assert_ne!(error, "ok");
        }
    }
}
