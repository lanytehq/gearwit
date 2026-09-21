//! Provider-neutral persistence conformance catalog.
//!
//! Each case has a stable id, an expected outcome, and either an executable
//! check or an explicit gap that names the slice which owns it. Executable
//! checks use the sealed persistence port or body-free snapshot admission.
//! They do not add a backend method. The deterministic fake is the only
//! authority this module runs.

use crate::controller::{
    ArmId, AttemptId, BoundedToken, CanonicalBodyDigest, ClaimPayloadRef, ClaimRequestId,
    ControllerBirthId, EventRef, ManagedCapability, RequestNonce, RetrievalId, SeatId, SignalId,
    VerifierRef,
};
use crate::persist::{
    AcknowledgeRequest, FakePersist, HelperExecutableIdentity, HelperOperations, IdempotentResult,
    Persist, PersistError, PersistedArm, PersistedClaimRecord, PersistedControllerAttachment,
    PersistedControllerBirth, PersistedHelperGrant, RearmJoinResult, RearmJoinScope,
    RecoverySnapshot, RetrieveExchange, ThreadCreateReservation, ValidatedHelperBinding,
    canonical_ack_body_digest, canonical_binding_digest, canonical_claim_digest,
    canonical_retrieve_body_digest, claim_admission_fixture,
};
use gearwit_protocol::ProviderEvent;
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaseFamily {
    ReplayIdentity,
    AuditSequence,
    RecoverySnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExpectedOutcome {
    ExactReplay,
    Conflict,
    InvalidTransition,
    SectionsWithoutBodies,
    RetiredGrantRecorded,
    JoinAbsent,
    Admitted,
    Gap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaseEvidence {
    /// Any [`Persist`] implementor.
    Port,
    /// Body-free snapshot admission. Later providers supply the same check.
    /// This is not a live-port method and not a backend escape hatch.
    SnapshotAdmission,
    Gap {
        owner: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConformanceCase {
    pub id: &'static str,
    pub family: CaseFamily,
    pub expected: ExpectedOutcome,
    pub evidence: CaseEvidence,
    pub summary: &'static str,
}

const AUDIT_OWNER: &str = "provider-independent audit sequence";
const REOPEN_OWNER: &str = "reopened-media process-death fixtures";

/// Stable case inventory. Ids do not change when a provider is added.
pub(crate) fn catalog() -> &'static [ConformanceCase] {
    &CATALOG
}

const CATALOG: [ConformanceCase; 15] = [
    ConformanceCase {
        id: "replay.retrieve.exact",
        family: CaseFamily::ReplayIdentity,
        expected: ExpectedOutcome::ExactReplay,
        evidence: CaseEvidence::Port,
        summary: "a repeated retrieve returns the stored result",
    },
    ConformanceCase {
        id: "replay.retrieve.changed-digest",
        family: CaseFamily::ReplayIdentity,
        expected: ExpectedOutcome::Conflict,
        evidence: CaseEvidence::Port,
        summary: "the same nonce with a different request digest conflicts and leaves one replay row",
    },
    ConformanceCase {
        id: "replay.ack.exact",
        family: CaseFamily::ReplayIdentity,
        expected: ExpectedOutcome::ExactReplay,
        evidence: CaseEvidence::Port,
        summary: "a repeated acknowledgment returns the stored result",
    },
    ConformanceCase {
        id: "replay.fresh-refused-after-handled",
        family: CaseFamily::ReplayIdentity,
        expected: ExpectedOutcome::InvalidTransition,
        evidence: CaseEvidence::Port,
        summary: "fresh retrieve is refused after handled completion; the original retrieve still replays",
    },
    ConformanceCase {
        id: "replay.restore.orphan-retrieval",
        family: CaseFamily::ReplayIdentity,
        expected: ExpectedOutcome::Conflict,
        evidence: CaseEvidence::SnapshotAdmission,
        summary: "a retrieval index row with no retrieve replay is refused",
    },
    ConformanceCase {
        id: "replay.restore.retrieval-id-mismatch",
        family: CaseFamily::ReplayIdentity,
        expected: ExpectedOutcome::Conflict,
        evidence: CaseEvidence::SnapshotAdmission,
        summary: "a retrieval index id that differs from its result id is refused",
    },
    ConformanceCase {
        id: "replay.restore.unswapped-pair",
        family: CaseFamily::ReplayIdentity,
        expected: ExpectedOutcome::Admitted,
        evidence: CaseEvidence::SnapshotAdmission,
        summary: "two valid claims with unchanged retrieve and ack rows restore",
    },
    ConformanceCase {
        id: "replay.restore.two-claim-substitution",
        family: CaseFamily::ReplayIdentity,
        expected: ExpectedOutcome::Conflict,
        evidence: CaseEvidence::SnapshotAdmission,
        summary: "keeping A's request identity while pointing retrieve and ack results at B is refused",
    },
    ConformanceCase {
        id: "audit.mutation-sequence",
        family: CaseFamily::AuditSequence,
        expected: ExpectedOutcome::Gap,
        evidence: CaseEvidence::Gap { owner: AUDIT_OWNER },
        summary: "authority mutations do not yet append a provider-independent audit sequence",
    },
    ConformanceCase {
        id: "audit.torn-tail",
        family: CaseFamily::AuditSequence,
        expected: ExpectedOutcome::Gap,
        evidence: CaseEvidence::Gap { owner: AUDIT_OWNER },
        summary: "a torn audit tail is not yet refused",
    },
    ConformanceCase {
        id: "audit.rollback-continuity",
        family: CaseFamily::AuditSequence,
        expected: ExpectedOutcome::Gap,
        evidence: CaseEvidence::Gap { owner: AUDIT_OWNER },
        summary: "rollback continuity is not yet visible on the audit sequence",
    },
    ConformanceCase {
        id: "snapshot.helper-sections-omit-bodies",
        family: CaseFamily::RecoverySnapshot,
        expected: ExpectedOutcome::SectionsWithoutBodies,
        evidence: CaseEvidence::Port,
        summary: "grant, replay, retrieval, ack, and handled sections recover without payload bodies",
    },
    ConformanceCase {
        id: "snapshot.grant-rotation-retires-prior-ref",
        family: CaseFamily::RecoverySnapshot,
        expected: ExpectedOutcome::RetiredGrantRecorded,
        evidence: CaseEvidence::Port,
        summary: "rotation records the prior grant ref as retired and the replacement as live",
    },
    ConformanceCase {
        id: "snapshot.rearm-join-absent-before-handled",
        family: CaseFamily::RecoverySnapshot,
        expected: ExpectedOutcome::JoinAbsent,
        evidence: CaseEvidence::Port,
        summary: "re-arm waits and records no join until handled coverage exists",
    },
    ConformanceCase {
        id: "snapshot.reopened-media",
        family: CaseFamily::RecoverySnapshot,
        expected: ExpectedOutcome::Gap,
        evidence: CaseEvidence::Gap {
            owner: REOPEN_OWNER,
        },
        summary: "process-death reopen from durable media is not claimed by the in-memory fake",
    },
];

pub(crate) fn case(id: &str) -> Option<&'static ConformanceCase> {
    CATALOG.iter().find(|case| case.id == id)
}

struct Prepared {
    store: FakePersist,
    binding: ValidatedHelperBinding,
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

fn prepared() -> Prepared {
    let mut store = FakePersist::default();
    let birth_id = ControllerBirthId::fixture(1);
    let lease_until = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(60);
    let birth = PersistedControllerBirth {
        birth_id: birth_id.clone(),
        seat_id: SeatId::new("seat-a").expect("seat"),
        arm_id: ArmId::new("arm-a").expect("arm"),
        generation: 1,
        capability: ManagedCapability::HandleClaimedSignal,
        lease_until,
        verifier_ref: VerifierRef::fixture(3),
        created_at: OffsetDateTime::UNIX_EPOCH,
        revoked: false,
    };
    let create = ThreadCreateReservation {
        birth_id: birth_id.clone(),
        create_attempt_id: RequestNonce::fixture(2),
        reserved_at: OffsetDateTime::UNIX_EPOCH,
    };
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
    let events = [
        wire_event("event-a", "test-a"),
        wire_event("event-b", "test-b"),
    ];
    let admission = claim_admission_fixture(
        "claim-a",
        birth.arm_id.clone(),
        birth.generation,
        signal_id.clone(),
        &events,
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
        seat_id: birth.seat_id,
        arm_id: birth.arm_id,
        generation: birth.generation,
        birth_id: birth.birth_id,
        attempt_id: grant.attempt_id.clone(),
        signal_id,
        claim_digest: admission.claim_digest,
        operations: HelperOperations::all(),
        lease_until,
    };
    Prepared { store, binding }
}

fn retrieve_for(binding: &ValidatedHelperBinding, nonce: u8) -> RetrieveExchange {
    let binding = ValidatedHelperBinding {
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
) -> crate::persist::RecordedRetrieveResult {
    match store
        .record_retrieve_exchange(&retrieve_for(binding, nonce))
        .expect("retrieve")
    {
        IdempotentResult::Recorded(authorized) => authorized.recorded,
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

fn run_port(id: &str) -> Result<(), String> {
    let Prepared { mut store, binding } = prepared();
    run_port_on(id, &mut store, &binding)
}

fn run_port_on(
    id: &str,
    store: &mut impl Persist,
    binding: &ValidatedHelperBinding,
) -> Result<(), String> {
    match id {
        "replay.retrieve.exact" => retrieve_exact(store, binding),
        "replay.retrieve.changed-digest" => retrieve_changed_digest(store, binding),
        "replay.ack.exact" => ack_exact(store, binding),
        "replay.fresh-refused-after-handled" => fresh_refused_after_handled(store, binding),
        "snapshot.helper-sections-omit-bodies" => helper_sections_omit_bodies(store, binding),
        "snapshot.grant-rotation-retires-prior-ref" => grant_rotation_retires_prior_ref(store),
        "snapshot.rearm-join-absent-before-handled" => {
            rearm_join_absent_before_handled(store, binding)
        }
        other => Err(format!("not a port case: {other}")),
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
    let recorded = recorded_retrieve(store, binding, 31);
    let request = ack_for(binding, &recorded.retrieval_id, "event-a", 32);
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

fn helper_sections_omit_bodies(
    store: &mut impl Persist,
    binding: &ValidatedHelperBinding,
) -> Result<(), String> {
    let recorded = recorded_retrieve(store, binding, 51);
    let full = ack_for(binding, &recorded.retrieval_id, "event-b", 52);
    store
        .acknowledge_retrieved_batch(binding, &full)
        .map_err(err)?;
    let snapshot = store.recover_authority_state().map_err(err)?;
    if snapshot.helper_grants.len() != 1
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

fn rearm_join_absent_before_handled(
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

fn second_claim(snapshot: &RecoverySnapshot) -> (PersistedClaimRecord, ClaimPayloadRef) {
    let mut claim_b = snapshot.claims[0].clone();
    claim_b.request_id = ClaimRequestId::new("claim-b").expect("claim");
    claim_b.attempt_id = AttemptId::new("attempt-b").expect("attempt");
    claim_b.signal_id = SignalId::new("signal-b").expect("signal");
    claim_b.payload_ref = ClaimPayloadRef::random().expect("payload ref");
    if let Some(coverage) = claim_b.coverage.as_mut() {
        coverage.request_id = claim_b.request_id.clone();
        coverage.signal_id = claim_b.signal_id.clone();
    }
    let payload_ref = claim_b.payload_ref.clone();
    (claim_b, payload_ref)
}

fn run_snapshot(id: &str) -> Result<(), String> {
    let Prepared { mut store, binding } = prepared();
    let recorded = recorded_retrieve(&mut store, &binding, 61);
    let full = ack_for(&binding, &recorded.retrieval_id, "event-b", 62);
    store
        .acknowledge_retrieved_batch(&binding, &full)
        .map_err(err)?;
    let payloads = store.claim_payloads();
    let snapshot = store.recover_authority_state().map_err(err)?;
    match id {
        "replay.restore.orphan-retrieval" => {
            let mut orphan = snapshot;
            orphan.retrieve_replays.clear();
            match FakePersist::restore_from_snapshot(orphan, payloads) {
                Err(PersistError::Conflict) => Ok(()),
                other => Err(format!("expected orphan conflict, got {other:?}")),
            }
        }
        "replay.restore.retrieval-id-mismatch" => {
            let mut mismatched = snapshot;
            mismatched.retrieval_bindings[0].retrieval_id = RetrievalId::fixture(99);
            match FakePersist::restore_from_snapshot(mismatched, payloads) {
                Err(PersistError::Conflict) => Ok(()),
                other => Err(format!("expected id mismatch conflict, got {other:?}")),
            }
        }
        "replay.restore.unswapped-pair" => {
            let (claim_b, payload_ref) = second_claim(&snapshot);
            let payload_a = payloads
                .get(&snapshot.claims[0].payload_ref)
                .expect("payload")
                .clone();
            let mut claim_b = claim_b;
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
            let mut both = snapshot;
            let mut both_payloads = payloads;
            both_payloads.insert(payload_ref, payload_a);
            both.claims.push(claim_b);
            FakePersist::restore_from_snapshot(both, both_payloads)
                .map(|_| ())
                .map_err(err)
        }
        "replay.restore.two-claim-substitution" => {
            let (mut claim_b, payload_ref) = second_claim(&snapshot);
            let payload_a = payloads
                .get(&snapshot.claims[0].payload_ref)
                .expect("payload")
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
            let mut both = snapshot;
            let mut both_payloads = payloads;
            both_payloads.insert(payload_ref.clone(), payload_a);
            both.claims.push(claim_b.clone());
            FakePersist::restore_from_snapshot(both.clone(), both_payloads.clone()).map_err(err)?;
            both.retrieve_replays[0].result.claim_payload_ref = payload_ref.clone();
            both.retrieval_bindings[0].result.claim_payload_ref = payload_ref;
            both.ack_replays[0].result.attempt_id = claim_b.attempt_id;
            both.ack_replays[0].result.signal_id = claim_b.signal_id;
            match FakePersist::restore_from_snapshot(both, both_payloads) {
                Err(PersistError::Conflict) => Ok(()),
                other => Err(format!("expected substitution conflict, got {other:?}")),
            }
        }
        other => Err(format!("not a snapshot case: {other}")),
    }
}

fn err(error: PersistError) -> String {
    format!("{error:?}")
}

/// Run one executable case. Gaps and unknown ids return an error.
pub(crate) fn execute(id: &str) -> Result<(), String> {
    let case = case(id).ok_or_else(|| format!("unknown case {id}"))?;
    match case.evidence {
        CaseEvidence::Gap { .. } => Err(format!("gap case is not executed: {id}")),
        CaseEvidence::Port => run_port(id),
        CaseEvidence::SnapshotAdmission => run_snapshot(id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_ids_are_unique_and_families_are_closed() {
        let mut ids = std::collections::BTreeSet::new();
        for case in catalog() {
            assert!(ids.insert(case.id), "duplicate {}", case.id);
            assert!(!case.summary.is_empty());
            match case.evidence {
                CaseEvidence::Gap { owner } => {
                    assert_eq!(case.expected, ExpectedOutcome::Gap);
                    assert!(!owner.is_empty());
                }
                CaseEvidence::Port | CaseEvidence::SnapshotAdmission => {
                    assert_ne!(case.expected, ExpectedOutcome::Gap);
                }
            }
        }
        for family in [
            CaseFamily::ReplayIdentity,
            CaseFamily::AuditSequence,
            CaseFamily::RecoverySnapshot,
        ] {
            assert!(catalog().iter().any(|case| case.family == family));
        }
        let gaps: Vec<_> = catalog()
            .iter()
            .filter(|case| matches!(case.evidence, CaseEvidence::Gap { .. }))
            .map(|case| case.id)
            .collect();
        assert_eq!(
            gaps,
            vec![
                "audit.mutation-sequence",
                "audit.torn-tail",
                "audit.rollback-continuity",
                "snapshot.reopened-media",
            ]
        );
    }

    #[test]
    fn every_executable_case_passes_on_the_fake() {
        for case in catalog() {
            if matches!(case.evidence, CaseEvidence::Gap { .. }) {
                continue;
            }
            execute(case.id).unwrap_or_else(|error| panic!("{}: {error}", case.id));
        }
    }

    #[test]
    fn port_case_rejects_a_backend_only_id() {
        let error = execute("audit.mutation-sequence").expect_err("gap");
        assert!(error.contains("gap"), "{error}");
    }
}
