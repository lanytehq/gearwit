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
    FixedTimeComparison,
    VerifierOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaseEvidence {
    Port,
    SnapshotAdmission,
    /// Proved by a separate writer process that is killed without cleanup.
    ProcessCrash,
    Gap {
        owner: &'static str,
    },
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
const IDENTITY: &str = "bounded claim request identity and private nonce validation";
const VERIFIER: &str = "fixed-time grant verifier comparison";

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

macro_rules! crash {
    ($id:literal, $family:ident, $required:ident, $summary:literal) => {
        ConformanceCase {
            id: $id,
            family: CaseFamily::$family,
            required: RequiredOutcome::$required,
            evidence: CaseEvidence::ProcessCrash,
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
    crash!(
        "snapshot.reopened-media.post-commit",
        Durability,
        ExactReplay,
        "SIGKILL after a committed helper transaction; a fresh process replays that retrieve and payload"
    ),
    crash!(
        "snapshot.reopened-media.pre-commit",
        Durability,
        NoPartialRecord,
        "SIGKILL during an open transaction; a fresh process keeps the previous committed pair"
    ),
    gap!(
        "snapshot.reopened-media",
        Durability,
        FailClosed,
        REOPEN,
        "host restart, power loss, and crash windows other than the named process_crash cases stay unproved"
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
    port!(
        "replay.retrieve.exact",
        ReplayIdentity,
        ExactReplay,
        "alias of op.record-retrieve-exchange"
    ),
    port!(
        "replay.ack.exact",
        ReplayIdentity,
        ExactReplay,
        "alias of op.acknowledge-retrieved-batch"
    ),
    port!(
        "snapshot.helper-sections-omit-bodies",
        RecoverySnapshot,
        SectionsWithoutBodies,
        "alias of op.recover-authority-state"
    ),
    port!(
        "snapshot.grant-rotation-retires-prior-ref",
        Revocation,
        RetiredGrantRecorded,
        "alias of op.persist-helper-grant"
    ),
    port!(
        "snapshot.rearm-join-absent-before-handled",
        RecoverySnapshot,
        JoinAbsent,
        "alias of op.try-rearm-join"
    ),
    port!(
        "grant.reissue-denied-after-revocation",
        Revocation,
        Conflict,
        "a revoked helper grant cannot be re-issued under a fresh ref and verifier"
    ),
    snap!(
        "grant.revocation-survives-admission",
        Revocation,
        StickyRevocation,
        "revocation remains set after snapshot admission and still denies re-issue"
    ),
    gap!(
        "auth.stale-generation",
        Revocation,
        Unauthorized,
        NATIVE,
        "fresh helper use and the controller path refuse a stale generation; an authenticated exact helper replay remains valid"
    ),
    gap!(
        "auth.expired-lease",
        Revocation,
        Unauthorized,
        NATIVE,
        "fresh helper use and the controller path refuse an expired lease; an authenticated exact helper replay remains valid"
    ),
    gap!(
        "auth.mismatched-controller",
        Revocation,
        Unauthorized,
        NATIVE,
        "a mismatched controller is refused"
    ),
    gap!(
        "auth.link-loss",
        Revocation,
        InvalidTransition,
        NATIVE,
        "fresh helper use after controller link loss returns InvalidTransition; an authenticated exact helper replay remains valid, and revocation still precedes this path"
    ),
    gap!(
        "claim.request-id-stable",
        ClaimAdmission,
        ExactReplay,
        IDENTITY,
        "a bounded claim request id stays accepted and stable"
    ),
    gap!(
        "claim.private-nonce-strict",
        ClaimAdmission,
        Conflict,
        IDENTITY,
        "a private nonce that is not 256 bits is refused"
    ),
    gap!(
        "native.probe-epoch-mismatch",
        NativeWrite,
        Unauthorized,
        NATIVE,
        "a reservation or command probe whose epoch mismatches fails before any write"
    ),
    gap!(
        "native.changed-observation-conflicts",
        NativeWrite,
        Conflict,
        NATIVE,
        "a changed prehash, fingerprint, or binding conflicts and records no conclusion"
    ),
    gap!(
        "native.changed-epoch-conflicts",
        NativeWrite,
        Conflict,
        NATIVE,
        "a changed mutation epoch conflicts"
    ),
    gap!(
        "ownership.duplicate",
        RecoverySnapshot,
        Conflict,
        NATIVE,
        "a duplicate ownership row fails recovery"
    ),
    gap!(
        "ownership.orphan",
        RecoverySnapshot,
        Conflict,
        NATIVE,
        "an orphan ownership row fails recovery"
    ),
    gap!(
        "ownership.conflicting-recovery",
        RecoverySnapshot,
        Conflict,
        NATIVE,
        "conflicting ownership rows fail recovery"
    ),
    gap!(
        "restart.reserved-first-create",
        Durability,
        ExactReplay,
        REOPEN,
        "restart from a reserved first create restores that reservation and no later fact"
    ),
    gap!(
        "restart.held-before-native-write",
        Durability,
        BothRecordsOrNeither,
        REOPEN,
        "restart from a pre-write hold restores the hold and no native acceptance"
    ),
    gap!(
        "restart.idle-state-unproven",
        Durability,
        NoPartialRecord,
        REOPEN,
        "restart from idle-state-unproven preserves the claim and records no native acceptance"
    ),
    gap!(
        "grant.verifier-fixed-time",
        Revocation,
        FixedTimeComparison,
        VERIFIER,
        "verifier presentation comparison does not take a data-dependent branch"
    ),
    gap!(
        "durability.interior-corruption",
        Durability,
        TornTailRefused,
        REOPEN,
        "interior corruption is refused on recovery"
    ),
    gap!(
        "durability.migration-crash",
        Retention,
        FailClosed,
        RETENTION,
        "a crash during migration fails closed"
    ),
    gap!(
        "durability.snapshot-crash",
        Durability,
        FailClosed,
        REOPEN,
        "a crash during snapshot write fails closed"
    ),
    gap!(
        "durability.compaction-crash",
        Retention,
        FailClosed,
        RETENTION,
        "a crash during compaction fails closed"
    ),
    gap!(
        "materialize.no-unscoped-oracle",
        Materialization,
        Unauthorized,
        NATIVE,
        "no unscoped content oracle can materialize a claim payload"
    ),
    gap!(
        "native.active-turn-preserves-claim",
        NativeWrite,
        BothRecordsOrNeither,
        NATIVE,
        "an exact active turn preserves the claim and records a pre-write hold with no native acceptance"
    ),
    gap!(
        "native.no-store-key",
        Custody,
        FailClosed,
        CUSTODY,
        "store key material and a MAC oracle never enter the controller"
    ),
    gap!(
        "join.unclassified-completion",
        ReplayIdentity,
        Conflict,
        NATIVE,
        "an unclassified completion cannot satisfy the handled and terminal join"
    ),
    gap!(
        "join.malformed-completion",
        ReplayIdentity,
        Conflict,
        NATIVE,
        "a malformed completion cannot satisfy the handled and terminal join"
    ),
    gap!(
        "join.in-progress-completion",
        ReplayIdentity,
        JoinAbsent,
        NATIVE,
        "an in-progress completion cannot satisfy the handled and terminal join"
    ),
    gap!(
        "claim.first-admission-atomic",
        ClaimAdmission,
        NoPartialRecord,
        NATIVE,
        "the first claim either persists in full or leaves no partial admission"
    ),
    gap!(
        "handled.cursor-atomic",
        RecoverySnapshot,
        BothRecordsOrNeither,
        NATIVE,
        "handled state and the provider cursor persist together or not at all"
    ),
    gap!(
        "join.handled-and-terminal-succeeds",
        RecoverySnapshot,
        Recorded,
        NATIVE,
        "a daemon-owned handled cursor plus recognized terminal evidence records the join"
    ),
    gap!(
        "restart.no-active-coordinate-reconstruct",
        Durability,
        FailClosed,
        NATIVE,
        "restart does not open or reconstruct an active-turn or transient-thread coordinate"
    ),
    gap!(
        "native.durable-unproven-bound",
        NativeWrite,
        BothRecordsOrNeither,
        NATIVE,
        "durable Unproven is a fully bound path, separate from proof and hold atomicity"
    ),
    gap!(
        "grant.persisted-verifier-only",
        Revocation,
        VerifierOnly,
        VERIFIER,
        "persisted grant data keeps the verifier and not the raw key"
    ),
    gap!(
        "auth.exact-helper-replay-survives-lease",
        ReplayIdentity,
        ExactReplay,
        NATIVE,
        "an authenticated exact helper replay remains valid after lease expiry"
    ),
    gap!(
        "custody.raw-artifacts",
        Custody,
        FailClosed,
        CUSTODY,
        "raw authority artifacts expose no private sentinel"
    ),
    gap!(
        "custody.snapshots-and-backups",
        Custody,
        FailClosed,
        CUSTODY,
        "snapshots and backups expose no private sentinel"
    ),
    gap!(
        "custody.incorrect-key",
        Custody,
        FailClosed,
        CUSTODY,
        "incorrect key material refuses recovery and writes no plaintext"
    ),
    gap!(
        "custody.no-plaintext-create",
        Custody,
        FailClosed,
        CUSTODY,
        "key refusal creates no plaintext"
    ),
    gap!(
        "custody.no-plaintext-migrate",
        Custody,
        FailClosed,
        CUSTODY,
        "key refusal migrates no plaintext"
    ),
    gap!(
        "custody.no-plaintext-export",
        Custody,
        FailClosed,
        CUSTODY,
        "key refusal exports no plaintext"
    ),
    gap!(
        "custody.wrong-store-identity",
        Custody,
        FailClosed,
        CUSTODY,
        "the wrong store identity is refused"
    ),
    gap!(
        "custody.unexpected-ancestry",
        Custody,
        FailClosed,
        CUSTODY,
        "unexpected ancestry is refused"
    ),
    gap!(
        "custody.unexpected-generation",
        Custody,
        FailClosed,
        CUSTODY,
        "an unexpected store generation is refused"
    ),
    gap!(
        "retention.steady-state-size",
        Retention,
        FailClosed,
        RETENTION,
        "post-retention steady-state size stays inside the declared budget"
    ),
    gap!(
        "retention.packing-amplification",
        Retention,
        FailClosed,
        RETENTION,
        "compaction and packing amplification stay inside the declared budget"
    ),
    gap!(
        "retention.maintenance-scratch",
        Retention,
        FailClosed,
        RETENTION,
        "maintenance scratch stays inside the declared budget"
    ),
    gap!(
        "retention.sealed-generation-rollover",
        Retention,
        FailClosed,
        RETENTION,
        "sealed-generation rollover stays inside the declared budget and fails closed past it"
    ),
];

pub(crate) fn case(id: &str) -> Option<&'static ConformanceCase> {
    CATALOG.iter().find(|case| case.id == id)
}

/// One predicate inside a brief conformance-matrix row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MatrixPredicate {
    pub label: &'static str,
    pub case_id: &'static str,
}

/// One brief matrix row. A row is not covered by a single positive operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MatrixRow {
    pub id: &'static str,
    pub predicates: &'static [MatrixPredicate],
}

macro_rules! pred {
    ($label:literal => $id:literal) => {
        MatrixPredicate {
            label: $label,
            case_id: $id,
        }
    };
}

/// Row-by-row crosswalk of the brief conformance matrix.
pub(crate) fn matrix() -> &'static [MatrixRow] {
    MATRIX
}

const MATRIX: &[MatrixRow] = &[
    MatrixRow {
        id: "matrix.claim-atomicity",
        predicates: &[
            pred!("first admission is atomic" => "claim.first-admission-atomic"),
            pred!("identical admission replays" => "op.admit-claim"),
            pred!("forged digest conflicts and leaves the stored claim" => "op.admit-claim"),
        ],
    },
    MatrixRow {
        id: "matrix.failure-windows",
        predicates: &[
            pred!("failure before append" => "crash.failure-windows"),
            pred!("failure during commit" => "crash.failure-windows"),
            pred!("failure after claim" => "crash.failure-windows"),
            pred!("failure before native send" => "crash.failure-windows"),
            pred!("failure after possible native acceptance" => "crash.failure-windows"),
        ],
    },
    MatrixRow {
        id: "matrix.restart-phases",
        predicates: &[
            pred!("restart from claimed" => "restart.phase-matrix"),
            pred!("restart from prepared" => "restart.phase-matrix"),
            pred!("restart from in-flight" => "restart.phase-matrix"),
            pred!("restart from ambiguous" => "restart.phase-matrix"),
            pred!("restart from terminal" => "restart.phase-matrix"),
            pred!("restart from handled" => "restart.phase-matrix"),
        ],
    },
    MatrixRow {
        id: "matrix.restart-reserved-held-idle",
        predicates: &[
            pred!("reserved first create" => "restart.reserved-first-create"),
            pred!("ambiguous create quarantine" => "op.thread-ownership-state"),
            pred!("held before native write" => "restart.held-before-native-write"),
            pred!("idle state unproven" => "restart.idle-state-unproven"),
        ],
    },
    MatrixRow {
        id: "matrix.reconciliation",
        predicates: &[
            pred!("proven not accepted" => "op.record-reconciliation-fact"),
            pred!("accepted" => "op.record-reconciliation-fact"),
            pred!("terminal" => "op.record-reconciliation-fact"),
            pred!("unknown" => "op.record-reconciliation-fact"),
        ],
    },
    MatrixRow {
        id: "matrix.stale-lease-controller-link",
        predicates: &[
            pred!("stale generation" => "auth.stale-generation"),
            pred!("expired lease" => "auth.expired-lease"),
            pred!("mismatched controller" => "auth.mismatched-controller"),
            pred!("fresh helper controller-loss returns InvalidTransition" => "auth.link-loss"),
            pred!("exact helper replay survives lease expiry" => "auth.exact-helper-replay-survives-lease"),
        ],
    },
    MatrixRow {
        id: "matrix.recyclable-identity",
        predicates: &[pred!("recycled process port or socket" => "native.recyclable-identity")],
    },
    MatrixRow {
        id: "matrix.active-turn-hold",
        predicates: &[
            pred!("claim preserved and hold without acceptance" => "native.active-turn-preserves-claim"),
        ],
    },
    MatrixRow {
        id: "matrix.active-observation",
        predicates: &[
            pred!("proof and held commit together" => "native.active-hold-atomicity"),
            pred!("changed prehash, fingerprint, or binding conflicts" => "native.changed-observation-conflicts"),
            pred!("restart does not reconstruct active or transient coordinates" => "restart.no-active-coordinate-reconstruct"),
            pred!("no store key in the controller" => "native.no-store-key"),
        ],
    },
    MatrixRow {
        id: "matrix.rejected-proof",
        predicates: &[
            pred!("rejected proof records neither held nor unproven" => "native.active-hold-atomicity"),
            pred!("durable unproven is a fully bound path" => "native.durable-unproven-bound"),
        ],
    },
    MatrixRow {
        id: "matrix.idle-unproven",
        predicates: &[pred!("idle unproven preserves the claim" => "restart.idle-state-unproven")],
    },
    MatrixRow {
        id: "matrix.idle-permits",
        predicates: &[
            pred!("missing stale replayed mismatched or restart-carried permits" => "native.idle-permit-negatives"),
        ],
    },
    MatrixRow {
        id: "matrix.epoch-crash-windows",
        predicates: &[
            pred!("reservation crash window" => "native.reservation-write-ambiguity"),
            pred!("write crash window" => "native.reservation-write-ambiguity"),
            pred!("response crash window" => "native.reservation-write-ambiguity"),
        ],
    },
    MatrixRow {
        id: "matrix.epoch-replay",
        predicates: &[
            pred!("exact epoch replay" => "native.epoch-invalidation"),
            pred!("changed epoch conflicts" => "native.changed-epoch-conflicts"),
            pred!("restart retains the zero-write conclusion" => "native.epoch-invalidation"),
        ],
    },
    MatrixRow {
        id: "matrix.claim-id-and-nonce",
        predicates: &[
            pred!("bounded claim request id remains stable" => "claim.request-id-stable"),
            pred!("private nonce validation stays strict" => "claim.private-nonce-strict"),
        ],
    },
    MatrixRow {
        id: "matrix.probe-epoch-and-ownership",
        predicates: &[
            pred!("probe epoch mismatch" => "native.probe-epoch-mismatch"),
            pred!("duplicate ownership" => "ownership.duplicate"),
            pred!("orphan ownership" => "ownership.orphan"),
            pred!("conflicting ownership" => "ownership.conflicting-recovery"),
        ],
    },
    MatrixRow {
        id: "matrix.monotonic-lifecycle",
        predicates: &[
            pred!("duplicate regressive or conflicting transition" => "native.monotonic-lifecycle"),
        ],
    },
    MatrixRow {
        id: "matrix.audit-atomicity",
        predicates: &[
            pred!("mutation and audit commit together" => "audit.mutation-sequence"),
            pred!("duplicate record with changed content" => "audit.conflicting-sequence"),
            pred!("gapped or rolled-back sequence" => "audit.rollback-continuity"),
            pred!("conflicting sequence" => "audit.conflicting-sequence"),
        ],
    },
    MatrixRow {
        id: "matrix.torn-interior-migration",
        predicates: &[
            pred!("torn tail" => "audit.torn-tail"),
            pred!("interior corruption" => "durability.interior-corruption"),
            pred!("migration crash" => "durability.migration-crash"),
            pred!("snapshot crash" => "durability.snapshot-crash"),
            pred!("compaction crash" => "durability.compaction-crash"),
        ],
    },
    MatrixRow {
        id: "matrix.handled-rearm",
        predicates: &[
            pred!("handled cursor closes fresh use" => "replay.fresh-refused-after-handled"),
            pred!("handled state and provider cursor persist together" => "handled.cursor-atomic"),
            pred!("recognized terminal records the join" => "join.handled-and-terminal-succeeds"),
            pred!("re-arm waits without handled coverage" => "snapshot.rearm-join-absent-before-handled"),
        ],
    },
    MatrixRow {
        id: "matrix.unrecognized-join",
        predicates: &[
            pred!("missing terminal" => "replay.restore.forged-join"),
            pred!("terminal without full handled coverage" => "replay.restore.terminal-leaves-partial-rearm"),
            pred!("unclassified completion" => "join.unclassified-completion"),
            pred!("malformed completion" => "join.malformed-completion"),
            pred!("in-progress completion" => "join.in-progress-completion"),
        ],
    },
    MatrixRow {
        id: "matrix.revocation-reissue",
        predicates: &[
            pred!("live revocation refuses fresh retrieve" => "op.revoke-helper-grant"),
            pred!("revocation survives snapshot admission" => "grant.revocation-survives-admission"),
            pred!("re-issue after revocation is denied" => "grant.reissue-denied-after-revocation"),
        ],
    },
    MatrixRow {
        id: "matrix.materialization",
        predicates: &[
            pred!("materialization requires the sealed binding" => "op.materialize-claimed-batch"),
            pred!("no unscoped content oracle" => "materialize.no-unscoped-oracle"),
        ],
    },
    MatrixRow {
        id: "matrix.verifier-fixed-time-zeroize",
        predicates: &[
            pred!("persisted grant data is verifier-only" => "grant.persisted-verifier-only"),
            pred!("recovered verifier is redacted" => "grant.verifier-redacted"),
            pred!("comparison is fixed-time" => "grant.verifier-fixed-time"),
            pred!("opened coordinate plaintext is erased" => "op.seal-native-coordinate"),
        ],
    },
    MatrixRow {
        id: "matrix.root-permission",
        predicates: &[pred!("unwritable root fails closed" => "custody.root-permission")],
    },
    MatrixRow {
        id: "matrix.redacted-export",
        predicates: &[pred!("export contains no forbidden sentinel" => "custody.redacted-export")],
    },
    MatrixRow {
        id: "matrix.snapshot-body-free",
        predicates: &[
            pred!("recovery omits provider bodies" => "snapshot.helper-sections-omit-bodies"),
            pred!("an unswapped pair restores through the private claim reference" => "replay.restore.unswapped-pair"),
            pred!("a substituted result is refused" => "replay.restore.two-claim-substitution"),
        ],
    },
    MatrixRow {
        id: "matrix.private-key-refusal",
        predicates: &[
            pred!("absent key refuses recovery" => "custody.key-refusal"),
            pred!("incorrect key refuses recovery" => "custody.incorrect-key"),
            pred!("raw artifacts expose no sentinel" => "custody.raw-artifacts"),
            pred!("snapshots and backups expose no sentinel" => "custody.snapshots-and-backups"),
            pred!("crash remnants expose no sentinel" => "custody.redacted-export"),
            pred!("no plaintext create" => "custody.no-plaintext-create"),
            pred!("no plaintext migrate" => "custody.no-plaintext-migrate"),
            pred!("no plaintext export" => "custody.no-plaintext-export"),
        ],
    },
    MatrixRow {
        id: "matrix.installation-identity",
        predicates: &[
            pred!("wrong installation or second host is refused" => "custody.installation-identity"),
            pred!("wrong store identity is refused" => "custody.wrong-store-identity"),
            pred!("unexpected ancestry is refused" => "custody.unexpected-ancestry"),
            pred!("unexpected store generation is refused" => "custody.unexpected-generation"),
        ],
    },
    MatrixRow {
        id: "matrix.retention",
        predicates: &[
            pred!("capacity refusal" => "retention.migration-compaction"),
            pred!("post-retention steady-state size" => "retention.steady-state-size"),
            pred!("packing amplification" => "retention.packing-amplification"),
            pred!("maintenance scratch" => "retention.maintenance-scratch"),
            pred!("sealed-generation rollover" => "retention.sealed-generation-rollover"),
            pred!("migration crash" => "durability.migration-crash"),
            pred!("compaction crash" => "durability.compaction-crash"),
        ],
    },
    MatrixRow {
        id: "matrix.disabled-remote",
        predicates: &[
            pred!("disabled remote makes no network attempt" => "durability.disabled-remote"),
        ],
    },
    MatrixRow {
        id: "matrix.sqlite-baseline",
        predicates: &[
            pred!("bundled baseline passes this catalog" => "durability.sqlite-baseline"),
        ],
    },
];

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
        let mut store = FakePersist::default();
        let (binding, admission, attachment) = install_helper(&mut store);
        Prepared {
            store,
            binding,
            admission,
            attachment,
        }
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

pub(crate) struct BirthParts {
    pub(crate) birth: PersistedControllerBirth,
    pub(crate) reservation: ThreadCreateReservation,
}

pub(crate) fn birth_parts() -> BirthParts {
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

pub(crate) fn install_helper(
    store: &mut impl Persist,
) -> (
    ValidatedHelperBinding,
    ClaimAdmission,
    PersistedControllerAttachment,
) {
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
    (binding, admission, attachment)
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

pub(crate) fn retrieve_for(binding: &ValidatedHelperBinding, nonce: u8) -> RetrieveExchange {
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

pub(crate) fn ack_for(
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
        "op.recover-authority-state" | "snapshot.helper-sections-omit-bodies" => {
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
        "op.persist-helper-grant"
        | "snapshot.grant-rotation-retires-prior-ref"
        | "grant.retired-identity-rejected" => {
            let Prepared { mut store, .. } = F::prepare();
            if id == "grant.retired-identity-rejected" {
                retired_identity_rejected(&mut store)
            } else {
                grant_rotation_retires_prior_ref(&mut store)
            }
        }
        "op.revoke-helper-grant" => {
            let Prepared {
                mut store, binding, ..
            } = F::prepare();
            revocation_sticky(&mut store, &binding)
        }
        "grant.reissue-denied-after-revocation" => {
            let Prepared {
                mut store, binding, ..
            } = F::prepare();
            reissue_denied_after_revocation(&mut store, &binding)
        }
        "op.record-retrieve-exchange" | "replay.retrieve.exact" => {
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
        "op.acknowledge-retrieved-batch" | "replay.ack.exact" => {
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
        "op.try-rearm-join" | "snapshot.rearm-join-absent-before-handled" => {
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
    if snapshot.arms.len() == 1
        && snapshot.arms[0].arm_id == binding.arm_id
        && snapshot.arms[0].generation == binding.generation
    {
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
    let prior_verifier = replacement.grant_verifier;
    replacement.grant_verifier = [0x34; 32];
    replacement.grant_ref = VerifierRef::fixture(10);
    store.persist_helper_grant(&replacement).map_err(err)?;
    let snapshot = store.recover_authority_state().map_err(err)?;
    let retired = snapshot
        .retired_helper_grants
        .iter()
        .any(|grant| grant.grant_ref == prior_ref && grant.grant_verifier == prior_verifier);
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

fn reissue_denied_after_revocation(
    store: &mut impl Persist,
    binding: &ValidatedHelperBinding,
) -> Result<(), String> {
    let scope = HelperRevocationScope {
        grant_ref: binding.grant_ref.clone(),
        birth_id: binding.birth_id.clone(),
        attempt_id: binding.attempt_id.clone(),
    };
    store.revoke_helper_grant(scope).map_err(err)?;
    let snapshot = store.recover_authority_state().map_err(err)?;
    let mut reissue = snapshot.helper_grants[0].clone();
    reissue.revoked = false;
    reissue.grant_verifier = [0x44; 32];
    reissue.grant_ref = VerifierRef::fixture(15);
    match store.persist_helper_grant(&reissue) {
        Err(PersistError::Conflict) => Ok(()),
        other => Err(format!("expected re-issue conflict, got {other:?}")),
    }
}

fn revocation_survives_admission<F: ConformanceFixture>() -> Result<(), String> {
    let Prepared {
        mut store, binding, ..
    } = F::prepare();
    let scope = HelperRevocationScope {
        grant_ref: binding.grant_ref.clone(),
        birth_id: binding.birth_id.clone(),
        attempt_id: binding.attempt_id.clone(),
    };
    store.revoke_helper_grant(scope).map_err(err)?;
    let payloads = F::payloads(&store);
    let snapshot = store.recover_authority_state().map_err(err)?;
    let mut restored = F::admit_snapshot(snapshot, payloads).map_err(err)?;
    let recovered = restored.recover_authority_state().map_err(err)?;
    if !recovered.helper_grants.iter().any(|grant| grant.revoked) {
        return Err("revocation lost on admission".into());
    }
    let mut reissue = recovered.helper_grants[0].clone();
    reissue.revoked = false;
    reissue.grant_verifier = [0x44; 32];
    reissue.grant_ref = VerifierRef::fixture(15);
    match restored.persist_helper_grant(&reissue) {
        Err(PersistError::Conflict) => Ok(()),
        other => Err(format!(
            "expected reconstructed re-issue conflict, got {other:?}"
        )),
    }
}

fn run_snapshot<F: ConformanceFixture>(id: &str) -> Result<(), String> {
    if id == "grant.revocation-survives-admission" {
        return revocation_survives_admission::<F>();
    }
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
        CaseEvidence::ProcessCrash => Err(format!(
            "process-crash fixture is outside this process: {id}"
        )),
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
    fn matrix_crosswalk_names_real_cases() {
        let mut rows = std::collections::BTreeSet::new();
        for row in matrix() {
            assert!(rows.insert(row.id), "duplicate {}", row.id);
            assert!(!row.predicates.is_empty(), "{}", row.id);
            for predicate in row.predicates {
                assert!(
                    case(predicate.case_id).is_some(),
                    "{} -> {}",
                    predicate.label,
                    predicate.case_id
                );
            }
        }
        for id in [
            "matrix.stale-lease-controller-link",
            "matrix.claim-id-and-nonce",
            "matrix.probe-epoch-and-ownership",
            "matrix.restart-reserved-held-idle",
            "matrix.revocation-reissue",
            "matrix.verifier-fixed-time-zeroize",
            "matrix.torn-interior-migration",
        ] {
            assert!(rows.contains(id), "missing {id}");
        }
        for id in [
            "replay.retrieve.exact",
            "replay.ack.exact",
            "snapshot.helper-sections-omit-bodies",
            "snapshot.grant-rotation-retires-prior-ref",
            "snapshot.rearm-join-absent-before-handled",
        ] {
            assert!(case(id).is_some(), "missing alias {id}");
        }
        assert_eq!(
            case("grant.verifier-fixed-time")
                .expect("fixed-time")
                .required,
            RequiredOutcome::FixedTimeComparison
        );
        assert_eq!(
            case("auth.link-loss").expect("link-loss").required,
            RequiredOutcome::InvalidTransition
        );
        let body_free = matrix()
            .iter()
            .find(|row| row.id == "matrix.snapshot-body-free")
            .expect("body-free row");
        assert!(
            body_free
                .predicates
                .iter()
                .any(|predicate| { predicate.case_id == "replay.restore.unswapped-pair" })
        );
    }

    #[test]
    fn every_executable_case_passes_on_the_fake() {
        for case in catalog() {
            if matches!(
                case.evidence,
                CaseEvidence::Gap { .. } | CaseEvidence::ProcessCrash
            ) {
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
