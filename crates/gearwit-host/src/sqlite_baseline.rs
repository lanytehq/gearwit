//! Synthetic bundled-SQLite baseline.
//!
//! The accepted in-memory fake remains the semantic oracle. This store commits
//! the body-free authority snapshot and the claim-payload rows in one `SQLite`
//! transaction, then reloads that pair. It is not a production provider.
//! Conformance gaps stay inconclusive; this module does not mark them passed.

use crate::conformance::{self, ConformanceFixture, Prepared};
use crate::controller::{
    ActorName, ArmId, AttemptId, BoundedBody, BoundedToken, BoundedVec, CanonicalBodyDigest,
    ClaimDigest, ClaimPayloadRef, ClaimRequestId, ControllerBirthId, EventRef, ManagedCapability,
    NativeCoordinateScope, NativeTurnFact, NativeWriteReservation, OpenedNativeCoordinate,
    PersistedTurnCorrelation, PrivateNativeRef, ProviderName, ReconciliationDisposition,
    ReconciliationScope, RequestNonce, RetrievalId, SeatId, SecretNativeCoordinate, SignalId,
    TerminalClass, ValidatedIdlePermit, VerifierRef,
};
use crate::persist::{
    AcknowledgeRequest, AcknowledgeResult, ActiveHoldCommit, AdmissionRecord, AuthorizedRetrieve,
    BoundedClaimPayload, ClaimAdmission, ClaimCoverageEvidence, ClaimDrainWitness,
    ClaimMaterializationPermit, FakePersist, HelperExecutableIdentity, HelperOperation,
    HelperOperations, HelperRevocationScope, IdempotentResult, IdempotentWrite,
    NativeTurnFactCommit, NativeWriteEvidenceCommit, Persist, PersistError, PersistedAckReplay,
    PersistedArm, PersistedClaimRecord, PersistedControllerAttachment, PersistedControllerBirth,
    PersistedHandledCoverage, PersistedHelperBindingIdentity, PersistedHelperGrant,
    PersistedNativeTurnFacts, PersistedRearmJoin, PersistedRetiredGrant, PersistedRetrievalRecord,
    PersistedRetrieveReplay, PersistedThreadOwnership, PreWriteConclusionCommit,
    PreparedDispatchCommit, ProviderEventRecord, RearmJoinResult, RearmJoinScope,
    RecordedRetrieveResult, RecoverySnapshot, ReserveBirthOutcome, RetrieveExchange,
    ThreadCreateCommit, ThreadCreateReservation, ThreadOwnershipState, ValidatedAttachmentScope,
    ValidatedHelperBinding, sealed,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

pub(crate) struct SqliteBaseline {
    conn: Connection,
    live: FakePersist,
    path: PathBuf,
    ephemeral: bool,
    fault: BaselineFault,
    poisoned: bool,
}

struct BaselineFault {
    after_partial_write: bool,
    reload_after_commit: bool,
}

impl Drop for SqliteBaseline {
    fn drop(&mut self) {
        if self.ephemeral {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl sealed::Sealed for SqliteBaseline {}

impl SqliteBaseline {
    pub(crate) fn open() -> Self {
        let path = std::env::temp_dir().join(format!(
            "gearwit-sqlite-baseline-{}-{}.sqlite",
            std::process::id(),
            unique_suffix()
        ));
        let mut store = Self::open_path(&path);
        store.ephemeral = true;
        store
    }

    fn open_path(path: &Path) -> Self {
        let conn = Connection::open(path).expect("sqlite open");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS authority_snapshot (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                document TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS claim_payload (
                payload_ref TEXT PRIMARY KEY,
                document TEXT NOT NULL
            );",
        )
        .expect("sqlite schema");
        conn.pragma_update(None, "journal_mode", "DELETE")
            .expect("journal mode");
        conn.pragma_update(None, "synchronous", "FULL")
            .expect("synchronous");
        let mut store = Self {
            conn,
            live: FakePersist::default(),
            path: path.to_path_buf(),
            ephemeral: false,
            fault: BaselineFault {
                after_partial_write: false,
                reload_after_commit: false,
            },
            poisoned: false,
        };
        store.reload().expect("empty baseline");
        store
    }

    fn reload(&mut self) -> Result<(), PersistError> {
        if self.fault.reload_after_commit {
            self.fault.reload_after_commit = false;
            return Err(PersistError::StorageUnavailable);
        }
        let document: Option<String> = self
            .conn
            .query_row(
                "SELECT document FROM authority_snapshot WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| PersistError::StorageUnavailable)?;
        let Some(document) = document else {
            self.live = FakePersist::default();
            return Ok(());
        };
        let mut payloads = BTreeMap::new();
        let mut statement = self
            .conn
            .prepare("SELECT payload_ref, document FROM claim_payload")
            .map_err(|_| PersistError::StorageUnavailable)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| PersistError::StorageUnavailable)?;
        for row in rows {
            let (payload_ref, document) = row.map_err(|_| PersistError::StorageUnavailable)?;
            let payload_ref = ClaimPayloadRef(unhex32(&payload_ref));
            payloads.insert(payload_ref, decode_payload(&document));
        }
        let (snapshot, creates) = decode_durable(&document);
        self.live = FakePersist::restore_from_snapshot(snapshot, payloads)
            .map_err(|_| PersistError::StorageUnavailable)?;
        self.live.install_creates(creates);
        Ok(())
    }

    fn commit(&mut self) -> Result<(), PersistError> {
        let creates = self.live.export_creates();
        let ownership = self.live.export_ownership();
        let mut image = self.live.clone();
        let mut snapshot = image.recover_authority_state()?;
        snapshot.ownership = ownership;
        if unsupported_section(&snapshot) {
            return Err(PersistError::StorageUnavailable);
        }
        let payloads = self.live.claim_payloads();
        let document = encode_durable(&snapshot, &creates);
        let tx = self
            .conn
            .transaction()
            .map_err(|_| PersistError::StorageUnavailable)?;
        tx.execute("DELETE FROM claim_payload", [])
            .map_err(|_| PersistError::StorageUnavailable)?;
        tx.execute(
            "INSERT INTO authority_snapshot (id, document) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET document = excluded.document",
            params![document],
        )
        .map_err(|_| PersistError::StorageUnavailable)?;
        if self.fault.after_partial_write {
            return Err(PersistError::StorageUnavailable);
        }
        for (payload_ref, payload) in payloads {
            tx.execute(
                "INSERT INTO claim_payload (payload_ref, document) VALUES (?1, ?2)",
                params![hex(&payload_ref.0), encode_payload(&payload)],
            )
            .map_err(|_| PersistError::StorageUnavailable)?;
        }
        tx.commit().map_err(|_| PersistError::StorageUnavailable)?;
        Ok(())
    }

    fn finish<T>(
        &mut self,
        saved: FakePersist,
        result: Result<T, PersistError>,
    ) -> Result<T, PersistError> {
        if self.poisoned {
            self.live = saved;
            return Err(PersistError::StorageUnavailable);
        }
        match result {
            Ok(value) => match self.commit() {
                Ok(()) => match self.reload() {
                    Ok(()) => Ok(value),
                    Err(error) => {
                        self.poisoned = true;
                        Err(error)
                    }
                },
                Err(error) => {
                    self.live = saved;
                    Err(error)
                }
            },
            Err(error) => {
                self.live = saved;
                Err(error)
            }
        }
    }
}

impl Persist for SqliteBaseline {
    fn persist_arm(&mut self, arm: &PersistedArm) -> Result<(), PersistError> {
        let saved = self.live.clone();
        let result = self.live.persist_arm(arm);
        self.finish(saved, result)
    }

    fn admit_claim(
        &mut self,
        admission: &ClaimAdmission,
        attachment: &PersistedControllerAttachment,
    ) -> Result<AdmissionRecord, PersistError> {
        let saved = self.live.clone();
        let result = self.live.admit_claim(admission, attachment);
        self.finish(saved, result)
    }

    fn reserve_controller_birth(
        &mut self,
        birth: &PersistedControllerBirth,
        create: &ThreadCreateReservation,
    ) -> Result<ReserveBirthOutcome, PersistError> {
        let saved = self.live.clone();
        let result = self.live.reserve_controller_birth(birth, create);
        self.finish(saved, result)
    }

    fn resolve_thread_create(
        &mut self,
        _commit: ThreadCreateCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        Err(PersistError::StorageUnavailable)
    }

    fn thread_ownership_state(
        &self,
        birth_id: &ControllerBirthId,
    ) -> Result<ThreadOwnershipState, PersistError> {
        if self.poisoned {
            return Err(PersistError::StorageUnavailable);
        }
        self.live.thread_ownership_state(birth_id)
    }

    fn seal_native_coordinate(
        &mut self,
        _scope: &NativeCoordinateScope,
        _coordinate: &SecretNativeCoordinate,
    ) -> Result<PrivateNativeRef, PersistError> {
        Err(PersistError::StorageUnavailable)
    }

    fn open_native_coordinate(
        &self,
        _scope: &NativeCoordinateScope,
        _native_ref: &PrivateNativeRef,
    ) -> Result<OpenedNativeCoordinate, PersistError> {
        Err(PersistError::StorageUnavailable)
    }

    fn record_dispatch_prepared(
        &mut self,
        _commit: PreparedDispatchCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        Err(PersistError::StorageUnavailable)
    }

    fn record_prewrite_conclusion(
        &mut self,
        _commit: PreWriteConclusionCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        Err(PersistError::StorageUnavailable)
    }

    fn record_active_hold(
        &mut self,
        _commit: ActiveHoldCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        Err(PersistError::StorageUnavailable)
    }

    fn reserve_native_turn_write(
        &mut self,
        _idle: ValidatedIdlePermit,
        _correlation: &PersistedTurnCorrelation,
    ) -> Result<NativeWriteReservation, PersistError> {
        Err(PersistError::StorageUnavailable)
    }

    fn record_native_write_evidence(
        &mut self,
        _commit: NativeWriteEvidenceCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        Err(PersistError::StorageUnavailable)
    }

    fn record_native_turn_fact(
        &mut self,
        _commit: NativeTurnFactCommit,
    ) -> Result<IdempotentWrite, PersistError> {
        Err(PersistError::StorageUnavailable)
    }

    fn record_reconciliation_fact(
        &mut self,
        _scope: ReconciliationScope,
        _disposition: &ReconciliationDisposition,
    ) -> Result<IdempotentWrite, PersistError> {
        Err(PersistError::StorageUnavailable)
    }

    fn revoke_controller_attachment(
        &mut self,
        scope: ValidatedAttachmentScope,
    ) -> Result<IdempotentWrite, PersistError> {
        let saved = self.live.clone();
        let result = self.live.revoke_controller_attachment(scope);
        self.finish(saved, result)
    }

    fn persist_helper_grant(&mut self, grant: &PersistedHelperGrant) -> Result<(), PersistError> {
        let saved = self.live.clone();
        let result = self.live.persist_helper_grant(grant);
        self.finish(saved, result)
    }

    fn revoke_helper_grant(
        &mut self,
        scope: HelperRevocationScope,
    ) -> Result<IdempotentWrite, PersistError> {
        let saved = self.live.clone();
        let result = self.live.revoke_helper_grant(scope);
        self.finish(saved, result)
    }

    fn record_retrieve_exchange(
        &mut self,
        exchange: &RetrieveExchange,
    ) -> Result<IdempotentResult<AuthorizedRetrieve>, PersistError> {
        let saved = self.live.clone();
        let result = self.live.record_retrieve_exchange(exchange);
        self.finish(saved, result)
    }

    fn materialize_claimed_batch(
        &self,
        binding: &ValidatedHelperBinding,
        permit: ClaimMaterializationPermit,
    ) -> Result<BoundedClaimPayload, PersistError> {
        if self.poisoned {
            return Err(PersistError::StorageUnavailable);
        }
        self.live.materialize_claimed_batch(binding, permit)
    }

    fn acknowledge_retrieved_batch(
        &mut self,
        binding: &ValidatedHelperBinding,
        request: &AcknowledgeRequest,
    ) -> Result<IdempotentResult<AcknowledgeResult>, PersistError> {
        let saved = self.live.clone();
        let result = self.live.acknowledge_retrieved_batch(binding, request);
        self.finish(saved, result)
    }

    fn try_rearm_join(&mut self, scope: RearmJoinScope) -> Result<RearmJoinResult, PersistError> {
        let saved = self.live.clone();
        let result = self.live.try_rearm_join(scope);
        self.finish(saved, result)
    }

    fn recover_authority_state(&mut self) -> Result<RecoverySnapshot, PersistError> {
        if self.poisoned {
            return Err(PersistError::StorageUnavailable);
        }
        self.live.recover_authority_state()
    }
}

impl ConformanceFixture for SqliteBaseline {
    type Store = Self;

    fn empty() -> Self::Store {
        Self::open()
    }

    fn prepare() -> Prepared<Self::Store> {
        let mut store = Self::open();
        let (binding, admission, attachment) = conformance::install_helper(&mut store);
        Prepared {
            store,
            binding,
            admission,
            attachment,
        }
    }

    fn payloads(store: &Self::Store) -> BTreeMap<ClaimPayloadRef, BoundedClaimPayload> {
        store.live.claim_payloads()
    }

    fn admit_snapshot(
        snapshot: RecoverySnapshot,
        payloads: BTreeMap<ClaimPayloadRef, BoundedClaimPayload>,
    ) -> Result<Self::Store, PersistError> {
        if unsupported_section(&snapshot) {
            return Err(PersistError::StorageUnavailable);
        }
        let mut store = Self::open();
        store.live = FakePersist::restore_from_snapshot(snapshot, payloads)?;
        store.commit()?;
        store.reload()?;
        Ok(store)
    }
}

fn unsupported_section(snapshot: &RecoverySnapshot) -> bool {
    !snapshot.turn_correlations.is_empty()
        || !snapshot.reservations.is_empty()
        || !snapshot.native_write_evidence.is_empty()
        || !snapshot.reconciliations.is_empty()
        || !snapshot.prewrite_conclusions.is_empty()
        || !snapshot.active_observations.is_empty()
}

fn unique_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn unhex32(text: &str) -> [u8; 32] {
    let bytes = unhex(text);
    bytes.try_into().expect("32 bytes")
}

fn unhex(text: &str) -> Vec<u8> {
    let chars: Vec<u8> = text.bytes().collect();
    chars
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("hex"))
        .collect()
}

fn stamp(time: OffsetDateTime) -> Value {
    json!({
        "secs": time.unix_timestamp(),
        "nanos": time.nanosecond(),
    })
}

fn unstamp(value: &Value) -> OffsetDateTime {
    let secs = value.get("secs").and_then(Value::as_i64).expect("secs");
    let nanos =
        u32::try_from(value.get("nanos").and_then(Value::as_u64).expect("nanos")).expect("nanos");
    OffsetDateTime::from_unix_timestamp(secs).expect("secs")
        + time::Duration::nanoseconds(i64::from(nanos))
}

fn time_field(value: &Value, key: &str) -> OffsetDateTime {
    unstamp(value.get(key).expect(key))
}

fn u64_json(value: u64) -> Value {
    Value::String(value.to_string())
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).expect(key)
}

fn int(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).expect(key)
}

fn u64_field(value: &Value, key: &str) -> u64 {
    match value.get(key) {
        Some(Value::String(text)) => text.parse().expect(key),
        Some(Value::Number(number)) => number.as_u64().expect(key),
        _ => panic!("{key}"),
    }
}

fn u8_field(value: &Value, key: &str) -> u8 {
    u8::try_from(int(value, key)).expect(key)
}

fn flag(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).expect(key)
}

fn bytes32_field(value: &Value, key: &str) -> [u8; 32] {
    unhex32(text(value, key))
}

fn arm_id(value: &Value, key: &str) -> ArmId {
    ArmId::new(text(value, key)).expect("arm")
}

fn seat_id(value: &Value, key: &str) -> SeatId {
    SeatId::new(text(value, key)).expect("seat")
}

fn attempt_id(value: &Value, key: &str) -> AttemptId {
    AttemptId::new(text(value, key)).expect("attempt")
}

fn signal_id(value: &Value, key: &str) -> SignalId {
    SignalId::new(text(value, key)).expect("signal")
}

fn claim_request(value: &Value, key: &str) -> ClaimRequestId {
    ClaimRequestId::new(text(value, key)).expect("claim")
}

fn event_ref(value: &str) -> EventRef {
    EventRef::new(value).expect("event")
}

fn event_refs(value: &Value) -> BoundedVec<EventRef, 1, 64> {
    let refs = value
        .as_array()
        .expect("refs")
        .iter()
        .map(|item| event_ref(item.as_str().expect("ref")))
        .collect::<Vec<_>>();
    BoundedVec::try_from(refs).expect("refs")
}

fn ops_json(operations: HelperOperations) -> Value {
    json!({
        "retrieve": operations.allows(HelperOperation::Retrieve),
        "acknowledge": operations.allows(HelperOperation::Acknowledge),
    })
}

fn ops_from(value: &Value) -> HelperOperations {
    match (flag(value, "retrieve"), flag(value, "acknowledge")) {
        (true, true) => HelperOperations::all(),
        (true, false) => HelperOperations::retrieve_only(),
        (false, true) => HelperOperations::acknowledge_only(),
        (false, false) => panic!("empty helper operations"),
    }
}

fn token<const MAX: usize>(value: &BoundedToken<MAX>) -> String {
    value.as_str().to_owned()
}

fn encode_durable(snapshot: &RecoverySnapshot, creates: &[ThreadCreateReservation]) -> String {
    json!({
        "attempt_seq": u64_json(snapshot.attempt_seq),
        "creates": creates.iter().map(encode_create).collect::<Vec<_>>(),
        "arms": snapshot.arms.iter().map(encode_arm).collect::<Vec<_>>(),
        "claims": snapshot.claims.iter().map(encode_claim).collect::<Vec<_>>(),
        "attachments": snapshot.attachments.iter().map(encode_attachment).collect::<Vec<_>>(),
        "births": snapshot.controller_births.iter().map(encode_birth).collect::<Vec<_>>(),
        "ownership": snapshot.ownership.iter().map(encode_ownership).collect::<Vec<_>>(),
        "grants": snapshot.helper_grants.iter().map(encode_grant).collect::<Vec<_>>(),
        "retired": snapshot.retired_helper_grants.iter().map(encode_retired).collect::<Vec<_>>(),
        "retrieves": snapshot.retrieve_replays.iter().map(encode_retrieve).collect::<Vec<_>>(),
        "retrievals": snapshot.retrieval_bindings.iter().map(encode_retrieval).collect::<Vec<_>>(),
        "acks": snapshot.ack_replays.iter().map(encode_ack).collect::<Vec<_>>(),
        "handled": snapshot.handled_coverage.iter().map(encode_handled).collect::<Vec<_>>(),
        "joins": snapshot.rearmed_joins.iter().map(encode_join).collect::<Vec<_>>(),
        "turn_facts": snapshot.native_turn_facts.iter().map(encode_turn_facts).collect::<Vec<_>>(),
    })
    .to_string()
}

fn encode_create(create: &ThreadCreateReservation) -> Value {
    json!({
        "birth_id": hex(&create.birth_id.0),
        "attempt": hex(&create.create_attempt_id.0),
        "reserved_at": stamp(create.reserved_at),
    })
}

fn encode_arm(arm: &PersistedArm) -> Value {
    json!({
        "arm_id": arm.arm_id.as_str(),
        "generation": u64_json(arm.generation),
        "seat_id": arm.seat_id.as_str(),
        "coverage_until": stamp(arm.coverage_until),
    })
}

fn encode_claim(claim: &PersistedClaimRecord) -> Value {
    json!({
        "attempt_id": claim.attempt_id.as_str(),
        "request_id": claim.request_id.as_str(),
        "arm_id": claim.arm_id.as_str(),
        "generation": u64_json(claim.generation),
        "signal_id": claim.signal_id.as_str(),
        "event_refs": claim.event_refs.as_slice().iter().map(super::controller::EventRef::as_str).collect::<Vec<_>>(),
        "claim_digest": hex(&claim.claim_digest.0),
        "payload_ref": hex(&claim.payload_ref.0),
        "claimed_at": stamp(claim.claimed_at),
        "coverage": claim.coverage.as_ref().map(encode_coverage),
        "drain": claim.drain_witness.as_ref().map(encode_drain),
    })
}

fn encode_coverage(coverage: &ClaimCoverageEvidence) -> Value {
    json!({
        "request_id": coverage.request_id.as_str(),
        "arm_id": coverage.arm_id.as_str(),
        "generation": u64_json(coverage.generation),
        "signal_id": coverage.signal_id.as_str(),
        "provider": coverage.provider.as_str(),
        "scope": token(&coverage.drain_filter_scope),
        "baseline": coverage.drain_baseline.as_str(),
        "batch": hex(&coverage.event_batch_digest),
        "covered_through": coverage.covered_through.as_str(),
        "source": hex(&coverage.source_evidence_id),
    })
}

fn encode_drain(drain: &ClaimDrainWitness) -> Value {
    json!({
        "provider": drain.provider.as_str(),
        "scope": token(&drain.drain_filter_scope),
        "event_refs": drain.event_refs.as_slice().iter().map(super::controller::EventRef::as_str).collect::<Vec<_>>(),
        "source": hex(&drain.source_evidence_id),
    })
}

fn encode_attachment(attachment: &PersistedControllerAttachment) -> Value {
    json!({
        "attempt_id": attachment.attempt_id.as_str(),
        "birth_id": hex(&attachment.birth_id.0),
        "seat_id": attachment.seat_id.as_str(),
        "arm_id": attachment.arm_id.as_str(),
        "generation": u64_json(attachment.generation),
        "lease_until": stamp(attachment.lease_until),
        "verifier_ref": hex(attachment.verifier_ref.bytes()),
        "revoked": attachment.revoked,
    })
}

fn encode_birth(birth: &PersistedControllerBirth) -> Value {
    json!({
        "birth_id": hex(&birth.birth_id.0),
        "seat_id": birth.seat_id.as_str(),
        "arm_id": birth.arm_id.as_str(),
        "generation": u64_json(birth.generation),
        "lease_until": stamp(birth.lease_until),
        "verifier_ref": hex(birth.verifier_ref.bytes()),
        "created_at": stamp(birth.created_at),
        "revoked": birth.revoked,
    })
}

fn encode_ownership(row: &PersistedThreadOwnership) -> Value {
    let (tag, attempt, thread) = match &row.state {
        ThreadOwnershipState::Absent => ("absent", None, None),
        ThreadOwnershipState::Reserved { create_attempt_id } => {
            ("reserved", Some(create_attempt_id), None)
        }
        ThreadOwnershipState::Unknown { create_attempt_id } => {
            ("unknown", Some(create_attempt_id), None)
        }
        ThreadOwnershipState::ProvenNotAccepted { create_attempt_id } => {
            ("not-accepted", Some(create_attempt_id), None)
        }
        ThreadOwnershipState::Owned {
            create_attempt_id,
            thread_ref,
        } => ("owned", Some(create_attempt_id), Some(thread_ref)),
    };
    json!({
        "birth_id": hex(&row.birth_id.0),
        "tag": tag,
        "attempt": attempt.map(|attempt| hex(&attempt.0)),
        "thread": thread.map(|thread| hex(&thread.0)),
    })
}

fn encode_grant(grant: &PersistedHelperGrant) -> Value {
    json!({
        "grant_verifier": hex(&grant.grant_verifier),
        "grant_ref": hex(grant.grant_ref.bytes()),
        "seat_id": grant.seat_id.as_str(),
        "arm_id": grant.arm_id.as_str(),
        "generation": u64_json(grant.generation),
        "birth_id": hex(&grant.birth_id.0),
        "attempt_id": grant.attempt_id.as_str(),
        "signal_id": grant.signal_id.as_str(),
        "claim_digest": hex(&grant.claim_digest.0),
        "operations": ops_json(grant.operations),
        "lease_until": stamp(grant.lease_until),
        "image_digest": hex(&grant.executable_identity.image_digest),
        "file_identity": token(&grant.executable_identity.file_identity),
        "build_identity": token(&grant.executable_identity.build_identity),
        "revoked": grant.revoked,
    })
}

fn encode_retired(grant: &PersistedRetiredGrant) -> Value {
    json!({
        "grant_ref": hex(grant.grant_ref.bytes()),
        "grant_verifier": hex(&grant.grant_verifier),
    })
}

fn encode_origin(origin: &PersistedHelperBindingIdentity) -> Value {
    json!({
        "grant_ref": hex(origin.grant_ref.bytes()),
        "seat_id": origin.seat_id.as_str(),
        "arm_id": origin.arm_id.as_str(),
        "generation": u64_json(origin.generation),
        "birth_id": hex(&origin.birth_id.0),
        "attempt_id": origin.attempt_id.as_str(),
        "signal_id": origin.signal_id.as_str(),
        "claim_digest": hex(&origin.claim_digest.0),
        "operations": ops_json(origin.operations),
        "lease_until": stamp(origin.lease_until),
    })
}

fn encode_recorded(result: &RecordedRetrieveResult) -> Value {
    json!({
        "retrieval_id": hex(&result.retrieval_id.0),
        "payload_ref": hex(&result.claim_payload_ref.0),
        "newest": result.newest_event_ref.as_str(),
        "event_count": result.event_count,
        "retrieved_at": stamp(result.retrieved_at),
    })
}

fn encode_retrieve(replay: &PersistedRetrieveReplay) -> Value {
    json!({
        "request_id": hex(&replay.request_id.0),
        "binding_digest": hex(&replay.binding_digest),
        "origin": encode_origin(&replay.origin),
        "body_digest": hex(&replay.canonical_body_digest.0),
        "result": encode_recorded(&replay.result),
    })
}

fn encode_retrieval(row: &PersistedRetrievalRecord) -> Value {
    json!({
        "retrieval_id": hex(&row.retrieval_id.0),
        "binding_digest": hex(&row.binding_digest),
        "origin": encode_origin(&row.origin),
        "result": encode_recorded(&row.result),
    })
}

fn encode_ack(replay: &PersistedAckReplay) -> Value {
    json!({
        "request_id": hex(&replay.request_id.0),
        "binding_digest": hex(&replay.binding_digest),
        "body_digest": hex(&replay.canonical_body_digest.0),
        "retrieval_id": hex(&replay.retrieval_id.0),
        "cursor": replay.cursor.as_str(),
        "attempt_id": replay.result.attempt_id.as_str(),
        "signal_id": replay.result.signal_id.as_str(),
        "result_cursor": replay.result.cursor.as_str(),
        "accepted_at": stamp(replay.result.accepted_at),
    })
}

fn encode_handled(row: &PersistedHandledCoverage) -> Value {
    json!({
        "attempt_id": row.attempt_id.as_str(),
        "signal_id": row.signal_id.as_str(),
        "cursor": row.cursor.as_str(),
        "newest": row.covered_through_newest,
    })
}

fn encode_join(row: &PersistedRearmJoin) -> Value {
    json!({
        "arm_id": row.arm_id.as_str(),
        "generation": u64_json(row.generation),
        "attempt_id": row.attempt_id.as_str(),
        "signal_id": row.signal_id.as_str(),
    })
}

fn encode_turn_facts(row: &PersistedNativeTurnFacts) -> Value {
    json!({
        "attempt_id": row.attempt_id.as_str(),
        "facts": row.facts.iter().map(encode_fact).collect::<Vec<_>>(),
    })
}

fn encode_fact(fact: &NativeTurnFact) -> Value {
    match fact {
        NativeTurnFact::Terminal { turn_ref, class } => json!({
            "tag": "terminal",
            "turn_ref": hex(&turn_ref.0),
            "class": match class {
                TerminalClass::Succeeded => "succeeded",
                TerminalClass::Failed => "failed",
                TerminalClass::NativeInterrupted => "interrupted",
            },
        }),
        NativeTurnFact::Accepted { turn_ref } => {
            json!({"tag": "accepted", "turn_ref": hex(&turn_ref.0)})
        }
        NativeTurnFact::Started { turn_ref } => {
            json!({"tag": "started", "turn_ref": hex(&turn_ref.0)})
        }
        NativeTurnFact::DegradedTerminalObservation => json!({"tag": "degraded"}),
        NativeTurnFact::ControllerLost => json!({"tag": "lost"}),
        NativeTurnFact::Unknown => json!({"tag": "unknown"}),
    }
}

fn encode_payload(payload: &BoundedClaimPayload) -> String {
    json!(
        payload
            .events
            .as_slice()
            .iter()
            .map(|event| json!({
                "event_ref": event.event_ref.as_str(),
                "provider": event.provider.as_str(),
                "actor": event.actor.as_ref().map(super::controller::ActorName::as_str),
                "observed_at": stamp(event.observed_at),
                "body": event.body.as_str(),
            }))
            .collect::<Vec<_>>()
    )
    .to_string()
}

fn decode_durable(document: &str) -> (RecoverySnapshot, Vec<ThreadCreateReservation>) {
    let value: Value = serde_json::from_str(document).expect("snapshot json");
    let creates = value
        .get("creates")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().map(decode_create).collect())
        .unwrap_or_default();
    let snapshot = RecoverySnapshot {
        arms: array(&value, "arms").iter().map(decode_arm).collect(),
        claims: array(&value, "claims").iter().map(decode_claim).collect(),
        attachments: array(&value, "attachments")
            .iter()
            .map(decode_attachment)
            .collect(),
        controller_births: array(&value, "births").iter().map(decode_birth).collect(),
        ownership: array(&value, "ownership")
            .iter()
            .map(decode_ownership)
            .collect(),
        turn_correlations: Vec::new(),
        reservations: Vec::new(),
        native_write_evidence: Vec::new(),
        native_turn_facts: array(&value, "turn_facts")
            .iter()
            .map(decode_turn_facts)
            .collect(),
        reconciliations: Vec::new(),
        prewrite_conclusions: Vec::new(),
        active_observations: Vec::new(),
        helper_grants: array(&value, "grants").iter().map(decode_grant).collect(),
        retired_helper_grants: array(&value, "retired")
            .iter()
            .map(decode_retired)
            .collect(),
        retrieve_replays: array(&value, "retrieves")
            .iter()
            .map(decode_retrieve)
            .collect(),
        retrieval_bindings: array(&value, "retrievals")
            .iter()
            .map(decode_retrieval)
            .collect(),
        ack_replays: array(&value, "acks").iter().map(decode_ack).collect(),
        handled_coverage: array(&value, "handled")
            .iter()
            .map(decode_handled)
            .collect(),
        rearmed_joins: array(&value, "joins").iter().map(decode_join).collect(),
        attempt_seq: u64_field(&value, "attempt_seq"),
    };
    (snapshot, creates)
}

fn decode_create(value: &Value) -> ThreadCreateReservation {
    ThreadCreateReservation {
        birth_id: ControllerBirthId(bytes32_field(value, "birth_id")),
        create_attempt_id: RequestNonce(bytes32_field(value, "attempt")),
        reserved_at: time_field(value, "reserved_at"),
    }
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value.get(key).and_then(Value::as_array).expect(key)
}

fn decode_arm(value: &Value) -> PersistedArm {
    PersistedArm {
        arm_id: arm_id(value, "arm_id"),
        generation: u64_field(value, "generation"),
        seat_id: seat_id(value, "seat_id"),
        capability: ManagedCapability::HandleClaimedSignal,
        coverage_until: time_field(value, "coverage_until"),
    }
}

fn decode_claim(value: &Value) -> PersistedClaimRecord {
    PersistedClaimRecord {
        attempt_id: attempt_id(value, "attempt_id"),
        request_id: claim_request(value, "request_id"),
        arm_id: arm_id(value, "arm_id"),
        generation: u64_field(value, "generation"),
        signal_id: signal_id(value, "signal_id"),
        event_refs: event_refs(value.get("event_refs").expect("event refs")),
        claim_digest: ClaimDigest(bytes32_field(value, "claim_digest")),
        payload_ref: ClaimPayloadRef(bytes32_field(value, "payload_ref")),
        claimed_at: time_field(value, "claimed_at"),
        coverage: value.get("coverage").and_then(|item| {
            if item.is_null() {
                None
            } else {
                Some(decode_coverage(item))
            }
        }),
        drain_witness: value.get("drain").and_then(|item| {
            if item.is_null() {
                None
            } else {
                Some(decode_drain(item))
            }
        }),
    }
}

fn decode_coverage(value: &Value) -> ClaimCoverageEvidence {
    ClaimCoverageEvidence {
        request_id: claim_request(value, "request_id"),
        arm_id: arm_id(value, "arm_id"),
        generation: u64_field(value, "generation"),
        signal_id: signal_id(value, "signal_id"),
        provider: ProviderName::new(text(value, "provider")).expect("provider"),
        drain_filter_scope: BoundedToken::new(text(value, "scope")).expect("scope"),
        drain_baseline: event_ref(text(value, "baseline")),
        event_batch_digest: bytes32_field(value, "batch"),
        covered_through: event_ref(text(value, "covered_through")),
        source_evidence_id: bytes32_field(value, "source"),
    }
}

fn decode_drain(value: &Value) -> ClaimDrainWitness {
    ClaimDrainWitness {
        provider: ProviderName::new(text(value, "provider")).expect("provider"),
        drain_filter_scope: BoundedToken::new(text(value, "scope")).expect("scope"),
        event_refs: event_refs(value.get("event_refs").expect("refs")),
        source_evidence_id: bytes32_field(value, "source"),
    }
}

fn decode_attachment(value: &Value) -> PersistedControllerAttachment {
    PersistedControllerAttachment {
        attempt_id: attempt_id(value, "attempt_id"),
        birth_id: ControllerBirthId(bytes32_field(value, "birth_id")),
        seat_id: seat_id(value, "seat_id"),
        arm_id: arm_id(value, "arm_id"),
        generation: u64_field(value, "generation"),
        capability: ManagedCapability::HandleClaimedSignal,
        lease_until: time_field(value, "lease_until"),
        verifier_ref: VerifierRef::from_bytes(bytes32_field(value, "verifier_ref")),
        revoked: flag(value, "revoked"),
    }
}

fn decode_birth(value: &Value) -> PersistedControllerBirth {
    PersistedControllerBirth {
        birth_id: ControllerBirthId(bytes32_field(value, "birth_id")),
        seat_id: seat_id(value, "seat_id"),
        arm_id: arm_id(value, "arm_id"),
        generation: u64_field(value, "generation"),
        capability: ManagedCapability::HandleClaimedSignal,
        lease_until: time_field(value, "lease_until"),
        verifier_ref: VerifierRef::from_bytes(bytes32_field(value, "verifier_ref")),
        created_at: time_field(value, "created_at"),
        revoked: flag(value, "revoked"),
    }
}

fn decode_ownership(value: &Value) -> PersistedThreadOwnership {
    let attempt = value
        .get("attempt")
        .and_then(Value::as_str)
        .map(|text| RequestNonce(unhex32(text)));
    let thread = value
        .get("thread")
        .and_then(Value::as_str)
        .map(|text| PrivateNativeRef(unhex32(text)));
    let state = match text(value, "tag") {
        "absent" => ThreadOwnershipState::Absent,
        "reserved" => ThreadOwnershipState::Reserved {
            create_attempt_id: attempt.expect("attempt"),
        },
        "unknown" => ThreadOwnershipState::Unknown {
            create_attempt_id: attempt.expect("attempt"),
        },
        "not-accepted" => ThreadOwnershipState::ProvenNotAccepted {
            create_attempt_id: attempt.expect("attempt"),
        },
        "owned" => ThreadOwnershipState::Owned {
            create_attempt_id: attempt.expect("attempt"),
            thread_ref: thread.expect("thread"),
        },
        other => panic!("ownership {other}"),
    };
    PersistedThreadOwnership {
        birth_id: ControllerBirthId(bytes32_field(value, "birth_id")),
        state,
    }
}

fn decode_origin(value: &Value) -> PersistedHelperBindingIdentity {
    PersistedHelperBindingIdentity {
        grant_ref: VerifierRef::from_bytes(bytes32_field(value, "grant_ref")),
        seat_id: seat_id(value, "seat_id"),
        arm_id: arm_id(value, "arm_id"),
        generation: u64_field(value, "generation"),
        birth_id: ControllerBirthId(bytes32_field(value, "birth_id")),
        attempt_id: attempt_id(value, "attempt_id"),
        signal_id: signal_id(value, "signal_id"),
        claim_digest: ClaimDigest(bytes32_field(value, "claim_digest")),
        operations: ops_from(value.get("operations").expect("ops")),
        lease_until: time_field(value, "lease_until"),
    }
}

fn decode_recorded(value: &Value) -> RecordedRetrieveResult {
    RecordedRetrieveResult {
        retrieval_id: RetrievalId(bytes32_field(value, "retrieval_id")),
        claim_payload_ref: ClaimPayloadRef(bytes32_field(value, "payload_ref")),
        newest_event_ref: event_ref(text(value, "newest")),
        event_count: u8_field(value, "event_count"),
        retrieved_at: time_field(value, "retrieved_at"),
    }
}

fn decode_retrieve(value: &Value) -> PersistedRetrieveReplay {
    PersistedRetrieveReplay {
        request_id: RequestNonce(bytes32_field(value, "request_id")),
        binding_digest: bytes32_field(value, "binding_digest"),
        origin: decode_origin(value.get("origin").expect("origin")),
        canonical_body_digest: CanonicalBodyDigest(bytes32_field(value, "body_digest")),
        result: decode_recorded(value.get("result").expect("result")),
    }
}

fn decode_retrieval(value: &Value) -> PersistedRetrievalRecord {
    PersistedRetrievalRecord {
        retrieval_id: RetrievalId(bytes32_field(value, "retrieval_id")),
        binding_digest: bytes32_field(value, "binding_digest"),
        origin: decode_origin(value.get("origin").expect("origin")),
        result: decode_recorded(value.get("result").expect("result")),
    }
}

fn decode_ack(value: &Value) -> PersistedAckReplay {
    PersistedAckReplay {
        request_id: RequestNonce(bytes32_field(value, "request_id")),
        binding_digest: bytes32_field(value, "binding_digest"),
        canonical_body_digest: CanonicalBodyDigest(bytes32_field(value, "body_digest")),
        retrieval_id: RetrievalId(bytes32_field(value, "retrieval_id")),
        cursor: event_ref(text(value, "cursor")),
        result: AcknowledgeResult {
            attempt_id: attempt_id(value, "attempt_id"),
            signal_id: signal_id(value, "signal_id"),
            cursor: event_ref(text(value, "result_cursor")),
            accepted_at: time_field(value, "accepted_at"),
        },
    }
}

fn decode_handled(value: &Value) -> PersistedHandledCoverage {
    PersistedHandledCoverage {
        attempt_id: attempt_id(value, "attempt_id"),
        signal_id: signal_id(value, "signal_id"),
        cursor: event_ref(text(value, "cursor")),
        covered_through_newest: flag(value, "newest"),
    }
}

fn decode_join(value: &Value) -> PersistedRearmJoin {
    PersistedRearmJoin {
        arm_id: arm_id(value, "arm_id"),
        generation: u64_field(value, "generation"),
        attempt_id: attempt_id(value, "attempt_id"),
        signal_id: signal_id(value, "signal_id"),
    }
}

fn decode_grant(value: &Value) -> PersistedHelperGrant {
    PersistedHelperGrant {
        grant_verifier: bytes32_field(value, "grant_verifier"),
        grant_ref: VerifierRef::from_bytes(bytes32_field(value, "grant_ref")),
        seat_id: seat_id(value, "seat_id"),
        arm_id: arm_id(value, "arm_id"),
        generation: u64_field(value, "generation"),
        birth_id: ControllerBirthId(bytes32_field(value, "birth_id")),
        attempt_id: attempt_id(value, "attempt_id"),
        signal_id: signal_id(value, "signal_id"),
        claim_digest: ClaimDigest(bytes32_field(value, "claim_digest")),
        operations: ops_from(value.get("operations").expect("ops")),
        lease_until: time_field(value, "lease_until"),
        executable_identity: HelperExecutableIdentity {
            image_digest: bytes32_field(value, "image_digest"),
            file_identity: BoundedToken::new(text(value, "file_identity")).expect("file"),
            build_identity: BoundedToken::new(text(value, "build_identity")).expect("build"),
        },
        revoked: flag(value, "revoked"),
    }
}

fn decode_retired(value: &Value) -> PersistedRetiredGrant {
    PersistedRetiredGrant {
        grant_ref: VerifierRef::from_bytes(bytes32_field(value, "grant_ref")),
        grant_verifier: bytes32_field(value, "grant_verifier"),
    }
}

fn decode_turn_facts(value: &Value) -> PersistedNativeTurnFacts {
    PersistedNativeTurnFacts {
        attempt_id: attempt_id(value, "attempt_id"),
        facts: array(value, "facts").iter().map(decode_fact).collect(),
    }
}

fn decode_fact(value: &Value) -> NativeTurnFact {
    let turn = || PrivateNativeRef(bytes32_field(value, "turn_ref"));
    match text(value, "tag") {
        "terminal" => NativeTurnFact::Terminal {
            turn_ref: turn(),
            class: match text(value, "class") {
                "succeeded" => TerminalClass::Succeeded,
                "failed" => TerminalClass::Failed,
                "interrupted" => TerminalClass::NativeInterrupted,
                other => panic!("class {other}"),
            },
        },
        "accepted" => NativeTurnFact::Accepted { turn_ref: turn() },
        "started" => NativeTurnFact::Started { turn_ref: turn() },
        "degraded" => NativeTurnFact::DegradedTerminalObservation,
        "lost" => NativeTurnFact::ControllerLost,
        "unknown" => NativeTurnFact::Unknown,
        other => panic!("fact {other}"),
    }
}

fn decode_payload(document: &str) -> BoundedClaimPayload {
    let events: Vec<Value> = serde_json::from_str(document).expect("payload json");
    let records = events
        .iter()
        .map(|event| ProviderEventRecord {
            event_ref: event_ref(text(event, "event_ref")),
            provider: ProviderName::new(text(event, "provider")).expect("provider"),
            actor: event
                .get("actor")
                .and_then(Value::as_str)
                .map(|actor| ActorName::new(actor).expect("actor")),
            observed_at: time_field(event, "observed_at"),
            body: BoundedBody::new(text(event, "body")).expect("body"),
        })
        .collect::<Vec<_>>();
    BoundedClaimPayload::try_from(records).expect("payload")
}

fn admit_fractional(
    store: &mut SqliteBaseline,
    observed: OffsetDateTime,
    lease: OffsetDateTime,
) -> (ValidatedHelperBinding, ClaimAdmission) {
    let mut parts = conformance::birth_parts();
    parts.birth.lease_until = lease;
    store
        .reserve_controller_birth(&parts.birth, &parts.reservation)
        .expect("reserve");
    store
        .persist_arm(&PersistedArm {
            arm_id: parts.birth.arm_id.clone(),
            generation: parts.birth.generation,
            seat_id: parts.birth.seat_id.clone(),
            capability: parts.birth.capability,
            coverage_until: lease + time::Duration::seconds(600),
        })
        .expect("arm");
    let signal_id = SignalId::new("signal-a").expect("signal");
    let events = [gearwit_protocol::ProviderEvent {
        provider: "test".to_owned(),
        event_ref: "event-a".to_owned(),
        actor: None,
        observed_at: observed
            .format(&time::format_description::well_known::Rfc3339)
            .expect("rfc3339"),
        body: "fractional-body".to_owned(),
    }];
    let admission = crate::persist::claim_admission_fixture(
        "claim-a",
        parts.birth.arm_id.clone(),
        parts.birth.generation,
        signal_id.clone(),
        &events,
        observed,
    );
    let attempt_id = AttemptId::new("attempt-a").expect("attempt");
    store
        .admit_claim(
            &admission,
            &PersistedControllerAttachment {
                attempt_id: attempt_id.clone(),
                birth_id: parts.birth.birth_id.clone(),
                seat_id: parts.birth.seat_id.clone(),
                arm_id: parts.birth.arm_id.clone(),
                generation: parts.birth.generation,
                capability: parts.birth.capability,
                lease_until: lease,
                verifier_ref: VerifierRef::fixture(8),
                revoked: false,
            },
        )
        .expect("admit");
    store
        .persist_helper_grant(&PersistedHelperGrant {
            grant_verifier: [0x33; 32],
            grant_ref: VerifierRef::fixture(9),
            seat_id: parts.birth.seat_id.clone(),
            arm_id: parts.birth.arm_id.clone(),
            generation: parts.birth.generation,
            birth_id: parts.birth.birth_id.clone(),
            attempt_id: attempt_id.clone(),
            signal_id: signal_id.clone(),
            claim_digest: admission.claim_digest.clone(),
            operations: HelperOperations::all(),
            lease_until: lease,
            executable_identity: HelperExecutableIdentity {
                image_digest: [0x11; 32],
                file_identity: BoundedToken::new("gearwit-helper").expect("file"),
                build_identity: BoundedToken::new("build-1").expect("build"),
            },
            revoked: false,
        })
        .expect("grant");
    let binding = ValidatedHelperBinding {
        grant_ref: VerifierRef::fixture(9),
        seat_id: parts.birth.seat_id,
        arm_id: parts.birth.arm_id,
        generation: parts.birth.generation,
        birth_id: parts.birth.birth_id,
        attempt_id,
        signal_id,
        claim_digest: admission.claim_digest.clone(),
        operations: HelperOperations::all(),
        lease_until: lease,
    };
    (binding, admission)
}

fn binding_from_grant(grant: &PersistedHelperGrant) -> ValidatedHelperBinding {
    ValidatedHelperBinding {
        grant_ref: grant.grant_ref.clone(),
        seat_id: grant.seat_id.clone(),
        arm_id: grant.arm_id.clone(),
        generation: grant.generation,
        birth_id: grant.birth_id.clone(),
        attempt_id: grant.attempt_id.clone(),
        signal_id: grant.signal_id.clone(),
        claim_digest: grant.claim_digest.clone(),
        operations: grant.operations,
        lease_until: grant.lease_until,
    }
}

fn filesystem_type(path: &Path) -> String {
    let listed = std::process::Command::new("df")
        .arg(path)
        .output()
        .expect("df");
    let listed = String::from_utf8_lossy(&listed.stdout);
    let device = listed
        .lines()
        .nth(1)
        .and_then(|line| line.split_whitespace().next())
        .expect("device");
    let mounted = std::process::Command::new("mount").output().expect("mount");
    let mounted = String::from_utf8_lossy(&mounted.stdout);
    mounted
        .lines()
        .find(|line| line.starts_with(device))
        .and_then(|line| line.split(['(', ',']).nth(1))
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

fn sqlite_durability(path: &Path) -> (String, i64) {
    let conn = Connection::open(path).expect("durability open");
    let journal: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal");
    let synchronous: i64 = conn
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .expect("synchronous");
    (journal, synchronous)
}

fn crash_writer(role: &str) {
    let path = std::env::var("GEARWIT_CRASH_PATH").expect("path");
    let path = PathBuf::from(path);
    let mut store = SqliteBaseline::open_path(&path);
    let (binding, _, _) = conformance::install_helper(&mut store);
    let exchange = conformance::retrieve_for(&binding, 41);
    let authorized = match store.record_retrieve_exchange(&exchange).expect("retrieve") {
        IdempotentResult::Recorded(authorized) => authorized,
        IdempotentResult::ExactReplay(_) => panic!("first retrieve must record"),
    };
    let request = conformance::ack_for(&binding, &authorized.recorded.retrieval_id, "event-a", 42);
    store
        .acknowledge_retrieved_batch(&binding, &request)
        .expect("ack");
    if role == "pre" {
        drop(store);
        let conn = Connection::open(&path).expect("dirty open");
        conn.execute_batch(
            "BEGIN IMMEDIATE;
             UPDATE authority_snapshot SET document = 'DIRTY' WHERE id = 1;",
        )
        .expect("dirty begin");
        write_marker(&path, "PRE_COMMIT");
        println!("PRE_COMMIT");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        std::thread::sleep(std::time::Duration::from_secs(60));
        let _ = conn;
        return;
    }
    write_marker(&path, "POST_COMMIT");
    println!("POST_COMMIT");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    std::thread::sleep(std::time::Duration::from_secs(60));
    let _ = store;
}

fn write_marker(path: &Path, marker: &str) {
    let marker_path = path.with_extension("marker");
    let mut file = std::fs::File::create(&marker_path).expect("marker");
    std::io::Write::write_all(&mut file, marker.as_bytes()).expect("marker write");
    std::io::Write::write_all(&mut file, b"\n").expect("marker newline");
    file.sync_all().expect("marker sync");
}

fn kill_writer_at(path: &Path, role: &str, marker: &str) {
    let stderr_path = path.with_extension("stderr");
    let stderr = std::fs::File::create(&stderr_path).expect("stderr");
    let mut child = std::process::Command::new(std::env::current_exe().expect("exe"))
        .arg("--exact")
        .arg("sqlite_baseline::tests::reopened_media_process_crash")
        .arg("--nocapture")
        .env("GEARWIT_CRASH_ROLE", role)
        .env("GEARWIT_CRASH_PATH", path)
        .stdout(std::process::Stdio::null())
        .stderr(stderr)
        .spawn()
        .expect("spawn writer");
    let marker_path = path.with_extension("marker");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut reached = false;
    while std::time::Instant::now() < deadline {
        if child.try_wait().expect("try wait").is_some() {
            break;
        }
        if let Ok(text) = std::fs::read_to_string(&marker_path)
            && text.contains(marker)
        {
            reached = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        reached,
        "writer exited before {marker}: {}",
        std::fs::read_to_string(&stderr_path).unwrap_or_default()
    );
    child.kill().expect("sigkill");
    let status = child.wait().expect("wait");
    let signal = std::os::unix::process::ExitStatusExt::signal(&status);
    assert_eq!(signal, Some(9), "writer status {status:?}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::{CaseEvidence, catalog, execute};

    #[test]
    fn sqlite_matches_every_executable_conformance_case() {
        for case in catalog() {
            if matches!(case.evidence, CaseEvidence::ProcessCrash) {
                continue;
            }
            if matches!(case.evidence, CaseEvidence::Gap { .. }) {
                let error = execute::<SqliteBaseline>(case.id).expect_err(case.id);
                assert!(error.contains("inconclusive"), "{error}");
                continue;
            }
            execute::<SqliteBaseline>(case.id)
                .unwrap_or_else(|error| panic!("{}: {error}", case.id));
        }
    }

    #[test]
    fn committed_birth_survives_reopen_and_a_torn_transaction_does_not() {
        let path = std::env::temp_dir().join(format!(
            "gearwit-sqlite-reopen-{}-{}.sqlite",
            std::process::id(),
            unique_suffix()
        ));
        let mut store = SqliteBaseline::open_path(&path);
        let parts = crate::conformance::birth_parts();
        store
            .reserve_controller_birth(&parts.birth, &parts.reservation)
            .expect("reserve");
        drop(store);
        let mut reopened = SqliteBaseline::open_path(&path);
        let snapshot = reopened.recover_authority_state().expect("recover");
        match snapshot.ownership.as_slice() {
            [row] => match &row.state {
                ThreadOwnershipState::Unknown { create_attempt_id } => {
                    assert_eq!(*create_attempt_id, parts.reservation.create_attempt_id);
                }
                other => panic!("ownership {other:?}"),
            },
            other => panic!("ownership rows {}", other.len()),
        }
        drop(reopened);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn connection_close_rolls_back_an_uncommitted_transaction() {
        let torn = std::env::temp_dir().join(format!(
            "gearwit-sqlite-close-{}-{}.sqlite",
            std::process::id(),
            unique_suffix()
        ));
        let conn = Connection::open(&torn).expect("torn open");
        conn.execute_batch("BEGIN IMMEDIATE; CREATE TABLE authority_snapshot (id INTEGER PRIMARY KEY, document TEXT NOT NULL); INSERT INTO authority_snapshot (id, document) VALUES (1, '{}');")
            .expect("begin");
        drop(conn);
        let reopened = Connection::open(&torn).expect("reopen torn");
        let present: i64 = reopened
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'authority_snapshot'",
                [],
                |row| row.get(0),
            )
            .expect("master");
        assert_eq!(present, 0);
        drop(reopened);
        let _ = std::fs::remove_file(&torn);
    }

    #[test]
    fn reopened_sql_preserves_payload_replay_ack_and_grant_rotation() {
        let path = std::env::temp_dir().join(format!(
            "gearwit-sqlite-helper-{}-{}.sqlite",
            std::process::id(),
            unique_suffix()
        ));
        let mut store = SqliteBaseline::open_path(&path);
        let (binding, _, _) = conformance::install_helper(&mut store);
        let exchange = conformance::retrieve_for(&binding, 21);
        let authorized = match store.record_retrieve_exchange(&exchange).expect("retrieve") {
            IdempotentResult::Recorded(authorized) => authorized,
            IdempotentResult::ExactReplay(_) => panic!("first retrieve must record"),
        };
        let payload = store
            .materialize_claimed_batch(&binding, authorized.permit)
            .expect("materialize");
        assert_eq!(payload.events.as_slice().len(), 2);
        let request =
            conformance::ack_for(&binding, &authorized.recorded.retrieval_id, "event-a", 22);
        store
            .acknowledge_retrieved_batch(&binding, &request)
            .expect("ack");
        drop(store);
        let mut reopened = SqliteBaseline::open_path(&path);
        let replay = match reopened
            .record_retrieve_exchange(&exchange)
            .expect("replay")
        {
            IdempotentResult::ExactReplay(authorized) => authorized,
            IdempotentResult::Recorded(_) => panic!("reopen must replay"),
        };
        let replayed = reopened
            .materialize_claimed_batch(&binding, replay.permit)
            .expect("replay materialize");
        assert_eq!(replayed.events.as_slice().len(), 2);
        match reopened
            .acknowledge_retrieved_batch(&binding, &request)
            .expect("ack replay")
        {
            IdempotentResult::ExactReplay(_) => {}
            IdempotentResult::Recorded(_) => panic!("ack must replay"),
        }
        let before = reopened.recover_authority_state().expect("before");
        let prior = before.helper_grants[0].clone();
        let mut replacement = prior.clone();
        replacement.grant_verifier = [0x44; 32];
        replacement.grant_ref = VerifierRef::fixture(15);
        reopened.persist_helper_grant(&replacement).expect("rotate");
        reopened
            .revoke_helper_grant(HelperRevocationScope {
                grant_ref: replacement.grant_ref.clone(),
                birth_id: binding.birth_id.clone(),
                attempt_id: binding.attempt_id.clone(),
            })
            .expect("revoke");
        drop(reopened);
        let mut revoked = SqliteBaseline::open_path(&path);
        let snapshot = revoked.recover_authority_state().expect("rotated");
        assert!(snapshot.retired_helper_grants.iter().any(|grant| {
            grant.grant_ref == prior.grant_ref && grant.grant_verifier == prior.grant_verifier
        }));
        assert!(snapshot.helper_grants.iter().any(|grant| grant.revoked));
        assert_eq!(snapshot.ack_replays.len(), 1);
        drop(revoked);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn codec_preserves_fractional_time_and_u64_boundary() {
        let parts = conformance::birth_parts();
        let mut birth = parts.birth;
        birth.lease_until = OffsetDateTime::UNIX_EPOCH
            + time::Duration::seconds(1)
            + time::Duration::nanoseconds(123_456_789);
        birth.created_at = birth.lease_until;
        let mut snapshot = RecoverySnapshot {
            attempt_seq: u64::MAX,
            ..RecoverySnapshot::default()
        };
        snapshot.controller_births.push(birth.clone());
        let (decoded, _) = decode_durable(&encode_durable(&snapshot, &[]));
        assert_eq!(decoded.attempt_seq, u64::MAX);
        assert_eq!(decoded.controller_births[0].lease_until, birth.lease_until);
        assert_eq!(decoded.controller_births[0].created_at, birth.created_at);
    }

    #[test]
    fn commit_fault_keeps_the_previous_sql_pair() {
        let path = std::env::temp_dir().join(format!(
            "gearwit-sqlite-fault-{}-{}.sqlite",
            std::process::id(),
            unique_suffix()
        ));
        let mut store = SqliteBaseline::open_path(&path);
        let (binding, _, _) = conformance::install_helper(&mut store);
        let exchange = conformance::retrieve_for(&binding, 21);
        let authorized = match store.record_retrieve_exchange(&exchange).expect("retrieve") {
            IdempotentResult::Recorded(authorized) => authorized,
            IdempotentResult::ExactReplay(_) => panic!("first retrieve must record"),
        };
        let request =
            conformance::ack_for(&binding, &authorized.recorded.retrieval_id, "event-a", 22);
        store
            .acknowledge_retrieved_batch(&binding, &request)
            .expect("ack");
        let before = store.recover_authority_state().expect("before");
        let payloads = store.live.claim_payloads();
        let extra = ArmId::new("arm-extra").expect("arm");
        store.fault.after_partial_write = true;
        let error = store
            .persist_arm(&PersistedArm {
                arm_id: extra.clone(),
                generation: 2,
                seat_id: binding.seat_id.clone(),
                capability: ManagedCapability::HandleClaimedSignal,
                coverage_until: binding.lease_until,
            })
            .expect_err("fault");
        assert!(matches!(error, PersistError::StorageUnavailable));
        let live = store.recover_authority_state().expect("live");
        assert_eq!(live, before);
        assert_eq!(store.live.claim_payloads(), payloads);
        assert!(live.arms.iter().all(|arm| arm.arm_id != extra));
        drop(store);
        let mut reopened = SqliteBaseline::open_path(&path);
        let snapshot = reopened.recover_authority_state().expect("sql");
        assert_eq!(snapshot, before);
        assert_eq!(reopened.live.claim_payloads(), payloads);
        assert!(snapshot.arms.iter().all(|arm| arm.arm_id != extra));
        drop(reopened);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn post_commit_reload_failure_poisons_the_handle() {
        let path = std::env::temp_dir().join(format!(
            "gearwit-sqlite-poison-{}-{}.sqlite",
            std::process::id(),
            unique_suffix()
        ));
        let mut store = SqliteBaseline::open_path(&path);
        let parts = conformance::birth_parts();
        store
            .reserve_controller_birth(&parts.birth, &parts.reservation)
            .expect("reserve");
        store.fault.reload_after_commit = true;
        let error = store
            .persist_arm(&PersistedArm {
                arm_id: parts.birth.arm_id.clone(),
                generation: parts.birth.generation,
                seat_id: parts.birth.seat_id.clone(),
                capability: parts.birth.capability,
                coverage_until: parts.birth.lease_until,
            })
            .expect_err("reload");
        assert!(matches!(error, PersistError::StorageUnavailable));
        assert!(matches!(
            store.recover_authority_state(),
            Err(PersistError::StorageUnavailable)
        ));
        assert!(matches!(
            store.persist_arm(&PersistedArm {
                arm_id: ArmId::new("arm-overwrite").expect("arm"),
                generation: 9,
                seat_id: parts.birth.seat_id.clone(),
                capability: parts.birth.capability,
                coverage_until: parts.birth.lease_until,
            }),
            Err(PersistError::StorageUnavailable)
        ));
        drop(store);
        let mut reopened = SqliteBaseline::open_path(&path);
        let snapshot = reopened.recover_authority_state().expect("committed");
        assert!(
            snapshot
                .arms
                .iter()
                .any(|arm| arm.arm_id == parts.birth.arm_id)
        );
        assert!(
            snapshot
                .arms
                .iter()
                .all(|arm| arm.arm_id.as_str() != "arm-overwrite")
        );
        drop(reopened);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fractional_event_and_lease_survive_in_digest_bearing_state() {
        let path = std::env::temp_dir().join(format!(
            "gearwit-sqlite-fraction-{}-{}.sqlite",
            std::process::id(),
            unique_suffix()
        ));
        let observed = OffsetDateTime::UNIX_EPOCH
            + time::Duration::seconds(1)
            + time::Duration::nanoseconds(123_456_789);
        let lease = OffsetDateTime::UNIX_EPOCH
            + time::Duration::seconds(90)
            + time::Duration::nanoseconds(987_654_321);
        let mut store = SqliteBaseline::open_path(&path);
        let (binding, admission) = admit_fractional(&mut store, observed, lease);
        let exchange = conformance::retrieve_for(&binding, 31);
        let authorized = match store.record_retrieve_exchange(&exchange).expect("retrieve") {
            IdempotentResult::Recorded(authorized) => authorized,
            IdempotentResult::ExactReplay(_) => panic!("first retrieve must record"),
        };
        let request =
            conformance::ack_for(&binding, &authorized.recorded.retrieval_id, "event-a", 32);
        store
            .acknowledge_retrieved_batch(&binding, &request)
            .expect("ack");
        drop(store);
        let mut reopened = SqliteBaseline::open_path(&path);
        let snapshot = reopened.recover_authority_state().expect("reload");
        assert_eq!(snapshot.claims[0].claim_digest, admission.claim_digest);
        assert_eq!(snapshot.helper_grants[0].lease_until, lease);
        let payload = reopened
            .live
            .claim_payloads()
            .remove(&snapshot.claims[0].payload_ref)
            .expect("payload");
        assert_eq!(payload.events.as_slice()[0].observed_at, observed);
        assert_eq!(
            payload.events.as_slice()[0].body.as_str(),
            "fractional-body"
        );
        match reopened
            .record_retrieve_exchange(&exchange)
            .expect("replay")
        {
            IdempotentResult::ExactReplay(replay) => {
                assert_eq!(replay.recorded, authorized.recorded);
            }
            IdempotentResult::Recorded(_) => panic!("retrieve must replay"),
        }
        match reopened
            .acknowledge_retrieved_batch(&binding, &request)
            .expect("ack replay")
        {
            IdempotentResult::ExactReplay(_) => {}
            IdempotentResult::Recorded(_) => panic!("ack must replay"),
        }
        drop(reopened);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn thread_create_resolution_is_refused_before_a_commit() {
        let path = std::env::temp_dir().join(format!(
            "gearwit-sqlite-create-{}-{}.sqlite",
            std::process::id(),
            unique_suffix()
        ));
        let mut store = SqliteBaseline::open_path(&path);
        let parts = conformance::birth_parts();
        store
            .reserve_controller_birth(&parts.birth, &parts.reservation)
            .expect("reserve");
        let error = store
            .resolve_thread_create(ThreadCreateCommit {
                birth_id: parts.birth.birth_id.clone(),
                create_attempt_id: parts.reservation.create_attempt_id.clone(),
                resolution: crate::persist::ThreadCreateResolution::ProvenNotAccepted,
                evidence_ref: VerifierRef::fixture(4),
            })
            .expect_err("resolve");
        assert!(matches!(error, PersistError::StorageUnavailable));
        drop(store);
        let mut reopened = SqliteBaseline::open_path(&path);
        let snapshot = reopened.recover_authority_state().expect("unchanged");
        assert!(matches!(
            snapshot.ownership[0].state,
            ThreadOwnershipState::Reserved { .. } | ThreadOwnershipState::Unknown { .. }
        ));
        drop(reopened);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unsupported_native_sections_fail_before_a_commit() {
        let path = std::env::temp_dir().join(format!(
            "gearwit-sqlite-refuse-{}-{}.sqlite",
            std::process::id(),
            unique_suffix()
        ));
        let mut store = SqliteBaseline::open_path(&path);
        let parts = conformance::birth_parts();
        let error = store
            .seal_native_coordinate(
                &NativeCoordinateScope::Thread {
                    birth_id: parts.birth.birth_id.clone(),
                    create_attempt_id: parts.reservation.create_attempt_id.clone(),
                },
                &SecretNativeCoordinate::thread("native-thread").expect("coordinate"),
            )
            .expect_err("seal");
        assert!(matches!(error, PersistError::StorageUnavailable));
        drop(store);
        let reopened = SqliteBaseline::open_path(&path);
        let count: i64 = reopened
            .conn
            .query_row("SELECT COUNT(*) FROM authority_snapshot", [], |row| {
                row.get(0)
            })
            .expect("count");
        assert_eq!(count, 0);
        drop(reopened);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reopened_media_process_crash() {
        if let Ok(role) = std::env::var("GEARWIT_CRASH_ROLE") {
            crash_writer(&role);
            return;
        }
        assert_eq!(std::env::consts::OS, "macos");
        assert_eq!(std::env::consts::ARCH, "aarch64");
        let root = std::env::temp_dir().join(format!(
            "gearwit-process-crash-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        std::fs::create_dir_all(&root).expect("dir");
        let filesystem = filesystem_type(&root);
        assert_eq!(filesystem, "apfs");

        let post = root.join("post.sqlite");
        kill_writer_at(&post, "post", "POST_COMMIT");
        let (journal, synchronous) = sqlite_durability(&post);
        assert_eq!(journal, "delete");
        assert_eq!(synchronous, 2);
        let mut fresh = SqliteBaseline::open_path(&post);
        let snapshot = fresh.recover_authority_state().expect("post reopen");
        assert_eq!(snapshot.claims.len(), 1);
        assert_eq!(snapshot.retrieve_replays.len(), 1);
        assert_eq!(snapshot.ack_replays.len(), 1);
        let binding = binding_from_grant(&snapshot.helper_grants[0]);
        let exchange = conformance::retrieve_for(&binding, 41);
        match fresh.record_retrieve_exchange(&exchange).expect("replay") {
            IdempotentResult::ExactReplay(authorized) => {
                let payload = fresh
                    .materialize_claimed_batch(&binding, authorized.permit)
                    .expect("materialize");
                assert_eq!(payload.events.as_slice().len(), 2);
            }
            IdempotentResult::Recorded(_) => panic!("committed retrieve must replay after SIGKILL"),
        }
        drop(fresh);

        let prior = root.join("prior.sqlite");
        kill_writer_at(&prior, "pre", "PRE_COMMIT");
        let mut reopened = SqliteBaseline::open_path(&prior);
        let snapshot = reopened.recover_authority_state().expect("pre reopen");
        assert_eq!(snapshot.claims.len(), 1);
        assert!(
            snapshot
                .arms
                .iter()
                .all(|arm| arm.arm_id.as_str() != "arm-dirty")
        );
        let binding = binding_from_grant(&snapshot.helper_grants[0]);
        let exchange = conformance::retrieve_for(&binding, 41);
        match reopened
            .record_retrieve_exchange(&exchange)
            .expect("prior replay")
        {
            IdempotentResult::ExactReplay(_) => {}
            IdempotentResult::Recorded(_) => {
                panic!("open transaction must not replace the committed retrieve")
            }
        }
        drop(reopened);
        let _ = std::fs::remove_dir_all(&root);
    }
}
