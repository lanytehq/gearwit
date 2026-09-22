//! Development-only bridge for the Gearwit simulator.
//!
//! This module is absent unless the `simulator` feature is selected. It keeps
//! fixture construction and fault controls out of production host surfaces.

use crate::conformance::{self, ConformanceFixture, FakeFixture, Prepared};
use crate::controller::{
    AttemptId, ClaimDigest, ControllerBirthId, EventRef, RequestNonce, SignalId, VerifierRef,
};
use crate::persist::{
    AcknowledgeRequest, AcknowledgeResult, AdmissionOutcome, AuthorizedRetrieve,
    HelperRevocationScope, IdempotentResult, Persist, PersistError, RearmJoinResult,
    RearmJoinScope, RetrieveExchange, ValidatedHelperBinding, canonical_ack_body_digest,
    canonical_binding_digest, canonical_retrieve_body_digest,
};
use crate::sqlite_baseline::{self, SqliteBaseline};
use gearwit_protocol::ProviderEvent;
use serde::{Deserialize, Serialize};
use std::path::Path;
use time::OffsetDateTime;

/// One operation accepted by the development-only store stream adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreStreamAction {
    Arm,
    Offer { event: String },
    Admit { event: String },
    Retrieve { request: String },
    StaleRetrieve { request: String },
    Acknowledge { request: String },
    Terminal,
    Rearm,
    Revoke,
    Restart,
    OmitRearm,
}

/// Store-derived receipt returned for one resolved simulator operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreStreamReceipt {
    pub outcome: String,
    pub logical_effects: u64,
    pub authority_revision: u64,
}

/// Stateful development adapter over one admitted persistence store.
pub struct StoreStreamAdapter(StoreStreamAdapterInner);

enum StoreStreamAdapterInner {
    Fake(StreamDriver<FakeFixture>),
    Sqlite(StreamDriver<SqliteBaseline>),
}

impl StoreStreamAdapter {
    #[must_use]
    pub fn new(store: SimulatorStore) -> Self {
        match store {
            SimulatorStore::Fake => Self(StoreStreamAdapterInner::Fake(StreamDriver::new())),
            SimulatorStore::Sqlite => Self(StoreStreamAdapterInner::Sqlite(StreamDriver::new())),
        }
    }

    /// Execute one operation against the same store used by earlier calls.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot execute or recover the requested
    /// operation.
    pub fn apply(
        &mut self,
        operation_id: &str,
        action: &StoreStreamAction,
    ) -> Result<StoreStreamReceipt, String> {
        match &mut self.0 {
            StoreStreamAdapterInner::Fake(driver) => driver.apply(operation_id, action),
            StoreStreamAdapterInner::Sqlite(driver) => driver.apply(operation_id, action),
        }
    }
}

struct StreamDriver<F: ConformanceFixture> {
    store: Option<F::Store>,
    binding: ValidatedHelperBinding,
    attachment: crate::persist::PersistedControllerAttachment,
    admissions: std::collections::BTreeMap<
        String,
        (
            String,
            crate::persist::ClaimAdmission,
            crate::persist::PersistedControllerAttachment,
        ),
    >,
    offered: Vec<String>,
    last_retrieve: Option<AuthorizedRetrieve>,
    admitted_event_ref: Option<String>,
    blueprint: crate::persist::RecoverySnapshot,
    grant_installed: bool,
    arm_count: u64,
    cycle_admitted: bool,
    logical_effects: u64,
    revision: u64,
}

impl<F: ConformanceFixture> StreamDriver<F> {
    fn new() -> Self {
        let Prepared {
            mut store,
            binding,
            admission: _,
            attachment,
        } = F::prepare();
        let blueprint = store
            .recover_authority_state()
            .expect("fixture blueprint must recover");
        Self {
            store: Some(F::empty()),
            binding,
            attachment,
            admissions: std::collections::BTreeMap::new(),
            offered: Vec::new(),
            last_retrieve: None,
            admitted_event_ref: None,
            blueprint,
            grant_installed: false,
            arm_count: 0,
            cycle_admitted: false,
            logical_effects: 0,
            revision: 0,
        }
    }

    fn apply(
        &mut self,
        operation_id: &str,
        action: &StoreStreamAction,
    ) -> Result<StoreStreamReceipt, String> {
        let outcome = match action {
            StoreStreamAction::Restart => {
                let store = self.store.take().ok_or("store unavailable")?;
                self.store = Some(F::reopen(store).map_err(debug_error)?);
                "reopened".to_owned()
            }
            _ => self.apply_live(operation_id, action)?,
        };
        let recovered = self
            .store
            .as_mut()
            .ok_or("store unavailable")?
            .recover_authority_state()
            .map_err(debug_error)?;
        self.logical_effects = u64::try_from(recovered.claims.len())
            .map_err(|_| "claim count exceeded receipt range".to_owned())?;
        Ok(StoreStreamReceipt {
            outcome,
            logical_effects: self.logical_effects,
            authority_revision: self.revision,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn apply_live(
        &mut self,
        operation_id: &str,
        action: &StoreStreamAction,
    ) -> Result<String, String> {
        let store = self.store.as_mut().ok_or("store unavailable")?;
        match action {
            StoreStreamAction::Arm => {
                let mut birth = self
                    .blueprint
                    .controller_births
                    .first()
                    .ok_or("fixture blueprint had no controller birth")?
                    .clone();
                let mut reservation = conformance::birth_parts().reservation;
                let mut arm = self
                    .blueprint
                    .arms
                    .first()
                    .ok_or("fixture blueprint had no arm")?
                    .clone();
                if self.arm_count > 0 {
                    let generation = self.binding.generation.saturating_add(1);
                    arm.generation = generation;
                    birth.generation = generation;
                    self.binding.generation = generation;
                    self.attachment.generation = generation;
                    let cycle = self.arm_count.to_string();
                    birth.birth_id = ControllerBirthId(identity_bytes("birth-cycle", &cycle));
                    birth.verifier_ref =
                        VerifierRef::from_bytes(identity_bytes("birth-verifier", &cycle));
                    reservation.birth_id.clone_from(&birth.birth_id);
                    reservation.create_attempt_id =
                        RequestNonce(identity_bytes("birth-reservation", &cycle));
                    self.binding.birth_id.clone_from(&birth.birth_id);
                    self.attachment.birth_id.clone_from(&birth.birth_id);
                    self.binding.attempt_id = AttemptId::new(bounded_id("attempt-cycle", &cycle))
                        .map_err(str::to_owned)?;
                    self.binding.signal_id =
                        SignalId::new(bounded_id("signal-cycle", &cycle)).map_err(str::to_owned)?;
                    self.binding.grant_ref =
                        VerifierRef::from_bytes(identity_bytes("grant-cycle", &cycle));
                    self.attachment
                        .attempt_id
                        .clone_from(&self.binding.attempt_id);
                    self.attachment.verifier_ref =
                        VerifierRef::from_bytes(identity_bytes("attachment-cycle", &cycle));
                    self.grant_installed = false;
                    self.cycle_admitted = false;
                    self.last_retrieve = None;
                    self.admitted_event_ref = None;
                }
                store
                    .reserve_controller_birth(&birth, &reservation)
                    .map_err(debug_error)?;
                store.persist_arm(&arm).map_err(debug_error)?;
                self.arm_count += 1;
                self.revision += 1;
                Ok("armed".to_owned())
            }
            StoreStreamAction::Offer { event } => {
                self.offered.push(event.clone());
                self.revision += 1;
                Ok("offered".to_owned())
            }
            StoreStreamAction::Admit { event } => {
                if !self.admissions.contains_key(operation_id)
                    && !self.offered.iter().any(|offered| offered == event)
                {
                    return Ok("unauthorized".to_owned());
                }
                let (admission, attachment) = if let Some((original, admission, attachment)) =
                    self.admissions.get(operation_id)
                {
                    let mut admission = admission.clone();
                    if original != event {
                        admission.claim_digest =
                            ClaimDigest(identity_bytes("changed-claim", event));
                    }
                    (admission, attachment.clone())
                } else {
                    let first = !self.cycle_admitted;
                    let event_record = ProviderEvent {
                        provider: "test".to_owned(),
                        event_ref: bounded_id("event", event),
                        actor: None,
                        observed_at: "1970-01-01T00:00:00Z".to_owned(),
                        body: format!("simulator event {event}"),
                    };
                    let request_id = bounded_id("claim", operation_id);
                    let admission = crate::persist::claim_admission_fixture(
                        &request_id,
                        self.binding.arm_id.clone(),
                        self.binding.generation,
                        if first {
                            self.binding.signal_id.clone()
                        } else {
                            SignalId::new(bounded_id("signal", operation_id))
                                .map_err(str::to_owned)?
                        },
                        &[event_record],
                        OffsetDateTime::UNIX_EPOCH,
                    );
                    let mut attachment = self.attachment.clone();
                    if !first {
                        attachment.attempt_id = AttemptId::new(bounded_id("attempt", operation_id))
                            .map_err(str::to_owned)?;
                        attachment.verifier_ref = VerifierRef::from_bytes(identity_bytes(
                            "attachment-verifier",
                            operation_id,
                        ));
                    }
                    (admission, attachment)
                };
                let result = store.admit_claim(&admission, &attachment);
                let outcome = match result {
                    Ok(result) if result.outcome == AdmissionOutcome::Admitted => {
                        if !self.grant_installed {
                            let mut grant = self
                                .blueprint
                                .helper_grants
                                .first()
                                .ok_or("fixture blueprint had no helper grant")?
                                .clone();
                            grant.claim_digest.clone_from(&admission.claim_digest);
                            grant.grant_ref.clone_from(&self.binding.grant_ref);
                            grant.generation = self.binding.generation;
                            grant.birth_id.clone_from(&self.binding.birth_id);
                            grant.attempt_id.clone_from(&self.binding.attempt_id);
                            grant.signal_id.clone_from(&self.binding.signal_id);
                            self.binding
                                .claim_digest
                                .clone_from(&admission.claim_digest);
                            store.persist_helper_grant(&grant).map_err(debug_error)?;
                            self.grant_installed = true;
                        }
                        self.admitted_event_ref = Some(bounded_id("event", event));
                        self.cycle_admitted = true;
                        self.logical_effects += 1;
                        self.revision += 1;
                        "admitted"
                    }
                    Ok(result) if result.outcome == AdmissionOutcome::ExactReplay => "exact_replay",
                    Err(PersistError::Conflict) => "conflict",
                    Err(PersistError::Unauthorized) => "unauthorized",
                    Err(PersistError::InvalidTransition) => "invalid_transition",
                    Err(error) => return Err(debug_error(error)),
                    Ok(result) => return Err(format!("unexpected admission outcome: {result:?}")),
                };
                self.admissions.entry(operation_id.to_owned()).or_insert((
                    event.clone(),
                    admission,
                    attachment,
                ));
                Ok(outcome.to_owned())
            }
            StoreStreamAction::Retrieve { request } => {
                let exchange = stream_retrieve(&self.binding, request);
                match store.record_retrieve_exchange(&exchange) {
                    Ok(IdempotentResult::Recorded(authorized)) => {
                        self.last_retrieve = Some(authorized);
                        self.revision += 1;
                        Ok("retrieved".to_owned())
                    }
                    Ok(IdempotentResult::ExactReplay(authorized)) => {
                        self.last_retrieve = Some(authorized);
                        Ok("exact_replay".to_owned())
                    }
                    Err(PersistError::Unauthorized) => Ok("unauthorized".to_owned()),
                    Err(PersistError::InvalidTransition) => Ok("invalid_transition".to_owned()),
                    Err(error) => Err(debug_error(error)),
                }
            }
            StoreStreamAction::StaleRetrieve { request } => {
                let mut advanced = self
                    .blueprint
                    .arms
                    .first()
                    .ok_or("fixture blueprint had no arm")?
                    .clone();
                advanced.generation = self.binding.generation.saturating_add(1);
                store.persist_arm(&advanced).map_err(debug_error)?;
                let exchange = stream_retrieve(&self.binding, request);
                match store.record_retrieve_exchange(&exchange) {
                    Err(PersistError::Unauthorized) => {
                        let recovered = store.recover_authority_state().map_err(debug_error)?;
                        let current_preserved =
                            recovered.arms.iter().any(|arm| {
                                arm.arm_id == advanced.arm_id
                                    && arm.generation == advanced.generation
                            }) && recovered.helper_grants.iter().any(|grant| !grant.revoked);
                        if current_preserved {
                            Ok("unauthorized".to_owned())
                        } else {
                            Err("stale retrieve did not preserve current authority".to_owned())
                        }
                    }
                    other => Err(format!("stale retrieve was accepted: {other:?}")),
                }
            }
            StoreStreamAction::Acknowledge { request } => {
                let authorized = self
                    .last_retrieve
                    .as_ref()
                    .ok_or("acknowledgment had no recorded retrieve")?;
                let ack = stream_ack(
                    &self.binding,
                    &authorized.recorded.retrieval_id,
                    self.admitted_event_ref
                        .as_deref()
                        .ok_or("acknowledgment had no admitted event")?,
                    request,
                );
                match store.acknowledge_retrieved_batch(&self.binding, &ack) {
                    Ok(IdempotentResult::Recorded(_)) => {
                        self.revision += 1;
                        Ok("acknowledged".to_owned())
                    }
                    Ok(IdempotentResult::ExactReplay(_)) => Ok("exact_replay".to_owned()),
                    Err(PersistError::Unauthorized) => Ok("unauthorized".to_owned()),
                    Err(PersistError::InvalidTransition) => Ok("invalid_transition".to_owned()),
                    Err(error) => Err(debug_error(error)),
                }
            }
            StoreStreamAction::Terminal => {
                F::install_terminal(
                    store,
                    &self.binding,
                    identity_bytes("terminal", operation_id),
                )
                .map_err(debug_error)?;
                self.revision += 1;
                Ok("terminal".to_owned())
            }
            StoreStreamAction::Rearm => match store
                .try_rearm_join(join_scope(&self.binding))
                .map_err(debug_error)?
            {
                RearmJoinResult::Rearmed => {
                    self.revision += 1;
                    Ok("rearmed".to_owned())
                }
                RearmJoinResult::AlreadyRearmed => Ok("exact_replay".to_owned()),
                RearmJoinResult::WaitingForHandled => Ok("waiting_for_handled".to_owned()),
                RearmJoinResult::WaitingForRecognizedTerminal => {
                    Ok("waiting_for_terminal".to_owned())
                }
            },
            StoreStreamAction::Revoke => {
                store
                    .revoke_helper_grant(revocation_scope(&self.binding))
                    .map_err(debug_error)?;
                self.revision += 1;
                Ok("revoked".to_owned())
            }
            StoreStreamAction::OmitRearm => Ok("inactive".to_owned()),
            StoreStreamAction::Restart => unreachable!("handled by apply"),
        }
    }
}

fn identity_bytes(domain: &str, value: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"gearwit.simulator-identity.v1\0");
    hasher.update(domain.as_bytes());
    hasher.update(b"\0");
    hasher.update(value.as_bytes());
    *hasher.finalize().as_bytes()
}

fn bounded_id(prefix: &str, value: &str) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(prefix.len() + 65);
    output.push_str(prefix);
    output.push('-');
    for byte in identity_bytes(prefix, value) {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
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

fn stream_retrieve(binding: &ValidatedHelperBinding, request: &str) -> RetrieveExchange {
    let binding = copy_binding(binding);
    let request_id = RequestNonce(identity_bytes("retrieve-request", request));
    let canonical_body_digest =
        canonical_retrieve_body_digest(&canonical_binding_digest(&binding), &request_id);
    RetrieveExchange {
        binding,
        request_id,
        canonical_body_digest,
    }
}

fn stream_ack(
    binding: &ValidatedHelperBinding,
    retrieval_id: &crate::controller::RetrievalId,
    cursor: &str,
    request: &str,
) -> AcknowledgeRequest {
    let request_id = RequestNonce(identity_bytes("ack-request", request));
    let cursor = EventRef::new(cursor).expect("admitted event ref is bounded");
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

/// Admitted synthetic stores. Neither variant is a production provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulatorStore {
    Fake,
    Sqlite,
}

/// Result of an executable host check.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostCheck {
    pub store: SimulatorStore,
    pub check: String,
    pub passed: bool,
    pub detail: String,
}

/// Execute one stable persistence conformance case.
#[must_use]
pub fn run_conformance(store: SimulatorStore, case_id: &str) -> HostCheck {
    let result = match store {
        SimulatorStore::Fake => conformance::execute::<FakeFixture>(case_id),
        SimulatorStore::Sqlite => conformance::execute::<SqliteBaseline>(case_id),
    };
    match result {
        Ok(()) => HostCheck {
            store,
            check: case_id.to_owned(),
            passed: true,
            detail: "passed".to_owned(),
        },
        Err(detail) => HostCheck {
            store,
            check: case_id.to_owned(),
            passed: false,
            detail,
        },
    }
}

/// Execute a complete retrieve/materialize/ack/restart/rearm chain.
#[must_use]
pub fn run_complete_chain(store: SimulatorStore) -> HostCheck {
    let result = match store {
        SimulatorStore::Fake => complete_chain::<FakeFixture>(),
        SimulatorStore::Sqlite => complete_chain::<SqliteBaseline>(),
    };
    match result {
        Ok(()) => HostCheck {
            store,
            check: "complete-chain".to_owned(),
            passed: true,
            detail: reopen_evidence(store, "complete chain passed"),
        },
        Err(detail) => HostCheck {
            store,
            check: "complete-chain".to_owned(),
            passed: false,
            detail,
        },
    }
}

/// Execute one named simulator chain through an admitted persistence store.
#[must_use]
pub fn run_chain_case(store: SimulatorStore, case_id: &str) -> HostCheck {
    let result = match store {
        SimulatorStore::Fake => chain_case::<FakeFixture>(case_id),
        SimulatorStore::Sqlite => chain_case::<SqliteBaseline>(case_id),
    };
    match result {
        Ok(detail) => HostCheck {
            store,
            check: format!("store-chain-{case_id}"),
            passed: true,
            detail: reopen_evidence(store, &detail),
        },
        Err(detail) => HostCheck {
            store,
            check: format!("store-chain-{case_id}"),
            passed: false,
            detail,
        },
    }
}

fn reopen_evidence(store: SimulatorStore, detail: &str) -> String {
    match store {
        SimulatorStore::Fake => format!("fake state reopened; {detail}"),
        SimulatorStore::Sqlite => format!("original SQLite media closed and reopened; {detail}"),
    }
}

fn chain_case<F: ConformanceFixture>(case_id: &str) -> Result<String, String> {
    match case_id {
        "SIM-CHAIN-02" => chain_exact_retries::<F>(),
        "SIM-CHAIN-03" => chain_changed_identity::<F>(),
        "SIM-CHAIN-04" => chain_revocation::<F>(),
        "SIM-CHAIN-05" => chain_stale_capability::<F>(),
        "SIM-CHAIN-06" => chain_event_during_rearm::<F>(),
        "SIM-CHAIN-08" => chain_omitted_rearm::<F>(),
        _ => Err(format!(
            "no store-backed chain implementation for {case_id}"
        )),
    }
}

fn chain_exact_retries<F: ConformanceFixture>() -> Result<String, String> {
    let Prepared {
        mut store, binding, ..
    } = F::prepare();
    let exchange = conformance::retrieve_for(&binding, 111);
    let authorized = recorded_retrieve(&mut store, &exchange)?;
    expect_retrieve_replay(&mut store, &exchange, &authorized)?;
    let ack = conformance::ack_for(&binding, &authorized.recorded.retrieval_id, "event-b", 112);
    let acknowledged = recorded_ack(&mut store, &binding, &ack)?;
    expect_ack_replay(&mut store, &binding, &ack, &acknowledged)?;
    let mut reopened = reopen::<F>(store)?;
    expect_retrieve_replay(&mut reopened, &exchange, &authorized)?;
    expect_ack_replay(&mut reopened, &binding, &ack, &acknowledged)?;
    Ok("recorded; exact retrieve+ack replay; reopened; exact retrieve+ack replay".to_owned())
}

fn chain_changed_identity<F: ConformanceFixture>() -> Result<String, String> {
    let Prepared {
        store,
        admission,
        attachment,
        ..
    } = F::prepare();
    let mut reopened = reopen::<F>(store)?;
    let replay = reopened
        .admit_claim(&admission, &attachment)
        .map_err(debug_error)?;
    if replay.outcome != AdmissionOutcome::ExactReplay {
        return Err(format!("admission did not replay after reopen: {replay:?}"));
    }
    let mut changed = admission;
    changed.claim_digest = ClaimDigest::fixture(91);
    match reopened.admit_claim(&changed, &attachment) {
        Err(PersistError::Conflict) => {
            let recovered = reopened.recover_authority_state().map_err(debug_error)?;
            if recovered.claims.len() != 1 {
                return Err(format!(
                    "changed-content conflict altered claim count: {}",
                    recovered.claims.len()
                ));
            }
            Ok(
                "reopened; exact claim replay; changed-content identity conflict; one claim retained"
                    .to_owned(),
            )
        }
        other => Err(format!(
            "changed-content identity did not conflict: {other:?}"
        )),
    }
}

fn chain_revocation<F: ConformanceFixture>() -> Result<String, String> {
    let Prepared {
        mut store, binding, ..
    } = F::prepare();
    store
        .revoke_helper_grant(revocation_scope(&binding))
        .map_err(debug_error)?;
    let mut reopened = reopen::<F>(store)?;
    let recovered = reopened.recover_authority_state().map_err(debug_error)?;
    if !recovered.helper_grants.iter().any(|grant| grant.revoked) {
        return Err("reopened state lost revocation".to_owned());
    }
    match reopened.record_retrieve_exchange(&conformance::retrieve_for(&binding, 121)) {
        Err(PersistError::Unauthorized) => {
            Ok("revoked; reopened; revoked state recovered; fresh retrieve refused".to_owned())
        }
        other => Err(format!("retrieve after reopened revocation: {other:?}")),
    }
}

fn chain_stale_capability<F: ConformanceFixture>() -> Result<String, String> {
    let Prepared {
        mut store, binding, ..
    } = F::prepare();
    let snapshot = store.recover_authority_state().map_err(debug_error)?;
    let mut replacement = snapshot.helper_grants[0].clone();
    replacement.grant_verifier = [0x55; 32];
    replacement.grant_ref = VerifierRef::fixture(122);
    store
        .persist_helper_grant(&replacement)
        .map_err(debug_error)?;
    let mut reopened = reopen::<F>(store)?;
    match reopened.record_retrieve_exchange(&conformance::retrieve_for(&binding, 123)) {
        Err(PersistError::Unauthorized) => Ok(
            "capability rotated; reopened; retired capability remained stale; retrieve refused"
                .to_owned(),
        ),
        other => Err(format!("stale capability regained access: {other:?}")),
    }
}

fn chain_event_during_rearm<F: ConformanceFixture>() -> Result<String, String> {
    let Prepared {
        mut store,
        binding,
        attachment,
        ..
    } = F::prepare();
    let exchange = conformance::retrieve_for(&binding, 131);
    let authorized = recorded_retrieve(&mut store, &exchange)?;
    let ack = conformance::ack_for(&binding, &authorized.recorded.retrieval_id, "event-b", 132);
    recorded_ack(&mut store, &binding, &ack)?;
    match store
        .try_rearm_join(join_scope(&binding))
        .map_err(debug_error)?
    {
        RearmJoinResult::WaitingForRecognizedTerminal => {}
        other => return Err(format!("early rearm did not wait for terminal: {other:?}")),
    }
    let before_event = store.recover_authority_state().map_err(debug_error)?;
    if !before_event.rearmed_joins.is_empty() {
        return Err("early rearm was durably published".to_owned());
    }
    let waiting_event = ProviderEvent {
        provider: "test".to_owned(),
        event_ref: "event-during-rearm".to_owned(),
        actor: None,
        observed_at: "1970-01-01T00:00:00Z".to_owned(),
        body: "synthetic queued event".to_owned(),
    };
    let waiting_admission = crate::persist::claim_admission_fixture(
        "claim-during-rearm",
        binding.arm_id.clone(),
        binding.generation,
        SignalId::new("signal-during-rearm").expect("fixture signal"),
        &[waiting_event],
        OffsetDateTime::UNIX_EPOCH,
    );
    let mut waiting_attachment = attachment;
    waiting_attachment.attempt_id =
        AttemptId::new("attempt-during-rearm").expect("fixture attempt");
    waiting_attachment.verifier_ref = VerifierRef::fixture(133);
    match store.admit_claim(&waiting_admission, &waiting_attachment) {
        Err(PersistError::Conflict) => {}
        other => {
            return Err(format!(
                "waiting event admission was not deferred: {other:?}"
            ));
        }
    }
    let mut pending = std::collections::VecDeque::new();
    pending.push_back(waiting_admission);
    let after_event = store.recover_authority_state().map_err(debug_error)?;
    if pending.len() != 1 || after_event != before_event {
        return Err("queued arrival changed authority before rearm completed".to_owned());
    }
    F::install_terminal(&mut store, &binding, [131; 32]).map_err(debug_error)?;
    let mut reopened = reopen::<F>(store)?;
    match reopened
        .try_rearm_join(join_scope(&binding))
        .map_err(debug_error)?
    {
        RearmJoinResult::Rearmed
            if pending.pop_front().is_some_and(|admission| {
                admission
                    .event_refs
                    .as_slice()
                    .iter()
                    .any(|event| event.as_str() == "event-during-rearm")
            }) => Ok(
                "acknowledged; rearm waited; event admission validated and deferred by active generation; authority unchanged; same media reopened; terminal recovered; rearmed; queued event retained"
                    .to_owned(),
            ),
        other => Err(format!("terminal rearm did not complete: {other:?}")),
    }
}

fn chain_omitted_rearm<F: ConformanceFixture>() -> Result<String, String> {
    let Prepared {
        mut store, binding, ..
    } = F::prepare();
    let exchange = conformance::retrieve_for(&binding, 141);
    let authorized = recorded_retrieve(&mut store, &exchange)?;
    let ack = conformance::ack_for(&binding, &authorized.recorded.retrieval_id, "event-b", 142);
    recorded_ack(&mut store, &binding, &ack)?;
    F::install_terminal(&mut store, &binding, [141; 32]).map_err(debug_error)?;
    let mut reopened = reopen::<F>(store)?;
    let recovered = reopened.recover_authority_state().map_err(debug_error)?;
    if !recovered.rearmed_joins.is_empty() {
        return Err("rearm appeared despite omission".to_owned());
    }
    match reopened.record_retrieve_exchange(&conformance::retrieve_for(&binding, 143)) {
        Err(PersistError::InvalidTransition) => Ok(
            "acknowledged; terminal recovered; rearm omitted; authority stayed inactive".to_owned(),
        ),
        other => Err(format!("omitted rearm did not remain inactive: {other:?}")),
    }
}

fn complete_chain<F: ConformanceFixture>() -> Result<(), String> {
    let Prepared {
        mut store, binding, ..
    } = F::prepare();
    let exchange = conformance::retrieve_for(&binding, 101);
    let authorized = match store
        .record_retrieve_exchange(&exchange)
        .map_err(debug_error)?
    {
        IdempotentResult::Recorded(authorized) => authorized,
        IdempotentResult::ExactReplay(_) => return Err("first retrieve replayed".to_owned()),
    };
    let payload = store
        .materialize_claimed_batch(&binding, authorized.permit)
        .map_err(debug_error)?;
    if payload.events.as_slice().len() != 2 {
        return Err("materialized payload count differed".to_owned());
    }
    let ack = conformance::ack_for(&binding, &authorized.recorded.retrieval_id, "event-b", 102);
    if !matches!(
        store
            .acknowledge_retrieved_batch(&binding, &ack)
            .map_err(debug_error)?,
        IdempotentResult::Recorded(_)
    ) {
        return Err("first acknowledgment replayed".to_owned());
    }
    F::install_terminal(&mut store, &binding, [71; 32]).map_err(debug_error)?;
    let mut reopened = reopen::<F>(store)?;
    match reopened
        .record_retrieve_exchange(&exchange)
        .map_err(debug_error)?
    {
        IdempotentResult::ExactReplay(replayed) if replayed.recorded == authorized.recorded => {}
        other => return Err(format!("retrieve did not replay after reopen: {other:?}")),
    }
    let scope = RearmJoinScope {
        arm_id: binding.arm_id.clone(),
        generation: binding.generation,
        attempt_id: binding.attempt_id.clone(),
        signal_id: binding.signal_id.clone(),
    };
    match reopened.try_rearm_join(scope).map_err(debug_error)? {
        RearmJoinResult::Rearmed => Ok(()),
        other => Err(format!("complete chain did not rearm: {other:?}")),
    }
}

fn reopen<F: ConformanceFixture>(store: F::Store) -> Result<F::Store, String> {
    F::reopen(store).map_err(debug_error)
}

fn recorded_retrieve(
    store: &mut impl Persist,
    exchange: &RetrieveExchange,
) -> Result<AuthorizedRetrieve, String> {
    match store
        .record_retrieve_exchange(exchange)
        .map_err(debug_error)?
    {
        IdempotentResult::Recorded(authorized) => Ok(authorized),
        IdempotentResult::ExactReplay(_) => Err("first retrieve unexpectedly replayed".to_owned()),
    }
}

fn expect_retrieve_replay(
    store: &mut impl Persist,
    exchange: &RetrieveExchange,
    expected: &AuthorizedRetrieve,
) -> Result<(), String> {
    match store
        .record_retrieve_exchange(exchange)
        .map_err(debug_error)?
    {
        IdempotentResult::ExactReplay(actual) if actual.recorded == expected.recorded => Ok(()),
        other => Err(format!("retrieve did not replay exactly: {other:?}")),
    }
}

fn recorded_ack(
    store: &mut impl Persist,
    binding: &ValidatedHelperBinding,
    request: &AcknowledgeRequest,
) -> Result<AcknowledgeResult, String> {
    match store
        .acknowledge_retrieved_batch(binding, request)
        .map_err(debug_error)?
    {
        IdempotentResult::Recorded(result) => Ok(result),
        IdempotentResult::ExactReplay(_) => {
            Err("first acknowledgment unexpectedly replayed".to_owned())
        }
    }
}

fn expect_ack_replay(
    store: &mut impl Persist,
    binding: &ValidatedHelperBinding,
    request: &AcknowledgeRequest,
    expected: &AcknowledgeResult,
) -> Result<(), String> {
    match store
        .acknowledge_retrieved_batch(binding, request)
        .map_err(debug_error)?
    {
        IdempotentResult::ExactReplay(actual) if &actual == expected => Ok(()),
        other => Err(format!("acknowledgment did not replay exactly: {other:?}")),
    }
}

fn revocation_scope(binding: &ValidatedHelperBinding) -> HelperRevocationScope {
    HelperRevocationScope {
        grant_ref: binding.grant_ref.clone(),
        birth_id: binding.birth_id.clone(),
        attempt_id: binding.attempt_id.clone(),
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

fn debug_error(error: PersistError) -> String {
    format!("{error:?}")
}

/// Run the `SQLite` writer side of a real process-crash scenario.
///
/// The caller must execute this in a child process and terminate it after the
/// requested milestone file appears.
///
/// # Errors
///
/// Returns an error when the phase is unknown or fixture preparation fails.
pub fn run_crash_child(path: &Path, phase: &str) -> Result<(), String> {
    sqlite_baseline::run_simulator_crash_child(path, phase)
}

/// Reopen and verify media left by a killed simulator child.
///
/// # Errors
///
/// Returns an error when the committed state cannot be recovered exactly.
pub fn verify_crash_reopen(path: &Path) -> Result<(), String> {
    sqlite_baseline::verify_simulator_crash_reopen(path)
}
