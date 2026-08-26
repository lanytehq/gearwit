//! Split-phase coordinator for idle-only managed native writes.

#![allow(clippy::missing_errors_doc)]

use crate::authority::{
    AdmissionResult, AuthorityError, ClaimRequest, ControllerBirthReservation, CreateResolution,
    DaemonAuthority, PreparedDispatch, ProbeAuthorization, QuarantinedBirthReservation,
    ReconciliationPhase,
};
use crate::controller::{
    ControllerCommand, ControllerIdleGuard, ControllerProbeError, ControllerWriteError,
    IdleProbeResult, IdleProbeScope, NativeWriteDisposition, ObservationScope, ReconciliationScope,
};
use crate::persist::{IdempotentWrite, Persist, ThreadCreateResolution};

/// Controller work that can cross the authority borrow only after a durable
/// reservation. The coordinator retains the non-remintable commit metadata.
#[derive(Debug)]
pub struct ReservedControllerWrite {
    pub lane: ControllerIdleGuard,
    pub command: ControllerCommand,
}

#[derive(Debug)]
pub enum CoordinatedProbe {
    Ready(Box<ReservedControllerWrite>),
    HeldBeforeNativeWrite,
    IdleStateUnproven,
}

pub struct HostCoordinator<P: Persist> {
    authority: DaemonAuthority<P>,
    probing: Option<PreparedDispatch>,
    writing: Option<PreparedDispatch>,
    observing: Option<ObservationScope>,
    reconciling: Option<ReconciliationScope>,
}

impl<P: Persist> HostCoordinator<P> {
    #[must_use]
    pub fn new(authority: DaemonAuthority<P>) -> Self {
        Self {
            authority,
            probing: None,
            writing: None,
            observing: None,
            reconciling: None,
        }
    }

    pub fn recover(mut authority: DaemonAuthority<P>) -> Result<Self, AuthorityError> {
        let (mut observing, mut reconciling) = authority.recover()?.into_followup_scopes();
        if observing.len() + reconciling.len() > 1 {
            return Err(AuthorityError::Conflict);
        }
        Ok(Self {
            authority,
            probing: None,
            writing: None,
            observing: observing.pop(),
            reconciling: reconciling.pop(),
        })
    }

    #[cfg(test)]
    fn authority_mut(&mut self) -> &mut DaemonAuthority<P> {
        &mut self.authority
    }

    pub fn admit(&mut self, request: &ClaimRequest) -> Result<AdmissionResult, AuthorityError> {
        self.authority.admit_claim(request)
    }

    pub fn reserve_controller_birth(
        &mut self,
        arm_id: &str,
    ) -> Result<ControllerBirthReservation, AuthorityError> {
        self.authority.reserve_controller_birth(arm_id)
    }

    pub fn resolve_thread_create(
        &mut self,
        reservation: ControllerBirthReservation,
        resolution: ThreadCreateResolution,
    ) -> Result<CreateResolution, AuthorityError> {
        self.authority
            .resolve_thread_create(reservation, resolution)
    }

    pub fn resolve_quarantined_thread_create(
        &mut self,
        reservation: QuarantinedBirthReservation,
        resolution: ThreadCreateResolution,
    ) -> Result<IdempotentWrite, AuthorityError> {
        self.authority
            .resolve_quarantined_thread_create(reservation, resolution)
    }

    pub(crate) fn set_now(&mut self, now: time::OffsetDateTime) {
        self.authority.set_now(now);
    }

    /// Record dispatch preparation and return only an exact sealed probe scope.
    pub fn prepare(
        &mut self,
        receipt: crate::authority::AdmissionReceipt,
    ) -> Result<IdleProbeScope, AuthorityError> {
        if self.probing.is_some() || self.writing.is_some() {
            return Err(AuthorityError::Conflict);
        }
        let (prepared, scope) = self.authority.prepare_handle_claimed_signal(receipt)?;
        self.probing = Some(prepared);
        Ok(scope)
    }

    /// Validate one exact probe. Active and unproven results clear the pending
    /// action after a durable zero-write conclusion.
    pub fn authorize_probe(
        &mut self,
        result: Result<IdleProbeResult, ControllerProbeError>,
    ) -> Result<CoordinatedProbe, AuthorityError> {
        let prepared = self.probing.take().ok_or(AuthorityError::Conflict)?;
        match self.authority.authorize_probe(prepared, result)? {
            ProbeAuthorization::Ready(authorized) => {
                let (prepared, lane, command) = (*authorized).into_parts();
                self.writing = Some(prepared);
                Ok(CoordinatedProbe::Ready(Box::new(ReservedControllerWrite {
                    lane,
                    command,
                })))
            }
            ProbeAuthorization::HeldBeforeNativeWrite => {
                Ok(CoordinatedProbe::HeldBeforeNativeWrite)
            }
            ProbeAuthorization::IdleStateUnproven => Ok(CoordinatedProbe::IdleStateUnproven),
        }
    }

    pub fn conclude_native_write(
        &mut self,
        disposition: Result<NativeWriteDisposition, ControllerWriteError>,
    ) -> Result<(), AuthorityError> {
        let prepared = self.writing.take().ok_or(AuthorityError::Conflict)?;
        let conclusion = self
            .authority
            .conclude_native_write(prepared, disposition)?;
        let (observing, reconciling) = conclusion.into_scopes();
        self.observing = observing;
        self.reconciling = reconciling;
        Ok(())
    }

    pub fn poll_and_record_exact<C: crate::controller::Controller>(
        &mut self,
        controller: &mut C,
    ) -> Result<Option<IdempotentWrite>, AuthorityError> {
        let scope = self.observing.as_ref().ok_or(AuthorityError::Conflict)?;
        let Some(fact) = controller.poll_exact_observation(scope) else {
            return Ok(None);
        };
        let terminal = matches!(fact, crate::controller::NativeTurnFact::Terminal { .. });
        let record = self.authority.record_exact_observation(scope, fact)?;
        if terminal || record.reconciliation.is_some() {
            self.observing = None;
        }
        self.reconciling = record.reconciliation;
        Ok(Some(record.write))
    }

    pub fn reconcile_and_record<C: crate::controller::Controller>(
        &mut self,
        controller: &mut C,
    ) -> Result<IdempotentWrite, AuthorityError> {
        let scope = self.reconciling.as_ref().ok_or(AuthorityError::Conflict)?;
        let disposition = controller.reconcile_exact(scope);
        let (result, phase) = self.authority.record_reconciliation(scope, disposition)?;
        match phase {
            ReconciliationPhase::Reconciling => {}
            ReconciliationPhase::Observing(scope) => {
                self.reconciling = None;
                self.observing = Some(*scope);
            }
            ReconciliationPhase::Closed => self.reconciling = None,
        }
        Ok(result)
    }

    #[must_use]
    pub fn has_pending_native_authority(&self) -> bool {
        self.probing.is_some()
            || self.writing.is_some()
            || self.observing.is_some()
            || self.reconciling.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::ManagedArmRegistration;
    use crate::controller::{
        Controller, FakeController, FakeIdleState, NativeTurnFact, NativeWriteDisposition,
        PrivateNativeRef, ReconciliationDisposition, SecretNativeCoordinate,
    };
    use crate::persist::{SharedFakePersist, ThreadCreateResolution};
    use time::{Duration, OffsetDateTime};

    fn now() -> OffsetDateTime {
        time::macros::datetime!(2026-01-15 12:00:00 UTC)
    }

    fn coordinator() -> HostCoordinator<SharedFakePersist> {
        let mut authority = DaemonAuthority::new(SharedFakePersist::default(), now());
        authority
            .register_managed_arm(ManagedArmRegistration {
                arm_id: "arm-a".to_owned(),
                generation: 1,
                seat_id: "seat-a".to_owned(),
                coverage_until: now() + Duration::hours(1),
            })
            .expect("arm");
        let birth = authority.reserve_controller_birth("arm-a").expect("birth");
        authority
            .resolve_thread_create(
                birth,
                ThreadCreateResolution::Owned {
                    thread_ref: PrivateNativeRef([7; 32]),
                },
            )
            .expect("owned");
        HostCoordinator::new(authority)
    }

    fn request() -> ClaimRequest {
        ClaimRequest {
            arm_id: "arm-a".to_owned(),
            request_id: "claim-a".to_owned(),
            signal_id: "signal-a".to_owned(),
            events: vec![gearwit_protocol::ProviderEvent {
                provider: "example".to_owned(),
                event_ref: "event-a".to_owned(),
                actor: None,
                observed_at: "2026-01-15T12:00:00Z".to_owned(),
                body: "untrusted".to_owned(),
            }],
        }
    }

    fn recovered_unknown() -> HostCoordinator<SharedFakePersist> {
        let mut coordinator = coordinator();
        let admission = coordinator.admit(&request()).expect("admit");
        let scope = coordinator
            .prepare(admission.into_receipt().expect("receipt"))
            .expect("prepare");
        let mut controller = FakeController::new(
            vec![FakeIdleState::Idle(1)],
            vec![NativeWriteDisposition::Unknown],
        )
        .with_now(now());
        let probe = controller.probe_idle(scope);
        let CoordinatedProbe::Ready(write) = coordinator.authorize_probe(probe).expect("authorize")
        else {
            panic!("ready");
        };
        let ReservedControllerWrite { lane, command } = *write;
        let disposition = controller.write_reserved_turn(lane, command);
        coordinator
            .conclude_native_write(disposition)
            .expect("unknown");
        let backend = coordinator.authority_mut().inspect_persist().clone();
        HostCoordinator::recover(DaemonAuthority::new(backend, now())).expect("recover")
    }

    fn durable_conclusion_counts(
        coordinator: &mut HostCoordinator<SharedFakePersist>,
    ) -> (usize, usize, usize) {
        let mut backend = coordinator.authority_mut().inspect_persist().clone();
        let snapshot = backend.recover_authority_state().expect("snapshot");
        (
            snapshot.native_write_evidence.len(),
            snapshot.native_turn_facts.len(),
            snapshot.reconciliations.len(),
        )
    }

    #[test]
    fn one_idle_probe_reserves_and_writes_one_fixed_turn() {
        let mut coordinator = coordinator();
        let admission = coordinator.admit(&request()).expect("admit");
        let scope = coordinator
            .prepare(admission.into_receipt().expect("receipt"))
            .expect("prepare");
        let mut controller = FakeController::new(
            vec![FakeIdleState::Idle(4)],
            vec![NativeWriteDisposition::Accepted {
                turn_ref: PrivateNativeRef([8; 32]),
            }],
        )
        .with_now(now());
        let probe = controller.probe_idle(scope);
        let CoordinatedProbe::Ready(write) = coordinator.authorize_probe(probe).expect("authorize")
        else {
            panic!("ready");
        };
        let ReservedControllerWrite { lane, command } = *write;
        let turn_scope = command.turn_scope();
        let mut backend = coordinator.authority_mut().inspect_persist().clone();
        let turn = backend
            .seal_native_coordinate(
                &turn_scope,
                &SecretNativeCoordinate::turn("coordinator-turn").expect("turn"),
            )
            .expect("seal turn");
        let _ = controller.write_reserved_turn(lane, command);
        let disposition = NativeWriteDisposition::Accepted {
            turn_ref: turn.clone(),
        };
        controller = controller.with_observations(vec![Some(NativeTurnFact::Started {
            turn_ref: turn.clone(),
        })]);
        assert!(controller.native_bytes() > 0);
        coordinator
            .conclude_native_write(Ok(disposition))
            .expect("conclude");
        assert!(coordinator.has_pending_native_authority());
        assert_eq!(
            coordinator
                .poll_and_record_exact(&mut controller)
                .expect("poll and persist"),
            Some(IdempotentWrite::Recorded)
        );
        let backend = coordinator.authority_mut().inspect_persist().clone();
        let mut recovered = HostCoordinator::recover(DaemonAuthority::new(backend, now()))
            .expect("recover observation");
        assert!(recovered.has_pending_native_authority());
        let mut terminal = FakeController::new(vec![], vec![]).with_observations(vec![Some(
            NativeTurnFact::Terminal {
                turn_ref: turn,
                class: crate::controller::TerminalClass::Succeeded,
            },
        )]);
        recovered
            .poll_and_record_exact(&mut terminal)
            .expect("persist terminal");
        assert!(!recovered.has_pending_native_authority());

        let backend = recovered.authority_mut().inspect_persist().clone();
        let closed = HostCoordinator::recover(DaemonAuthority::new(backend, now()))
            .expect("recover terminal");
        assert!(!closed.has_pending_native_authority());
    }

    #[test]
    fn unknown_write_recovers_only_as_metadata_and_is_never_resent() {
        let mut recovered = recovered_unknown();
        assert!(recovered.has_pending_native_authority());
        let turn_scope = recovered
            .reconciling
            .as_ref()
            .expect("reconciliation scope")
            .turn_scope();
        let mut backend = recovered.authority_mut().inspect_persist().clone();
        let turn_ref = backend
            .seal_native_coordinate(
                &turn_scope,
                &SecretNativeCoordinate::turn("reconciled-turn").expect("turn"),
            )
            .expect("seal reconciled turn");
        let mut reconciler = FakeController::new(vec![], vec![])
            .with_reconciliation(ReconciliationDisposition::Accepted {
                turn_ref: turn_ref.clone(),
            })
            .with_observations(vec![Some(NativeTurnFact::Started {
                turn_ref: turn_ref.clone(),
            })]);
        assert_eq!(
            recovered
                .reconcile_and_record(&mut reconciler)
                .expect("reconcile and persist"),
            IdempotentWrite::Recorded
        );
        assert!(recovered.has_pending_native_authority());
        recovered
            .poll_and_record_exact(&mut reconciler)
            .expect("persist reconciled start");
        assert!(recovered.has_pending_native_authority());

        let backend = recovered.authority_mut().inspect_persist().clone();
        let restarted = HostCoordinator::recover(DaemonAuthority::new(backend, now()))
            .expect("recover reconciliation");
        assert!(restarted.has_pending_native_authority());
    }

    #[test]
    fn uncertain_observations_enter_reconciliation() {
        for fact in [
            NativeTurnFact::DegradedTerminalObservation,
            NativeTurnFact::Unknown,
            NativeTurnFact::ControllerLost,
        ] {
            let mut coordinator = coordinator();
            let admission = coordinator.admit(&request()).expect("admit");
            let scope = coordinator
                .prepare(admission.into_receipt().expect("receipt"))
                .expect("prepare");
            let mut controller = FakeController::new(
                vec![FakeIdleState::Idle(4)],
                vec![NativeWriteDisposition::Accepted {
                    turn_ref: PrivateNativeRef([8; 32]),
                }],
            )
            .with_now(now());
            let probe = controller.probe_idle(scope);
            let CoordinatedProbe::Ready(write) =
                coordinator.authorize_probe(probe).expect("authorize")
            else {
                panic!("ready");
            };
            let ReservedControllerWrite { lane, command } = *write;
            let turn_scope = command.turn_scope();
            let mut backend = coordinator.authority_mut().inspect_persist().clone();
            let turn = backend
                .seal_native_coordinate(
                    &turn_scope,
                    &SecretNativeCoordinate::turn("uncertain-turn").expect("turn"),
                )
                .expect("seal turn");
            let _ = controller.write_reserved_turn(lane, command);
            coordinator
                .conclude_native_write(Ok(NativeWriteDisposition::Accepted { turn_ref: turn }))
                .expect("conclude");
            controller = controller.with_observations(vec![Some(fact)]);
            assert_eq!(
                coordinator
                    .poll_and_record_exact(&mut controller)
                    .expect("record uncertain observation"),
                Some(IdempotentWrite::Recorded)
            );
            let mut reconciler = FakeController::new(vec![], vec![])
                .with_reconciliation(ReconciliationDisposition::Unknown);
            assert_eq!(
                coordinator
                    .reconcile_and_record(&mut reconciler)
                    .expect("reconciliation scope"),
                IdempotentWrite::Recorded
            );
            assert!(coordinator.has_pending_native_authority());
        }
    }

    #[test]
    fn proven_prewrite_rejection_never_opens_reconciliation() {
        let mut coordinator = coordinator();
        let admission = coordinator.admit(&request()).expect("admit");
        let scope = coordinator
            .prepare(admission.into_receipt().expect("receipt"))
            .expect("prepare");
        let mut controller =
            FakeController::new(vec![FakeIdleState::Idle(1)], vec![]).with_now(now());
        let probe = controller.probe_idle(scope);
        let CoordinatedProbe::Ready(_) = coordinator.authorize_probe(probe).expect("authorize")
        else {
            panic!("ready");
        };
        coordinator
            .conclude_native_write(Ok(NativeWriteDisposition::ProvenNotAccepted))
            .expect("conclude prewrite rejection");
        assert!(!coordinator.has_pending_native_authority());
    }

    #[test]
    fn controller_write_binding_rejection_records_no_conclusion() {
        let mut coordinator = coordinator();
        let admission = coordinator.admit(&request()).expect("admit");
        let scope = coordinator
            .prepare(admission.into_receipt().expect("receipt"))
            .expect("prepare");
        let mut controller = FakeController::new(
            vec![FakeIdleState::Idle(1)],
            vec![NativeWriteDisposition::ProvenNotAccepted],
        )
        .with_now(now())
        .with_write_binding_rejection();
        let probe = controller.probe_idle(scope);
        let CoordinatedProbe::Ready(write) = coordinator.authorize_probe(probe).expect("authorize")
        else {
            panic!("ready");
        };
        let before = durable_conclusion_counts(&mut coordinator);
        let ReservedControllerWrite { lane, command } = *write;
        let result = controller.write_reserved_turn(lane, command);
        assert_eq!(controller.native_bytes(), 0);
        assert_eq!(
            coordinator.conclude_native_write(result),
            Err(AuthorityError::Unauthorized)
        );
        assert_eq!(durable_conclusion_counts(&mut coordinator), before);
        assert!(!coordinator.has_pending_native_authority());
    }

    #[test]
    fn controller_reconciliation_binding_rejection_records_no_conclusion() {
        let mut coordinator = recovered_unknown();
        let before = durable_conclusion_counts(&mut coordinator);
        let mut wrong_controller =
            FakeController::new(vec![], vec![]).with_reconciliation_binding_rejection();

        assert_eq!(
            coordinator.reconcile_and_record(&mut wrong_controller),
            Err(AuthorityError::Unauthorized)
        );
        assert_eq!(wrong_controller.native_bytes(), 0);
        assert_eq!(durable_conclusion_counts(&mut coordinator), before);
        assert!(coordinator.has_pending_native_authority());
    }

    #[test]
    fn reconciliation_closed_outcomes_do_not_reopen_after_restart() {
        for terminal in [false, true] {
            let mut recovered = recovered_unknown();
            let disposition = if terminal {
                let turn_scope = recovered
                    .reconciling
                    .as_ref()
                    .expect("reconciliation scope")
                    .turn_scope();
                let mut backend = recovered.authority_mut().inspect_persist().clone();
                ReconciliationDisposition::Terminal {
                    turn_ref: backend
                        .seal_native_coordinate(
                            &turn_scope,
                            &SecretNativeCoordinate::turn("terminal-turn").expect("turn"),
                        )
                        .expect("seal terminal turn"),
                    class: crate::controller::TerminalClass::Failed,
                }
            } else {
                ReconciliationDisposition::ProvenNotAccepted
            };
            let mut reconciler =
                FakeController::new(vec![], vec![]).with_reconciliation(disposition.clone());
            recovered
                .reconcile_and_record(&mut reconciler)
                .expect("persist closed reconciliation");
            assert!(!recovered.has_pending_native_authority());
            let backend = recovered.authority_mut().inspect_persist().clone();
            if matches!(disposition, ReconciliationDisposition::Terminal { .. }) {
                let mut inspection = DaemonAuthority::new(backend.clone(), now());
                let recovery = inspection.recover().expect("inspect terminal facts");
                assert!(matches!(
                    recovery.snapshot.native_turn_facts[0].facts.as_slice(),
                    [NativeTurnFact::Terminal { .. }]
                ));
            }
            let restarted = HostCoordinator::recover(DaemonAuthority::new(backend, now()))
                .expect("recover closed reconciliation");
            assert!(!restarted.has_pending_native_authority());
        }

        let mut recovered = recovered_unknown();
        let mut unresolved = FakeController::new(vec![], vec![])
            .with_reconciliation(ReconciliationDisposition::Unknown);
        recovered
            .reconcile_and_record(&mut unresolved)
            .expect("persist unknown reconciliation");
        let backend = recovered.authority_mut().inspect_persist().clone();
        let restarted = HostCoordinator::recover(DaemonAuthority::new(backend, now()))
            .expect("recover unknown reconciliation");
        assert!(restarted.has_pending_native_authority());
    }
}
