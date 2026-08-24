//! Host coordinator — split-phase state machine for dispatch lifecycle.
//!
//! Lives one level outside `DaemonAuthority`. Exercises the three-phase
//! sequence required by the cxotech option-(c) ruling:
//!
//! 1. Enter authority → `prepare_dispatch` → exit with opaque token +
//!    sealed `ControllerCommand`.
//! 2. Caller performs native I/O via `Controller` outside authority
//!    (the command is consumed by the native-I/O adapter).
//! 3. Re-enter authority → `conclude_dispatch` consuming the opaque token
//!    by value.
//!
//! The coordinator does NOT hold a controller reference. It emits bounded
//! controller work; the caller drives provider I/O independently. No
//! authority borrow or lock survives across provider I/O, and no
//! coordinator method panics — every misuse returns a typed error.

use crate::authority::ReconciliationWork;
use crate::controller::ReconciliationDisposition;
use crate::controller::{ControllerCommand, DispatchDisposition, LifecycleObservation};
use crate::{
    AdmissionError, AdmissionReceipt, AdmissionResult, ClaimRequest, DaemonAuthority,
    DispatchConclusion, DispatchError, Persist, PreparedDispatch,
};

/// Split-phase host coordinator for the Gearwit dispatch lifecycle.
///
/// Owns the authority only. Emits a sealed `ControllerCommand` on
/// prepare; accepts disposition + observations on conclude. The pending
/// token is consumed by value at conclusion.
pub struct HostCoordinator<P: Persist> {
    authority: DaemonAuthority<P>,
    /// Opaque prepared token from phase 2, consumed in phase 4.
    pending: Option<PreparedDispatch>,
}

impl<P: Persist> HostCoordinator<P> {
    /// Create a new coordinator with the given authority.
    #[must_use]
    pub fn new(authority: DaemonAuthority<P>) -> Self {
        Self {
            authority,
            pending: None,
        }
    }

    /// Mutable access to the authority (for re-arm between phases).
    /// The authority lock is released after every phase — the provider
    /// does not dispatch while this handle exists.
    #[must_use]
    pub fn authority_mut(&mut self) -> &mut DaemonAuthority<P> {
        &mut self.authority
    }

    // -- Phase 1: admit claim (entered authority, exits immediately) --

    /// Admit a claim under authority. Returns the admission result,
    /// which carries the opaque admission receipt for `prepare`.
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError` when admission fails.
    pub fn admit(&mut self, req: &ClaimRequest) -> Result<AdmissionResult, AdmissionError> {
        self.authority.admit_claim(req)
    }

    // -- Phase 2: prepare dispatch (entered authority, exits with command) --

    /// Prepare a dispatch: the opaque `AdmissionReceipt` is consumed by
    /// value; the authority rehydrates the claim and attachment from
    /// stored state and durably records the prepare. Returns the sealed
    /// `ControllerCommand` for native I/O. The authority borrow ends here.
    ///
    /// # Errors
    ///
    /// Returns `DispatchError::PreSend` when rehydration, validation, or
    /// persistence fails.
    pub fn prepare(
        &mut self,
        receipt: AdmissionReceipt,
    ) -> Result<ControllerCommand, DispatchError> {
        let (prepared, cmd) = self.authority.prepare_dispatch(receipt)?;
        self.pending = Some(prepared);
        Ok(cmd)
    }

    // -- Phase 3: native I/O (no authority guard; caller drives) --

    // No methods — the caller drives `command.dispatch(controller)` and
    // `controller.poll_observation(command.attempt_id())` outside
    // authority. `ControllerCommand::dispatch` consumes the command, so
    // a second I/O pass cannot be assembled from the same work.

    // -- Phase 4: conclude (re-entered authority, consumes token) --

    /// Conclude a dispatch: atomically record disposition, first
    /// transition, and the durable consumption marker under authority.
    /// The prepared token is consumed by value.
    ///
    /// # Errors
    ///
    /// Returns `DispatchError::PreSend` when no prepare is pending;
    /// `DispatchError::PostSend` when the atomic conclusion cannot be
    /// persisted.
    pub fn conclude(
        &mut self,
        disposition: DispatchDisposition,
        observations: Vec<LifecycleObservation>,
    ) -> Result<DispatchConclusion, DispatchError> {
        let prepared = self.pending.take().ok_or_else(|| {
            DispatchError::PreSend(
                "conclude called with no prepared dispatch — call prepare first".to_owned(),
            )
        })?;
        self.authority
            .conclude_dispatch(prepared, disposition, observations)
    }

    /// True if a prepared token is pending (between phases 2 and 4).
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    // -- Split-phase reconciliation (authority | probe | authority) ------

    /// Authority phase 1: produce reconciliation work. The caller probes
    /// the controller strictly outside any authority borrow between this
    /// call and `commit_reconciliation`.
    ///
    /// # Errors
    ///
    /// Returns `DispatchError::PostSend` when the attempt has no
    /// persisted binding or is already resolved. Fails closed.
    pub fn prepare_reconciliation(
        &mut self,
        attempt_id: &str,
    ) -> Result<ReconciliationWork, DispatchError> {
        self.authority.prepare_reconciliation(attempt_id)
    }

    /// Authority phase 3: commit the provider probe's resolution
    /// durably. Consumes the reconciliation work by value.
    ///
    /// # Errors
    ///
    /// Returns `DispatchError::PostSend` when the resolution cannot be
    /// persisted, conflicts, or no prior ambiguity exists.
    pub fn commit_reconciliation(
        &mut self,
        work: ReconciliationWork,
        disposition: ReconciliationDisposition,
    ) -> Result<ReconciliationDisposition, DispatchError> {
        self.authority.commit_reconciliation(work, disposition)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::{Controller, FakeController, ManagedCapability};
    use crate::persist::FakePersist;
    use crate::{ClaimOutcome, KnownArm, Transition};
    use gearwit_protocol::ProviderEvent;
    use time::Duration as TimeDuration;
    use time::OffsetDateTime;

    fn now() -> OffsetDateTime {
        time::macros::datetime!(2026-01-15 12:00:00 UTC)
    }

    fn sample_event(body: &str) -> ProviderEvent {
        ProviderEvent {
            provider: "test".to_owned(),
            event_ref: format!("event-{body}"),
            actor: Some("example-devlead".to_owned()),
            observed_at: "2026-01-15T12:00:00Z".to_owned(),
            body: body.to_owned(),
        }
    }

    fn arm() -> KnownArm {
        KnownArm {
            arm_id: "arm-01".to_owned(),
            generation: 1,
            seat_id: "example-devrev".to_owned(),
            route: ManagedCapability::MANAGED_TURN_START_ROUTE.to_owned(),
            capability: ManagedCapability::ManagedTurnStart,
            coverage_until: now() + TimeDuration::hours(24),
        }
    }

    fn req(rid: &str, sid: &str, body: &str) -> ClaimRequest {
        ClaimRequest {
            arm_id: "arm-01".to_owned(),
            request_id: rid.to_owned(),
            signal_id: sid.to_owned(),
            events: vec![sample_event(body)],
        }
    }

    fn coordinated() -> HostCoordinator<FakePersist> {
        let mut authority = DaemonAuthority::new(FakePersist::default(), now());
        authority.register_arm(arm()).expect("register");
        HostCoordinator::new(authority)
    }

    fn restarted(persist: &FakePersist) -> HostCoordinator<FakePersist> {
        HostCoordinator::new(DaemonAuthority::new(persist.clone(), now()))
    }

    /// Accepting controller scripted for a specific attempt id (so the
    /// poll correlation is checked) with started + terminal observations.
    fn accepting_controller_for(attempt: &str) -> FakeController {
        FakeController::new(vec![DispatchDisposition::Accepted {
            correlation: "turn-X".to_owned(),
        }])
        .with_observations(vec![
            Some(LifecycleObservation::TurnStarted("T1".to_owned())),
            Some(LifecycleObservation::TurnTerminal("T1".to_owned(), true)),
        ])
        .with_expected_attempt_id(attempt)
    }

    /// Admit → prepare → consume sealed command → poll → conclude.
    /// Returns the attempt id.
    fn drive_full_cycle(coord: &mut HostCoordinator<FakePersist>, rid: &str, sid: &str) -> String {
        let admission = coord.admit(&req(rid, sid, "hello")).expect("admit");
        let attempt_id = admission.attempt_id.clone();
        let receipt = admission.into_receipt().expect("receipt");
        let command = coord.prepare(receipt).expect("prepare");
        let attempt = command.attempt_id().to_owned();
        // The sealed command is consumed by the native-I/O adapter;
        // the provider I/O happens strictly outside authority.
        let mut controller = accepting_controller_for(&attempt);
        let disposition = command.dispatch(&mut controller);
        let observations: Vec<_> = std::iter::once(controller.poll_observation(&attempt))
            .chain(std::iter::once(controller.poll_observation(&attempt)))
            .flatten()
            .collect();
        coord.conclude(disposition, observations).expect("conclude");
        attempt_id
    }

    #[test]
    fn full_sequence_through_coordinator_with_fake_controller() {
        let mut coord = coordinated();
        let attempt_id = drive_full_cycle(&mut coord, "req-1", "sig-1");
        assert_eq!(attempt_id, "attempt-1");
        assert!(!coord.has_pending());
        let persist = coord.authority_mut().persist();
        let ts = persist.get_transitions("sig-1", "attempt-1");
        assert!(ts.contains(&Transition::DispatchPrepared));
        assert!(ts.contains(&Transition::NativeAccepted));
        assert!(ts.contains(&Transition::ExactTurnStart));
        assert!(ts.contains(&Transition::ExactTurnTerminal));
    }

    #[test]
    fn authority_is_available_while_provider_work_is_outstanding() {
        let mut coord = coordinated();
        let admission = coord.admit(&req("req-1", "sig-1", "hello")).expect("admit");
        let receipt = admission.into_receipt().expect("receipt");
        let command = coord.prepare(receipt).expect("prepare");
        assert!(coord.has_pending());

        // Provider work is outstanding (command not yet dispatched).
        // The authority remains usable: register and re-arm a peer arm.
        let mut peer = arm();
        peer.arm_id = "arm-02".to_owned();
        peer.route = "managed_turn_start".to_owned();
        coord
            .authority_mut()
            .register_arm(peer)
            .expect("register peer while work outstanding");
        coord
            .authority_mut()
            .advance_generation("arm-02")
            .expect("re-arm peer while work outstanding");

        // Then the provider I/O happens strictly outside authority.
        let attempt = command.attempt_id().to_owned();
        let mut controller = accepting_controller_for(&attempt);
        let disposition = command.dispatch(&mut controller);
        let observations: Vec<_> = std::iter::once(controller.poll_observation(&attempt))
            .chain(std::iter::once(controller.poll_observation(&attempt)))
            .flatten()
            .collect();
        coord.conclude(disposition, observations).expect("conclude");
        assert_eq!(controller.dispatch_count(), 1);
    }

    #[test]
    fn conclude_before_prepare_returns_typed_error_not_panic() {
        let mut coord = coordinated();
        let err = coord
            .conclude(DispatchDisposition::Rejected, vec![])
            .expect_err("conclude without prepare");
        assert!(
            matches!(&err, DispatchError::PreSend(msg) if msg.contains("no prepared dispatch")),
            "got {err:?}"
        );
    }

    #[test]
    fn command_is_single_use_across_restart_and_replay() {
        // One dispatch ever: replay and restart cannot re-assemble work.
        let mut coord = coordinated();
        let attempt_id = drive_full_cycle(&mut coord, "req-1", "sig-1");

        // Exact replay: Replay outcome, no receipt, no new dispatch.
        let replay = coord
            .admit(&req("req-1", "sig-1", "hello"))
            .expect("replay");
        assert_eq!(replay.outcome, ClaimOutcome::Replay);
        assert!(replay.into_receipt().is_none());

        // Restart: fresh authority from the same backend; the durable
        // consumption markers survive and gates stay closed.
        let mut coord2 = restarted(coord.authority_mut().persist());
        let recovery = coord2.authority_mut().recover().expect("recover");
        assert!(
            !recovery
                .derivable_ambiguous_attempts()
                .contains(&attempt_id)
        );
        let replay2 = coord2
            .admit(&req("req-1", "sig-1", "hello"))
            .expect("replay after restart");
        assert_eq!(replay2.outcome, ClaimOutcome::Replay);
        assert!(replay2.into_receipt().is_none());
    }

    #[test]
    fn conclusion_failure_leaves_attempt_recoverable() {
        // Session 1: prepare + dispatch + atomic conclusion failure.
        let persist = FakePersist {
            next_conclusion_error: Some("commit failed".to_owned()),
            ..Default::default()
        };
        let mut authority = DaemonAuthority::new(persist, now());
        authority.register_arm(arm()).expect("register");
        let mut coord = HostCoordinator::new(authority);

        let admission = coord.admit(&req("req-1", "sig-1", "hello")).expect("admit");
        let receipt = admission.into_receipt().expect("receipt");
        let command = coord.prepare(receipt).expect("prepare");
        let attempt = command.attempt_id().to_owned();
        let mut controller = accepting_controller_for(&attempt);
        let disposition = command.dispatch(&mut controller);
        let observations: Vec<_> = std::iter::once(controller.poll_observation(&attempt))
            .chain(std::iter::once(controller.poll_observation(&attempt)))
            .flatten()
            .collect();
        let err = coord
            .conclude(disposition, observations)
            .expect_err("atomic conclusion failure");
        assert!(matches!(err, DispatchError::PostSend(_)));
        assert_eq!(
            controller.dispatch_count(),
            1,
            "exactly one native dispatch"
        );

        // Nothing durable recorded; the attempt survives restart as
        // ambiguous and the token was not consumed.
        let snapshot = coord
            .authority_mut()
            .persist_mut()
            .recover()
            .expect("snapshot");
        assert!(!snapshot.concluded_set.contains_key("attempt-1"));

        let mut coord2 = restarted(coord.authority_mut().persist());
        let recovery = coord2.authority_mut().recover().expect("recover");
        assert!(
            recovery
                .derivable_ambiguous_attempts()
                .contains(&"attempt-1".to_owned())
        );

        // Re-admitting the same request yields Replay — never a second
        // dispatch-capable grant. The provider saw exactly one dispatch.
        let replay = coord2
            .admit(&req("req-1", "sig-1", "hello"))
            .expect("replay");
        assert_eq!(replay.outcome, ClaimOutcome::Replay);
        assert!(replay.into_receipt().is_none());
        assert_eq!(controller.dispatch_count(), 1);
    }

    #[test]
    fn coordinator_split_phase_reconcile_probes_outside_authority() {
        let mut coord = coordinated();
        // Ambiguous lifecycle through the coordinator.
        {
            let admission = coord.admit(&req("req-1", "sig-1", "hello")).expect("admit");
            let receipt = admission.into_receipt().expect("receipt");
            let command = coord.prepare(receipt).expect("prepare");
            let mut controller = FakeController::new(vec![DispatchDisposition::Ambiguous]);
            let disposition = command.dispatch(&mut controller);
            coord.conclude(disposition, vec![]).expect("conclude");
        }
        let attempt_id = "attempt-1";

        // Phase 1: authority only.
        let work = coord
            .prepare_reconciliation(attempt_id)
            .expect("prepare reconciliation");

        // Between phases the authority is free for other production use.
        coord
            .authority_mut()
            .advance_generation("arm-01")
            .expect("re-arm between reconciliation phases");

        // Phase 2: provider probe strictly outside authority.
        let controller = FakeController::new(vec![])
            .with_reconciliation(ReconciliationDisposition::ProvenNotAccepted);
        let disposition = controller.reconcile(work.attempt_id());

        // Phase 3: authority commit.
        let result = coord
            .commit_reconciliation(work, disposition)
            .expect("commit");
        assert_eq!(result, ReconciliationDisposition::ProvenNotAccepted);

        let mut coord2 = restarted(coord.authority_mut().persist());
        let recovery = coord2.authority_mut().recover().expect("recover");
        assert!(
            !recovery
                .derivable_ambiguous_attempts()
                .contains(&attempt_id.to_owned()),
            "resolved attempt must not be derivable"
        );
    }

    #[test]
    fn refreshed_coordinator_after_restart_serves_full_lifecycle() {
        // Proves recovered authority state is usable — not just
        // reconstructed — by running a complete fresh cycle.
        let mut coord = coordinated();
        let _ = drive_full_cycle(&mut coord, "req-1", "sig-1");
        coord
            .authority_mut()
            .set_rearmed("arm-01")
            .expect("rearm persisting");

        let mut coord2 = restarted(coord.authority_mut().persist());
        coord2.authority_mut().recover().expect("recover");
        coord2
            .authority_mut()
            .advance_generation("arm-01")
            .expect("re-arm after restart");

        let admission = coord2
            .admit(&req("req-3", "sig-3", "fresh"))
            .expect("fresh admission after restart");
        assert_eq!(admission.attempt_id, "attempt-2");
        let receipt = admission.into_receipt().expect("receipt");
        let command = coord2.prepare(receipt).expect("prepare");
        let attempt = command.attempt_id().to_owned();
        let mut controller2 = accepting_controller_for(&attempt);
        let disposition = command.dispatch(&mut controller2);
        let observations: Vec<_> = std::iter::once(controller2.poll_observation(&attempt))
            .chain(std::iter::once(controller2.poll_observation(&attempt)))
            .flatten()
            .collect();
        coord2
            .conclude(disposition, observations)
            .expect("conclude after restart");
        assert_eq!(controller2.dispatch_count(), 1);
    }
}
