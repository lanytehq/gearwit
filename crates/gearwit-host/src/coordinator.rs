//! Host coordinator — split-phase state machine for dispatch lifecycle.
//!
//! Lives one level outside `DaemonAuthority`. Exercises the three-phase
//! sequence required by cxotech ruling `ioe77faay3ndbc6mf5wcur1k6a`:
//!
//! 1. Enter authority → `prepare_dispatch` → exit (opaque token returned).
//! 2. Caller performs `Controller::dispatch` with no authority guard.
//! 3. Re-enter authority → `conclude_dispatch` consuming the opaque token.
//!
//! The coordinator does not hold an authority reference across phases.

use crate::controller::{
    Controller, ControllerAttachment, DispatchDisposition, LifecycleObservation, SignalAction,
};
use crate::{
    AdmissionError, AdmissionResult, ClaimRequest, DaemonAuthority, DispatchConclusion,
    DispatchError, Persist, PreparedDispatch,
};

/// Split-phase host coordinator for the Gearwit dispatch lifecycle.
///
/// Owns the authority and a mutable controller reference. Callers drive
/// phases explicitly — no authority borrow or lock survives across
/// provider I/O.
pub struct HostCoordinator<'c, P: Persist, C: Controller> {
    authority: DaemonAuthority<P>,
    controller: &'c mut C,
    /// Opaque prepared token from phase 2, consumed in phase 4.
    pending: Option<PreparedDispatch>,
}

impl<'c, P: Persist, C: Controller> HostCoordinator<'c, P, C> {
    /// Create a new coordinator with the given authority and controller.
    #[must_use]
    pub fn new(authority: DaemonAuthority<P>, controller: &'c mut C) -> Self {
        Self {
            authority,
            controller,
            pending: None,
        }
    }

    /// Mutable access to the authority (for re-arm between phases).
    #[must_use]
    pub fn authority_mut(&mut self) -> &mut DaemonAuthority<P> {
        &mut self.authority
    }

    // -- Phase 1: admit claim (entered authority, exits immediately) --

    /// Admit a claim under authority. Returns the admission result.
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError` when admission fails.
    pub fn admit(&mut self, req: &ClaimRequest) -> Result<AdmissionResult, AdmissionError> {
        self.authority.admit_claim(req)
    }

    // -- Phase 2: prepare dispatch (entered authority, exits with token) --

    /// Prepare a dispatch: validate attachment, record `DispatchPrepared`,
    /// and store the opaque prepared token. The authority borrow ends here.
    ///
    /// # Errors
    ///
    /// Returns `DispatchError::PreSend` when validation or persistence fails.
    pub fn prepare(&mut self, admission: &AdmissionResult) -> Result<(), DispatchError> {
        let claim = admission.claim.clone();
        let att = admission
            .attachment
            .as_ref()
            .ok_or_else(|| DispatchError::PreSend("no attachment".to_owned()))?;
        let prepared = self.authority.prepare_dispatch(&claim, att)?;
        self.pending = Some(prepared);
        Ok(())
    }

    /// The signal action for native I/O (valid only after `prepare`).
    ///
    /// # Panics
    ///
    /// Panics if called before `prepare`.
    #[must_use]
    pub fn pending_action(&self) -> &SignalAction {
        self.pending
            .as_ref()
            .expect("pending_action called before prepare")
            .action()
    }

    // -- Phase 3: native I/O (no authority guard) --

    /// Dispatch through the controller — no authority guard held.
    /// Returns the disposition.
    pub fn dispatch(&mut self, attachment: &ControllerAttachment) -> DispatchDisposition {
        let action = self.pending_action().clone();
        self.controller.dispatch(attachment, &action)
    }

    /// Poll for lifecycle observations after dispatch.
    ///
    /// # Panics
    ///
    /// Panics if called before `prepare`.
    pub fn poll_observations(&mut self) -> Vec<LifecycleObservation> {
        let attempt_id = self
            .pending
            .as_ref()
            .expect("poll_observations called before prepare")
            .action()
            .signal_id
            .clone();
        let mut obs = Vec::new();
        while let Some(o) = self.controller.poll_observation(&attempt_id) {
            obs.push(o);
        }
        obs
    }

    // -- Phase 4: conclude (re-entered authority, consumes token) --

    /// Conclude a dispatch: record disposition and observations under
    /// authority. The prepared token is consumed.
    ///
    /// # Errors
    ///
    /// Returns `DispatchError` when conclusion fails.
    ///
    /// # Panics
    ///
    /// Panics if called before `prepare`.
    pub fn conclude(
        &mut self,
        disposition: DispatchDisposition,
        observations: Vec<LifecycleObservation>,
    ) -> Result<DispatchConclusion, DispatchError> {
        let prepared = self.pending.take().expect("conclude called before prepare");
        self.authority
            .conclude_dispatch(prepared, disposition, observations)
    }

    /// True if a prepared token is pending (between phases 2 and 4).
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
}
