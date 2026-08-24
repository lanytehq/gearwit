//! Host coordinator — split-phase state machine for dispatch lifecycle.
//!
//! Lives one level outside `DaemonAuthority`. Exercises the three-phase
//! sequence required by cxotech ruling `ioe77faay3ndbc6mf5wcur1k6a`:
//!
//! 1. Enter authority → `prepare_dispatch` → exit with opaque token +
//!    authority-produced `ControllerCommand`.
//! 2. Caller performs native I/O via `Controller` outside authority.
//! 3. Re-enter authority → `conclude_dispatch` consuming the opaque token.
//!
//! The coordinator does NOT hold a controller reference. It emits bounded
//! controller work; the caller drives provider I/O independently.

use crate::controller::{ControllerCommand, DispatchDisposition, LifecycleObservation};
use crate::{
    AdmissionError, AdmissionResult, ClaimRequest, DaemonAuthority, DispatchConclusion,
    DispatchError, Persist, PreparedDispatch,
};

/// Split-phase host coordinator for the Gearwit dispatch lifecycle.
///
/// Owns the authority only. Emits `ControllerCommand` on prepare; accepts
/// disposition + observations on conclude. No authority borrow or lock
/// survives across provider I/O.
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

    // -- Phase 2: prepare dispatch (entered authority, exits with command) --

    /// Prepare a dispatch: validate attachment, record `DispatchPrepared`,
    /// and return an authority-produced `ControllerCommand` for native I/O.
    /// The opaque `PreparedDispatch` token is stored for phase 4.
    /// The authority borrow ends here.
    ///
    /// # Errors
    ///
    /// Returns `DispatchError::PreSend` when validation or persistence fails.
    pub fn prepare(
        &mut self,
        admission: &AdmissionResult,
    ) -> Result<ControllerCommand, DispatchError> {
        let claim = admission.claim.clone();
        let att = admission
            .attachment
            .as_ref()
            .ok_or_else(|| DispatchError::PreSend("no attachment".to_owned()))?;
        let (prepared, cmd) = self.authority.prepare_dispatch(&claim, att)?;
        self.pending = Some(prepared);
        Ok(cmd)
    }

    // -- Phase 3: native I/O (no authority guard; caller drives) --

    // No methods — the caller invokes `Controller::dispatch(command.attachment, command.action)`
    // and `Controller::poll_observation(attempt_id)` outside authority.

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
            .conclude_dispatch(&prepared, disposition, observations)
    }

    /// True if a prepared token is pending (between phases 2 and 4).
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
}
