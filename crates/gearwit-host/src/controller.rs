//! In-process semantic controller port for gearwitd.
//!
//! Freezes a platform-neutral Rust trait for the actions `gearwitd` takes
//! when a claimed signal batch is ready. The real controller adapts a
//! provider-native app-server; the fake controller is deterministic for
//! crash/ambiguity tests.
//!
//! # Authority boundary
//!
//! `gearwitd` is the sole registry, policy, lease, claim, lifecycle,
//! persistence, handled-cursor, and re-arm authority. The controller port
//! consumes its contracts; it does not maintain competing state.

use time::OffsetDateTime;

/// Host-minted controller attachment bound to seat, arm, generation,
/// capabilities, and lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerAttachment {
    /// Stable attempt id (minted by gearwitd).
    pub attempt_id: String,
    /// Arm id.
    pub arm_id: String,
    /// Arm generation at claim time.
    pub generation: u64,
    /// Seat token this attempt runs for.
    pub seat_id: String,
    /// Bounded capability route (e.g. `"complete_background_tool"`).
    pub route: String,
    /// Lease end.
    pub lease_until: OffsetDateTime,
}

/// The fixed action: a closed, versioned `handle_claimed_signal`.
///
/// Carries only bounded Gearwit identifiers. The claimed batch is
/// retrieved through the authorized persistence port, not passed
/// here. Provider bodies and ring reason are data — never
/// interpolated as model instructions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalAction {
    /// Claimed signal id.
    pub signal_id: String,
    /// Provider name.
    pub provider: String,
    /// Count of events in the batch.
    pub event_count: usize,
}

/// Result of dispatching a claimed signal to the controller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchDisposition {
    /// Controller accepted the dispatch; carries private provider correlation.
    Accepted {
        /// Opaque provider correlation.
        correlation: String,
    },
    /// Controller rejected the dispatch.
    Rejected,
    /// Outcome is ambiguous — may or may not have reached the provider.
    Ambiguous,
}

/// Correlated lifecycle observation from the controller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleObservation {
    /// Exact turn started (`turn_id`).
    TurnStarted(String),
    /// Exact turn terminal (`turn_id`, completed).
    TurnTerminal(String, bool),
    /// Controller loss — the attempt could not be delivered further.
    ControllerLost,
}

/// In-process controller port.
///
/// # Contract
///
/// - `dispatch` sends the claimed signal to the controller exactly once
///   per attempt and returns the disposition.
/// - `poll_observation` queries for correlated lifecycle observations
///   from a previous dispatch without re-dispatching, keyed by `attempt_id`.
/// - `reconcile` probes the provider after an ambiguous outcome.
/// - No bearer or credential material is exposed through this port.
pub trait Controller {
    /// Dispatch a claimed signal batch. The daemon guarantees that the
    /// claim is durably recorded before calling this.
    fn dispatch(
        &mut self,
        attachment: &ControllerAttachment,
        action: &SignalAction,
    ) -> DispatchDisposition;

    /// Poll for a correlated lifecycle observation from a prior dispatch.
    fn poll_observation(&mut self, attempt_id: &str) -> Option<LifecycleObservation>;

    /// Reconcile after an ambiguous outcome.
    fn reconcile(&self, attempt_id: &str) -> ReconciliationDisposition;
}

/// Disposition of a reconciliation probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationDisposition {
    /// Provider confirmed the request was never accepted.
    ProvenNotAccepted,
    /// Provider confirmed acceptance.
    Accepted,
    /// Provider confirmed terminal state.
    Terminal,
    /// Provider cannot resolve; state remains unknown.
    Unknown,
}

// ---------------------------------------------------------------------------
// Deterministic fake controller for unit tests
// ---------------------------------------------------------------------------

/// A deterministic fake controller that returns scripted outcomes.
#[derive(Clone, Debug)]
pub struct FakeController {
    dispositions: Vec<DispatchDisposition>,
    disp_cursor: usize,
    observations: Vec<Option<LifecycleObservation>>,
    obs_cursor: usize,
    reconcile_disposition: ReconciliationDisposition,
    /// When set, `poll_observation` panics if the `attempt_id` does not match.
    expected_attempt_id: Option<String>,
}

impl FakeController {
    /// Create a fake that returns the given dispositions in order.
    #[must_use]
    pub fn new(dispositions: Vec<DispatchDisposition>) -> Self {
        Self {
            dispositions,
            disp_cursor: 0,
            observations: Vec::new(),
            obs_cursor: 0,
            reconcile_disposition: ReconciliationDisposition::Unknown,
            expected_attempt_id: None,
        }
    }

    /// Set lifecycle observations to return from `poll_observation`.
    #[must_use]
    pub fn with_observations(mut self, observations: Vec<Option<LifecycleObservation>>) -> Self {
        self.observations = observations;
        self
    }

    /// Set the reconciliation disposition.
    #[must_use]
    pub fn with_reconciliation(mut self, d: ReconciliationDisposition) -> Self {
        self.reconcile_disposition = d;
        self
    }

    /// Require `poll_observation` to be called with exactly this `attempt_id`.
    #[must_use]
    pub fn with_expected_attempt_id(mut self, id: &str) -> Self {
        self.expected_attempt_id = Some(id.to_owned());
        self
    }

    /// How many dispatches have been consumed.
    #[must_use]
    pub fn dispatch_count(&self) -> usize {
        self.disp_cursor
    }

    /// How many observation polls have been consumed.
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.obs_cursor
    }
}

impl Controller for FakeController {
    fn dispatch(
        &mut self,
        _attachment: &ControllerAttachment,
        _action: &SignalAction,
    ) -> DispatchDisposition {
        let disposition = self
            .dispositions
            .get(self.disp_cursor)
            .cloned()
            .expect("no scripted dispatch disposition");
        self.disp_cursor += 1;
        disposition
    }

    fn poll_observation(&mut self, attempt_id: &str) -> Option<LifecycleObservation> {
        if let Some(ref expected) = self.expected_attempt_id {
            assert_eq!(
                attempt_id, expected,
                "poll_observation called with mismatched attempt_id"
            );
        }
        let obs = self
            .observations
            .get(self.obs_cursor)
            .cloned()
            .expect("no scripted observation");
        self.obs_cursor += 1;
        obs
    }

    fn reconcile(&self, _attempt_id: &str) -> ReconciliationDisposition {
        self.reconcile_disposition
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_attachment() -> ControllerAttachment {
        ControllerAttachment {
            attempt_id: "01J00000000000000000000099".to_owned(),
            arm_id: "01J00000000000000000000010".to_owned(),
            generation: 1,
            seat_id: "example-devrev".to_owned(),
            route: "complete_background_tool".to_owned(),
            lease_until: time::macros::datetime!(2026-01-15 12:20:00 UTC),
        }
    }

    fn sample_action() -> SignalAction {
        SignalAction {
            signal_id: "01J00000000000000000000021".to_owned(),
            provider: "mattermost".to_owned(),
            event_count: 1,
        }
    }

    #[test]
    fn accepts_then_observes_turn_start_and_terminal() {
        let mut controller = FakeController::new(vec![DispatchDisposition::Accepted {
            correlation: "turn-XYZ".to_owned(),
        }])
        .with_observations(vec![
            Some(LifecycleObservation::TurnStarted("T1".to_owned())),
            Some(LifecycleObservation::TurnTerminal("T1".to_owned(), true)),
            None, // no more observations
        ]);

        let disposition = controller.dispatch(&sample_attachment(), &sample_action());
        assert_eq!(
            disposition,
            DispatchDisposition::Accepted {
                correlation: "turn-XYZ".to_owned(),
            }
        );
        assert_eq!(controller.dispatch_count(), 1);

        let obs = controller.poll_observation("01J00000000000000000000099");
        assert_eq!(
            obs,
            Some(LifecycleObservation::TurnStarted("T1".to_owned()))
        );
        let obs = controller.poll_observation("01J00000000000000000000099");
        assert_eq!(
            obs,
            Some(LifecycleObservation::TurnTerminal("T1".to_owned(), true))
        );
        let obs = controller.poll_observation("01J00000000000000000000099");
        assert_eq!(obs, None);
    }

    #[test]
    fn rejected_dispatch_is_not_consumed_again() {
        let mut controller = FakeController::new(vec![DispatchDisposition::Rejected]);
        let disposition = controller.dispatch(&sample_attachment(), &sample_action());
        assert_eq!(disposition, DispatchDisposition::Rejected);
        assert_eq!(controller.dispatch_count(), 1);
    }

    #[test]
    fn ambiguous_dispatch_then_reconcile() {
        let mut controller = FakeController::new(vec![DispatchDisposition::Ambiguous])
            .with_reconciliation(ReconciliationDisposition::Accepted);
        let disposition = controller.dispatch(&sample_attachment(), &sample_action());
        assert_eq!(disposition, DispatchDisposition::Ambiguous);
        assert_eq!(
            controller.reconcile("01J00000000000000000000099"),
            ReconciliationDisposition::Accepted
        );
    }

    #[test]
    #[should_panic(expected = "no scripted dispatch disposition")]
    fn panics_on_empty_script() {
        let mut controller = FakeController::new(vec![]);
        controller.dispatch(&sample_attachment(), &sample_action());
    }
}
