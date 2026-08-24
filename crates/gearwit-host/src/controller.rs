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
//!
//! # Sealing
//!
//! Every surface the caller handles between authority phases is sealed:
//! attachment, action, and command carry no public constructible or mutable
//! fields and cannot be cloned. The command is consumed by the native-I/O
//! adapter exactly once.

use time::OffsetDateTime;

/// Closed capability set for controller grants.
///
/// The managed-turn-start capability is the only closed value in Gate 1.
/// Route strings are mapped into this set through [`ManagedCapability::parse`];
/// anything else fails closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ManagedCapability {
    /// Start an exact managed model turn for a claimed Gearwit signal.
    ManagedTurnStart,
}

impl ManagedCapability {
    /// Canonical provider route spelling for the managed-turn capability.
    pub const MANAGED_TURN_START_ROUTE: &'static str = "complete_background_tool";

    /// Parse a provider route name into the closed capability set.
    #[must_use]
    pub fn parse(route: &str) -> Option<Self> {
        match route {
            Self::MANAGED_TURN_START_ROUTE | "managed_turn_start" => Some(Self::ManagedTurnStart),
            _ => None,
        }
    }

    /// The canonical route spelling for this capability.
    #[must_use]
    pub fn as_route(self) -> &'static str {
        match self {
            Self::ManagedTurnStart => Self::MANAGED_TURN_START_ROUTE,
        }
    }
}

/// Host-minted controller attachment bound to seat, arm, generation,
/// capability, and lease.
///
/// Sealed: fields are private and this type is not `Clone`. Only the daemon
/// authority mints attachment instances; the controller port can only read
/// dimensions through accessors.
#[derive(Debug, Eq, PartialEq)]
pub struct ControllerAttachment {
    /// Stable attempt id (minted by gearwitd).
    attempt_id: String,
    /// Arm id.
    arm_id: String,
    /// Arm generation at claim time.
    generation: u64,
    /// Seat token this attempt runs for.
    seat_id: String,
    /// Bounded capability route.
    route: String,
    /// Closed capability granted by this attachment.
    capability: ManagedCapability,
    /// Lease end.
    lease_until: OffsetDateTime,
}

impl ControllerAttachment {
    /// Authority-only construction.
    pub(crate) fn new(
        attempt_id: String,
        arm_id: String,
        generation: u64,
        seat_id: String,
        route: String,
        capability: ManagedCapability,
        lease_until: OffsetDateTime,
    ) -> Self {
        Self {
            attempt_id,
            arm_id,
            generation,
            seat_id,
            route,
            capability,
            lease_until,
        }
    }

    /// The attempt id.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// The arm id.
    #[must_use]
    pub fn arm_id(&self) -> &str {
        &self.arm_id
    }

    /// The arm generation at claim time.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The seat token.
    #[must_use]
    pub fn seat_id(&self) -> &str {
        &self.seat_id
    }

    /// The bounded capability route.
    #[must_use]
    pub fn route(&self) -> &str {
        &self.route
    }

    /// The closed capability granted.
    #[must_use]
    pub fn capability(&self) -> ManagedCapability {
        self.capability
    }

    /// The lease end.
    #[must_use]
    pub fn lease_until(&self) -> OffsetDateTime {
        self.lease_until
    }
}

/// Authority-produced bounded controller work for phase 2.
///
/// The only handle the caller receives for the native-I/O phase. Sealed: all
/// fields are private, there is no `Clone`, and the command is single-use —
/// [`ControllerCommand::dispatch`] consumes it. Read dimensions only through
/// accessors, before dispatch.
#[derive(Debug, Eq, PartialEq)]
pub struct ControllerCommand {
    /// Authority-minted attachment for the controller.
    attachment: ControllerAttachment,
    /// Bounded signal action for dispatch.
    action: SignalAction,
    /// Opaque `attempt_id` for phase 3 correlation.
    attempt_id: String,
}

impl ControllerCommand {
    /// Authority-only construction.
    pub(crate) fn new(
        attachment: ControllerAttachment,
        action: SignalAction,
        attempt_id: String,
    ) -> Self {
        Self {
            attachment,
            action,
            attempt_id,
        }
    }

    /// Read-only attachment reference.
    #[must_use]
    pub fn attachment(&self) -> &ControllerAttachment {
        &self.attachment
    }

    /// Read-only action reference.
    #[must_use]
    pub fn action(&self) -> &SignalAction {
        &self.action
    }

    /// The opaque `attempt_id`, for phase 3 observation correlation.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Consume this command and perform the native dispatch exactly once.
    ///
    /// After this call the command is gone — a duplicate dispatch cannot be
    /// assembled from the same command.
    pub fn dispatch(self, controller: &mut dyn Controller) -> DispatchDisposition {
        controller.dispatch(&self.attachment, &self.action)
    }
}

/// The fixed action: a closed, versioned `handle_claimed_signal`.
///
/// Carries only bounded Gearwit identifiers. The claimed batch is
/// retrieved through the authorized persistence port, not passed
/// here. Provider bodies and ring reason are data — never
/// interpolated as model instructions.
///
/// Sealed: fields are private; only the daemon authority produces actions.
#[derive(Debug, Eq, PartialEq)]
pub struct SignalAction {
    /// Claimed signal id.
    signal_id: String,
    /// Provider name.
    provider: String,
    /// Count of events in the batch.
    event_count: usize,
}

impl SignalAction {
    /// Authority-only construction.
    pub(crate) fn new(signal_id: String, provider: String, event_count: usize) -> Self {
        Self {
            signal_id,
            provider,
            event_count,
        }
    }

    /// The claimed signal id.
    #[must_use]
    pub fn signal_id(&self) -> &str {
        &self.signal_id
    }

    /// The provider name.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// The event count.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.event_count
    }
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
        ControllerAttachment::new(
            "01J00000000000000000000099".to_owned(),
            "01J00000000000000000000010".to_owned(),
            1,
            "example-devrev".to_owned(),
            ManagedCapability::MANAGED_TURN_START_ROUTE.to_owned(),
            ManagedCapability::ManagedTurnStart,
            time::macros::datetime!(2026-01-15 12:20:00 UTC),
        )
    }

    fn sample_action() -> SignalAction {
        SignalAction::new(
            "01J00000000000000000000021".to_owned(),
            "mattermost".to_owned(),
            1,
        )
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
        controller.dispatch(
            &ControllerAttachment::new(
                "01J00000000000000000000099".to_owned(),
                "01J00000000000000000000010".to_owned(),
                1,
                "example-devrev".to_owned(),
                ManagedCapability::MANAGED_TURN_START_ROUTE.to_owned(),
                ManagedCapability::ManagedTurnStart,
                time::macros::datetime!(2026-01-15 12:20:00 UTC),
            ),
            &SignalAction::new(
                "01J00000000000000000000021".to_owned(),
                "mattermost".to_owned(),
                1,
            ),
        );

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
    fn command_dispatch_is_single_use() {
        // The command is consumed by dispatch: constructing the same fake
        // dispatch outcome twice is impossible without a second command, and
        // commands are not Clone (compile-time property).
        let mut controller = FakeController::new(vec![
            DispatchDisposition::Accepted {
                correlation: "turn-XYZ".to_owned(),
            },
            DispatchDisposition::Rejected,
        ]);
        let cmd = ControllerCommand::new(
            sample_attachment(),
            sample_action(),
            "01J00000000000000000000099".to_owned(),
        );
        assert_eq!(cmd.attempt_id(), "01J00000000000000000000099");
        let disposition = cmd.dispatch(&mut controller);
        assert_eq!(
            disposition,
            DispatchDisposition::Accepted {
                correlation: "turn-XYZ".to_owned(),
            }
        );
        assert_eq!(controller.dispatch_count(), 1);
    }

    #[test]
    fn rejected_dispatch_is_not_consumed_again() {
        let mut controller = FakeController::new(vec![DispatchDisposition::Rejected]);
        let cmd = ControllerCommand::new(
            sample_attachment(),
            sample_action(),
            "01J00000000000000000000099".to_owned(),
        );
        let disposition = cmd.dispatch(&mut controller);
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
    fn capability_set_is_closed() {
        assert_eq!(
            ManagedCapability::parse("complete_background_tool"),
            Some(ManagedCapability::ManagedTurnStart)
        );
        assert_eq!(
            ManagedCapability::parse("managed_turn_start"),
            Some(ManagedCapability::ManagedTurnStart)
        );
        assert_eq!(ManagedCapability::parse("not_a_capability"), None);
        assert_eq!(
            ManagedCapability::ManagedTurnStart.as_route(),
            "complete_background_tool"
        );
    }

    #[test]
    #[should_panic(expected = "no scripted dispatch disposition")]
    fn panics_on_empty_script() {
        let mut controller = FakeController::new(vec![]);
        let cmd = ControllerCommand::new(
            sample_attachment(),
            sample_action(),
            "01J00000000000000000000099".to_owned(),
        );
        let _ = cmd.dispatch(&mut controller);
    }
}
