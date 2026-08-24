//! Platform-free interrupt intent and lifecycle evidence.
//!
//! These types deliberately carry no provider payloads and no wire
//! serialization. A receipt proves exactly one fact. It never promotes a
//! later lifecycle phase by implication.

use std::fmt;
use std::time::Duration;

/// How a matching interrupt should return attention to a seat.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DeliveryRoute {
    /// Complete the harness-owned foreground tool call.
    ReturnForeground,
    /// Complete a harness-owned background tool call.
    CompleteBackgroundTool,
    /// Use an attached controller with current authority.
    ControllerAttached,
    /// Notify an operator without claiming a model turn.
    NotifyOperator,
}

impl DeliveryRoute {
    /// Stable token for CLI and protocol faces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReturnForeground => "return_foreground",
            Self::CompleteBackgroundTool => "complete_background_tool",
            Self::ControllerAttached => "controller_attached",
            Self::NotifyOperator => "notify_operator",
        }
    }
}

impl fmt::Display for DeliveryRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Bounded coverage and waiter deadman policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoveragePolicy {
    coverage: Duration,
    deadman: Duration,
}

impl CoveragePolicy {
    /// Construct a policy with a non-zero deadman no longer than coverage.
    ///
    /// # Errors
    ///
    /// Returns [`CoveragePolicyError`] when either duration is zero or the
    /// deadman exceeds total coverage.
    pub fn try_new(coverage: Duration, deadman: Duration) -> Result<Self, CoveragePolicyError> {
        if coverage.is_zero() {
            return Err(CoveragePolicyError::ZeroCoverage);
        }
        if deadman.is_zero() {
            return Err(CoveragePolicyError::ZeroDeadman);
        }
        if deadman > coverage {
            return Err(CoveragePolicyError::DeadmanExceedsCoverage);
        }
        Ok(Self { coverage, deadman })
    }

    /// Total duration for which the seat intends to remain covered.
    #[must_use]
    pub const fn coverage(self) -> Duration {
        self.coverage
    }

    /// Maximum duration of one waiter interval.
    #[must_use]
    pub const fn deadman(self) -> Duration {
        self.deadman
    }
}

/// Invalid coverage policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoveragePolicyError {
    /// Total coverage was zero.
    ZeroCoverage,
    /// Waiter deadman was zero.
    ZeroDeadman,
    /// One waiter interval was longer than total intended coverage.
    DeadmanExceedsCoverage,
}

impl fmt::Display for CoveragePolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroCoverage => "coverage must be greater than zero",
            Self::ZeroDeadman => "deadman must be greater than zero",
            Self::DeadmanExceedsCoverage => "deadman must not exceed coverage",
        })
    }
}

impl std::error::Error for CoveragePolicyError {}

/// One independently observable interrupt lifecycle phase.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum InterruptPhase {
    /// The wait was admitted and began covering the condition.
    WaitArmed,
    /// A provider event matched the armed condition.
    SignalMatched,
    /// The waiter process returned a terminal result.
    WaiterCompleted,
    /// The harness began a model turn.
    TurnStarted,
    /// The model observed the correlated signal.
    ModelObserved,
    /// The seat acknowledged that it acted on the signal.
    SeatActed,
    /// The seat established successor coverage.
    CoverageRearmed,
    /// Coverage ended without a successor wait in this lifecycle.
    CoverageEnded,
}

impl InterruptPhase {
    /// Stable token for CLI and protocol faces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WaitArmed => "wait_armed",
            Self::SignalMatched => "signal_matched",
            Self::WaiterCompleted => "waiter_completed",
            Self::TurnStarted => "turn_started",
            Self::ModelObserved => "model_observed",
            Self::SeatActed => "seat_acted",
            Self::CoverageRearmed => "coverage_rearmed",
            Self::CoverageEnded => "coverage_ended",
        }
    }
}

impl fmt::Display for InterruptPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Terminal result reported by a waiter that actually started.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WaiterCompletion {
    /// A provider event matched.
    Matched,
    /// The bounded interval ended cleanly without a match.
    DeadmanExpired,
    /// The waiter started but failed.
    Failed,
    /// This waiter was displaced by an authorized successor.
    Replaced,
}

impl WaiterCompletion {
    /// Stable token from the pinned interrupt contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::DeadmanExpired => "deadman_expired",
            Self::Failed => "failed",
            Self::Replaced => "replaced",
        }
    }
}

/// Why intended coverage ended.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CoverageEndReason {
    /// The provider runner never started.
    RunnerNotStarted,
    /// A bounded interval expired and no successor was established.
    DeadmanExpired,
    /// Provider state could not be proven.
    ProviderFailed,
    /// The caller explicitly cancelled coverage.
    Cancelled,
    /// Another generation replaced this coverage.
    Replaced,
}

impl CoverageEndReason {
    /// Stable token from the pinned interrupt contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RunnerNotStarted => "runner_not_started",
            Self::DeadmanExpired => "deadman_expired",
            Self::ProviderFailed => "provider_failed",
            Self::Cancelled => "cancelled",
            Self::Replaced => "replaced",
        }
    }
}

/// Exact fact carried by a lifecycle receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LifecycleFact {
    /// The wait was admitted.
    WaitArmed,
    /// A signal matched.
    SignalMatched,
    /// A waiter that started returned.
    WaiterCompleted(WaiterCompletion),
    /// A harness turn began.
    TurnStarted,
    /// The model observed the correlated signal.
    ModelObserved,
    /// The seat acknowledged action.
    SeatActed,
    /// Successor coverage was established.
    CoverageRearmed,
    /// Coverage ended.
    CoverageEnded(CoverageEndReason),
}

impl LifecycleFact {
    /// Phase proved by this exact fact.
    #[must_use]
    pub const fn phase(self) -> InterruptPhase {
        match self {
            Self::WaitArmed => InterruptPhase::WaitArmed,
            Self::SignalMatched => InterruptPhase::SignalMatched,
            Self::WaiterCompleted(_) => InterruptPhase::WaiterCompleted,
            Self::TurnStarted => InterruptPhase::TurnStarted,
            Self::ModelObserved => InterruptPhase::ModelObserved,
            Self::SeatActed => InterruptPhase::SeatActed,
            Self::CoverageRearmed => InterruptPhase::CoverageRearmed,
            Self::CoverageEnded(_) => InterruptPhase::CoverageEnded,
        }
    }
}

/// Producer that directly observed one lifecycle fact.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReceiptSource {
    /// Gearwit's control-plane state machine.
    ControlPlane,
    /// A provider adapter.
    Provider,
    /// The waiter process that was held by the harness.
    WaiterProcess,
    /// A harness-native lifecycle surface.
    Harness,
    /// A host-minted controller attachment.
    Controller,
    /// The seat's explicit declaration.
    Seat,
    /// A human operator's explicit attestation.
    Operator,
}

impl ReceiptSource {
    /// Stable token from the pinned interrupt contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ControlPlane => "control_plane",
            Self::Provider => "provider",
            Self::WaiterProcess => "waiter_process",
            Self::Harness => "harness",
            Self::Controller => "controller",
            Self::Seat => "seat",
            Self::Operator => "operator",
        }
    }

    const fn supports(self, phase: InterruptPhase) -> bool {
        match self {
            Self::ControlPlane => matches!(
                phase,
                InterruptPhase::WaitArmed
                    | InterruptPhase::SignalMatched
                    | InterruptPhase::WaiterCompleted
                    | InterruptPhase::CoverageRearmed
                    | InterruptPhase::CoverageEnded
            ),
            Self::Provider => matches!(phase, InterruptPhase::SignalMatched),
            Self::WaiterProcess => matches!(
                phase,
                InterruptPhase::WaitArmed
                    | InterruptPhase::WaiterCompleted
                    | InterruptPhase::CoverageRearmed
                    | InterruptPhase::CoverageEnded
            ),
            Self::Harness => matches!(
                phase,
                InterruptPhase::TurnStarted | InterruptPhase::ModelObserved
            ),
            Self::Controller => matches!(
                phase,
                InterruptPhase::TurnStarted | InterruptPhase::ModelObserved
            ),
            Self::Seat => matches!(
                phase,
                InterruptPhase::ModelObserved
                    | InterruptPhase::SeatActed
                    | InterruptPhase::CoverageRearmed
            ),
            Self::Operator => matches!(phase, InterruptPhase::SeatActed),
        }
    }
}

/// One append-only, independently evidenced lifecycle fact.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LifecycleReceipt {
    sequence: u64,
    fact: LifecycleFact,
    source: ReceiptSource,
}

impl LifecycleReceipt {
    /// Construct a receipt only when the source can directly support the fact.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::ZeroSequence`] or
    /// [`ReceiptError::UnsupportedEvidence`].
    pub fn try_new(
        sequence: u64,
        fact: LifecycleFact,
        source: ReceiptSource,
    ) -> Result<Self, ReceiptError> {
        if sequence == 0 {
            return Err(ReceiptError::ZeroSequence);
        }
        if !source.supports(fact.phase()) {
            return Err(ReceiptError::UnsupportedEvidence {
                source,
                phase: fact.phase(),
            });
        }
        Ok(Self {
            sequence,
            fact,
            source,
        })
    }

    /// Monotonic sequence within one interrupt lifecycle.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Exact fact carried by this receipt.
    #[must_use]
    pub const fn fact(self) -> LifecycleFact {
        self.fact
    }

    /// Direct observer supporting this fact.
    #[must_use]
    pub const fn source(self) -> ReceiptSource {
        self.source
    }
}

/// Projection of one lifecycle phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseObservation {
    /// One receipt directly supports this phase.
    Observed {
        /// Exact fact, including any phase-specific outcome.
        fact: LifecycleFact,
        /// Direct observer for the fact.
        source: ReceiptSource,
    },
    /// No receipt supports this phase.
    Unknown,
}

impl PhaseObservation {
    /// Report whether this phase remains unknown.
    #[must_use]
    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// Append-only receipts for one interrupt lifecycle.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReceiptLog {
    receipts: Vec<LifecycleReceipt>,
}

impl ReceiptLog {
    /// Create an empty lifecycle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            receipts: Vec::new(),
        }
    }

    /// Append the next receipt.
    ///
    /// Facts are independent: a later phase may be observed while an earlier
    /// phase remains unknown. Sequence and phase uniqueness still prevent
    /// replay from manufacturing duplicate facts.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::UnexpectedSequence`] for a gap or replay, or
    /// [`ReceiptError::DuplicatePhase`] when this lifecycle already contains
    /// a receipt for the phase.
    pub fn append(&mut self, receipt: LifecycleReceipt) -> Result<(), ReceiptError> {
        let expected = u64::try_from(self.receipts.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if receipt.sequence != expected {
            return Err(ReceiptError::UnexpectedSequence {
                expected,
                actual: receipt.sequence,
            });
        }
        let phase = receipt.fact.phase();
        if self
            .receipts
            .iter()
            .any(|existing| existing.fact.phase() == phase)
        {
            return Err(ReceiptError::DuplicatePhase(phase));
        }
        self.receipts.push(receipt);
        Ok(())
    }

    /// Project one phase without inferring it from neighboring receipts.
    #[must_use]
    pub fn observe(&self, phase: InterruptPhase) -> PhaseObservation {
        self.receipts
            .iter()
            .find(|receipt| receipt.fact.phase() == phase)
            .map_or(PhaseObservation::Unknown, |receipt| {
                PhaseObservation::Observed {
                    fact: receipt.fact,
                    source: receipt.source,
                }
            })
    }

    /// Number of receipts in this lifecycle.
    #[must_use]
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Report whether the lifecycle has no receipts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }
}

/// Invalid receipt or append operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptError {
    /// Receipt sequences start at one.
    ZeroSequence,
    /// The direct observer cannot prove the named phase.
    UnsupportedEvidence {
        /// Proposed observer.
        source: ReceiptSource,
        /// Phase it cannot prove.
        phase: InterruptPhase,
    },
    /// Receipt sequence was not the next expected value.
    UnexpectedSequence {
        /// Next acceptable sequence.
        expected: u64,
        /// Supplied sequence.
        actual: u64,
    },
    /// This lifecycle already has a fact for the phase.
    DuplicatePhase(InterruptPhase),
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSequence => formatter.write_str("receipt sequence must start at one"),
            Self::UnsupportedEvidence { source, phase } => {
                write!(formatter, "{source:?} cannot evidence {phase}")
            }
            Self::UnexpectedSequence { expected, actual } => {
                write!(
                    formatter,
                    "expected receipt sequence {expected}, received {actual}"
                )
            }
            Self::DuplicatePhase(phase) => write!(formatter, "duplicate receipt phase {phase}"),
        }
    }
}

impl std::error::Error for ReceiptError {}

#[cfg(test)]
mod tests {
    use super::{
        CoverageEndReason, CoveragePolicy, CoveragePolicyError, DeliveryRoute, InterruptPhase,
        LifecycleFact, LifecycleReceipt, PhaseObservation, ReceiptError, ReceiptLog, ReceiptSource,
        WaiterCompletion,
    };
    use std::time::Duration;

    fn receipt(sequence: u64, fact: LifecycleFact, source: ReceiptSource) -> LifecycleReceipt {
        LifecycleReceipt::try_new(sequence, fact, source).expect("valid receipt")
    }

    #[test]
    fn coverage_policy_bounds_each_waiter_interval() {
        let policy =
            CoveragePolicy::try_new(Duration::from_secs(60 * 60), Duration::from_secs(10 * 60))
                .expect("one-hour coverage with ten-minute deadman");

        assert_eq!(policy.coverage(), Duration::from_secs(60 * 60));
        assert_eq!(policy.deadman(), Duration::from_secs(10 * 60));
        assert_eq!(
            CoveragePolicy::try_new(Duration::ZERO, Duration::from_secs(1)),
            Err(CoveragePolicyError::ZeroCoverage)
        );
        assert_eq!(
            CoveragePolicy::try_new(Duration::from_secs(1), Duration::ZERO),
            Err(CoveragePolicyError::ZeroDeadman)
        );
        assert_eq!(
            CoveragePolicy::try_new(Duration::from_secs(1), Duration::from_secs(2)),
            Err(CoveragePolicyError::DeadmanExceedsCoverage)
        );
    }

    #[test]
    fn stable_route_and_phase_tokens_match_product_language() {
        assert_eq!(
            DeliveryRoute::ReturnForeground.as_str(),
            "return_foreground"
        );
        assert_eq!(
            DeliveryRoute::CompleteBackgroundTool.as_str(),
            "complete_background_tool"
        );
        assert_eq!(
            DeliveryRoute::ControllerAttached.as_str(),
            "controller_attached"
        );
        assert_eq!(DeliveryRoute::NotifyOperator.as_str(), "notify_operator");
        assert_eq!(InterruptPhase::SignalMatched.as_str(), "signal_matched");
        assert_eq!(InterruptPhase::SeatActed.as_str(), "seat_acted");
        assert_eq!(WaiterCompletion::DeadmanExpired.as_str(), "deadman_expired");
        assert_eq!(
            CoverageEndReason::RunnerNotStarted.as_str(),
            "runner_not_started"
        );
        assert_eq!(ReceiptSource::WaiterProcess.as_str(), "waiter_process");
    }

    #[test]
    fn waiter_completion_does_not_promote_a_model_turn() {
        let mut log = ReceiptLog::new();
        log.append(receipt(
            1,
            LifecycleFact::WaitArmed,
            ReceiptSource::WaiterProcess,
        ))
        .expect("arm");
        log.append(receipt(
            2,
            LifecycleFact::SignalMatched,
            ReceiptSource::Provider,
        ))
        .expect("match");
        log.append(receipt(
            3,
            LifecycleFact::WaiterCompleted(WaiterCompletion::Matched),
            ReceiptSource::WaiterProcess,
        ))
        .expect("wait completion");

        assert!(log.observe(InterruptPhase::TurnStarted).is_unknown());
        assert!(log.observe(InterruptPhase::ModelObserved).is_unknown());
        assert!(log.observe(InterruptPhase::SeatActed).is_unknown());
    }

    #[test]
    fn waiter_process_cannot_claim_turn_started() {
        assert_eq!(
            LifecycleReceipt::try_new(1, LifecycleFact::TurnStarted, ReceiptSource::WaiterProcess,),
            Err(ReceiptError::UnsupportedEvidence {
                source: ReceiptSource::WaiterProcess,
                phase: InterruptPhase::TurnStarted,
            })
        );
    }

    #[test]
    fn runner_not_started_never_becomes_waiter_completed() {
        let mut log = ReceiptLog::new();
        log.append(receipt(
            1,
            LifecycleFact::CoverageEnded(CoverageEndReason::RunnerNotStarted),
            ReceiptSource::ControlPlane,
        ))
        .expect("failed coverage");

        assert!(log.observe(InterruptPhase::WaiterCompleted).is_unknown());
        assert_eq!(
            log.observe(InterruptPhase::CoverageEnded),
            PhaseObservation::Observed {
                fact: LifecycleFact::CoverageEnded(CoverageEndReason::RunnerNotStarted),
                source: ReceiptSource::ControlPlane,
            }
        );
    }

    #[test]
    fn deadman_completion_is_not_a_matched_signal() {
        let mut log = ReceiptLog::new();
        log.append(receipt(
            1,
            LifecycleFact::WaitArmed,
            ReceiptSource::WaiterProcess,
        ))
        .expect("arm");
        log.append(receipt(
            2,
            LifecycleFact::WaiterCompleted(WaiterCompletion::DeadmanExpired),
            ReceiptSource::WaiterProcess,
        ))
        .expect("deadman completion");
        log.append(receipt(
            3,
            LifecycleFact::CoverageEnded(CoverageEndReason::DeadmanExpired),
            ReceiptSource::WaiterProcess,
        ))
        .expect("coverage end");

        assert!(log.observe(InterruptPhase::SignalMatched).is_unknown());
        assert!(log.observe(InterruptPhase::TurnStarted).is_unknown());
    }

    #[test]
    fn observed_later_phase_does_not_invent_unknown_predecessors() {
        let mut log = ReceiptLog::new();
        log.append(receipt(1, LifecycleFact::SeatActed, ReceiptSource::Seat))
            .expect("seat acknowledgement");

        assert_eq!(
            log.observe(InterruptPhase::SeatActed),
            PhaseObservation::Observed {
                fact: LifecycleFact::SeatActed,
                source: ReceiptSource::Seat,
            }
        );
        assert!(log.observe(InterruptPhase::TurnStarted).is_unknown());
        assert!(log.observe(InterruptPhase::ModelObserved).is_unknown());
    }

    #[test]
    fn log_rejects_sequence_gaps_and_duplicate_phase_replay() {
        let mut log = ReceiptLog::new();
        assert_eq!(
            log.append(receipt(
                2,
                LifecycleFact::WaitArmed,
                ReceiptSource::ControlPlane,
            )),
            Err(ReceiptError::UnexpectedSequence {
                expected: 1,
                actual: 2,
            })
        );

        log.append(receipt(
            1,
            LifecycleFact::WaitArmed,
            ReceiptSource::ControlPlane,
        ))
        .expect("first arm");
        assert_eq!(
            log.append(receipt(
                2,
                LifecycleFact::WaitArmed,
                ReceiptSource::WaiterProcess,
            )),
            Err(ReceiptError::DuplicatePhase(InterruptPhase::WaitArmed))
        );
    }
}
