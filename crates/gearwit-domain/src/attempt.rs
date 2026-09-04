//! Managed doorbell attempt evidence.
//!
//! A trace records only public-safe attempt phases and direct observer classes.
//! It deliberately carries no provider body, native session id, controller proof,
//! lease material, or filesystem location. Callers must bind all receipts to one
//! durable attempt before appending; this projection validates only the safe
//! phase/source vocabulary and doorbell partial order.

use std::fmt;

/// One independently recorded phase in a managed doorbell attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DoorbellAttemptPhase {
    /// An external signal was observed by a provider or local control face.
    Observed,
    /// Matching provider events were drained into a bounded batch.
    Drained,
    /// The batch was durably claimed before any native dispatch.
    DurableClaimed,
    /// Gearwit prepared one managed dispatch for the claimed batch.
    DispatchPrepared,
    /// The native harness accepted the write attempt.
    NativeAccepted,
    /// The exact correlated native turn started.
    ExactTurnStarted,
    /// The managed helper retrieved the already-claimed batch.
    ClaimedBatchRetrieved,
    /// The managed helper acknowledged the handled batch.
    HandledAcknowledged,
    /// The newest fully handled provider cursor was recorded durably.
    HandledCursorRecorded,
    /// The exact correlated native turn reached a recognized terminal fact.
    ExactTerminalObserved,
    /// The seat produced direct action evidence for the handled batch.
    SeatActed,
    /// Successor coverage was armed after terminal and handled evidence.
    CoverageRearmed,
}

impl DoorbellAttemptPhase {
    /// Stable public token used by tests, fixtures, and projections.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Drained => "drained",
            Self::DurableClaimed => "durable_claimed",
            Self::DispatchPrepared => "dispatch_prepared",
            Self::NativeAccepted => "native_accepted",
            Self::ExactTurnStarted => "exact_turn_started",
            Self::ClaimedBatchRetrieved => "claimed_batch_retrieved",
            Self::HandledAcknowledged => "handled_acknowledged",
            Self::HandledCursorRecorded => "handled_cursor_recorded",
            Self::ExactTerminalObserved => "exact_terminal_observed",
            Self::SeatActed => "seat_acted",
            Self::CoverageRearmed => "coverage_rearmed",
        }
    }

    const fn prerequisites(self) -> &'static [Self] {
        match self {
            Self::Observed => &[],
            Self::Drained => &[Self::Observed],
            Self::DurableClaimed => &[Self::Drained],
            Self::DispatchPrepared => &[Self::DurableClaimed],
            Self::NativeAccepted => &[Self::DispatchPrepared],
            Self::ExactTurnStarted => &[Self::NativeAccepted],
            Self::ClaimedBatchRetrieved | Self::ExactTerminalObserved => &[Self::ExactTurnStarted],
            Self::HandledAcknowledged => &[Self::ClaimedBatchRetrieved],
            Self::HandledCursorRecorded => &[Self::HandledAcknowledged],
            Self::SeatActed => &[Self::HandledCursorRecorded],
            Self::CoverageRearmed => &[Self::HandledCursorRecorded, Self::ExactTerminalObserved],
        }
    }
}

impl fmt::Display for DoorbellAttemptPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Producer class that directly observed one doorbell attempt phase.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DoorbellAttemptSource {
    /// Gearwit's local authority process.
    ControlPlane,
    /// A provider adapter or provider-facing face.
    Provider,
    /// Gearwit's native controller adapter.
    Controller,
    /// A narrow helper bound to one already-claimed batch.
    ClaimedBatchHelper,
    /// The managed seat's explicit acknowledgement.
    Seat,
}

impl DoorbellAttemptSource {
    /// Stable public token used by tests, fixtures, and projections.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ControlPlane => "control_plane",
            Self::Provider => "provider",
            Self::Controller => "controller",
            Self::ClaimedBatchHelper => "claimed_batch_helper",
            Self::Seat => "seat",
        }
    }

    const fn supports(self, phase: DoorbellAttemptPhase) -> bool {
        match self {
            Self::ControlPlane => matches!(
                phase,
                DoorbellAttemptPhase::Observed
                    | DoorbellAttemptPhase::Drained
                    | DoorbellAttemptPhase::DurableClaimed
                    | DoorbellAttemptPhase::DispatchPrepared
                    | DoorbellAttemptPhase::HandledCursorRecorded
                    | DoorbellAttemptPhase::CoverageRearmed
            ),
            Self::Provider => matches!(
                phase,
                DoorbellAttemptPhase::Observed | DoorbellAttemptPhase::Drained
            ),
            Self::Controller => matches!(
                phase,
                DoorbellAttemptPhase::NativeAccepted
                    | DoorbellAttemptPhase::ExactTurnStarted
                    | DoorbellAttemptPhase::ExactTerminalObserved
            ),
            Self::ClaimedBatchHelper => matches!(
                phase,
                DoorbellAttemptPhase::ClaimedBatchRetrieved
                    | DoorbellAttemptPhase::HandledAcknowledged
            ),
            Self::Seat => matches!(phase, DoorbellAttemptPhase::SeatActed),
        }
    }
}

impl fmt::Display for DoorbellAttemptSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One append-only doorbell attempt receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DoorbellAttemptReceipt {
    sequence: u64,
    phase: DoorbellAttemptPhase,
    source: DoorbellAttemptSource,
}

impl DoorbellAttemptReceipt {
    /// Construct a receipt when the source can directly support the phase.
    ///
    /// # Errors
    ///
    /// Returns [`DoorbellAttemptError::ZeroSequence`] or
    /// [`DoorbellAttemptError::UnsupportedEvidence`].
    pub fn try_new(
        sequence: u64,
        phase: DoorbellAttemptPhase,
        source: DoorbellAttemptSource,
    ) -> Result<Self, DoorbellAttemptError> {
        if sequence == 0 {
            return Err(DoorbellAttemptError::ZeroSequence);
        }
        if !source.supports(phase) {
            return Err(DoorbellAttemptError::UnsupportedEvidence { source, phase });
        }
        Ok(Self {
            sequence,
            phase,
            source,
        })
    }

    /// Monotonic sequence within one managed attempt.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Phase carried by this receipt.
    #[must_use]
    pub const fn phase(self) -> DoorbellAttemptPhase {
        self.phase
    }

    /// Direct observer supporting this phase.
    #[must_use]
    pub const fn source(self) -> DoorbellAttemptSource {
        self.source
    }
}

/// Observation for one doorbell attempt phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoorbellAttemptObservation {
    /// One receipt directly supports this phase.
    Observed {
        /// Direct observer for this phase.
        source: DoorbellAttemptSource,
    },
    /// No receipt directly supports this phase.
    Unknown,
}

impl DoorbellAttemptObservation {
    /// Report whether this phase remains unknown.
    #[must_use]
    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// Append-only, public-safe receipts for one already-correlated attempt.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DoorbellAttemptTrace {
    receipts: Vec<DoorbellAttemptReceipt>,
}

impl DoorbellAttemptTrace {
    /// Create an empty attempt trace.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            receipts: Vec::new(),
        }
    }

    /// Append the next receipt when it preserves the managed doorbell partial order.
    ///
    /// # Errors
    ///
    /// Returns [`DoorbellAttemptError`] for sequence gaps, duplicate phases, or
    /// missing prerequisite evidence.
    pub fn append(&mut self, receipt: DoorbellAttemptReceipt) -> Result<(), DoorbellAttemptError> {
        let expected = u64::try_from(self.receipts.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if receipt.sequence != expected {
            return Err(DoorbellAttemptError::UnexpectedSequence {
                expected,
                actual: receipt.sequence,
            });
        }
        if self.contains(receipt.phase) {
            return Err(DoorbellAttemptError::DuplicatePhase(receipt.phase));
        }
        if let Some(missing) = receipt
            .phase
            .prerequisites()
            .iter()
            .copied()
            .find(|phase| !self.contains(*phase))
        {
            return Err(DoorbellAttemptError::MissingPrerequisite {
                phase: receipt.phase,
                prerequisite: missing,
            });
        }
        self.receipts.push(receipt);
        Ok(())
    }

    /// Project one phase without exposing any private identifiers or payload.
    #[must_use]
    pub fn observe(&self, phase: DoorbellAttemptPhase) -> DoorbellAttemptObservation {
        self.receipts
            .iter()
            .find(|receipt| receipt.phase == phase)
            .map_or(DoorbellAttemptObservation::Unknown, |receipt| {
                DoorbellAttemptObservation::Observed {
                    source: receipt.source,
                }
            })
    }

    /// Return the public-safe receipts in append order.
    #[must_use]
    pub fn receipts(&self) -> &[DoorbellAttemptReceipt] {
        &self.receipts
    }

    /// Report whether the trace has no receipts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    fn contains(&self, phase: DoorbellAttemptPhase) -> bool {
        self.receipts.iter().any(|receipt| receipt.phase == phase)
    }
}

/// Managed doorbell phases in one canonical fixture order.
pub const MANAGED_DOORBELL_PHASES: [DoorbellAttemptPhase; 12] = [
    DoorbellAttemptPhase::Observed,
    DoorbellAttemptPhase::Drained,
    DoorbellAttemptPhase::DurableClaimed,
    DoorbellAttemptPhase::DispatchPrepared,
    DoorbellAttemptPhase::NativeAccepted,
    DoorbellAttemptPhase::ExactTurnStarted,
    DoorbellAttemptPhase::ClaimedBatchRetrieved,
    DoorbellAttemptPhase::HandledAcknowledged,
    DoorbellAttemptPhase::HandledCursorRecorded,
    DoorbellAttemptPhase::ExactTerminalObserved,
    DoorbellAttemptPhase::SeatActed,
    DoorbellAttemptPhase::CoverageRearmed,
];

/// Public-safe phase/source pairs for one managed doorbell proof fixture.
pub const MANAGED_DOORBELL_PROOF_STEPS: [(DoorbellAttemptPhase, DoorbellAttemptSource); 12] = [
    (
        DoorbellAttemptPhase::Observed,
        DoorbellAttemptSource::Provider,
    ),
    (
        DoorbellAttemptPhase::Drained,
        DoorbellAttemptSource::Provider,
    ),
    (
        DoorbellAttemptPhase::DurableClaimed,
        DoorbellAttemptSource::ControlPlane,
    ),
    (
        DoorbellAttemptPhase::DispatchPrepared,
        DoorbellAttemptSource::ControlPlane,
    ),
    (
        DoorbellAttemptPhase::NativeAccepted,
        DoorbellAttemptSource::Controller,
    ),
    (
        DoorbellAttemptPhase::ExactTurnStarted,
        DoorbellAttemptSource::Controller,
    ),
    (
        DoorbellAttemptPhase::ClaimedBatchRetrieved,
        DoorbellAttemptSource::ClaimedBatchHelper,
    ),
    (
        DoorbellAttemptPhase::HandledAcknowledged,
        DoorbellAttemptSource::ClaimedBatchHelper,
    ),
    (
        DoorbellAttemptPhase::HandledCursorRecorded,
        DoorbellAttemptSource::ControlPlane,
    ),
    (
        DoorbellAttemptPhase::ExactTerminalObserved,
        DoorbellAttemptSource::Controller,
    ),
    (DoorbellAttemptPhase::SeatActed, DoorbellAttemptSource::Seat),
    (
        DoorbellAttemptPhase::CoverageRearmed,
        DoorbellAttemptSource::ControlPlane,
    ),
];

/// Invalid managed doorbell attempt receipt or append operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoorbellAttemptError {
    /// Receipt sequences start at one.
    ZeroSequence,
    /// The direct observer cannot prove the named phase.
    UnsupportedEvidence {
        /// Proposed observer.
        source: DoorbellAttemptSource,
        /// Phase it cannot prove.
        phase: DoorbellAttemptPhase,
    },
    /// Receipt sequence was not the next expected value.
    UnexpectedSequence {
        /// Next acceptable sequence.
        expected: u64,
        /// Supplied sequence.
        actual: u64,
    },
    /// This trace already has a receipt for the phase.
    DuplicatePhase(DoorbellAttemptPhase),
    /// A strict doorbell proof prerequisite is not yet observed.
    MissingPrerequisite {
        /// Phase being appended.
        phase: DoorbellAttemptPhase,
        /// Required earlier phase.
        prerequisite: DoorbellAttemptPhase,
    },
}

impl fmt::Display for DoorbellAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSequence => formatter.write_str("attempt receipt sequence must start at one"),
            Self::UnsupportedEvidence { source, phase } => {
                write!(formatter, "{source} cannot evidence {phase}")
            }
            Self::UnexpectedSequence { expected, actual } => {
                write!(
                    formatter,
                    "expected attempt receipt sequence {expected}, received {actual}"
                )
            }
            Self::DuplicatePhase(phase) => write!(formatter, "duplicate attempt phase {phase}"),
            Self::MissingPrerequisite {
                phase,
                prerequisite,
            } => write!(formatter, "{phase} requires prior {prerequisite}"),
        }
    }
}

impl std::error::Error for DoorbellAttemptError {}

#[cfg(test)]
mod tests {
    use super::{
        DoorbellAttemptError, DoorbellAttemptObservation, DoorbellAttemptPhase,
        DoorbellAttemptReceipt, DoorbellAttemptSource, DoorbellAttemptTrace,
        MANAGED_DOORBELL_PHASES, MANAGED_DOORBELL_PROOF_STEPS,
    };

    fn receipt(
        sequence: u64,
        phase: DoorbellAttemptPhase,
        source: DoorbellAttemptSource,
    ) -> DoorbellAttemptReceipt {
        DoorbellAttemptReceipt::try_new(sequence, phase, source).expect("valid receipt")
    }

    #[test]
    fn stable_tokens_are_public_safe() {
        assert_eq!(
            DoorbellAttemptPhase::DurableClaimed.as_str(),
            "durable_claimed"
        );
        assert_eq!(
            DoorbellAttemptPhase::ExactTurnStarted.as_str(),
            "exact_turn_started"
        );
        assert_eq!(DoorbellAttemptPhase::SeatActed.as_str(), "seat_acted");
        assert_eq!(
            DoorbellAttemptSource::ClaimedBatchHelper.as_str(),
            "claimed_batch_helper"
        );
    }

    #[test]
    fn canonical_fixture_covers_the_managed_doorbell_proof_order() {
        let mut trace = DoorbellAttemptTrace::new();
        assert_eq!(
            MANAGED_DOORBELL_PROOF_STEPS.len(),
            MANAGED_DOORBELL_PHASES.len()
        );
        for (index, (phase, source)) in MANAGED_DOORBELL_PROOF_STEPS.iter().copied().enumerate() {
            assert_eq!(phase, MANAGED_DOORBELL_PHASES[index]);
            trace
                .append(receipt(
                    u64::try_from(index + 1).expect("sequence fits"),
                    phase,
                    source,
                ))
                .expect("canonical phase appends");
        }

        assert_eq!(trace.receipts().len(), MANAGED_DOORBELL_PHASES.len());
        assert_eq!(
            trace.observe(DoorbellAttemptPhase::SeatActed),
            DoorbellAttemptObservation::Observed {
                source: DoorbellAttemptSource::Seat,
            }
        );
        assert_eq!(
            trace.observe(DoorbellAttemptPhase::CoverageRearmed),
            DoorbellAttemptObservation::Observed {
                source: DoorbellAttemptSource::ControlPlane,
            }
        );
    }

    #[test]
    fn terminal_and_helper_branches_may_arrive_in_either_order() {
        let mut trace = DoorbellAttemptTrace::new();
        for (index, (phase, source)) in MANAGED_DOORBELL_PROOF_STEPS[..6]
            .iter()
            .copied()
            .enumerate()
        {
            trace
                .append(receipt(
                    u64::try_from(index + 1).expect("sequence fits"),
                    phase,
                    source,
                ))
                .expect("pre-branch phase appends");
        }

        trace
            .append(receipt(
                7,
                DoorbellAttemptPhase::ExactTerminalObserved,
                DoorbellAttemptSource::Controller,
            ))
            .expect("terminal may precede helper retrieval");
        trace
            .append(receipt(
                8,
                DoorbellAttemptPhase::ClaimedBatchRetrieved,
                DoorbellAttemptSource::ClaimedBatchHelper,
            ))
            .expect("helper retrieval remains valid after terminal");
    }

    #[test]
    fn native_acceptance_cannot_skip_the_durable_claim() {
        let mut trace = DoorbellAttemptTrace::new();
        trace
            .append(receipt(
                1,
                DoorbellAttemptPhase::Observed,
                DoorbellAttemptSource::Provider,
            ))
            .expect("observed");
        trace
            .append(receipt(
                2,
                DoorbellAttemptPhase::Drained,
                DoorbellAttemptSource::Provider,
            ))
            .expect("drained");

        assert_eq!(
            trace.append(receipt(
                3,
                DoorbellAttemptPhase::NativeAccepted,
                DoorbellAttemptSource::Controller,
            )),
            Err(DoorbellAttemptError::MissingPrerequisite {
                phase: DoorbellAttemptPhase::NativeAccepted,
                prerequisite: DoorbellAttemptPhase::DispatchPrepared,
            })
        );
        assert!(
            trace
                .observe(DoorbellAttemptPhase::NativeAccepted)
                .is_unknown()
        );
    }

    #[test]
    fn rearm_requires_handled_cursor_and_exact_terminal() {
        let mut trace = DoorbellAttemptTrace::new();
        for (index, (phase, source)) in MANAGED_DOORBELL_PROOF_STEPS[..9]
            .iter()
            .copied()
            .enumerate()
        {
            trace
                .append(receipt(
                    u64::try_from(index + 1).expect("sequence fits"),
                    phase,
                    source,
                ))
                .expect("pre-terminal phase appends");
        }

        assert_eq!(
            trace.append(receipt(
                10,
                DoorbellAttemptPhase::CoverageRearmed,
                DoorbellAttemptSource::ControlPlane,
            )),
            Err(DoorbellAttemptError::MissingPrerequisite {
                phase: DoorbellAttemptPhase::CoverageRearmed,
                prerequisite: DoorbellAttemptPhase::ExactTerminalObserved,
            })
        );
        assert!(
            trace
                .observe(DoorbellAttemptPhase::CoverageRearmed)
                .is_unknown()
        );
    }

    #[test]
    fn unsupported_sources_cannot_claim_stronger_evidence() {
        assert_eq!(
            DoorbellAttemptReceipt::try_new(
                1,
                DoorbellAttemptPhase::ExactTurnStarted,
                DoorbellAttemptSource::Provider,
            ),
            Err(DoorbellAttemptError::UnsupportedEvidence {
                source: DoorbellAttemptSource::Provider,
                phase: DoorbellAttemptPhase::ExactTurnStarted,
            })
        );
        assert_eq!(
            DoorbellAttemptReceipt::try_new(
                1,
                DoorbellAttemptPhase::SeatActed,
                DoorbellAttemptSource::ControlPlane,
            ),
            Err(DoorbellAttemptError::UnsupportedEvidence {
                source: DoorbellAttemptSource::ControlPlane,
                phase: DoorbellAttemptPhase::SeatActed,
            })
        );
    }

    #[test]
    fn replay_and_sequence_gaps_are_rejected() {
        let mut trace = DoorbellAttemptTrace::new();
        assert_eq!(
            trace.append(receipt(
                2,
                DoorbellAttemptPhase::Observed,
                DoorbellAttemptSource::Provider,
            )),
            Err(DoorbellAttemptError::UnexpectedSequence {
                expected: 1,
                actual: 2,
            })
        );

        trace
            .append(receipt(
                1,
                DoorbellAttemptPhase::Observed,
                DoorbellAttemptSource::Provider,
            ))
            .expect("first observation");
        assert_eq!(
            trace.append(receipt(
                2,
                DoorbellAttemptPhase::Observed,
                DoorbellAttemptSource::ControlPlane,
            )),
            Err(DoorbellAttemptError::DuplicatePhase(
                DoorbellAttemptPhase::Observed,
            ))
        );
    }
}
