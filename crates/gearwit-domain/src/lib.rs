//! Platform-free Gearwit domain primitives.
//!
//! Wire serialization belongs in schema-backed protocol bindings. This crate
//! deliberately exposes no provider, storage, process, or transport types.

#![forbid(unsafe_code)]

use std::fmt;

/// The evidence supporting a known observation.
///
/// This is a classification, not a numeric confidence score. Callers must not
/// promote one field because another field on the same seat has stronger
/// evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EvidenceClass {
    /// A live controller binding and lease prove the observation.
    ControllerProven,
    /// The seat explicitly declared the observation.
    SelfDeclared,
    /// Host census or another indirect source inferred the observation.
    CensusInferred,
}

impl EvidenceClass {
    /// Stable token used by CLI and console faces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ControllerProven => "controller_proven",
            Self::SelfDeclared => "self_declared",
            Self::CensusInferred => "census_inferred",
        }
    }
}

impl fmt::Display for EvidenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a wait completion can reach the intended seat.
///
/// Presence is not authority. A harness identity does not imply a class.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Reachability {
    /// An in-turn blocking wait will return into the current inference.
    HeldForeground,
    /// Completing a harness-owned background tool starts a new turn.
    CompletionDoorbell,
    /// A host-minted controller can submit a native prompt.
    NativeInjectable,
    /// Only an operator (or out-of-band human) can continue the seat.
    OperatorOnly,
    /// No supported path exists for this binding.
    Unreachable,
}

impl Reachability {
    /// Stable token used by CLI and console faces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HeldForeground => "held_foreground",
            Self::CompletionDoorbell => "completion_doorbell",
            Self::NativeInjectable => "native_injectable",
            Self::OperatorOnly => "operator_only",
            Self::Unreachable => "unreachable",
        }
    }
}

impl fmt::Display for Reachability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Planned action if a matching event arrives.
///
/// A plan without matching evidence is not a promise.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WakePlan {
    /// Return from a foreground wait in the current turn.
    ReturnForeground,
    /// Complete a background tool so the harness may start a turn.
    CompleteBackgroundTool,
    /// Submit a native prompt through a proven controller.
    SubmitPrompt,
    /// Notify a human operator; do not claim a model turn.
    NotifyOperator,
    /// No wake action is armed.
    None,
}

impl WakePlan {
    /// Stable token used by CLI and console faces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReturnForeground => "return_foreground",
            Self::CompleteBackgroundTool => "complete_background_tool",
            Self::SubmitPrompt => "submit_prompt",
            Self::NotifyOperator => "notify_operator",
            Self::None => "none",
        }
    }
}

impl fmt::Display for WakePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A fact that is either known with field-level evidence or explicitly
/// unknown.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ObservedFact<T> {
    /// The value and the evidence supporting this specific field.
    Known {
        /// Observed value.
        value: T,
        /// Evidence for this value.
        evidence: EvidenceClass,
    },
    /// No value is currently supportable.
    Unknown,
}

impl<T> ObservedFact<T> {
    /// Construct a known fact with its field-level evidence.
    #[must_use]
    pub const fn known(value: T, evidence: EvidenceClass) -> Self {
        Self::Known { value, evidence }
    }

    /// Construct an explicitly unknown fact.
    #[must_use]
    pub const fn unknown() -> Self {
        Self::Unknown
    }

    /// Borrow a known value without discarding its evidence.
    #[must_use]
    pub const fn as_known(&self) -> Option<(&T, EvidenceClass)> {
        match self {
            Self::Known { value, evidence } => Some((value, *evidence)),
            Self::Unknown => None,
        }
    }

    /// Report whether this fact is explicitly unknown.
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// Render a fact as `unknown` or `value  (evidence)`.
pub fn format_observed_fact<T: fmt::Display>(fact: &ObservedFact<T>) -> String {
    match fact {
        ObservedFact::Known { value, evidence } => {
            format!("{value}  ({evidence})")
        }
        ObservedFact::Unknown => "unknown".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{EvidenceClass, ObservedFact, Reachability, WakePlan, format_observed_fact};

    #[test]
    fn known_fact_preserves_field_level_evidence() {
        let fact = ObservedFact::known("held", EvidenceClass::SelfDeclared);

        assert_eq!(
            fact.as_known(),
            Some((&"held", EvidenceClass::SelfDeclared))
        );
        assert!(!fact.is_unknown());
    }

    #[test]
    fn unknown_fact_cannot_carry_a_value() {
        let fact = ObservedFact::<&str>::unknown();

        assert_eq!(fact.as_known(), None);
        assert!(fact.is_unknown());
    }

    #[test]
    fn evidence_and_reachability_tokens_are_stable() {
        assert_eq!(EvidenceClass::CensusInferred.as_str(), "census_inferred");
        assert_eq!(
            Reachability::CompletionDoorbell.as_str(),
            "completion_doorbell"
        );
        assert_eq!(
            WakePlan::CompleteBackgroundTool.as_str(),
            "complete_background_tool"
        );
    }

    #[test]
    fn formatted_facts_do_not_promote_unknown() {
        let known = ObservedFact::known("grok", EvidenceClass::CensusInferred);
        assert_eq!(format_observed_fact(&known), "grok  (census_inferred)");
        assert_eq!(
            format_observed_fact(&ObservedFact::<&str>::unknown()),
            "unknown"
        );
    }
}
