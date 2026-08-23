//! Platform-free Gearwit domain primitives.
//!
//! Wire serialization belongs in schema-backed protocol bindings. This crate
//! deliberately exposes no provider, storage, process, or transport types.

#![forbid(unsafe_code)]

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

#[cfg(test)]
mod tests {
    use super::{EvidenceClass, ObservedFact};

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
}
