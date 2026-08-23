//! Census-safe `self who` card.
//!
//! Native session identifiers, controller endpoints, pids, and host paths stay
//! off this face. Environment variables are treated as untrusted census.

use crate::sanitize::{MAX_TERM, paste_token};
use gearwit_domain::{EvidenceClass, ObservedFact, Reachability, WakePlan, format_observed_fact};

/// Recognized harness family. Presence only; no native identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessFamily {
    /// Grok marker present (`GROK_SESSION_ID` or `GROK_AGENT`).
    Grok,
    /// Codex marker present (`CODEX_THREAD_ID` or `CODEX_SESSION_ID`).
    Codex,
    /// Claude Code marker present (`CLAUDECODE`).
    ClaudeCode,
    /// `OPENCODE` or `OPENCODE_PID` marker present.
    OpenCode,
}

impl HarnessFamily {
    /// Stable census token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grok => "grok",
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::OpenCode => "opencode",
        }
    }
}

/// How many distinct harness families were observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessObservation {
    /// No recognized marker.
    None,
    /// Exactly one family.
    Unique(HarnessFamily),
    /// Two or more families; do not pick a winner.
    Ambiguous,
}

/// Process-visible hints used to classify a seat. Not identifier material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessCensus {
    /// `std::env::consts::OS`
    pub os: &'static str,
    /// `std::env::consts::ARCH`
    pub arch: &'static str,
    /// `TERM_PROGRAM` when set, non-empty, and paste-safe.
    pub term_program: Option<String>,
    /// Distinct harness families present in the environment.
    pub harness: HarnessObservation,
}

impl ProcessCensus {
    /// Observe the current process without capturing identifier values.
    #[must_use]
    pub fn from_current_process() -> Self {
        Self {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            term_program: nonempty_env("TERM_PROGRAM")
                .and_then(|term| paste_token(&term, MAX_TERM).map(ToOwned::to_owned)),
            harness: observe_harness(&env_harness_families()),
        }
    }
}

/// Field-level census card for the calling process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WhoCard {
    /// Operating system token.
    pub os: ObservedFact<&'static str>,
    /// CPU architecture token.
    pub arch: ObservedFact<&'static str>,
    /// Terminal program name when the host exported one.
    pub term: ObservedFact<String>,
    /// Harness family when an env marker is present.
    pub harness: ObservedFact<&'static str>,
    /// Controller attachment. Unknown unless a host proof exists.
    pub controller_attached: ObservedFact<bool>,
    /// Whether this process currently holds an armed wait.
    pub wait_armed: ObservedFact<bool>,
    /// How a matching event can reach this seat.
    pub reachability: ObservedFact<Reachability>,
    /// Planned wake action, if any.
    pub wake_plan: ObservedFact<WakePlan>,
    /// Local daemon observation for this command.
    pub daemon: ObservedFact<&'static str>,
    /// Durability of this command's own observation path.
    pub durability: &'static str,
}

impl WhoCard {
    /// Build a card from process census. Does not claim wait or controller state.
    #[must_use]
    pub fn from_census(census: &ProcessCensus) -> Self {
        Self {
            os: ObservedFact::known(census.os, EvidenceClass::SelfDeclared),
            arch: ObservedFact::known(census.arch, EvidenceClass::SelfDeclared),
            term: census
                .term_program
                .as_deref()
                .and_then(|term| paste_token(term, MAX_TERM))
                .map_or_else(ObservedFact::unknown, |term| {
                    ObservedFact::known(term.to_owned(), EvidenceClass::CensusInferred)
                }),
            harness: classify_harness(census),
            controller_attached: ObservedFact::unknown(),
            wait_armed: ObservedFact::unknown(),
            reachability: ObservedFact::unknown(),
            wake_plan: ObservedFact::unknown(),
            daemon: ObservedFact::unknown(),
            durability: "in_process",
        }
    }

    /// Render a paste-safe text card. Not a public wire protocol.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "\
gearwit self who
os: {os}
arch: {arch}
term: {term}
harness: {harness}
controller_attached: {controller_attached}
wait_armed: {wait_armed}
reachability: {reachability}
wake_plan: {wake_plan}
daemon: {daemon}
durability: {durability}
",
            os = format_observed_fact(&self.os),
            arch = format_observed_fact(&self.arch),
            term = format_observed_fact(&self.term),
            harness = format_observed_fact(&self.harness),
            controller_attached = format_observed_fact(&self.controller_attached),
            wait_armed = format_observed_fact(&self.wait_armed),
            reachability = format_observed_fact(&self.reachability),
            wake_plan = format_observed_fact(&self.wake_plan),
            daemon = format_observed_fact(&self.daemon),
            durability = self.durability,
        )
    }
}

fn classify_harness(census: &ProcessCensus) -> ObservedFact<&'static str> {
    match census.harness {
        HarnessObservation::Unique(family) => {
            ObservedFact::known(family.as_str(), EvidenceClass::CensusInferred)
        }
        HarnessObservation::None | HarnessObservation::Ambiguous => ObservedFact::unknown(),
    }
}

/// Classify distinct family markers. Multiple families stay unknown.
#[must_use]
pub fn observe_harness(families: &[HarnessFamily]) -> HarnessObservation {
    let mut unique = Vec::new();
    for family in [
        HarnessFamily::Grok,
        HarnessFamily::Codex,
        HarnessFamily::ClaudeCode,
        HarnessFamily::OpenCode,
    ] {
        if families.contains(&family) {
            unique.push(family);
        }
    }
    match unique.as_slice() {
        [] => HarnessObservation::None,
        [only] => HarnessObservation::Unique(*only),
        _ => HarnessObservation::Ambiguous,
    }
}

fn env_harness_families() -> Vec<HarnessFamily> {
    let mut families = Vec::new();
    if env_present("GROK_SESSION_ID") || env_present("GROK_AGENT") {
        families.push(HarnessFamily::Grok);
    }
    if env_present("CODEX_THREAD_ID") || env_present("CODEX_SESSION_ID") {
        families.push(HarnessFamily::Codex);
    }
    if env_present("CLAUDECODE") {
        families.push(HarnessFamily::ClaudeCode);
    }
    if env_present("OPENCODE") || env_present("OPENCODE_PID") {
        families.push(HarnessFamily::OpenCode);
    }
    families
}

fn env_present(key: &str) -> bool {
    std::env::var_os(key).is_some_and(|value| !value.is_empty())
}

fn nonempty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{HarnessFamily, HarnessObservation, ProcessCensus, WhoCard, observe_harness};

    use gearwit_domain::{EvidenceClass, ObservedFact};

    fn empty_census() -> ProcessCensus {
        ProcessCensus {
            os: "macos",
            arch: "aarch64",
            term_program: None,
            harness: HarnessObservation::None,
        }
    }

    #[test]
    fn grok_env_is_census_not_a_doorbell_claim() {
        let mut census = empty_census();
        census.harness = HarnessObservation::Unique(HarnessFamily::Grok);
        census.term_program = Some("ghostty".to_owned());
        let card = WhoCard::from_census(&census);
        assert_eq!(
            card.harness,
            ObservedFact::known("grok", EvidenceClass::CensusInferred)
        );
        assert!(card.controller_attached.is_unknown());
        assert!(card.wait_armed.is_unknown());
        assert!(card.reachability.is_unknown());
        assert_eq!(card.durability, "in_process");
        let text = card.render();
        assert!(text.contains("harness: grok  (census_inferred)"));
        assert!(text.contains("reachability: unknown"));
        assert!(!text.contains("completion_doorbell"));
    }

    #[test]
    fn unknown_harness_stays_unknown() {
        let card = WhoCard::from_census(&empty_census());
        assert!(card.harness.is_unknown());
        assert!(card.render().contains("harness: unknown"));
    }

    #[test]
    fn render_does_not_echo_identifier_material() {
        let mut census = empty_census();
        census.harness = HarnessObservation::Unique(HarnessFamily::Grok);
        let text = WhoCard::from_census(&census).render();
        assert!(!text.contains("GROK_SESSION_ID"));
        assert!(!text.contains("session"));
    }

    #[test]
    fn pairwise_markers_are_ambiguous() {
        let pairs = [
            [HarnessFamily::Grok, HarnessFamily::Codex],
            [HarnessFamily::Grok, HarnessFamily::ClaudeCode],
            [HarnessFamily::Grok, HarnessFamily::OpenCode],
            [HarnessFamily::Codex, HarnessFamily::ClaudeCode],
            [HarnessFamily::Codex, HarnessFamily::OpenCode],
            [HarnessFamily::ClaudeCode, HarnessFamily::OpenCode],
        ];
        for pair in pairs {
            assert_eq!(observe_harness(&pair), HarnessObservation::Ambiguous);
            let mut census = empty_census();
            census.harness = HarnessObservation::Ambiguous;
            let text = WhoCard::from_census(&census).render();
            assert!(text.contains("harness: unknown"));
            assert!(!text.contains("harness: grok"));
            assert!(!text.contains("harness: codex"));
        }
    }

    #[test]
    fn unsafe_term_program_is_omitted() {
        let mut census = empty_census();
        census.term_program = Some("ghostty\nwait_result: matched".to_owned());
        let card = WhoCard::from_census(&census);
        assert!(card.term.is_unknown());
        let text = card.render();
        assert!(!text.contains("wait_result: matched"));
        assert!(text.contains("term: unknown"));
    }
}
