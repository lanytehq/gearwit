//! Deterministic development simulator for Gearwit persistence chains.
//!
//! Production crates never depend on this crate. The simulator drives an
//! independent abstract oracle and invokes the admitted host fixture bridge
//! for the current fake and bundled `SQLite` baseline.

#![forbid(unsafe_code)]

use gearwit_host::simulator::{
    HostCheck, SimulatorStore, run_complete_chain, run_conformance, verify_crash_reopen,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const ARTIFACT_VERSION: &str = "gearwit.sim/v1";
pub const ORACLE_VERSION: &str = "gearwit.abstract-oracle/v1";
pub const MAX_ARTIFACT_BYTES: usize = 1_048_576;

pub const CASE_IDS: &[&str] = &[
    "SIM-CHAIN-01",
    "SIM-CHAIN-02",
    "SIM-CHAIN-03",
    "SIM-CHAIN-04",
    "SIM-CHAIN-05",
    "SIM-CHAIN-06",
    "SIM-CHAIN-07",
    "SIM-CHAIN-08",
    "SIM-QUEUE-01",
    "SIM-REPLAY-01",
    "SIM-PROC-01",
    "SIM-ORACLE-01",
    "SIM-ORACLE-02",
    "SIM-ORACLE-03",
    "SIM-ORACLE-04",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Passed,
    Failed,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverflowPolicy {
    Reject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunLimits {
    pub queue_capacity: usize,
    pub max_events: usize,
    pub max_virtual_tick: u64,
    pub overflow: OverflowPolicy,
}

impl Default for RunLimits {
    fn default() -> Self {
        Self {
            queue_capacity: 64,
            max_events: 1_024,
            max_virtual_tick: 10_000,
            overflow: OverflowPolicy::Reject,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScenarioEnvelope {
    pub version: String,
    pub case_id: String,
    pub seed: u64,
    pub seeds: SeedSet,
    pub store: SimulatorStore,
    pub limits: RunLimits,
    pub stimuli: Vec<Stimulus>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SeedSet {
    pub source: u64,
    pub actor: u64,
    pub scheduler: u64,
    pub fault: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Stimulus {
    pub version: String,
    pub due_tick: u64,
    pub sequence: u64,
    pub operation_id: String,
    pub causal_parent: Option<String>,
    pub action: Action,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Action {
    Arm,
    Offer { event: String },
    Admit { event: String },
    Retrieve { request: String },
    StaleRetrieve { request: String },
    Acknowledge { request: String },
    Terminal,
    Rearm,
    Revoke,
    Restart,
    OmitRearm,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Observation {
    pub version: String,
    pub operation_id: String,
    pub outcome: String,
    pub logical_effects: u64,
    pub authority_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueAccounting {
    pub offered: usize,
    pub admitted: usize,
    pub rejected: usize,
    pub completed: usize,
    pub delivered: usize,
    pub duplicated: usize,
    pub dropped: usize,
    pub max_depth: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PlatformPin {
    pub os: String,
    pub arch: String,
    pub simulator_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunArtifact {
    pub version: String,
    pub run_id: String,
    pub oracle_version: String,
    pub scenario: ScenarioEnvelope,
    pub platform: PlatformPin,
    pub observations: Vec<Observation>,
    pub host_checks: Vec<HostCheck>,
    pub queue: QueueAccounting,
    pub oracle_findings: Vec<String>,
    pub status: CaseStatus,
    pub semantic_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Comparison {
    pub same_scenario: bool,
    pub same_semantics: bool,
    pub left_status: CaseStatus,
    pub right_status: CaseStatus,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct Oracle {
    armed: bool,
    claimed: bool,
    retrieved: bool,
    acknowledged: bool,
    terminal: bool,
    rearmed: bool,
    revoked: bool,
    offered: usize,
    logical_effects: u64,
    revision: u64,
    request_results: BTreeMap<String, String>,
    seen_operations: BTreeMap<String, Action>,
}

impl Oracle {
    fn apply(&mut self, stimulus: &Stimulus) -> Observation {
        let outcome = if let Some(original) = self.seen_operations.get(&stimulus.operation_id) {
            if original == &stimulus.action {
                "exact_replay".to_owned()
            } else {
                "conflict".to_owned()
            }
        } else {
            self.seen_operations
                .insert(stimulus.operation_id.clone(), stimulus.action.clone());
            self.apply_fresh(&stimulus.action)
        };
        Observation {
            version: ARTIFACT_VERSION.to_owned(),
            operation_id: stimulus.operation_id.clone(),
            outcome,
            logical_effects: self.logical_effects,
            authority_revision: self.revision,
        }
    }

    fn apply_fresh(&mut self, action: &Action) -> String {
        match action {
            Action::Arm => {
                self.armed = true;
                self.commit("armed")
            }
            Action::Offer { .. } if self.armed => {
                self.offered += 1;
                self.commit("offered")
            }
            Action::Admit { event } if self.armed && !self.revoked && self.offered > 0 => {
                if self.claimed {
                    "conflict".to_owned()
                } else {
                    self.claimed = true;
                    self.logical_effects += 1;
                    self.request_results
                        .insert(event.clone(), "admitted".to_owned());
                    self.commit("admitted")
                }
            }
            Action::Retrieve { request } if self.claimed && !self.revoked => {
                if let Some(result) = self.request_results.get(request) {
                    result.clone()
                } else if self.acknowledged {
                    "invalid_transition".to_owned()
                } else {
                    self.retrieved = true;
                    self.request_results
                        .insert(request.clone(), "retrieved".to_owned());
                    self.commit("retrieved")
                }
            }
            Action::Acknowledge { request } if self.retrieved && !self.revoked => {
                if let Some(result) = self.request_results.get(request) {
                    result.clone()
                } else {
                    self.acknowledged = true;
                    self.request_results
                        .insert(request.clone(), "acknowledged".to_owned());
                    self.commit("acknowledged")
                }
            }
            Action::Terminal if self.claimed => {
                self.terminal = true;
                self.commit("terminal")
            }
            Action::Rearm if self.acknowledged && self.terminal => {
                self.rearmed = true;
                self.claimed = false;
                self.retrieved = false;
                self.acknowledged = false;
                self.terminal = false;
                self.commit("rearmed")
            }
            Action::Rearm if !self.acknowledged => "waiting_for_handled".to_owned(),
            Action::Rearm => "waiting_for_terminal".to_owned(),
            Action::Revoke => {
                self.revoked = true;
                self.commit("revoked")
            }
            Action::Restart => "reopened".to_owned(),
            Action::OmitRearm => "inactive".to_owned(),
            _ => "unauthorized".to_owned(),
        }
    }

    fn commit(&mut self, outcome: &str) -> String {
        self.revision += 1;
        outcome.to_owned()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultMode {
    None,
    DuplicateAdmission,
    LoseAcknowledgment,
    ResurrectRevokedGrant,
    FalsePublication,
}

impl FaultMode {
    fn for_case(case_id: &str) -> Self {
        match case_id {
            "SIM-ORACLE-01" => Self::DuplicateAdmission,
            "SIM-ORACLE-02" => Self::LoseAcknowledgment,
            "SIM-ORACLE-03" => Self::ResurrectRevokedGrant,
            "SIM-ORACLE-04" => Self::FalsePublication,
            _ => Self::None,
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Default)]
struct AdapterState {
    armed: bool,
    offered: usize,
    claimed: bool,
    retrieved: bool,
    acknowledged: bool,
    terminal: bool,
    revoked: bool,
    logical_effects: u64,
    revision: u64,
    requests: BTreeMap<String, String>,
    operations: BTreeMap<String, Action>,
}

struct TestAdapter {
    live: AdapterState,
    durable: AdapterState,
    fault: FaultMode,
}

impl TestAdapter {
    fn new(fault: FaultMode) -> Self {
        Self {
            live: AdapterState::default(),
            durable: AdapterState::default(),
            fault,
        }
    }

    fn apply(&mut self, stimulus: &Stimulus) -> Observation {
        if matches!(stimulus.action, Action::Restart) {
            self.live = self.durable.clone();
            match self.fault {
                FaultMode::LoseAcknowledgment => self.live.acknowledged = false,
                FaultMode::ResurrectRevokedGrant => self.live.revoked = false,
                _ => {}
            }
            return self.observation(stimulus, "reopened");
        }
        let outcome = if let Some(original) = self.live.operations.get(&stimulus.operation_id) {
            if original == &stimulus.action {
                "exact_replay".to_owned()
            } else {
                "conflict".to_owned()
            }
        } else {
            self.live
                .operations
                .insert(stimulus.operation_id.clone(), stimulus.action.clone());
            self.apply_fresh(&stimulus.action)
        };
        self.observation(stimulus, &outcome)
    }

    fn apply_fresh(&mut self, action: &Action) -> String {
        let (outcome, committed) = match action {
            Action::Arm => {
                self.live.armed = true;
                ("armed", true)
            }
            Action::Offer { .. } if self.live.armed => {
                self.live.offered += 1;
                ("offered", true)
            }
            Action::Admit { event }
                if self.live.armed && !self.live.revoked && self.live.offered > 0 =>
            {
                if self.live.claimed {
                    ("conflict", false)
                } else {
                    self.live.claimed = true;
                    self.live.logical_effects += 1;
                    self.live
                        .requests
                        .insert(event.clone(), "admitted".to_owned());
                    if self.fault == FaultMode::DuplicateAdmission {
                        self.live.logical_effects += 1;
                    }
                    ("admitted", true)
                }
            }
            Action::Retrieve { request } if self.live.claimed && !self.live.revoked => {
                if let Some(result) = self.live.requests.get(request) {
                    return result.clone();
                }
                if self.live.acknowledged {
                    ("invalid_transition", false)
                } else {
                    self.live.retrieved = true;
                    self.live
                        .requests
                        .insert(request.clone(), "retrieved".to_owned());
                    ("retrieved", true)
                }
            }
            Action::Acknowledge { request } if self.live.retrieved && !self.live.revoked => {
                if let Some(result) = self.live.requests.get(request) {
                    return result.clone();
                }
                if self.fault == FaultMode::FalsePublication {
                    return "acknowledged".to_owned();
                }
                self.live.acknowledged = true;
                self.live
                    .requests
                    .insert(request.clone(), "acknowledged".to_owned());
                ("acknowledged", true)
            }
            Action::Terminal if self.live.claimed => {
                self.live.terminal = true;
                ("terminal", true)
            }
            Action::Rearm if self.live.acknowledged && self.live.terminal => {
                self.live.claimed = false;
                self.live.retrieved = false;
                self.live.acknowledged = false;
                self.live.terminal = false;
                ("rearmed", true)
            }
            Action::Rearm if !self.live.acknowledged => ("waiting_for_handled", false),
            Action::Rearm => ("waiting_for_terminal", false),
            Action::Revoke => {
                self.live.revoked = true;
                ("revoked", true)
            }
            Action::OmitRearm => ("inactive", false),
            _ => ("unauthorized", false),
        };
        if committed {
            self.live.revision += 1;
            self.durable = self.live.clone();
        }
        outcome.to_owned()
    }

    fn observation(&self, stimulus: &Stimulus, outcome: &str) -> Observation {
        Observation {
            version: ARTIFACT_VERSION.to_owned(),
            operation_id: stimulus.operation_id.clone(),
            outcome: outcome.to_owned(),
            logical_effects: self.live.logical_effects,
            authority_revision: self.live.revision,
        }
    }
}

/// Build the stable scenario envelope for one named readiness case.
///
/// # Errors
///
/// Returns an error when `case_id` is not in the required scenario catalog.
#[allow(clippy::too_many_lines)] // The stable case inventory is easier to audit in one match.
pub fn scenario(
    case_id: &str,
    seed: u64,
    store: SimulatorStore,
) -> Result<ScenarioEnvelope, String> {
    if !CASE_IDS.contains(&case_id) {
        return Err(format!("unknown scenario id: {case_id}"));
    }
    let seeds = derive_seeds(seed);
    let mut limits = RunLimits::default();
    let event = format!("event-{:016x}", seeds.actor);
    let retrieve = format!("retrieve-{:016x}", seeds.actor);
    let acknowledge = format!("ack-{:016x}", seeds.actor);
    let mut stimuli = match case_id {
        "SIM-CHAIN-01" => complete_chain(&event, &retrieve, &acknowledge),
        "SIM-REPLAY-01" => {
            let mut chain = first_acknowledged_chain(&event, &retrieve, &acknowledge);
            chain.push(stimulus(5, 6, "controlled-early-rearm", Action::Rearm));
            chain
        }
        "SIM-CHAIN-02" => {
            let mut chain = first_acknowledged_chain(&event, &retrieve, &acknowledge);
            chain.push(stimulus(5, 6, "restart-1", Action::Restart));
            chain.push(stimulus(
                6,
                7,
                "retrieve-1",
                Action::Retrieve {
                    request: retrieve.clone(),
                },
            ));
            chain.push(stimulus(
                7,
                8,
                "ack-1",
                Action::Acknowledge {
                    request: acknowledge.clone(),
                },
            ));
            chain
        }
        "SIM-CHAIN-03" => {
            let mut chain = vec![
                stimulus(0, 1, "arm-1", Action::Arm),
                stimulus(
                    1,
                    2,
                    "offer-1",
                    Action::Offer {
                        event: event.clone(),
                    },
                ),
                stimulus(
                    2,
                    3,
                    "claim-1",
                    Action::Admit {
                        event: event.clone(),
                    },
                ),
                stimulus(3, 4, "restart-1", Action::Restart),
            ];
            chain.push(stimulus(
                4,
                5,
                "claim-1",
                Action::Admit {
                    event: "changed-event".to_owned(),
                },
            ));
            chain
        }
        "SIM-CHAIN-04" => vec![
            stimulus(0, 1, "arm-1", Action::Arm),
            stimulus(
                1,
                2,
                "offer-1",
                Action::Offer {
                    event: event.clone(),
                },
            ),
            stimulus(
                2,
                3,
                "claim-1",
                Action::Admit {
                    event: event.clone(),
                },
            ),
            stimulus(3, 4, "revoke-1", Action::Revoke),
            stimulus(4, 5, "restart-1", Action::Restart),
            stimulus(
                5,
                6,
                "retrieve-after-revoke",
                Action::Retrieve {
                    request: retrieve.clone(),
                },
            ),
        ],
        "SIM-CHAIN-05" => vec![
            stimulus(0, 1, "arm-1", Action::Arm),
            stimulus(
                1,
                2,
                "offer-1",
                Action::Offer {
                    event: event.clone(),
                },
            ),
            stimulus(
                2,
                3,
                "claim-1",
                Action::Admit {
                    event: event.clone(),
                },
            ),
            stimulus(3, 4, "restart-1", Action::Restart),
            stimulus(
                4,
                5,
                "stale-retrieve",
                Action::StaleRetrieve {
                    request: retrieve.clone(),
                },
            ),
        ],
        "SIM-CHAIN-06" => {
            let mut chain = first_acknowledged_chain(&event, &retrieve, &acknowledge);
            chain.push(stimulus(5, 6, "rearm-wait", Action::Rearm));
            chain.push(stimulus(
                6,
                7,
                "offer-during-rearm",
                Action::Offer {
                    event: "event-during-rearm".to_owned(),
                },
            ));
            chain.push(stimulus(7, 8, "terminal-1", Action::Terminal));
            chain.push(stimulus(8, 9, "rearm-1", Action::Rearm));
            chain
        }
        "SIM-CHAIN-07" | "SIM-PROC-01" => {
            let mut chain = first_acknowledged_chain(&event, &retrieve, &acknowledge);
            chain.push(stimulus(5, 6, "restart-after-ack", Action::Restart));
            chain.push(stimulus(6, 7, "terminal-1", Action::Terminal));
            chain.push(stimulus(7, 8, "rearm-1", Action::Rearm));
            chain
        }
        "SIM-CHAIN-08" => {
            let mut chain = first_acknowledged_chain(&event, &retrieve, &acknowledge);
            chain.push(stimulus(5, 6, "terminal-1", Action::Terminal));
            chain.push(stimulus(6, 7, "omit-rearm", Action::OmitRearm));
            chain
        }
        "SIM-QUEUE-01" => {
            limits.queue_capacity = 8;
            let mut arrivals = SplitMix64(seeds.scheduler);
            (0..24)
                .map(|index| {
                    stimulus(
                        arrivals.next() % 6,
                        index,
                        &format!("queue-{index}"),
                        Action::Offer {
                            event: format!("event-{index}"),
                        },
                    )
                })
                .collect()
        }
        "SIM-ORACLE-01" => vec![
            stimulus(0, 1, "arm-1", Action::Arm),
            stimulus(
                1,
                2,
                "offer-1",
                Action::Offer {
                    event: event.clone(),
                },
            ),
            stimulus(
                2,
                3,
                "claim-1",
                Action::Admit {
                    event: event.clone(),
                },
            ),
        ],
        "SIM-ORACLE-02" => {
            let mut chain = first_acknowledged_chain(&event, &retrieve, &acknowledge);
            chain.push(stimulus(5, 6, "restart-1", Action::Restart));
            chain.push(stimulus(6, 7, "terminal-1", Action::Terminal));
            chain.push(stimulus(7, 8, "rearm-1", Action::Rearm));
            chain
        }
        "SIM-ORACLE-03" => vec![
            stimulus(0, 1, "arm-1", Action::Arm),
            stimulus(
                1,
                2,
                "offer-1",
                Action::Offer {
                    event: event.clone(),
                },
            ),
            stimulus(
                2,
                3,
                "claim-1",
                Action::Admit {
                    event: event.clone(),
                },
            ),
            stimulus(3, 4, "revoke-1", Action::Revoke),
            stimulus(4, 5, "restart-1", Action::Restart),
            stimulus(
                5,
                6,
                "retrieve-after-revoke",
                Action::Retrieve { request: retrieve },
            ),
        ],
        "SIM-ORACLE-04" => first_acknowledged_chain(&event, &retrieve, &acknowledge),
        _ => unreachable!("catalog checked"),
    };
    if case_id != "SIM-QUEUE-01" {
        let mut prior = None;
        for stimulus in &mut stimuli {
            stimulus.causal_parent.clone_from(&prior);
            prior = Some(stimulus.operation_id.clone());
        }
    }
    Ok(ScenarioEnvelope {
        version: ARTIFACT_VERSION.to_owned(),
        case_id: case_id.to_owned(),
        seed,
        seeds,
        store,
        limits,
        stimuli,
    })
}

fn stimulus(due_tick: u64, sequence: u64, operation_id: &str, action: Action) -> Stimulus {
    Stimulus {
        version: ARTIFACT_VERSION.to_owned(),
        due_tick,
        sequence,
        operation_id: operation_id.to_owned(),
        causal_parent: None,
        action,
    }
}

fn first_acknowledged_chain(event: &str, retrieve: &str, acknowledge: &str) -> Vec<Stimulus> {
    vec![
        stimulus(0, 1, "arm-1", Action::Arm),
        stimulus(
            1,
            2,
            "offer-1",
            Action::Offer {
                event: event.to_owned(),
            },
        ),
        stimulus(
            2,
            3,
            "claim-1",
            Action::Admit {
                event: event.to_owned(),
            },
        ),
        stimulus(
            3,
            4,
            "retrieve-1",
            Action::Retrieve {
                request: retrieve.to_owned(),
            },
        ),
        stimulus(
            4,
            5,
            "ack-1",
            Action::Acknowledge {
                request: acknowledge.to_owned(),
            },
        ),
    ]
}

fn complete_chain(event: &str, retrieve: &str, acknowledge: &str) -> Vec<Stimulus> {
    let mut chain = first_acknowledged_chain(event, retrieve, acknowledge);
    chain.push(stimulus(5, 6, "terminal-1", Action::Terminal));
    chain.push(stimulus(6, 7, "rearm-1", Action::Rearm));
    chain.push(stimulus(
        7,
        8,
        "offer-2",
        Action::Offer {
            event: "event-next".to_owned(),
        },
    ));
    chain.push(stimulus(
        8,
        9,
        "claim-2",
        Action::Admit {
            event: "event-next".to_owned(),
        },
    ));
    chain
}

/// Run a deterministic scenario and return a replayable artifact.
#[must_use]
pub fn run(envelope: ScenarioEnvelope) -> RunArtifact {
    let mut queue = envelope.stimuli.clone();
    queue.sort_by_key(|stimulus| (stimulus.due_tick, stimulus.sequence));
    let offered = queue.len();
    let admitted = offered.min(envelope.limits.queue_capacity);
    let rejected = offered.saturating_sub(admitted);
    if rejected > 0
        && envelope.limits.overflow == OverflowPolicy::Reject
        && envelope.case_id != "SIM-QUEUE-01"
    {
        queue.truncate(admitted);
    }
    let resource_limited = queue.len() > envelope.limits.max_events
        || queue
            .iter()
            .any(|stimulus| stimulus.due_tick > envelope.limits.max_virtual_tick);
    let runnable = queue
        .iter()
        .filter(|stimulus| stimulus.due_tick <= envelope.limits.max_virtual_tick)
        .take(envelope.limits.max_events)
        .cloned()
        .collect::<Vec<_>>();
    let (observations, queue_accounting) = if envelope.case_id == "SIM-QUEUE-01" {
        run_slow_queue(&runnable, &envelope.limits)
    } else {
        let mut adapter = TestAdapter::new(FaultMode::for_case(&envelope.case_id));
        let observations = runnable
            .iter()
            .map(|stimulus| adapter.apply(stimulus))
            .collect::<Vec<_>>();
        let completed = observations.len();
        (
            observations,
            QueueAccounting {
                offered,
                admitted,
                rejected,
                completed,
                delivered: completed,
                duplicated: 0,
                dropped: 0,
                max_depth: admitted,
            },
        )
    };
    let mut host_checks = host_checks(&envelope.case_id, envelope.store);
    let mut findings = if envelope.case_id == "SIM-QUEUE-01" {
        Vec::new()
    } else {
        oracle_findings(&runnable, &observations)
    };
    let case_findings = validate_observations(&envelope.case_id, &observations);
    findings.extend(case_findings.iter().cloned());
    let fault = FaultMode::for_case(&envelope.case_id);
    if fault != FaultMode::None {
        host_checks.push(HostCheck {
            store: envelope.store,
            check: format!("oracle-detects-{}", fault.name()),
            passed: !findings.is_empty(),
            detail: if findings.is_empty() {
                "deliberate adapter violation escaped the independent oracle".to_owned()
            } else {
                format!(
                    "independent oracle reported {} mismatch(es)",
                    findings.len()
                )
            },
        });
    }
    if envelope.case_id == "SIM-PROC-01" {
        host_checks.push(HostCheck {
            store: SimulatorStore::Sqlite,
            check: "real-process-runner".to_owned(),
            passed: false,
            detail: "use run_process_case so a separate child can be killed".to_owned(),
        });
    }
    let status = if resource_limited {
        CaseStatus::Incomplete
    } else if case_findings.is_empty()
        && (fault != FaultMode::None || findings.is_empty())
        && host_checks.iter().all(|check| check.passed)
    {
        CaseStatus::Passed
    } else if envelope.case_id == "SIM-PROC-01" {
        CaseStatus::Incomplete
    } else {
        CaseStatus::Failed
    };
    finish_artifact(
        envelope,
        observations,
        host_checks,
        queue_accounting,
        findings,
        status,
    )
}

impl FaultMode {
    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::DuplicateAdmission => "duplicate-admission",
            Self::LoseAcknowledgment => "lost-committed-ack",
            Self::ResurrectRevokedGrant => "revoked-grant-resurrection",
            Self::FalsePublication => "false-durable-publication",
        }
    }
}

fn oracle_findings(stimuli: &[Stimulus], observations: &[Observation]) -> Vec<String> {
    let mut oracle = Oracle::default();
    let expected = stimuli
        .iter()
        .map(|stimulus| oracle.apply(stimulus))
        .collect::<Vec<_>>();
    expected
        .iter()
        .zip(observations)
        .filter(|(expected, actual)| expected != actual)
        .map(|(expected, actual)| {
            format!(
                "{} expected outcome={} effects={} revision={}, observed outcome={} effects={} revision={}",
                actual.operation_id,
                expected.outcome,
                expected.logical_effects,
                expected.authority_revision,
                actual.outcome,
                actual.logical_effects,
                actual.authority_revision
            )
        })
        .collect()
}

fn run_slow_queue(stimuli: &[Stimulus], limits: &RunLimits) -> (Vec<Observation>, QueueAccounting) {
    let mut pending = std::collections::VecDeque::new();
    let mut observations = Vec::new();
    let mut admitted = 0;
    let mut rejected = 0;
    let mut max_depth = 0;
    let final_tick = stimuli
        .iter()
        .map(|stimulus| stimulus.due_tick)
        .max()
        .unwrap_or(0);
    for tick in 0..=final_tick + u64::try_from(limits.queue_capacity).expect("queue capacity") {
        for stimulus in stimuli.iter().filter(|stimulus| stimulus.due_tick == tick) {
            if pending.len() == limits.queue_capacity {
                rejected += 1;
            } else {
                pending.push_back(stimulus.clone());
                admitted += 1;
            }
        }
        max_depth = max_depth.max(pending.len());
        if let Some(completed) = pending.pop_front() {
            observations.push(queue_completion(completed, observations.len()));
        }
    }
    while let Some(completed) = pending.pop_front() {
        observations.push(queue_completion(completed, observations.len()));
    }
    (
        observations,
        QueueAccounting {
            offered: stimuli.len(),
            admitted,
            rejected,
            completed: admitted,
            delivered: admitted,
            duplicated: 0,
            dropped: 0,
            max_depth,
        },
    )
}

fn queue_completion(stimulus: Stimulus, prior: usize) -> Observation {
    Observation {
        version: ARTIFACT_VERSION.to_owned(),
        operation_id: stimulus.operation_id,
        outcome: "completed".to_owned(),
        logical_effects: 0,
        authority_revision: u64::try_from(prior + 1).expect("revision"),
    }
}

fn host_checks(case_id: &str, store: SimulatorStore) -> Vec<HostCheck> {
    let ids: &[&str] = match case_id {
        "SIM-CHAIN-01" => return vec![run_complete_chain(store)],
        "SIM-CHAIN-02" => &[
            "replay.retrieve.exact",
            "replay.ack.exact",
            "op.recover-authority-state",
        ],
        "SIM-CHAIN-03" => &["op.admit-claim", "op.recover-authority-state"],
        "SIM-CHAIN-04" => &[
            "op.revoke-helper-grant",
            "grant.revocation-survives-admission",
        ],
        "SIM-CHAIN-05" => &[
            "grant.retired-identity-rejected",
            "op.recover-authority-state",
        ],
        "SIM-CHAIN-06" => &[
            "snapshot.rearm-join-absent-before-handled",
            "op.try-rearm-join",
        ],
        "SIM-CHAIN-07" => &["replay.ack.exact", "op.recover-authority-state"],
        "SIM-CHAIN-08" => &["snapshot.rearm-join-absent-before-handled"],
        _ => &[],
    };
    ids.iter().map(|id| run_conformance(store, id)).collect()
}

fn validate_observations(case_id: &str, observations: &[Observation]) -> Vec<String> {
    let mut findings = Vec::new();
    let effects = observations
        .last()
        .map_or(0, |observation| observation.logical_effects);
    if case_id == "SIM-CHAIN-01"
        && !observations
            .iter()
            .any(|observation| observation.outcome == "rearmed")
    {
        findings.push("complete chain did not rearm".to_owned());
    }
    if case_id == "SIM-CHAIN-02"
        && observations
            .iter()
            .filter(|observation| observation.outcome == "exact_replay")
            .count()
            < 2
    {
        findings.push("exact retries created a second result".to_owned());
    }
    if case_id == "SIM-CHAIN-03"
        && observations
            .last()
            .is_some_and(|observation| observation.outcome != "conflict")
    {
        findings
            .push("changed-content operation identity did not conflict after restart".to_owned());
    }
    if case_id == "SIM-CHAIN-04"
        && observations
            .last()
            .is_some_and(|observation| observation.outcome != "unauthorized")
    {
        findings.push("revoked authority returned after restart".to_owned());
    }
    if case_id == "SIM-CHAIN-05"
        && observations
            .last()
            .is_some_and(|observation| observation.outcome != "unauthorized")
    {
        findings.push("stale authority regained access after restart".to_owned());
    }
    if case_id == "SIM-CHAIN-06"
        && !observations
            .iter()
            .any(|observation| observation.outcome == "waiting_for_terminal")
    {
        findings.push("early rearm did not wait for terminal state".to_owned());
    }
    if case_id == "SIM-CHAIN-07"
        && observations
            .last()
            .is_some_and(|observation| observation.outcome != "rearmed")
    {
        findings.push("post-ack restart did not preserve state through rearm".to_owned());
    }
    if case_id == "SIM-CHAIN-08"
        && observations
            .last()
            .is_some_and(|observation| observation.outcome != "inactive")
    {
        findings.push("omitted rearm was not reported inactive".to_owned());
    }
    if case_id == "SIM-CHAIN-01" && effects != 2 {
        findings.push(format!(
            "complete chain admitted {effects} logical effects, expected 2"
        ));
    }
    if case_id == "SIM-REPLAY-01"
        && !observations
            .iter()
            .any(|observation| observation.outcome == "waiting_for_terminal")
    {
        findings.push("controlled replay failure was not observed".to_owned());
    }
    findings
}

fn finish_artifact(
    envelope: ScenarioEnvelope,
    observations: Vec<Observation>,
    host_checks: Vec<HostCheck>,
    queue: QueueAccounting,
    oracle_findings: Vec<String>,
    status: CaseStatus,
) -> RunArtifact {
    let run_id = format!(
        "{}-{}-{}",
        envelope.case_id.to_ascii_lowercase(),
        envelope.seed,
        match envelope.store {
            SimulatorStore::Fake => "fake",
            SimulatorStore::Sqlite => "sqlite",
        }
    );
    let semantic_fingerprint = fingerprint(&envelope, &observations, &host_checks, &queue);
    RunArtifact {
        version: ARTIFACT_VERSION.to_owned(),
        run_id,
        oracle_version: ORACLE_VERSION.to_owned(),
        scenario: envelope,
        platform: PlatformPin {
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            simulator_version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        observations,
        host_checks,
        queue,
        oracle_findings,
        status,
        semantic_fingerprint,
    }
}

fn fingerprint(
    envelope: &ScenarioEnvelope,
    observations: &[Observation],
    host_checks: &[HostCheck],
    queue: &QueueAccounting,
) -> String {
    let bytes = serde_json::to_vec(&(envelope, observations, host_checks, queue))
        .expect("serializable simulator state");
    blake3::hash(&bytes).to_hex().to_string()
}

/// Persist a bounded replay bundle.
///
/// # Errors
///
/// Returns an error when the parent cannot be created or the artifact cannot
/// be serialized and written.
pub fn write_artifact(path: &Path, artifact: &RunArtifact) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "artifact path has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let document = serde_json::to_vec_pretty(artifact).map_err(|error| error.to_string())?;
    if document.len() > MAX_ARTIFACT_BYTES {
        return Err(format!("artifact exceeds {MAX_ARTIFACT_BYTES} byte limit"));
    }
    fs::write(path, document).map_err(|error| error.to_string())
}

/// Read an artifact and refuse unknown versions.
///
/// # Errors
///
/// Returns an error for I/O, malformed JSON, or an unsupported version.
pub fn read_artifact(path: &Path) -> Result<RunArtifact, String> {
    let document = fs::read(path).map_err(|error| error.to_string())?;
    if document.len() > MAX_ARTIFACT_BYTES {
        return Err(format!("artifact exceeds {MAX_ARTIFACT_BYTES} byte limit"));
    }
    let artifact: RunArtifact =
        serde_json::from_slice(&document).map_err(|error| error.to_string())?;
    let incompatible_envelope = artifact
        .scenario
        .stimuli
        .iter()
        .any(|stimulus| stimulus.version != ARTIFACT_VERSION)
        || artifact
            .observations
            .iter()
            .any(|observation| observation.version != ARTIFACT_VERSION);
    if artifact.version != ARTIFACT_VERSION
        || artifact.scenario.version != ARTIFACT_VERSION
        || artifact.oracle_version != ORACLE_VERSION
        || incompatible_envelope
    {
        return Err(format!(
            "unsupported artifact version: {}",
            artifact.version
        ));
    }
    Ok(artifact)
}

/// Deterministically replay an artifact and require the same semantic result.
///
/// # Errors
///
/// Returns an error when the case requires a real child process or when the
/// replay produces a different semantic fingerprint.
pub fn replay(artifact: &RunArtifact) -> Result<RunArtifact, String> {
    if artifact.scenario.case_id == "SIM-PROC-01" {
        return Err("process case requires a new real child run".to_owned());
    }
    let replayed = run(artifact.scenario.clone());
    if replayed.semantic_fingerprint != artifact.semantic_fingerprint {
        return Err("semantic replay fingerprint differed".to_owned());
    }
    Ok(replayed)
}

#[must_use]
pub fn compare(left: &RunArtifact, right: &RunArtifact) -> Comparison {
    Comparison {
        same_scenario: left.scenario == right.scenario,
        same_semantics: left.semantic_fingerprint == right.semantic_fingerprint,
        left_status: left.status,
        right_status: right.status,
    }
}

/// Run a seeded campaign. Random streams are independent from adapter work.
///
/// # Panics
///
/// Panics only if the compile-time case catalog is empty or contains an id
/// rejected by [`scenario`].
#[must_use]
pub fn campaign(seed: u64, runs: usize, store: SimulatorStore) -> Vec<RunArtifact> {
    let mut source = SplitMix64(seed ^ 0x736f_7572_6365);
    let mut schedule = SplitMix64(seed ^ 0x7363_6865_6475_6c65);
    let candidates = CASE_IDS
        .iter()
        .copied()
        .filter(|id| *id != "SIM-PROC-01")
        .collect::<Vec<_>>();
    (0..runs)
        .map(|_| {
            let index = usize::try_from(
                source.next() % u64::try_from(candidates.len()).expect("case count"),
            )
            .expect("bounded index");
            let case_id = candidates[index];
            let run_seed = schedule.next();
            run(scenario(case_id, run_seed, store).expect("catalog id"))
        })
        .collect()
}

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}

fn derive_seeds(seed: u64) -> SeedSet {
    let mut stream = SplitMix64(seed);
    SeedSet {
        source: stream.next(),
        actor: stream.next(),
        scheduler: stream.next(),
        fault: stream.next(),
    }
}

/// Execute both named `SQLite` crash windows using a separately killed child.
///
/// # Panics
///
/// Panics if `case_id` is not a process-backed catalog entry.
#[must_use]
pub fn run_process_case(executable: &Path, seed: u64, case_id: &str, root: &Path) -> RunArtifact {
    assert!(matches!(case_id, "SIM-CHAIN-07" | "SIM-PROC-01"));
    let envelope = scenario(case_id, seed, SimulatorStore::Sqlite).expect("known case");
    let base = run(envelope);
    let mut checks = base.host_checks;
    checks.retain(|check| check.check != "real-process-runner");
    for phase in ["pre_commit", "post_commit"] {
        checks.push(run_crash_phase(executable, phase, root));
    }
    let status = if base.oracle_findings.is_empty() && checks.iter().all(|check| check.passed) {
        CaseStatus::Passed
    } else {
        CaseStatus::Failed
    };
    finish_artifact(
        base.scenario,
        base.observations,
        checks,
        base.queue,
        base.oracle_findings,
        status,
    )
}

fn run_crash_phase(executable: &Path, phase: &str, artifact_root: &Path) -> HostCheck {
    let phase_root = artifact_root.join(format!("process-{}-{phase}", std::process::id()));
    let _ = fs::remove_dir_all(&phase_root);
    if let Err(error) = fs::create_dir_all(&phase_root) {
        return failed_process_check(phase, error.to_string());
    }
    let path = phase_root.join("authority.sqlite");
    let marker = path.with_extension("marker");
    let mut child = match Command::new(executable)
        .arg("__crash-child")
        .arg("--path")
        .arg(&path)
        .arg("--phase")
        .arg(phase)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return failed_process_check(phase, error.to_string()),
    };
    let expected = if phase == "pre_commit" {
        "PRE_COMMIT"
    } else {
        "POST_COMMIT"
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut reached = false;
    while Instant::now() < deadline {
        if fs::read_to_string(&marker).is_ok_and(|text| text.contains(expected)) {
            reached = true;
            break;
        }
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    if !reached {
        let _ = child.kill();
        let _ = child.wait();
        return failed_process_check(phase, format!("milestone {expected} not reached"));
    }
    if let Err(error) = child.kill() {
        return failed_process_check(phase, error.to_string());
    }
    let _ = child.wait();
    let result = verify_crash_reopen(&path);
    let _ = fs::remove_dir_all(&phase_root);
    match result {
        Ok(()) => HostCheck {
            store: SimulatorStore::Sqlite,
            check: format!("process-crash-{phase}"),
            passed: true,
            detail: "fresh-process reopen passed".to_owned(),
        },
        Err(detail) => failed_process_check(phase, detail),
    }
}

fn failed_process_check(phase: &str, detail: String) -> HostCheck {
    HostCheck {
        store: SimulatorStore::Sqlite,
        check: format!("process-crash-{phase}"),
        passed: false,
        detail,
    }
}

#[must_use]
pub fn default_artifact_path(root: &Path, artifact: &RunArtifact) -> PathBuf {
    root.join(format!(
        "{}-{}-{}.json",
        artifact.scenario.case_id.to_ascii_lowercase(),
        artifact.scenario.seed,
        match artifact.scenario.store {
            SimulatorStore::Fake => "fake",
            SimulatorStore::Sqlite => "sqlite",
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_required_case_has_a_scenario() {
        for id in CASE_IDS {
            scenario(id, 7, SimulatorStore::Fake).expect(id);
        }
    }

    #[test]
    fn every_in_process_case_passes_on_both_admitted_stores() {
        for id in CASE_IDS.iter().copied().filter(|id| *id != "SIM-PROC-01") {
            for store in [SimulatorStore::Fake, SimulatorStore::Sqlite] {
                let artifact = run(scenario(id, 9, store).expect(id));
                assert_eq!(artifact.status, CaseStatus::Passed, "{id}: {artifact:#?}");
                if !id.starts_with("SIM-ORACLE-") {
                    assert!(artifact.oracle_findings.is_empty(), "{id}: {artifact:#?}");
                }
            }
        }
    }

    #[test]
    fn complete_chain_runs_against_both_admitted_stores() {
        for store in [SimulatorStore::Fake, SimulatorStore::Sqlite] {
            let artifact = run(scenario("SIM-CHAIN-01", 11, store).expect("scenario"));
            assert_eq!(artifact.status, CaseStatus::Passed, "{artifact:#?}");
        }
    }

    #[test]
    fn deterministic_replay_has_the_same_fingerprint() {
        let artifact = run(scenario("SIM-REPLAY-01", 19, SimulatorStore::Fake).expect("scenario"));
        let replayed = replay(&artifact).expect("replay");
        assert_eq!(artifact.semantic_fingerprint, replayed.semantic_fingerprint);
    }

    #[test]
    fn queue_overflow_is_accounted_for() {
        let artifact = run(scenario("SIM-QUEUE-01", 23, SimulatorStore::Fake).expect("scenario"));
        assert_eq!(artifact.queue.offered, 24);
        assert_eq!(
            artifact.queue.admitted + artifact.queue.rejected,
            artifact.queue.offered
        );
        assert_eq!(artifact.queue.completed, artifact.queue.admitted);
        assert_eq!(artifact.queue.delivered, artifact.queue.completed);
        assert_eq!(artifact.queue.duplicated, 0);
        assert_eq!(artifact.queue.dropped, 0);
        assert_eq!(artifact.queue.max_depth, 8);
        assert!(artifact.queue.rejected > 0);
    }

    #[test]
    fn faulty_adapter_cases_are_detected() {
        for id in [
            "SIM-ORACLE-01",
            "SIM-ORACLE-02",
            "SIM-ORACLE-03",
            "SIM-ORACLE-04",
        ] {
            let artifact = run(scenario(id, 29, SimulatorStore::Fake).expect("scenario"));
            assert_eq!(artifact.status, CaseStatus::Passed, "{id}: {artifact:#?}");
            assert!(!artifact.oracle_findings.is_empty(), "{id}: {artifact:#?}");
            assert!(
                artifact
                    .host_checks
                    .iter()
                    .any(|check| check.check.starts_with("oracle-detects-") && check.passed),
                "{id}: {artifact:#?}"
            );
        }
    }

    #[test]
    fn stable_chain_ids_have_the_required_terminal_observation() {
        for (id, operation_id, outcome) in [
            ("SIM-CHAIN-01", "claim-2", "admitted"),
            ("SIM-CHAIN-02", "ack-1", "exact_replay"),
            ("SIM-CHAIN-03", "claim-1", "conflict"),
            ("SIM-CHAIN-04", "retrieve-after-revoke", "unauthorized"),
            ("SIM-CHAIN-05", "stale-retrieve", "unauthorized"),
            ("SIM-CHAIN-06", "rearm-1", "rearmed"),
            ("SIM-CHAIN-07", "rearm-1", "rearmed"),
            ("SIM-CHAIN-08", "omit-rearm", "inactive"),
            (
                "SIM-REPLAY-01",
                "controlled-early-rearm",
                "waiting_for_terminal",
            ),
        ] {
            let artifact = run(scenario(id, 37, SimulatorStore::Fake).expect(id));
            assert!(
                artifact.observations.iter().any(|observation| {
                    observation.operation_id == operation_id && observation.outcome == outcome
                }),
                "{id}: {artifact:#?}"
            );
        }
    }

    #[test]
    fn unknown_artifact_version_is_refused() {
        let mut artifact =
            run(scenario("SIM-CHAIN-01", 31, SimulatorStore::Fake).expect("scenario"));
        artifact.scenario.stimuli[0].version = "gearwit.sim/v2".to_owned();
        let root = std::env::temp_dir().join(format!("gearwit-sim-version-{}", std::process::id()));
        let path = root.join("artifact.json");
        write_artifact(&path, &artifact).expect("write");
        assert!(
            read_artifact(&path)
                .expect_err("version")
                .contains("unsupported")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runner_limit_is_incomplete() {
        let mut envelope = scenario("SIM-CHAIN-01", 41, SimulatorStore::Fake).expect("scenario");
        envelope.limits.max_events = 1;
        let artifact = run(envelope);
        assert_eq!(artifact.status, CaseStatus::Incomplete);
    }

    #[test]
    fn random_streams_are_separate_and_repeatable() {
        let first = scenario("SIM-QUEUE-01", 43, SimulatorStore::Fake).expect("scenario");
        let second = scenario("SIM-QUEUE-01", 43, SimulatorStore::Fake).expect("scenario");
        assert_eq!(first, second);
        let values = [
            first.seeds.source,
            first.seeds.actor,
            first.seeds.scheduler,
            first.seeds.fault,
        ];
        assert_eq!(values.iter().collect::<BTreeSet<_>>().len(), values.len());
    }
}
