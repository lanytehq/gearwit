//! Deterministic development simulator for Gearwit persistence chains.
//!
//! Production crates never depend on this crate. The simulator drives an
//! independent abstract oracle and invokes the admitted host fixture bridge
//! for the current fake and bundled `SQLite` baseline.

#![forbid(unsafe_code)]

use gearwit_host::simulator::{
    HostCheck, SimulatorStore, StoreStreamAction, StoreStreamAdapter, verify_crash_reopen,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const ARTIFACT_VERSION: &str = "gearwit.sim/v2";
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
    pub provenance_fingerprint: String,
    pub artifact_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Comparison {
    pub same_scenario: bool,
    pub same_semantics: bool,
    pub same_provenance: bool,
    pub left_status: CaseStatus,
    pub right_status: CaseStatus,
}

pub const MAX_CAMPAIGN_RUNS: usize = 256;
pub const MAX_CAMPAIGN_EVENTS: usize = 16_384;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CampaignManifest {
    pub version: String,
    pub seed: u64,
    pub runs: usize,
    pub store: SimulatorStore,
    pub max_total_events: usize,
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
        match case_id.rsplit('-').next() {
            Some("01") if case_id.contains("ORACLE") => Self::DuplicateAdmission,
            Some("02") if case_id.contains("ORACLE") => Self::LoseAcknowledgment,
            Some("03") if case_id.contains("ORACLE") => Self::ResurrectRevokedGrant,
            Some("04") if case_id.contains("ORACLE") => Self::FalsePublication,
            _ => Self::None,
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
    chain
}

/// Run a deterministic scenario and return a replayable artifact.
#[must_use]
pub fn run(envelope: ScenarioEnvelope) -> RunArtifact {
    let (observations, queue, mut host_checks, resource_limited) = execute_stream(&envelope);
    let runnable = envelope
        .stimuli
        .iter()
        .filter(|stimulus| {
            observations
                .iter()
                .any(|observation| observation.operation_id == stimulus.operation_id)
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut findings = if envelope.case_id == "SIM-QUEUE-01" {
        Vec::new()
    } else {
        oracle_findings(&runnable, &observations)
    };
    let case_findings = validate_observations(&envelope.case_id, &observations);
    findings.extend(case_findings.iter().cloned());
    if envelope.case_id != "SIM-QUEUE-01" && observations.len() != envelope.stimuli.len() {
        findings.push(format!(
            "mandatory stream completed {} of {} operations",
            observations.len(),
            envelope.stimuli.len()
        ));
    }
    let fault = FaultMode::for_case(&envelope.case_id);
    if fault != FaultMode::None {
        host_checks.push(HostCheck {
            store: envelope.store,
            check: format!("oracle-detects-{}", fault.name()),
            passed: !findings.is_empty(),
            detail: if findings.is_empty() {
                "deliberate adapter receipt violation escaped the independent oracle".to_owned()
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
    let status =
        if resource_limited || (envelope.case_id != "SIM-QUEUE-01" && observations.is_empty()) {
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
    finish_artifact(envelope, observations, host_checks, queue, findings, status)
}

#[allow(clippy::too_many_lines)] // Scheduler state is kept together so queue transitions stay auditable.
fn execute_stream(
    envelope: &ScenarioEnvelope,
) -> (Vec<Observation>, QueueAccounting, Vec<HostCheck>, bool) {
    let mut scheduled = envelope.stimuli.clone();
    scheduled.sort_by_key(|stimulus| (stimulus.due_tick, stimulus.sequence));
    let mut ready = VecDeque::new();
    let mut in_flight: Option<(u64, Stimulus)> = None;
    let mut completed_ids = BTreeSet::new();
    let mut offered = 0usize;
    let mut observations = Vec::new();
    let mut adapter = StoreStreamAdapter::new(envelope.store);
    let mut errors = Vec::new();
    let mut admitted = 0usize;
    let mut rejected = 0usize;
    let mut max_depth = 0usize;
    let service_ticks = usize::from(envelope.case_id == "SIM-QUEUE-01") as u64 * 2;
    let mut tick = 0u64;
    let mut resource_limited = false;

    while !scheduled.is_empty() || !ready.is_empty() || in_flight.is_some() {
        if tick > envelope.limits.max_virtual_tick
            || observations.len() >= envelope.limits.max_events
        {
            resource_limited = true;
            break;
        }

        if in_flight
            .as_ref()
            .is_some_and(|(complete_at, _)| *complete_at <= tick)
        {
            let (_, stimulus) = in_flight.take().expect("checked in-flight");
            complete_store_step(
                &mut adapter,
                &stimulus,
                FaultMode::for_case(&envelope.case_id),
                &mut observations,
                &mut completed_ids,
                &mut errors,
            );
        }

        let mut index = 0;
        while index < scheduled.len() {
            if scheduled[index].due_tick > tick {
                index += 1;
                continue;
            }
            let parent_ready = scheduled[index]
                .causal_parent
                .as_ref()
                .is_none_or(|parent| completed_ids.contains(parent));
            if !parent_ready {
                index += 1;
                continue;
            }
            let stimulus = scheduled.remove(index);
            offered += 1;
            let occupied = ready.len() + usize::from(in_flight.is_some());
            if occupied >= envelope.limits.queue_capacity {
                rejected += 1;
            } else {
                ready.push_back(stimulus);
                admitted += 1;
                max_depth = max_depth.max(ready.len() + usize::from(in_flight.is_some()));
            }
        }

        if service_ticks == 0 {
            while let Some(stimulus) = ready.pop_front() {
                if observations.len() >= envelope.limits.max_events {
                    resource_limited = true;
                    break;
                }
                complete_store_step(
                    &mut adapter,
                    &stimulus,
                    FaultMode::for_case(&envelope.case_id),
                    &mut observations,
                    &mut completed_ids,
                    &mut errors,
                );
            }
        } else if in_flight.is_none()
            && let Some(stimulus) = ready.pop_front()
        {
            in_flight = Some((tick.saturating_add(service_ticks), stimulus));
        }

        if resource_limited {
            break;
        }
        let next_scheduled = scheduled.iter().map(|item| item.due_tick).min();
        let next_completion = in_flight.as_ref().map(|(at, _)| *at);
        let next_tick = match (next_scheduled, next_completion, ready.is_empty()) {
            (_, _, false) => tick.saturating_add(1),
            (Some(scheduled), Some(completion), true) => scheduled.min(completion).max(tick + 1),
            (Some(scheduled), None, true) => scheduled.max(tick + 1),
            (None, Some(completion), true) => completion.max(tick + 1),
            (None, None, true) => break,
        };
        tick = next_tick;
    }

    if !scheduled.is_empty() || !ready.is_empty() || in_flight.is_some() {
        resource_limited = true;
    }
    let host_checks = vec![HostCheck {
        store: envelope.store,
        check: "resolved-store-stream".to_owned(),
        passed: errors.is_empty() && !observations.is_empty(),
        detail: if observations.is_empty() && errors.is_empty() {
            "no resolved operations reached the store".to_owned()
        } else if errors.is_empty() {
            format!(
                "{} resolved operations executed against one stateful store",
                observations.len()
            )
        } else {
            errors.join("; ")
        },
    }];
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
            max_depth,
        },
        host_checks,
        resource_limited,
    )
}

fn complete_store_step(
    adapter: &mut StoreStreamAdapter,
    stimulus: &Stimulus,
    fault: FaultMode,
    observations: &mut Vec<Observation>,
    completed_ids: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    let action = store_action(&stimulus.action);
    match adapter.apply(&stimulus.operation_id, &action) {
        Ok(receipt) => {
            let mut observation = Observation {
                version: ARTIFACT_VERSION.to_owned(),
                operation_id: stimulus.operation_id.clone(),
                outcome: receipt.outcome,
                logical_effects: receipt.logical_effects,
                authority_revision: receipt.authority_revision,
            };
            inject_receipt_fault(fault, &stimulus.action, &mut observation);
            completed_ids.insert(stimulus.operation_id.clone());
            observations.push(observation);
        }
        Err(error) => errors.push(format!("{}: {error}", stimulus.operation_id)),
    }
}

fn store_action(action: &Action) -> StoreStreamAction {
    match action {
        Action::Arm => StoreStreamAction::Arm,
        Action::Offer { event } => StoreStreamAction::Offer {
            event: event.clone(),
        },
        Action::Admit { event } => StoreStreamAction::Admit {
            event: event.clone(),
        },
        Action::Retrieve { request } => StoreStreamAction::Retrieve {
            request: request.clone(),
        },
        Action::StaleRetrieve { request } => StoreStreamAction::StaleRetrieve {
            request: request.clone(),
        },
        Action::Acknowledge { request } => StoreStreamAction::Acknowledge {
            request: request.clone(),
        },
        Action::Terminal => StoreStreamAction::Terminal,
        Action::Rearm => StoreStreamAction::Rearm,
        Action::Revoke => StoreStreamAction::Revoke,
        Action::Restart => StoreStreamAction::Restart,
        Action::OmitRearm => StoreStreamAction::OmitRearm,
    }
}

fn inject_receipt_fault(fault: FaultMode, action: &Action, observation: &mut Observation) {
    match (fault, action) {
        (FaultMode::DuplicateAdmission, Action::Admit { .. }) => {
            observation.logical_effects = observation.logical_effects.saturating_add(1);
        }
        (FaultMode::LoseAcknowledgment, Action::Restart) => {
            observation.authority_revision = observation.authority_revision.saturating_sub(1);
        }
        (
            FaultMode::ResurrectRevokedGrant,
            Action::Retrieve { .. } | Action::StaleRetrieve { .. },
        ) => {
            "retrieved".clone_into(&mut observation.outcome);
        }
        (FaultMode::FalsePublication, Action::Acknowledge { .. }) => {
            observation.authority_revision = observation.authority_revision.saturating_add(1);
        }
        _ => {}
    }
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
    if case_id == "SIM-CHAIN-01" && effects != 1 {
        findings.push(format!(
            "complete chain admitted {effects} logical effects, expected 1"
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
    let platform = PlatformPin {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        simulator_version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    let semantic_fingerprint =
        semantic_fingerprint(&envelope, &observations, &queue, &oracle_findings, status);
    let provenance_fingerprint = provenance_fingerprint(&run_id, &envelope, &platform);
    let mut artifact = RunArtifact {
        version: ARTIFACT_VERSION.to_owned(),
        run_id,
        oracle_version: ORACLE_VERSION.to_owned(),
        scenario: envelope,
        platform,
        observations,
        host_checks,
        queue,
        oracle_findings,
        status,
        semantic_fingerprint,
        provenance_fingerprint,
        artifact_digest: String::new(),
    };
    artifact.artifact_digest = artifact_digest(&artifact);
    artifact
}

fn semantic_fingerprint(
    envelope: &ScenarioEnvelope,
    observations: &[Observation],
    queue: &QueueAccounting,
    findings: &[String],
    status: CaseStatus,
) -> String {
    let bytes = serde_json::to_vec(&(
        &envelope.version,
        &envelope.case_id,
        envelope.seed,
        &envelope.seeds,
        &envelope.limits,
        &envelope.stimuli,
        observations,
        queue,
        findings,
        status,
    ))
    .expect("serializable simulator state");
    blake3::hash(&bytes).to_hex().to_string()
}

fn provenance_fingerprint(
    run_id: &str,
    envelope: &ScenarioEnvelope,
    platform: &PlatformPin,
) -> String {
    let bytes = serde_json::to_vec(&(run_id, envelope.store, platform))
        .expect("serializable simulator provenance");
    blake3::hash(&bytes).to_hex().to_string()
}

fn artifact_digest(artifact: &RunArtifact) -> String {
    let bytes = serde_json::to_vec(&(
        &artifact.version,
        &artifact.run_id,
        &artifact.oracle_version,
        &artifact.scenario,
        &artifact.platform,
        &artifact.observations,
        &artifact.host_checks,
        &artifact.queue,
        &artifact.oracle_findings,
        artifact.status,
        &artifact.semantic_fingerprint,
        &artifact.provenance_fingerprint,
    ))
    .expect("serializable artifact integrity fields");
    blake3::hash(&bytes).to_hex().to_string()
}

fn validate_artifact(artifact: &RunArtifact) -> Result<(), String> {
    let expected_semantic = semantic_fingerprint(
        &artifact.scenario,
        &artifact.observations,
        &artifact.queue,
        &artifact.oracle_findings,
        artifact.status,
    );
    if artifact.semantic_fingerprint != expected_semantic {
        return Err("artifact semantic fingerprint is stale".to_owned());
    }
    let expected_provenance =
        provenance_fingerprint(&artifact.run_id, &artifact.scenario, &artifact.platform);
    if artifact.provenance_fingerprint != expected_provenance {
        return Err("artifact provenance fingerprint is stale".to_owned());
    }
    if artifact.artifact_digest != artifact_digest(artifact) {
        return Err("artifact integrity digest is stale".to_owned());
    }
    Ok(())
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
    validate_artifact(&artifact)?;
    Ok(artifact)
}

/// Deterministically replay an artifact and require the same semantic result.
///
/// # Errors
///
/// Returns an error when the case requires a real child process or when the
/// replay produces a different semantic fingerprint.
pub fn replay(artifact: &RunArtifact) -> Result<RunArtifact, String> {
    validate_artifact(artifact)?;
    if matches!(
        artifact.scenario.case_id.as_str(),
        "SIM-CHAIN-07" | "SIM-PROC-01"
    ) {
        return Err("process case requires a new real child run".to_owned());
    }
    let replayed = run(artifact.scenario.clone());
    if replayed.semantic_fingerprint != artifact.semantic_fingerprint {
        return Err("semantic replay fingerprint differed".to_owned());
    }
    Ok(replayed)
}

/// Compare validated semantic results and their separate provenance identity.
///
/// # Errors
///
/// Returns an error if either in-memory artifact fails its integrity checks.
pub fn compare(left: &RunArtifact, right: &RunArtifact) -> Result<Comparison, String> {
    validate_artifact(left)?;
    validate_artifact(right)?;
    Ok(Comparison {
        same_scenario: left.scenario == right.scenario,
        same_semantics: left.semantic_fingerprint == right.semantic_fingerprint,
        same_provenance: left.provenance_fingerprint == right.provenance_fingerprint,
        left_status: left.status,
        right_status: right.status,
    })
}

/// Resolve a bounded campaign before any adapter work begins.
///
/// # Errors
///
/// Returns an error when the requested run or aggregate event budget is too
/// large.
///
/// # Panics
///
/// Panics only if the compile-time stable case catalog is empty or contains an
/// id rejected by [`scenario`].
pub fn campaign_envelopes(
    seed: u64,
    runs: usize,
    store: SimulatorStore,
) -> Result<Vec<ScenarioEnvelope>, String> {
    if runs > MAX_CAMPAIGN_RUNS {
        return Err(format!("campaign exceeds {MAX_CAMPAIGN_RUNS} run limit"));
    }
    let mut source = SplitMix64(seed ^ 0x736f_7572_6365);
    let mut schedule = SplitMix64(seed ^ 0x7363_6865_6475_6c65);
    let candidates = CASE_IDS
        .iter()
        .copied()
        .filter(|id| !matches!(*id, "SIM-CHAIN-07" | "SIM-PROC-01"))
        .collect::<Vec<_>>();
    let envelopes = (0..runs)
        .map(|run_index| {
            let run_seed = schedule.next();
            if run_index % 2 == 0 {
                return generated_chain(run_seed, store);
            }
            let index = usize::try_from(
                source.next() % u64::try_from(candidates.len()).expect("case count"),
            )
            .expect("bounded index");
            let case_id = candidates[index];
            scenario(case_id, run_seed, store).expect("catalog id")
        })
        .collect::<Vec<_>>();
    let total_events = envelopes
        .iter()
        .map(|envelope| envelope.stimuli.len())
        .sum::<usize>();
    if total_events > MAX_CAMPAIGN_EVENTS {
        return Err(format!(
            "campaign resolves {total_events} events, exceeding {MAX_CAMPAIGN_EVENTS} event limit"
        ));
    }
    Ok(envelopes)
}

fn generated_chain(seed: u64, store: SimulatorStore) -> ScenarioEnvelope {
    let seeds = derive_seeds(seed);
    let event = format!("event-{:016x}", seeds.actor);
    let retrieve = format!("retrieve-{:016x}", seeds.actor);
    let acknowledge = format!("ack-{:016x}", seeds.actor);
    let mut stimuli = first_acknowledged_chain(&event, &retrieve, &acknowledge);
    let cycles = 2 + usize::try_from(seeds.source % 3).expect("bounded cycles");
    let mut sequence = 6u64;
    for _ in 0..cycles {
        stimuli.push(stimulus(
            sequence,
            sequence,
            &format!("restart-{sequence}"),
            Action::Restart,
        ));
        sequence += 1;
        stimuli.push(stimulus(
            sequence,
            sequence,
            "retrieve-1",
            Action::Retrieve {
                request: retrieve.clone(),
            },
        ));
        sequence += 1;
        stimuli.push(stimulus(
            sequence,
            sequence,
            "ack-1",
            Action::Acknowledge {
                request: acknowledge.clone(),
            },
        ));
        sequence += 1;
    }
    stimuli.push(stimulus(
        sequence,
        sequence,
        "terminal-generated",
        Action::Terminal,
    ));
    sequence += 1;
    stimuli.push(stimulus(
        sequence,
        sequence,
        "rearm-generated",
        Action::Rearm,
    ));
    let mut prior = None;
    let mut scheduler = SplitMix64(seeds.scheduler);
    let mut due = 0u64;
    for item in &mut stimuli {
        due = due.saturating_add(1 + scheduler.next() % 3);
        item.due_tick = due;
        item.causal_parent.clone_from(&prior);
        prior = Some(item.operation_id.clone());
    }
    let fault_index = seeds.fault % 5;
    let case_id = if fault_index == 0 {
        "SIM-GENERATED-NORMAL".to_owned()
    } else {
        format!("SIM-GENERATED-ORACLE-{fault_index:02}")
    };
    ScenarioEnvelope {
        version: ARTIFACT_VERSION.to_owned(),
        case_id,
        seed,
        seeds,
        store,
        limits: RunLimits::default(),
        stimuli,
    }
}

/// Run a seeded campaign through the shared store stream adapter.
///
/// # Errors
///
/// Returns an error when campaign resolution exceeds a resource budget.
pub fn campaign(seed: u64, runs: usize, store: SimulatorStore) -> Result<Vec<RunArtifact>, String> {
    Ok(campaign_envelopes(seed, runs, store)?
        .into_iter()
        .map(run)
        .collect())
}

#[must_use]
pub fn campaign_manifest(seed: u64, runs: usize, store: SimulatorStore) -> CampaignManifest {
    CampaignManifest {
        version: ARTIFACT_VERSION.to_owned(),
        seed,
        runs,
        store,
        max_total_events: MAX_CAMPAIGN_EVENTS,
    }
}

/// Save campaign identity and aggregate limits before executing its first run.
///
/// # Errors
///
/// Returns an error if the output directory cannot be created or the manifest
/// cannot be serialized or written.
pub fn write_campaign_manifest(root: &Path, manifest: &CampaignManifest) -> Result<(), String> {
    fs::create_dir_all(root).map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec_pretty(manifest).map_err(|error| error.to_string())?;
    fs::write(root.join("campaign-manifest.json"), bytes).map_err(|error| error.to_string())
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
    fn campaigns_exclude_process_cases_and_replay_refuses_them() {
        let results = campaign(20, 128, SimulatorStore::Fake).expect("campaign");
        assert!(results.iter().all(|artifact| !matches!(
            artifact.scenario.case_id.as_str(),
            "SIM-CHAIN-07" | "SIM-PROC-01"
        )));
        for id in ["SIM-CHAIN-07", "SIM-PROC-01"] {
            let artifact = run(scenario(id, 21, SimulatorStore::Sqlite).expect(id));
            assert!(
                replay(&artifact)
                    .expect_err("process replay")
                    .contains("real child")
            );
        }
    }

    #[test]
    fn named_chain_checks_execute_on_each_selected_store() {
        for id in [
            "SIM-CHAIN-02",
            "SIM-CHAIN-03",
            "SIM-CHAIN-04",
            "SIM-CHAIN-05",
            "SIM-CHAIN-06",
            "SIM-CHAIN-08",
        ] {
            for store in [SimulatorStore::Fake, SimulatorStore::Sqlite] {
                let artifact = run(scenario(id, 22, store).expect(id));
                let check = artifact.host_checks.first().expect("store stream check");
                assert_eq!(check.check, "resolved-store-stream");
                assert!(check.passed, "{id}/{store:?}: {check:?}");
                assert!(
                    check.detail.contains("stateful store"),
                    "{id}/{store:?}: {check:?}"
                );
            }
        }
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
            ("SIM-CHAIN-01", "rearm-1", "rearmed"),
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
        artifact.scenario.stimuli[0].version = "gearwit.sim/v3".to_owned();
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

    #[test]
    fn empty_or_reduced_mandatory_stream_cannot_pass_fixed_store_evidence() {
        let mut empty = scenario("SIM-CHAIN-03", 47, SimulatorStore::Sqlite).expect("scenario");
        empty.stimuli.clear();
        let empty_result = run(empty);
        assert_eq!(empty_result.status, CaseStatus::Incomplete);
        assert!(empty_result.observations.is_empty());
        assert!(empty_result.host_checks.iter().all(|check| !check.passed));

        let complete =
            run(scenario("SIM-CHAIN-03", 47, SimulatorStore::Sqlite).expect("complete scenario"));
        let mut reduced =
            scenario("SIM-CHAIN-03", 47, SimulatorStore::Sqlite).expect("reduced scenario");
        reduced.stimuli.pop();
        let reduced = run(reduced);
        assert_ne!(complete.semantic_fingerprint, reduced.semantic_fingerprint);
        assert_eq!(reduced.status, CaseStatus::Failed);
        assert_eq!(
            reduced.observations.last().expect("trace").outcome,
            "reopened"
        );
    }

    #[test]
    fn injected_store_receipt_violation_reaches_the_oracle() {
        let result =
            run(scenario("SIM-ORACLE-01", 49, SimulatorStore::Sqlite).expect("fault scenario"));
        assert_eq!(result.status, CaseStatus::Passed);
        assert!(result.host_checks[0].passed);
        assert!(
            result
                .oracle_findings
                .iter()
                .any(|finding| finding.contains("logical") || finding.contains("effects="))
        );
    }

    #[test]
    fn scheduled_arrivals_do_not_consume_transport_capacity_early() {
        let mut envelope = scenario("SIM-CHAIN-01", 51, SimulatorStore::Fake).expect("scenario");
        envelope.limits.queue_capacity = 1;
        for (index, item) in envelope.stimuli.iter_mut().enumerate() {
            item.due_tick = u64::try_from(index).expect("index") * 100;
        }
        let result = run(envelope);
        assert_eq!(result.status, CaseStatus::Passed, "{result:#?}");
        assert_eq!(result.queue.rejected, 0);
        assert_eq!(result.queue.max_depth, 1);
    }

    #[test]
    fn slow_adapter_accumulates_and_accounts_for_backlog() {
        let mut envelope = scenario("SIM-QUEUE-01", 53, SimulatorStore::Fake).expect("scenario");
        envelope.limits.queue_capacity = 2;
        for item in &mut envelope.stimuli {
            item.due_tick = 0;
        }
        let result = run(envelope);
        assert_eq!(result.queue.offered, envelope_len_for_queue_test());
        assert!(result.queue.rejected > 0);
        assert_eq!(
            result.queue.admitted + result.queue.rejected,
            result.queue.offered
        );
        assert_eq!(result.queue.completed, result.queue.admitted);
        assert_eq!(result.queue.max_depth, 2);
    }

    fn envelope_len_for_queue_test() -> usize {
        24
    }

    #[test]
    fn generated_campaigns_are_bounded_multicycle_and_repeatable() {
        let first = campaign_envelopes(59, 12, SimulatorStore::Fake).expect("campaign");
        let second = campaign_envelopes(59, 12, SimulatorStore::Fake).expect("campaign");
        assert_eq!(first, second);
        let generated = first
            .iter()
            .filter(|envelope| envelope.case_id.starts_with("SIM-GENERATED-"))
            .collect::<Vec<_>>();
        assert_eq!(generated.len(), 6);
        assert!(generated.iter().all(|envelope| {
            envelope
                .stimuli
                .iter()
                .filter(|item| matches!(item.action, Action::Restart))
                .count()
                >= 2
        }));
        assert!(
            generated
                .iter()
                .any(|envelope| envelope.case_id.contains("ORACLE"))
        );
        let first_results = first.into_iter().map(run).collect::<Vec<_>>();
        let second_results = second.into_iter().map(run).collect::<Vec<_>>();
        assert_eq!(
            first_results
                .iter()
                .map(|item| &item.semantic_fingerprint)
                .collect::<Vec<_>>(),
            second_results
                .iter()
                .map(|item| &item.semantic_fingerprint)
                .collect::<Vec<_>>()
        );
        assert!(
            first_results
                .iter()
                .all(|result| result.status == CaseStatus::Passed)
        );
    }

    #[test]
    fn artifact_integrity_covers_verdict_findings_and_observations() {
        let artifact = run(scenario("SIM-CHAIN-01", 61, SimulatorStore::Fake).expect("scenario"));
        let mut tampered = artifact.clone();
        tampered.status = CaseStatus::Failed;
        tampered.oracle_findings.push("edited finding".to_owned());
        tampered.observations.clear();
        assert!(
            replay(&tampered)
                .expect_err("tampered replay")
                .contains("stale")
        );
        assert!(
            compare(&artifact, &tampered)
                .expect_err("tampered comparison")
                .contains("stale")
        );

        let root =
            std::env::temp_dir().join(format!("gearwit-sim-integrity-{}", std::process::id()));
        let path = root.join("artifact.json");
        write_artifact(&path, &tampered).expect("write tampered fixture");
        assert!(
            read_artifact(&path)
                .expect_err("tampered read")
                .contains("stale")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn semantic_equivalence_is_distinct_from_provenance() {
        let fake = run(scenario("SIM-CHAIN-01", 67, SimulatorStore::Fake).expect("fake scenario"));
        let sqlite =
            run(scenario("SIM-CHAIN-01", 67, SimulatorStore::Sqlite).expect("sqlite scenario"));
        let comparison = compare(&fake, &sqlite).expect("valid comparison");
        assert!(!comparison.same_scenario);
        assert!(comparison.same_semantics);
        assert!(!comparison.same_provenance);
    }

    #[test]
    fn campaign_manifest_can_be_saved_before_execution() {
        let root =
            std::env::temp_dir().join(format!("gearwit-sim-manifest-{}", std::process::id()));
        let manifest = campaign_manifest(71, 8, SimulatorStore::Fake);
        write_campaign_manifest(&root, &manifest).expect("manifest");
        let saved: CampaignManifest = serde_json::from_slice(
            &fs::read(root.join("campaign-manifest.json")).expect("saved manifest"),
        )
        .expect("manifest json");
        assert_eq!(saved, manifest);
        assert!(campaign_envelopes(71, MAX_CAMPAIGN_RUNS + 1, SimulatorStore::Fake).is_err());
        let _ = fs::remove_dir_all(root);
    }
}
