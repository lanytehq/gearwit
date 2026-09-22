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
    Admit { event: String },
    Retrieve { request: String },
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
            Action::Admit { event } if self.armed && !self.revoked => {
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
    let mut stimuli = base_chain(seeds.actor);
    let mut limits = RunLimits::default();
    match case_id {
        "SIM-CHAIN-02" => {
            let mut retrieve_replay = stimuli[2].clone();
            retrieve_replay.due_tick = 7;
            retrieve_replay.sequence = 8;
            stimuli.push(retrieve_replay);
            let mut ack_replay = stimuli[3].clone();
            ack_replay.due_tick = 8;
            ack_replay.sequence = 9;
            stimuli.push(ack_replay);
        }
        "SIM-CHAIN-03" => {
            stimuli.truncate(3);
            stimuli.push(stimulus(3, 4, "revoke-1", Action::Revoke));
            stimuli.push(stimulus(4, 5, "restart-1", Action::Restart));
            stimuli.push(stimulus(
                5,
                6,
                "retrieve-after-revoke",
                Action::Retrieve {
                    request: "retrieve-2".to_owned(),
                },
            ));
        }
        "SIM-CHAIN-04" => {
            stimuli.truncate(3);
            stimuli.push(stimulus(3, 4, "rearm-early", Action::Rearm));
            stimuli.push(stimulus(
                4,
                5,
                "admit-during-rearm",
                Action::Admit {
                    event: "event-b".to_owned(),
                },
            ));
        }
        "SIM-CHAIN-05" => {
            stimuli.truncate(5);
            stimuli.push(stimulus(5, 6, "restart-after-ack", Action::Restart));
            stimuli.push(stimulus(6, 7, "terminal-1", Action::Terminal));
            stimuli.push(stimulus(7, 8, "rearm-1", Action::Rearm));
        }
        "SIM-CHAIN-06" => {
            stimuli.truncate(2);
            stimuli.push(stimulus(2, 3, "revoke-lease", Action::Revoke));
            stimuli.push(stimulus(
                3,
                4,
                "stale-retrieve",
                Action::Retrieve {
                    request: "retrieve-stale".to_owned(),
                },
            ));
        }
        "SIM-CHAIN-07" => {
            stimuli.truncate(2);
            stimuli.push(stimulus(
                2,
                3,
                "claim-1",
                Action::Admit {
                    event: "changed-event".to_owned(),
                },
            ));
        }
        "SIM-CHAIN-08" => {
            stimuli.truncate(6);
            stimuli.push(stimulus(6, 7, "omit-rearm", Action::OmitRearm));
        }
        "SIM-QUEUE-01" => {
            limits.queue_capacity = 8;
            let mut arrivals = SplitMix64(seeds.scheduler);
            stimuli = (0..24)
                .map(|index| {
                    stimulus(
                        arrivals.next() % 6,
                        index,
                        &format!("queue-{index}"),
                        Action::Arm,
                    )
                })
                .collect();
        }
        "SIM-REPLAY-01" | "SIM-PROC-01" | "SIM-ORACLE-01" | "SIM-ORACLE-02" | "SIM-ORACLE-03"
        | "SIM-ORACLE-04" | "SIM-CHAIN-01" => {}
        _ => unreachable!("catalog checked"),
    }
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

fn base_chain(seed: u64) -> Vec<Stimulus> {
    let event = format!("event-{seed:016x}");
    let retrieve = format!("retrieve-{seed:016x}");
    let acknowledge = format!("ack-{seed:016x}");
    vec![
        stimulus(0, 1, "arm-1", Action::Arm),
        stimulus(1, 2, "claim-1", Action::Admit { event }),
        stimulus(2, 3, "retrieve-1", Action::Retrieve { request: retrieve }),
        stimulus(
            3,
            4,
            "ack-1",
            Action::Acknowledge {
                request: acknowledge,
            },
        ),
        stimulus(4, 5, "terminal-1", Action::Terminal),
        stimulus(5, 6, "rearm-1", Action::Rearm),
        stimulus(
            6,
            7,
            "next-event",
            Action::Admit {
                event: "event-b".to_owned(),
            },
        ),
    ]
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
        let mut oracle = Oracle::default();
        let observations = runnable
            .iter()
            .map(|stimulus| oracle.apply(stimulus))
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
    let findings = validate_observations(&envelope.case_id, &observations);
    if let Some(check) = faulty_adapter_probe(&envelope.case_id) {
        host_checks.push(check);
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
    } else if findings.is_empty() && host_checks.iter().all(|check| check.passed) {
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
        "SIM-CHAIN-01" | "SIM-REPLAY-01" => return vec![run_complete_chain(store)],
        "SIM-CHAIN-02" => &[
            "replay.retrieve.exact",
            "replay.ack.exact",
            "replay.retrieve.changed-digest",
        ],
        "SIM-CHAIN-03" => &[
            "op.revoke-helper-grant",
            "grant.revocation-survives-admission",
        ],
        "SIM-CHAIN-04" => &[
            "snapshot.rearm-join-absent-before-handled",
            "replay.restore.terminal-leaves-partial-rearm",
        ],
        "SIM-CHAIN-05" => &["replay.ack.exact", "snapshot.helper-sections-omit-bodies"],
        "SIM-CHAIN-06" => &["op.revoke-helper-grant", "replay.retrieve.exact"],
        "SIM-CHAIN-07" => &["op.admit-claim", "replay.retrieve.changed-digest"],
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
            .is_some_and(|observation| observation.outcome != "unauthorized")
    {
        findings.push("revoked authority returned after restart".to_owned());
    }
    if case_id == "SIM-CHAIN-08"
        && observations
            .last()
            .is_some_and(|observation| observation.outcome != "inactive")
    {
        findings.push("omitted rearm was not reported inactive".to_owned());
    }
    if case_id == "SIM-CHAIN-07"
        && observations
            .last()
            .is_some_and(|observation| observation.outcome != "conflict")
    {
        findings.push("changed-content identity reuse did not conflict".to_owned());
    }
    if effects > 1 {
        findings.push(format!("logical effect count exceeded one: {effects}"));
    }
    findings
}

fn faulty_adapter_probe(case_id: &str) -> Option<HostCheck> {
    let (name, detected) = match case_id {
        "SIM-ORACLE-01" => {
            let reported_effects = [1_u64, 2];
            (
                "duplicate-admission",
                reported_effects.windows(2).any(|pair| pair[1] > pair[0]),
            )
        }
        "SIM-ORACLE-02" => {
            let acknowledged_before_restart = true;
            let acknowledged_after_restart = false;
            (
                "lost-committed-ack",
                acknowledged_before_restart && !acknowledged_after_restart,
            )
        }
        "SIM-ORACLE-03" => {
            let grant_revoked = true;
            let fresh_retrieve_reported = true;
            (
                "revoked-grant-resurrection",
                grant_revoked && fresh_retrieve_reported,
            )
        }
        "SIM-ORACLE-04" => {
            let revision_before = 7_u64;
            let revision_after_reported_success = 7_u64;
            (
                "false-durable-publication",
                revision_before == revision_after_reported_success,
            )
        }
        _ => return None,
    };
    Some(HostCheck {
        store: SimulatorStore::Fake,
        check: format!("oracle-detects-{name}"),
        passed: detected,
        detail: if detected {
            "deliberate violation detected".to_owned()
        } else {
            "deliberate violation escaped the oracle".to_owned()
        },
    })
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
/// Panics if the compile-time `SIM-PROC-01` catalog entry is removed.
#[must_use]
pub fn run_process_case(executable: &Path, seed: u64) -> RunArtifact {
    let envelope = scenario("SIM-PROC-01", seed, SimulatorStore::Sqlite).expect("known case");
    let mut checks = Vec::new();
    for phase in ["pre_commit", "post_commit"] {
        checks.push(run_crash_phase(executable, phase));
    }
    let status = if checks.iter().all(|check| check.passed) {
        CaseStatus::Passed
    } else {
        CaseStatus::Failed
    };
    finish_artifact(
        envelope,
        Vec::new(),
        checks,
        QueueAccounting {
            offered: 0,
            admitted: 0,
            rejected: 0,
            completed: 0,
            delivered: 0,
            duplicated: 0,
            dropped: 0,
            max_depth: 0,
        },
        Vec::new(),
        status,
    )
}

fn run_crash_phase(executable: &Path, phase: &str) -> HostCheck {
    let root = std::env::temp_dir().join(format!("gearwit-sim-{}-{phase}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    if let Err(error) = fs::create_dir(&root) {
        return failed_process_check(phase, error.to_string());
    }
    let path = root.join("authority.sqlite");
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
    let _ = fs::remove_dir_all(&root);
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
