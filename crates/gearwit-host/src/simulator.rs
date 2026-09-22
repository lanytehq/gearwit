//! Development-only bridge for the Gearwit simulator.
//!
//! This module is absent unless the `simulator` feature is selected. It keeps
//! fixture construction and fault controls out of production host surfaces.

use crate::conformance::{self, ConformanceFixture, FakeFixture, Prepared};
use crate::controller::{NativeTurnFact, PrivateNativeRef, TerminalClass};
use crate::persist::{
    IdempotentResult, Persist, PersistError, PersistedNativeTurnFacts, RearmJoinResult,
    RearmJoinScope,
};
use crate::sqlite_baseline::{self, SqliteBaseline};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Admitted synthetic stores. Neither variant is a production provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulatorStore {
    Fake,
    Sqlite,
}

/// Result of an executable host check.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostCheck {
    pub store: SimulatorStore,
    pub check: String,
    pub passed: bool,
    pub detail: String,
}

/// Execute one stable persistence conformance case.
#[must_use]
pub fn run_conformance(store: SimulatorStore, case_id: &str) -> HostCheck {
    let result = match store {
        SimulatorStore::Fake => conformance::execute::<FakeFixture>(case_id),
        SimulatorStore::Sqlite => conformance::execute::<SqliteBaseline>(case_id),
    };
    match result {
        Ok(()) => HostCheck {
            store,
            check: case_id.to_owned(),
            passed: true,
            detail: "passed".to_owned(),
        },
        Err(detail) => HostCheck {
            store,
            check: case_id.to_owned(),
            passed: false,
            detail,
        },
    }
}

/// Execute a complete retrieve/materialize/ack/restart/rearm chain.
#[must_use]
pub fn run_complete_chain(store: SimulatorStore) -> HostCheck {
    let result = match store {
        SimulatorStore::Fake => complete_chain::<FakeFixture>(),
        SimulatorStore::Sqlite => complete_chain::<SqliteBaseline>(),
    };
    match result {
        Ok(()) => HostCheck {
            store,
            check: "complete-chain".to_owned(),
            passed: true,
            detail: "passed".to_owned(),
        },
        Err(detail) => HostCheck {
            store,
            check: "complete-chain".to_owned(),
            passed: false,
            detail,
        },
    }
}

fn complete_chain<F: ConformanceFixture>() -> Result<(), String> {
    let Prepared {
        mut store, binding, ..
    } = F::prepare();
    let exchange = conformance::retrieve_for(&binding, 101);
    let authorized = match store
        .record_retrieve_exchange(&exchange)
        .map_err(debug_error)?
    {
        IdempotentResult::Recorded(authorized) => authorized,
        IdempotentResult::ExactReplay(_) => return Err("first retrieve replayed".to_owned()),
    };
    let payload = store
        .materialize_claimed_batch(&binding, authorized.permit)
        .map_err(debug_error)?;
    if payload.events.as_slice().len() != 2 {
        return Err("materialized payload count differed".to_owned());
    }
    let ack = conformance::ack_for(&binding, &authorized.recorded.retrieval_id, "event-b", 102);
    if !matches!(
        store
            .acknowledge_retrieved_batch(&binding, &ack)
            .map_err(debug_error)?,
        IdempotentResult::Recorded(_)
    ) {
        return Err("first acknowledgment replayed".to_owned());
    }
    let payloads = F::payloads(&store);
    let mut snapshot = store.recover_authority_state().map_err(debug_error)?;
    snapshot.native_turn_facts = vec![PersistedNativeTurnFacts {
        attempt_id: binding.attempt_id.clone(),
        facts: vec![NativeTurnFact::Terminal {
            turn_ref: PrivateNativeRef::fixture(71),
            class: TerminalClass::Succeeded,
        }],
    }];
    let mut reopened = F::admit_snapshot(snapshot, payloads).map_err(debug_error)?;
    match reopened
        .record_retrieve_exchange(&exchange)
        .map_err(debug_error)?
    {
        IdempotentResult::ExactReplay(replayed) if replayed.recorded == authorized.recorded => {}
        other => return Err(format!("retrieve did not replay after reopen: {other:?}")),
    }
    let scope = RearmJoinScope {
        arm_id: binding.arm_id.clone(),
        generation: binding.generation,
        attempt_id: binding.attempt_id.clone(),
        signal_id: binding.signal_id.clone(),
    };
    match reopened.try_rearm_join(scope).map_err(debug_error)? {
        RearmJoinResult::Rearmed => Ok(()),
        other => Err(format!("complete chain did not rearm: {other:?}")),
    }
}

fn debug_error(error: PersistError) -> String {
    format!("{error:?}")
}

/// Run the `SQLite` writer side of a real process-crash scenario.
///
/// The caller must execute this in a child process and terminate it after the
/// requested milestone file appears.
///
/// # Errors
///
/// Returns an error when the phase is unknown or fixture preparation fails.
pub fn run_crash_child(path: &Path, phase: &str) -> Result<(), String> {
    sqlite_baseline::run_simulator_crash_child(path, phase)
}

/// Reopen and verify media left by a killed simulator child.
///
/// # Errors
///
/// Returns an error when the committed state cannot be recovered exactly.
pub fn verify_crash_reopen(path: &Path) -> Result<(), String> {
    sqlite_baseline::verify_simulator_crash_reopen(path)
}
