//! Local command surface for deterministic Gearwit simulation.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand, ValueEnum};
use gearwit_host::simulator::{SimulatorStore, run_crash_child};
use gearwit_sim::{
    CaseStatus, campaign, compare, default_artifact_path, read_artifact, replay, run,
    run_process_case, scenario, write_artifact,
};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "gearwit-sim",
    about = "Deterministic Gearwit development simulator"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run one stable scenario id.
    Scenario {
        #[arg(long)]
        id: String,
        #[arg(long, value_enum, default_value_t = StoreArg::Fake)]
        store: StoreArg,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long)]
        root: PathBuf,
    },
    /// Run a bounded seeded campaign and save every replay bundle.
    Campaign {
        #[arg(long)]
        seed: u64,
        #[arg(long, default_value_t = 16)]
        runs: usize,
        #[arg(long, value_enum, default_value_t = StoreArg::Fake)]
        store: StoreArg,
        #[arg(long)]
        root: PathBuf,
    },
    /// Replay a saved bundle and require the same semantic fingerprint.
    Replay {
        #[arg(long)]
        bundle: PathBuf,
    },
    /// Compare two saved result bundles.
    Compare {
        #[arg(long)]
        left: PathBuf,
        #[arg(long)]
        right: PathBuf,
    },
    #[command(name = "__crash-child", hide = true)]
    CrashChild {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        phase: String,
    },
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum StoreArg {
    #[default]
    Fake,
    Sqlite,
}

impl From<StoreArg> for SimulatorStore {
    fn from(value: StoreArg) -> Self {
        match value {
            StoreArg::Fake => Self::Fake,
            StoreArg::Sqlite => Self::Sqlite,
        }
    }
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("gearwit-sim: {error}");
            ExitCode::from(2)
        }
    }
}

fn execute(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Command::Scenario {
            id,
            store,
            seed,
            root,
        } => {
            let result = if matches!(id.as_str(), "SIM-CHAIN-07" | "SIM-PROC-01") {
                run_process_case(
                    &std::env::current_exe().map_err(|error| error.to_string())?,
                    seed,
                    &id,
                    &root,
                )
            } else {
                run(scenario(&id, seed, store.into())?)
            };
            write_artifact(&default_artifact_path(&root, &result), &result)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&result).map_err(|error| error.to_string())?
            );
            Ok(exit_for(result.status))
        }
        Command::Campaign {
            seed,
            runs,
            store,
            root,
        } => {
            let results = campaign(seed, runs, store.into());
            for result in &results {
                write_artifact(&default_artifact_path(&root, result), result)?;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&results).map_err(|error| error.to_string())?
            );
            let status = if results
                .iter()
                .all(|result| result.status == CaseStatus::Passed)
            {
                CaseStatus::Passed
            } else {
                CaseStatus::Failed
            };
            Ok(exit_for(status))
        }
        Command::Replay { bundle } => {
            let original = read_artifact(&bundle)?;
            let replayed = replay(&original)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&replayed).map_err(|error| error.to_string())?
            );
            Ok(exit_for(replayed.status))
        }
        Command::Compare { left, right } => {
            let comparison = compare(&read_artifact(&left)?, &read_artifact(&right)?);
            println!(
                "{}",
                serde_json::to_string_pretty(&comparison).map_err(|error| error.to_string())?
            );
            Ok(if comparison.same_semantics {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Command::CrashChild { path, phase } => {
            run_crash_child(Path::new(&path), &phase)?;
            Err("crash child returned".to_owned())
        }
    }
}

fn exit_for(status: CaseStatus) -> ExitCode {
    match status {
        CaseStatus::Passed => ExitCode::SUCCESS,
        CaseStatus::Failed => ExitCode::from(1),
        CaseStatus::Incomplete => ExitCode::from(2),
    }
}
