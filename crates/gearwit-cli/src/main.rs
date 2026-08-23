//! Thin Gearwit command surface.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use gearwit_cli::{ProcessCensus, WaitOnSpec, WhoCard, run_wait_on};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Self_(self_cmd) => match self_cmd.command {
            SelfCommand::Who => {
                let card = WhoCard::from_census(&ProcessCensus::from_current_process());
                print!("{}", card.render());
                ExitCode::SUCCESS
            }
            SelfCommand::WaitOn(args) => {
                let code = run_wait_on(&WaitOnSpec {
                    channel: args.channel,
                    after: args.after,
                    timeout: args.timeout,
                    team: args.team,
                });
                ExitCode::from(u8::try_from(code).unwrap_or(2))
            }
        },
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "gearwit",
    version,
    about = "Everyone performs better with good kit.",
    long_about = "Local-first kit for coding-agent seats that already exist. \
This binary is a face of the Gearwit host. It is not a harness."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Verbs for the calling seat.
    #[command(name = "self")]
    Self_(SelfArgs),
}

#[derive(Debug, Parser)]
struct SelfArgs {
    #[command(subcommand)]
    command: SelfCommand,
}

#[derive(Debug, Subcommand)]
enum SelfCommand {
    /// Print a census-safe card for this process.
    ///
    /// Native identifiers and controller coordinates are omitted. Field
    /// evidence is shown per fact. Unknown stays unknown.
    Who,
    /// Arm an in-process wait by wrapping `chanvoy wait`.
    ///
    /// Completing this process is `waiter_completed`, not `turn_started`.
    #[command(name = "wait-on", visible_alias = "sit")]
    WaitOn(WaitOnArgs),
}

#[derive(Debug, Parser)]
struct WaitOnArgs {
    /// Channel name (`november-team`) or `team/channel`.
    channel: String,
    /// Exclusive cursor; posts at or before this id do not fire.
    #[arg(long)]
    after: Option<String>,
    /// Deadman duration (`20m`, `60s`).
    #[arg(long, default_value = "20m")]
    timeout: String,
    /// Mattermost team slug when the channel name is ambiguous.
    #[arg(long)]
    team: Option<String>,
}
