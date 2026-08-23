//! Thin Gearwit command surface.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use gearwit_cli::{ProcessCensus, WhoCard};

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Self_(self_cmd) => match self_cmd.command {
            SelfCommand::Who => {
                let card = WhoCard::from_census(&ProcessCensus::from_current_process());
                print!("{}", card.render());
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
}
