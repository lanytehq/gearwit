//! Thin Gearwit command surface.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand, ValueEnum};
use gearwit_cli::{ProcessCensus, WaitOnSpec, WhoCard, render_check, run_wait_on};
use gearwit_domain::DeliveryRoute;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Daemon(daemon) => match daemon.command {
            DaemonCommand::WaitOn(args) => {
                let code = run_wait_on(&spec_from_args(args, true));
                ExitCode::from(u8::try_from(code).unwrap_or(2))
            }
            DaemonCommand::Status => {
                print!("{}", render_check());
                ExitCode::SUCCESS
            }
        },
        Commands::Self_(self_cmd) => match self_cmd.command {
            SelfCommand::Who => {
                let card = WhoCard::from_census(&ProcessCensus::from_current_process());
                print!("{}", card.render());
                ExitCode::SUCCESS
            }
            SelfCommand::WaitOn(args) => {
                let code = run_wait_on(&spec_from_args(args, false));
                ExitCode::from(u8::try_from(code).unwrap_or(2))
            }
            SelfCommand::Check => {
                print!("{}", render_check());
                ExitCode::SUCCESS
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
    /// Local watcher process. Not a harness inject. Coverage only.
    Daemon(DaemonArgs),
}

#[derive(Debug, Parser)]
struct DaemonArgs {
    #[command(subcommand)]
    command: DaemonCommand,
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    /// Sit on a channel and re-arm from `newest_observed`. Notify/observe only.
    #[command(name = "wait-on")]
    WaitOn(WaitOnArgs),
    /// Print the last stored receipt.
    Status,
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
    /// Print the last in-process wait receipt.
    Check,
}

#[derive(Debug, Parser)]
struct WaitOnArgs {
    /// Channel name (`november-team`) or `team/channel`.
    channel: String,
    /// Exclusive cursor; required so drain uses the same arm baseline.
    #[arg(long)]
    after: String,
    /// Deadman duration (`20m`, `60s`).
    #[arg(long, default_value = "20m")]
    timeout: String,
    /// Mattermost team slug when the channel name is ambiguous.
    #[arg(long)]
    team: Option<String>,
    /// Interrupt source. Only `chanvoy` is implemented in this slice.
    #[arg(long, default_value = "chanvoy")]
    source: String,
    /// Declared return route. Not proof of a model turn.
    #[arg(long = "return", value_enum, default_value_t = ReturnArg::Foreground)]
    return_route: ReturnArg,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum ReturnArg {
    /// Return into a harness-owned foreground tool call.
    #[default]
    Foreground,
    /// Complete a harness-owned background tool (Grok doorbell).
    #[value(name = "background-tool")]
    BackgroundTool,
    /// Notify an operator; do not claim a model turn.
    #[value(name = "notify-operator")]
    NotifyOperator,
}

fn spec_from_args(args: WaitOnArgs, follow: bool) -> WaitOnSpec {
    WaitOnSpec {
        channel: args.channel,
        after: Some(args.after),
        timeout: args.timeout,
        team: args.team,
        source: args.source,
        return_route: args.return_route.route(),
        follow,
    }
}

impl ReturnArg {
    fn route(self) -> DeliveryRoute {
        match self {
            Self::Foreground => DeliveryRoute::ReturnForeground,
            Self::BackgroundTool => DeliveryRoute::CompleteBackgroundTool,
            Self::NotifyOperator => DeliveryRoute::NotifyOperator,
        }
    }
}
