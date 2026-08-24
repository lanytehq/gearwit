//! Thin Gearwit command surface.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand, ValueEnum};
use gearwit_cli::{
    AckHandledSpec, AttachSpec, ProcessCensus, WaitOnSpec, WhoCard, render_check, run_ack_handled,
    run_attach_session, run_daemon_wait, run_wait_on,
};
use gearwit_domain::DeliveryRoute;
use gearwit_host::GearwitPaths;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Daemon(daemon) => match daemon.command {
            DaemonCommand::WaitOn(args) => {
                let code = run_daemon_wait(daemon_spec_from_args(args));
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
                if args.attach {
                    return run_attach_from_args(&args);
                }
                let code = run_wait_on(&spec_from_args(args, false));
                ExitCode::from(u8::try_from(code).unwrap_or(2))
            }
            SelfCommand::Check => {
                print!("{}", render_check());
                ExitCode::SUCCESS
            }
            SelfCommand::AckHandled(args) => run_ack_handled_from_args(args),
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
    /// Sit on a channel, own Chanvoy coverage, and deliver to an attached waiter.
    #[command(name = "wait-on")]
    WaitOn(DaemonWaitOnArgs),
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
    /// Record a handled cursor on the local daemon. Transport only.
    #[command(name = "ack-handled")]
    AckHandled(AckHandledArgs),
}

#[derive(Debug, Parser)]
struct AckHandledArgs {
    /// Arm id.
    #[arg(long)]
    arm: String,
    /// Arm generation.
    #[arg(long)]
    generation: u64,
    /// Seat token.
    #[arg(long)]
    seat: String,
    /// Stable signal id.
    #[arg(long)]
    signal: String,
    /// Prefix endpoint `event_ref`.
    #[arg(long)]
    cursor: String,
    /// Idempotency key. Minted when omitted; printed before send.
    #[arg(long)]
    request_id: Option<String>,
    /// Observation time. Set before send when omitted.
    #[arg(long)]
    observed_at: Option<String>,
    /// Override the default user socket.
    #[arg(long)]
    socket: Option<std::path::PathBuf>,
}

#[derive(Debug, Parser)]
struct WaitOnArgs {
    /// Channel name (`november-team`) or `team/channel`.
    #[arg(required_unless_present = "attach", conflicts_with = "attach")]
    channel: Option<String>,
    /// Exclusive cursor; required so drain uses the same arm baseline.
    #[arg(long, required_unless_present = "attach", conflicts_with = "attach")]
    after: Option<String>,
    /// Deadman duration (`20m`, `60s`).
    #[arg(long, default_value = "20m", conflicts_with = "attach")]
    timeout: String,
    /// Mattermost team slug when the channel name is ambiguous.
    #[arg(long, conflicts_with = "attach")]
    team: Option<String>,
    /// Interrupt source. Only `chanvoy` is implemented in this slice.
    #[arg(long, default_value = "chanvoy", conflicts_with = "attach")]
    source: String,
    /// Declared return route. Not proof of a model turn.
    #[arg(long = "return", value_enum, default_value_t = ReturnArg::Foreground)]
    return_route: ReturnArg,
    /// Attach to local gearwitd. Does not wrap Chanvoy.
    #[arg(long)]
    attach: bool,
    /// Arm id. Required with `--attach`.
    #[arg(long, required_if_eq("attach", "true"), conflicts_with = "channel")]
    arm: Option<String>,
    /// Seat token. Required with `--attach`.
    #[arg(long, required_if_eq("attach", "true"), conflicts_with = "channel")]
    seat: Option<String>,
    /// Arm generation. Required with `--attach`.
    #[arg(long, required_if_eq("attach", "true"), conflicts_with = "channel")]
    generation: Option<u64>,
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

#[derive(Debug, Parser)]
struct DaemonWaitOnArgs {
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
}

fn daemon_spec_from_args(args: DaemonWaitOnArgs) -> WaitOnSpec {
    WaitOnSpec {
        channel: args.channel,
        after: Some(args.after),
        timeout: args.timeout,
        team: args.team,
        source: args.source,
        return_route: DeliveryRoute::NotifyOperator,
        follow: true,
    }
}

fn spec_from_args(args: WaitOnArgs, follow: bool) -> WaitOnSpec {
    WaitOnSpec {
        channel: args.channel.expect("channel"),
        after: Some(args.after.expect("after")),
        timeout: args.timeout,
        team: args.team,
        source: args.source,
        return_route: args.return_route.route(),
        follow,
    }
}

fn run_ack_handled_from_args(args: AckHandledArgs) -> ExitCode {
    let spec = AckHandledSpec {
        arm_id: args.arm,
        generation: args.generation,
        seat_id: args.seat,
        signal_id: args.signal,
        cursor: args.cursor,
        request_id: args.request_id,
        observed_at: args.observed_at,
    };
    let socket = match args.socket {
        Some(path) => path,
        None => match GearwitPaths::user_default() {
            Ok(paths) => paths.socket_path(),
            Err(error) => {
                eprintln!("gearwit: {error}");
                return ExitCode::from(2);
            }
        },
    };
    match run_ack_handled(&socket, &spec) {
        Ok(report) => ExitCode::from(report.exit),
        Err(error) => {
            eprintln!("gearwit: {error}");
            ExitCode::from(2)
        }
    }
}

fn run_attach_from_args(args: &WaitOnArgs) -> ExitCode {
    if args.return_route == ReturnArg::NotifyOperator {
        eprintln!("gearwit: attach cannot use notify-operator");
        return ExitCode::from(2);
    }
    let spec = AttachSpec {
        arm_id: args.arm.clone().expect("arm"),
        generation: args.generation.expect("generation"),
        seat_id: args.seat.clone().expect("seat"),
        route: args.return_route.route().as_str().to_owned(),
    };
    let paths = match GearwitPaths::user_default() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gearwit: {error}");
            return ExitCode::from(2);
        }
    };
    match run_attach_session(&paths.socket_path(), &spec) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gearwit: {error}");
            ExitCode::from(2)
        }
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

#[cfg(test)]
mod tests {
    use super::{Cli, ReturnArg, WaitOnArgs};
    use clap::Parser;

    #[test]
    fn wrap_mode_requires_channel_and_after() {
        assert!(Cli::try_parse_from(["gearwit", "self", "wait-on"]).is_err());
        assert!(Cli::try_parse_from(["gearwit", "self", "wait-on", "november-team"]).is_err());
        assert!(
            Cli::try_parse_from([
                "gearwit",
                "self",
                "wait-on",
                "november-team",
                "--after",
                "post1"
            ])
            .is_ok()
        );
    }

    #[test]
    fn attach_mode_is_exclusive_of_channel_and_after() {
        assert!(
            Cli::try_parse_from([
                "gearwit",
                "self",
                "wait-on",
                "--attach",
                "--arm",
                "01J00000000000000000000010",
                "--seat",
                "example-devrev",
                "--generation",
                "1",
                "--return",
                "background-tool"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "gearwit",
                "self",
                "wait-on",
                "november-team",
                "--after",
                "post1",
                "--attach"
            ])
            .is_err()
        );
    }

    #[test]
    fn ack_handled_requires_explicit_authority() {
        assert!(Cli::try_parse_from(["gearwit", "self", "ack-handled"]).is_err());
        assert!(
            Cli::try_parse_from([
                "gearwit",
                "self",
                "ack-handled",
                "--arm",
                "01J00000000000000000000010",
                "--generation",
                "1",
                "--seat",
                "example-devrev",
                "--signal",
                "01J00000000000000000000021",
                "--cursor",
                "post02",
                "--request-id",
                "01J00000000000000000000051",
                "--observed-at",
                "2026-01-15T12:05:20Z"
            ])
            .is_ok()
        );
    }

    #[test]
    fn attach_rejects_notify_operator_before_io() {
        let args = WaitOnArgs {
            channel: None,
            after: None,
            timeout: "20m".to_owned(),
            team: None,
            source: "chanvoy".to_owned(),
            return_route: ReturnArg::NotifyOperator,
            attach: true,
            arm: Some("01J00000000000000000000010".to_owned()),
            seat: Some("example-devrev".to_owned()),
            generation: Some(1),
        };
        super::run_attach_from_args(&args);
    }
}
