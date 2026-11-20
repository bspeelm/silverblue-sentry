//! `sentry-network` (and `sentry network`): a home network through its router, over ssh. Runs
//! only while you run it.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sentry_network::cli;

#[derive(Parser)]
#[command(
    name = "sentry-network",
    version,
    about = "Watch a home network through its router (OpenWrt) over ssh. Nothing is installed \
             on the router; networks are described in ~/.config/sentry/network_config.yaml.",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Command>,
    /// The network to open (the only configured one if left out).
    network: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Look at a router (read-only) and write a starter network_config.yaml from what it
    /// reports: its ports, the firewall's zones and port forwards, and every device holding
    /// a lease, still to be named. Never touches a file that's already there.
    Init {
        /// What ssh connects to: an alias from ~/.ssh/config or root@host.
        ssh: String,
        /// Name for the network (default: home).
        #[arg(long)]
        name: Option<String>,
    },
    /// Check network_config.yaml (without contacting any router).
    Lint { name: Option<String> },
    /// Test the connection and say what was found: the release and board, the ports, the
    /// uplink, the tools.
    Check { name: Option<String> },
    /// Run one collector (probe, ifaces, clients, listeners, uci, cert, services) and print
    /// its result as JSON; all of them when none is named. Secrets in `uci` are tags.
    Collect {
        kind: Option<String>,
        /// The network (needed when several are configured).
        name: Option<String>,
    },
    /// Audit a network: what on its router needs attention (the firewall against what's
    /// expected, listeners, ssh and the web interface, unknown devices), written to a report.
    Audit { name: Option<String> },
    /// Record a router's metrics every 10 s for the History screen, from this machine, in
    /// the foreground until Ctrl-C (the TUI records too, while its Dashboard is open).
    /// Nothing runs on the router between samples.
    Record { name: Option<String> },
}

/// `args`: the command line, the program's name first.
pub fn main(args: Vec<std::ffi::OsString>) -> ExitCode {
    let cli = Cli::parse_from(args);
    ExitCode::from(match cli.cmd {
        Some(Command::Init { ssh, name }) => cli::init(&ssh, name.as_deref()),
        Some(Command::Lint { name }) => cli::lint(name.as_deref()),
        Some(Command::Check { name }) => cli::check(name.as_deref()),
        Some(Command::Collect { kind, name }) => cli::collect(kind.as_deref(), name.as_deref()),
        Some(Command::Audit { name }) => cli::audit(name.as_deref()),
        Some(Command::Record { name }) => cli::record(name.as_deref()),
        None => crate::tui::run(crate::tui::Open::Network(cli.network.as_deref())),
    })
}
