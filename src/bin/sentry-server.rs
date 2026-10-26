//! sentry-server: monitor and maintain a server over ssh. Runs only while you run it.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sentry::server::cli;

#[derive(Parser)]
#[command(
    name = "sentry-server",
    version,
    about = "Monitor and maintain a server over ssh. Nothing is installed on the server; \
             servers are described in ~/.config/sentry/server_config.yaml.",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Command>,
    /// The server to open (the only configured one if left out).
    server: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Look around a server (read-only) and draft its server_config.yaml entry.
    Init {
        /// What ssh connects to: an alias from ~/.ssh/config or user@host.
        ssh: String,
        /// Name for it in server_config.yaml (default: from the host).
        #[arg(long)]
        name: Option<String>,
        /// Add the draft to server_config.yaml (never replaces an existing entry).
        #[arg(long)]
        write: bool,
    },
    /// Check server_config.yaml, and that what it names exists on the server.
    Lint {
        name: Option<String>,
        /// Only check the file; don't connect.
        #[arg(long)]
        offline: bool,
    },
    /// Test the connection, sudo and the tools sentry-server uses.
    Check { name: Option<String> },
    /// Run one collector and print its result as JSON (probe, units, docker, apt, smart,
    /// sensors, gpu, fail2ban, disks, listeners, journal, docker-stats, snapshot).
    Collect { server: String, kind: String },
    /// Audit a server: what needs attention, written to a report.
    Audit { name: Option<String> },
    /// Check a workflow condition (reboot_required, kernel_pending, updates_pending,
    /// services_ok, containers_healthy); exit 0 when it holds.
    Cond {
        server: String,
        name: String,
        /// Keep checking every 5 s for up to this many seconds.
        #[arg(long)]
        wait: Option<u64>,
    },
    /// Run one read-only command on a server (the gateway Ask Claude uses; anything off its
    /// allowlist is refused).
    Exec {
        server: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },
    /// List the server workflows (`list`) or show their lint issues (`lint`).
    Workflow {
        #[arg(default_value = "list")]
        what: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    ExitCode::from(match cli.cmd {
        Some(Command::Init { ssh, name, write }) => cli::init(&ssh, name.as_deref(), write),
        Some(Command::Lint { name, offline }) => cli::lint(name.as_deref(), offline),
        Some(Command::Check { name }) => cli::check(name.as_deref()),
        Some(Command::Collect { server, kind }) => cli::collect(&server, &kind),
        Some(Command::Audit { name }) => cli::audit(name.as_deref()),
        Some(Command::Cond { server, name, wait }) => cli::cond(&server, &name, wait),
        Some(Command::Workflow { what }) => cli::workflow(&what),
        Some(Command::Exec { server, argv }) => cli::exec(&server, &argv),
        None => cli::tui(cli.server.as_deref()),
    })
}
