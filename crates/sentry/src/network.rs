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
    /// Run one collector (probe, ifaces, clients, listeners, uci, cert, services, updates,
    /// counters, flows, seclog, dnsstate) and print its result as JSON; all of them when none
    /// is named. Secrets in `uci` are tags. `flows` and `seclog` print addresses (every far
    /// end the network talks to, who logged in): keep their output to yourself.
    Collect {
        kind: Option<String>,
        /// The network (needed when several are configured).
        name: Option<String>,
    },
    /// Audit a network: what on its router needs attention (the firewall against what's
    /// expected, listeners, ssh and the web interface, unknown devices), written to a report.
    Audit { name: Option<String> },
    /// Back the router's configuration up, encrypted on this machine to the recipients in
    /// network_config.yaml (`sysupgrade --create-backup`: nothing is written on the router).
    /// `backup list`, `backup key <file>` and `backup decrypt <file> -i <key>` beside it.
    #[command(args_conflicts_with_subcommands = true)]
    Backup {
        #[command(subcommand)]
        cmd: Option<Backup>,
        /// The network (needed when several are configured).
        name: Option<String>,
        /// Make none: check that the newest is there, encrypted, and holds what the router
        /// has now.
        #[arg(long)]
        verify: bool,
    },
    /// Run one read-only command on a router (the gateway Ask Claude uses): anything that
    /// isn't known to only read is refused, and what a read prints is scrubbed (secrets,
    /// the uplink's address, MACs, SSIDs, hostnames).
    Exec {
        name: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },
    /// Run one shell command line on a router (the gateway an apply session's Claude
    /// uses). Only a line that reads is run; a change is refused and becomes a request,
    /// config and service changes belong in a guard step, upgrades and reboots in a workflow.
    Run {
        name: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        line: Vec<String>,
    },
    /// A guarded config change (what the `guarded-change` workflow runs): `preview` (reads
    /// only), `apply` (snapshot, arm the router's own revert, stage, commit, reload,
    /// reconnect, confirm) or `keep`, with `configs=a,b services=x,y [wan=yes] -- <uci lines>`.
    Guard {
        name: String,
        action: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// What the `package-update` workflow's steps run: `preview` (refresh the index, list
    /// what could be upgraded), `upgrade [base] -- <names>` (named packages only), `check`.
    Packages {
        name: String,
        action: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// What the `firmware-upgrade` workflow's own steps run: `check`, `backup`, `plan`,
    /// `download`, `flash`, `wait`, `after`, `add-missing`, `forget`.
    Firmware { name: String, action: String },
    /// What needs attention on a network and how it is covered, as text (`--json`: as
    /// data): `security [name]`. Also what the `security-action` workflow's steps run:
    /// `security <name> plan|apply <action>` (`plan` only reads).
    Security {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Record a router's metrics every 10 s for the History screen, from this machine, in
    /// the foreground until Ctrl-C (the TUI records too, while its Dashboard is open).
    /// Nothing runs on the router between samples.
    Record { name: Option<String> },
}

#[derive(Subcommand)]
enum Backup {
    /// The backups kept for a network, newest first.
    List { name: Option<String> },
    /// Make a key to encrypt backups to: the file holds the secret key (0600, never over
    /// one that's there), and the recipient line for network_config.yaml is printed.
    Key { path: std::path::PathBuf },
    /// Decrypt a backup with your secret key. What comes out is the plain archive, which
    /// OpenWrt restores (`sysupgrade -r`, or LuCI's Backup / Flash page); sentry restores
    /// nothing itself.
    Decrypt {
        file: std::path::PathBuf,
        /// The file holding the secret key (`backup key` made it).
        #[arg(short, long)]
        identity: std::path::PathBuf,
        /// Where to write it (default: the file's name without `.age`, here; `-`: stdout).
        #[arg(short, long)]
        out: Option<String>,
    },
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
        Some(Command::Backup { cmd, name, verify }) => match cmd {
            Some(Backup::List { name }) => cli::backup_list(name.as_deref()),
            Some(Backup::Key { path }) => cli::backup_key(&path),
            Some(Backup::Decrypt {
                file,
                identity,
                out,
            }) => cli::backup_decrypt(&file, &identity, out.as_deref()),
            None if verify => cli::backup_verify(name.as_deref()),
            None => cli::backup(name.as_deref()),
        },
        Some(Command::Exec { name, argv }) => cli::exec(&name, &argv),
        Some(Command::Run { name, line }) => cli::run(&name, &line),
        Some(Command::Guard { name, action, rest }) => cli::guard(&name, &action, &rest),
        Some(Command::Packages { name, action, rest }) => cli::packages(&name, &action, &rest),
        Some(Command::Firmware { name, action }) => cli::firmware(&name, &action),
        Some(Command::Security { rest }) => cli::security(&rest),
        Some(Command::Record { name }) => cli::record(name.as_deref()),
        None => crate::tui::run(crate::tui::Open::Network(cli.network.as_deref())),
    })
}
