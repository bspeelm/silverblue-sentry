//! sentry: daemon-free monitor & maintenance TUI for Fedora Silverblue, and for the servers
//! it reaches over ssh. One program: called as `sentry-server` (a symlink to it), or as
//! `sentry server …`, it is that command.

mod server;
#[cfg(test)]
mod tests;
mod tui;

use sentry_local::{checks, collectors, config, jobs, paths, recorder, status, workflows};

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "sentry",
    version,
    about = "Silverblue monitor & maintenance TUI. Runs only while you run it."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run one job headless (plan → confirm → run).
    Job {
        /// audit, update-check, update-apply, cleanup-flatpak, cleanup-podman, cleanup-ostree,
        /// cleanup-cache
        name: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        diff_against: Option<String>,
        /// Skip the confirmation prompt (the TUI passes this after its own confirm modal).
        #[arg(long, short)]
        yes: bool,
        /// Run only these plan items (comma-separated keys from --dry-run).
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
    },
    /// Built-in checks used by workflows (exit 0/1 + one-line reason).
    Check {
        /// preflight, booted-version, booted-kernel, kernel-changed, nvidia-module,
        /// nvidia-loaded, rpmfusion-version, rpmfusion-pinned, kargs, secureboot-mok,
        /// kmod-local, akmods-built, akmods-key, flatpak-gl-nvidia, flatpak-idle, master-repo-present
        name: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Start/continue a workflow headless; also `list`, `lint [name]`, `abandon`.
    Workflow {
        /// A workflow name, or list | lint | abandon
        name: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// One-line summary from state files only (no collectors).
    Status {
        #[arg(long)]
        short: bool,
    },
    /// Foreground metrics recorder; exits on Ctrl-C.
    Record {
        /// Sample interval (default: [recorder] interval, 10s).
        #[arg(long)]
        interval: Option<String>,
    },
    /// Toolbox/distrobox packages: `check` (dnf check-update in each, cached) or `upgrade` (all).
    Toolbox {
        /// check | upgrade
        action: String,
    },
    /// Dump a collector as JSON.
    Collect {
        /// One of: system, processes, gpu, disk, disk-breakdown, net, ostree, flatpak,
        /// flatpak-updates, podman, units, repos, shell, journal
        name: String,
        /// JSON output (the default; accepted for compatibility).
        #[arg(long)]
        json: bool,
    },
    /// A server over ssh: `sentry server …` is `sentry-server …` (its own --help says what).
    Server {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

/// The command line as `sentry-server` would get it, when that's what was called: by that
/// name (the symlink beside this program), or as `sentry server …`.
fn as_server(mut args: Vec<std::ffi::OsString>) -> Option<Vec<std::ffi::OsString>> {
    let called = args
        .first()
        .and_then(|a| std::path::Path::new(a).file_name())
        .is_some_and(|n| n == "sentry-server");
    if called {
        return Some(args);
    }
    if args.get(1).is_some_and(|a| a == "server") {
        args.remove(1);
        args[0] = "sentry-server".into();
        return Some(args);
    }
    None
}

fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let dir = paths::cache_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("sentry.log");
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > 1 << 20) {
        let _ = std::fs::remove_file(&path);
    }
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };
    let filter = EnvFilter::try_from_env("SENTRY_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(std::sync::Mutex::new(file))
        .try_init();
}

fn main() -> ExitCode {
    if let Some(args) = as_server(std::env::args_os().collect()) {
        return server::main(args);
    }
    let cli = Cli::parse();
    if cli.cmd.is_some() {
        init_logging();
    }
    match cli.cmd {
        // (Taken before the parse: `as_server`.)
        Some(Command::Server { args }) => server::main(
            std::iter::once("sentry-server".into())
                .chain(args.into_iter().map(Into::into))
                .collect(),
        ),
        None => ExitCode::from(tui::run(None)),
        Some(Command::Collect { name, json: _ }) => {
            let (cfg, warnings) = config::Config::load();
            warnings.iter().for_each(|w| eprintln!("{w}"));
            let ctx = collectors::Ctx::new(cfg);
            match collectors::collect_json(&name, &ctx) {
                Ok(v) => {
                    println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
                    ExitCode::SUCCESS
                }
                Err(collectors::CollectError::Unavailable(bin)) => {
                    println!("{}", serde_json::json!({ "unavailable": bin }));
                    ExitCode::from(3)
                }
                Err(e) => {
                    eprintln!("sentry collect {name}: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(Command::Toolbox { action }) => {
            let (cfg, warnings) = config::Config::load();
            warnings.iter().for_each(|w| eprintln!("{w}"));
            ExitCode::from(collectors::toolbox::run_cli(
                &action,
                &collectors::Ctx::new(cfg),
            ))
        }
        Some(Command::Status { short }) => {
            println!("{}", status::line(short));
            ExitCode::SUCCESS
        }
        Some(Command::Job {
            name,
            dry_run,
            tag,
            diff_against,
            yes,
            only,
        }) => {
            let (cfg, warnings) = config::Config::load();
            warnings.iter().for_each(|w| eprintln!("{w}"));
            let ctx = collectors::Ctx::new(cfg);
            ExitCode::from(jobs::run_cli(
                &name,
                jobs::Opts {
                    dry_run,
                    yes,
                    tag,
                    diff_against,
                    only,
                },
                &ctx,
            ))
        }
        Some(Command::Check { name, args }) => ExitCode::from(checks::run_cli(&name, &args)),
        Some(Command::Workflow { name, args }) => {
            ExitCode::from(workflows::cli::run_cli(&name, &args))
        }
        Some(Command::Record { interval }) => {
            ExitCode::from(recorder::run_cli(interval.as_deref()))
        }
    }
}
