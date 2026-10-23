//! sentry: daemon-free monitor & maintenance TUI for Fedora Silverblue.

mod baseline;
mod cache;
mod collectors;
mod config;
mod exec;
mod fmt;
mod keyfile;
mod paths;
mod resume;
mod status;
mod tui;

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
    /// Run one job headless.
    Job {
        name: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        diff_against: Option<String>,
    },
    /// Built-in checks used by workflows (exit 0/1 + one-line reason).
    Check {
        name: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Start/continue a workflow headless, or `workflow lint <name>`.
    Workflow {
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
        #[arg(long, default_value = "10s")]
        interval: String,
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

fn not_yet(what: &str, milestone: u8) -> ExitCode {
    eprintln!("sentry {what}: not implemented yet (milestone {milestone})");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging();
    match cli.cmd {
        None => match tui::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sentry: {e:#}");
                ExitCode::FAILURE
            }
        },
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
        Some(Command::Status { short }) => {
            println!("{}", status::line(short));
            ExitCode::SUCCESS
        }
        Some(Command::Job { .. }) => not_yet("job", 4),
        Some(Command::Check { .. }) => not_yet("check", 5),
        Some(Command::Workflow { .. }) => not_yet("workflow", 5),
        Some(Command::Record { .. }) => not_yet("record", 6),
    }
}
