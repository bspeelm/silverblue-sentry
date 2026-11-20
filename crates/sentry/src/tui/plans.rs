//! Claude's reviews of this machine's maintenance: a separate flow from Ask Claude (no
//! length cap, no chat), over everything Maintenance recommends. (A plan is no longer written
//! this way: an apply session researches, shows its plan once, and that plan is kept in
//! `~/.config/sentry/plans/<workflow>.md`.)

use crate::claude::Profile;
use crate::config::Config;
use crate::maint::{self, LOCAL};

/// What Claude may use: the machine's read-only commands (as for Ask Claude), the web for
/// release notes, and Read on your notes and the maintenance log.
fn profile(cfg: &Config, system: String) -> Profile {
    let mut p = Profile::local()
        .with_notes(&cfg.maintenance.notes)
        .without_edits();
    p.system = system;
    let mut p = with_web(p);
    let log_dir = maint::real_path(&maint::log::dir(LOCAL));
    p.allowed.push(format!("Read(/{log_dir}/**)"));
    // Claude Code can only add a directory that exists (the log appears with the first run).
    if std::path::Path::new(&log_dir).is_dir() {
        p.dirs.push(log_dir);
    }
    p.dirs.sort();
    p.dirs.dedup();
    p
}

/// The web, for release notes and known issues (reviews, apply sessions).
pub fn with_web(mut p: Profile) -> Profile {
    p.tools.extend(["WebFetch", "WebSearch"].map(String::from));
    p.allowed
        .extend(["WebFetch", "WebSearch"].map(String::from));
    p.denied.retain(|d| d != "WebFetch" && d != "WebSearch");
    p
}

fn facts() -> String {
    format!(
        "Fedora Silverblue {}, kernel {}; the NVIDIA driver kmod is built by akmods and layered \
         as a local rpm-ostree package (Secure Boot, MOK-signed); toolboxes are podman \
         containers sharing $HOME",
        crate::paths::os_version(),
        crate::collectors::ostree::booted_kernel()
    )
}

const READS: &str = "You can run only the read-only commands you're allowed (rpm-ostree \
status, rpm -q, journalctl, flatpak info, podman ps…); nothing that needs root. If something \
can only be checked with sudo, say so in the document and give the command for the user.";

pub fn review_profile(cfg: &Config) -> Profile {
    profile(
        cfg,
        format!(
            "You review the maintenance of the user's own machine ({}) for sentry, a \
maintenance TUI: what to do next, and why. The review is saved as a Markdown file and acted on \
later.\n\
Start with the maintenance ledger named in the request and read the entries that bear on what's \
pending. Use the recommendations given, release notes and known issues on the web (WebFetch, \
WebSearch), the notes files named (Read), and the machine read-only. {READS}\n\
Then answer with ONLY the review document: no preamble, no remarks after it. Its title is \
`# Maintenance review`, then the sections the request lists. Be concrete: name the update, the \
version, the workflow, and why now or why it can wait. You never change anything yourself.",
            facts()
        ),
    )
}

/// Where the ledger and the notes are, for the request.
pub fn records(cfg: &Config) -> String {
    let ledger = maint::real_path(&maint::log::dir(LOCAL).join("LOG.md"));
    let notes = maint::resolve_notes(&cfg.maintenance.notes);
    format!(
        "Maintenance ledger: {}\nThe user's notes: {}",
        if std::path::Path::new(&ledger).exists() {
            ledger
        } else {
            "(none yet: no workflow has run since the log began)".into()
        },
        if notes.is_empty() {
            "(none: `[maintenance] notes` in config.toml)".to_string()
        } else {
            notes.join(", ")
        }
    )
}

pub fn review_request(cfg: &Config, recs: &str, context: &str, tasks: &str) -> String {
    format!(
        "{}\n\nWhat sentry recommends now, ranked:\n{recs}\n\n{context}\n\n\
         Review the maintenance of this machine. Sections:\n\
         ## Summary: two or three lines on where things stand.\n\
         ## Now: what to do first, one bullet each, and why it can't wait.\n\
         ## Soon: the same, for the next weeks.\n\
         ## Routine: regular maintenance due, and what can simply wait (say why).\n\
         ## Watch: Fedora releases, driver or kernel changes and anything else to look at \
         again, with dates.\n\n{tasks}",
        records(cfg)
    )
}

/// A review sentry starts by itself (`ask`: `review::run_ask` or `review::start_ask`).
pub fn auto_review_request(
    cfg: &Config,
    ask: &str,
    recs: &str,
    context: &str,
    tasks: &str,
) -> String {
    format!(
        "{}\n\n{ask}\n\nWhat sentry recommends now, ranked:\n{recs}\n\n{context}\n\n{tasks}",
        records(cfg)
    )
}
