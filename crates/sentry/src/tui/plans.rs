//! Claude's plans and reviews for this machine: a separate flow from Ask Claude (no length
//! cap, no chat). A plan is for a workflow (`release-rebase`, `quick-update` on a kernel
//! change…): Claude reads the ledger, your notes, release notes and the machine read-only,
//! and writes `~/.config/sentry/plans/<workflow>.md`, which Enter applies later by starting
//! the workflow with its values. A review looks over everything Maintenance recommends.

use crate::claude::Profile;
use crate::config::Config;
use crate::maint::{self, LOCAL};

/// What Claude may use: the machine's read-only commands (as for Ask Claude), the web for
/// release notes, and Read on your notes and the maintenance log.
fn profile(cfg: &Config, system: String) -> Profile {
    let mut p = Profile::local();
    p.system = system;
    p.tools.extend(["WebFetch", "WebSearch"].map(String::from));
    p.allowed
        .extend(["WebFetch", "WebSearch"].map(String::from));
    p.denied.retain(|d| d != "WebFetch" && d != "WebSearch");
    let notes = maint::resolve_notes(&cfg.maintenance.notes);
    p.allowed.extend(maint::read_rules(&notes));
    let log_dir = maint::real_path(&maint::log::dir(LOCAL));
    p.allowed.push(format!("Read(/{log_dir}/**)"));
    let mut dirs: Vec<String> = notes
        .iter()
        .filter_map(|n| std::path::Path::new(n).parent())
        .map(|d| d.display().to_string())
        .collect();
    // Claude Code can only add a directory that exists (the log appears with the first run).
    if std::path::Path::new(&log_dir).is_dir() {
        dirs.push(log_dir);
    }
    dirs.sort();
    dirs.dedup();
    p.dirs = dirs;
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

pub fn plan_profile(cfg: &Config) -> Profile {
    profile(
        cfg,
        format!(
            "You write maintenance execution plans for the user's own machine ({}), for sentry, \
a maintenance TUI. A plan is saved as a Markdown file and followed later with one of sentry's \
workflows, step by step, so it must stand on its own.\n\
First read the maintenance ledger named in the request (every earlier workflow run on this \
machine, a one-line summary and tags each): pick the runs that bear on this change (the same \
workflow, kernel, driver and release changes, anything that failed or was done by hand), read \
those entries with Read, and use them: repeat what worked, plan around what went wrong, and name \
the entries you relied on. Read the notes files named in the request (Read), release notes and \
known issues on the web (WebFetch, WebSearch), and check the machine read-only. {READS}\n\
Then answer with ONLY the plan document: no preamble, no remarks after it. As long as it needs \
to be. Its first line is `TARGET: <value>` (the version to move to when the workflow takes one, \
else `now`), or `TARGET: wait` if it shouldn't run yet; then `# Plan: <workflow> …` and the \
sections the request lists, with every command in a ```sh block. You never change anything \
yourself.",
            facts()
        ),
    )
}

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
fn records(cfg: &Config) -> String {
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

/// The first turn of a plan: the machine, the workflow (its TOML), the note.
pub fn plan_request(
    cfg: &Config,
    context: &str,
    workflow: &str,
    toml: &str,
    note: Option<&str>,
) -> String {
    format!(
        "{}\n\n{context}\n\nThe workflow that will apply it ({workflow}):\n```toml\n{toml}\n```{}\n\n\
         Write the execution plan for running {workflow} on this machine. Sections, each with the \
         exact commands:\n\
         ## Assessment: what changes (kernel, driver, release), known breakage, and how risky it \
         really is (low, medium, high).\n\
         ## History: what the maintenance log says that bears on this (the entries you read, by \
         file name), or that it has nothing relevant.\n\
         ## Before: checks and backups to make first.\n\
         ## Change: the workflow's steps, in order; what to expect at each confirm card and \
         reboot, and any manual commands between them.\n\
         ## Verify: what to check afterwards and what good looks like.\n\
         ## Roll back: how to undo it (rpm-ostree rollback, pinned deployments), and when it \
         can't be undone.\n\
         ## When: whether it needs a quiet hour, and how long the reboots take.",
        records(cfg),
        note.map_or(String::new(), |n| format!(
            "\nThe user's note for this plan: {n}"
        ))
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

pub fn revise(what: &str) -> String {
    format!(
        "Revise the plan: {what}\nAnswer with the complete revised plan document in the same \
         format (the TARGET line first)."
    )
}
