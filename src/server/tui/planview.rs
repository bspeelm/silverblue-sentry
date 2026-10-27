//! Writing and reading execution plans: a separate flow from Ask Claude. Claude gets its own
//! instructions (gather the facts, then answer with only the plan document), runs in the
//! background, and its final answer becomes `plans/<item>.md`. The Plan view shows that file
//! as a document, with progress while Claude writes.

use crate::claude::Profile;
use crate::server::remote::{Remote, SudoMode};
pub use crate::tui::docview::{Writer, draw, draw_review};

/// Claude's instructions for a maintenance review.
pub fn review_profile(r: &Remote, os: &str, kernel: &str, sudo: Option<SudoMode>) -> Profile {
    let mut p = profile(r, os, kernel, sudo);
    let name = &r.name;
    p.system = format!(
        "You review the maintenance of the server `{name}` ({os}, kernel {kernel}) for the user's \
sentry-server: what to maintain next, and why. The review is saved as a Markdown file and acted \
on later, item by item.\n\
Start with the maintenance ledger named in the request (every earlier maintenance run, a \
one-line summary and tags each) and read the entries that bear on what's pending. Then use the \
standing of every tracked item given, release notes and advisories for anything with newer \
versions (WebFetch and WebSearch; never curl), the notes files named (Read), and the server \
read-only, ONLY as `sentry-server exec {name} -- <command> <args>` (one command per call, no \
pipes; allowed: {}). If a read needs root and is refused, it's queued for the user; make every \
read you need first, and if any was queued answer with only `READS PENDING` and one line saying \
what you're waiting for.\n\
Then answer with ONLY the review document: no preamble, no remarks after it. Its title is \
`# Maintenance review · {name}`, then the sections the request lists. Be concrete: name the item, \
the version, the workflow, and why now or why it can wait. You never change anything on the \
server yourself.",
        crate::server::gateway::summary()
    );
    p
}

/// What a review is asked.
pub fn review_request(context: &str) -> String {
    format!(
        "{context}\n\nReview the maintenance of this server. Sections:\n\
         ## Summary: two or three lines on where things stand.\n\
         ## Now: what to do first, one bullet each: the item, what to do (plan it to which \
         version, run which workflow), and why it can't wait.\n\
         ## Soon: the same, for the next weeks.\n\
         ## Routine: regular maintenance due, and what can simply wait (say why).\n\
         ## The list: what to start or stop tracking, sources to add, risk levels, holds and \
         review dates to revisit.\n\
         ## Watch: ends of life, upstream changes or anything else to look at again, with dates."
    )
}

/// Claude's instructions for writing a plan: not Ask Claude's (no length cap, no chat).
pub fn profile(r: &Remote, os: &str, kernel: &str, sudo: Option<SudoMode>) -> Profile {
    let mut p = super::ask::assess_profile(r, os, kernel, sudo);
    let name = &r.name;
    p.system = format!(
        "You write maintenance execution plans for the server `{name}` ({os}, kernel {kernel}), \
for the user's sentry-server. A plan is saved as a Markdown file and followed later, step by \
step, so it must stand on its own.\n\
First read the maintenance ledger named in the request (every earlier maintenance run on this \
server, a one-line summary and tags each): pick the runs that bear on this change (the same \
item or workflow, what it depends on or what depends on it, kernel, driver and engine changes, \
anything that failed or was done by hand), read those entries with Read, and use them: repeat \
what worked, plan around what went wrong, and name the entries you relied on.\n\
Then gather the facts: release notes and advisories with WebFetch and WebSearch (fetch the \
GitHub release pages given; never curl), the notes files named in the request with Read, and \
the server read-only, ONLY as `sentry-server exec {name} -- <command> <args>` (one command per \
call, no pipes; allowed: {}). If a read needs root and is refused, it's queued for the user to \
run with their password. Make every read you'll need first. If any was queued, DON'T write the \
plan yet: answer with only `READS PENDING` on the first line and one line saying what you're \
waiting for; the outputs come back to you, then you write the plan.\n\
Then answer with ONLY the plan document: no preamble, no remarks after it. As long as it needs to \
be. Its first line is `TARGET: <exact upstream tag>`, or `TARGET: wait` if it shouldn't move now; \
then `# Plan: <item> <from> → <to>` and the sections the request lists, with every command in \
a ```sh block. You never change anything on the server yourself.{}",
        crate::server::gateway::summary(),
        match sudo {
            Some(SudoMode::Password) => {
                " sudo on this server asks for a password: the user runs the commands that need it."
            }
            _ => "",
        }
    );
    p
}

/// What the first turn asks: the item, the workflow that will apply it, the target.
#[allow(clippy::too_many_arguments)]
pub fn request(
    context: &str,
    workflow: &str,
    steps: &str,
    goal: &str,
    note: Option<&str>,
) -> String {
    let how = if workflow.is_empty() {
        "No workflow applies it: the user runs every step by hand, in a terminal on the server, \
         from this plan. So the Change section is the complete procedure, one command at a time, \
         with what each prints when it worked, and where to stop if it didn't."
            .to_string()
    } else {
        format!("The workflow that will apply it ({workflow}), step by step:\n{steps}")
    };
    format!(
        "{context}\n\n{how}{}\n\n\
         Write the execution plan for {goal}. Sections, each with the exact commands:\n\
         ## Assessment: what changes (breaking changes, one-way migrations, security fixes), \
         whether the reason it's held still applies, and how risky it really is (low, medium, high).\n\
         ## History: what the maintenance log says that bears on this (the entries you read, \
         by file name), or that it has nothing relevant.\n\
         ## Before: checks and backups to make first.\n\
         ## Change: the workflow's steps above, in order (or, without one, the whole procedure); \
         what to expect at each step, and any manual commands between them.\n\
         ## Verify: what to check afterwards and what good looks like.\n\
         ## Roll back: how to undo it, and when it can't be undone.\n\
         ## When: whether it needs a window, and the expected downtime.",
        note.map_or(String::new(), |n| format!(
            "\nThe user's note for this plan: {n}"
        ))
    )
}

pub fn revise(what: &str) -> String {
    format!(
        "Revise the plan: {what}\nAnswer with the complete revised plan document in the same \
         format (the TARGET line first)."
    )
}

/// The user skipped the reads: write it with what there is.
pub fn reads_skipped() -> String {
    "The user didn't run the reads that need root. Write the plan now with what you have, and \
     say in it what couldn't be checked and how to check it by hand. Answer with the complete \
     plan document (the TARGET line first)."
        .into()
}

/// Claude stopped to wait for reads that need root (it hasn't written the plan yet).
pub fn waits_for_reads(answer: &str) -> bool {
    answer
        .trim_start()
        .to_ascii_uppercase()
        .starts_with("READS PENDING")
}

pub fn reads_back(outputs: &str) -> String {
    format!(
        "{outputs}\nTake these into account, then answer with the complete plan document in \
         the same format (the TARGET line first)."
    )
}
