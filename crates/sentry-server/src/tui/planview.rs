//! Maintenance reviews: a separate flow from Ask Claude. Claude gets its own instructions
//! (gather the facts, then answer with only the review document) and runs in the background.
//! (A plan is no longer written this way: an apply session researches, shows its plan once,
//! and that plan is kept in `plans/<item>.md`.)

use crate::remote::{Remote, SudoMode};
use sentry_core::claude::Profile;

/// Claude's instructions for a maintenance review.
pub fn review_profile(r: &Remote, os: &str, kernel: &str, sudo: Option<SudoMode>) -> Profile {
    let mut p = super::ask::writer_profile(r, os, kernel, sudo);
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
        crate::gateway::summary()
    );
    p
}

/// What a review is asked: the standing of everything, then how the list should change.
pub fn review_request(context: &str, changes: &str) -> String {
    format!(
        "{context}\n\nReview the maintenance of this server. Sections:\n\
         ## Summary: two or three lines on where things stand.\n\
         ## Now: what to do first, one bullet each: the item, what to do (plan it to which \
         version, run which workflow), and why it can't wait.\n\
         ## Soon: the same, for the next weeks.\n\
         ## Routine: regular maintenance due, and what can simply wait (say why).\n\
         ## Watch: ends of life, upstream changes or anything else to look at again, with dates.\n\n\
         {changes}"
    )
}

/// A review sentry-server starts by itself (`ask`: core's `review::run_ask` or `start_ask`).
/// Its reads stay within what needs no root: nobody is there to type a password.
pub fn auto_review_request(ask: &str, context: &str, changes: &str) -> String {
    format!(
        "{ask}\nDon't make reads that need root for this (none will be run): say what you \
         couldn't check instead, and never answer `READS PENDING`.\n\n{context}\n\n{changes}"
    )
}

/// The user skipped the reads: write it with what there is.
pub fn reads_skipped() -> String {
    "The user didn't run the reads that need root. Write the review now with what you have, \
     and say in it what couldn't be checked. Answer with the complete review document in the \
     format asked for (its changes block last)."
        .into()
}

/// Claude stopped to wait for reads that need root (it hasn't written the review yet).
pub fn waits_for_reads(answer: &str) -> bool {
    answer
        .trim_start()
        .to_ascii_uppercase()
        .starts_with("READS PENDING")
}

pub fn reads_back(outputs: &str) -> String {
    format!(
        "{outputs}\nTake these into account, then answer with the complete review document \
         in the format asked for (its changes block last)."
    )
}
