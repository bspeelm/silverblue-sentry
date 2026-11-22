//! The security audit in the window (core `secaudit`): one for every target, so it belongs
//! to the window, not to a slot. [`Sec`] is what the window holds of it (`Win::sec`): the
//! latest report, the facts it was made from while this window is open (they hold
//! addresses and never leave memory), Claude's review of it, and whether it runs. The
//! flows are in `slot/secaudit.rs`; every target sees it through `Cx::sec` and lists the
//! items that are its own ([`mine`]).

use std::sync::Arc;
use std::time::Instant;

use sentry_core::claude::Profile;
use sentry_core::secaudit::{Answers, Item, LOCAL, Report, State, TargetFacts};

use crate::system::Sys;
use crate::target::TargetId;

/// How every target's facts are read (the program gives it: it alone knows every kind of
/// target). Runs on a worker thread.
pub type Collect = Arc<dyn Fn() -> Vec<TargetFacts> + Send + Sync>;

/// What a worker thread sends back: every target's facts.
pub struct Done(pub Vec<TargetFacts>);

/// The key that shows the audit (or runs it), on every target.
pub const KEY: char = 'S';

/// The writer's item while Claude reviews the audit's evidence.
pub const REVIEW: &str = "(security)";

pub struct Sec {
    /// The latest report: read from disk at start, replaced when an audit ends.
    pub report: Option<Report>,
    /// The facts of the audit this window ran (not saved: answers re-evaluate over them).
    pub facts: Vec<TargetFacts>,
    /// What the user answered (`answers.toml`).
    pub answers: Answers,
    /// Since when the targets are being read.
    pub running: Option<Instant>,
    /// Asked for, and waiting for what targets read as root first: since when, and whose
    /// slot asked.
    pub pending: Option<(Instant, TargetId)>,
    /// Claude's review of the report: "What matters most here".
    pub review: Option<String>,
    /// Claude is writing it.
    pub reviewing: bool,
    pub collect: Option<Collect>,
    /// The report on disk was looked for.
    pub loaded: bool,
    /// Counts every change of the report or the answers: a slot's copy of its items
    /// (`Shared::sec`) follows it.
    pub rev: u64,
}

impl Sec {
    pub const fn new() -> Self {
        Self {
            report: None,
            facts: Vec::new(),
            answers: Answers {
                answers: std::collections::BTreeMap::new(),
            },
            running: None,
            pending: None,
            review: None,
            reviewing: false,
            collect: None,
            loaded: false,
            rev: 0,
        }
    }

    pub fn busy(&self) -> bool {
        self.running.is_some() || self.pending.is_some()
    }

    /// The banner row while it works.
    pub fn line(&self) -> Option<&'static str> {
        if self.busy() {
            Some("security audit · reading every target (a minute or two)")
        } else if self.reviewing {
            Some("security audit · done · Claude is reviewing what it found")
        } else {
            None
        }
    }

    /// "audited 3 days ago · S runs it again", or that it never ran.
    pub fn age(&self, now: jiff::Timestamp) -> String {
        match &self.report {
            Some(r) => format!("{} · {KEY} shows it", audited(now, r.at)),
            None => format!("never audited · {KEY} runs the security audit"),
        }
    }
}

impl Default for Sec {
    fn default() -> Self {
        Self::new()
    }
}

/// "audited today", "audited 3 days ago".
pub fn audited(now: jiff::Timestamp, at: jiff::Timestamp) -> String {
    match (now.as_second() - at.as_second()) / 86_400 {
        d if d <= 0 => "audited today".into(),
        1 => "audited yesterday".into(),
        d => format!("audited {d} days ago"),
    }
}

/// The key of an item's row in a target's list (put off and found again by it).
pub fn row_key(id: &str) -> String {
    sentry_core::maint::rec::audit_key(id)
}

/// A slot's id as the audit's items write it.
pub fn name(id: &str) -> &str {
    if id.is_empty() { LOCAL } else { id }
}

/// The target whose list shows an item: the network it names; for one that spans targets
/// or names none, a network the window has (Security is where the system is looked at as
/// one); else the one target it is about.
fn home<'a>(i: &'a Item, system: &'a [Sys]) -> &'a str {
    if let Some(n) = i.targets.iter().find(|t| t.starts_with("net:")) {
        return n;
    }
    if i.targets.len() != 1
        && let Some(s) = system.iter().find(|s| s.peer.id.starts_with("net:"))
    {
        return &s.peer.id;
    }
    i.targets.first().map_or(LOCAL, String::as_str)
}

/// The audit's items the target `me` lists: what is to do first, what is worth doing and
/// what is asked of the user (fine and couldn't-check are the report's). With one target
/// in the window, all of them; an item whose own target the window doesn't have goes to
/// this machine.
pub fn mine<'a>(sec: &'a Sec, me: &str, system: &[Sys]) -> Vec<&'a Item> {
    let Some(r) = &sec.report else {
        return Vec::new();
    };
    let has = |id: &str| system.iter().any(|s| name(&s.peer.id) == id);
    let mut out: Vec<&Item> = r
        .items
        .iter()
        .filter(|i| match i.state {
            State::DoFirst | State::Worth => true,
            // Answered since the report was made: nothing to ask any more.
            State::Ask => i
                .question
                .as_ref()
                .is_some_and(|q| sec.answers.get(q).is_none()),
            State::Fine | State::CouldNotCheck => false,
        })
        .filter(|i| {
            if system.len() < 2 {
                return true;
            }
            let h = home(i, system);
            h == name(me) || (!has(h) && me.is_empty())
        })
        .collect();
    out.sort_by_key(|i| (std::cmp::Reverse(i.state.weight()), i.rank));
    out
}

/// What `items` with this id spans: more than one target makes its session one across
/// them (which any session is; this is for the words).
pub fn spans(i: &Item) -> bool {
    i.targets.len() > 1
}

/// Claude's review of the audit's evidence: the web for advisories, and nothing else. It
/// can run nothing, read no file and write nothing, so it keeps the web whatever targets
/// the window has.
pub fn review_profile() -> Profile {
    let web = ["WebFetch", "WebSearch"].map(String::from).to_vec();
    Profile {
        system: "You are reviewing the evidence of a security audit inside sentry, a \
                 monitoring and maintenance TUI. You can run nothing and change nothing, and \
                 you have no access to the devices: only the evidence you are given, and the \
                 web (WebFetch, WebSearch) for security advisories on the exact versions it \
                 lists. Answer in plain words for someone who is not a security expert, in \
                 under about 400 words."
            .into(),
        tools: web.clone(),
        allowed: web,
        denied: [
            "Bash",
            "Read",
            "Edit",
            "Write",
            "NotebookEdit",
            "Grep",
            "Glob",
        ]
        .map(String::from)
        .to_vec(),
        dirs: Vec::new(),
    }
}

/// The report as a document: Claude's review first, when there is one, then the report's
/// own sections.
pub fn document(sec: &Sec) -> String {
    let Some(r) = &sec.report else {
        return String::new();
    };
    let mut out = String::new();
    match (&sec.review, sec.reviewing) {
        (Some(text), _) => {
            out.push_str("## What matters most here\n");
            out.push_str("(Claude's reading of the evidence below; the checks are sentry's.)\n");
            // Its own headings go one level down, under ours.
            for l in text.trim().lines() {
                match l.strip_prefix("## ").or_else(|| l.strip_prefix("# ")) {
                    Some(h) => out.push_str(&format!("**{h}**\n")),
                    None => out.push_str(&format!("{l}\n")),
                }
            }
            out.push('\n');
        }
        (None, true) => out.push_str(
            "## What matters most here\nClaude is reading the evidence: its review appears \
             here.\n\n",
        ),
        (None, false) => {}
    }
    // The plain report, its section titles as headings.
    for l in sentry_core::secaudit::render(r).lines() {
        let section = !l.starts_with(' ')
            && l.ends_with(')')
            && ["Do these first", "Worth doing", "Fine", "Couldn't check"]
                .iter()
                .any(|s| l.starts_with(s));
        if section || l == "Not read" {
            out.push_str(&format!("## {l}\n"));
        } else if l.starts_with("Security audit · ") {
            out.push_str(&format!("# {l}\n"));
        } else if let Some(rest) = l.strip_prefix("      Answer: ") {
            // In the window an answer is Enter on its row, not a command.
            let _ = rest;
            out.push_str("      Answer: Enter on its row (yes, no, or you don't know)\n");
        } else {
            out.push_str(&format!("{l}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry_core::apply::session::Peer;
    use sentry_core::secaudit::Group;

    fn item(id: &str, state: State, targets: &[&str]) -> Item {
        Item {
            id: id.into(),
            group: Group::GettingIn,
            state,
            rank: 0,
            title: id.into(),
            why: String::new(),
            fix: String::new(),
            targets: targets.iter().map(|t| t.to_string()).collect(),
            evidence: Vec::new(),
            brief: String::new(),
            question: (state == State::Ask).then(|| format!("q:{id}")),
        }
    }

    fn sys(id: &str) -> Sys {
        Sys {
            peer: Peer {
                id: id.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Each item is listed by one target: the network for what names it or spans targets,
    /// else the target it is about; fine and couldn't-check stay in the report; an
    /// answered question isn't asked again.
    #[test]
    fn each_item_has_one_home() {
        let mut sec = Sec::new();
        let items = vec![
            item("door", State::DoFirst, &["net:home", "srv:nas"]),
            item("watch", State::Worth, &["srv:nas", "local"]),
            item("os", State::Worth, &["srv:nas"]),
            item("keys", State::DoFirst, &["local"]),
            item("fine", State::Fine, &["local"]),
            item("blind", State::CouldNotCheck, &["srv:nas"]),
            item("asked", State::Ask, &["local"]),
            item("gone", State::Worth, &["srv:other"]),
        ];
        sec.report = Some(Report {
            version: 1,
            at: "2026-11-01T00:00:00Z".parse().unwrap(),
            targets: Vec::new(),
            observed: false,
            items,
            errors: Vec::new(),
            diff: Default::default(),
        });
        let ids = |sec: &Sec, me: &str, system: &[Sys]| -> Vec<String> {
            mine(sec, me, system).iter().map(|i| i.id.clone()).collect()
        };
        let all = [sys(""), sys("srv:nas"), sys("net:home")];
        assert_eq!(ids(&sec, "net:home", &all), ["door", "watch"]);
        assert_eq!(ids(&sec, "srv:nas", &all), ["os"]);
        // (A server the window doesn't have: this machine lists it.)
        assert_eq!(ids(&sec, "", &all), ["keys", "gone", "asked"]);
        // Without a network, what spans targets is the first target's.
        let two = [sys(""), sys("srv:nas")];
        assert_eq!(ids(&sec, "srv:nas", &two), ["watch", "os"]);
        // One target alone lists everything.
        assert_eq!(ids(&sec, "", &[]).len(), 6);
        // Answered: no longer asked.
        sec.answers
            .set("q:asked", true, jiff::civil::date(2026, 11, 2));
        assert_eq!(ids(&sec, "", &all), ["keys", "gone"]);

        assert_eq!(
            audited(
                "2026-11-04T01:00:00Z".parse().unwrap(),
                sec.report.as_ref().unwrap().at
            ),
            "audited 3 days ago"
        );
        let doc = document(&sec);
        assert!(doc.contains("## Do these first (2)"), "{doc}");
        assert!(!doc.contains("What matters most here"));
        sec.review = Some("## Do these first\nClose the door.".into());
        let doc = document(&sec);
        assert!(
            doc.starts_with("## What matters most here\n")
                && doc.contains("**Do these first**\nClose the door."),
            "{doc}"
        );
        // The review can only read the web.
        let p = review_profile();
        assert_eq!(p.tools, ["WebFetch", "WebSearch"]);
        assert!(p.denied.iter().any(|d| d == "Bash"));
    }
}
