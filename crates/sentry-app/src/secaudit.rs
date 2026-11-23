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
/// The key as Maintenance's key bar names it (Security names it itself): the last of
/// the screen's hints, so the first to go when the bar is narrow.
pub const HINT: (&str, &str) = ("S", "security audit");

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
    /// Per slot, the newest firmware or OS upgrade its log has (`App::survey`), said
    /// with where it ran.
    pub upgraded: Vec<Option<(jiff::Timestamp, String)>>,
    /// An upgrade that ended well in this window just now (a slot's run): when.
    pub upgrade_new: Option<jiff::Timestamp>,
    /// The newest upgrade the audit was run again for, by itself (once per upgrade).
    pub rerun_for: Option<jiff::Timestamp>,
    /// The audit running is that one: nothing opens, no review is asked for.
    pub quiet: bool,
    /// Tests: the run after an upgrade starts offline too (they hand the facts in), and so
    /// does the one a session on one of its items waits for.
    pub rerun_offline: bool,
    /// The sessions waiting for the run under way (or about to start) to say whether
    /// their item is still reported.
    pub asked: Vec<Asked>,
    /// The sessions that asked while a run was already under way: its facts may be from
    /// before their change, so a fresh run starts for them when it ends.
    pub again: Vec<Asked>,
}

/// A session on one of the audit's items that waits for the audit's answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Asked {
    /// Its slot.
    pub slot: TargetId,
    /// The item's id.
    pub item: String,
    /// The targets the item is about, as the report it was opened on said.
    pub targets: Vec<String>,
}

/// What the audit says of an item a session waits on: Ok(None) it no longer reports it,
/// Ok(Some(how)) it still does (its title and evidence), Err(why) it couldn't check.
pub type Answer = Result<Option<String>, String>;

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
            upgraded: Vec::new(),
            upgrade_new: None,
            rerun_for: None,
            quiet: false,
            rerun_offline: false,
            asked: Vec::new(),
            again: Vec::new(),
        }
    }

    /// What the latest report says of the item `id` (about `targets`, as the session was
    /// opened on it): one of its targets wasn't reached, or the audit couldn't check it,
    /// is no answer.
    pub fn answer(&self, id: &str, targets: &[String]) -> Answer {
        let Some(r) = &self.report else {
            return Err("there is no report".into());
        };
        let item = r.items.iter().find(|i| i.id == id);
        let about = item.map_or(targets, |i| i.targets.as_slice());
        let unreached: Vec<&str> = r
            .targets
            .iter()
            .filter(|t| !t.reached && about.contains(&t.id))
            .map(|t| t.name.as_str())
            .collect();
        if !unreached.is_empty() {
            return Err(format!("{} wasn't reachable", unreached.join(", ")));
        }
        match item {
            Some(i) if i.state == State::CouldNotCheck => Err(format!(
                "it couldn't check it this time ({})",
                if i.evidence.is_empty() {
                    i.title.clone()
                } else {
                    i.evidence.join("; ")
                }
            )),
            Some(i) if listed(self, i) => {
                let mut how = i.title.clone();
                for e in &i.evidence {
                    how.push_str(&format!("\n- {e}"));
                }
                Ok(Some(how))
            }
            _ => Ok(None),
        }
    }

    /// The newest upgrade the window knows of that ended after the report was made: the
    /// audit is run again for it (once).
    pub fn rerun_due(&self) -> Option<jiff::Timestamp> {
        let at = self
            .upgraded
            .iter()
            .flatten()
            .map(|(at, _)| *at)
            .chain(self.upgrade_new)
            .max()?;
        let report = self.report.as_ref()?;
        (at > report.at && self.rerun_for.is_none_or(|r| r < at) && !self.busy()).then_some(at)
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

/// What an upgrade of a target changes, and so what a report from before it can't say any
/// more: its firmware, its packages, its operating system and that system's support.
pub const UPGRADED: &[&str] = &["firmware", "packages", "os", "os-life"];

/// An item of a report made at `at` about what an upgrade since changed (`upgrades`: the
/// target as items name it, and when its newest upgrade ended). Withheld from the rows
/// until the audit has looked again.
pub fn outdated(i: &Item, at: jiff::Timestamp, upgrades: &[(String, jiff::Timestamp)]) -> bool {
    upgrades
        .iter()
        .any(|(t, when)| *when > at && UPGRADED.iter().any(|w| i.id == format!("sec:{w}:{t}")))
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
        .filter(|i| listed(sec, i))
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

/// Whether an item is one a target lists: to do first, worth doing, or a question not
/// answered since the report was made.
fn listed(sec: &Sec, i: &Item) -> bool {
    match i.state {
        State::DoFirst | State::Worth => true,
        State::Ask => i
            .question
            .as_ref()
            .is_some_and(|q| sec.answers.get(q).is_none()),
        State::Fine | State::CouldNotCheck => false,
    }
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
            && [
                "Do these first",
                "Worth doing",
                "Fine",
                "Couldn't check",
                "Needs your answer",
            ]
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
    /// A door's certificate is the network's (the session spans both); a machine's end of
    /// support and its log are that machine's alone, on its own Maintenance.
    #[test]
    fn certificates_releases_and_logs_have_their_home() {
        let mut sec = Sec::new();
        let items = vec![
            item(
                "sec:cert:net:home:tcp:443",
                State::DoFirst,
                &["net:home", "srv:nas"],
            ),
            item("sec:os-life:srv:nas", State::DoFirst, &["srv:nas"]),
            item("sec:os-life:local", State::Worth, &["local"]),
            item("sec:logs:srv:nas", State::Worth, &["srv:nas"]),
        ];
        sec.report = Some(Report {
            version: 1,
            at: "2026-11-01T00:00:00Z".parse().unwrap(),
            targets: Vec::new(),
            observed: false,
            items,
            errors: Vec::new(),
            diff: Default::default(),
            alone: String::new(),
        });
        let ids = |me: &str| -> Vec<String> {
            let all = [sys(""), sys("srv:nas"), sys("net:home")];
            mine(&sec, me, &all).iter().map(|i| i.id.clone()).collect()
        };
        assert_eq!(ids("net:home"), ["sec:cert:net:home:tcp:443"]);
        assert_eq!(ids("srv:nas"), ["sec:os-life:srv:nas", "sec:logs:srv:nas"]);
        assert_eq!(ids(""), ["sec:os-life:local"]);
    }

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
            alone: String::new(),
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

    /// After an upgrade, what the report said of that target's firmware, packages or system
    /// is withheld until a newer report; the audit is run again for it once.
    #[test]
    fn an_upgrade_since_the_report_withholds_its_items_and_reruns_once() {
        let at: jiff::Timestamp = "2026-11-01T00:00:00Z".parse().unwrap();
        let later: jiff::Timestamp = "2026-11-02T00:00:00Z".parse().unwrap();
        let up = vec![("net:home".to_string(), later)];
        let fw = item("sec:firmware:net:home", State::DoFirst, &["net:home"]);
        assert!(outdated(&fw, at, &up));
        assert!(!outdated(&fw, later, &up), "a report after it");
        let other = item("sec:firmware:net:lab", State::DoFirst, &["net:lab"]);
        assert!(!outdated(&other, at, &up), "another target's");
        let door = item("sec:door:net:home:tcp:443", State::DoFirst, &["net:home"]);
        assert!(!outdated(&door, at, &up), "not what an upgrade changes");
        let mut sec = Sec::new();
        sec.upgrade_new = Some(later);
        assert_eq!(sec.rerun_due(), None, "no report: nothing to look again at");
        sec.report = Some(Report {
            version: 1,
            at,
            targets: Vec::new(),
            observed: false,
            items: vec![fw],
            errors: Vec::new(),
            diff: Default::default(),
            alone: String::new(),
        });
        assert_eq!(sec.rerun_due(), Some(later));
        sec.rerun_for = Some(later);
        assert_eq!(sec.rerun_due(), None, "once");
    }
}
