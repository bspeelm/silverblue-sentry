//! What this machine keeps about a server's SusCheck checks: how far you have looked, and
//! which checks you marked right or wrong. `servers/<name>/suscheck.toml`, beside the
//! server's other records; never anything of a check itself (no text, brand, domain or
//! computer), only ids and your word for each.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::collect::suscheck::{Id, Verdict};

/// A mark is kept this long after its check was made: SusCheck keeps a check 30 days, so by
/// then it is long gone.
pub const KEEP_DAYS: i64 = 120;

/// The word for "SusCheck was right".
pub const RIGHT: &str = "right";

/// Your word on one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mark {
    /// `right`, or what it should have been: `likely_safe`, `suspicious`, `likely_malicious`.
    pub verdict: String,
    pub at: jiff::Timestamp,
}

impl Mark {
    /// What the mark says the check should have been; None: it was right.
    pub fn should_be(&self) -> Option<Verdict> {
        Verdict::of(&self.verdict)
    }

    /// As the screen says it.
    pub fn said(&self) -> String {
        match self.should_be() {
            Some(v) => format!("wrong: should be \"{}\"", v.said()),
            None => "right".into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Records {
    /// The newest check you have had on screen (its id). Checks after it are new to you.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seen: Option<String>,
    /// Id → your mark.
    pub marks: BTreeMap<String, Mark>,
}

pub fn path(server: &str) -> PathBuf {
    sentry_core::maint::root(server).join("suscheck.toml")
}

impl Records {
    /// The file's text as records. Whatever isn't an id, or a word a mark can be, is left
    /// out: the file is this machine's, and still only ever holds what the grammar allows.
    pub fn parse(text: &str) -> Records {
        let mut r: Records = toml::from_str(text).unwrap_or_default();
        r.seen = r.seen.filter(|s| Id::parse(s).is_some());
        r.marks.retain(|id, m| {
            Id::parse(id).is_some() && (m.verdict == RIGHT || m.should_be().is_some())
        });
        r
    }

    pub fn load(server: &str) -> Records {
        std::fs::read_to_string(path(server))
            .map(|t| Records::parse(&t))
            .unwrap_or_default()
    }

    /// Marks of checks made more than [`KEEP_DAYS`] ago go. True: some did.
    pub fn prune(&mut self, now: jiff::Timestamp) -> bool {
        let oldest = now.as_second() - KEEP_DAYS * 86_400;
        let before = self.marks.len();
        self.marks.retain(|id, _| {
            Id::parse(id)
                .and_then(|i| i.time())
                .is_none_or(|t| t >= oldest)
        });
        self.marks.len() != before
    }

    pub fn text(&self) -> String {
        format!(
            "# SusCheck on this server: how far you have looked (seen), and the checks you\n\
             # marked right or wrong (m on the SusCheck screen, x clears). Ids only: nothing\n\
             # of a check is kept here.\n{}",
            toml::to_string(self).unwrap_or_default()
        )
    }

    /// Written whole, through a temporary file renamed into place.
    pub fn save(&self, server: &str) -> std::io::Result<()> {
        sentry_core::paths::write_atomic(&path(server), self.text().as_bytes())
    }

    pub fn mark(&self, id: &Id) -> Option<&Mark> {
        self.marks.get(id.as_str())
    }

    /// (marked wrong, marked at all)
    pub fn marked(&self) -> (usize, usize) {
        (
            self.marks.values().filter(|m| m.verdict != RIGHT).count(),
            self.marks.len(),
        )
    }

    /// `newest` has been on screen: true when that moved `seen` forward.
    pub fn see(&mut self, newest: Id) -> bool {
        if self.seen.as_deref().is_some_and(|s| s >= newest.as_str()) {
            return false;
        }
        self.seen = Some(newest.as_str().to_string());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_and_seen_survive_the_file_and_old_marks_go() {
        let id = |s: &str| Id::parse(s).unwrap();
        let now: jiff::Timestamp = "2026-11-05T12:00:00Z".parse().unwrap();
        let mut r = Records::default();
        assert!(r.see(id("20261103T080542Z-e5f6")));
        assert!(!r.see(id("20261101T091500Z-a1b2")), "never backwards");
        assert!(!r.see(id("20261103T080542Z-e5f6")));
        r.marks.insert(
            "20261101T091500Z-a1b2".into(),
            Mark {
                verdict: RIGHT.into(),
                at: now,
            },
        );
        r.marks.insert(
            "20261103T080542Z-e5f6".into(),
            Mark {
                verdict: Verdict::Suspicious.word().into(),
                at: now,
            },
        );
        // A check from last spring: its mark is past keeping.
        r.marks.insert(
            "20260401T000000Z-0000".into(),
            Mark {
                verdict: RIGHT.into(),
                at: now,
            },
        );
        assert_eq!(r.marked(), (1, 3));
        let server = format!("sus-records-{}", std::process::id());
        r.save(&server).unwrap();
        let mut back = Records::load(&server);
        assert_eq!(back, r);
        assert!(back.prune(now) && !back.prune(now));
        assert_eq!(back.marked(), (1, 2));
        assert_eq!(
            back.mark(&id("20261103T080542Z-e5f6")).unwrap().said(),
            "wrong: should be \"be careful\""
        );
        assert_eq!(
            back.mark(&id("20261101T091500Z-a1b2")).unwrap().said(),
            "right"
        );
        // Nothing but ids and the four words gets in from the file, whoever wrote it.
        let odd = Records::parse(
            "seen = \"../../etc\"\n[marks.\"../x\"]\nverdict = \"right\"\nat = \"2026-11-05T12:00:00Z\"\n\
             [marks.\"20261103T080542Z-e5f6\"]\nverdict = \"rm -rf\"\nat = \"2026-11-05T12:00:00Z\"\n\
             [marks.\"20261101T091500Z-a1b2\"]\nverdict = \"likely_safe\"\nat = \"2026-11-05T12:00:00Z\"\n",
        );
        assert_eq!(odd.seen, None);
        assert_eq!(
            odd.marks.keys().collect::<Vec<_>>(),
            ["20261101T091500Z-a1b2"]
        );
        assert_eq!(Records::parse("not toml ["), Records::default());
        let text = std::fs::read_to_string(path(&server)).unwrap();
        assert!(text.starts_with("# SusCheck on this server"), "{text}");
        let _ = std::fs::remove_file(path(&server));
    }
}
