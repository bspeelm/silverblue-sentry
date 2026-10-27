//! Each item's standing: pinned vs running vs newest upstream, and what deserves a look.
//! Pure: from the config, what the server has, the cached lookups and today's date.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::local::Local;
use super::upstream::{self, Eol, Lookups, Release};
use super::{State, version};
use crate::audit::{Finding, Sev};
use crate::server::config::{MaintItem, Risk};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Flag {
    /// A newer release mentions a security fix.
    Security,
    /// What runs isn't what's pinned.
    Drift,
    /// Its review date has passed.
    ReviewDue,
    /// Past its end of life.
    Eol,
    /// End of life within 90 days.
    EolSoon,
    /// Newer versions exist.
    Behind,
    /// Held on purpose (a reason given, or apt holds).
    Held,
    /// Up to date with what upstream offers.
    Current,
    /// Planned to be removed.
    Retire,
    /// Its version couldn't be read, or there's nothing to compare it with.
    Unknown,
}

impl Flag {
    pub fn word(self) -> &'static str {
        match self {
            Flag::Security => "security",
            Flag::Drift => "drift",
            Flag::ReviewDue => "review due",
            Flag::Eol => "end of life",
            Flag::EolSoon => "eol soon",
            Flag::Behind => "behind",
            Flag::Held => "held",
            Flag::Current => "current",
            Flag::Retire => "retire",
            Flag::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Status {
    pub id: String,
    pub risk: Risk,
    pub pinned: Option<String>,
    pub running: Option<String>,
    /// The newest upstream release that counts (or apt's candidate).
    pub latest: Option<String>,
    /// Releases newer than the pin, newest first.
    pub newer: Vec<Release>,
    pub flags: Vec<Flag>,
    /// The review date in force (a snooze overrides the config's).
    pub review_by: Option<jiff::civil::Date>,
    pub eol: Option<Eol>,
    /// Why something is unknown.
    pub note: Option<String>,
}

impl Status {
    pub fn has(&self, f: Flag) -> bool {
        self.flags.contains(&f)
    }
}

pub fn evaluate(
    items: &[MaintItem],
    local: &BTreeMap<String, Local>,
    lookups: Option<&Lookups>,
    state: &State,
    today: jiff::civil::Date,
) -> Vec<Status> {
    items
        .iter()
        .map(|it| one(it, local.get(&it.id), lookups, state, today))
        .collect()
}

fn one(
    it: &MaintItem,
    l: Option<&Local>,
    lookups: Option<&Lookups>,
    state: &State,
    today: jiff::civil::Date,
) -> Status {
    let l = l.cloned().unwrap_or_default();
    let mut s = Status {
        id: it.id.clone(),
        risk: it.risk,
        pinned: l.pinned.clone(),
        running: l.running.clone(),
        review_by: state.snooze.get(&it.id).copied().or(it.review_by),
        note: l.note.clone(),
        ..Default::default()
    };
    let mut flags = Vec::new();
    // What's newer: apt's candidate for packages, upstream releases otherwise.
    if !it.apt.is_empty() {
        if let (Some(c), Some(p)) = (&l.candidate, &l.pinned) {
            s.latest = Some(c.clone());
            if version::cmp(c, p).is_gt() {
                s.newer.push(Release {
                    version: c.clone(),
                    ..Default::default()
                });
            }
        }
    } else if let Some(src) = &it.source {
        match lookups.and_then(|lk| lk.sources.get(src)) {
            Some(up) if up.err.is_none() => {
                let all =
                    upstream::comparable(&up.releases, it.tag.as_deref(), l.pinned.as_deref());
                s.latest = all.first().map(|r| r.version.clone());
                if let Some(p) = &l.pinned {
                    s.newer = all
                        .into_iter()
                        .filter(|r| version::cmp(&r.version, p).is_gt())
                        .collect();
                }
            }
            Some(up) => {
                s.note
                    .get_or_insert_with(|| up.err.clone().unwrap_or_default());
            }
            None => {
                s.note
                    .get_or_insert_with(|| "not looked up yet (c on the Maintenance tab)".into());
            }
        }
    }
    if let Some(key) = &it.eol
        && let Some(Ok(e)) = lookups.and_then(|lk| lk.eol.get(key))
    {
        if let Some(d) = e.eol {
            let days = (d - today).get_days();
            if d <= today {
                flags.push(Flag::Eol);
            } else if days <= 90 {
                flags.push(Flag::EolSoon);
            }
        }
        s.eol = Some(e.clone());
        // Only an end of life to watch (an OS release): its cycle stands for the version.
        if it.image.is_none() && it.apt.is_empty() && it.version_cmd.is_none() {
            s.pinned = Some(e.cycle.clone());
            s.latest = e.latest.clone();
        }
    }
    if s.newer.iter().any(|r| r.security) {
        flags.push(Flag::Security);
    }
    if let (Some(p), Some(r)) = (&l.pinned, &l.running)
        && version::cmp(p, r).is_ne()
    {
        flags.push(Flag::Drift);
    }
    if s.review_by.is_some_and(|d| d <= today) {
        flags.push(Flag::ReviewDue);
    }
    if it.retire.is_some() {
        flags.push(Flag::Retire);
    }
    if it.hold.is_some() || l.held {
        flags.push(Flag::Held);
    }
    let eol_only = it.image.is_none() && it.apt.is_empty() && it.version_cmd.is_none();
    if !s.newer.is_empty() {
        flags.push(Flag::Behind);
    } else if it.retire.is_some() {
        // Going away: whether it's current doesn't matter.
    } else if eol_only && s.eol.is_some() {
        if !flags.contains(&Flag::Eol) && !flags.contains(&Flag::EolSoon) {
            flags.push(Flag::Current);
        }
    } else if s.pinned.is_none() || s.latest.is_none() {
        if s.note.is_none() && it.source.is_none() && it.apt.is_empty() {
            s.note = Some("no source: to compare it with".into());
        }
        flags.push(Flag::Unknown);
    } else {
        flags.push(Flag::Current);
    }
    s.flags = flags;
    s
}

/// `srv:maint:*` findings: security fixes upstream, drift, end of life, review dates, and
/// newer versions (for a held item only once its review date has passed, so a deliberate hold
/// doesn't nag).
pub fn findings(statuses: &[Status], items: &[MaintItem]) -> Vec<Finding> {
    let mut out = Vec::new();
    for s in statuses {
        let it = items.iter().find(|i| i.id == s.id);
        let hold = it.and_then(|i| i.hold.clone());
        let pinned = s.pinned.as_deref().unwrap_or("?");
        let newest = s.newer.first().map_or("?", |r| r.version.as_str());
        let mk =
            |kind: &str, sev: Sev, msg: String, what: &str, why: String, fix: String| Finding {
                id: format!("srv:maint:{kind}:{}", s.id),
                severity: sev,
                category: "maintenance".into(),
                message: msg,
                evidence: hold
                    .as_ref()
                    .map_or(String::new(), |h| format!("held because: {h}")),
                what: what.into(),
                why,
                fix,
                ..Default::default()
            };
        if s.has(Flag::Security) {
            let fixes: Vec<&str> = s
                .newer
                .iter()
                .filter(|r| r.security)
                .map(|r| r.version.as_str())
                .collect();
            out.push(mk(
                "security",
                Sev::High,
                format!("{}: newer releases mention security fixes ({})", s.id, fixes.join(", ")),
                "Upstream released versions after the pinned one whose notes mention a security fix.",
                format!("Pinned at {pinned}; the fix may matter for how this server uses it."),
                "Assess it (A on the Maintenance tab), then move it with its workflow (p).".into(),
            ));
        }
        if s.has(Flag::Drift) {
            out.push(mk(
                "drift",
                Sev::Medium,
                format!(
                    "{}: runs {} but the pin says {pinned}",
                    s.id,
                    s.running.as_deref().unwrap_or("?")
                ),
                "What runs isn't what the configuration pins.",
                "A change was made by hand, or the pin changed without the container being recreated.".into(),
                "Recreate it from the pin, or pin what runs.".into(),
            ));
        }
        if s.has(Flag::Eol) || s.has(Flag::EolSoon) {
            let when = s
                .eol
                .as_ref()
                .and_then(|e| e.eol)
                .map_or("?".into(), |d| d.to_string());
            out.push(mk(
                "eol",
                if s.has(Flag::Eol) {
                    Sev::High
                } else {
                    Sev::Medium
                },
                format!("{}: end of life {when}", s.id),
                "Its release line stops getting fixes.",
                "Past that date, security fixes stop.".into(),
                "Plan the move to a supported version.".into(),
            ));
        }
        if s.has(Flag::ReviewDue) {
            out.push(mk(
                "review",
                Sev::Medium,
                format!(
                    "{}: review due ({})",
                    s.id,
                    s.review_by.map_or(String::new(), |d| d.to_string())
                ),
                "It's held deliberately until a date that has passed.",
                "The reason for holding it may no longer apply.".into(),
                "Assess it (A), then move it (p), or set a new date (z).".into(),
            ));
        }
        let held = s.has(Flag::Held);
        if s.has(Flag::Behind) && (!held || s.has(Flag::ReviewDue)) {
            out.push(mk(
                "behind",
                Sev::Low,
                format!("{}: {pinned} → {newest} ({} newer)", s.id, s.newer.len()),
                "Newer versions exist upstream.",
                "Staying far behind makes the eventual move bigger.".into(),
                "Assess it (A on the Maintenance tab).".into(),
            ));
        }
        if s.has(Flag::Retire) {
            let by = it
                .and_then(|i| i.retire.as_ref())
                .and_then(|r| r.replaced_by.clone())
                .map_or(String::new(), |r| format!(", replaced by {r}"));
            out.push(mk(
                "retire",
                Sev::Low,
                format!("{}: planned for removal{by}", s.id),
                "Marked to be retired in server_config.yaml.",
                "Until it's removed it still runs and needs updates.".into(),
                "Retire it with its workflow (p) when ready.".into(),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::config::{ImageRef, Retire};
    use crate::server::maint::upstream::Upstream;

    fn d(s: &str) -> jiff::civil::Date {
        s.parse().unwrap()
    }

    fn rel(v: &str, security: bool) -> Release {
        Release {
            version: v.into(),
            security,
            ..Default::default()
        }
    }

    fn setup() -> (Vec<MaintItem>, BTreeMap<String, Local>, Lookups) {
        let web = MaintItem {
            id: "web".into(),
            image: Some(ImageRef {
                service: Some("web".into()),
                ..Default::default()
            }),
            source: Some("github:example/web".into()),
            hold: Some("1.5 migrates the database one way".into()),
            review_by: Some(d("2027-01-15")),
            ..Default::default()
        };
        let engine = MaintItem {
            id: "engine".into(),
            apt: vec!["engine-pkg".into()],
            risk: Risk::High,
            ..Default::default()
        };
        let legacy = MaintItem {
            id: "legacy".into(),
            version_cmd: Some("legacy --version".into()),
            retire: Some(Retire {
                replaced_by: Some("new.service".into()),
                workflow: None,
            }),
            ..Default::default()
        };
        let os = MaintItem {
            id: "os".into(),
            eol: Some("debian/12".into()),
            ..Default::default()
        };
        let mut local = BTreeMap::new();
        local.insert(
            "web".into(),
            Local {
                pinned: Some("1.4.2".into()),
                running: Some("1.4.1".into()),
                ..Default::default()
            },
        );
        local.insert(
            "engine".into(),
            Local {
                pinned: Some("5:24.3.1-1".into()),
                running: Some("5:24.3.1-1".into()),
                candidate: Some("5:24.4.0-1".into()),
                held: true,
                ..Default::default()
            },
        );
        local.insert(
            "legacy".into(),
            Local {
                pinned: Some("2.0".into()),
                running: Some("2.0".into()),
                ..Default::default()
            },
        );
        let mut lk = Lookups::default();
        lk.sources.insert(
            "github:example/web".into(),
            Upstream {
                releases: vec![
                    rel("v1.5.2", true),
                    rel("v1.5.1", false),
                    rel("v1.4.2", false),
                ],
                err: None,
            },
        );
        lk.eol.insert(
            "debian/12".into(),
            Ok(Eol {
                cycle: "12".into(),
                eol: Some(d("2026-12-01")),
                latest: None,
            }),
        );
        (vec![web, engine, legacy, os], local, lk)
    }

    #[test]
    fn standing_of_each_item() {
        let (items, local, lk) = setup();
        let st = evaluate(
            &items,
            &local,
            Some(&lk),
            &State::default(),
            d("2026-10-27"),
        );
        let web = &st[0];
        assert_eq!(web.latest.as_deref(), Some("v1.5.2"));
        assert_eq!(web.newer.len(), 2);
        for f in [Flag::Security, Flag::Drift, Flag::Held, Flag::Behind] {
            assert!(web.has(f), "{f:?} in {:?}", web.flags);
        }
        assert!(!web.has(Flag::ReviewDue));
        let engine = &st[1];
        assert!(engine.has(Flag::Held) && engine.has(Flag::Behind));
        assert_eq!(engine.newer[0].version, "5:24.4.0-1");
        assert!(st[2].has(Flag::Retire) && !st[2].has(Flag::Unknown));
        assert!(st[3].has(Flag::EolSoon));
    }

    #[test]
    fn a_held_item_only_nags_once_its_review_is_due() {
        let (items, local, lk) = setup();
        let ids = |today: &str, state: &State| -> Vec<String> {
            let st = evaluate(&items, &local, Some(&lk), state, d(today));
            findings(&st, &items).into_iter().map(|f| f.id).collect()
        };
        let now = ids("2026-10-27", &State::default());
        assert!(now.contains(&"srv:maint:security:web".to_string()));
        assert!(now.contains(&"srv:maint:drift:web".to_string()));
        assert!(
            !now.contains(&"srv:maint:behind:web".to_string()),
            "held, not due: {now:?}"
        );
        assert!(
            !now.contains(&"srv:maint:behind:engine".to_string()),
            "apt-held: {now:?}"
        );
        assert!(now.contains(&"srv:maint:retire:legacy".to_string()));
        assert!(now.contains(&"srv:maint:eol:os".to_string()));
        let later = ids("2027-02-01", &State::default());
        assert!(later.contains(&"srv:maint:review:web".to_string()));
        assert!(later.contains(&"srv:maint:behind:web".to_string()));
        // A snooze moves the review date.
        let mut snoozed = State::default();
        snoozed.snooze.insert("web".into(), d("2027-06-01"));
        let s = ids("2027-02-01", &snoozed);
        assert!(!s.contains(&"srv:maint:review:web".to_string()));
    }
}
