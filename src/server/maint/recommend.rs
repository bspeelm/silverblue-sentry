//! What to maintain next, and why: rules over each item's standing, the plans, what
//! discovery found, pending updates and reboots, and how long ago each routine workflow last
//! ran (the maintenance log against `maintenance.cadence`). Pure.

use std::collections::BTreeMap;

use super::discover::Found;
use super::eval::{Flag, Status};
use super::log::LogEntry;
use super::plan::{PlanDoc, PlanStatus};
use crate::server::collect::apt::Apt;
use crate::server::config::{MaintItem, Risk};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Now,
    Soon,
    Routine,
    Tidy,
}

impl Level {
    pub fn word(self) -> &'static str {
        match self {
            Level::Now => "now",
            Level::Soon => "soon",
            Level::Routine => "routine",
            Level::Tidy => "tidy",
        }
    }
}

/// What Enter does on a recommendation.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Have Claude write a plan for the item.
    Plan(String),
    /// Open the item's plan (ready to apply).
    OpenPlan(String),
    /// Start a workflow.
    Run(String),
    /// Track what discovery found (index into `Found::candidates`).
    Track(usize),
    /// Stop tracking a gone item.
    Remove(String),
    /// Look at the item (its details; nothing to run).
    Look(String),
    /// An audit finding: ask Claude how to fix it (finding id).
    Fix(String),
    /// Audit the server now.
    Audit,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rec {
    pub level: Level,
    /// For `z` (look again later): the item's id, `wf:<name>`, or the discovery key.
    pub key: String,
    pub title: String,
    pub why: String,
    pub action: Action,
    pub item: Option<String>,
}

pub struct Inputs<'a> {
    pub items: &'a [MaintItem],
    pub statuses: &'a [Status],
    pub plans: &'a BTreeMap<String, PlanDoc>,
    pub found: &'a Found,
    pub apt: Option<&'a Apt>,
    pub log: &'a [LogEntry],
    pub cadence: &'a BTreeMap<String, crate::config::Dur>,
    pub workflows: &'a [String],
    /// Recommendations put off until a date (`z`), by key.
    pub snooze: &'a BTreeMap<String, jiff::civil::Date>,
    pub now: jiff::Timestamp,
    /// The latest audit's findings, and when it was taken (None: no audit yet).
    pub findings: &'a [crate::audit::Finding],
    pub audited: Option<jiff::Timestamp>,
}

/// An audit older than this is due again.
const AUDIT_EVERY_DAYS: i64 = 7;

fn days(secs: i64) -> i64 {
    secs / 86_400
}

pub fn recommend(i: &Inputs) -> Vec<Rec> {
    let today = i.now.to_zoned(jiff::tz::TimeZone::UTC).date();
    let mut out: Vec<Rec> = Vec::new();
    let item = |id: &str| i.items.iter().find(|x| x.id == id);
    for s in i.statuses {
        let id = s.id.clone();
        let plan = i.plans.get(&id);
        let rec = |level, title: String, why: String, action| Rec {
            level,
            key: id.clone(),
            title,
            why,
            action,
            item: Some(id.clone()),
        };
        let newest = s.newer.first().map(|r| r.version.as_str()).unwrap_or("?");
        let pinned = s.pinned.as_deref().unwrap_or("?");
        if let Some(p) = plan {
            match p.head.status {
                PlanStatus::Ready => {
                    out.push(rec(
                        Level::Now,
                        format!(
                            "Apply the plan for {id} (→ {})",
                            p.head.to.as_deref().unwrap_or("retire")
                        ),
                        "A plan is ready.".into(),
                        Action::OpenPlan(id.clone()),
                    ));
                    continue;
                }
                PlanStatus::Failed => out.push(rec(
                    Level::Tidy,
                    format!("Plan {id} again"),
                    "Writing its plan failed.".into(),
                    Action::Plan(id.clone()),
                )),
                // Being written, or Claude advised waiting: nothing to add.
                _ => continue,
            }
        }
        let held = s.has(Flag::Held);
        if s.has(Flag::Security) && !held {
            let fixes: Vec<&str> = s
                .newer
                .iter()
                .filter(|r| r.security)
                .map(|r| r.version.as_str())
                .collect();
            out.push(rec(
                Level::Now,
                format!("{id}: security fix upstream ({pinned} → {newest})"),
                format!(
                    "Releases after the pin mention security fixes: {}.",
                    fixes.join(", ")
                ),
                Action::Plan(id.clone()),
            ));
        } else if s.has(Flag::Security) {
            out.push(rec(
                Level::Soon,
                format!("{id}: held, but newer releases fix security issues"),
                format!(
                    "Held because: {}. Check the hold still outweighs the fixes.",
                    item(&id)
                        .and_then(|x| x.hold.as_deref())
                        .unwrap_or("(no reason given)")
                ),
                Action::Plan(id.clone()),
            ));
        }
        if s.has(Flag::Eol) {
            out.push(rec(
                Level::Now,
                format!("{id}: past its end of life"),
                format!(
                    "{} stopped getting fixes on {}.",
                    s.eol.as_ref().map_or("It", |e| e.cycle.as_str()),
                    s.eol
                        .as_ref()
                        .and_then(|e| e.eol)
                        .map_or("?".into(), |d| d.to_string())
                ),
                Action::Plan(id.clone()),
            ));
        } else if s.has(Flag::EolSoon) {
            out.push(rec(
                Level::Soon,
                format!("{id}: end of life soon"),
                format!(
                    "Fixes stop on {}.",
                    s.eol
                        .as_ref()
                        .and_then(|e| e.eol)
                        .map_or("?".into(), |d| d.to_string())
                ),
                Action::Plan(id.clone()),
            ));
        }
        if s.has(Flag::Drift) {
            out.push(rec(
                Level::Now,
                format!(
                    "{id}: runs {} but the pin says {pinned}",
                    s.running.as_deref().unwrap_or("?")
                ),
                "Changed by hand, or the pin changed without the container being recreated.".into(),
                Action::Look(id.clone()),
            ));
        }
        if s.has(Flag::ReviewDue) {
            out.push(rec(
                Level::Soon,
                format!("{id}: its review date has passed"),
                format!(
                    "Held until {}: {}",
                    s.review_by.map_or("?".into(), |d| d.to_string()),
                    item(&id)
                        .and_then(|x| x.hold.as_deref())
                        .unwrap_or("check whether to move it")
                ),
                Action::Plan(id.clone()),
            ));
        }
        if s.has(Flag::Behind) && !held && !s.has(Flag::Security) {
            out.push(rec(
                Level::Routine,
                format!("{id}: {pinned} → {newest} ({} newer)", s.newer.len()),
                "Not held; staying far behind makes the eventual move bigger.".into(),
                Action::Plan(id.clone()),
            ));
        }
        if s.has(Flag::Retire) {
            out.push(rec(
                Level::Routine,
                format!("Retire {id}"),
                item(&id)
                    .and_then(|x| x.retire.as_ref())
                    .and_then(|r| r.replaced_by.as_deref())
                    .map_or("Marked for retirement.".into(), |r| {
                        format!("Replaced by {r}.")
                    }),
                Action::Plan(id.clone()),
            ));
        }
        let it = item(&id);
        let eol_only =
            it.is_some_and(|x| x.image.is_none() && x.apt.is_empty() && x.version_cmd.is_none());
        if s.has(Flag::Unknown)
            && !eol_only
            && it.is_some_and(|x| x.source.is_none() && x.apt.is_empty() && x.retire.is_none())
        {
            out.push(rec(
                Level::Tidy,
                format!("{id}: nothing to compare it with"),
                "Give it a source: (github:owner/repo, docker:repo or ghcr:owner/image) in the config."
                    .into(),
                Action::Look(id.clone()),
            ));
        }
    }
    // Routine workflows by cadence, from the log.
    let mut by_cadence: Vec<&str> = Vec::new();
    for (wf, every) in i.cadence {
        let last = i
            .log
            .iter()
            .filter(|e| &e.head.workflow == wf && e.head.result == "done")
            .filter_map(|e| e.head.ended)
            .max();
        let every_s = every.0.as_secs() as i64;
        let due = match last {
            None => true,
            Some(t) => i.now.as_second() - t.as_second() >= every_s,
        };
        if due && i.workflows.contains(wf) {
            by_cadence.push(wf);
            let overdue_twice =
                last.is_some_and(|t| i.now.as_second() - t.as_second() >= 2 * every_s);
            out.push(Rec {
                level: if overdue_twice {
                    Level::Soon
                } else {
                    Level::Routine
                },
                key: format!("wf:{wf}"),
                title: format!("Run {wf}"),
                why: match last {
                    Some(t) => format!(
                        "Last done {} days ago; due every {} days.",
                        days(i.now.as_second() - t.as_second()),
                        days(every_s)
                    ),
                    None => format!("Never run here; due every {} days.", days(every_s)),
                },
                action: Action::Run(wf.clone()),
                item: None,
            });
        }
    }
    // Updates and reboots waiting.
    if let Some(a) = i.apt {
        let has = |w: &str| i.workflows.iter().any(|x| x == w);
        let apt_wf = "apt-maintenance";
        let security = a
            .upgrades
            .iter()
            .filter(|p| p.kind == crate::server::collect::apt::Kind::Security)
            .count();
        // Security updates can't wait for the routine run.
        if !a.upgrades.is_empty() && has(apt_wf) && (security > 0 || !by_cadence.contains(&apt_wf))
        {
            out.push(Rec {
                level: if security > 0 {
                    Level::Now
                } else {
                    Level::Routine
                },
                key: format!("wf:{apt_wf}:updates"),
                title: if security > 0 {
                    format!(
                        "{} package update(s) waiting, {security} for security",
                        a.upgrades.len()
                    )
                } else {
                    format!("{} package update(s) waiting", a.upgrades.len())
                },
                why: format!("{apt_wf} applies them."),
                action: Action::Run(apt_wf.into()),
                item: None,
            });
        }
        if let Some(since) = a.reboot_since {
            let d = days(a.now - since);
            if d >= 7 {
                out.push(Rec {
                    level: Level::Soon,
                    key: "reboot".into(),
                    title: format!("A reboot has been pending for {d} days"),
                    why: format!(
                        "Running {}, newest installed {}: fixes in the new kernel and libraries aren't in use yet.",
                        a.running_kernel,
                        a.newest_kernel.as_deref().unwrap_or("?")
                    ),
                    action: if has(apt_wf) {
                        Action::Run(apt_wf.into())
                    } else {
                        Action::Look(String::new())
                    },
                    item: None,
                });
            }
        }
    }
    // The audit's findings (health and security), by severity. What the rules above already
    // say (items: srv:maint:*; updates and reboots) isn't repeated.
    let covered = |id: &str| {
        ["srv:maint:", "srv:updates:", "srv:reboot-required"]
            .iter()
            .any(|p| id.starts_with(p))
    };
    for f in i.findings.iter().filter(|f| !f.expected && !covered(&f.id)) {
        use crate::audit::Sev;
        out.push(Rec {
            level: match f.severity {
                Sev::High => Level::Now,
                Sev::Medium => Level::Soon,
                Sev::Low => Level::Tidy,
            },
            key: format!("finding:{}", f.id),
            title: f.message.clone(),
            why: if f.why.is_empty() {
                f.what.clone()
            } else {
                f.why.clone()
            },
            action: Action::Fix(f.id.clone()),
            item: None,
        });
    }
    // The audit itself: due again after a week.
    let age = i.audited.map(|t| days(i.now.as_second() - t.as_second()));
    if age.is_none_or(|d| d >= AUDIT_EVERY_DAYS) {
        out.push(Rec {
            level: Level::Routine,
            key: "audit".into(),
            title: "Audit the server".into(),
            why: match age {
                Some(d) => format!("The last audit was {d} days ago."),
                None => {
                    "No audit yet: services, containers, disks, SMART, listeners, updates.".into()
                }
            },
            action: Action::Audit,
            item: None,
        });
    }
    // Discovery.
    for (n, c) in i.found.candidates.iter().enumerate() {
        out.push(Rec {
            level: Level::Tidy,
            key: c.key.clone(),
            title: format!("Track {}", c.item.id),
            why: format!("Not tracked: {}.", c.what),
            action: Action::Track(n),
            item: None,
        });
    }
    for g in &i.found.gone {
        out.push(Rec {
            level: Level::Tidy,
            key: format!("gone:{}", g.id),
            title: format!("{} is gone", g.id),
            why: format!("{}: stop tracking it.", g.why),
            action: Action::Remove(g.id.clone()),
            item: Some(g.id.clone()),
        });
    }
    // Put off with z.
    out.retain(|r| i.snooze.get(&r.key).is_none_or(|d| *d <= today));
    let risk = |r: &Rec| {
        r.item
            .as_deref()
            .and_then(item)
            .map_or(Risk::Medium, |x| x.risk)
    };
    out.sort_by(|a, b| {
        a.level
            .cmp(&b.level)
            .then(risk(b).cmp(&risk(a)))
            .then(a.title.cmp(&b.title))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::maint::discover::{Candidate, Gone};
    use crate::server::maint::upstream::Release;

    fn status(id: &str, flags: &[Flag]) -> Status {
        Status {
            id: id.into(),
            pinned: Some("1.0".into()),
            newer: vec![Release {
                version: "1.2".into(),
                security: flags.contains(&Flag::Security),
                ..Default::default()
            }],
            flags: flags.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn ranked_with_reasons_and_actions() {
        let items: Vec<MaintItem> = ["web", "db", "cache", "engine", "planned"]
            .iter()
            .map(|id| MaintItem {
                id: id.to_string(),
                source: Some("docker:x".into()),
                risk: if *id == "engine" {
                    Risk::High
                } else {
                    Risk::Medium
                },
                hold: (*id == "engine").then(|| "restarts everything".into()),
                ..Default::default()
            })
            .collect();
        let statuses = vec![
            status("web", &[Flag::Security, Flag::Behind]),
            status("db", &[Flag::Behind]),
            status("cache", &[Flag::Current]),
            status("engine", &[Flag::Security, Flag::Held, Flag::Behind]),
            status("planned", &[Flag::Behind]),
        ];
        let mut plans = BTreeMap::new();
        let mut p = PlanDoc::default();
        p.head.status = PlanStatus::Ready;
        p.head.to = Some("1.2".into());
        plans.insert("planned".to_string(), p);
        let found = Found {
            candidates: vec![Candidate {
                key: "image:ui".into(),
                what: "compose service ui".into(),
                item: MaintItem {
                    id: "ui".into(),
                    ..Default::default()
                },
            }],
            gone: vec![Gone {
                id: "old".into(),
                why: "no container old any more".into(),
            }],
        };
        let mut cadence = BTreeMap::new();
        cadence.insert(
            "apt-maintenance".to_string(),
            crate::config::Dur::secs(30 * 86_400),
        );
        let now: jiff::Timestamp = "2026-10-27T12:00:00Z".parse().unwrap();
        let log = vec![
            LogEntry::parse(
                "+++\nworkflow = \"apt-maintenance\"\nresult = \"done\"\nended = \"2026-09-20T12:00:00Z\"\n+++\n",
            )
            .unwrap(),
        ];
        let workflows = vec!["apt-maintenance".to_string(), "compose-bump".to_string()];
        let snooze = BTreeMap::new();
        let finding = |id: &str, sev, msg: &str| crate::audit::Finding {
            id: id.into(),
            severity: sev,
            message: msg.into(),
            why: "because".into(),
            ..Default::default()
        };
        let mut expected = finding("srv:disk:/srv", crate::audit::Sev::High, "/srv is 96% full");
        expected.expected = true;
        let findings = vec![
            finding(
                "srv:service-down:app.service",
                crate::audit::Sev::High,
                "app.service is failed",
            ),
            finding(
                "srv:maint:security:web",
                crate::audit::Sev::High,
                "duplicate of the item",
            ),
            expected,
            finding(
                "srv:fail2ban:sshd",
                crate::audit::Sev::Low,
                "sshd: 3 banned",
            ),
        ];
        let inputs = Inputs {
            items: &items,
            statuses: &statuses,
            plans: &plans,
            found: &found,
            apt: None,
            log: &log,
            cadence: &cadence,
            workflows: &workflows,
            snooze: &snooze,
            now,
            findings: &findings,
            audited: Some(now),
        };
        let r = recommend(&inputs);
        let got: Vec<(Level, &str)> = r.iter().map(|x| (x.level, x.title.as_str())).collect();
        assert_eq!(
            got,
            [
                (Level::Now, "Apply the plan for planned (→ 1.2)"),
                (Level::Now, "app.service is failed"),
                (Level::Now, "web: security fix upstream (1.0 → 1.2)"),
                (
                    Level::Soon,
                    "engine: held, but newer releases fix security issues"
                ),
                (Level::Routine, "Run apt-maintenance"),
                (Level::Routine, "db: 1.0 → 1.2 (1 newer)"),
                (Level::Tidy, "Track ui"),
                (Level::Tidy, "old is gone"),
                (Level::Tidy, "sshd: 3 banned"),
            ]
        );
        assert_eq!(r[4].why, "Last done 37 days ago; due every 30 days.");
        assert_eq!(r[0].action, Action::OpenPlan("planned".into()));
        assert_eq!(
            r[1].action,
            Action::Fix("srv:service-down:app.service".into())
        );
        assert_eq!(r[6].action, Action::Track(0));
        // No audit for a week: it's recommended.
        let old: jiff::Timestamp = "2026-10-10T12:00:00Z".parse().unwrap();
        let r = recommend(&Inputs {
            audited: Some(old),
            ..inputs
        });
        let a = r.iter().find(|x| x.action == Action::Audit).unwrap();
        assert_eq!(a.why, "The last audit was 17 days ago.");
        // z: put off until a date.
        let mut snooze = BTreeMap::new();
        snooze.insert(
            "wf:apt-maintenance".to_string(),
            jiff::civil::date(2026, 11, 20),
        );
        let r = recommend(&Inputs {
            snooze: &snooze,
            ..Inputs { ..inputs }
        });
        assert!(!r.iter().any(|x| x.title == "Run apt-maintenance"));
    }
}
