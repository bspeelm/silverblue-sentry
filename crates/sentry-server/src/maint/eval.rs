//! Each item's standing: pinned vs running vs newest upstream, and what deserves a look.
//! Pure: from the config, what the server has, the cached lookups and today's date.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::local::Local;
use super::upstream::{self, Eol, Lookups, Release};
use super::version;
use crate::config::{MaintItem, Risk};
use sentry_core::finding::{Finding, Sev};

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
    /// Its retirement ran and ended well (the maintenance log says so): nothing left to do.
    Retired,
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
            Flag::Retired => "retired",
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
    /// The release series `eol:` resolved to, and its end of life.
    pub eol: Option<Eol>,
    /// How that series was told.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eol_from: Option<EolFrom>,
    /// Why something is unknown.
    pub note: Option<String>,
}

/// Where an item's release series (endoflife.date's cycle) came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EolFrom {
    /// The version that runs (or is pinned): `upstream::cycle_for`.
    Running,
    /// The server's own operating system release (`/etc/os-release`), for an item that only
    /// watches the OS's end of life.
    Os,
    /// The cycle written in the config (`product/cycle`): nothing else told it.
    Typed,
}

/// The server's operating system as endoflife.date names it: product and cycle
/// (`secaudit::release_from` of its `ID` and `VERSION_ID`).
pub type HostOs<'a> = Option<(&'a str, &'a str)>;

impl Status {
    pub fn has(&self, f: Flag) -> bool {
        self.flags.contains(&f)
    }
}

/// `retired`: the items whose retirement ended well (from the maintenance log, `retired_in`);
/// `os`: the server's own release, when it was read.
pub fn evaluate(
    items: &[MaintItem],
    local: &BTreeMap<String, Local>,
    lookups: Option<&Lookups>,
    os: HostOs,
    later: &sentry_core::maint::later::Snoozes,
    retired: &std::collections::BTreeSet<String>,
    today: jiff::civil::Date,
) -> Vec<Status> {
    items
        .iter()
        .map(|it| {
            one(
                it,
                local.get(&it.id),
                lookups,
                os,
                later,
                retired.contains(&it.id),
                today,
            )
        })
        .collect()
}

fn add_note(s: &mut Status, n: String) {
    match &mut s.note {
        Some(old) if !old.is_empty() => {
            old.push_str("; ");
            old.push_str(&n);
        }
        _ => s.note = Some(n),
    }
}

/// The series an item's `eol:` stands for, from what runs first (see [`EolFrom`]), with a
/// note when that isn't what the config says or nothing told it. None, no note: not looked
/// up yet.
fn series(
    it: &MaintItem,
    l: &Local,
    lookups: Option<&Lookups>,
    os: HostOs,
    s: &mut Status,
) -> Option<(Eol, EolFrom)> {
    let key = it.eol.as_deref()?;
    let product = upstream::product(key);
    let typed = key
        .split_once('/')
        .map(|(_, c)| c.trim())
        .filter(|c| !c.is_empty());
    let cycles = match lookups.and_then(|lk| lk.eol.get(product))? {
        Ok(c) => c,
        Err(e) => {
            add_note(
                s,
                format!("endoflife.date {product} couldn't be asked: {e}"),
            );
            return None;
        }
    };
    let eol_only = it.image.is_none() && it.apt.is_empty() && it.version_cmd.is_none();
    let version = if eol_only {
        None
    } else {
        l.running.as_deref().or(l.pinned.as_deref())
    };
    let found = if let Some(v) = version {
        upstream::cycle_for(cycles, v).map(|e| (e, EolFrom::Running, v.to_string()))
    } else if eol_only {
        os.filter(|(p, _)| *p == product).and_then(|(p, c)| {
            cycles
                .iter()
                .find(|e| e.cycle == c)
                .map(|e| (e, EolFrom::Os, format!("{p} {c}")))
        })
    } else {
        None
    };
    let found = found.or_else(|| {
        let t = typed?;
        cycles
            .iter()
            .find(|e| e.cycle == t)
            .map(|e| (e, EolFrom::Typed, String::new()))
    });
    match found {
        Some((e, from, what)) => {
            if from != EolFrom::Typed
                && let Some(t) = typed
                && t != e.cycle
            {
                add_note(
                    s,
                    format!("config says {t}; {what} runs, series {}", e.cycle),
                );
            }
            Some((e.clone(), from))
        }
        None => {
            add_note(
                s,
                match (version, typed) {
                    (Some(v), None) => format!(
                        "couldn't tell which series {v} belongs to (endoflife.date {product})"
                    ),
                    (_, Some(t)) => format!("endoflife.date {product} has no cycle {t}"),
                    (None, None) => {
                        format!("couldn't tell which series runs here (endoflife.date {product})")
                    }
                },
            );
            None
        }
    }
}

/// The items the maintenance log says were retired: a retirement run (kind `retire`) that
/// ended well. A retirement is done once, not routine.
pub fn retired_in(log: &[sentry_core::maint::log::LogEntry]) -> std::collections::BTreeSet<String> {
    log.iter()
        .filter(|e| e.head.kind == "retire" && e.head.result == "done")
        .filter_map(|e| e.head.item.clone())
        .collect()
}

fn one(
    it: &MaintItem,
    l: Option<&Local>,
    lookups: Option<&Lookups>,
    os: HostOs,
    later: &sentry_core::maint::later::Snoozes,
    retired: bool,
    today: jiff::civil::Date,
) -> Status {
    let l = l.cloned().unwrap_or_default();
    let mut s = Status {
        id: it.id.clone(),
        risk: it.risk,
        pinned: l.pinned.clone(),
        running: l.running.clone(),
        review_by: later.get(&it.id).copied().or(it.review_by),
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
                    .get_or_insert_with(|| "not looked up yet (c on Maintenance)".into());
            }
        }
    }
    if let Some((e, from)) = series(it, &l, lookups, os, &mut s) {
        s.eol_from = Some(from);
        if let Some(d) = e.eol {
            let days = (d - today).get_days();
            if d <= today {
                flags.push(Flag::Eol);
            } else if days <= 90 {
                flags.push(Flag::EolSoon);
            }
        }
        // Only an end of life to watch (an OS release): its cycle stands for the version.
        if it.image.is_none() && it.apt.is_empty() && it.version_cmd.is_none() {
            s.pinned = Some(e.cycle.clone());
            s.latest = e.latest.clone();
        }
        s.eol = Some(e);
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
        flags.push(if retired { Flag::Retired } else { Flag::Retire });
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
                "Plan the move (p on Maintenance): Claude reads the release notes first.".into(),
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
                "Plan the move (p), or set a new date (z).".into(),
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
                "Plan the move when it suits (p on Maintenance).".into(),
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
    use crate::config::{ImageRef, Retire};
    use crate::maint::upstream::Upstream;

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
            "debian".into(),
            Ok(vec![
                Eol {
                    cycle: "13".into(),
                    eol: Some(d("2030-06-30")),
                    latest: Some("13.7".into()),
                },
                Eol {
                    cycle: "12".into(),
                    eol: Some(d("2026-12-01")),
                    latest: None,
                },
            ]),
        );
        (vec![web, engine, legacy, os], local, lk)
    }

    fn eol(cycle: &str, eol: &str, latest: &str) -> Eol {
        Eol {
            cycle: cycle.into(),
            eol: Some(d(eol)),
            latest: Some(latest.into()),
        }
    }

    /// The nvidia driver's cycles as endoflife.date lists them (newest first).
    fn nvidia() -> Lookups {
        let mut lk = Lookups::default();
        lk.eol.insert(
            "nvidia".into(),
            Ok(vec![
                eol("r620-linux", "2029-11-04", "620.70.06"),
                eol("r620-windows", "2029-11-04", "621.14"),
                eol("r550-linux", "2025-04-17", "550.144.03"),
                eol("r550-windows", "2025-04-17", "553.74"),
            ]),
        );
        lk
    }

    fn driver(eol: &str, running: &str) -> (MaintItem, Local) {
        (
            MaintItem {
                id: "nvidia-driver".into(),
                apt: vec!["nvidia-driver".into()],
                eol: Some(eol.into()),
                ..Default::default()
            },
            Local {
                pinned: Some(running.into()),
                running: Some(running.into()),
                ..Default::default()
            },
        )
    }

    fn judge(it: &MaintItem, l: &Local, lk: &Lookups, os: HostOs) -> Status {
        one(
            it,
            Some(l),
            Some(lk),
            os,
            &Default::default(),
            false,
            d("2026-11-23"),
        )
    }

    #[test]
    fn the_series_is_the_one_that_runs_not_the_one_typed() {
        let lk = nvidia();
        // The config still names the old series; 620 runs now.
        let (it, l) = driver("nvidia/r550-linux", "620.70.06-1");
        let s = judge(&it, &l, &lk, None);
        assert_eq!(s.eol.as_ref().unwrap().cycle, "r620-linux");
        assert_eq!(s.eol_from, Some(EolFrom::Running));
        assert!(!s.has(Flag::Eol) && !s.has(Flag::EolSoon), "{:?}", s.flags);
        assert_eq!(
            s.note.as_deref(),
            Some("config says r550-linux; 620.70.06-1 runs, series r620-linux")
        );
        // While 550 ran, the same config was right: past its end.
        let (it, l) = driver("nvidia/r550-linux", "550.144.03-1");
        let s = judge(&it, &l, &lk, None);
        assert_eq!(s.eol_from, Some(EolFrom::Running));
        assert!(s.has(Flag::Eol) && s.note.is_none());
        // A product alone is enough.
        let (it, l) = driver("nvidia", "620.70.06-1");
        let s = judge(&it, &l, &lk, None);
        assert_eq!(s.eol.as_ref().unwrap().cycle, "r620-linux");
        assert!(s.note.is_none());
        // An existing note is kept, the series' added after it.
        let (it, mut l) = driver("nvidia/r550-linux", "620.70.06-1");
        l.note = Some("held by hand".into());
        let s = judge(&it, &l, &lk, None);
        assert!(
            s.note
                .as_deref()
                .is_some_and(|n| n.starts_with("held by hand; config says r550-linux")),
            "{:?}",
            s.note
        );
    }

    #[test]
    fn a_series_nothing_tells_is_said_not_guessed() {
        let lk = nvidia();
        let (it, l) = driver("nvidia", "470.256.02-1");
        let s = judge(&it, &l, &lk, None);
        assert!(s.eol.is_none() && s.eol_from.is_none());
        assert!(!s.has(Flag::Eol) && !s.has(Flag::EolSoon));
        assert_eq!(
            s.note.as_deref(),
            Some("couldn't tell which series 470.256.02-1 belongs to (endoflife.date nvidia)")
        );
        // The typed cycle stands when the version names none.
        let (it, l) = driver("nvidia/r550-linux", "470.256.02-1");
        let s = judge(&it, &l, &lk, None);
        assert_eq!(s.eol_from, Some(EolFrom::Typed));
        assert!(s.has(Flag::Eol));
        // A lookup that failed is said.
        let mut failed = Lookups::default();
        failed.eol.insert("nvidia".into(), Err("timed out".into()));
        let s = judge(&it, &l, &failed, None);
        assert!(s.eol.is_none());
        assert_eq!(
            s.note.as_deref(),
            Some("endoflife.date nvidia couldn't be asked: timed out")
        );
        // Not looked up yet: nothing said.
        let s = judge(&it, &l, &Lookups::default(), None);
        assert!(s.eol.is_none() && s.note.is_none());
    }

    #[test]
    fn an_os_item_follows_the_hosts_release() {
        let (items, _, lk) = setup();
        let os = &items[3];
        // `debian/12` in the config; the server was upgraded to 13.
        let s = judge(os, &Local::default(), &lk, Some(("debian", "13")));
        assert_eq!(s.eol_from, Some(EolFrom::Os));
        assert_eq!(s.pinned.as_deref(), Some("13"));
        assert_eq!(s.latest.as_deref(), Some("13.7"));
        assert!(s.has(Flag::Current) && !s.has(Flag::EolSoon));
        assert_eq!(
            s.note.as_deref(),
            Some("config says 12; debian 13 runs, series 13")
        );
        // `eol: debian` alone, on a Debian 12 host.
        let bare = MaintItem {
            eol: Some("debian".into()),
            ..os.clone()
        };
        let s = judge(&bare, &Local::default(), &lk, Some(("debian", "12")));
        assert_eq!(s.pinned.as_deref(), Some("12"));
        assert!(s.has(Flag::EolSoon) && s.note.is_none());
        // Another system's release says nothing about this product.
        let s = judge(&bare, &Local::default(), &lk, Some(("ubuntu", "24.04")));
        assert!(s.eol.is_none() && s.has(Flag::Unknown));
        assert!(s.note.is_some());
        // Without the host's release, the typed cycle as before.
        let s = judge(os, &Local::default(), &lk, None);
        assert_eq!(s.eol_from, Some(EolFrom::Typed));
        assert!(s.has(Flag::EolSoon));
    }

    #[test]
    fn a_status_stored_before_reads_without_eol_from() {
        let old = r#"{"id":"os","risk":"medium","pinned":"12","running":null,"latest":null,
            "newer":[],"flags":["current"],"review_by":null,
            "eol":{"cycle":"12","eol":"2028-06-10","latest":"12.15"},"note":null}"#;
        let s: Status = serde_json::from_str(old).unwrap();
        assert_eq!(s.eol_from, None);
        assert_eq!(s.eol.unwrap().cycle, "12");
    }

    #[test]
    fn standing_of_each_item() {
        let (items, local, lk) = setup();
        let st = evaluate(
            &items,
            &local,
            Some(&lk),
            None,
            &Default::default(),
            &Default::default(),
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
    fn a_retirement_that_ran_is_done() {
        let (items, local, lk) = setup();
        let id = items[2].id.clone();
        // The log has a retirement run for it that ended well (and one for another that failed).
        let entry = |item: &str, result: &str| {
            let mut e = sentry_core::maint::log::LogEntry::event(
                "s",
                "retire",
                "retire-service",
                result == "done",
                "",
                &[],
                jiff::Timestamp::now(),
            );
            e.head.item = Some(item.to_string());
            e
        };
        let retired = retired_in(&[entry(&id, "done"), entry("web", "failed")]);
        assert_eq!(retired.iter().collect::<Vec<_>>(), [&id]);
        let st = evaluate(
            &items,
            &local,
            Some(&lk),
            None,
            &Default::default(),
            &retired,
            d("2026-10-27"),
        );
        assert!(st[2].has(Flag::Retired) && !st[2].has(Flag::Retire));
        // No "retire" finding, no "Retire …" recommendation: it's done.
        assert!(
            !findings(&st, &items)
                .iter()
                .any(|f| f.id.contains("retire"))
        );
    }

    #[test]
    fn a_held_item_only_nags_once_its_review_is_due() {
        let (items, local, lk) = setup();
        let ids = |today: &str, later: &sentry_core::maint::later::Snoozes| -> Vec<String> {
            let st = evaluate(
                &items,
                &local,
                Some(&lk),
                None,
                later,
                &Default::default(),
                d(today),
            );
            findings(&st, &items).into_iter().map(|f| f.id).collect()
        };
        let now = ids("2026-10-27", &Default::default());
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
        let later = ids("2027-02-01", &Default::default());
        assert!(later.contains(&"srv:maint:review:web".to_string()));
        assert!(later.contains(&"srv:maint:behind:web".to_string()));
        // A snooze moves the review date.
        let mut snoozed = sentry_core::maint::later::Snoozes::new();
        snoozed.insert("web".into(), d("2027-06-01"));
        let s = ids("2027-02-01", &snoozed);
        assert!(!s.contains(&"srv:maint:review:web".to_string()));
    }
}
