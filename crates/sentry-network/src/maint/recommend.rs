//! The rules of a network's upkeep: what the firmware, the packages and the backups ask
//! for (rows on Maintenance, ranked with the audit's findings), and how each stands (the
//! Items panel). Pure: everything comes in as [`State`].

use jiff::Timestamp;

use super::eval::{EolState, Firmware};
use crate::backup::{self, Status};
use crate::collect::updates::Updates;
use crate::config::{ItemKind, Network};
use sentry_core::fmt;
use sentry_core::maint::Level;

/// The workflow that makes a backup.
pub const BACKUP_WF: &str = "config-backup";

pub const KEY_EOL: &str = "net:maint:eol";
pub const KEY_FIRMWARE: &str = "net:maint:firmware";
pub const KEY_PACKAGES: &str = "net:maint:packages";
pub const KEY_BACKUP: &str = "net:maint:backup";

/// How the firmware and the packages are changed: by their workflows (Enter on the row).
pub const FIRMWARE_VIA: &str = "the firmware-upgrade workflow (owut) does it, after a \
     config backup, within the release series the router is on";
pub const PACKAGES_VIA: &str =
    "the package-update workflow upgrades the packages you name, after a config backup";

/// What is known when the rules are asked.
pub struct State<'a> {
    /// None: the board wasn't read yet.
    pub firmware: Option<&'a Firmware>,
    pub updates: Option<&'a Updates>,
    pub backup: Option<&'a Status>,
    /// A backup older than this is due (seconds).
    pub backup_age: i64,
    pub now: Timestamp,
    /// The audit's own finding about an unsaved config is in the list: no second row.
    pub unsaved_listed: bool,
}

/// What Enter does on a rule's row.
#[derive(Debug, Clone, PartialEq)]
pub enum Do {
    /// Start this workflow.
    Run(String),
    /// Nothing sentry does yet: say so.
    Say(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub key: &'static str,
    pub level: Level,
    pub title: String,
    pub why: String,
    pub action: Do,
    /// Nothing asks for it: behind `o`.
    pub can_wait: bool,
    pub item: ItemKind,
}

fn secs_since(now: Timestamp, t: Timestamp) -> i64 {
    (now.as_second() - t.as_second()).max(0)
}

pub fn rules(s: &State) -> Vec<Rule> {
    let mut out = Vec::new();
    if let Some(f) = s.firmware {
        let series = f.series.as_deref().unwrap_or("?");
        match f.eol_state {
            EolState::Past(days) => out.push(Rule {
                key: KEY_EOL,
                level: Level::Soon,
                title: format!("OpenWrt {series} is past its end of life"),
                why: format!(
                    "The series ended {days} days ago{}: it gets no more security fixes. \
                     Moving to a newer series is a firmware upgrade.",
                    f.eol.map_or(String::new(), |d| format!(" ({d})"))
                ),
                action: Do::Say(FIRMWARE_VIA),
                can_wait: false,
                item: ItemKind::Firmware,
            }),
            EolState::Soon(days) => out.push(Rule {
                key: KEY_EOL,
                level: Level::Tidy,
                title: format!("OpenWrt {series} reaches its end of life in {days} days"),
                why: format!(
                    "After {} it gets no more security fixes: plan the move to a newer series.",
                    f.eol.map_or("then".to_string(), |d| d.to_string())
                ),
                action: Do::Say(FIRMWARE_VIA),
                can_wait: false,
                item: ItemKind::Firmware,
            }),
            EolState::Supported | EolState::Unknown => {}
        }
        if let (true, Some(latest)) = (f.newer, &f.latest) {
            let security = f.security == Some(true);
            out.push(Rule {
                key: KEY_FIRMWARE,
                level: if security { Level::Soon } else { Level::Routine },
                title: format!("Firmware {} → {latest}", f.installed),
                why: match f.security {
                    Some(true) => {
                        "A newer release of the same series is out, and its notes list security fixes."
                            .to_string()
                    }
                    Some(false) => {
                        "A newer release of the same series is out; its notes list no security fix."
                            .to_string()
                    }
                    None => {
                        "A newer release of the same series is out (its notes couldn't be read, so whether it fixes anything urgent isn't known)."
                            .to_string()
                    }
                },
                action: Do::Say(FIRMWARE_VIA),
                can_wait: !security,
                item: ItemKind::Firmware,
            });
        }
    }
    if let Some(u) = s.updates.filter(|u| !u.packages.is_empty()) {
        let names: Vec<&str> = u.packages.iter().take(6).map(|p| p.name.as_str()).collect();
        out.push(Rule {
            key: KEY_PACKAGES,
            level: Level::Routine,
            title: format!("{} package(s) could be upgraded", u.packages.len()),
            why: format!(
                "{}{} ({}).",
                names.join(", "),
                match u.packages.len().saturating_sub(names.len()) {
                    0 => String::new(),
                    n => format!(" and {n} more"),
                },
                u.index_said()
            ),
            action: Do::Say(PACKAGES_VIA),
            can_wait: true,
            item: ItemKind::Packages,
        });
    }
    if let Some(b) = s.backup {
        let run = || Do::Run(BACKUP_WF.to_string());
        let old = b
            .newest
            .as_ref()
            .map(|k| secs_since(s.now, k.at))
            .filter(|age| *age > s.backup_age);
        let changed = b.changed.as_ref().filter(|c| c.any());
        let rule = |level, title: String, why: String| Rule {
            key: KEY_BACKUP,
            level,
            title,
            why,
            action: run(),
            can_wait: false,
            item: ItemKind::Backup,
        };
        if let Some(age) = old {
            out.push(rule(
                Level::Routine,
                format!("The newest config backup is {} old", fmt::age(age)),
                match changed {
                    Some(c) => format!(
                        "Older than thresholds.backup_age, and {} file(s) changed since.",
                        c.files.len()
                    ),
                    None => "Older than thresholds.backup_age.".to_string(),
                },
            ));
        } else if !s.unsaved_listed {
            // Until an audit says it as a finding.
            if b.newest.is_none() {
                out.push(rule(
                    if b.recipients {
                        Level::Soon
                    } else {
                        Level::Tidy
                    },
                    "There is no backup of the router's config".into(),
                    if b.recipients {
                        "A reset or a failed upgrade loses the config: Enter makes one.".into()
                    } else {
                        backup::NO_RECIPIENTS.to_string()
                    },
                ));
            } else if let Some(c) = changed {
                out.push(rule(
                    Level::Soon,
                    "The config changed since the last backup".into(),
                    backup::capped(
                        if c.options.is_empty() {
                            &c.files
                        } else {
                            &c.options
                        },
                        6,
                    )
                    .join(" · "),
                ));
            }
        }
    }
    out
}

/// How an item's row reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Ok,
    /// Something could be done; nothing asks for it.
    Note,
    Warn,
    /// Not known yet.
    Dim,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ItemRow {
    pub id: String,
    pub kind: ItemKind,
    pub state: String,
    pub detail: String,
    pub tone: Tone,
}

/// The kinds on the panel, with their ids: the config's `maintenance.items`, or all three.
pub fn kinds(cfg: &Network) -> Vec<(String, ItemKind)> {
    if cfg.maintenance.items.is_empty() {
        return vec![
            ("firmware".into(), ItemKind::Firmware),
            ("packages".into(), ItemKind::Packages),
            ("backup".into(), ItemKind::Backup),
        ];
    }
    cfg.maintenance
        .items
        .iter()
        .map(|i| (i.id.clone(), i.kind))
        .collect()
}

pub fn items(cfg: &Network, s: &State) -> Vec<ItemRow> {
    kinds(cfg)
        .into_iter()
        .map(|(id, kind)| {
            let (state, detail, tone) = match kind {
                ItemKind::Firmware => firmware_row(s.firmware),
                ItemKind::Packages => packages_row(s.updates),
                ItemKind::Backup => backup_row(s),
            };
            ItemRow {
                id,
                kind,
                state,
                detail,
                tone,
            }
        })
        .collect()
}

fn firmware_row(f: Option<&Firmware>) -> (String, String, Tone) {
    let Some(f) = f else {
        return ("…".into(), String::new(), Tone::Dim);
    };
    let eol = match (f.eol_state, f.eol) {
        (EolState::Past(_), Some(d)) => format!("past end of life ({d})"),
        (EolState::Past(_), None) => "past end of life".into(),
        (EolState::Soon(n), Some(d)) => format!("end of life {d} ({n} days)"),
        (EolState::Supported, Some(d)) => format!("end of life {d}"),
        (EolState::Supported, None) => "no end of life announced".into(),
        _ => f.note.clone().unwrap_or_default(),
    };
    let state = match (&f.latest, f.newer) {
        (Some(l), true) => format!("{} → {l}", f.installed),
        (Some(_), false) => format!("{} · latest", f.installed),
        (None, _) => f.installed.clone(),
    };
    let tone = match (f.eol_state, f.newer, f.security) {
        (EolState::Past(_), ..) | (_, true, Some(true)) => Tone::Warn,
        (EolState::Soon(_), ..) | (_, true, _) => Tone::Note,
        (EolState::Unknown, ..) => Tone::Dim,
        _ => Tone::Ok,
    };
    (state, eol, tone)
}

fn packages_row(u: Option<&Updates>) -> (String, String, Tone) {
    let Some(u) = u else {
        return ("…".into(), String::new(), Tone::Dim);
    };
    // What went wrong comes first: the row is cut where the panel ends.
    let failed = u.refresh_failed.map_or(String::new(), |c| {
        format!("refresh failed (apk exit {c}) · ")
    });
    match (u.index_at, u.packages.len()) {
        // Nothing can be upgradable against an index that isn't there.
        (None, _) => (
            "not known".into(),
            format!("{failed}no index since boot · r fetches it"),
            Tone::Dim,
        ),
        (Some(_), 0) => (
            "up to date".into(),
            format!("{failed}{}", u.index_said()),
            Tone::Ok,
        ),
        (Some(_), n) => (
            format!("{n} upgradable"),
            format!("{failed}{} · r fetches it again", u.index_said()),
            Tone::Note,
        ),
    }
}

fn backup_row(s: &State) -> (String, String, Tone) {
    let Some(b) = s.backup else {
        return ("…".into(), String::new(), Tone::Dim);
    };
    let Some(k) = &b.newest else {
        return if b.recipients {
            ("none yet".into(), "Enter makes one".into(), Tone::Warn)
        } else {
            (
                "none yet".into(),
                "no recipient: set backup.recipients".into(),
                Tone::Dim,
            )
        };
    };
    let age = secs_since(s.now, k.at);
    let state = format!("newest {}", fmt::ago(age));
    let old = age > s.backup_age;
    match &b.changed {
        None => (state, "no manifest to compare with".into(), Tone::Note),
        Some(c) if c.any() => (
            state,
            format!("{} file(s) changed since", c.files.len()),
            Tone::Warn,
        ),
        Some(_) if old => (
            state,
            "nothing changed since · due again".into(),
            Tone::Note,
        ),
        Some(_) => (state, "nothing changed since".into(), Tone::Ok),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::{Changed, Kept};
    use crate::collect::updates::Package;
    use jiff::civil::date;

    const NOW: &str = "2026-10-26T12:00:00Z";

    fn fw(newer: Option<&str>, security: Option<bool>, eol: EolState) -> Firmware {
        Firmware {
            installed: "25.12.3".into(),
            series: Some("25.12".into()),
            latest: Some(newer.unwrap_or("25.12.3").to_string()),
            newer: newer.is_some(),
            security,
            eol: matches!(eol, EolState::Past(_) | EolState::Soon(_)).then(|| date(2026, 9, 30)),
            eol_state: eol,
            note: None,
        }
    }

    fn updates(n: usize, index: Option<i64>) -> Updates {
        Updates {
            packages: (0..n)
                .map(|i| Package {
                    name: format!("pkg{i}"),
                    ..Default::default()
                })
                .collect(),
            index_at: index.map(|age| 1_000_000 - age),
            now: 1_000_000,
            refresh_failed: None,
        }
    }

    fn kept(days_ago: i64) -> Kept {
        let now: Timestamp = NOW.parse().unwrap();
        let at = Timestamp::from_second(now.as_second() - days_ago * 86_400).unwrap();
        Kept {
            stamp: backup::stamp(at),
            at,
            release: "25.12.3".into(),
            size: 30_000,
            path: "x".into(),
        }
    }

    fn status(newest: Option<i64>, changed: Option<&[&str]>, recipients: bool) -> Status {
        Status {
            recipients,
            count: usize::from(newest.is_some()),
            newest: newest.map(kept),
            changed: changed.map(|f| Changed {
                files: f.iter().map(|s| s.to_string()).collect(),
                options: f.iter().map(|s| format!("{s} changed")).collect(),
            }),
        }
    }

    fn state<'a>(
        f: Option<&'a Firmware>,
        u: Option<&'a Updates>,
        b: Option<&'a Status>,
    ) -> State<'a> {
        State {
            firmware: f,
            updates: u,
            backup: b,
            backup_age: 30 * 86_400,
            now: NOW.parse().unwrap(),
            unsaved_listed: false,
        }
    }

    #[test]
    fn firmware_rules() {
        // (firmware) → [(key, level, can_wait)]
        type Row = (&'static str, Level, bool);
        let table: Vec<(Firmware, Vec<Row>)> = vec![
            (fw(None, None, EolState::Supported), vec![]),
            (
                fw(Some("25.12.5"), Some(true), EolState::Supported),
                vec![(KEY_FIRMWARE, Level::Soon, false)],
            ),
            (
                fw(Some("25.12.5"), Some(false), EolState::Supported),
                vec![(KEY_FIRMWARE, Level::Routine, true)],
            ),
            // Whether it's a security release can't be known: it waits.
            (
                fw(Some("25.12.5"), None, EolState::Supported),
                vec![(KEY_FIRMWARE, Level::Routine, true)],
            ),
            (
                fw(None, None, EolState::Past(26)),
                vec![(KEY_EOL, Level::Soon, false)],
            ),
            (
                fw(None, None, EolState::Soon(36)),
                vec![(KEY_EOL, Level::Tidy, false)],
            ),
            (
                fw(Some("25.12.5"), Some(true), EolState::Past(26)),
                vec![
                    (KEY_EOL, Level::Soon, false),
                    (KEY_FIRMWARE, Level::Soon, false),
                ],
            ),
            (fw(None, None, EolState::Unknown), vec![]),
        ];
        for (f, want) in table {
            let got: Vec<(&str, Level, bool)> = rules(&state(Some(&f), None, None))
                .iter()
                .map(|r| (r.key, r.level, r.can_wait))
                .collect();
            assert_eq!(got, want, "{f:?}");
        }
        let r = rules(&state(
            Some(&fw(Some("25.12.5"), Some(true), EolState::Supported)),
            None,
            None,
        ));
        assert_eq!(r[0].title, "Firmware 25.12.3 → 25.12.5");
        assert_eq!(r[0].action, Do::Say(FIRMWARE_VIA));
    }

    #[test]
    fn packages_wait_and_say_how_old_the_index_is() {
        let u = updates(8, Some(9 * 86_400));
        let r = rules(&state(None, Some(&u), None));
        assert_eq!(r.len(), 1);
        assert_eq!(
            (r[0].key, r[0].level, r[0].can_wait),
            (KEY_PACKAGES, Level::Routine, true)
        );
        assert_eq!(r[0].title, "8 package(s) could be upgraded");
        assert!(r[0].why.contains("pkg0, pkg1") && r[0].why.contains("and 2 more"));
        assert!(r[0].why.contains("index 9d ago"), "{}", r[0].why);
        assert!(rules(&state(None, Some(&updates(0, Some(60))), None)).is_empty());
    }

    #[test]
    fn backup_rules() {
        let run = Do::Run(BACKUP_WF.into());
        // Fresh and unchanged: nothing.
        let ok = status(Some(3), Some(&[]), true);
        assert!(rules(&state(None, None, Some(&ok))).is_empty());
        // Older than the threshold.
        let old = status(Some(45), Some(&[]), true);
        let r = rules(&state(None, None, Some(&old)));
        assert_eq!((r[0].key, r[0].level), (KEY_BACKUP, Level::Routine));
        assert_eq!(r[0].title, "The newest config backup is 45d old");
        assert_eq!(r[0].action, run);
        // Changed since: named.
        let changed = status(Some(3), Some(&["wireless.default_radio0.key"]), true);
        let r = rules(&state(None, None, Some(&changed)));
        assert_eq!(r[0].title, "The config changed since the last backup");
        assert_eq!(r[0].why, "wireless.default_radio0.key changed");
        assert_eq!(r[0].level, Level::Soon);
        // None at all: its own words; without a recipient it says what to set, and waits.
        let none = status(None, None, true);
        let r = rules(&state(None, None, Some(&none)));
        assert_eq!(r[0].title, "There is no backup of the router's config");
        assert_eq!(r[0].level, Level::Soon);
        let unset = status(None, None, false);
        let r = rules(&state(None, None, Some(&unset)));
        assert_eq!(r[0].level, Level::Tidy);
        assert!(r[0].why.contains("backup.recipients"), "{}", r[0].why);
        // The audit's finding says it already: one row, not two (an old one still shows).
        for b in [&changed, &none] {
            let mut s = state(None, None, Some(b));
            s.unsaved_listed = true;
            assert!(rules(&s).is_empty());
        }
        let mut s = state(None, None, Some(&old));
        s.unsaved_listed = true;
        assert_eq!(rules(&s).len(), 1);
    }

    #[test]
    fn the_items_rows() {
        let cfg = Network::default();
        let f = fw(Some("25.12.5"), Some(true), EolState::Supported);
        let u = updates(7, Some(9 * 86_400));
        let b = status(Some(6), Some(&[]), true);
        let rows = items(&cfg, &state(Some(&f), Some(&u), Some(&b)));
        let said: Vec<(&str, &str, &str, Tone)> = rows
            .iter()
            .map(|r| (r.id.as_str(), r.state.as_str(), r.detail.as_str(), r.tone))
            .collect();
        assert_eq!(
            said,
            [
                (
                    "firmware",
                    "25.12.3 → 25.12.5",
                    "no end of life announced",
                    Tone::Warn
                ),
                (
                    "packages",
                    "7 upgradable",
                    "index 9d ago · r fetches it again",
                    Tone::Note
                ),
                ("backup", "newest 6d ago", "nothing changed since", Tone::Ok),
            ]
        );
        // Nothing read yet.
        let rows = items(&cfg, &state(None, None, None));
        assert!(rows.iter().all(|r| r.state == "…" && r.tone == Tone::Dim));
        // The index's other states, and the backup's.
        let row = |u: &Updates| packages_row(Some(u));
        assert_eq!(
            row(&updates(0, None)).1,
            "no index since boot · r fetches it"
        );
        assert_eq!(row(&updates(0, Some(120))).0, "up to date");
        let mut failed = updates(0, Some(120));
        failed.refresh_failed = Some(1);
        assert_eq!(row(&failed).1, "refresh failed (apk exit 1) · index 2m ago");
        let b = |st: &Status| {
            let s = state(None, None, Some(st));
            let (a, d, t) = backup_row(&s);
            (a, d, t)
        };
        assert_eq!(
            b(&status(None, None, false)),
            (
                "none yet".into(),
                "no recipient: set backup.recipients".into(),
                Tone::Dim
            )
        );
        assert_eq!(b(&status(None, None, true)).2, Tone::Warn);
        assert_eq!(
            b(&status(Some(2), Some(&["a", "b"]), true)).1,
            "2 file(s) changed since"
        );
        assert_eq!(
            b(&status(Some(40), Some(&[]), true)).1,
            "nothing changed since · due again"
        );
        // The config can name fewer items, under its own ids.
        let mut cfg = Network::default();
        cfg.maintenance.items = vec![crate::config::Item {
            id: "cfg".into(),
            kind: ItemKind::Backup,
        }];
        let rows = items(&cfg, &state(None, None, None));
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].id.as_str(), rows[0].kind),
            ("cfg", ItemKind::Backup)
        );
    }
}
