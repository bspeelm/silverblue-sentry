//! Structural diff between two reports, section by section (spec §7). Set-like sections show
//! `+`/`-` entries; kargs compare as a set. Unchanged sections collapse to one line.

use std::collections::{BTreeMap, BTreeSet};

use super::Report;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Section,
    Add,
    Remove,
    Change,
    Same,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    pub kind: Kind,
    pub text: String,
}

#[derive(Default)]
struct Out(Vec<Line>);

impl Out {
    fn push(&mut self, kind: Kind, text: impl Into<String>) {
        self.0.push(Line {
            kind,
            text: text.into(),
        });
    }

    /// One `+`/`-` line per entry; a single summary line when nothing changed.
    fn sets(&mut self, title: &str, a: &BTreeSet<String>, b: &BTreeSet<String>) {
        if a.is_empty() && b.is_empty() {
            return;
        }
        self.push(Kind::Section, title);
        let added: Vec<_> = b.difference(a).collect();
        let removed: Vec<_> = a.difference(b).collect();
        if added.is_empty() && removed.is_empty() {
            self.same(b.iter().map(String::as_str).collect());
        }
        for x in added {
            self.push(Kind::Add, format!("+ {x}"));
        }
        for x in removed {
            self.push(Kind::Remove, format!("- {x}"));
        }
        self.push(Kind::Same, "");
    }

    /// A section one side didn't collect: say so instead of reporting everything as changed.
    fn missing(&mut self, title: &str, a: bool, b: bool) -> bool {
        if a && b {
            return false;
        }
        self.push(Kind::Section, title);
        self.push(
            Kind::Same,
            if a {
                "  not collected this time (see the report's errors)"
            } else {
                "  not collected in the previous report: nothing to compare"
            },
        );
        self.push(Kind::Same, "");
        true
    }

    fn same(&mut self, items: Vec<&str>) {
        let joined = items.join("  ");
        let text = if items.is_empty() {
            "  (none)".to_string()
        } else if joined.chars().count() <= 56 {
            format!("  {joined}  (unchanged)")
        } else {
            format!("  {} entries (unchanged)", items.len())
        };
        self.push(Kind::Same, text);
    }
}

fn set<T, F: Fn(&T) -> String>(v: Option<&Vec<T>>, f: F) -> BTreeSet<String> {
    v.map(|v| v.iter().map(f).collect()).unwrap_or_default()
}

pub fn diff(a: &Report, b: &Report) -> Vec<Line> {
    let (sa, sb) = (&a.sections, &b.sections);
    let mut o = Out::default();

    // Only listeners other machines can reach: loopback ports of dev tools churn every run.
    let reachable = |l: &super::ListenSec| {
        let (_, port, _) = super::known::split_key(&l.key);
        let name = super::known::service(&l.proto, port).map_or("", |s| s.name);
        format!("{:<4} {:<44} {name}", l.proto, l.key)
            .trim_end()
            .to_string()
    };
    let lset = |r: &Report| -> BTreeSet<String> {
        r.sections
            .listeners
            .iter()
            .flatten()
            .filter(|l| !l.local)
            .map(reachable)
            .collect()
    };
    if !o.missing(
        "listeners (reachable)",
        sa.listeners.is_some(),
        sb.listeners.is_some(),
    ) {
        o.sets("listeners (reachable)", &lset(a), &lset(b));
    }

    let fp = !o.missing("flatpak", sa.flatpak.is_some(), sb.flatpak.is_some());
    // flatpak apps: added / removed / permission flags changed
    if fp {
        o.push(Kind::Section, "flatpak");
        let apps = |r: &Report| -> BTreeMap<String, (String, Vec<String>)> {
            r.sections
                .flatpak
                .as_ref()
                .map(|f| {
                    f.apps
                        .iter()
                        .map(|a| (a.id.clone(), (a.origin.clone(), a.flags.clone())))
                        .collect()
                })
                .unwrap_or_default()
        };
        let (pa, pb) = (apps(a), apps(b));
        let mut changed = false;
        for (id, (origin, flags)) in &pb {
            match pa.get(id) {
                None => o.push(Kind::Add, format!("+ {id:<40} {origin}")),
                Some((_, old)) if old != flags => o.push(
                    Kind::Change,
                    format!("~ {id:<40} {} → {}", show(old), show(flags)),
                ),
                Some(_) => continue,
            }
            changed = true;
        }
        for (id, (origin, _)) in &pa {
            if !pb.contains_key(id) {
                o.push(Kind::Remove, format!("- {id:<40} {origin}"));
                changed = true;
            }
        }
        if !changed {
            o.push(Kind::Same, format!("  {} apps (unchanged)", pb.len()));
        }
        o.push(Kind::Same, "");
    }

    let remotes = |r: &Report| {
        set(r.sections.flatpak.as_ref().map(|f| &f.remotes), |(n, u)| {
            format!("{n} {u}")
        })
    };
    if fp {
        o.sets("flatpak remotes", &remotes(a), &remotes(b));
    }

    let os = |r: &Report, f: fn(&super::OstreeSec) -> &Vec<String>| -> BTreeSet<String> {
        r.sections
            .ostree
            .as_ref()
            .map(|o| f(o).iter().cloned().collect())
            .unwrap_or_default()
    };
    let ost = !o.missing(
        "packages (rpm-ostree)",
        sa.ostree.is_some(),
        sb.ostree.is_some(),
    );
    if ost {
        o.sets(
            "layered packages",
            &os(a, |o| &o.layered),
            &os(b, |o| &o.layered),
        );
        o.sets("local packages", &os(a, |o| &o.local), &os(b, |o| &o.local));
        o.sets(
            "base removals",
            &os(a, |o| &o.removals),
            &os(b, |o| &o.removals),
        );
    }

    let repos = |r: &Report| {
        set(r.sections.repos.as_ref(), |x| {
            format!(
                "{}{} [{}]",
                x.file,
                if x.enabled { "" } else { " (disabled)" },
                x.section
            )
        })
    };
    let only_third = |s: BTreeSet<String>| -> BTreeSet<String> {
        s.into_iter().filter(|x| !x.starts_with("fedora")).collect()
    };
    if !o.missing(
        "repos (third-party)",
        sa.repos.is_some(),
        sb.repos.is_some(),
    ) {
        o.sets(
            "repos (third-party)",
            &only_third(repos(a)),
            &only_third(repos(b)),
        );
    }

    let units = |r: &Report, user: bool| -> BTreeSet<String> {
        r.sections
            .units
            .as_ref()
            .map(|u| {
                if user {
                    &u.user_enabled
                } else {
                    &u.system_enabled
                }
                .iter()
                .cloned()
                .collect()
            })
            .unwrap_or_default()
    };
    let un = !o.missing("units", sa.units.is_some(), sb.units.is_some());
    if un {
        o.sets("units (user, enabled)", &units(a, true), &units(b, true));
        o.sets(
            "units (system, enabled)",
            &units(a, false),
            &units(b, false),
        );
    }
    let failed = |r: &Report| {
        r.sections
            .units
            .as_ref()
            .map(|u| u.failed.iter().cloned().collect())
            .unwrap_or_default()
    };
    if un {
        o.sets("failed units", &failed(a), &failed(b));
    }
    let autostart = |r: &Report| {
        r.sections
            .units
            .as_ref()
            .map(|u| u.autostart.iter().cloned().collect())
            .unwrap_or_default()
    };
    if un {
        o.sets("autostart", &autostart(a), &autostart(b));
    }

    if !o.missing(
        "containers",
        sa.containers.is_some(),
        sb.containers.is_some(),
    ) {
        o.sets(
            "containers",
            &set(sa.containers.as_ref(), |c| {
                format!("{} ({})", c.name, c.kind)
            }),
            &set(sb.containers.as_ref(), |c| {
                format!("{} ({})", c.name, c.kind)
            }),
        );
    }
    o.sets(
        "shell rc",
        &set(Some(&sa.shell), |h| {
            format!("~/{}: {}", h.file, h.text.trim())
        }),
        &set(Some(&sb.shell), |h| {
            format!("~/{}: {}", h.file, h.text.trim())
        }),
    );

    // kargs: order-insensitive; the ostree/root args change every deployment.
    let kargs = |r: &Report| -> BTreeSet<String> {
        r.sections
            .ostree
            .as_ref()
            .and_then(|o| o.kargs.as_deref())
            .unwrap_or("")
            .split_whitespace()
            .filter(|w| !w.starts_with("ostree=") && !w.starts_with("BOOT_IMAGE="))
            .map(str::to_string)
            .collect()
    };
    if ost {
        o.sets("kargs", &kargs(a), &kargs(b));
    }
    o.0
}

fn show(flags: &[String]) -> String {
    if flags.is_empty() {
        "—".into()
    } else {
        flags.join(" ")
    }
}

/// `diff: 2 listeners · 1 flatpak · 0 repos` style summary of the sections that changed.
pub fn summary(lines: &[Line]) -> String {
    let mut parts = Vec::new();
    let mut cur = "";
    let mut n = 0;
    for l in lines {
        match l.kind {
            Kind::Section => {
                if n > 0 {
                    parts.push(format!("{n} {cur}"));
                }
                cur = &l.text;
                n = 0;
            }
            Kind::Add | Kind::Remove | Kind::Change => n += 1,
            Kind::Same => {}
        }
    }
    if n > 0 {
        parts.push(format!("{n} {cur}"));
    }
    if parts.is_empty() {
        "no changes".into()
    } else {
        parts.join(" · ")
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    fn r(listeners: &[&str], kargs: &str, apps: &[(&str, &[&str])]) -> Report {
        let mut rep = crate::audit::test_report(Sections::default());
        rep.sections.listeners = Some(
            listeners
                .iter()
                .map(|k| ListenSec {
                    proto: "tcp".into(),
                    key: k.to_string(),
                    local: false,
                })
                .collect(),
        );
        rep.sections.ostree = Some(OstreeSec {
            kargs: Some(kargs.into()),
            layered: vec!["ghostty".into()],
            ..Default::default()
        });
        rep.sections.flatpak = Some(FlatpakSec {
            apps: apps
                .iter()
                .map(|(id, flags)| FpApp {
                    id: id.to_string(),
                    origin: "flathub".into(),
                    flags: flags.iter().map(|s| s.to_string()).collect(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        });
        rep
    }

    #[test]
    fn sections_and_word_diff() {
        let a = r(
            &["0.0.0.0:22/?"],
            "rhgb quiet nvidia-drm.modeset=1",
            &[("a.App", &["home"]), ("gone.App", &[])],
        );
        let b = r(
            &["0.0.0.0:22/?", "0.0.0.0:22000/syncthing"],
            "rhgb nvidia-drm.modeset=1 rd.driver.blacklist=nouveau",
            &[("a.App", &["host"]), ("new.App", &[])],
        );
        let d = diff(&a, &b);
        let txt: Vec<&str> = d.iter().map(|l| l.text.as_str()).collect();
        assert!(
            txt.iter().any(
                |t| t.starts_with("+ tcp  0.0.0.0:22000/syncthing") && t.ends_with("Syncthing")
            ),
            "{txt:#?}"
        );
        assert!(
            txt.iter()
                .any(|t| t.starts_with("~ a.App") && t.ends_with("home → host"))
        );
        assert!(txt.iter().any(|t| t.starts_with("+ new.App")));
        assert!(txt.iter().any(|t| t.starts_with("- gone.App")));
        assert!(txt.contains(&"  ghostty  (unchanged)"));
        assert!(txt.contains(&"- quiet"));
        assert!(txt.contains(&"+ rd.driver.blacklist=nouveau"));
        assert_eq!(summary(&d), "1 listeners (reachable) · 3 flatpak · 2 kargs");
        assert_eq!(summary(&diff(&a, &a)), "no changes");
    }

    #[test]
    fn missing_sections_and_loopback_churn() {
        let mut a = r(&["0.0.0.0:22/?"], "rhgb", &[]);
        a.sections.ostree = None; // the previous audit timed out on rpm-ostree
        a.sections.listeners.as_mut().unwrap().push(ListenSec {
            proto: "tcp".into(),
            key: "127.0.0.1:41333/node".into(),
            local: true,
        });
        let mut b = r(&["0.0.0.0:22/?"], "rhgb", &[]);
        b.sections.listeners.as_mut().unwrap().push(ListenSec {
            proto: "tcp".into(),
            key: "127.0.0.1:45159/node".into(),
            local: true,
        });
        let d = diff(&a, &b);
        let txt: Vec<&str> = d.iter().map(|l| l.text.as_str()).collect();
        assert!(
            !txt.iter().any(|t| t.contains("ghostty")),
            "no false package additions: {txt:#?}"
        );
        assert!(txt.contains(&"  not collected in the previous report: nothing to compare"));
        assert!(
            !txt.iter().any(|t| t.contains("node")),
            "loopback churn hidden: {txt:#?}"
        );
        assert_eq!(summary(&d), "no changes");
    }
}
