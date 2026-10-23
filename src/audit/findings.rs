//! Findings from a report (spec §7 severities, plus the host-specific rules in
//! `docs/design/m3-m7.md`). Pure: no I/O, so every rule is unit-tested.

use std::collections::{BTreeMap, BTreeSet};

use super::{Finding, Report, Sev};
use crate::baseline::Baseline;
use crate::collectors::flatpak::gl_version_for_driver;
use crate::config::Config;
use crate::fmt;

/// Whether the (current) baseline suppresses `f`. Listener findings are baselined through
/// `listeners` (so the Network screen agrees); everything else through `findings`.
pub fn is_expected(f: &Finding, b: &Baseline) -> bool {
    match f.id.strip_prefix("listener:") {
        Some(key) => b.has_listener(key),
        None => b.findings.iter().any(|x| crate::baseline::glob(x, &f.id)),
    }
}

/// Short stable hash for ids built from free text (rc lines).
fn hash(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:08x}", h as u32)
}

pub fn derive(r: &Report, prev: Option<&Report>, b: &Baseline, cfg: &Config) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut add = |id: String, severity: Sev, category: &str, message: String, evidence: String| {
        out.push(Finding {
            id,
            severity,
            category: category.into(),
            message,
            evidence,
            expected: false,
        });
    };
    let s = &r.sections;
    let ps = prev.map(|p| &p.sections);

    // listeners: reachable and not in the baseline (tcp+udp on one key → one finding)
    let mut by_key: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for l in s.listeners.iter().flatten().filter(|l| !l.local) {
        by_key.entry(&l.key).or_default().push(&l.proto);
    }
    for (key, protos) in by_key {
        add(
            format!("listener:{key}"),
            Sev::High,
            "listener",
            format!("New listener {} ({})", addr_of(key), proc_of(key)),
            format!(
                "ss -tulpnH\n{} {key}\nnot in [baseline].listeners or baseline.toml",
                protos.join("+")
            ),
        );
    }

    // flatpak: host/home filesystems and sandbox-escape talk names
    if let Some(fp) = &s.flatpak {
        let prev_apps: BTreeMap<&str, &super::FpApp> = ps
            .and_then(|p| p.flatpak.as_ref())
            .map(|f| f.apps.iter().map(|a| (a.id.as_str(), a)).collect())
            .unwrap_or_default();
        for a in &fp.apps {
            let before = prev_apps.get(a.id.as_str());
            for flag in a.flags.iter().filter(|f| *f != "devices=all") {
                let had = before.is_some_and(|p| p.flags.contains(flag));
                let what = if flag.starts_with("talk:") {
                    flag.replacen("talk:", "talk-name=", 1)
                } else {
                    format!("filesystem={flag}")
                };
                // Only a change since the previous report is "gained" (high).
                let (sev, verb) = if prev.is_some() && !had {
                    (Sev::High, "gained")
                } else {
                    (Sev::Medium, "has")
                };
                let prev_fs = before.map_or("(not installed)".to_string(), |p| {
                    format!("filesystems={};", p.filesystems.join(";"))
                });
                add(
                    format!("flatpak-perm:{}:{flag}", a.id),
                    sev,
                    "flatpak",
                    format!("{} {verb} {what}", a.id),
                    format!(
                        "metadata + overrides for {} ({})\n[Context] filesystems={};\nprev: {}",
                        a.id,
                        a.installation,
                        a.filesystems.join(";"),
                        if prev.is_some() {
                            prev_fs
                        } else {
                            "no previous report".into()
                        }
                    ),
                );
            }
            if a.unverified {
                let url = fp
                    .remotes
                    .iter()
                    .find(|(n, _)| *n == a.origin)
                    .map_or("?", |(_, u)| u.as_str());
                let new = before.is_none();
                add(
                    format!("flatpak-origin:{}", a.id),
                    Sev::Medium,
                    "flatpak",
                    format!(
                        "{}app from unverified origin {}: {}",
                        if new && prev.is_some() { "New " } else { "" },
                        a.origin,
                        a.id
                    ),
                    format!(
                        "remote {} → {url}\nnot in [flatpak].trusted_origins",
                        a.origin
                    ),
                );
            }
        }
        if let Some(unused) = fp.unused.as_ref().filter(|u| !u.is_empty()) {
            add(
                "flatpak-unused".into(),
                Sev::Low,
                "flatpak",
                format!("{} unused Flatpak runtime(s)", unused.len()),
                format!(
                    "flatpak uninstall --unused would remove:\n{}",
                    unused.join("\n")
                ),
            );
        }
        if let Some(driver) = &r.host.driver {
            let want = gl_version_for_driver(driver);
            for (kind, ver) in fp.gl_nvidia.iter().filter(|(_, v)| *v != want) {
                let ext = format!("org.freedesktop.Platform.{kind}.nvidia-{ver}");
                add(
                    format!("flatpak-gl-stale:{ext}"),
                    Sev::Low,
                    "flatpak",
                    format!("Old {kind}.nvidia-{ver} extension (driver is {driver})"),
                    format!(
                        "{ext}\nnot removed by `flatpak uninstall --unused`; Cleanup offers to remove it"
                    ),
                );
            }
        }
    }

    // containers: stale with $HOME mounted
    for c in s
        .containers
        .iter()
        .flatten()
        .filter(|c| c.stale && c.home_mount)
    {
        add(
            format!("container-stale-home:{}", c.name),
            Sev::Medium,
            "container",
            format!("{}: stopped {}d, mounts $HOME", c.name, c.idle_days),
            format!(
                "podman ps -a · {} · {} · exited {} days ago\nimage {}\nmounts $HOME (shared, read-write)",
                c.kind, c.state, c.idle_days, c.image
            ),
        );
    }

    // units
    if let Some(u) = &s.units {
        for f in &u.failed {
            let (scope, unit) = f.split_once(':').unwrap_or(("system", f));
            add(
                format!("unit-failed:{f}"),
                Sev::Medium,
                "units",
                format!("Failed {scope} unit {unit}"),
                format!(
                    "systemctl{} --failed\n{unit}  failed",
                    if scope == "user" { " --user" } else { "" }
                ),
            );
        }
    }

    // repos, grouped per file (one finding per .repo, listing its enabled sections)
    if let Some(repos) = &s.repos {
        let prev_files: BTreeSet<&str> = ps
            .and_then(|p| p.repos.as_ref())
            .map(|rs| {
                rs.iter()
                    .filter(|r| r.enabled)
                    .map(|r| r.file.as_str())
                    .collect()
            })
            .unwrap_or_default();
        let mut by_file: BTreeMap<&str, Vec<&super::RepoSec>> = BTreeMap::new();
        for r in repos.iter().filter(|r| r.enabled && r.third_party) {
            by_file.entry(&r.file).or_default().push(r);
        }
        for (file, rs) in by_file {
            let copr = rs.iter().any(|r| r.copr);
            let seen = prev_files.contains(file);
            let sections: Vec<String> = rs
                .iter()
                .map(|r| format!("[{}] {}", r.section, r.url))
                .collect();
            let (sev, msg) = match (copr, seen || prev.is_none()) {
                (true, false) => (Sev::High, format!("New COPR repo {file}")),
                (true, true) => (Sev::Medium, format!("COPR repo enabled: {file}")),
                (false, _) => (Sev::Medium, format!("Third-party repo enabled: {file}")),
            };
            add(
                format!("repo:{file}"),
                sev,
                "repos",
                msg,
                format!("/etc/yum.repos.d/{file}\n{}", sections.join("\n")),
            );
        }
    }

    // shell rc patterns
    for h in &s.shell {
        add(
            format!("shell:{}:{}:{}", h.file, h.pattern, hash(h.text.trim())),
            Sev::High,
            "shell",
            format!("~/{} line {} uses {}", h.file, h.line, h.pattern),
            format!("~/{}:{}\n{}", h.file, h.line, h.text.trim()),
        );
    }

    // ostree signatures
    if let Some(o) = &s.ostree {
        for v in &o.bad_signatures {
            add(
                format!("ostree-sig:{v}"),
                Sev::High,
                "ostree",
                format!("Deployment {v} has an invalid GPG signature"),
                format!("rpm-ostree status --json\nversion {v} · signatures[0] invalid"),
            );
        }
    }

    // ~/.cache size
    if let Some(c) = &s.cache
        && c.bytes > cfg.audit.cache_warn_mb << 20
    {
        let top: Vec<String> = c
            .top
            .iter()
            .take(6)
            .map(|(n, b)| format!("{n} {}", fmt::bytes_short(*b)))
            .collect();
        add(
            "cache-size".into(),
            Sev::Low,
            "cache",
            format!(
                "~/.cache is {} (> {} MB)",
                fmt::bytes(c.bytes),
                cfg.audit.cache_warn_mb
            ),
            format!("~/.cache/{}", top.join(" · ")),
        );
    }

    // failed logins
    if let Some(j) = &s.journal
        && j.failed_logins > 0
    {
        add(
            "failed-logins".into(),
            Sev::Low,
            "auth",
            format!("{} failed login(s) in the last 24 h", j.failed_logins),
            "journalctl SYSLOG_FACILITY=10 --since -24h · \"authentication failure\"".into(),
        );
    }

    for f in &mut out {
        f.expected = is_expected(f, b);
    }
    // Open findings first, by severity; expected ones sink to the bottom.
    out.sort_by(|a, b| {
        a.expected
            .cmp(&b.expected)
            .then(b.severity.cmp(&a.severity))
            .then(a.category.cmp(&b.category))
            .then(a.id.cmp(&b.id))
    });
    out
}

fn addr_of(key: &str) -> &str {
    key.rsplit_once('/').map_or(key, |(a, _)| a)
}

fn proc_of(key: &str) -> &str {
    key.rsplit_once('/').map_or("?", |(_, p)| p)
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use crate::audit::test_report as report;

    fn app(id: &str, flags: &[&str]) -> FpApp {
        FpApp {
            id: id.into(),
            origin: "flathub".into(),
            installation: "system".into(),
            flags: flags.iter().map(|s| s.to_string()).collect(),
            filesystems: flags.iter().map(|s| s.to_string()).collect(),
            unverified: false,
        }
    }

    fn base(listeners: &[&str], findings: &[&str]) -> Baseline {
        Baseline {
            listeners: listeners.iter().map(|s| s.to_string()).collect(),
            findings: findings.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn ids(fs: &[Finding]) -> Vec<(&str, Sev, bool)> {
        fs.iter()
            .map(|f| (f.id.as_str(), f.severity, f.expected))
            .collect()
    }

    #[test]
    fn listeners_new_vs_local_vs_baselined() {
        let r = report(Sections {
            listeners: Some(vec![
                ListenSec {
                    proto: "tcp".into(),
                    key: "0.0.0.0:22000/syncthing".into(),
                    local: false,
                },
                ListenSec {
                    proto: "tcp".into(),
                    key: "127.0.0.1:631/?".into(),
                    local: true,
                },
                ListenSec {
                    proto: "tcp".into(),
                    key: "0.0.0.0:22/?".into(),
                    local: false,
                },
                ListenSec {
                    proto: "udp".into(),
                    key: "0.0.0.0:22000/syncthing".into(),
                    local: false,
                },
            ]),
            ..Default::default()
        });
        let f = derive(&r, None, &base(&["0.0.0.0:22/sshd"], &[]), &Config::default());
        assert_eq!(
            ids(&f),
            vec![
                ("listener:0.0.0.0:22000/syncthing", Sev::High, false),
                ("listener:0.0.0.0:22/?", Sev::High, true),
            ]
        );
        assert_eq!(f[0].message, "New listener 0.0.0.0:22000 (syncthing)");
        assert!(f[0].evidence.contains("tcp+udp 0.0.0.0:22000/syncthing"));
    }

    #[test]
    fn flatpak_gained_vs_persisted() {
        let prev = report(Sections {
            flatpak: Some(FlatpakSec {
                apps: vec![app("com.valvesoftware.Steam", &["home"])],
                ..Default::default()
            }),
            ..Default::default()
        });
        let cur = report(Sections {
            flatpak: Some(FlatpakSec {
                apps: vec![
                    app("com.valvesoftware.Steam", &["home"]),
                    app("com.visualstudio.code", &["host"]),
                ],
                gl_nvidia: vec![
                    ("GL".into(), "615-71-09".into()),
                    ("GL".into(), "610-57-04".into()),
                ],
                unused: Some(vec![]),
                ..Default::default()
            }),
            ..Default::default()
        });
        let f = derive(&cur, Some(&prev), &base(&[], &[]), &Config::default());
        assert_eq!(
            ids(&f),
            vec![
                ("flatpak-perm:com.visualstudio.code:host", Sev::High, false),
                ("flatpak-perm:com.valvesoftware.Steam:home", Sev::Medium, false),
                (
                    "flatpak-gl-stale:org.freedesktop.Platform.GL.nvidia-610-57-04",
                    Sev::Low,
                    false
                ),
            ]
        );
        assert_eq!(f[0].message, "com.visualstudio.code gained filesystem=host");
        // First report: nothing was "gained".
        let first = derive(&cur, None, &base(&[], &[]), &Config::default());
        assert_eq!(first[0].severity, Sev::Medium);
        assert_eq!(first[1].message, "com.visualstudio.code has filesystem=host");
    }

    #[test]
    fn repos_copr_new_then_persisted_and_third_party() {
        let repo = |file: &str, copr: bool| RepoSec {
            file: file.into(),
            section: "main".into(),
            enabled: true,
            url: "https://example".into(),
            copr,
            third_party: true,
        };
        let cur = report(Sections {
            repos: Some(vec![
                repo("_copr:copr.fedorainfracloud.org:someuser:project.repo", true),
                repo("updates-master.repo", false),
            ]),
            ..Default::default()
        });
        let empty = report(Sections {
            repos: Some(vec![]),
            ..Default::default()
        });
        let f = derive(&cur, Some(&empty), &base(&[], &[]), &Config::default());
        assert_eq!(f[0].severity, Sev::High);
        assert!(f[0].message.starts_with("New COPR"));
        assert_eq!(f[1].message, "Third-party repo enabled: updates-master.repo");
        let again = derive(&cur, Some(&cur), &base(&[], &[]), &Config::default());
        assert_eq!(again[0].severity, Sev::Medium);
        let first = derive(&cur, None, &base(&[], &[]), &Config::default());
        assert_eq!(first[0].severity, Sev::Medium);
    }

    #[test]
    fn baseline_globs_and_ordering() {
        let cur = report(Sections {
            units: Some(UnitsSec {
                failed: vec![
                    "system:systemd-remount-fs.service".into(),
                    "user:a.service".into(),
                ],
                ..Default::default()
            }),
            containers: Some(vec![CtrSec {
                name: "arch".into(),
                kind: "distrobox".into(),
                state: "exited".into(),
                home_mount: true,
                stale: true,
                idle_days: 64,
                ..Default::default()
            }]),
            cache: Some(CacheSec {
                bytes: 9 << 30,
                top: vec![("pip".into(), 1 << 30)],
            }),
            ..Default::default()
        });
        let f = derive(
            &cur,
            None,
            &base(&[], &["unit-failed:system:*"]),
            &Config::default(),
        );
        assert_eq!(
            ids(&f),
            vec![
                ("container-stale-home:arch", Sev::Medium, false),
                ("unit-failed:user:a.service", Sev::Medium, false),
                ("cache-size", Sev::Low, false),
                ("unit-failed:system:systemd-remount-fs.service", Sev::Medium, true),
            ]
        );
        assert_eq!(f[0].message, "arch: stopped 64d, mounts $HOME");
        assert_eq!(cur.counts(&base(&[], &[])).medium, 0, "counts use stored findings");
    }

    #[test]
    fn shell_ids_are_stable() {
        let h = |line| crate::collectors::shell::Hit {
            file: ".bashrc".into(),
            line,
            pattern: "curl".into(),
            text: "  curl -s x | sh".into(),
        };
        let a = derive(
            &report(Sections {
                shell: vec![h(3)],
                ..Default::default()
            }),
            None,
            &base(&[], &[]),
            &Config::default(),
        );
        let b = derive(
            &report(Sections {
                shell: vec![h(9)],
                ..Default::default()
            }),
            None,
            &base(&[], &[]),
            &Config::default(),
        );
        assert_eq!(a[0].id, b[0].id, "moving a line doesn't change its id");
        assert_eq!(a[0].severity, Sev::High);
    }
}
