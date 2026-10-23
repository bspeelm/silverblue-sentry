//! Read-only plans for every job: what would run, what it would reclaim, and why. `--dry-run`
//! prints these; the TUI shows them in confirm modals and on the Cleanup screen.

use std::collections::HashSet;
use std::path::PathBuf;

use super::JobId;
use crate::collectors::breakdown;
use crate::collectors::flatpak::{self, gl_version_for_driver};
use crate::collectors::ostree::{self, UpgradePlan};
use crate::collectors::podman::{self, Kind};
use crate::collectors::{CollectError, Ctx, gpu};
use crate::exec::Cmd;
use crate::fmt;

#[derive(Debug, Clone)]
pub struct Item {
    pub job: JobId,
    /// Stable within a job; `sentry job <job> --only <key>` selects it.
    pub key: String,
    pub label: String,
    pub bytes: Option<u64>,
    pub preview: Vec<String>,
    pub act: Act,
    /// Pre-checked on the Cleanup screen.
    pub default_on: bool,
}

#[derive(Debug, Clone)]
pub enum Act {
    Run(Cmd),
    /// Done in-process by `sentry job` (audit, update-check).
    Builtin,
    /// Shown, never run.
    ListOnly,
    /// Would run, but there's nothing to do right now.
    Nothing,
}

impl Act {
    fn opt(c: Option<Cmd>) -> Self {
        c.map_or(Act::Nothing, Act::Run)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub items: Vec<Item>,
    /// Problems that made a section unavailable (`podman not found`).
    pub notes: Vec<String>,
}

impl Plan {
    pub fn runnable(&self) -> impl Iterator<Item = &Item> {
        self.items.iter().filter(|i| i.runnable())
    }
}

impl Item {
    pub fn runnable(&self) -> bool {
        matches!(self.act, Act::Run(_) | Act::Builtin)
    }
}

fn du(paths: &[PathBuf]) -> u64 {
    let (mut seen, mut bad) = (HashSet::new(), 0);
    breakdown::du(paths, &mut seen, &mut bad)
}

pub fn plan(job: JobId, ctx: &Ctx) -> Plan {
    let mut p = Plan::default();
    let r =
        match job {
            JobId::Audit => {
                p.items.push(Item {
                    job,
                    key: "audit".into(),
                    label: "snapshot + findings + diff".into(),
                    bytes: None,
                    preview: vec![
                    "read-only: ostree flatpak podman listeners units repos shell journal cache"
                        .into(),
                    format!("report → {}/<date>.json + .md", crate::audit::store::dir().display()),
                ],
                    act: Act::Builtin,
                    default_on: true,
                });
                Ok(())
            }
            JobId::UpdateCheck => {
                p.items.push(Item {
                    job,
                    key: "check".into(),
                    label: "rpm-ostree upgrade --preview · flatpak remote-ls --updates".into(),
                    bytes: None,
                    preview: vec!["network; refreshes the cached update lists (no apply)".into()],
                    act: Act::Builtin,
                    default_on: true,
                });
                Ok(())
            }
            JobId::UpdateApply => update_apply(&mut p),
            JobId::CleanupFlatpak => cleanup_flatpak(&mut p),
            JobId::CleanupPodman => cleanup_podman(&mut p, ctx),
            JobId::CleanupOstree => {
                let bytes = du(&[crate::paths::host("/var/cache/rpm-ostree")]);
                p.items.push(Item {
                    job,
                    key: "repomd".into(),
                    label: "rpm-ostree cleanup -m".into(),
                    bytes: Some(bytes),
                    preview: vec![format!(
                        "cached rpm repo metadata in /var/cache/rpm-ostree ≈ {}",
                        fmt::bytes(bytes)
                    )],
                    act: Act::Run(
                        Cmd::host("rpm-ostree")
                            .args(["cleanup", "-m"])
                            .timeout(None),
                    ),
                    default_on: true,
                });
                p.items.push(Item {
                    job,
                    key: "base".into(),
                    label: "rpm-ostree cleanup -b".into(),
                    bytes: None,
                    preview: vec!["temporary files; deployments unchanged (opt-in)".into()],
                    act: Act::Run(
                        Cmd::host("rpm-ostree")
                            .args(["cleanup", "-b"])
                            .timeout(None),
                    ),
                    default_on: false,
                });
                Ok(())
            }
            JobId::CleanupCache => {
                cleanup_cache(&mut p, ctx);
                Ok(())
            }
        };
    if let Err(e) = r {
        p.items.push(Item {
            job,
            key: "unavailable".into(),
            label: format!("{}: unavailable", job.name()),
            bytes: None,
            preview: vec![e.to_string()],
            act: Act::ListOnly,
            default_on: false,
        });
    }
    p
}

fn update_apply(p: &mut Plan) -> Result<(), CollectError> {
    let job = JobId::UpdateApply;
    let o = ostree::collect()?;
    let (label, preview, cmd) = match ostree::upgrade_plan(&o) {
        UpgradePlan::NoUpdate => (
            "rpm-ostree: no pending update".to_string(),
            vec!["nothing in cached-update — run update-check (or c) first".to_string()],
            None,
        ),
        UpgradePlan::Routine => {
            let u = o.update.as_ref();
            (
                "rpm-ostree upgrade".into(),
                vec![format!(
                    "{} → {} · {} packages · stages; reboot to apply",
                    o.booted().map_or("?", |b| b.version.as_str()),
                    u.and_then(|u| u.version.as_deref()).unwrap_or("?"),
                    u.map_or(0, |u| u.upgraded.len() + u.added.len())
                )],
                Some(Cmd::host("rpm-ostree").arg("upgrade").timeout(None)),
            )
        }
        UpgradePlan::Ritual(kmod) => (
            "rpm-ostree upgrade: kernel changes".into(),
            vec![
                format!("kmod ritual required (drops {kmod}, two reboots)"),
                "not run by this job: use the quick-update workflow (Upgrade, 0)".into(),
            ],
            None,
        ),
        UpgradePlan::Ambiguous(k) => (
            "rpm-ostree upgrade: blocked".into(),
            vec![format!(
                "kernel changes and {} kmod-nvidia packages are layered — resolve by hand",
                k.len()
            )],
            None,
        ),
    };
    p.items.push(Item {
        job,
        key: "ostree".into(),
        label,
        bytes: None,
        preview,
        default_on: cmd.is_some(),
        act: Act::opt(cmd),
    });
    let pending = crate::cache::load::<Vec<flatpak::FpUpdate>>(crate::cache::FLATPAK_UPDATES);
    let running = flatpak_running();
    let mut preview = vec![match &pending {
        Some(c) => format!(
            "{} pending (last check {})",
            c.data.len(),
            fmt::ago(c.age_secs(jiff::Timestamp::now()))
        ),
        None => "pending updates unknown (never checked)".into(),
    }];
    if !running.is_empty() {
        preview.push(format!(
            "running sandboxes: {} — quit them first (cheatsheet §3b)",
            running.join(", ")
        ));
    }
    p.items.push(Item {
        job,
        key: "flatpak".into(),
        label: "flatpak update -y".into(),
        bytes: None,
        preview,
        act: Act::Run(
            Cmd::host("flatpak")
                .args(["update", "-y", "--noninteractive"])
                .timeout(None),
        ),
        default_on: true,
    });
    Ok(())
}

/// Apps with a running sandbox (`flatpak ps`); empty if flatpak is missing.
pub fn flatpak_running() -> Vec<String> {
    let out = Cmd::host("flatpak")
        .args(["ps", "--columns=application"])
        .timeout(Some(std::time::Duration::from_secs(3)))
        .output()
        .unwrap_or_default();
    let mut v: Vec<String> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    v.sort();
    v.dedup();
    v
}

fn cleanup_flatpak(p: &mut Plan) -> Result<(), CollectError> {
    let job = JobId::CleanupFlatpak;
    let unused = flatpak::collect_unused()?;
    let runtime_dirs = |refs: &[String]| -> Vec<PathBuf> {
        refs.iter()
            .filter_map(|r| {
                let (id, branch) = r.split_once("//")?;
                Some(
                    crate::paths::host("/var/lib/flatpak/runtime")
                        .join(id)
                        .join(std::env::consts::ARCH)
                        .join(branch),
                )
            })
            .collect()
    };
    let bytes = du(&runtime_dirs(&unused));
    p.items.push(Item {
        job,
        key: "unused".into(),
        label: "flatpak uninstall --unused".into(),
        bytes: (!unused.is_empty()).then_some(bytes),
        preview: if unused.is_empty() {
            vec!["nothing unused (pinned runtimes are kept)".into()]
        } else {
            unused.iter().map(|r| format!("would remove {r}")).collect()
        },
        act: Act::opt((!unused.is_empty()).then(|| {
            Cmd::host("sh")
                .args([
                    "-c",
                    "flatpak uninstall --unused -y --noninteractive --system && \
                     flatpak uninstall --unused -y --noninteractive --user",
                ])
                .timeout(None)
        })),
        default_on: true,
    });

    // GL.nvidia extensions that don't match the host driver aren't "unused" to flatpak.
    let driver = gpu::collect().ok().flatten().map(|g| g.driver);
    let refs = crate::exec::Cmd::host("flatpak")
        .args(["list", "--runtime", "--columns=ref"])
        .output()?;
    if let Some(d) = driver {
        let want = gl_version_for_driver(&d);
        for r in refs.lines().map(str::trim) {
            let Some(id) = r.split('/').next() else {
                continue;
            };
            let is_gl = id.starts_with("org.freedesktop.Platform.GL.nvidia-")
                || id.starts_with("org.freedesktop.Platform.GL32.nvidia-");
            if !is_gl || id.ends_with(&format!("nvidia-{want}")) {
                continue;
            }
            let bytes = du(&[crate::paths::host("/var/lib/flatpak/runtime").join(id)]);
            p.items.push(Item {
                job,
                key: format!("gl:{id}"),
                label: format!("old {}", id.trim_start_matches("org.freedesktop.Platform.")),
                bytes: Some(bytes),
                preview: vec![
                    format!("host driver is {d}; this extension is for another driver"),
                    format!("would remove runtime/{r}"),
                    "not removed by --unused (cheatsheet §3b)".into(),
                ],
                act: Act::Run(
                    Cmd::host("flatpak")
                        .args([
                            "uninstall",
                            "-y",
                            "--noninteractive",
                            &format!("runtime/{r}"),
                        ])
                        .timeout(None),
                ),
                default_on: true,
            });
        }
    }
    Ok(())
}

fn cleanup_podman(p: &mut Plan, ctx: &Ctx) -> Result<(), CollectError> {
    let job = JobId::CleanupPodman;
    let pd = podman::collect(ctx)?;
    let days = ctx.cfg.audit.stale_container_days;
    let stale: Vec<&podman::Ctr> = pd
        .containers
        .iter()
        .filter(|c| c.stale && c.kind == Kind::Podman)
        .collect();
    let names: Vec<String> = stale.iter().map(|c| c.name.clone()).collect();
    p.items.push(Item {
        job,
        key: "stopped".into(),
        label: format!("podman: stopped > {days}d"),
        bytes: None,
        preview: if stale.is_empty() {
            vec![format!("no plain podman containers stopped > {days}d")]
        } else {
            stale
                .iter()
                .map(|c| {
                    format!(
                        "would remove {} ({}, {})",
                        c.name,
                        fmt::age(c.age_s),
                        c.image
                    )
                })
                .collect()
        },
        act: Act::opt((!names.is_empty()).then(|| {
            Cmd::host("podman")
                .arg("rm")
                .args(names.iter().map(String::as_str))
                .timeout(None)
        })),
        default_on: true,
    });
    let boxes: Vec<String> = pd
        .containers
        .iter()
        .filter(|c| c.stale && c.kind != Kind::Podman)
        .map(|c| {
            format!(
                "{} ({}, stopped {})",
                c.name,
                c.kind.as_str(),
                fmt::age(c.age_s)
            )
        })
        .collect();
    if !boxes.is_empty() {
        p.items.push(Item {
            job,
            key: "boxes".into(),
            label: "stale toolbox/distrobox (list only)".into(),
            bytes: None,
            preview: boxes
                .into_iter()
                .chain([
                    "they hold installed packages; remove from Containers (5) if unwanted".into(),
                ])
                .collect(),
            act: Act::ListOnly,
            default_on: false,
        });
    }
    p.items.push(Item {
        job,
        key: "dangling".into(),
        label: "podman: dangling images".into(),
        bytes: (pd.dangling.count > 0).then_some(pd.dangling.bytes),
        preview: vec![if pd.dangling.count == 0 {
            "no dangling images".into()
        } else {
            format!(
                "would delete {} untagged image(s) ≈ {}",
                pd.dangling.count,
                fmt::bytes(pd.dangling.bytes)
            )
        }],
        act: Act::opt((pd.dangling.count > 0).then(|| {
            Cmd::host("podman")
                .args(["image", "prune", "-f"])
                .timeout(None)
        })),
        default_on: true,
    });
    Ok(())
}

/// `[cleanup.cache].delete_dirs` entries must be plain child names of `~/.cache`.
pub fn valid_cache_dir(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && name != "sentry"
}

fn cleanup_cache(p: &mut Plan, ctx: &Ctx) {
    let job = JobId::CleanupCache;
    let (total, top) = breakdown::cache_top(&ctx.home, 100 << 20);
    let warn = ctx.cfg.audit.cache_warn_mb << 20;
    let opted: Vec<&String> = ctx.cfg.cleanup.cache.delete_dirs.iter().collect();
    let valid = opted.iter().filter(|n| valid_cache_dir(n)).count();
    let mut listed = vec![format!(
        "~/.cache is {} (threshold {} MB){}",
        fmt::bytes(total),
        ctx.cfg.audit.cache_warn_mb,
        if total > warn { " — over" } else { "" }
    )];
    listed.extend(
        top.iter()
            .take(12)
            .map(|(n, b)| format!("  {n:<24} {:>9}", fmt::bytes(*b))),
    );
    listed.push("Add names to [cleanup.cache].delete_dirs to allow deletion.".into());
    p.items.push(Item {
        job,
        key: "report".into(),
        label: format!(
            "~/.cache (opted-in: {})",
            if valid == 0 {
                "none".to_string()
            } else {
                valid.to_string()
            }
        ),
        bytes: None,
        preview: listed,
        act: Act::ListOnly,
        default_on: false,
    });
    for name in opted {
        if !valid_cache_dir(name) {
            p.notes.push(format!(
                "[cleanup.cache].delete_dirs: {name:?} ignored (must be a plain directory name)"
            ));
            continue;
        }
        let path = ctx.home.join(".cache").join(name);
        if !path.is_dir() {
            continue;
        }
        let bytes = du(std::slice::from_ref(&path));
        p.items.push(Item {
            job,
            key: format!("dir:{name}"),
            label: format!("~/.cache/{name}"),
            bytes: Some(bytes),
            preview: vec![format!(
                "would delete {} ({})",
                path.display(),
                fmt::bytes(bytes)
            )],
            act: Act::Run(
                Cmd::local("rm")
                    .args(["-rf", "--"])
                    .arg(path.as_os_str())
                    .timeout(None),
            ),
            default_on: true,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::valid_cache_dir;

    #[test]
    fn cache_dir_names() {
        assert!(valid_cache_dir("pip"));
        for bad in ["", ".", "..", "a/b", "../x", "sentry"] {
            assert!(!valid_cache_dir(bad), "{bad}");
        }
    }
}
