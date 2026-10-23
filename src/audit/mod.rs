//! Security audit (spec §7): a snapshot of diffable facts, findings derived from it, and a
//! structural diff against the previous snapshot. Read-only; run only when the user asks.

pub mod diff;
pub mod findings;
pub mod store;

use std::time::Instant;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::baseline::Baseline;
use crate::collectors::shell::Hit;
use crate::collectors::{
    CollectError, Ctx, breakdown, flatpak, gpu, journal, net, ostree, podman, repos, shell, units,
};

pub const VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub version: u32,
    pub taken_at: Timestamp,
    pub tag: Option<String>,
    pub host: Host,
    pub sections: Sections,
    /// Sections that couldn't be collected (`podman: not found`).
    pub errors: Vec<String>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Host {
    pub os_version: String,
    pub kernel: String,
    pub driver: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Sections {
    pub ostree: Option<OstreeSec>,
    pub flatpak: Option<FlatpakSec>,
    pub containers: Option<Vec<CtrSec>>,
    pub listeners: Option<Vec<ListenSec>>,
    pub units: Option<UnitsSec>,
    pub repos: Option<Vec<RepoSec>>,
    pub shell: Vec<Hit>,
    pub journal: Option<JournalSec>,
    pub cache: Option<CacheSec>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct OstreeSec {
    pub booted_version: String,
    pub origin: String,
    pub layered: Vec<String>,
    pub local: Vec<String>,
    pub removals: Vec<String>,
    pub kargs: Option<String>,
    /// Versions of deployments whose GPG signature is present but invalid.
    pub bad_signatures: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FlatpakSec {
    pub apps: Vec<FpApp>,
    pub remotes: Vec<(String, String)>,
    pub gl_nvidia: Vec<(String, String)>,
    /// What `flatpak uninstall --unused` would remove; `None` if the preview failed.
    pub unused: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FpApp {
    pub id: String,
    pub origin: String,
    pub installation: String,
    pub flags: Vec<String>,
    pub filesystems: Vec<String>,
    pub unverified: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct CtrSec {
    pub name: String,
    pub kind: String,
    pub state: String,
    pub image: String,
    pub home_mount: bool,
    pub stale: bool,
    pub idle_days: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ListenSec {
    pub proto: String,
    /// `addr:port/process`, the baseline key.
    pub key: String,
    pub local: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UnitsSec {
    pub user_enabled: Vec<String>,
    pub system_enabled: Vec<String>,
    /// `scope:unit` (`user:tracker-miner-fs-3.service`).
    pub failed: Vec<String>,
    pub autostart: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RepoSec {
    pub file: String,
    pub section: String,
    pub enabled: bool,
    pub url: String,
    pub copr: bool,
    pub third_party: bool,
}

/// Counts only: journal messages can contain secrets and are never stored.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct JournalSec {
    pub user_warn: usize,
    pub sys_err: Option<usize>,
    pub failed_logins: usize,
    pub top_idents: Vec<(String, usize)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheSec {
    pub bytes: u64,
    pub top: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sev {
    Low,
    Medium,
    High,
}

impl Sev {
    pub fn as_str(self) -> &'static str {
        match self {
            Sev::High => "high",
            Sev::Medium => "medium",
            Sev::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    /// Stable across reports; what `baseline.toml findings` stores.
    pub id: String,
    pub severity: Sev,
    pub category: String,
    pub message: String,
    pub evidence: String,
    /// Suppressed by the baseline when the report was taken.
    #[serde(default)]
    pub expected: bool,
}

/// Open findings by severity, honouring the *current* baseline.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl Report {
    pub fn open<'a>(&'a self, b: &'a Baseline) -> impl Iterator<Item = &'a Finding> + 'a {
        self.findings.iter().filter(|f| !findings::is_expected(f, b))
    }

    pub fn counts(&self, b: &Baseline) -> Counts {
        let mut c = Counts::default();
        for f in self.open(b) {
            match f.severity {
                Sev::High => c.high += 1,
                Sev::Medium => c.medium += 1,
                Sev::Low => c.low += 1,
            }
        }
        c
    }
}

/// Collect every section. `progress` gets one line per section (streamed by `sentry job audit`).
pub fn snapshot(ctx: &Ctx, tag: Option<String>, progress: &mut dyn FnMut(String)) -> Report {
    let mut errors = Vec::new();
    let mut s = Sections::default();
    let mut step = |name: &str, f: &mut dyn FnMut() -> Result<(), CollectError>| {
        let t = Instant::now();
        let r = f();
        let ms = t.elapsed().as_millis();
        match r {
            Ok(()) => progress(format!("  {name:<10} ok   {ms} ms")),
            Err(e) => {
                progress(format!("  {name:<10} skip {e}"));
                errors.push(format!("{name}: {e}"));
            }
        }
    };

    let mut host = Host {
        os_version: crate::paths::os_version(),
        kernel: ostree::booted_kernel(),
        driver: None,
    };
    step("gpu", &mut || {
        host.driver = gpu::collect()?.map(|g| g.driver);
        Ok(())
    });
    step("ostree", &mut || {
        let o = ostree::collect()?;
        let b = o.booted();
        s.ostree = Some(OstreeSec {
            booted_version: b.map(|d| d.version.clone()).unwrap_or_default(),
            origin: b.map(|d| d.origin.clone()).unwrap_or_default(),
            layered: b.map(|d| d.layered.clone()).unwrap_or_default(),
            local: b.map(|d| d.local.clone()).unwrap_or_default(),
            removals: b.map(|d| d.removals.clone()).unwrap_or_default(),
            kargs: o.kargs.clone(),
            bad_signatures: o
                .deployments
                .iter()
                .filter(|d| d.sig_valid == Some(false))
                .map(|d| d.version.clone())
                .collect(),
        });
        Ok(())
    });
    step("flatpak", &mut || {
        let fp = flatpak::collect(ctx)?;
        s.flatpak = Some(FlatpakSec {
            apps: fp
                .apps
                .iter()
                .map(|a| FpApp {
                    id: a.id.clone(),
                    origin: a.origin.clone(),
                    installation: a.installation.clone(),
                    flags: a.flags.iter().map(|f| f.label.clone()).collect(),
                    filesystems: a.perms.filesystems.clone(),
                    unverified: a.unverified_origin,
                })
                .collect(),
            remotes: fp
                .remotes
                .iter()
                .map(|r| (r.name.clone(), r.url.clone()))
                .collect(),
            gl_nvidia: fp.gl_nvidia.clone(),
            unused: flatpak::collect_unused().ok(),
        });
        Ok(())
    });
    step("podman", &mut || {
        let p = podman::collect(ctx)?;
        s.containers = Some(
            p.containers
                .iter()
                .map(|c| CtrSec {
                    name: c.name.clone(),
                    kind: c.kind.as_str().into(),
                    state: c.state.clone(),
                    image: c.image.clone(),
                    home_mount: c.home_mount,
                    stale: c.stale,
                    idle_days: c.age_s / 86400,
                })
                .collect(),
        );
        Ok(())
    });
    step("listeners", &mut || {
        let n = net::collect(ctx)?;
        let low = net::ephemeral_low();
        let mut ls: Vec<ListenSec> = n
            .listeners
            .iter()
            // Client UDP sockets come and go with every browser tab; they'd swamp the diff.
            .filter(|l| !net::is_ephemeral(l, low))
            .map(|l| ListenSec {
                proto: l.proto.clone(),
                key: l.key(),
                local: net::is_local(&l.addr),
            })
            .collect();
        ls.sort_by(|a, b| a.key.cmp(&b.key).then(a.proto.cmp(&b.proto)));
        ls.dedup();
        s.listeners = Some(ls);
        Ok(())
    });
    step("units", &mut || {
        let u = units::collect(ctx)?;
        s.units = Some(UnitsSec {
            user_enabled: u.user_enabled.clone(),
            system_enabled: u.system_enabled.clone(),
            failed: u
                .failed
                .iter()
                .map(|f| format!("{}:{}", f.scope, f.unit))
                .collect(),
            autostart: u
                .autostart
                .iter()
                .filter(|a| !a.hidden)
                .map(|a| a.file.clone())
                .collect(),
        });
        Ok(())
    });
    step("repos", &mut || {
        s.repos = Some(
            repos::collect()?
                .into_iter()
                .map(|r| RepoSec {
                    file: r.file,
                    section: r.section,
                    enabled: r.enabled,
                    url: r.url,
                    copr: r.copr,
                    third_party: r.third_party,
                })
                .collect(),
        );
        Ok(())
    });
    step("shell", &mut || {
        s.shell = shell::collect(ctx);
        Ok(())
    });
    step("journal", &mut || {
        let j = journal::collect()?;
        let mut idents: std::collections::BTreeMap<String, usize> = Default::default();
        for e in j.user_warn.iter().chain(j.sys_err.iter().flatten()) {
            *idents.entry(e.ident.clone()).or_default() += 1;
        }
        let mut top: Vec<(String, usize)> = idents.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        top.truncate(8);
        s.journal = Some(JournalSec {
            user_warn: j.user_warn.len(),
            sys_err: j.sys_err.as_ref().map(Vec::len),
            failed_logins: j.failed_logins,
            top_idents: top,
        });
        Ok(())
    });
    step("cache", &mut || {
        let (bytes, top) = breakdown::cache_top(&ctx.home, 100 << 20);
        s.cache = Some(CacheSec { bytes, top });
        Ok(())
    });

    Report {
        version: VERSION,
        taken_at: ctx.now,
        tag,
        host,
        sections: s,
        errors,
        findings: Vec::new(),
    }
}

/// Snapshot, derive findings against the previous report, store, prune. Returns the stored
/// report, its path and the report it was diffed against.
pub fn run(
    ctx: &Ctx,
    tag: Option<String>,
    diff_against: Option<&str>,
    progress: &mut dyn FnMut(String),
) -> anyhow::Result<(Report, std::path::PathBuf, Option<store::Stored>)> {
    progress("collecting…".into());
    let mut r = snapshot(ctx, tag, progress);
    let all = store::list();
    let prev = match diff_against {
        Some(t) => Some(
            store::find_tag(&all, t)
                .ok_or_else(|| anyhow::anyhow!("no report tagged {t:?} to diff against"))?
                .clone(),
        ),
        None => all.last().cloned(),
    };
    let baseline = Baseline::effective(&ctx.cfg);
    r.findings = findings::derive(&r, prev.as_ref().map(|p| &p.report), &baseline, &ctx.cfg);
    let path = store::save(&r, prev.as_ref())?;
    let pruned = store::prune(ctx.cfg.audit.retention_months, ctx.now);
    if pruned > 0 {
        progress(format!("pruned {pruned} report(s) older than {} months", ctx.cfg.audit.retention_months));
    }
    Ok((r, path, prev))
}

#[cfg(test)]
pub fn test_report(s: Sections) -> Report {
    Report {
        version: VERSION,
        taken_at: Timestamp::UNIX_EPOCH,
        tag: None,
        host: Host {
            driver: Some("615.71.09".into()),
            ..Host::default()
        },
        sections: s,
        errors: vec![],
        findings: vec![],
    }
}
