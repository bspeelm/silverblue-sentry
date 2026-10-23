//! Jobs (spec §8). Every job runs as `sentry job <name>`; the TUI streams that same command, so
//! headless and TUI runs share output, reports and last-run records.

pub mod state;

use std::io::Write;

use crate::collectors::Ctx;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum JobId {
    Audit,
    UpdateCheck,
    UpdateApply,
    CleanupFlatpak,
    CleanupPodman,
    CleanupOstree,
    CleanupCache,
}

impl JobId {
    pub const ALL: [JobId; 7] = [
        JobId::Audit,
        JobId::UpdateCheck,
        JobId::UpdateApply,
        JobId::CleanupFlatpak,
        JobId::CleanupPodman,
        JobId::CleanupOstree,
        JobId::CleanupCache,
    ];

    pub fn name(self) -> &'static str {
        match self {
            JobId::Audit => "audit",
            JobId::UpdateCheck => "update-check",
            JobId::UpdateApply => "update-apply",
            JobId::CleanupFlatpak => "cleanup-flatpak",
            JobId::CleanupPodman => "cleanup-podman",
            JobId::CleanupOstree => "cleanup-ostree",
            JobId::CleanupCache => "cleanup-cache",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|j| j.name() == s)
    }

    #[allow(dead_code)]
    pub fn description(self) -> &'static str {
        match self {
            JobId::Audit => "snapshot + diff + findings",
            JobId::UpdateCheck => "rpm-ostree + flatpak availability (no apply)",
            JobId::UpdateApply => "rpm-ostree upgrade · flatpak update -y",
            JobId::CleanupFlatpak => "flatpak uninstall --unused · stale GL.nvidia",
            JobId::CleanupPodman => "prune stopped podman containers, dangling images",
            JobId::CleanupOstree => "rpm-ostree cleanup -m",
            JobId::CleanupCache => "report ~/.cache over threshold; delete opted-in dirs",
        }
    }

    #[allow(dead_code)]
    /// Spec §8 suggested cadence; `None` = no cadence (update-apply), `"off"` = disabled.
    pub fn default_every(self) -> Option<&'static str> {
        match self {
            JobId::Audit => Some("30d"),
            JobId::UpdateCheck => Some("7d"),
            JobId::UpdateApply => None,
            JobId::CleanupFlatpak | JobId::CleanupPodman | JobId::CleanupOstree => Some("30d"),
            JobId::CleanupCache => Some("off"),
        }
    }
}

pub struct Opts {
    pub dry_run: bool,
    #[allow(dead_code)] // destructive jobs arrive in milestone 4
    pub yes: bool,
    pub tag: Option<String>,
    pub diff_against: Option<String>,
}

/// `sentry job <name>`: returns the process exit code.
pub fn run_cli(name: &str, o: Opts, ctx: &Ctx) -> u8 {
    let Some(job) = JobId::from_name(name) else {
        eprintln!(
            "sentry job: unknown job {name:?}; one of: {}",
            JobId::ALL.map(JobId::name).join(", ")
        );
        return 2;
    };
    let out = &mut std::io::stdout();
    let r = match job {
        JobId::Audit => audit(o, ctx, out),
        _ => {
            eprintln!("sentry job {name}: not implemented yet (milestone 4)");
            return 2;
        }
    };
    match r {
        Ok(summary) => {
            if !summary.is_empty() {
                let _ = state::record(job, true, &summary);
            }
            0
        }
        Err(e) => {
            let _ = state::record(job, false, &format!("{e:#}"));
            eprintln!("sentry job {name}: {e:#}");
            1
        }
    }
}

/// Read-only, so no confirm. Prints progress, then the report path and summaries.
fn audit(o: Opts, ctx: &Ctx, out: &mut dyn Write) -> anyhow::Result<String> {
    use crate::audit;
    if o.dry_run {
        writeln!(
            out,
            "would collect: gpu ostree flatpak podman listeners units repos shell journal cache"
        )?;
        writeln!(out, "would write: {}/<date>.json + .md", audit::store::dir().display())?;
        return Ok(String::new());
    }
    let (r, path, prev) = audit::run(ctx, o.tag, o.diff_against.as_deref(), &mut |l| {
        let _ = writeln!(out, "{l}");
        let _ = out.flush();
    })?;
    let b = crate::baseline::Baseline::effective(&ctx.cfg);
    let c = r.counts(&b);
    writeln!(out, "report → {}", path.display())?;
    let counts = format!("{} high · {} medium · {} low", c.high, c.medium, c.low);
    writeln!(out, "findings: {counts}")?;
    for f in r.open(&b) {
        writeln!(out, "  {:<6} {:<10} {}", f.severity.as_str(), f.category, f.message)?;
    }
    match &prev {
        Some(p) => {
            let d = audit::diff::diff(&p.report, &r);
            writeln!(out, "diff vs {}: {}", p.name(), audit::diff::summary(&d))?;
        }
        None => writeln!(out, "first report: no diff")?,
    }
    Ok(counts)
}
