//! Jobs (spec §8). Every job runs as `sentry job <name>`; the TUI streams that same command, so
//! headless and TUI runs share output, reports and last-run records.

pub mod plan;
pub mod state;

use std::io::Write;

use crate::cache;
use crate::collectors::{CollectError, Ctx};
use crate::exec::Cmd;

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

    pub const CLEANUP: [JobId; 4] = [
        JobId::CleanupOstree,
        JobId::CleanupFlatpak,
        JobId::CleanupPodman,
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

/// The user declined (or there was no terminal to ask on): not a failed run.
#[derive(Debug, thiserror::Error)]
#[error("not confirmed")]
struct Cancelled;

pub struct Opts {
    pub dry_run: bool,
    pub yes: bool,
    pub tag: Option<String>,
    pub diff_against: Option<String>,
    /// Plan item keys to run (Cleanup screen selections); empty = all runnable items.
    pub only: Vec<String>,
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
    let dry = o.dry_run;
    let r = match job {
        JobId::Audit => audit(o, ctx, out),
        JobId::UpdateCheck if !o.dry_run => update_check(out),
        _ => run_plan(job, &o, ctx, out),
    };
    match r {
        Ok(Some(summary)) => {
            let _ = state::record(job, true, &summary);
            0
        }
        Ok(None) => 0,
        Err(e) if e.is::<Cancelled>() => {
            eprintln!("sentry job {name}: not confirmed (pass --yes to run without a prompt)");
            1
        }
        // A dry run changes nothing, so it never counts as a run (even if printing failed).
        Err(e) if dry => {
            eprintln!("sentry job {name}: {e:#}");
            1
        }
        Err(e) => {
            let _ = state::record(job, false, &format!("{e:#}"));
            eprintln!("sentry job {name}: {e:#}");
            1
        }
    }
}

pub fn print_plan(p: &plan::Plan, out: &mut dyn Write) -> std::io::Result<()> {
    for i in &p.items {
        let size = i
            .bytes
            .map_or(String::new(), |b| format!("  ≈ {}", crate::fmt::bytes(b)));
        let mark = match &i.act {
            plan::Act::Run(_) | plan::Act::Builtin => "•",
            plan::Act::ListOnly | plan::Act::Nothing => "·",
        };
        writeln!(out, "{mark} [{}] {}{size}", i.key, i.label)?;
        for l in &i.preview {
            writeln!(out, "    {l}")?;
        }
        if let plan::Act::Run(c) = &i.act {
            writeln!(out, "    $ {}", c.display())?;
        }
    }
    for n in &p.notes {
        writeln!(out, "! {n}")?;
    }
    Ok(())
}

fn confirm(prompt: &str) -> bool {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return false;
    }
    print!("{prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).is_ok() && matches!(s.trim(), "y" | "Y" | "yes")
}

/// Plan → (confirm) → run each selected item in order, stopping at the first failure.
fn run_plan(
    job: JobId,
    o: &Opts,
    ctx: &Ctx,
    out: &mut dyn Write,
) -> anyhow::Result<Option<String>> {
    let p = plan::plan(job, ctx);
    print_plan(&p, out)?;
    if o.dry_run {
        return Ok(None);
    }
    let unknown: Vec<&String> = o
        .only
        .iter()
        .filter(|k| !p.items.iter().any(|i| &i.key == *k))
        .collect();
    if !unknown.is_empty() {
        anyhow::bail!("--only: no such item {unknown:?} (it may have nothing left to do)");
    }
    // Default selection = the items the Cleanup screen pre-checks; opt-ins need --only.
    let todo: Vec<&plan::Item> = p
        .runnable()
        .filter(|i| {
            if o.only.is_empty() {
                i.default_on
            } else {
                o.only.contains(&i.key)
            }
        })
        .collect();
    if todo.is_empty() {
        writeln!(out, "nothing to do")?;
        return Ok(Some("nothing to do".into()));
    }
    if !o.yes && !confirm(&format!("run {} item(s)?", todo.len())) {
        return Err(Cancelled.into());
    }
    let mut est = 0;
    for i in &todo {
        let plan::Act::Run(cmd) = &i.act else {
            continue;
        };
        writeln!(out, "$ {}", cmd.display())?;
        out.flush()?;
        let st = cmd.interactive()?;
        if !st.success() {
            anyhow::bail!("{} failed (exit {})", i.label, st.code().unwrap_or(-1));
        }
        est += i.bytes.unwrap_or(0);
    }
    let summary = if est > 0 {
        format!(
            "{} item(s) · ≈ {} freed",
            todo.len(),
            crate::fmt::bytes(est)
        )
    } else {
        format!("{} item(s) done", todo.len())
    };
    writeln!(out, "✓ {summary}")?;
    Ok(Some(summary))
}

/// `rpm-ostree upgrade --preview` (refreshes cached-update) and `flatpak remote-ls --updates`
/// (cached). Also what the TUI's `c` does.
fn update_check(out: &mut dyn Write) -> anyhow::Result<Option<String>> {
    writeln!(out, "$ rpm-ostree upgrade --preview")?;
    out.flush()?;
    let o = check_ostree()?;
    let n = o
        .update
        .as_ref()
        .map_or(0, |u| u.upgraded.len() + u.added.len());
    writeln!(
        out,
        "rpm-ostree: {}",
        match &o.update {
            None => "no update".to_string(),
            Some(u) => format!(
                "{n} packages{}",
                if u.kernel_changed {
                    " · kernel changes (kmod ritual)"
                } else {
                    ""
                }
            ),
        }
    )?;
    writeln!(out, "$ flatpak remote-ls --updates")?;
    out.flush()?;
    let fp = check_flatpak()?;
    writeln!(out, "flatpak: {} update(s)", fp.data.len())?;
    Ok(Some(format!("{n} ostree · {} flatpak", fp.data.len())))
}

pub fn check_ostree() -> Result<crate::collectors::ostree::Ostree, CollectError> {
    let out = Cmd::host("rpm-ostree")
        .args(["upgrade", "--preview"])
        .timeout(Some(std::time::Duration::from_secs(600)))
        .run()?;
    // --preview implies --unchanged-exit-77: 77 means "no updates".
    if out.code != 0 && out.code != 77 {
        return Err(CollectError::Other(anyhow::anyhow!(
            "rpm-ostree upgrade --preview: {}",
            out.stderr.trim()
        )));
    }
    cache::store(cache::OSTREE_CHECK, &serde_json::json!({}))?;
    crate::collectors::ostree::collect()
}

pub fn check_flatpak()
-> Result<cache::Cached<Vec<crate::collectors::flatpak::FpUpdate>>, CollectError> {
    let u = crate::collectors::flatpak::collect_updates()?;
    let at = cache::store(cache::FLATPAK_UPDATES, &u)?;
    Ok(cache::Cached {
        fetched_at: at,
        data: u,
    })
}

/// Read-only, so no confirm. Prints progress, then the report path and summaries.
fn audit(o: Opts, ctx: &Ctx, out: &mut dyn Write) -> anyhow::Result<Option<String>> {
    use crate::audit;
    if o.dry_run {
        writeln!(
            out,
            "would collect: gpu ostree flatpak podman listeners units repos shell journal cache"
        )?;
        writeln!(
            out,
            "would write: {}/<date>.json + .md",
            audit::store::dir().display()
        )?;
        return Ok(None);
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
        writeln!(
            out,
            "  {:<6} {:<10} {}",
            f.severity.as_str(),
            f.category,
            f.message
        )?;
    }
    match &prev {
        Some(p) => {
            let d = audit::diff::diff(&p.report, &r);
            writeln!(out, "diff vs {}: {}", p.name(), audit::diff::summary(&d))?;
        }
        None => writeln!(out, "first report: no diff")?,
    }
    Ok(Some(counts))
}
