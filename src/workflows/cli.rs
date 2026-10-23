//! `sentry workflow …` (headless) and the real `Env`. The TUI drives the same runner.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};

use super::runner::{self, Env, Next};
use super::state::{Run, RunState, RunStatus};
use super::{Entry, Workflow};
use crate::checks;
use crate::collectors::ostree;
use crate::exec::Cmd;

/// Conditions and built-ins from the live system.
pub struct RealEnv;

impl Env for RealEnv {
    fn cond(&self, name: &str) -> Result<bool, String> {
        let check = checks::cond_check(name).ok_or_else(|| format!("unknown condition {name}"))?;
        checks::run(check, &[]).map(|o| o.ok)
    }

    fn builtin(&self, name: &str) -> Result<String, String> {
        match name {
            "current_version" => Ok(checks::version_id()),
            "booted_kernel" => Ok(ostree::booted_kernel()),
            "home" => Ok(crate::paths::home().display().to_string()),
            "pending_kernel" => ostree::collect()
                .map_err(|e| e.to_string())?
                .update
                .and_then(|u| u.pending_kernel())
                .ok_or_else(|| "no pending kernel update (run the preview step)".into()),
            "old_kmod" => {
                let o = ostree::collect().map_err(|e| e.to_string())?;
                match o.kmods().as_slice() {
                    [one] => Ok(one.to_string()),
                    k => Err(format!(
                        "{} layered kmod-nvidia packages, need exactly one",
                        k.len()
                    )),
                }
            }
            n => Err(format!("unknown built-in {n}")),
        }
    }

    fn boot_id(&self) -> String {
        checks::boot_id()
    }
}

pub fn exe() -> String {
    std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "sentry".into())
}

/// The command that executes a step (`bash -c` on the host, output tee'd to the step log).
pub fn step_cmd(run: &Run, id: &str, rendered: &str) -> Cmd {
    let log = run.log_path(id);
    Cmd::host("bash")
        .arg("-c")
        .arg(runner::script(
            rendered,
            &exe(),
            &run.dir.display().to_string(),
            &log.display().to_string(),
        ))
        .timeout(None)
}

pub fn reboot_cmd() -> Cmd {
    // SENTRY_NO_REBOOT=1 (tests, demos): show what would happen instead of rebooting.
    if std::env::var_os("SENTRY_NO_REBOOT").is_some() {
        Cmd::local("sh")
            .args([
                "-c",
                "echo 'SENTRY_NO_REBOOT set: not rebooting (systemctl reboot)'",
            ])
            .timeout(None)
    } else {
        Cmd::host("systemctl").arg("reboot").timeout(None)
    }
}

/// Initial vars: defaults rendered against built-ins, then `--var k=v` overrides.
pub fn initial_vars(
    wf: &Workflow,
    env: &dyn Env,
    overrides: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    let mut scratch = RunState::new(&wf.name, &[], BTreeMap::new());
    let mut vars = BTreeMap::new();
    for (k, spec) in &wf.vars {
        let v = match (overrides.get(k), &spec.default) {
            (Some(v), _) => v.clone(),
            (None, Some(d)) => runner::render(&mut scratch, env, d)?,
            (None, None) => return Err(format!("var {k}: no default; pass --var {k}=…")),
        };
        vars.insert(k.clone(), v);
    }
    // Built-ins resolved while rendering defaults are frozen into the run too.
    vars.extend(scratch.vars);
    Ok(vars)
}

/// Start a run of `entry` (refuses drafts, lint errors and a second run in progress).
pub fn start(entry: &Entry, vars: BTreeMap<String, String>) -> anyhow::Result<Run> {
    if let Some(why) = entry.blocked() {
        anyhow::bail!("{}: {why}", entry.name);
    }
    if let Some(r) = super::state::in_progress() {
        anyhow::bail!(
            "{} is already in progress ({}); finish or abandon it first",
            r.state.workflow,
            r.dir.display()
        );
    }
    let wf = entry.wf.as_ref().map_err(|e| anyhow::anyhow!("{e}"))?;
    let text = std::fs::read_to_string(&entry.path)?;
    let ids: Vec<String> = wf.steps.iter().map(|s| s.id.clone()).collect();
    Run::create(&entry.name, &text, RunState::new(&entry.name, &ids, vars))
}

/// Load a run with its frozen workflow copy, after crash recovery.
pub fn open(run: Run) -> anyhow::Result<(Workflow, Run)> {
    let mut run = run;
    let wf = super::parse(&run.workflow_text()?).map_err(|e| anyhow::anyhow!(e))?;
    runner::recover(&mut run.state, &wf);
    Ok((wf, run))
}

fn ask(prompt: &str) -> String {
    print!("{prompt} ");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    s.trim().to_lowercase()
}

/// `sentry workflow <name>|lint <name>|abandon [--var k=v]`. Returns the exit code.
pub fn run_cli(name: &str, args: &[String]) -> u8 {
    match name {
        "lint" => lint_cli(args.first().map(String::as_str)),
        "list" => {
            for e in super::list() {
                let steps = e.wf.as_ref().map_or(0, |w| w.steps.len());
                let state = e.blocked().unwrap_or_else(|| "ok".into());
                println!("{:<16} {steps:>2} steps  {state}", e.name);
            }
            0
        }
        "abandon" => match super::state::in_progress() {
            Some(mut r) => {
                runner::abandon(&mut r.state);
                match r.save() {
                    Ok(()) => {
                        println!("abandoned {} ({})", r.state.workflow, r.dir.display());
                        0
                    }
                    Err(e) => {
                        eprintln!("sentry workflow abandon: {e}");
                        1
                    }
                }
            }
            None => {
                println!("no workflow in progress");
                0
            }
        },
        _ => match drive(name, args) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("sentry workflow {name}: {e:#}");
                1
            }
        },
    }
}

fn lint_cli(name: Option<&str>) -> u8 {
    let entries: Vec<Entry> = match name {
        Some(n) => match super::find(n) {
            Some(e) => vec![e],
            None => {
                eprintln!("no workflow {n:?} in {}", super::dir().display());
                return 2;
            }
        },
        None => super::list(),
    };
    let mut bad = false;
    for e in entries {
        match &e.wf {
            Err(err) => {
                bad = true;
                println!("✗ {}: {err}", e.name);
            }
            Ok(w) => {
                let errs = e.errors().count();
                bad |= errs > 0;
                println!(
                    "{} {} · {} steps{}",
                    if errs > 0 { "✗" } else { "✓" },
                    e.name,
                    w.steps.len(),
                    if w.draft { " · draft" } else { "" }
                );
                for i in &e.issues {
                    println!(
                        "  {} {}",
                        if i.error { "error:" } else { "warning:" },
                        i.msg
                    );
                }
            }
        }
    }
    if bad { 1 } else { 0 }
}

fn parse_vars(args: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut m = BTreeMap::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let kv = match a.strip_prefix("--var=") {
            Some(kv) => kv.to_string(),
            None if a == "--var" => it
                .next()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("--var needs k=v"))?,
            None => anyhow::bail!("unexpected argument {a:?} (use --var k=v)"),
        };
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--var {kv:?}: expected k=v"))?;
        m.insert(k.to_string(), v.to_string());
    }
    Ok(m)
}

/// Headless driver: same runner, prompts on this terminal.
fn drive(name: &str, args: &[String]) -> anyhow::Result<u8> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("needs a terminal for its confirmations");
    }
    let env = RealEnv;
    let run = match super::state::in_progress() {
        Some(r) if r.state.workflow == name => {
            println!("↻ continuing {} ({})", name, r.dir.display());
            r
        }
        Some(r) => anyhow::bail!(
            "{} is in progress; finish or abandon it first",
            r.state.workflow
        ),
        None => {
            let entry = super::find(name).ok_or_else(|| {
                anyhow::anyhow!("no workflow {name:?} in {}", super::dir().display())
            })?;
            let wf = entry.wf.as_ref().map_err(|e| anyhow::anyhow!("{e}"))?;
            let vars =
                initial_vars(wf, &env, &parse_vars(args)?).map_err(|e| anyhow::anyhow!(e))?;
            for (k, spec) in &wf.vars {
                println!("{} = {}", spec.prompt, vars[k]);
            }
            let r = start(&entry, vars)?;
            println!("▶ {name} · run dir {}", r.dir.display());
            r
        }
    };
    let (wf, mut run) = open(run)?;
    let total = wf.steps.len();
    loop {
        let next = runner::advance(&wf, &mut run.state, &env).map_err(|e| anyhow::anyhow!(e))?;
        run.save()?;
        let Some(i) = next.idx() else {
            println!("✓ {name} complete");
            return Ok(0);
        };
        let step = &wf.steps[i];
        let title = runner::preview(&run.state, &step.title);
        println!("\n{}/{total} {title}  [{}]", i + 1, step.tag());
        match next {
            Next::Done => unreachable!(),
            Next::Run(_) | Next::Confirm(_) => {
                let cmd = runner::render(&mut run.state, &env, step.run.as_deref().unwrap_or(""))
                    .map_err(|e| anyhow::anyhow!(e))?;
                println!("$ {cmd}");
                if matches!(next, Next::Confirm(_)) {
                    match ask(&format!(
                        "[y] run  {}[a] abandon  [q] quit (keeps state) >",
                        if step.optional { "[s] skip  " } else { "" }
                    ))
                    .as_str()
                    {
                        "y" | "yes" => {}
                        "s" if step.optional => {
                            runner::skip(&mut run.state, i, "skipped by user");
                            continue;
                        }
                        "a" => {
                            runner::abandon(&mut run.state);
                            run.save()?;
                            println!("abandoned");
                            return Ok(1);
                        }
                        _ => {
                            run.save()?;
                            println!(
                                "state saved; run `sentry workflow {name}` or `sentry` to continue"
                            );
                            return Ok(0);
                        }
                    }
                }
                if runner::needs_tty(&cmd)
                    && let Some(why) = runner::tty_blocker()
                {
                    anyhow::bail!("{why}");
                }
                runner::start(&mut run.state, i, env.boot_id());
                run.save()?;
                let st = step_cmd(&run, &step.id, &cmd).interactive()?;
                let code = st.code().unwrap_or(-1);
                runner::finish(&mut run.state, i, code, None);
                run.save()?;
                println!("{} exit {code}", if code == 0 { "✓" } else { "✗" });
            }
            Next::Reboot { idx, requested } => {
                if requested {
                    println!("The reboot was requested but this is still the same boot.");
                }
                println!("State saved — run `sentry` after login to continue.");
                match ask("[y] reboot now  [d] mark done (already rebooted)  [q] quit >").as_str() {
                    "y" | "yes" => {
                        runner::request_reboot(&wf, &mut run.state, idx, &env);
                        run.save()?;
                        reboot_cmd().interactive()?;
                        return Ok(0);
                    }
                    "d" => runner::mark_done(&mut run.state, idx, "marked done by user"),
                    _ => return Ok(0),
                }
            }
            Next::Shell(idx) => {
                let sh = std::env::var("SHELL").unwrap_or_else(|_| "bash".into());
                println!("opening {sh}; exit it to continue the workflow");
                Cmd::local(&sh).timeout(None).interactive()?;
                runner::mark_done(&mut run.state, idx, "shell exited");
            }
            Next::Stopped(idx) | Next::Manual { idx, failed: true } => {
                let stopped = matches!(next, Next::Stopped(_));
                println!(
                    "✗ failed (exit {}) — see {}",
                    run.state.steps[idx]
                        .code
                        .map_or("?".into(), |c| c.to_string()),
                    run.log_path(&step.id).display()
                );
                if let Some(m) = &step.manual {
                    println!("{}", runner::preview(&run.state, m));
                }
                let prompt = if stopped {
                    "[r] retry  [a] abandon  [q] quit >"
                } else {
                    "[d] done by hand  [r] retry  [a] abandon  [q] quit >"
                };
                match ask(prompt).as_str() {
                    "d" if !stopped => runner::mark_done(&mut run.state, idx, "done by hand"),
                    "r" => runner::retry(&mut run.state, idx),
                    "a" => {
                        runner::abandon(&mut run.state);
                        run.save()?;
                        return Ok(1);
                    }
                    _ => return Ok(1),
                }
            }
            Next::Manual { idx, failed: false } => {
                if let Some(m) = &step.manual {
                    println!("{}", runner::preview(&run.state, m));
                }
                match ask("[d] done  [q] quit >").as_str() {
                    "d" => runner::mark_done(&mut run.state, idx, "done by hand"),
                    _ => return Ok(0),
                }
            }
        }
        run.save()?;
        if run.state.status != RunStatus::InProgress {
            return Ok(0);
        }
    }
}
