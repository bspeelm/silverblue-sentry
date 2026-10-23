//! The workflow state machine. Pure apart from the `Env` it's given, so the gating, `when`
//! freezing, failure handling and reboot detection are unit-tested without a system.

use super::state::{RunState, RunStatus, StepState, StepStatus};
use super::template;
use super::{Gate, Kind, OnFail, Workflow};

/// What the runner needs from the outside world.
pub trait Env {
    /// Evaluate a `when` condition (`kernel_changed`).
    fn cond(&self, name: &str) -> Result<bool, String>;
    /// Resolve a built-in variable (`pending_kernel`).
    fn builtin(&self, name: &str) -> Result<String, String>;
    fn boot_id(&self) -> String;
}

/// Built-ins that always reflect the current boot instead of being frozen.
const LIVE: &[&str] = &["booted_kernel", "home"];

#[derive(Debug, Clone, PartialEq)]
pub enum Next {
    Done,
    /// Auto gate: run without asking.
    Run(usize),
    /// Confirm gate: show the card, run on Enter.
    Confirm(usize),
    /// `requested`: the reboot was asked for, but the boot id hasn't changed.
    Reboot {
        idx: usize,
        requested: bool,
    },
    Shell(usize),
    /// Instructions + "done"; `failed` when it's an `on_fail = "manual"` fallback.
    Manual {
        idx: usize,
        failed: bool,
    },
    /// Failed with `on_fail = "stop"`: retry, skip (optional) or abandon.
    Stopped(usize),
}

impl Next {
    pub fn idx(&self) -> Option<usize> {
        match *self {
            Next::Done => None,
            Next::Run(i) | Next::Confirm(i) | Next::Shell(i) | Next::Stopped(i) => Some(i),
            Next::Reboot { idx, .. } | Next::Manual { idx, .. } => Some(idx),
        }
    }
}

fn now() -> jiff::Timestamp {
    jiff::Timestamp::now()
}

fn eval_cond(st: &mut RunState, env: &dyn Env, name: &str) -> Result<bool, String> {
    if let Some(v) = st.conds.get(name) {
        return Ok(*v);
    }
    let v = env.cond(name)?;
    st.conds.insert(name.to_string(), v);
    Ok(v)
}

/// After loading a run from disk: commands that were running when sentry exited didn't
/// finish, so they count as failed (and get their on_fail treatment).
pub fn recover(st: &mut RunState, wf: &Workflow) {
    for (s, step) in st.steps.iter_mut().zip(&wf.steps) {
        if s.status == StepStatus::Running && step.kind != Kind::Reboot {
            s.status = StepStatus::Failed;
            s.note = Some("interrupted: sentry exited while it ran".into());
        }
    }
}

/// Move past finished/skipped steps and decide what happens next.
pub fn advance(wf: &Workflow, st: &mut RunState, env: &dyn Env) -> Result<Next, String> {
    if st.status != RunStatus::InProgress {
        return Ok(Next::Done);
    }
    for idx in 0..wf.steps.len() {
        let step = &wf.steps[idx];
        let s = &st.steps[idx];
        match s.status {
            StepStatus::Ok | StepStatus::Skipped => continue,
            StepStatus::Failed => match step.on_fail {
                OnFail::Continue => continue,
                OnFail::Stop => return Ok(Next::Stopped(idx)),
                OnFail::Manual => return Ok(Next::Manual { idx, failed: true }),
            },
            StepStatus::Running => {
                // Only reboot steps survive a restart as Running (see `recover`).
                if step.kind == Kind::Reboot {
                    if s.boot_id.as_deref().is_some_and(|b| b != env.boot_id()) {
                        let s = &mut st.steps[idx];
                        s.status = StepStatus::Ok;
                        s.ended = Some(now());
                        s.note = Some("reboot observed (boot id changed)".into());
                        continue;
                    }
                    return Ok(Next::Reboot {
                        idx,
                        requested: true,
                    });
                }
                return Ok(Next::Run(idx));
            }
            StepStatus::Pending => {}
        }
        if step.rollback {
            skip(st, idx, "rollback step: only offered from abandon");
            continue;
        }
        if let Some((neg, name)) = step.cond() {
            let v = eval_cond(st, env, name)?;
            if v == neg {
                let note = format!("when {}{name} is false", if neg { "!" } else { "" });
                skip(st, idx, &note);
                continue;
            }
        }
        return Ok(match (step.kind, step.gate()) {
            (Kind::Reboot, _) => Next::Reboot {
                idx,
                requested: false,
            },
            (Kind::Shell, _) => Next::Shell(idx),
            (Kind::Manual, _) | (Kind::Run, Gate::Manual) => Next::Manual { idx, failed: false },
            (Kind::Run, Gate::Auto) => Next::Run(idx),
            (Kind::Run, Gate::Confirm) => Next::Confirm(idx),
        });
    }
    st.status = RunStatus::Done;
    st.ended = Some(now());
    Ok(Next::Done)
}

fn set(st: &mut RunState, idx: usize, f: impl FnOnce(&mut StepState)) {
    if let Some(s) = st.steps.get_mut(idx) {
        f(s);
    }
}

pub fn skip(st: &mut RunState, idx: usize, note: &str) {
    set(st, idx, |s| {
        s.status = StepStatus::Skipped;
        s.ended = Some(now());
        s.note = Some(note.into());
    });
}

pub fn start(st: &mut RunState, idx: usize, boot_id: String) {
    set(st, idx, |s| {
        s.status = StepStatus::Running;
        s.started = Some(now());
        s.ended = None;
        s.code = None;
        s.note = None;
        s.boot_id = Some(boot_id);
    });
}

pub fn finish(st: &mut RunState, idx: usize, code: i32, note: Option<String>) {
    set(st, idx, |s| {
        s.status = if code == 0 {
            StepStatus::Ok
        } else {
            StepStatus::Failed
        };
        s.code = Some(code);
        s.ended = Some(now());
        s.note = note;
    });
}

/// Manual card confirmed, shell exited, or a failed step accepted by hand.
pub fn mark_done(st: &mut RunState, idx: usize, note: &str) {
    set(st, idx, |s| {
        s.status = StepStatus::Ok;
        s.ended = Some(now());
        s.note = Some(note.into());
    });
}

/// Reset a failed (or interrupted) step so it runs again.
pub fn retry(st: &mut RunState, idx: usize) {
    set(st, idx, |s| {
        s.status = StepStatus::Pending;
        s.code = None;
        s.note = None;
        s.dry_ok = false;
    });
}

/// Reboot confirmed: remember the boot id, then the caller runs `systemctl reboot`.
pub fn request_reboot(wf: &Workflow, st: &mut RunState, idx: usize, env: &dyn Env) {
    freeze_all(wf, st, env);
    start(st, idx, env.boot_id());
}

pub fn abandon(st: &mut RunState) {
    st.status = RunStatus::Abandoned;
    st.ended = Some(now());
}

/// Resolve a variable for rendering, freezing built-ins on first use.
fn lookup(st: &mut RunState, env: &dyn Env, name: &str) -> Result<String, String> {
    if let Some(v) = st.vars.get(name) {
        return Ok(v.clone());
    }
    if !super::BUILTINS.contains(&name) {
        return Err(format!("undefined variable `{name}`"));
    }
    let v = env.builtin(name)?;
    if !LIVE.contains(&name) {
        st.vars.insert(name.to_string(), v.clone());
    }
    Ok(v)
}

/// Render text for execution (freezes the built-ins it uses).
pub fn render(st: &mut RunState, env: &dyn Env, text: &str) -> Result<String, String> {
    let ids = template::idents(text)?;
    let mut vals = std::collections::BTreeMap::new();
    for id in ids {
        vals.insert(id.clone(), lookup(st, env, &id)?);
    }
    template::render(text, &|k| vals.get(k).cloned())
}

/// Render for display only: unresolved names show as `‹name›`, nothing is frozen.
pub fn preview(st: &RunState, text: &str) -> String {
    template::render(text, &|k| {
        Some(st.vars.get(k).cloned().unwrap_or_else(|| format!("‹{k}›")))
    })
    .unwrap_or_else(|_| text.to_string())
}

/// Built-ins describe the pre-reboot world (`pending_kernel`, `old_kmod`): freeze every one
/// the workflow mentions before the first reboot, so post-reboot steps see the planned values.
pub fn freeze_all(wf: &Workflow, st: &mut RunState, env: &dyn Env) {
    for s in &wf.steps {
        for text in [Some(&s.title), s.run.as_ref(), s.manual.as_ref()]
            .into_iter()
            .flatten()
        {
            for id in template::idents(text).unwrap_or_default() {
                if super::BUILTINS.contains(&id.as_str()) && !LIVE.contains(&id.as_str()) {
                    let _ = lookup(st, env, &id);
                }
            }
        }
    }
}

/// Shell script for a `run` step: `sentry` resolves to this binary, output is tee'd to the log,
/// and pipefail keeps the command's exit status.
pub fn script(cmd: &str, exe: &str, run_dir: &str, log: &str) -> String {
    format!(
        "set -o pipefail\nexport SENTRY_WORKFLOW_RUN={}\nsentry() {{ {} \"$@\"; }}\n( {cmd}\n) 2>&1 | tee -a {}",
        quote(run_dir),
        quote(exe),
        quote(log)
    )
}

pub fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// `sudo` needs a terminal for its password prompt: such steps run with the TUI suspended.
/// `sudo` inside a container (`toolbox run … sudo dnf`) is passwordless and doesn't count.
pub fn needs_tty(cmd: &str) -> bool {
    cmd.split([';', '&', '|', '\n']).any(|seg| {
        let words: Vec<&str> = seg
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .collect();
        let in_ctr = seg.contains("toolbox run")
            || seg.contains("distrobox enter")
            || seg.contains("podman exec");
        words.contains(&"sudo") && !in_ctr
    })
}

/// Why a terminal-needing step can't run here: inside a toolbox, `flatpak-spawn --host`
/// gives the host process no controlling terminal, so sudo can't ask for a password.
pub fn tty_blocker() -> Option<&'static str> {
    crate::exec::spawn_mode().then_some(
        "this step runs sudo, which needs a host terminal: sentry is running inside a toolbox. \
         Quit and run `sentry` (or `sentry workflow <name>`) from a host terminal; state is saved.",
    )
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    use super::*;
    use crate::workflows::{SEEDS, parse};

    struct Fake {
        kernel_changed: bool,
        boot: RefCell<String>,
        cond_calls: Cell<usize>,
    }

    impl Env for Fake {
        fn cond(&self, name: &str) -> Result<bool, String> {
            self.cond_calls.set(self.cond_calls.get() + 1);
            match name {
                "kernel_changed" => Ok(self.kernel_changed),
                "master_repo_present" => Ok(false),
                n => Err(format!("unknown {n}")),
            }
        }
        fn builtin(&self, name: &str) -> Result<String, String> {
            Ok(match name {
                "pending_kernel" => "7.2.11-200.fc44.x86_64".into(),
                "old_kmod" => "kmod-nvidia-7.2.8-200.fc44.x86_64-3:615.71.09-3.fc44.x86_64".into(),
                "current_version" => "44".into(),
                "booted_kernel" => "7.2.8-200.fc44.x86_64".into(),
                "home" => "/var/home/user".into(),
                "booted_version" => "44.20261002.0".into(),
                "rpmfusion_uninstall" => "--uninstall rpmfusion-free-release-44-3.noarch --uninstall rpmfusion-nonfree-release-44-3.noarch".into(),
                n => return Err(format!("no {n}")),
            })
        }
        fn boot_id(&self) -> String {
            self.boot.borrow().clone()
        }
    }

    fn quick(kernel_changed: bool) -> (Workflow, RunState, Fake) {
        let wf = parse(SEEDS[0].1).unwrap();
        let ids: Vec<String> = wf.steps.iter().map(|s| s.id.clone()).collect();
        let st = RunState::new("quick-update", &ids, BTreeMap::new());
        let env = Fake {
            kernel_changed,
            boot: RefCell::new("boot-a".into()),
            cond_calls: Cell::new(0),
        };
        (wf, st, env)
    }

    fn id(wf: &Workflow, n: &Next) -> String {
        n.idx().map_or("done".into(), |i| wf.steps[i].id.clone())
    }

    /// Drive the workflow: every run step succeeds, every gate is confirmed, reboots happen.
    fn drive(wf: &Workflow, st: &mut RunState, env: &Fake) -> Vec<String> {
        let mut seen = Vec::new();
        for _ in 0..100 {
            let n = advance(wf, st, env).unwrap();
            seen.push(format!(
                "{}:{}",
                id(wf, &n),
                match &n {
                    Next::Run(_) => "run",
                    Next::Confirm(_) => "confirm",
                    Next::Reboot { .. } => "reboot",
                    Next::Manual { .. } => "manual",
                    Next::Shell(_) => "shell",
                    Next::Stopped(_) => "stopped",
                    Next::Done => "",
                }
            ));
            match n {
                Next::Done => break,
                Next::Run(i) | Next::Confirm(i) => {
                    let cmd = render(st, env, wf.steps[i].run.as_ref().unwrap()).unwrap();
                    assert!(!cmd.contains("{{ "), "{cmd}");
                    start(st, i, env.boot_id());
                    finish(st, i, 0, None);
                }
                Next::Reboot { idx, requested } => {
                    assert!(!requested);
                    request_reboot(wf, st, idx, env);
                    *env.boot.borrow_mut() = format!("boot-{idx}");
                }
                Next::Manual { idx, .. } | Next::Shell(idx) => mark_done(st, idx, "ok"),
                Next::Stopped(_) => panic!("stopped"),
            }
        }
        seen
    }

    #[test]
    fn routine_path_skips_the_ritual() {
        let (wf, mut st, env) = quick(false);
        let seen = drive(&wf, &mut st, &env);
        assert_eq!(
            seen,
            vec![
                "preview:run",
                "flatpak-idle:run",
                "flatpak:confirm",
                "toolboxes:confirm",
                "upgrade-routine:confirm",
                "reboot-routine:reboot",
                "flatpak-gl:run",
                "done:"
            ]
        );
        assert_eq!(st.status, RunStatus::Done);
        assert_eq!(
            env.cond_calls.get(),
            2,
            "kernel_changed frozen after one evaluation"
        );
    }

    #[test]
    fn kernel_path_runs_the_ritual_with_frozen_values() {
        let (wf, mut st, env) = quick(true);
        let seen = drive(&wf, &mut st, &env);
        let ids: Vec<&str> = seen.iter().map(|s| s.split(':').next().unwrap()).collect();
        assert_eq!(
            ids,
            vec![
                "preview",
                "flatpak-idle",
                "flatpak",
                "toolboxes",
                "kmod-guard",
                "upgrade-ritual",
                "reboot-1",
                "verify-kernel",
                "akmods",
                "kmod-built",
                "layer-kmod",
                "reboot-2",
                "verify",
                "flatpak-gl",
                "done"
            ]
        );
        assert_eq!(st.vars["pending_kernel"], "7.2.11-200.fc44.x86_64");
        assert!(st.vars["old_kmod"].starts_with("kmod-nvidia-7.2.8"));
        assert!(
            !st.vars.contains_key("booted_kernel"),
            "live built-ins aren't frozen"
        );
    }

    #[test]
    fn reboot_detection_and_failure_modes() {
        let (wf, mut st, env) = quick(false);
        // Get to the routine reboot.
        loop {
            match advance(&wf, &mut st, &env).unwrap() {
                Next::Reboot { idx, .. } => {
                    request_reboot(&wf, &mut st, idx, &env);
                    break;
                }
                Next::Run(i) | Next::Confirm(i) => finish(&mut st, i, 0, None),
                n => panic!("{n:?}"),
            }
        }
        // Same boot id: the reboot never happened → ask again.
        assert!(matches!(
            advance(&wf, &mut st, &env).unwrap(),
            Next::Reboot {
                requested: true,
                ..
            }
        ));
        *env.boot.borrow_mut() = "boot-b".into();
        let n = advance(&wf, &mut st, &env).unwrap();
        assert_eq!(id(&wf, &n), "flatpak-gl");
        // flatpak-gl is on_fail = manual.
        let i = n.idx().unwrap();
        finish(&mut st, i, 1, None);
        assert_eq!(
            advance(&wf, &mut st, &env).unwrap(),
            Next::Manual {
                idx: i,
                failed: true
            }
        );
        retry(&mut st, i);
        assert_eq!(advance(&wf, &mut st, &env).unwrap(), Next::Run(i));
        // An interrupted run (sentry killed mid-step) becomes a failure.
        start(&mut st, i, "boot-b".into());
        recover(&mut st, &wf);
        assert_eq!(st.steps[i].status, StepStatus::Failed);
    }

    #[test]
    fn release_rebase_sequence_and_frozen_pin() {
        let wf = parse(SEEDS[1].1).unwrap();
        let ids: Vec<String> = wf.steps.iter().map(|s| s.id.clone()).collect();
        let mut vars = BTreeMap::new();
        vars.insert("target".to_string(), "45".to_string());
        let mut st = RunState::new("release-rebase", &ids, vars);
        let env = Fake {
            kernel_changed: false,
            boot: RefCell::new("boot-a".into()),
            cond_calls: Cell::new(0),
        };
        let seen = drive(&wf, &mut st, &env);
        let order: Vec<&str> = seen.iter().map(|s| s.split(':').next().unwrap()).collect();
        assert_eq!(
            order,
            vec![
                "preflight",
                "repos-ready",
                "rpmfusion-tracked",
                "target-ref",
                "kmod-guard",
                "snapshot",
                "pin-current",
                "pin-verify",
                "rebase",
                "reboot-1",
                "verify-boot",
                "akmods",
                "kmod-built",
                "layer-kmod",
                "reboot-2",
                "final-verify",
                "flatpak-idle",
                "flatpak-gl",
                "toolbox-lists",
                "toolbox-upgrade",
                "post-snapshot",
                "cleanup",
                "unpin-old",
                "done"
            ],
            "rollback only runs from abandon"
        );
        assert_eq!(
            st.vars["booted_version"], "44.20261002.0",
            "frozen before the reboots"
        );
        let rb = ids.iter().position(|i| i == "rollback").unwrap();
        assert_eq!(st.steps[rb].status, StepStatus::Skipped);
        let cmd = render(&mut st, &env, wf.steps[rb].run.as_ref().unwrap()).unwrap();
        assert!(
            cmd.contains("v='44.20261002.0'") && cmd.contains("set-default"),
            "{cmd}"
        );
    }

    #[test]
    fn scripts() {
        let s = script(
            "echo hi && sentry check kargs",
            "/x/sentry",
            "/r/run-1",
            "/r/run-1/steps/a.log",
        );
        assert!(s.starts_with("set -o pipefail\n"));
        assert!(s.contains("sentry() { '/x/sentry' \"$@\"; }"));
        assert!(
            s.ends_with("( echo hi && sentry check kargs\n) 2>&1 | tee -a '/r/run-1/steps/a.log'")
        );
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert!(needs_tty("ls x || sudo akmods --force"));
        assert!(!needs_tty("echo pseudo-sudoku"));
        assert!(!needs_tty(
            "for c in a b; do toolbox run -c \"$c\" sudo dnf -y upgrade; done"
        ));
        assert!(needs_tty(
            "toolbox list\nsudo rm /etc/yum.repos.d/updates-master.repo"
        ));
    }
}
