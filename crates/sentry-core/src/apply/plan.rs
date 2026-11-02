//! Applying something with Claude: Claude writes one plan (a ```` ```sentry-apply ```` TOML
//! block: file edits as exact old → new text, commands, checks, a workflow to start), the user
//! approves it once, and sentry carries it out in order. Pure, except `apply_edit` (your own
//! files; root's are `sudo::prepare_root_edit`).

use serde::Deserialize;

const FENCE: &str = "```sentry-apply";

#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub summary: String,
    /// How to undo it, in words (never run).
    pub rollback: String,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub title: String,
    pub kind: Kind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    /// Replace `old` (found exactly once) with `new` in `file`.
    Edit {
        file: String,
        old: String,
        new: String,
    },
    /// A command that changes something (sudo: the terminal is handed over).
    Run(String),
    /// A command that must exit 0, or the plan stops.
    Check(String),
    /// A sentry workflow: started, and the plan waits for its run to end.
    Workflow(String),
}

impl Kind {
    pub fn word(&self) -> &'static str {
        match self {
            Kind::Edit { .. } => "edit",
            Kind::Run(_) => "run",
            Kind::Check(_) => "check",
            Kind::Workflow(_) => "workflow",
        }
    }

    /// The file, command or workflow it's about.
    pub fn target(&self) -> &str {
        match self {
            Kind::Edit { file, .. } => file,
            Kind::Run(c) | Kind::Check(c) => c,
            Kind::Workflow(w) => w,
        }
    }
}

#[derive(Deserialize)]
struct RawPlan {
    #[serde(default)]
    summary: String,
    #[serde(default)]
    rollback: String,
    #[serde(default)]
    step: Vec<RawStep>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStep {
    #[serde(default)]
    title: String,
    edit: Option<String>,
    old: Option<String>,
    new: Option<String>,
    run: Option<String>,
    check: Option<String>,
    workflow: Option<String>,
}

/// The answer without its plan block, and the plan (Err: the block is there but wrong, and
/// why, for Claude). None: no block.
pub fn take(answer: &str) -> (String, Option<Result<Plan, String>>) {
    let Some((body, block)) = crate::maint::fenced_block(answer, FENCE) else {
        return (answer.to_string(), None);
    };
    (body, Some(parse(&block)))
}

fn parse(block: &str) -> Result<Plan, String> {
    let raw: RawPlan = toml::from_str(block).map_err(|e| e.message().to_string())?;
    if raw.step.is_empty() {
        return Err("the plan has no steps".into());
    }
    let mut steps = Vec::new();
    for (i, s) in raw.step.into_iter().enumerate() {
        let n = i + 1;
        let kinds = [
            s.edit.is_some(),
            s.run.is_some(),
            s.check.is_some(),
            s.workflow.is_some(),
        ]
        .iter()
        .filter(|x| **x)
        .count();
        if kinds != 1 {
            return Err(format!(
                "step {n} needs exactly one of edit, run, check or workflow"
            ));
        }
        let kind = if let Some(file) = s.edit {
            match (s.old, s.new) {
                (Some(old), Some(new)) if !old.is_empty() => Kind::Edit { file, old, new },
                _ => return Err(format!("step {n} (edit) needs old and new text")),
            }
        } else if let Some(c) = s.run {
            Kind::Run(c)
        } else if let Some(c) = s.check {
            Kind::Check(c)
        } else {
            Kind::Workflow(s.workflow.unwrap_or_default())
        };
        steps.push(Step {
            title: if s.title.is_empty() {
                format!("step {n}")
            } else {
                s.title
            },
            kind,
        });
    }
    Ok(Plan {
        summary: raw.summary,
        rollback: raw.rollback,
        steps,
    })
}

/// What stops the plan from being approved: (step index, why).
pub fn problems(p: &Plan, workflows: &[String]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, s) in p.steps.iter().enumerate() {
        match &s.kind {
            Kind::Edit { file, old, .. } => {
                let owner = match super::sudo::edit_target(file) {
                    Ok(o) => o,
                    Err(why) => {
                        out.push((i, why));
                        continue;
                    }
                };
                match super::sudo::read(file, owner) {
                    Err(e) => out.push((i, format!("{file}: {e}"))),
                    Ok(t) => match t.matches(old.as_str()).count() {
                        1 => {}
                        0 => out.push((i, "its old text isn't in the file".into())),
                        n => out.push((i, format!("its old text is in the file {n} times"))),
                    },
                }
            }
            Kind::Workflow(w) if !workflows.iter().any(|x| x == w) => {
                out.push((i, format!("no workflow {w}")));
            }
            _ => {}
        }
    }
    out
}

/// An edit step, done: the file backed up, `old` replaced by `new` once. Returns the backup
/// and the line counts before and after. Read fresh: a file that changed since the plan was
/// written fails here rather than getting a wrong edit.
pub fn apply_edit(s: &Step) -> Result<(std::path::PathBuf, usize, usize), String> {
    let Kind::Edit { file, old, new } = &s.kind else {
        return Err("not an edit".into());
    };
    let text = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    if text.matches(old.as_str()).count() != 1 {
        return Err(format!(
            "{file}: its old text isn't there exactly once any more"
        ));
    }
    let backup = crate::claude::backup(file).map_err(|e| format!("backup: {e}"))?;
    let changed = text.replacen(old.as_str(), new, 1);
    crate::paths::write_atomic(std::path::Path::new(file), changed.as_bytes())
        .map_err(|e| format!("{file}: {e}"))?;
    Ok((backup, text.lines().count(), changed.lines().count()))
}

/// How a step went.
#[derive(Debug, Clone, PartialEq)]
pub struct StepResult {
    pub ok: bool,
    /// One line (edit: lines and backup; a command: its exit), then its output's tail.
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    /// Shown, waiting for the user's approval.
    Proposed,
    Running,
    /// The workflow of this step is running; the plan waits for it to end.
    WaitingWorkflow(usize),
    Done,
    Failed(usize),
}

/// What the app does next.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Edit(usize),
    Command { idx: usize, cmd: String },
    StartWorkflow(usize, String),
    Finished,
}

/// A plan being carried out.
#[derive(Debug, Clone, PartialEq)]
pub struct Run {
    pub plan: Plan,
    pub results: Vec<StepResult>,
    pub state: RunState,
}

impl Run {
    pub fn new(plan: Plan) -> Self {
        Self {
            plan,
            results: Vec::new(),
            state: RunState::Proposed,
        }
    }

    /// The step under way (or next).
    pub fn current(&self) -> usize {
        self.results.len()
    }

    fn action(&mut self) -> Action {
        let i = self.current();
        let Some(s) = self.plan.steps.get(i) else {
            self.state = RunState::Done;
            return Action::Finished;
        };
        match &s.kind {
            Kind::Edit { .. } => Action::Edit(i),
            Kind::Run(c) | Kind::Check(c) => Action::Command {
                idx: i,
                cmd: c.clone(),
            },
            Kind::Workflow(w) => {
                self.state = RunState::WaitingWorkflow(i);
                Action::StartWorkflow(i, w.clone())
            }
        }
    }

    /// Approved: the first step.
    pub fn start(&mut self) -> Action {
        self.state = RunState::Running;
        self.action()
    }

    /// The current step ended: the next one, or Finished (done, or stopped at a failure).
    pub fn step_done(&mut self, ok: bool, note: String) -> Action {
        let i = self.current();
        self.results.push(StepResult { ok, note });
        if !ok {
            self.state = RunState::Failed(i);
            return Action::Finished;
        }
        self.state = RunState::Running;
        self.action()
    }

    pub fn finished(&self) -> bool {
        matches!(self.state, RunState::Done | RunState::Failed(_))
    }

    /// What Claude is told when the run ends: every step's result, and on a failure what's
    /// left to plan.
    pub fn report(&self) -> String {
        let lines: Vec<String> = self
            .results
            .iter()
            .zip(&self.plan.steps)
            .enumerate()
            .map(|(i, (r, s))| {
                format!(
                    "{}. {} {} ({} {}): {}",
                    i + 1,
                    if r.ok { "✓" } else { "✗" },
                    s.title,
                    s.kind.word(),
                    s.kind.target(),
                    r.note
                )
            })
            .collect();
        match self.state {
            RunState::Failed(k) => format!(
                "sentry carried out the plan and stopped at step {} ({}), which failed:\n{}\n\n\
                 Steps 1–{} are done.",
                k + 1,
                self.plan.steps[k].title,
                lines.join("\n"),
                k
            ),
            _ => format!(
                "sentry carried out all {} steps of the plan:\n{}",
                self.plan.steps.len(),
                lines.join("\n")
            ),
        }
    }
}

/// The tail of a command's output, for a step's note.
pub fn tail(output: &str, n: usize) -> String {
    let t: Vec<&str> = output.lines().rev().take(n).collect();
    t.into_iter().rev().collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANSWER: &str = "The plan still fits.\n\n```sentry-apply\nsummary = \"fix it\"\n\
rollback = \"sentry restores the backup\"\n\n[[step]]\ntitle = \"Line 5\"\nedit = \"/tmp/x.md\"\n\
old = \"\"\"old line\"\"\"\nnew = \"\"\"new line\nwith a fence:\n```\nok\n```\"\"\"\n\n\
[[step]]\ntitle = \"Check\"\ncheck = \"grep -q new /tmp/x.md\"\n\n[[step]]\nworkflow = \"quick-update\"\n```\n\
Approve it and sentry does it.";

    #[test]
    fn the_plan_is_taken_out_of_the_answer() {
        let (body, plan) = take(ANSWER);
        assert_eq!(
            body,
            "The plan still fits.\n\nApprove it and sentry does it."
        );
        let p = plan.unwrap().unwrap();
        assert_eq!(p.steps.len(), 3);
        assert!(matches!(&p.steps[0].kind, Kind::Edit { new, .. } if new.contains("```\nok")));
        assert_eq!(p.steps[1].kind, Kind::Check("grep -q new /tmp/x.md".into()));
        assert_eq!(p.steps[2].title, "step 3");
        assert!(take("no plan here").1.is_none());
        let bad = take("```sentry-apply\n[[step]]\nrun = \"a\"\ncheck = \"b\"\n```").1;
        assert!(bad.unwrap().unwrap_err().contains("exactly one"));
    }

    #[test]
    fn what_stops_approval() {
        let dir = crate::paths::home().join(".cache/sentry-applyplan-test");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join(format!("plan-{}.md", std::process::id()));
        std::fs::write(&f, "a\nb\nb\n").unwrap();
        let file = f.display().to_string();
        let edit = |old: &str| Step {
            title: "e".into(),
            kind: Kind::Edit {
                file: file.clone(),
                old: old.into(),
                new: "c".into(),
            },
        };
        let p = Plan {
            summary: String::new(),
            rollback: String::new(),
            steps: vec![
                edit("a"),
                edit("zz"),
                edit("b"),
                Step {
                    title: "w".into(),
                    kind: Kind::Workflow("nope".into()),
                },
                Step {
                    title: "e".into(),
                    kind: Kind::Edit {
                        file: "/etc/hosts".into(),
                        old: "x".into(),
                        new: "y".into(),
                    },
                },
            ],
        };
        let pr = problems(&p, &["quick-update".into()]);
        let idx: Vec<usize> = pr.iter().map(|(i, _)| *i).collect();
        assert_eq!(idx, [1, 2, 3, 4], "{pr:?}");
        assert!(pr[1].1.contains("2 times"));
        // The edit: backed up, replaced once; then refused, the text being gone.
        let (backup, before, after) = apply_edit(&edit("a")).unwrap();
        assert_eq!((before, after), (3, 3));
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "c\nb\nb\n");
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "a\nb\nb\n");
        assert!(apply_edit(&edit("a")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_run_goes_step_by_step_and_stops_at_a_failure() {
        let (_, plan) = take(ANSWER);
        let mut r = Run::new(plan.unwrap().unwrap());
        assert_eq!(r.start(), Action::Edit(0));
        assert_eq!(
            r.step_done(true, "3 → 6 lines".into()),
            Action::Command {
                idx: 1,
                cmd: "grep -q new /tmp/x.md".into()
            }
        );
        assert_eq!(
            r.step_done(true, "exit 0".into()),
            Action::StartWorkflow(2, "quick-update".into())
        );
        assert_eq!(r.state, RunState::WaitingWorkflow(2));
        assert_eq!(r.step_done(true, "done".into()), Action::Finished);
        assert_eq!(r.state, RunState::Done);
        assert!(r.report().starts_with("sentry carried out all 3 steps"));
        // A failing check stops it; the report says what's left.
        let mut r = Run::new(take(ANSWER).1.unwrap().unwrap());
        r.start();
        r.step_done(true, "ok".into());
        assert_eq!(r.step_done(false, "exit 1".into()), Action::Finished);
        assert_eq!(r.state, RunState::Failed(1));
        let rep = r.report();
        assert!(
            rep.contains("stopped at step 2 (Check), which failed")
                && rep.contains("Steps 1–1 are done"),
            "{rep}"
        );
    }
}
