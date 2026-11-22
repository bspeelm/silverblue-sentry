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
    /// The target it runs on (its id: `""` this machine, `srv:<name>`, `net:<name>`).
    /// None: where the session started.
    pub on: Option<String>,
    /// A run or check step: the last line it prints on stdout, trimmed, is kept under
    /// this name for the session, and later steps on any target use it as `{{name}}`.
    pub capture: Option<String>,
    /// The captured or asked value is never shown or written down: a tag stands for it.
    pub secret: bool,
}

impl Step {
    pub fn new(title: impl Into<String>, kind: Kind) -> Self {
        Self {
            title: title.into(),
            kind,
            on: None,
            capture: None,
            secret: false,
        }
    }

    /// The name of the value this step gives the session (a capture, or what it asks for).
    pub fn gives(&self) -> Option<&str> {
        match &self.kind {
            Kind::Ask { name, .. } => Some(name),
            _ => self.capture.as_deref(),
        }
    }

    /// Every text of the step a `{{name}}` may stand in.
    pub fn texts(&self) -> Vec<&str> {
        match &self.kind {
            Kind::Run(c) | Kind::Check(c) => vec![c],
            Kind::Workflow { vars, .. } => vars.values().map(String::as_str).collect(),
            _ => Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    /// Replace `old` (found exactly once) with `new` in `file`.
    Edit {
        file: String,
        old: String,
        new: String,
    },
    /// A command that changes something (sudo: with the password, asked once).
    Run(String),
    /// A command that must exit 0, or the plan stops.
    Check(String),
    /// A sentry workflow, with values for its `[vars]`: started, and the plan waits for its
    /// run to end. A var it needs that isn't given is asked when it starts.
    Workflow {
        name: String,
        vars: std::collections::BTreeMap<String, String>,
    },
    /// A value only the user has (a password from their head or a manager): asked for in
    /// the session's own input line when the plan reaches it, kept as `name`.
    Ask { name: String, prompt: String },
    /// Stop sentry watching something its config lists and that was retired on purpose
    /// (`what`: `timer:<unit>`, as the brief names it). Nothing on the host changes: sentry
    /// writes its own `watch.toml`, and Records can take it back.
    Unwatch { what: String, why: String },
}

impl Kind {
    pub fn word(&self) -> &'static str {
        match self {
            Kind::Edit { .. } => "edit",
            Kind::Run(_) => "run",
            Kind::Check(_) => "check",
            Kind::Workflow { .. } => "workflow",
            Kind::Ask { .. } => "ask",
            Kind::Unwatch { .. } => "stop watching",
        }
    }

    /// The file, command or workflow it's about.
    pub fn target(&self) -> &str {
        match self {
            Kind::Edit { file, .. } => file,
            Kind::Run(c) | Kind::Check(c) => c,
            Kind::Workflow { name, .. } => name,
            Kind::Ask { name, .. } => name,
            Kind::Unwatch { what, .. } => what,
        }
    }
}

/// The `{{name}}`s in `text`, in order.
pub fn placeholders(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("{{") {
        let after = &rest[i + 2..];
        let Some(j) = after.find("}}") else { break };
        let name = &after[..j];
        if value_name(name) {
            out.push(name);
            rest = &after[j + 2..];
        } else {
            rest = after;
        }
    }
    out
}

/// A value's name: lowercase letters, digits and `_`.
pub fn value_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 32
        && n.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// A value that means the same wherever a shell reads it.
fn plain_value(v: &str) -> bool {
    v.chars()
        .all(|c| c.is_ascii_alphanumeric() || "._:/+=@%,-".contains(c))
}

/// Why a value can't be kept: it must be one line, without a single quote (it is put
/// inside single quotes) or control characters.
pub fn value_problem(v: &str) -> Option<&'static str> {
    if v.is_empty() {
        Some("it is empty")
    } else if v.chars().any(|c| c.is_control()) {
        Some("it has a control character or more than one line")
    } else if v.contains('\'') {
        Some("it has a single quote in it")
    } else {
        None
    }
}

/// `text` with each `{{name}}` replaced by its value. A value that isn't plain (spaces,
/// shell characters) only goes inside single quotes. Err: why not, for Claude.
pub fn fill(text: &str, value: &dyn Fn(&str) -> Option<String>) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut quoted = false;
    let mut rest = text;
    while let Some(i) = rest.find("{{") {
        let after = &rest[i + 2..];
        let name = after.find("}}").map(|j| &after[..j]);
        let Some(name) = name.filter(|n| value_name(n)) else {
            quoted ^= rest[..i + 2].matches('\'').count() % 2 == 1;
            out.push_str(&rest[..i + 2]);
            rest = after;
            continue;
        };
        quoted ^= rest[..i].matches('\'').count() % 2 == 1;
        out.push_str(&rest[..i]);
        let v = value(name)
            .ok_or_else(|| format!("no value {{{{{name}}}}} has been captured or asked for yet"))?;
        if !quoted && !plain_value(&v) {
            return Err(format!(
                "{{{{{name}}}}} must stand inside single quotes ('…{{{{{name}}}}}…'): its value isn't a plain word"
            ));
        }
        out.push_str(&v);
        rest = &after[name.len() + 2..];
    }
    out.push_str(rest);
    Ok(out)
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
    /// A workflow step's values (strings, or numbers and booleans written as they are).
    vars: Option<std::collections::BTreeMap<String, toml::Value>>,
    ask: Option<String>,
    prompt: Option<String>,
    unwatch: Option<String>,
    why: Option<String>,
    on: Option<String>,
    capture: Option<String>,
    #[serde(default)]
    secret: bool,
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
            s.ask.is_some(),
            s.unwatch.is_some(),
        ]
        .iter()
        .filter(|x| **x)
        .count();
        if kinds != 1 {
            return Err(format!(
                "step {n} needs exactly one of edit, run, check, workflow, ask or unwatch"
            ));
        }
        if let Some(c) = &s.capture {
            if s.run.is_none() && s.check.is_none() {
                return Err(format!("step {n}: only a run or check step captures"));
            }
            if !value_name(c) {
                return Err(format!(
                    "step {n}: capture = \"{c}\" isn't a name (lowercase letters, digits, _)"
                ));
            }
        }
        if s.secret && s.capture.is_none() && s.ask.is_none() {
            return Err(format!("step {n}: secret = true goes with capture or ask"));
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
        } else if let Some(what) = s.unwatch {
            let what = what.trim().to_string();
            if crate::maint::watch::split(&what).is_none() {
                return Err(format!(
                    "step {n}: unwatch = \"{what}\" isn't `<kind>:<name>` as the brief names it"
                ));
            }
            match s
                .why
                .map(|w| w.trim().to_string())
                .filter(|w| !w.is_empty())
            {
                Some(why) => Kind::Unwatch { what, why },
                None => {
                    return Err(format!(
                        "step {n} (unwatch) needs a `why`: what was retired, and what replaced it"
                    ));
                }
            }
        } else if let Some(name) = s.ask {
            if !value_name(&name) {
                return Err(format!(
                    "step {n}: ask = \"{name}\" isn't a name (lowercase letters, digits, _)"
                ));
            }
            match s.prompt.filter(|p| !p.trim().is_empty()) {
                Some(p) => Kind::Ask {
                    name,
                    prompt: p.lines().next().unwrap_or("").trim().to_string(),
                },
                None => return Err(format!("step {n} (ask) needs a one-line prompt")),
            }
        } else {
            Kind::Workflow {
                name: s.workflow.unwrap_or_default(),
                vars: s
                    .vars
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(k, v)| {
                        let v = match v {
                            toml::Value::String(x) => x,
                            other => other.to_string(),
                        };
                        (k, v)
                    })
                    .collect(),
            }
        };
        steps.push(Step {
            title: if s.title.is_empty() {
                format!("step {n}")
            } else {
                s.title
            },
            kind,
            on: s.on.map(|o| o.trim().to_string()),
            capture: s.capture,
            secret: s.secret,
        });
    }
    Ok(Plan {
        summary: raw.summary,
        rollback: raw.rollback,
        steps,
    })
}

/// The plan as the block it came in (what's saved with a plan's document, and read back
/// by `take` when the plan seeds a session later).
pub fn to_block(p: &Plan) -> String {
    let mut t = toml::Table::new();
    t.insert("summary".into(), p.summary.clone().into());
    if !p.rollback.trim().is_empty() {
        t.insert("rollback".into(), p.rollback.clone().into());
    }
    let steps: Vec<toml::Value> = p
        .steps
        .iter()
        .map(|s| {
            let mut st = toml::Table::new();
            st.insert("title".into(), s.title.clone().into());
            match &s.kind {
                Kind::Edit { file, old, new } => {
                    st.insert("edit".into(), file.clone().into());
                    st.insert("old".into(), old.clone().into());
                    st.insert("new".into(), new.clone().into());
                }
                Kind::Run(c) => {
                    st.insert("run".into(), c.clone().into());
                }
                Kind::Check(c) => {
                    st.insert("check".into(), c.clone().into());
                }
                Kind::Workflow { name, vars } => {
                    st.insert("workflow".into(), name.clone().into());
                    if !vars.is_empty() {
                        let v: toml::Table = vars
                            .iter()
                            .map(|(k, v)| (k.clone(), toml::Value::from(v.clone())))
                            .collect();
                        st.insert("vars".into(), v.into());
                    }
                }
                Kind::Ask { name, prompt } => {
                    st.insert("ask".into(), name.clone().into());
                    st.insert("prompt".into(), prompt.clone().into());
                }
                Kind::Unwatch { what, why } => {
                    st.insert("unwatch".into(), what.clone().into());
                    st.insert("why".into(), why.clone().into());
                }
            }
            if let Some(on) = &s.on {
                st.insert("on".into(), on.clone().into());
            }
            if let Some(c) = &s.capture {
                st.insert("capture".into(), c.clone().into());
            }
            if s.secret {
                st.insert("secret".into(), true.into());
            }
            toml::Value::Table(st)
        })
        .collect();
    t.insert("step".into(), steps.into());
    format!("{FENCE}\n{}```", toml::to_string(&t).unwrap_or_default())
}

/// A workflow sentry knows: its name and, when its file reads, its `[vars]` (name, whether
/// it has a default).
#[derive(Debug, Clone, PartialEq)]
pub struct WfInfo {
    pub name: String,
    pub vars: Option<Vec<(String, bool)>>,
    /// Why it won't start (a draft, a parse or lint error): the plan can't use it as is.
    pub blocked: Option<String>,
}

impl From<&str> for WfInfo {
    fn from(name: &str) -> Self {
        Self {
            name: name.to_string(),
            vars: None,
            blocked: None,
        }
    }
}

impl WfInfo {
    pub fn of(e: &crate::workflows::Entry) -> Self {
        Self {
            name: e.name.clone(),
            vars: e.wf.as_ref().ok().map(|w| {
                w.vars
                    .iter()
                    .map(|(k, v)| (k.clone(), v.default.is_some()))
                    .collect()
            }),
            blocked: e.blocked(),
        }
    }
}

pub fn problems(p: &Plan, workflows: &[WfInfo]) -> Vec<(usize, String)> {
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
            Kind::Workflow { name, vars } => match workflows.iter().find(|x| &x.name == name) {
                None => out.push((i, format!("no workflow {name}"))),
                Some(WfInfo {
                    blocked: Some(why), ..
                }) => out.push((i, format!("{name} won't start ({why})"))),
                Some(WfInfo {
                    vars: Some(declared),
                    ..
                }) => {
                    for k in vars
                        .keys()
                        .filter(|k| !declared.iter().any(|(d, _)| d == *k))
                    {
                        out.push((i, format!("{name} has no var {k}")));
                    }
                }
                _ => {}
            },
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
    Command {
        idx: usize,
        cmd: String,
    },
    StartWorkflow(usize, String, std::collections::BTreeMap<String, String>),
    /// Ask the user for the step's value.
    Ask(usize),
    /// sentry stops watching what the step names (its own file; nothing runs).
    Unwatch(usize),
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
            Kind::Workflow { name, vars } => {
                self.state = RunState::WaitingWorkflow(i);
                Action::StartWorkflow(i, name.clone(), vars.clone())
            }
            Kind::Ask { .. } => Action::Ask(i),
            Kind::Unwatch { .. } => Action::Unwatch(i),
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
                    "{}. {} {} ({}{} {}): {}",
                    i + 1,
                    if r.ok { "✓" } else { "✗" },
                    s.title,
                    s.kind.word(),
                    match &s.on {
                        Some(on) => format!(" on {}", if on.is_empty() { "local" } else { on }),
                        None => String::new(),
                    },
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
    fn an_unwatch_step_names_a_kind_and_a_name_and_says_why() {
        let block = |step: &str| {
            format!("```sentry-apply\nsummary = \"s\"\n[[step]]\ntitle = \"Stop\"\n{step}```")
        };
        let (_, p) = take(&block(
            "unwatch = \" timer:report.timer \"\nwhy = \"retired; v2 runs\"\n",
        ));
        let p = p.unwrap().unwrap();
        assert_eq!(
            p.steps[0].kind,
            Kind::Unwatch {
                what: "timer:report.timer".into(),
                why: "retired; v2 runs".into()
            }
        );
        assert_eq!(
            (p.steps[0].kind.word(), p.steps[0].kind.target()),
            ("stop watching", "timer:report.timer")
        );
        // It reads back as written (a plan kept in plans/).
        let (_, back) = take(&to_block(&p));
        assert_eq!(back.unwrap().unwrap(), p);
        for (step, why) in [
            (
                "unwatch = \"report.timer\"\nwhy = \"x\"\n",
                "isn't `<kind>:<name>`",
            ),
            ("unwatch = \"timer:report.timer\"\n", "needs a `why`"),
            (
                "unwatch = \"timer:a\"\nwhy = \"x\"\nrun = \"true\"\n",
                "exactly one of",
            ),
        ] {
            let (_, p) = take(&block(step));
            let e = p.unwrap().unwrap_err();
            assert!(e.contains(why), "{e}");
        }
        // Nothing runs: the app writes sentry's own file.
        let mut r = Run::new(p);
        assert_eq!(r.start(), Action::Unwatch(0));
        assert_eq!(r.step_done(true, "written".into()), Action::Finished);
        assert!(
            r.report()
                .contains("(stop watching timer:report.timer): written")
        );
    }

    #[test]
    fn a_plan_written_back_reads_the_same() {
        let (_, plan) = take(ANSWER);
        let plan = plan.unwrap().unwrap();
        let block = to_block(&plan);
        let (body, back) = take(&format!("# Plan: x\n\nWhy.\n\n{block}\n"));
        assert_eq!(body, "# Plan: x\n\nWhy.");
        assert_eq!(back.unwrap().unwrap(), plan, "{block}");
        let wf = Plan {
            summary: "bump web".into(),
            rollback: String::new(),
            steps: vec![Step::new(
                "Run it",
                Kind::Workflow {
                    name: "compose-bump".into(),
                    vars: [("image".to_string(), "example/web:1.5.2".to_string())].into(),
                },
            )],
        };
        assert_eq!(take(&to_block(&wf)).1.unwrap().unwrap(), wf);
    }

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
    fn a_workflow_step_carries_values() {
        let (_, p) = take(
            "```sentry-apply\n[[step]]\ntitle = \"Bump\"\nworkflow = \"compose-bump\"\n\
             vars = { image = \"example/web:1.5.1\", wait = 30 }\n```",
        );
        let p = p.unwrap().unwrap();
        let Kind::Workflow { name, vars } = &p.steps[0].kind else {
            panic!("{:?}", p.steps[0])
        };
        assert_eq!(name, "compose-bump");
        assert_eq!(vars["image"], "example/web:1.5.1");
        assert_eq!(vars["wait"], "30");
        let known = |vars: Option<Vec<(String, bool)>>| WfInfo {
            name: "compose-bump".into(),
            vars,
            blocked: None,
        };
        // Declared: fine. Not declared: a problem. Unknown (the file didn't read): not checked.
        let ok = known(Some(vec![("image".into(), false), ("wait".into(), true)]));
        assert!(problems(&p, &[ok]).is_empty());
        let short = known(Some(vec![("image".into(), false)]));
        assert_eq!(problems(&p, &[short])[0].1, "compose-bump has no var wait");
        assert!(problems(&p, &[known(None)]).is_empty());
        // A workflow that won't start (a draft): the plan can't use it.
        let draft = WfInfo {
            blocked: Some("draft".into()),
            ..known(None)
        };
        assert_eq!(
            problems(&p, &[draft])[0].1,
            "compose-bump won't start (draft)"
        );
        assert_eq!(problems(&p, &[])[0].1, "no workflow compose-bump");
    }

    #[test]
    fn what_stops_approval() {
        let dir = crate::paths::home().join(".cache/sentry-applyplan-test");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join(format!("plan-{}.md", std::process::id()));
        std::fs::write(&f, "a\nb\nb\n").unwrap();
        let file = f.display().to_string();
        let edit = |old: &str| {
            Step::new(
                "e",
                Kind::Edit {
                    file: file.clone(),
                    old: old.into(),
                    new: "c".into(),
                },
            )
        };
        let p = Plan {
            summary: String::new(),
            rollback: String::new(),
            steps: vec![
                edit("a"),
                edit("zz"),
                edit("b"),
                Step::new(
                    "w",
                    Kind::Workflow {
                        name: "nope".into(),
                        vars: Default::default(),
                    },
                ),
                Step::new(
                    "e",
                    Kind::Edit {
                        file: "/etc/hosts".into(),
                        old: "text no hosts file has".into(),
                        new: "y".into(),
                    },
                ),
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
            Action::StartWorkflow(2, "quick-update".into(), Default::default())
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

    #[test]
    fn a_step_names_its_target_and_what_it_captures() {
        let (_, p) = take(
            "```sentry-apply\nsummary = \"bouncer\"\n\n[[step]]\ntitle = \"Key\"\non = \"srv:myserver\"\n\
             run = \"sudo cscli bouncers add router -o raw\"\ncapture = \"key\"\nsecret = true\n\n\
             [[step]]\ntitle = \"Set\"\nrun = \"uci set crowdsec.bouncer.api_key='{{key}}'\"\n\n\
             [[step]]\nask = \"pass\"\nprompt = \"The portal's password\"\nsecret = true\n```",
        );
        let p = p.unwrap().unwrap();
        assert_eq!(p.steps[0].on.as_deref(), Some("srv:myserver"));
        assert_eq!(p.steps[0].gives(), Some("key"));
        assert!(p.steps[0].secret && p.steps[1].on.is_none());
        assert_eq!(placeholders(p.steps[1].texts()[0]), ["key"]);
        assert_eq!(
            p.steps[2].kind,
            Kind::Ask {
                name: "pass".into(),
                prompt: "The portal's password".into()
            }
        );
        // Written back, it reads the same; a step without them is written as before.
        assert_eq!(take(&to_block(&p)).1.unwrap().unwrap(), p);
        assert!(!to_block(&take(ANSWER).1.unwrap().unwrap()).contains("on ="));
        for (bad, why) in [
            (
                "edit = \"/x\"\nold = \"a\"\nnew = \"b\"\ncapture = \"k\"",
                "only a run or check",
            ),
            ("run = \"a\"\ncapture = \"My Key\"", "isn't a name"),
            ("run = \"a\"\nsecret = true", "goes with capture or ask"),
            ("ask = \"k\"", "one-line prompt"),
        ] {
            let e = take(&format!("```sentry-apply\n[[step]]\n{bad}\n```"))
                .1
                .unwrap()
                .unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn values_are_filled_in_and_only_plain_ones_outside_quotes() {
        let v = |n: &str| match n {
            "key" => Some("abc123+/=".to_string()),
            "pass" => Some("two words; $x".to_string()),
            _ => None,
        };
        assert_eq!(
            fill("set k={{key}} '{{pass}}'", &v).unwrap(),
            "set k=abc123+/= 'two words; $x'"
        );
        assert!(
            fill("echo {{pass}}", &v)
                .unwrap_err()
                .contains("inside single quotes")
        );
        assert!(
            fill("echo '{{nope}}'", &v)
                .unwrap_err()
                .contains("no value {{nope}}")
        );
        // Not a placeholder: left as it is.
        assert_eq!(
            fill("awk '{{ print }}' {{key}}", &v).unwrap(),
            "awk '{{ print }}' abc123+/="
        );
        assert_eq!(value_problem("it's"), Some("it has a single quote in it"));
        assert_eq!(
            value_problem("a\nb"),
            Some("it has a control character or more than one line")
        );
        assert_eq!(value_problem("fine value"), None);
    }
}
