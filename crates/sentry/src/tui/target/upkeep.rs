//! What this machine's maintenance lists hold, and what Claude is asked and allowed here.

use std::path::PathBuf;

use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::text::Line;

use super::*;
use crate::tui::plans;
use crate::tui::screens::maint::{self, How};
use crate::tui::widgets;
use sentry_app::effect::ItemChange;
use sentry_app::target::{Asks, Changes, ProfileFor, SeriesStep, Upkeep};
use sentry_core::claude::{Ask, Grant, Profile};
use sentry_core::maint::changes::{Change, Known};
use sentry_core::maint::log::ItemInfo;
use sentry_core::maint::plan::{Head, PlanDoc, PlanStatus};
use sentry_core::maint::tasks::Task;
use sentry_core::tui::records::{LaterKind, LaterRow};

/// A review's changes here are tasks and what's put off, which the app settles itself;
/// the rest (tracked items) only a server has.
struct NoChanges;

impl Changes for NoChanges {
    fn apply(&mut self, _c: &Change) -> Option<Result<String, String>> {
        Some(Err("only on a server".into()))
    }
    fn save(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn done(self: Box<Self>) -> Vec<Effect> {
        Vec::new()
    }
}

impl LocalTarget {
    fn workflow_names(&self, cx: &Cx) -> Vec<String> {
        match self.data.workflows.get() {
            Some(w) => w.iter().map(|i| i.entry.name.clone()).collect(),
            None if !cx.offline => crate::workflows::list()
                .into_iter()
                .map(|e| e.name)
                .collect(),
            // Tests: the seeded ones.
            None => crate::workflows::SEEDS
                .iter()
                .map(|(n, _)| n.to_string())
                .collect(),
        }
    }

    /// After the note: what Claude will do, in a confirm box; yes starts the writer.
    pub(super) fn plan_box(&self, wf: &str, note: Option<String>, cx: &Cx) -> Vec<Effect> {
        let t = cx.theme;
        let notes = &self.cfg.maintenance.notes;
        vec![lift(local::Effect::Confirm(local::Modal {
            title: format!("Plan {wf} with Claude"),
            color: t.mag,
            lines: vec![
                Line::styled(
                    format!(
                        "Claude reads the maintenance log, your notes ({}), release notes on the \
                         web and this machine (read-only), then writes how to run {wf} here: \
                         the assessment, what to check and back up first, what to expect at each \
                         step, how to verify and roll back.",
                        if notes.is_empty() {
                            "none: [maintenance] notes in config.toml".to_string()
                        } else {
                            notes.join(", ")
                        }
                    ),
                    t.fg(),
                ),
                Line::raw(""),
                Line::styled(
                    format!(
                        "Saved as {}; Enter in the Plan view starts {wf} with its values.",
                        widgets::short_home(&crate::maint::plan::path(crate::maint::LOCAL, wf))
                    ),
                    t.dim(),
                ),
                Line::raw(""),
                Line::styled(
                    "Sent to Claude through your Claude Code login (Anthropic). Nothing on this \
                     machine changes.",
                    t.s(t.yellow),
                ),
            ],
            yes: Some((
                "plan".into(),
                vec![local::Effect::PlanWrite(wf.to_string(), note)],
            )),
        }))]
    }

    /// The plan to be written for `wf`, and what Claude is asked.
    pub(super) fn plan_write(
        &self,
        wf: &str,
        note: Option<String>,
        sh: &Shared,
        cx: &Cx,
    ) -> Vec<Effect> {
        let Some(entry) = crate::workflows::find(wf) else {
            return vec![Effect::Toast(format!("no workflow {wf}"))];
        };
        let toml = std::fs::read_to_string(&entry.path).unwrap_or_default();
        let vars = entry
            .wf
            .as_ref()
            .ok()
            .and_then(|w| {
                crate::workflows::cli::initial_vars(
                    w,
                    &crate::workflows::cli::RealEnv,
                    &BTreeMap::new(),
                )
                .ok()
            })
            .unwrap_or_default();
        let doc = PlanDoc {
            head: Head {
                item: wf.to_string(),
                status: PlanStatus::Writing,
                from: self.booted_version(),
                workflow: wf.to_string(),
                vars,
                note: note.clone(),
                created: Some(jiff::Timestamp::now()),
                ..Default::default()
            },
            body: String::new(),
        };
        let ctx = maint::context(&self.view(sh, cx));
        let prompt = plans::plan_request(&self.cfg, &ctx, wf, &toml, note.as_deref());
        vec![Effect::PlanWrite(wf.to_string(), doc, prompt)]
    }
}

impl Upkeep for LocalTarget {
    fn derived_tasks(&self, _sh: &Shared) -> Vec<Task> {
        crate::jobs::state::tasks(&self.cfg)
    }

    fn with_known(&self, sh: &Shared, cx: &Cx, f: &mut dyn FnMut(&Known)) {
        let v = self.view(sh, cx);
        let workflows = self.workflow_names(cx);
        let tasks = maint::all_tasks(&v);
        let rows: Vec<(String, String)> = maint::recs_all(&v)
            .into_iter()
            .map(|r| (r.key, r.title))
            .collect();
        f(&Known {
            workflows: &workflows,
            tasks: &tasks,
            rows: &rows,
            later: Some(&sh.later),
            items: &[],
            found: &[],
            log: &sh.log,
            audited: self.audited(),
            now: Some(jiff::Timestamp::now()),
        })
    }

    fn changes(&self, _sh: &Shared, _cx: &Cx) -> Box<dyn Changes> {
        Box::new(NoChanges)
    }

    fn series_step(&self, key: &str, sh: &Shared, cx: &Cx) -> Option<SeriesStep> {
        Some(match maint::series_how(&self.view_all(sh, cx), key)? {
            How::Session(ask) => SeriesStep::Session(*ask),
            How::Workflow(name) => SeriesStep::Workflow(name),
            How::Audit => SeriesStep::Audit,
        })
    }

    fn task_enter(&self, id: &str, sh: &Shared, cx: &Cx) -> Vec<Effect> {
        lifted(maint::task_effects(&self.view(sh, cx), id))
    }

    /// Nothing here is a tracked item: what a run changed is said by `run_info`.
    fn item_kind(&self, _item: &str) -> Option<(String, String)> {
        None
    }

    fn records(&self, _sh: &Shared, _cx: &Cx) -> (Vec<LaterRow>, Option<jiff::Timestamp>) {
        (Vec::new(), self.audited())
    }

    fn undo(&mut self, row: &LaterRow, _sh: &mut Shared, _cx: &Cx) -> Result<Vec<Effect>, String> {
        Ok(match row.kind {
            LaterKind::Expected => vec![lift(local::Effect::Unbaseline(BaselineEdit::Finding(
                row.key.clone(),
            )))],
            _ => Vec::new(),
        })
    }

    /// However the run was started, the ready plan for its workflow is what it applied.
    fn run_plan(&mut self, _run: &dyn WfRun, _change: Option<&ItemChange>) -> Option<String> {
        self.wf_plan.take()
    }

    /// An OS change says from → to (the booted versions).
    fn run_info(
        &self,
        run: &dyn WfRun,
        _change: Option<&ItemChange>,
        plan: Option<PathBuf>,
    ) -> Option<ItemInfo> {
        let name = &run.wf().name;
        let kind = log_kind(name);
        let to = self.booted_version();
        (kind != "system" || plan.is_some()).then(|| ItemInfo {
            item: if kind == "system" {
                name.clone()
            } else {
                "os".into()
            },
            kind: kind.into(),
            risk: if kind == "kmod" || kind == "rebase" {
                "high"
            } else {
                "medium"
            }
            .into(),
            from: self.wf_from.clone(),
            to: to.filter(|t| Some(t) != self.wf_from.as_ref()),
            plan,
        })
    }
}

impl Asks for LocalTarget {
    fn ask(&self, sh: &Shared, cx: &Cx) -> Result<Ask, String> {
        self.screens.ask(cx.screen, &self.view(sh, cx))
    }

    fn apply_ask(&self, sh: &Shared, cx: &Cx) -> Option<Ask> {
        self.screens.maint.apply_ask(&self.view(sh, cx))
    }

    fn plan_ask(&self, item: &str, _key: String, sh: &Shared, cx: &Cx) -> Option<Ask> {
        maint::plan_apply_ask(&self.view(sh, cx), item)
    }

    /// Plans here are a workflow's: `p` on it asks for the note and shows what Claude will
    /// do (`plan_box`), so the app's own question for an item is never put.
    fn plan_brief(
        &self,
        _item: &str,
        _doc: &PlanDoc,
        _sh: &Shared,
        _cx: &Cx,
    ) -> Result<(Vec<Line<'static>>, String), String> {
        Err("a plan here is for a workflow: p on it (0)".into())
    }

    fn review_brief(&self, cx: &Cx) -> Vec<Line<'static>> {
        let t = cx.theme;
        vec![
            Line::raw(""),
            Line::styled(
                "  Claude reviews what Maintenance lists (recommendations, tasks, what's put off), the",
                t.fg(),
            ),
            Line::styled(
                "  deployments and updates waiting, the maintenance log and release notes, then writes",
                t.fg(),
            ),
            Line::styled("  what to do now, soon and routinely, and why.", t.fg()),
            Line::raw(""),
            Line::styled(
                "  It ends with how the list should change: tasks to add, remove or change, and what",
                t.fg(),
            ),
            Line::styled(
                "  can wait. You see those as one list, ticked; Enter applies them together.",
                t.fg(),
            ),
            Line::raw(""),
            Line::styled(
                format!(
                    "  It reads the web, your notes and this machine (read-only). Saved in {}.",
                    widgets::short_home(&crate::maint::review::dir(crate::maint::LOCAL))
                ),
                t.dim(),
            ),
            Line::styled(
                "  Sent to Claude through your Claude Code login (Anthropic). Nothing on this machine changes.",
                t.s(t.yellow),
            ),
            Line::raw(""),
            Line::styled("  Enter starts the review.", t.s(t.cyan)),
        ]
    }

    fn review_request(&self, auto: Option<&str>, changes: &str, sh: &Shared, cx: &Cx) -> String {
        let v = self.view(sh, cx);
        let (recs, context) = (maint::recs_text(&v), maint::context(&v));
        match auto {
            Some(ask) => plans::auto_review_request(&self.cfg, ask, &recs, &context, changes),
            None => plans::review_request(&self.cfg, &recs, &context, changes),
        }
    }

    fn plan_revise(&self, what: &str) -> String {
        plans::revise(what)
    }

    /// A chat explains (read-only commands); a session finds out whatever it needs; both
    /// with the notes files, the log, and what the user granted in the conversation.
    fn profile(&self, f: ProfileFor, grants: &[Grant]) -> Profile {
        let base = match f {
            ProfileFor::Plan => return plans::plan_profile(&self.cfg),
            ProfileFor::Review => return plans::review_profile(&self.cfg),
            ProfileFor::Session => Profile::acting(),
            ProfileFor::Chat => Profile::local(),
        };
        base.with_notes(&self.cfg.maintenance.notes)
            .with_log(&crate::maint::log::dir(crate::maint::LOCAL))
            .with_grants(grants)
    }

    /// The Plan view's keys that mean something else here: a plan is for a workflow, and
    /// applying it starts that workflow with the plan's values.
    fn plan_key(
        &mut self,
        wf: &str,
        k: KeyEvent,
        writing: bool,
        sh: &Shared,
        cx: &Cx,
    ) -> Option<Vec<Effect>> {
        let toast = |s: &str| Some(vec![Effect::Toast(s.to_string())]);
        let wf = wf.to_string();
        match k.code {
            KeyCode::Char('A') | KeyCode::Enter | KeyCode::Char('r') | KeyCode::Char('x')
                if writing =>
            {
                Some(Vec::new())
            }
            // Claude alongside: apply this plan, or ask about it.
            KeyCode::Char('A') => {
                if !crate::claude::available() {
                    return toast(self.ident.ways.no_claude);
                }
                let Some(apply) = maint::plan_apply_ask(&self.view(sh, cx), &wf) else {
                    return toast("the plan isn't ready to apply");
                };
                let ask = Ask::new(
                    format!("the plan for {wf}"),
                    apply.context.clone(),
                    "Is this plan still right for my machine as it is now? What would you check \
                     or change first?",
                );
                Some(vec![Effect::Choose(crate::tui::frame::claude_choice(
                    cx.theme,
                    "sentry",
                    vec![Effect::AskConsent(Box::new(apply.clone()))],
                    vec![Effect::AskWith(Box::new(ask), Box::new(apply))],
                ))])
            }
            KeyCode::Enter => match sh.plans.get(&wf).map(|d| d.head.status) {
                Some(PlanStatus::Ready) => Some(vec![lift(local::Effect::PlanApply(wf))]),
                Some(PlanStatus::Wait) => toast(
                    "Claude advises waiting: r revises it, or start the workflow from Upgrade",
                ),
                _ => toast("this plan isn't ready: r revises it, P plans again"),
            },
            KeyCode::Char('r') => Some(vec![Effect::Prompt(
                effect::Prompt::PlanRevise(wf),
                String::new(),
            )]),
            KeyCode::Char('x') => {
                let t = cx.theme;
                Some(vec![lift(local::Effect::Confirm(local::Modal {
                    title: format!("Drop the plan for {wf}"),
                    color: t.red,
                    lines: vec![Line::styled(
                        "It moves to plans/done/ (kept, not applied).",
                        t.fg(),
                    )],
                    yes: Some(("drop".into(), vec![local::Effect::PlanDrop(wf)])),
                }))])
            }
            // Scrolling and stopping are the app's; no other key does anything here.
            KeyCode::Char('c' | 'j' | 'k' | ' ' | 'g' | 'G')
            | KeyCode::Down
            | KeyCode::Up
            | KeyCode::PageDown
            | KeyCode::PageUp
            | KeyCode::Home
            | KeyCode::End => None,
            _ => Some(Vec::new()),
        }
    }

    /// Claude's answer becomes the plan: the version to move to goes into the values of a
    /// workflow that takes one (release-rebase).
    fn plan_written(
        &self,
        doc: &mut PlanDoc,
        answer: Result<&str, Option<&str>>,
    ) -> Option<String> {
        match answer {
            Ok(a) => {
                doc.take_answer(a);
                if let Some(Some(t)) = crate::maint::plan::target(a)
                    && !t.eq_ignore_ascii_case("now")
                {
                    if doc.head.vars.contains_key("target") {
                        doc.head.vars.insert("target".into(), t.clone());
                    }
                    doc.head.to = Some(t);
                }
            }
            Err(err) => {
                doc.head.status = PlanStatus::Failed;
                doc.body = format!(
                    "Writing the plan failed: {}",
                    err.unwrap_or("Claude gave no answer")
                );
            }
        }
        let wf = &doc.head.item;
        Some(match doc.head.status {
            PlanStatus::Ready => format!("the plan for {wf} is saved: Enter in it applies it"),
            PlanStatus::Wait => format!("Claude advises waiting with {wf} (the plan says why)"),
            _ => format!("no plan for {wf}: see the Plan view"),
        })
    }

    /// `C`: the conversation goes on in Claude Code itself, in this terminal.
    fn chat_continue(&mut self, session: &str) -> Option<Vec<Effect>> {
        Some(vec![
            Effect::ChatNote(
                "continued in Claude Code (sudo and file edits stay off; it asks before other commands)"
                    .into(),
            ),
            Effect::Suspend(Suspend {
                cmd: crate::claude::interactive_cmd(session),
                banner: "sentry: continuing this conversation in Claude Code. Read-only commands are \
                         pre-allowed; it asks before anything else, and sudo and file edits are off.\n\
                         (The first time, Claude Code asks whether to trust sentry's scratch folder.)\n\
                         Quit Claude Code (/exit or Ctrl-D twice) to return to sentry."
                    .into(),
                then: Vec::new(),
                own: Some(own(Own::After(vec![local::Effect::ChatBack]))),
            }),
        ])
    }
}
