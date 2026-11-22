//! What this machine's maintenance lists hold, and what Claude is asked and allowed here.

use std::path::PathBuf;

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
use sentry_core::maint::plan::{Head, PlanDoc};
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
            How::Session(ask) => SeriesStep::Session(ask),
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
    fn peer(&self) -> sentry_core::apply::session::Peer {
        sentry_core::apply::session::Peer {
            id: self.ident.id.clone(),
            title: self.ident.title.clone(),
            ..Default::default()
        }
    }

    fn describe(&self, _sh: &Shared, _cx: &Cx) -> sentry_app::system::SystemLine {
        sentry_app::system::SystemLine {
            kind: "this machine".into(),
            what: "the laptop sentry runs on (Fedora Silverblue: rpm-ostree, Flatpak, \
                   toolbox). It reaches every other target over ssh."
                .into(),
            ..Default::default()
        }
    }

    fn ask(&self, sh: &Shared, cx: &Cx) -> Result<Ask, String> {
        self.screens.ask(cx.screen, &self.view(sh, cx))
    }

    fn apply_ask(&self, sh: &Shared, cx: &Cx) -> Option<Ask> {
        self.screens.maint.apply_ask(&self.view(sh, cx))
    }

    fn plan_ask(&self, item: &str, _key: String, sh: &Shared, cx: &Cx) -> Option<Ask> {
        maint::plan_apply_ask(&self.view(sh, cx), item)
    }

    /// The header of a workflow's plan, kept for the first time: the version booted, the
    /// workflow and its values as they'd be asked now.
    fn plan_head(&self, wf: &str, _sh: &Shared, _cx: &Cx) -> Option<Head> {
        let entry = crate::workflows::find(wf)?;
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
        Some(Head {
            item: wf.to_string(),
            from: self.booted_version(),
            workflow: wf.to_string(),
            vars,
            ..Default::default()
        })
    }

    /// The version to move to goes into the values of a workflow that takes one
    /// (release-rebase).
    fn plan_kept(&self, doc: &mut PlanDoc, answer: &str) {
        if let Some(Some(t)) = crate::maint::plan::target(answer)
            && !t.eq_ignore_ascii_case("now")
        {
            if doc.head.vars.contains_key("target") {
                doc.head.vars.insert("target".into(), t.clone());
            }
            doc.head.to = Some(t);
        }
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

    /// A chat explains (read-only commands); a session finds out whatever it needs; both
    /// with the notes files, the log, and what the user granted in the conversation.
    fn profile(&self, f: ProfileFor, grants: &[Grant]) -> Profile {
        let base = match f {
            ProfileFor::Review => return plans::review_profile(&self.cfg),
            // A session researches what a plan was written for: release notes on the web.
            ProfileFor::Session => plans::with_web(Profile::acting()),
            // A session that started on another target: nothing here runs by itself.
            ProfileFor::Peer => {
                return Profile {
                    system: "Commands on this machine are not this session's to run freely: \
                             call the read-only command you need with Bash; it is refused at \
                             first, I am shown the exact line, and Enter allows it (end your \
                             turn there, saying in one line what you asked for). What changes \
                             this machine is a plan step with `on = \"local\"`: a `run` step \
                             (with sudo in it where it needs root), or an `edit` step for a \
                             file here. Upgrades, rebases, rollbacks and reboots are this \
                             machine's workflows (`workflow = \"…\"` with `on = \"local\"`)."
                        .into(),
                    tools: ["Bash", "Read"].map(String::from).to_vec(),
                    allowed: Vec::new(),
                    denied: Profile::local().denied,
                    dirs: Vec::new(),
                };
            }
            ProfileFor::Chat => Profile::local(),
        };
        base.with_notes(&self.cfg.maintenance.notes)
            .with_log(&crate::maint::log::dir(crate::maint::LOCAL))
            .with_grants(grants)
    }

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
