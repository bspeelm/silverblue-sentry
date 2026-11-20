//! The server's maintenance lists and what Claude is asked about them: `Upkeep` and `Asks`
//! for [`ServerTarget`].

use super::*;

/// A review's track / untrack / ignore / item changes, settled with the tasks.
struct ItemChanges {
    name: String,
    items: Tracked,
    before: Tracked,
    /// The ids server_config.yaml defines: never rewritten, changed through items.toml.
    yaml: Vec<String>,
    found: Vec<crate::maint::discover::Candidate>,
}

impl Changes for ItemChanges {
    fn apply(&mut self, c: &Change) -> Option<Result<String, String>> {
        tracked::apply(&mut self.items, c, &self.yaml, &self.found)
    }

    fn save(&mut self) -> Result<(), String> {
        if self.items == self.before {
            return Ok(());
        }
        tracked::save(&self.name, &self.items).map_err(|e| e.to_string())
    }

    fn done(self: Box<Self>) -> Vec<Effect> {
        if self.items == self.before {
            return Vec::new();
        }
        vec![Own::ItemsChanged(self.items).into()]
    }
}

impl Upkeep for ServerTarget {
    fn derived_tasks(&self, sh: &Shared) -> Vec<Task> {
        crate::maint::cadence_tasks(&self.remote.cfg, &sh.workflows)
    }

    fn with_known(&self, sh: &Shared, cx: &Cx, f: &mut dyn FnMut(&Known)) {
        let v = self.view_all(sh, cx);
        let tasks = super::super::screens::maint::all_tasks(&v);
        let rows: Vec<(String, String)> = super::super::screens::maint::recs(&v)
            .into_iter()
            .map(|r| (r.key, r.title))
            .collect();
        let own: Vec<String> = tracked::load(&self.remote.name)
            .items
            .into_iter()
            .map(|i| i.id)
            .collect();
        let items: Vec<(String, String)> = self
            .remote
            .cfg
            .maintenance
            .items
            .iter()
            .map(|i| {
                (
                    i.id.clone(),
                    format!(
                        "{} risk; defined in {}",
                        i.risk.as_str(),
                        if own.contains(&i.id) {
                            "items.toml"
                        } else {
                            "server_config.yaml"
                        }
                    ),
                )
            })
            .collect();
        let found: Vec<(String, String)> = self
            .store
            .maint_found
            .candidates
            .iter()
            .map(|c| (c.key.clone(), c.what.clone()))
            .collect();
        f(&Known {
            workflows: &sh.workflows,
            tasks: &tasks,
            rows: &rows,
            later: Some(&sh.later),
            items: &items,
            found: &found,
            log: &sh.log,
            audited: None,
            now: Some(jiff::Timestamp::now()),
        })
    }

    fn changes(&self, _sh: &Shared, cx: &Cx) -> Box<dyn Changes> {
        let name = self.remote.name.clone();
        let items = tracked::load(&name);
        let yaml: Vec<String> = match crate::config::load() {
            Ok((f, _)) if !cx.offline => f.servers.get(&name).map_or(Vec::new(), |s| {
                s.maintenance.items.iter().map(|i| i.id.clone()).collect()
            }),
            _ => self
                .item_ids()
                .into_iter()
                .filter(|id| !items.items.iter().any(|i| &i.id == id))
                .collect(),
        };
        Box::new(ItemChanges {
            name,
            before: items.clone(),
            items,
            yaml,
            found: self.store.maint_found.candidates.clone(),
        })
    }

    fn series_step(&self, key: &str, sh: &Shared, cx: &Cx) -> Option<SeriesStep> {
        use super::super::screens::maint::{self as m, SeriesKind};
        let v = self.view_all(sh, cx);
        let rec = m::every_rec(&v).into_iter().find(|r| r.key == key)?;
        Some(match m::series_kind(&v, &rec)? {
            SeriesKind::Finding(id) => SeriesStep::Session(Box::new(
                super::super::ask::ask_finding(&v, &self.remote, m::finding(&v, &id)?),
            )),
            SeriesKind::Apply => SeriesStep::Session(Box::new(super::super::ask::apply_rec(
                &v,
                &self.remote,
                &rec,
                &Self::steps_text(sh),
            )?)),
            SeriesKind::Workflow(name) => SeriesStep::Workflow(name),
            SeriesKind::Audit => SeriesStep::Audit,
        })
    }

    fn task_enter(&self, id: &str, sh: &Shared, cx: &Cx) -> Vec<Effect> {
        super::super::screens::maint::task_enter(&self.view(sh, cx), id)
    }

    fn item_kind(&self, item: &str) -> Option<(String, String)> {
        let it = self
            .remote
            .cfg
            .maintenance
            .items
            .iter()
            .find(|i| i.id == item)?;
        Some((item_kind(it).to_string(), it.risk.as_str().to_string()))
    }

    fn records(&self, _sh: &Shared, cx: &Cx) -> (Vec<LaterRow>, Option<jiff::Timestamp>) {
        let mut later = Vec::new();
        if !cx.offline {
            let tracked = tracked::load(&self.remote.name);
            later.extend(
                tracked
                    .ignore
                    .into_iter()
                    .chain(tracked.untracked.iter().map(|id| format!("item:{id}")))
                    .map(|k| LaterRow {
                        kind: LaterKind::Ignored,
                        key: k,
                        file: "items.toml",
                    }),
            );
        }
        let audited = self
            .store
            .report
            .value
            .as_ref()
            .and_then(|r| r.as_deref())
            .and_then(|r| r.snapshot.taken_at);
        (later, audited)
    }

    fn undo(&mut self, row: &LaterRow, _sh: &mut Shared, cx: &Cx) -> Result<Vec<Effect>, String> {
        let name = &self.remote.name;
        match row.kind {
            LaterKind::Expected => Ok(vec![Own::expected(row.key.clone(), false)]),
            // A YAML item a review untracked: tracked again.
            LaterKind::Ignored if row.key.starts_with("item:") => {
                let id = row.key.trim_start_matches("item:");
                tracked::retrack(name, id).map_err(|e| format!("items.toml: {e}"))?;
                Ok(self.reload_config(cx))
            }
            LaterKind::Ignored => {
                tracked::unignore(name, &row.key).map_err(|e| format!("items.toml: {e}"))?;
                self.fetch(Kind::Maint, cx);
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    }

    fn settled(&mut self, cx: &Cx) -> Vec<Effect> {
        self.reread(cx)
    }
}

impl Asks for ServerTarget {
    fn ask(&self, sh: &Shared, cx: &Cx) -> Result<Ask, String> {
        let v = self.view(sh, cx);
        if cx.screen == ScreenId::Upgrade
            && let Some(s) = v.wf
        {
            return Ok(super::super::ask::ask_run(&v, &self.remote, s));
        }
        self.screens
            .ask(cx.screen, &v, &self.remote)
            .map_err(|_| super::super::ask::nothing_here(cx.screen, &v).to_string())
    }

    fn apply_ask(&self, sh: &Shared, cx: &Cx) -> Option<Ask> {
        super::super::ask::apply_ask(&self.view(sh, cx), &self.remote, &Self::steps_text(sh))
    }

    fn plan_ask(&self, item: &str, key: String, sh: &Shared, cx: &Cx) -> Option<Ask> {
        super::super::ask::apply_item(
            &self.view(sh, cx),
            &self.remote,
            item,
            key,
            &Self::steps_text(sh),
        )
    }

    /// The header of an item's plan, kept for the first time: what it moves from, its
    /// workflow and that workflow's values.
    fn plan_head(&self, key: &str, sh: &Shared, cx: &Cx) -> Option<crate::maint::plan::Head> {
        use super::super::screens::maint as m;
        let v = self.view(sh, cx);
        let (s, it) = m::status_of(&v, key).zip(m::item_of(&v, key))?;
        Some(m::plan_doc(&v, s, it, None).head)
    }

    fn review_brief(&self, cx: &Cx) -> Vec<Line<'static>> {
        let t = cx.theme;
        let name = &self.remote.name;
        let notes = &self.remote.cfg.maintenance.notes;
        vec![
            Line::raw(""),
            Line::styled(
                format!(
                    "  Claude reviews the maintenance of {name}: every tracked item, what isn't tracked,"
                ),
                t.fg(),
            ),
            Line::styled(
                "  tasks and what's put off, updates and reboots waiting, the maintenance log and upstream's",
                t.fg(),
            ),
            Line::styled(
                "  release notes, then writes what to do now, soon and routinely, and why.",
                t.fg(),
            ),
            Line::raw(""),
            Line::styled(
                "  It ends with how the list should change: tasks to add, remove or change, items to track",
                t.fg(),
            ),
            Line::styled(
                "  or stop tracking, and what can wait. You see those as one list, ticked; Enter applies them",
                t.fg(),
            ),
            Line::styled("  together.", t.fg()),
            Line::raw(""),
            Line::styled(
                format!(
                    "  It reads the web, your notes ({}), and {name} read-only through the gateway; reads",
                    if notes.is_empty() {
                        "none".to_string()
                    } else {
                        notes.join(", ")
                    }
                ),
                t.dim(),
            ),
            Line::styled(
                format!(
                    "  that need root are asked for first. Saved in {}.",
                    sentry_core::tui::widgets::short_home(&crate::maint::review::dir(name))
                ),
                t.dim(),
            ),
            Line::styled(
                "  Sent to Claude through your Claude Code login (Anthropic). Nothing on the server changes.",
                t.s(t.yellow),
            ),
            Line::raw(""),
            Line::styled("  Enter starts the review.", t.s(t.cyan)),
        ]
    }

    fn review_request(&self, auto: Option<&str>, changes: &str, sh: &Shared, cx: &Cx) -> String {
        let context =
            super::super::screens::maint::review_context(&self.view_all(sh, cx), &self.remote);
        match auto {
            Some(ask) => planview::auto_review_request(ask, &context, changes),
            None => planview::review_request(&context, changes),
        }
    }

    fn profile(&self, f: ProfileFor, grants: &[Grant]) -> Profile {
        let r = &self.remote;
        let (os, kernel) = self.store.host.value.clone().unwrap_or_default();
        let sudo = self.store.sudo.value;
        match f {
            // The gateway, plus the notes files, plus what the user granted.
            ProfileFor::Chat => super::super::ask::profile(r, &os, &kernel, sudo)
                .with_notes(&r.cfg.maintenance.notes)
                .with_log(&sentry_core::maint::log::dir(&r.name))
                .with_grants(grants),
            // An apply session researches what a plan document was written for: release
            // notes on the web, the notes files, the maintenance log.
            ProfileFor::Session => super::super::ask::with_web(
                super::super::ask::session_profile(r, &os, &kernel, sudo)
                    .with_notes(&r.cfg.maintenance.notes)
                    .with_log(&sentry_core::maint::log::dir(&r.name))
                    .with_grants(grants),
            ),
            ProfileFor::Review => planview::review_profile(r, &os, &kernel, sudo),
        }
    }

    fn waits_for_reads(&self, answer: &str) -> bool {
        planview::waits_for_reads(answer)
    }

    /// After a turn: if Claude asked to read things that need root, show them and ask.
    fn offer_reads(&mut self, to: ReadsFor, waiting: bool, cx: &Cx) -> Vec<Effect> {
        if cx.offline {
            return Vec::new();
        }
        let reads = crate::gateway::take_reads(&self.remote.name);
        if !reads.is_empty() {
            return self.root_reads(reads, to);
        }
        if waiting {
            // Nothing queued after all: have it write what it was writing.
            return vec![Effect::WriterFollow(planview::reads_skipped())];
        }
        Vec::new()
    }
}
