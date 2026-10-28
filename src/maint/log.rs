//! The maintenance log: what was maintained, when and how, written for the next person or
//! agent who plans a change. `log/` under [`super::root`]:
//!
//! - one file per workflow run, `YYYY-MM-DD-HHMM-<item|workflow>-<workflow>.md`: a `+++` TOML
//!   header with fixed fields and `key:value` tags (filter on those), then the steps as a
//!   table, what went wrong or was done by hand, the user's note, and the plan applied;
//! - `LOG.md`, an index of every entry, newest first, one table row each.
//!
//! Local only, never in git.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths;
use crate::workflows::Workflow;
use crate::workflows::state::{RunState, RunStatus, StepStatus};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogHead {
    /// The server it ran on (empty: this machine).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server: String,
    /// The maintenance item changed, when the run came from one.
    pub item: Option<String>,
    /// `image`, `packages`, `app`, `retire`, `release`, or `system` (no item).
    pub kind: String,
    pub workflow: String,
    /// `done` (ran to the end) or `abandoned`.
    pub result: String,
    pub from: Option<String>,
    pub to: Option<String>,
    /// low, medium or high (older entries say green/amber/red under `tier`).
    #[serde(alias = "tier")]
    pub risk: Option<String>,
    pub started: Option<jiff::Timestamp>,
    pub ended: Option<jiff::Timestamp>,
    pub duration_s: Option<i64>,
    /// Steps that failed, were done by hand, or were skipped by the user (ids).
    pub failed: Vec<String>,
    pub by_hand: Vec<String>,
    pub skipped: Vec<String>,
    /// The plan it applied (in plans/done/), and the run's own directory (step logs).
    pub plan: Option<String>,
    pub run: Option<String>,
    /// `server:myserver item:web kind:image workflow:compose-bump result:done risk:high …`
    pub tags: Vec<String>,
    /// One line for the ledger: the note's first line, or what went wrong.
    pub summary: String,
}

/// The ledger line: what an agent needs to decide whether to read the entry.
fn summarize(note: Option<&str>, h: &LogHead) -> String {
    let first = note
        .and_then(|n| n.lines().map(str::trim).find(|l| !l.is_empty()))
        .map(str::to_string);
    let problems = [
        (!h.failed.is_empty()).then(|| format!("failed: {}", h.failed.join(", "))),
        (!h.by_hand.is_empty()).then(|| format!("by hand: {}", h.by_hand.join(", "))),
        (!h.skipped.is_empty()).then(|| format!("skipped: {}", h.skipped.join(", "))),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("; ");
    match (first, problems.is_empty()) {
        (Some(n), true) => n,
        (Some(n), false) => format!("{n} ({problems})"),
        (None, false) => problems,
        (None, true) if h.result == "done" => "went as planned".into(),
        (None, true) => format!("{} without a note", h.result),
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LogEntry {
    pub head: LogHead,
    pub body: String,
}

/// What a run changed, when it came from a maintenance item.
#[derive(Debug, Clone, Default)]
pub struct ItemInfo {
    pub item: String,
    pub kind: String,
    pub risk: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub plan: Option<PathBuf>,
}

const FENCE: &str = "+++";

impl LogEntry {
    /// From a finished run: its steps, what failed or was done by hand, the note.
    pub fn from_run(
        server: &str,
        wf: &Workflow,
        st: &RunState,
        run_dir: &Path,
        info: Option<&ItemInfo>,
        note: Option<&str>,
    ) -> Self {
        let mut h = LogHead {
            server: server.to_string(),
            workflow: wf.name.clone(),
            result: match st.status {
                RunStatus::Done => "done",
                RunStatus::Abandoned => "abandoned",
                RunStatus::InProgress => "in-progress",
            }
            .into(),
            started: Some(st.started),
            ended: st.ended,
            duration_s: st.ended.map(|e| e.as_second() - st.started.as_second()),
            run: Some(run_dir.display().to_string()),
            kind: "system".into(),
            ..Default::default()
        };
        if let Some(i) = info {
            h.item = Some(i.item.clone());
            h.kind = i.kind.clone();
            h.risk = Some(i.risk.clone());
            h.from = i.from.clone();
            h.to = i.to.clone();
            h.plan = i.plan.as_ref().map(|p| p.display().to_string());
        }
        let mut rows = Vec::new();
        for (i, (step, s)) in wf.steps.iter().zip(&st.steps).enumerate() {
            let result = match s.status {
                StepStatus::Ok if s.note.as_deref() == Some("done by hand") => {
                    h.by_hand.push(step.id.clone());
                    "done by hand"
                }
                StepStatus::Ok => "ok",
                StepStatus::Failed => {
                    h.failed.push(step.id.clone());
                    "failed"
                }
                StepStatus::Skipped if s.note.as_deref() == Some("skipped by user") => {
                    h.skipped.push(step.id.clone());
                    "skipped"
                }
                StepStatus::Skipped => "not needed",
                StepStatus::Pending => "not reached",
                StepStatus::Running => "interrupted",
            };
            let when = s
                .ended
                .or(s.started)
                .map_or(String::new(), |t| t.strftime("%H:%M").to_string());
            rows.push(format!(
                "| {} | {} | {result} | {} | {when} | {} |",
                i + 1,
                cell(&format!(
                    "{} (`{}`)",
                    crate::workflows::runner::preview(st, &step.title),
                    step.id
                )),
                s.code.map_or(String::new(), |c| c.to_string()),
                cell(s.note.as_deref().unwrap_or(""))
            ));
        }
        h.tags = [
            Some(if server.is_empty() {
                "machine:local".to_string()
            } else {
                format!("server:{server}")
            }),
            h.item.as_ref().map(|i| format!("item:{i}")),
            Some(format!("kind:{}", h.kind)),
            Some(format!("workflow:{}", h.workflow)),
            Some(format!("result:{}", h.result)),
            h.risk.as_ref().map(|t| format!("risk:{t}")),
            h.to.as_ref().map(|t| format!("to:{t}")),
            (!h.failed.is_empty()).then(|| "had:failed-steps".to_string()),
            (!h.by_hand.is_empty()).then(|| "had:manual-steps".to_string()),
            st.vars.get("service").map(|s| format!("service:{s}")),
        ]
        .into_iter()
        .flatten()
        .collect();
        let title = title(&h);
        let mut body = format!("# {title}\n\n## Summary\n\n");
        body.push_str(note.filter(|n| !n.trim().is_empty()).unwrap_or("(no note)"));
        body.push_str("\n\n## Steps\n\n| # | Step | Result | Exit | Time | Note |\n|---|---|---|---|---|---|\n");
        body.push_str(&rows.join("\n"));
        body.push('\n');
        let vars: Vec<String> = st
            .vars
            .iter()
            .map(|(k, v)| format!("- `{k}` = `{v}`"))
            .collect();
        if !vars.is_empty() {
            body.push_str("\n## Values\n\n");
            body.push_str(&vars.join("\n"));
            body.push('\n');
        }
        body.push_str("\n## Records\n\n");
        if let Some(p) = &h.plan {
            body.push_str(&format!("- Plan applied: `{p}`\n"));
        }
        body.push_str(&format!("- Step logs: `{}/steps/`\n", run_dir.display()));
        h.summary = summarize(note, &h);
        Self {
            head: h,
            body: body.trim_end().to_string(),
        }
    }

    /// A task from a review done by hand (`d` on Maintenance): tagged `task:<id>`, which is
    /// what marks it done.
    pub fn task(server: &str, id: &str, title: &str, note: Option<&str>) -> Self {
        let mut e = Self::by_hand(server, id, "task", None, None, None, note);
        e.head.tags.push(format!("task:{id}"));
        e.body = e.body.replace(
            "Carried out by hand from the plan (no workflow run).",
            &format!("Done by hand: {title} (a task from a review; no workflow run)."),
        );
        e
    }

    /// A change made by hand from a plan (no workflow run): what it was, the plan, the note.
    pub fn by_hand(
        server: &str,
        item: &str,
        kind: &str,
        from: Option<String>,
        to: Option<String>,
        plan: Option<&Path>,
        note: Option<&str>,
    ) -> Self {
        let now = jiff::Timestamp::now();
        let mut h = LogHead {
            server: server.to_string(),
            item: Some(item.to_string()),
            kind: kind.to_string(),
            workflow: "by-hand".into(),
            result: "done".into(),
            from,
            to,
            started: Some(now),
            ended: Some(now),
            plan: plan.map(|p| p.display().to_string()),
            ..Default::default()
        };
        h.tags = [
            Some(if server.is_empty() {
                "machine:local".to_string()
            } else {
                format!("server:{server}")
            }),
            Some(format!("item:{item}")),
            Some(format!("kind:{kind}")),
            Some("workflow:by-hand".to_string()),
            Some("result:done".to_string()),
            h.to.as_ref().map(|t| format!("to:{t}")),
            Some("had:manual-steps".to_string()),
        ]
        .into_iter()
        .flatten()
        .collect();
        let mut body = format!("# {}\n\n## Summary\n\n", title(&h));
        body.push_str(note.filter(|n| !n.trim().is_empty()).unwrap_or("(no note)"));
        body.push_str("\n\n## Steps\n\nCarried out by hand from the plan (no workflow run).\n");
        if let Some(p) = &h.plan {
            body.push_str(&format!("\n## Records\n\n- Plan applied: `{p}`\n"));
        }
        h.summary = summarize(note, &h);
        Self {
            head: h,
            body: body.trim_end().to_string(),
        }
    }

    pub fn to_md(&self) -> String {
        format!(
            "{FENCE}\n{}{FENCE}\n\n{}\n",
            toml::to_string(&self.head).unwrap_or_default(),
            self.body.trim_end()
        )
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let rest = text
            .strip_prefix(FENCE)
            .ok_or("no +++ header")?
            .trim_start_matches(['\r', '\n']);
        let end = rest
            .find(&format!("\n{FENCE}"))
            .ok_or("unterminated header")?;
        let head: LogHead = toml::from_str(&rest[..end]).map_err(|e| e.to_string())?;
        Ok(Self {
            head,
            body: rest[end + 1 + FENCE.len()..].trim().to_string(),
        })
    }

    pub fn file_name(&self) -> String {
        let when = self
            .head
            .ended
            .or(self.head.started)
            .map(|t| t.strftime("%Y-%m-%d-%H%M").to_string())
            .unwrap_or_else(|| "undated".into());
        let what = self.head.item.as_deref().unwrap_or(&self.head.workflow);
        if what == self.head.workflow {
            format!("{when}-{what}.md")
        } else {
            format!("{when}-{what}-{}.md", self.head.workflow)
        }
    }

    /// One line for an agent's context: when, what, how, result, and the file.
    pub fn line(&self) -> String {
        let h = &self.head;
        format!(
            "{} · {} · {}{}",
            h.ended
                .or(h.started)
                .map_or("?".into(), |t| t.strftime("%Y-%m-%d").to_string()),
            title(h),
            if h.failed.is_empty() && h.by_hand.is_empty() {
                String::new()
            } else {
                format!(
                    "failed: {} · by hand: {} · ",
                    list_or_none(&h.failed),
                    list_or_none(&h.by_hand)
                )
            },
            self.file_name()
        )
    }
}

fn list_or_none(v: &[String]) -> String {
    if v.is_empty() {
        "none".into()
    } else {
        v.join(", ")
    }
}

fn title(h: &LogHead) -> String {
    let what = match (&h.item, &h.from, &h.to) {
        (Some(i), Some(f), Some(t)) => format!("{i} {f} → {t}"),
        (Some(i), _, None) if h.kind == "retire" => format!("{i} retired"),
        (Some(i), _, _) => i.clone(),
        (None, ..) => return format!("{} · {}", h.workflow, h.result),
    };
    format!("{what} · {} · {}", h.workflow, h.result)
}

/// A table cell: no pipes or line breaks.
fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

pub fn dir(server: &str) -> PathBuf {
    super::root(server).join("log")
}

/// Write an entry (replacing the same run's earlier one) and the index.
pub fn write(entry: &LogEntry) -> anyhow::Result<PathBuf> {
    let d = dir(&entry.head.server);
    std::fs::create_dir_all(&d)?;
    // The same run logged again (a note added): replace it.
    for old in list(&entry.head.server) {
        if old.head.run.is_some() && old.head.run == entry.head.run {
            let _ = std::fs::remove_file(d.join(old.file_name()));
        }
    }
    let p = d.join(entry.file_name());
    paths::write_atomic(&p, entry.to_md().as_bytes())?;
    write_index(&entry.head.server)?;
    Ok(p)
}

/// Write `new` in place of `old` (a note added to an entry that has no run to match on).
pub fn write_replacing(old: &LogEntry, new: &LogEntry) -> anyhow::Result<PathBuf> {
    let _ = std::fs::remove_file(dir(&old.head.server).join(old.file_name()));
    write(new)
}

/// Every entry, newest first.
pub fn list(server: &str) -> Vec<LogEntry> {
    list_in(&dir(server))
}

pub fn list_in(d: &Path) -> Vec<LogEntry> {
    let mut v: Vec<LogEntry> = std::fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|x| x == "md") && p.file_name().is_some_and(|n| n != "LOG.md")
        })
        .filter_map(|p| LogEntry::parse(&std::fs::read_to_string(p).ok()?).ok())
        .collect();
    v.sort_by_key(|e| std::cmp::Reverse(e.head.ended.or(e.head.started)));
    v
}

/// An item's entries, newest first.
pub fn for_item(server: &str, item: &str) -> Vec<LogEntry> {
    list(server)
        .into_iter()
        .filter(|e| e.head.item.as_deref() == Some(item))
        .collect()
}

fn write_index(server: &str) -> anyhow::Result<()> {
    write_index_in(&dir(server), server)
}

/// Rewrite `LOG.md` in `d` from the entries there.
pub fn write_index_in(d: &Path, server: &str) -> anyhow::Result<()> {
    let text = ledger(server, &list_in(d));
    paths::write_atomic(&d.join("LOG.md"), text.as_bytes())?;
    Ok(())
}

/// The ledger's text: what each entry is, enough to choose which to read.
pub fn ledger(server: &str, entries: &[LogEntry]) -> String {
    let server = super::label(server);
    let mut s = format!(
        "# Maintenance ledger · {server}\n\n\
         Every maintenance run on {server}, newest first: start here. Pick the rows that bear on \
         what you're doing (the same item, the same workflow, what it depends on or what depends \
         on it, kernel, driver and engine changes, anything that failed or was done by hand), \
         then read those entries for their steps and notes.\n\n\
         Each entry is a Markdown file in this directory with a `+++` TOML header: `item`, \
         `kind` (image, packages, app, retire, release, system), `workflow`, `result` (done, \
         abandoned), `from`/`to`, `started`/`ended`, the steps that `failed`, were done \
         `by_hand` or `skipped`, the `plan` it applied, a one-line `summary`, and `tags` \
         (`item:`, `kind:`, `workflow:`, `result:`, `risk:`, `to:`, `service:`, \
         `had:failed-steps`, `had:manual-steps`).\n\n\
         | When | Item | Kind | Change | Workflow | Result | Summary | Tags | Entry |\n\
         |---|---|---|---|---|---|---|---|---|\n"
    );
    for e in entries {
        let h = &e.head;
        let change = match (&h.from, &h.to) {
            (Some(f), Some(t)) => format!("{f} → {t}"),
            _ if h.kind == "retire" => "retired".into(),
            _ => String::new(),
        };
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | [{}]({}) |\n",
            h.ended
                .or(h.started)
                .map_or("?".into(), |t| t.strftime("%Y-%m-%d %H:%M").to_string()),
            h.item.as_deref().unwrap_or("-"),
            h.kind,
            cell(&change),
            h.workflow,
            h.result,
            cell(&h.summary),
            cell(&h.tags.join(" ")),
            e.file_name(),
            e.file_name()
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflows::state::StepState;

    fn run() -> (Workflow, RunState) {
        let wf = crate::workflows::parse(
            "name = \"compose-bump\"\ndescription = \"x\"\n\
             [[steps]]\nid = \"pin\"\ntitle = \"Change the pin of {{ service }}\"\nrun = \"true\"\n\
             [[steps]]\nid = \"copy\"\ntitle = \"Copy | its data\"\nrun = \"true\"\noptional = true\n\
             [[steps]]\nid = \"verify\"\ntitle = \"Healthy\"\nrun = \"true\"\n",
        )
        .unwrap();
        let t = |s: &str| -> jiff::Timestamp { s.parse().unwrap() };
        let step = |id: &str, status, note: Option<&str>| StepState {
            id: id.into(),
            status,
            code: Some(0),
            started: Some(t("2026-10-27T15:00:00Z")),
            ended: Some(t("2026-10-27T15:01:00Z")),
            boot_id: None,
            dry_ok: false,
            note: note.map(str::to_string),
        };
        let st = RunState {
            workflow: "compose-bump".into(),
            status: RunStatus::Done,
            started: t("2026-10-27T15:00:00Z"),
            ended: Some(t("2026-10-27T15:04:30Z")),
            vars: [("service".to_string(), "web".to_string())].into(),
            conds: Default::default(),
            steps: vec![
                step("pin", StepStatus::Ok, None),
                step("copy", StepStatus::Skipped, Some("skipped by user")),
                step("verify", StepStatus::Ok, Some("done by hand")),
            ],
        };
        (wf, st)
    }

    #[test]
    fn a_change_by_hand_is_logged_with_its_plan() {
        let e = LogEntry::by_hand(
            "myserver",
            "gpu-driver",
            "packages",
            Some("550".into()),
            Some("580".into()),
            Some(Path::new("/p/plans/done/gpu-driver-1.md")),
            Some("rebooted twice"),
        );
        assert_eq!(e.head.workflow, "by-hand");
        assert!(e.head.tags.contains(&"workflow:by-hand".to_string()));
        assert!(e.body.contains("rebooted twice") && e.body.contains("gpu-driver-1.md"));
        assert_eq!(e.head.summary, "rebooted twice");
        assert_eq!(LogEntry::parse(&e.to_md()).unwrap(), e);
        assert!(
            e.file_name().ends_with("-gpu-driver-by-hand.md"),
            "{}",
            e.file_name()
        );
    }

    #[test]
    fn a_local_entry_names_no_server() {
        let (wf, st) = run();
        let e = LogEntry::from_run(
            super::super::LOCAL,
            &wf,
            &st,
            Path::new("/r/run-1"),
            None,
            None,
        );
        let md = e.to_md();
        assert!(!md.contains("server ="), "{md}");
        assert!(e.head.tags.contains(&"machine:local".to_string()));
        assert_eq!(LogEntry::parse(&md).unwrap(), e);
        assert!(ledger("", &[e]).starts_with("# Maintenance ledger · this machine"));
    }

    #[test]
    fn a_run_becomes_a_tagged_entry() {
        let (wf, st) = run();
        let info = ItemInfo {
            item: "web".into(),
            kind: "image".into(),
            risk: "high".into(),
            from: Some("1.4.2".into()),
            to: Some("1.5.2".into()),
            plan: Some("/p/plans/done/web-1.md".into()),
        };
        let e = LogEntry::from_run(
            "myserver",
            &wf,
            &st,
            Path::new("/r/run-1"),
            Some(&info),
            Some("health check took 90 s; caddy 502 meanwhile"),
        );
        let h = &e.head;
        assert_eq!(h.result, "done");
        assert_eq!(h.duration_s, Some(270));
        assert_eq!(
            (h.by_hand.clone(), h.skipped.clone()),
            (vec!["verify".to_string()], vec!["copy".to_string()])
        );
        for t in [
            "item:web",
            "kind:image",
            "workflow:compose-bump",
            "result:done",
            "risk:high",
            "to:1.5.2",
            "had:manual-steps",
            "service:web",
        ] {
            assert!(h.tags.contains(&t.to_string()), "{t} in {:?}", h.tags);
        }
        assert!(
            e.body
                .starts_with("# web 1.4.2 → 1.5.2 · compose-bump · done")
        );
        assert!(e.body.contains("health check took 90 s"));
        assert!(
            e.body
                .contains("| 2 | Copy \\| its data (`copy`) | skipped |"),
            "{}",
            e.body
        );
        assert!(e.body.contains("Plan applied: `/p/plans/done/web-1.md`"));
        assert_eq!(LogEntry::parse(&e.to_md()).unwrap(), e);
        assert_eq!(e.file_name(), "2026-10-27-1504-web-compose-bump.md");
        assert!(
            e.line().contains(
                "web 1.4.2 → 1.5.2 · compose-bump · done · failed: none · by hand: verify"
            )
        );
        assert_eq!(
            e.head.summary,
            "health check took 90 s; caddy 502 meanwhile (by hand: verify; skipped: copy)"
        );
    }

    #[test]
    fn step_titles_have_their_values_filled_in() {
        let (wf, st) = run();
        let e = LogEntry::from_run("myserver", &wf, &st, Path::new("/r/run-9"), None, None);
        assert!(
            e.body
                .contains("| 1 | Change the pin of web (`pin`) | ok |"),
            "{}",
            e.body
        );
    }

    #[test]
    fn a_run_without_an_item_is_system_maintenance() {
        let (wf, st) = run();
        let e = LogEntry::from_run("myserver", &wf, &st, Path::new("/r/run-2"), None, None);
        assert_eq!(e.head.kind, "system");
        assert!(e.head.item.is_none() && e.body.contains("(no note)"));
        assert_eq!(e.head.summary, "by hand: verify; skipped: copy");
        assert_eq!(e.file_name(), "2026-10-27-1504-compose-bump.md");
    }

    #[test]
    fn the_ledger_lists_every_entry_with_what_an_agent_needs() {
        let (wf, st) = run();
        let e = LogEntry::from_run(
            "myserver",
            &wf,
            &st,
            Path::new("/r/run-3"),
            None,
            Some("all fine"),
        );
        let text = ledger("myserver", &[e]);
        assert!(text.starts_with("# Maintenance ledger · myserver"));
        assert!(text.contains("start here"), "says how to use it");
        let row = text.lines().last().unwrap();
        assert!(
            row.starts_with("| 2026-10-27 15:04 | - | system |  | compose-bump | done |"),
            "{row}"
        );
        assert!(
            row.contains("| all fine (by hand: verify; skipped: copy) |"),
            "{row}"
        );
        assert!(
            row.contains("result:done") && row.contains("had:manual-steps"),
            "{row}"
        );
        assert!(
            row.ends_with("[2026-10-27-1504-compose-bump.md](2026-10-27-1504-compose-bump.md) |"),
            "{row}"
        );
    }
}
