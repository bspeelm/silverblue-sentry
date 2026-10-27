//! Writing and reading execution plans: a separate flow from Ask Claude. Claude gets its own
//! instructions (gather the facts, then answer with only the plan document), runs in the
//! background, and its final answer becomes `plans/<item>.md`. The Plan view shows that file
//! as a document, with progress while Claude writes.

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph, Wrap};

use crate::claude::{Event, Profile};
use crate::server::maint::plan::{PlanDoc, PlanStatus};
use crate::server::remote::{Remote, SudoMode};
use crate::tui::theme::Theme;

/// Claude writing (or revising) one plan in the background.
pub struct Writer {
    pub item: String,
    pub doc: PlanDoc,
    /// Stream id and pid of the running turn.
    pub live: Option<(u64, u32)>,
    pub started: Instant,
    pub web: usize,
    pub files: usize,
    pub server: usize,
    /// What it's doing now, in a few words.
    pub doing: String,
    /// The turn's final answer (the plan), or why there's none.
    pub answer: Option<String>,
    pub err: Option<String>,
    pub session: Option<String>,
}

impl Writer {
    pub fn new(item: &str, doc: PlanDoc) -> Self {
        let session = doc.head.session.clone();
        Self {
            item: item.to_string(),
            doc,
            live: None,
            started: Instant::now(),
            web: 0,
            files: 0,
            server: 0,
            doing: "starting".into(),
            answer: None,
            err: None,
            session,
        }
    }

    pub fn running(&self) -> bool {
        self.live.is_some()
    }

    pub fn on_event(&mut self, e: Event) {
        match e {
            Event::Init { session_id } => self.session = Some(session_id),
            Event::Text(_) => self.doing = "writing".into(),
            Event::ToolUse { name, input } => {
                self.doing = match name.as_str() {
                    "WebFetch" | "WebSearch" => {
                        self.web += 1;
                        "reading release notes".into()
                    }
                    "Read" => {
                        self.files += 1;
                        "reading your notes".into()
                    }
                    _ => {
                        self.server += 1;
                        let cmd = input
                            .split(" -- ")
                            .nth(1)
                            .unwrap_or(&input)
                            .chars()
                            .take(40)
                            .collect::<String>();
                        format!("checking the server: {cmd}")
                    }
                }
            }
            Event::ToolResult { .. } => {}
            Event::Done {
                is_error, result, ..
            } => {
                if is_error {
                    self.err = Some(result);
                } else {
                    self.answer = Some(result);
                }
            }
        }
    }

    pub fn progress(&self) -> String {
        let s = self.started.elapsed().as_secs();
        format!(
            "{} · {} web page(s) · {} note file(s) · {} server read(s) · {}:{:02}",
            self.doing,
            self.web,
            self.files,
            self.server,
            s / 60,
            s % 60
        )
    }
}

/// Claude's instructions for writing a plan: not Ask Claude's (no length cap, no chat).
pub fn profile(r: &Remote, os: &str, kernel: &str, sudo: Option<SudoMode>) -> Profile {
    let mut p = super::ask::assess_profile(r, os, kernel, sudo);
    let name = &r.name;
    p.system = format!(
        "You write maintenance execution plans for the server `{name}` ({os}, kernel {kernel}), \
for the user's sentry-server. A plan is saved as a Markdown file and followed later, step by \
step, so it must stand on its own.\n\
First read the maintenance ledger named in the request (every earlier maintenance run on this \
server, a one-line summary and tags each): pick the runs that bear on this change (the same \
item or workflow, what it depends on or what depends on it, kernel, driver and engine changes, \
anything that failed or was done by hand), read those entries with Read, and use them: repeat \
what worked, plan around what went wrong, and name the entries you relied on.\n\
Then gather the facts: release notes and advisories with WebFetch and WebSearch (fetch the \
GitHub release pages given; never curl), the notes files named in the request with Read, and \
the server read-only, ONLY as `sentry-server exec {name} -- <command> <args>` (one command per \
call, no pipes; allowed: {}). If a read needs root and is refused, it's queued for the user to \
run with their password. Make every read you'll need first. If any was queued, DON'T write the \
plan yet: answer with only `READS PENDING` on the first line and one line saying what you're \
waiting for; the outputs come back to you, then you write the plan.\n\
Then answer with ONLY the plan document: no preamble, no remarks after it. As long as it needs to \
be. Its first line is `TARGET: <exact upstream tag>`, or `TARGET: wait` if it shouldn't move now; \
then `# Plan: <item> <from> → <to>` and the sections the request lists, with every command in \
a ```sh block. You never change anything on the server yourself.{}",
        crate::server::gateway::summary(),
        match sudo {
            Some(SudoMode::Password) => {
                " sudo on this server asks for a password: the user runs the commands that need it."
            }
            _ => "",
        }
    );
    p
}

/// What the first turn asks: the item, the workflow that will apply it, the target.
#[allow(clippy::too_many_arguments)]
pub fn request(
    context: &str,
    workflow: &str,
    steps: &str,
    goal: &str,
    note: Option<&str>,
) -> String {
    format!(
        "{context}\n\nThe workflow that will apply it ({workflow}), step by step:\n{steps}{}\n\n\
         Write the execution plan for {goal}. Sections, each with the exact commands:\n\
         ## Assessment: what changes (breaking changes, one-way migrations, security fixes), \
         whether the reason it's held still applies, and the real tier.\n\
         ## History: what the maintenance log says that bears on this (the entries you read, \
         by file name), or that it has nothing relevant.\n\
         ## Before: checks and backups to make first.\n\
         ## Change: the workflow's steps above, in order; what to expect at each confirm card, \
         and any manual commands between them.\n\
         ## Verify: what to check afterwards and what good looks like.\n\
         ## Roll back: how to undo it, and when it can't be undone.\n\
         ## When: whether it needs a window, and the expected downtime.",
        note.map_or(String::new(), |n| format!(
            "\nThe user's note for this plan: {n}"
        ))
    )
}

pub fn revise(what: &str) -> String {
    format!(
        "Revise the plan: {what}\nAnswer with the complete revised plan document in the same \
         format (the TARGET line first)."
    )
}

/// The user skipped the reads: write it with what there is.
pub fn reads_skipped() -> String {
    "The user didn't run the reads that need root. Write the plan now with what you have, and \
     say in it what couldn't be checked and how to check it by hand. Answer with the complete \
     plan document (the TARGET line first)."
        .into()
}

/// Claude stopped to wait for reads that need root (it hasn't written the plan yet).
pub fn waits_for_reads(answer: &str) -> bool {
    answer
        .trim_start()
        .to_ascii_uppercase()
        .starts_with("READS PENDING")
}

pub fn reads_back(outputs: &str) -> String {
    format!(
        "{outputs}\nTake these into account, then answer with the complete plan document in \
         the same format (the TARGET line first)."
    )
}

/// The Plan view: the item's plan as a document, or Claude's progress while it writes.
pub fn draw(
    f: &mut Frame,
    area: Rect,
    t: &Theme,
    doc: Option<&PlanDoc>,
    writer: Option<&Writer>,
    scroll: usize,
    path: &str,
) {
    f.render_widget(Clear, area);
    let [head, rule, body] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);
    let d = writer.map(|w| &w.doc).or(doc);
    let Some(d) = d else {
        f.render_widget(Paragraph::new(Line::styled("no plan", t.dim())), body);
        return;
    };
    let h = &d.head;
    let (status, color) = match (writer.is_some_and(|w| w.running()), h.status) {
        (true, _) => ("Claude is writing it", t.cyan),
        (_, PlanStatus::Ready) => ("ready to apply", t.green),
        (_, PlanStatus::Wait) => ("Claude advises waiting", t.yellow),
        (_, PlanStatus::Failed) => ("writing it failed", t.red),
        (_, s) => (s.word(), t.dim),
    };
    let target = h.to.clone().unwrap_or_else(|| {
        if h.vars.contains_key("unit") {
            "retire".into()
        } else {
            "?".into()
        }
    });
    let mut l1 = vec![
        Span::styled(
            " Plan ",
            Style::new()
                .fg(t.ink)
                .bg(t.mag)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "  {}  {} → {}",
                h.item,
                h.from.as_deref().unwrap_or("?"),
                target
            ),
            t.fg(),
        ),
        Span::styled(format!("  · {}", h.workflow), t.dim()),
        Span::styled(format!("  · {status}"), t.s(color)),
    ];
    if let Some(u) = h.updated.or(h.created) {
        l1.push(Span::styled(
            format!("  · {}", u.strftime("%Y-%m-%d %H:%M")),
            t.dim(),
        ));
    }
    let l2 = match writer.filter(|w| w.running()) {
        Some(w) => Line::styled(format!(" {}", w.progress()), t.s(t.cyan)),
        None => Line::styled(
            format!(
                " {}{}",
                path,
                h.note
                    .as_deref()
                    .map_or(String::new(), |n| format!("  · note: {n}"))
            ),
            t.dim(),
        ),
    };
    f.render_widget(Paragraph::new(vec![Line::from(l1), l2]), head);
    f.render_widget(
        Paragraph::new("─".repeat(rule.width as usize)).style(t.s(t.border)),
        rule,
    );
    let lines = if d.body.trim().is_empty() {
        vec![Line::styled(
            if writer.is_some_and(|w| w.running()) {
                "  The plan appears here when Claude has gathered what it needs and written it."
            } else {
                "  (empty)"
            },
            t.dim(),
        )]
    } else {
        markdown(t, &d.body)
    };
    // Scroll is lines from the top; clamp so the last page stays full.
    let max = lines.len().saturating_sub(body.height as usize);
    let top = scroll.min(max);
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((top as u16, 0)),
        body,
    );
}

/// Enough Markdown for a plan: headings, bullets, code blocks, **bold**.
pub fn markdown(t: &Theme, text: &str) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let mut code = false;
    for raw in text.lines() {
        let l = raw.trim_end();
        if l.trim_start().starts_with("```") {
            code = !code;
            continue;
        }
        if code {
            out.push(Line::from(vec![
                Span::styled("   │ ", t.s(t.border)),
                Span::styled(l.to_string(), t.s(t.cyan)),
            ]));
            continue;
        }
        let plain = l.replace("**", "");
        if let Some(h) = plain.strip_prefix("# ") {
            out.push(Line::styled(
                format!(" {h}"),
                Style::new().fg(t.fg).add_modifier(Modifier::BOLD),
            ));
        } else if let Some(h) = plain
            .strip_prefix("## ")
            .or_else(|| plain.strip_prefix("### "))
        {
            out.push(Line::raw(""));
            out.push(Line::styled(
                format!(" {h}"),
                Style::new().fg(t.mag).add_modifier(Modifier::BOLD),
            ));
        } else {
            out.push(Line::styled(format!(" {plain}"), t.fg()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_counts_what_claude_reads() {
        let mut w = Writer::new("web", PlanDoc::default());
        w.on_event(Event::ToolUse {
            name: "WebFetch".into(),
            input: "{}".into(),
        });
        w.on_event(Event::ToolUse {
            name: "Bash".into(),
            input: "sentry-server exec myserver -- docker ps".into(),
        });
        assert!(
            w.progress()
                .starts_with("checking the server: docker ps · 1 web page(s)")
        );
        w.on_event(Event::Done {
            is_error: false,
            result: "TARGET: 1.5.2\n# Plan".into(),
            cost: None,
        });
        assert_eq!(w.answer.as_deref(), Some("TARGET: 1.5.2\n# Plan"));
    }
}
