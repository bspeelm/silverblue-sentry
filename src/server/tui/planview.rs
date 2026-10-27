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
use crate::tui::docview::markdown;
use crate::tui::theme::Theme;

/// Claude writing (or revising) one plan in the background.
pub struct Writer {
    pub item: String,
    pub doc: PlanDoc,
    /// Writing a maintenance review instead of a plan.
    pub review: Option<crate::server::maint::review::ReviewDoc>,
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
            review: None,
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

    /// A maintenance review, written the same way as a plan.
    pub fn review(doc: crate::server::maint::review::ReviewDoc) -> Self {
        let session = doc.head.session.clone();
        let mut w = Self::new(REVIEW, PlanDoc::default());
        w.session = session;
        w.review = Some(doc);
        w
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

/// The writer's item name while it writes a review.
pub const REVIEW: &str = "(review)";

/// Claude's instructions for a maintenance review.
pub fn review_profile(r: &Remote, os: &str, kernel: &str, sudo: Option<SudoMode>) -> Profile {
    let mut p = profile(r, os, kernel, sudo);
    let name = &r.name;
    p.system = format!(
        "You review the maintenance of the server `{name}` ({os}, kernel {kernel}) for the user's \
sentry-server: what to maintain next, and why. The review is saved as a Markdown file and acted \
on later, item by item.\n\
Start with the maintenance ledger named in the request (every earlier maintenance run, a \
one-line summary and tags each) and read the entries that bear on what's pending. Then use the \
standing of every tracked item given, release notes and advisories for anything with newer \
versions (WebFetch and WebSearch; never curl), the notes files named (Read), and the server \
read-only, ONLY as `sentry-server exec {name} -- <command> <args>` (one command per call, no \
pipes; allowed: {}). If a read needs root and is refused, it's queued for the user; make every \
read you need first, and if any was queued answer with only `READS PENDING` and one line saying \
what you're waiting for.\n\
Then answer with ONLY the review document: no preamble, no remarks after it. Its title is \
`# Maintenance review · {name}`, then the sections the request lists. Be concrete: name the item, \
the version, the workflow, and why now or why it can wait. You never change anything on the \
server yourself.",
        crate::server::gateway::summary()
    );
    p
}

/// What a review is asked.
pub fn review_request(context: &str) -> String {
    format!(
        "{context}\n\nReview the maintenance of this server. Sections:\n\
         ## Summary: two or three lines on where things stand.\n\
         ## Now: what to do first, one bullet each: the item, what to do (plan it to which \
         version, run which workflow), and why it can't wait.\n\
         ## Soon: the same, for the next weeks.\n\
         ## Routine: regular maintenance due, and what can simply wait (say why).\n\
         ## The list: what to start or stop tracking, sources to add, risk levels, holds and \
         review dates to revisit.\n\
         ## Watch: ends of life, upstream changes or anything else to look at again, with dates."
    )
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
         whether the reason it's held still applies, and how risky it really is (low, medium, high).\n\
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

/// The Review view: the latest maintenance review, or Claude's progress while it writes.
pub fn draw_review(
    f: &mut Frame,
    area: Rect,
    t: &Theme,
    doc: Option<&crate::server::maint::review::ReviewDoc>,
    writer: Option<&Writer>,
    scroll: usize,
) {
    f.render_widget(Clear, area);
    let [head, rule, body] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);
    let writing = writer.is_some_and(|w| w.running());
    let mut l1 = vec![Span::styled(
        " Maintenance review ",
        Style::new()
            .fg(t.ink)
            .bg(t.mag)
            .add_modifier(Modifier::BOLD),
    )];
    if let Some(d) = doc {
        l1.push(Span::styled(
            format!(
                "  {}",
                d.head
                    .updated
                    .or(d.head.created)
                    .map_or(String::new(), |u| u.strftime("%Y-%m-%d %H:%M").to_string())
            ),
            t.fg(),
        ));
    }
    let l2 = match writer.filter(|w| w.running()) {
        Some(w) => Line::styled(format!(" {}", w.progress()), t.s(t.cyan)),
        None => Line::styled(
            " what to maintain next, and why · R writes a new one",
            t.dim(),
        ),
    };
    f.render_widget(Paragraph::new(vec![Line::from(l1), l2]), head);
    f.render_widget(
        Paragraph::new("─".repeat(rule.width as usize)).style(t.s(t.border)),
        rule,
    );
    let lines = match doc {
        Some(d) if !writing => markdown(t, &d.body),
        Some(d) => {
            let mut l = vec![
                Line::styled(
                    "  Claude is writing a new review; the last one is below.",
                    t.s(t.cyan),
                ),
                Line::raw(""),
            ];
            l.extend(markdown(t, &d.body));
            l
        }
        None if writing => vec![Line::styled(
            "  The review appears here when Claude has gathered what it needs and written it.",
            t.dim(),
        )],
        None => vec![Line::styled("  No review yet: R writes one.", t.dim())],
    };
    let top = scroll.min(lines.len().saturating_sub(body.height as usize));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((top as u16, 0)),
        body,
    );
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
