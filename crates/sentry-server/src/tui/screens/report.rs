//! The audit report view (`F` on Maintenance): a report's findings with the selected one
//! explained, beside what changed since the report before. Drawn and moved around in by
//! `sentry_core::tui::reportview`, as sentry's is; the findings and what the keys do are the
//! server's.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;

use super::{Hints, View};
use crate::audit::Report;
use crate::tui::data::Kind;
use crate::tui::target::{Effect, Modal, Own};
use sentry_core::finding::{Finding, Sev};
use sentry_core::tui::keys::Action;
use sentry_core::tui::reportview::{self, Mark, Page, ReportView, Row};
use sentry_core::tui::theme::Theme;

/// The report on screen: the one the view asked for when it's been read, else the newest.
struct Shown<'a> {
    cur: &'a Report,
    prev: Option<&'a Report>,
    name: String,
    /// Where it is among the reports kept, and how many there are.
    idx: usize,
    n: usize,
}

fn shown<'a>(v: &View<'a>) -> Option<Shown<'a>> {
    if let Some(s) = &v.s.shown
        && let Some(cur) = s.cur.as_deref()
    {
        return Some(Shown {
            cur,
            prev: s.prev.as_deref(),
            name: s.names.get(s.idx).cloned().unwrap_or_default(),
            idx: s.idx,
            n: s.names.len(),
        });
    }
    let cur = v.s.report.value.as_ref()?.as_deref()?;
    Some(Shown {
        cur,
        prev: None,
        name: cur.snapshot.taken_at.map_or("the latest".into(), |t| {
            t.strftime("%Y-%m-%d-%H%M%S").to_string()
        }),
        idx: 0,
        n: 1,
    })
}

/// The findings listed: what the filter keeps, those to look at first.
fn rows<'a>(v: &View<'a>) -> Vec<&'a Finding> {
    let Some(s) = shown(v) else {
        return Vec::new();
    };
    let mut rows: Vec<&Finding> = s
        .cur
        .findings
        .iter()
        .filter(|f| v.matches(&[&f.message, &f.category, f.severity.as_str()]))
        .collect();
    rows.sort_by_key(|f| (f.expected, std::cmp::Reverse(f.severity)));
    rows
}

/// What / Why / To do / Fix, then the evidence and its id.
pub fn finding_lines(t: &Theme, fd: &Finding, width: usize) -> Vec<Line<'static>> {
    let fix = sentry_core::claude::available()
        .then_some("press Enter: Claude looks into it and plans the fix");
    let mut l = reportview::finding_lines(t, fd, width, fix);
    l.push(Line::styled(
        format!(
            "       {}{}",
            fd.id,
            if fd.expected {
                " · expected (x takes it back)"
            } else {
                ""
            }
        ),
        t.dim(),
    ));
    l
}

pub fn hints(v: &View) -> Hints {
    if shown(v).is_none() {
        return vec![("Esc", "back"), ("Enter", "run audit")];
    }
    vec![
        ("Esc", "back"),
        ("j/k", "select"),
        ("Enter", "fix (with Claude)"),
        ("x", "expected on/off"),
        ("B", "all like it"),
        ("c", "run audit"),
        ("[ ]", "browse reports"),
        ("C-h/l", "focus"),
    ]
}

fn audit_now() -> Vec<Effect> {
    vec![
        Own::fetch(Kind::Audit),
        Effect::Toast("auditing the server…".into()),
    ]
}

/// `B`: everything like this finding is expected too, asked first.
pub fn pattern_effects(v: &View, f: &Finding) -> Vec<Effect> {
    let Some((pattern, what)) = crate::audit::pattern_for(&f.id) else {
        return vec![Effect::Toast(
            "no broader pattern for this finding: x marks it expected".into(),
        )];
    };
    let t = v.t;
    vec![Effect::Confirm(Modal {
        title: "Baseline pattern".into(),
        color: t.yellow,
        lines: vec![
            Line::styled(format!("Treat {what} as expected?"), t.fg()),
            Line::styled(
                format!("servers/{}.baseline.toml ← {pattern}", v.name),
                t.dim(),
            ),
            Line::styled(
                "Future audits suppress matching findings. Edit the file to undo.",
                t.dim(),
            ),
        ],
        yes: Some(("add pattern".into(), vec![Own::expected(pattern, true)])),
    })]
}

pub fn handle(view: &mut ReportView, a: Action, v: &View) -> Vec<Effect> {
    let Some(s) = shown(v) else {
        return match a {
            Action::Enter | Action::Check => audit_now(),
            Action::Refresh => vec![Own::fetch(Kind::Report)],
            _ => Vec::new(),
        };
    };
    match a {
        Action::Check => return audit_now(),
        Action::Refresh => {
            view.report = None;
            return vec![Own::fetch(Kind::Report)];
        }
        _ => {}
    }
    // The view counts from the report that's on screen.
    view.report = (s.idx + 1 < s.n).then_some(s.idx);
    let rows = rows(v);
    if view.key(a, s.n, rows.len()) {
        // `[` `]`: another report, read from disk.
        return match view.idx(s.n) {
            Some(i) if i != s.idx => vec![Own::fetch(if i + 1 >= s.n {
                Kind::Report
            } else {
                Kind::ReportAt(i as u16)
            })],
            _ => Vec::new(),
        };
    }
    let Some(f) = rows.get(view.selected(rows.len())) else {
        return Vec::new();
    };
    match a {
        Action::Enter | Action::Char('f') => vec![Own::fix_finding(f.id.clone())],
        Action::Char('x' | 'b') => vec![Own::expected(f.id.clone(), !f.expected)],
        Action::Char('B') => pattern_effects(v, f),
        _ => Vec::new(),
    }
}

/// The finding selected in the view (for Ask Claude).
pub fn selected<'a>(view: &ReportView, v: &View<'a>) -> Option<&'a Finding> {
    let rows = rows(v);
    rows.get(view.cur.sel.min(rows.len().saturating_sub(1)))
        .copied()
}

/// What changed between two reports: findings that are new, findings that are gone, and
/// what this audit couldn't check.
fn changes(cur: &Report, prev: Option<&Report>) -> Vec<(Mark, String)> {
    let line = |f: &Finding| {
        format!(
            "  {:<7}{}",
            match f.severity {
                Sev::High => "check",
                Sev::Medium => "review",
                Sev::Low => "info",
            },
            f.message
        )
    };
    let mut out = Vec::new();
    match prev {
        None => out.push((
            Mark::Same,
            "Nothing to compare against yet. The next audit is compared with this one.".to_string(),
        )),
        Some(p) => {
            let new: Vec<&Finding> = cur
                .findings
                .iter()
                .filter(|f| !p.findings.iter().any(|x| x.id == f.id))
                .collect();
            let gone: Vec<&Finding> = p
                .findings
                .iter()
                .filter(|f| !cur.findings.iter().any(|x| x.id == f.id))
                .collect();
            if new.is_empty() && gone.is_empty() {
                out.push((
                    Mark::Section,
                    "Nothing changed since the previous audit.".to_string(),
                ));
            } else {
                out.push((
                    Mark::Section,
                    format!("Changed: {} new, {} gone", new.len(), gone.len()),
                ));
            }
            if !new.is_empty() {
                out.push((Mark::Same, String::new()));
                out.push((Mark::Section, "New since the previous audit".into()));
                out.extend(
                    new.iter()
                        .map(|f| (Mark::Add, format!("+{}", &line(f)[1..]))),
                );
            }
            if !gone.is_empty() {
                out.push((Mark::Same, String::new()));
                out.push((Mark::Section, "Gone since the previous audit".into()));
                out.extend(
                    gone.iter()
                        .map(|f| (Mark::Remove, format!("-{}", &line(f)[1..]))),
                );
            }
        }
    }
    if !cur.snapshot.errors.is_empty() {
        out.push((Mark::Same, String::new()));
        out.push((Mark::Section, "Not checked".into()));
        out.extend(
            cur.snapshot
                .errors
                .iter()
                .map(|(sec, e)| (Mark::Change, format!("  {sec}: {e}"))),
        );
    }
    out
}

pub fn draw(view: &mut ReportView, f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    let Some(s) = shown(v) else {
        reportview::draw_placeholder(
            f,
            area,
            t,
            v.s.report.value.is_none() && v.s.report.err.is_none(),
            "Press Enter to run one. It only reads, and takes a few seconds.",
            "Reports are kept in ~/.local/share/sentry/servers/<name>/reports/.",
        );
        return;
    };
    let rows = rows(v);
    let open = |sev: Sev| {
        s.cur
            .findings
            .iter()
            .filter(|f| !f.expected && f.severity == sev)
            .count()
    };
    let page = Page {
        name: s.name.clone(),
        pos: (s.n > 1).then_some((s.idx + 1, s.n)),
        header: "Worth a look on this server.",
        keys: "Enter = fix it (Claude helps) · x = expected on/off · A = ask Claude · c = audit again",
        rows: rows
            .iter()
            .map(|fd| Row {
                finding: fd,
                expected: fd.expected,
            })
            .collect(),
        empty: if s.cur.findings.is_empty() {
            "Nothing to report."
        } else {
            "No findings match the filter."
        },
        counts: (open(Sev::High), open(Sev::Medium), open(Sev::Low)),
        not_collected: s
            .cur
            .snapshot
            .errors
            .iter()
            .map(|(k, _)| k.clone())
            .collect(),
        detail: &|fd, w| finding_lines(t, fd, w),
        changes_name: "Changes",
        changes_title: match s.prev {
            Some(_) => "since the audit before".into(),
            None => "first report".into(),
        },
        changes: changes(s.cur, s.prev),
    };
    view.draw(f, area, t, &page);
}
