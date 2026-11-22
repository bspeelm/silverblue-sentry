//! Audit: findings of the selected report with an evidence box, and the structural diff against
//! the report before it. `Enter` fixes the finding (as on Maintenance), `c` audits now (read-only), `x`/`B` baseline, `[`/`]` browse.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};

use super::{Hints, View, sentry_cmd};
use crate::audit::Finding;
use crate::audit::diff::{self, Kind};
use crate::audit::findings::is_expected;
use crate::audit::store::Stored;
use crate::exec::Cmd;
use crate::tui::app::{BaselineEdit, Effect, Modal, RunSpec};
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::reportview::{self, Mark, Page, ReportView, Row};

/// The report view's state (drawn and moved around in by `tui::reportview`).
#[derive(Default)]
pub struct Audit {
    view: ReportView,
}

pub fn hints(v: &View) -> Hints {
    if v.d.reports.get().is_none_or(|r| r.is_empty()) {
        return vec![("Enter", "run audit")];
    }
    // The same keys as a finding on Maintenance (f and b still work).
    vec![
        ("j/k", "select"),
        (
            "Enter",
            if crate::claude::available() {
                "fix (with Claude)"
            } else {
                "fix"
            },
        ),
        ("x", "expected on/off"),
        ("B", "all like it"),
        ("c", "run audit"),
        ("[ ]", "browse reports"),
        ("C-h/l", "focus"),
    ]
}

/// `sentry job audit`, streamed. Same binary, so headless and TUI runs are identical.
pub fn audit_run() -> Effect {
    Effect::Run(RunSpec {
        title: "sentry job audit".into(),
        cmd: sentry_cmd(&["job", "audit"]),
        queue: Vec::new(),
        then: vec![Fetch::Reports, Fetch::Log],
        ok_toast: "audit complete".into(),
        log: None,
    })
}

/// `b`: mark the finding expected, or un-mark it if it already is.
pub fn expected_toggle(v: &View, f: &Finding) -> Effect {
    let edit = if !f.listeners.is_empty() {
        BaselineEdit::Listeners(f.listeners.clone())
    } else {
        match f.id.strip_prefix("listener:") {
            Some(k) => BaselineEdit::Listener(k.to_string()),
            None => BaselineEdit::Finding(f.id.clone()),
        }
    };
    if is_expected(f, &v.d.baseline) {
        Effect::Unbaseline(edit)
    } else {
        Effect::Baseline(edit)
    }
}

/// `B`: treat every finding like this one as expected (a baseline pattern), asked first.
pub fn pattern_effects(v: &View, f: &Finding) -> Vec<Effect> {
    let Some((edit, what)) = pattern_for(f) else {
        return vec![Effect::Toast(
            "no broader pattern for this finding — use b".into(),
        )];
    };
    let t = v.t;
    vec![Effect::Confirm(Modal {
        title: "Baseline pattern".into(),
        color: t.yellow,
        lines: vec![
            Line::styled(format!("Treat {what} as expected?"), t.fg()),
            Line::styled(format!("baseline.toml ← {}", edit.value()), t.dim()),
            Line::styled(
                "Future audits suppress matching findings. Edit the file to undo.",
                t.dim(),
            ),
        ],
        yes: Some(("add pattern".into(), vec![Effect::Baseline(edit)])),
    })]
}

/// What / Why / To do / Fix for a finding, wrapped to `width`, then its evidence.
pub fn finding_lines(
    t: &crate::tui::theme::Theme,
    fd: &Finding,
    width: usize,
    fix_key: &str,
) -> Vec<Line<'static>> {
    let fixes = crate::audit::fix::fixes(fd);
    let labels: Vec<&str> = fixes.iter().map(|x| x.label.as_str()).collect();
    let fix = if crate::claude::available() {
        let mut l = format!("press {fix_key}: Claude looks into it and tells you what to run");
        if !labels.is_empty() {
            l.push_str(&format!(" (known fixes: {})", labels.join(" · ")));
        }
        Some(l)
    } else if !labels.is_empty() {
        Some(format!("press {fix_key}: {}", labels.join(" · ")))
    } else {
        None
    };
    reportview::finding_lines(t, fd, width, fix.as_deref())
}

/// `f`: the finding's fixes as a confirm box (one) or a numbered choice (several).
pub fn fix_effects(v: &View, f: &Finding) -> Vec<Effect> {
    use crate::audit::fix::{self, Act};
    let t = v.t;
    let fixes = fix::fixes(f);
    if fixes.is_empty() {
        return vec![Effect::Toast(fix::no_fix_reason(f).into())];
    }
    let to_effects = |x: &fix::Fix| -> Result<Vec<Effect>, String> {
        let reaudit = if x.inspect { vec![] } else { vec![audit_run()] };
        Ok(match &x.act {
            Act::Shell { cmd, sudo } => {
                let mut queue = Vec::new();
                if !x.inspect {
                    queue.push(sentry_cmd(&["job", "audit"]));
                }
                let spec = RunSpec {
                    title: x.label.clone(),
                    cmd: Cmd::host("bash").args(["-c", cmd]).timeout(None),
                    queue,
                    then: vec![Fetch::Reports, Fetch::Log],
                    ok_toast: if x.inspect {
                        "done".into()
                    } else {
                        "fixed · audited again".into()
                    },
                    log: None,
                };
                // With sudo: the same pane, the password asked once (never the terminal).
                vec![if *sudo {
                    Effect::RunRoot(spec, cmd.clone())
                } else {
                    Effect::Run(spec)
                }]
            }
            Act::Edit { path, line } => {
                let editor = std::env::var("VISUAL")
                    .or_else(|_| std::env::var("EDITOR"))
                    .unwrap_or_else(|_| "nano".into());
                let path = path.replacen('~', &crate::paths::home().display().to_string(), 1);
                vec![Effect::Interactive(
                    Cmd::local(&editor)
                        .arg(format!("+{line}"))
                        .arg(path)
                        .timeout(None),
                    reaudit,
                )]
            }
            Act::Open(slug) => match crate::tui::SCREENS.from_name(slug) {
                Some(id) => vec![Effect::Goto(id)],
                None => vec![],
            },
            Act::Cleanup(job) => vec![Effect::CleanupFocus(*job)],
        })
    };
    let describe = |x: &fix::Fix| -> Vec<Line<'static>> {
        let mut l = Vec::new();
        match &x.act {
            Act::Shell { cmd, sudo } => {
                l.push(Line::styled(
                    format!("$ {cmd}"),
                    t.s(if x.risky { t.red } else { t.fg }),
                ));
                if *sudo {
                    l.push(Line::styled(
                        "Needs sudo: your password is asked for here, once.",
                        t.dim(),
                    ));
                }
            }
            Act::Edit { path, line } => l.push(Line::styled(
                format!("opens {path} at line {line} in $EDITOR"),
                t.fg(),
            )),
            Act::Open(slug) => l.push(Line::styled(format!("goes to the {slug} tab"), t.fg())),
            Act::Cleanup(job) => l.push(Line::styled(
                format!(
                    "opens Cleanup with {} selected (you confirm there)",
                    job.name()
                ),
                t.fg(),
            )),
        }
        if let Some(u) = &x.undo {
            l.push(Line::styled(format!("undo: {u}"), t.dim()));
        }
        l
    };
    if fixes.len() == 1 {
        let x = &fixes[0];
        let effects = match to_effects(x) {
            Ok(e) => e,
            Err(why) => return vec![Effect::Toast(why)],
        };
        let mut lines = vec![
            Line::styled(f.message.clone(), t.fg()),
            Line::styled(format!("→ {}", x.label), t.s(t.cyan)),
        ];
        lines.extend(describe(x));
        if !x.inspect && matches!(x.act, Act::Shell { .. } | Act::Edit { .. }) {
            lines.push(Line::styled(
                "Afterwards sentry audits again so you can see it's gone.",
                t.dim(),
            ));
        }
        return vec![Effect::Confirm(Modal {
            title: "Fix".into(),
            color: if x.risky { t.red } else { t.yellow },
            lines,
            yes: Some(("run it".into(), effects)),
        })];
    }
    let mut lines = vec![Line::styled(f.message.clone(), t.fg()), Line::raw("")];
    let mut options = Vec::new();
    for (i, x) in fixes.iter().enumerate() {
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {} ", i + 1),
                ratatui::style::Style::new().fg(t.ink).bg(t.yellow),
            ),
            Span::styled(format!(" {}", x.label), t.s(t.cyan)),
        ]));
        for d in describe(x) {
            let spans: Vec<Span> = std::iter::once(Span::raw("    ")).chain(d.spans).collect();
            lines.push(Line::from(spans));
        }
        match to_effects(x) {
            Ok(e) => options.push((x.label.clone(), e)),
            Err(why) => options.push((format!("{} (unavailable: {why})", x.label), vec![])),
        }
    }
    lines.push(Line::raw(""));
    vec![Effect::Choose(crate::tui::app::Choice {
        title: "Fix · pick one (1–9, n cancels)".into(),
        lines,
        options,
    })]
}

/// Broader baseline pattern for `B`: same process on any address, same app any permission, …
pub fn pattern_for(f: &Finding) -> Option<(BaselineEdit, String)> {
    let id = f.id.as_str();
    let (kind, rest) = id.split_once(':')?;
    let (p, what) = match kind {
        "flatpak-perm" => {
            let app = rest.split(':').next()?;
            (
                format!("flatpak-perm:{app}:*"),
                format!("every flagged permission of {app}"),
            )
        }
        "repo" | "repos" => ("repo*".into(), "every third-party repo finding".into()),
        "unit-failed" => {
            let scope = rest.split(':').next()?;
            (
                format!("unit-failed:{scope}:*"),
                format!("every failed {scope} unit"),
            )
        }
        "flatpak-gl-stale" => (
            "flatpak-gl-stale:*".into(),
            "every stale GL extension".into(),
        ),
        _ => return None,
    };
    Some((BaselineEdit::Finding(p), what))
}

impl Audit {
    fn reports<'a>(&self, v: &View<'a>) -> &'a [Stored] {
        v.d.reports.get().map_or(&[], |r| r.as_slice())
    }

    fn idx(&self, n: usize) -> Option<usize> {
        self.view.idx(n)
    }

    fn rows<'a>(&self, v: &View<'a>) -> Vec<&'a Finding> {
        let all = self.reports(v);
        let Some(i) = self.idx(all.len()) else {
            return Vec::new();
        };
        let b = &v.d.baseline;
        let mut rows: Vec<&Finding> = all[i]
            .report
            .findings
            .iter()
            .filter(|f| v.matches(&[&f.message, &f.category, f.severity.as_str()]))
            .collect();
        // The current baseline decides what's expected (b takes effect immediately).
        rows.sort_by_key(|f| (is_expected(f, b), std::cmp::Reverse(f.severity)));
        rows
    }

    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        let n = self.reports(v).len();
        match a {
            // No report yet: Enter runs the first audit; c always does.
            Action::Enter if n == 0 => return vec![audit_run()],
            Action::Check => return vec![audit_run()],
            Action::Refresh => return vec![Effect::Fetch(Fetch::Reports)],
            _ => {}
        }
        let rows = self.rows(v);
        if self.view.key(a, n, rows.len()) {
            return Vec::new();
        }
        let Some(f) = rows.get(self.view.selected(rows.len())) else {
            return Vec::new();
        };
        match a {
            // Claude reads the logs and says what to run; without it, sentry's own list.
            Action::Enter | Action::Char('f') if crate::claude::available() => {
                vec![Effect::AskConsent(crate::audit::fix::ask(f))]
            }
            Action::Enter | Action::Char('f') => fix_effects(v, f),
            // `x` toggles: marks the finding expected, or un-marks it if it already is.
            Action::Char('x' | 'b') => vec![expected_toggle(v, f)],
            Action::Char('B') => pattern_effects(v, f),
            _ => Vec::new(),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        let all = self.reports(v);
        let Some(i) = self.idx(all.len()) else {
            reportview::draw_placeholder(
                f,
                area,
                t,
                v.d.loading(Fetch::Reports),
                "Press Enter to run one. It's read-only and takes about a second.",
                "Reports are kept in ~/.local/share/sentry/reports/ (json + md).",
            );
            return;
        };
        let cur = &all[i];
        let prev = i.checked_sub(1).map(|j| &all[j]);
        let b = &v.d.baseline;
        let c = cur.report.counts(b);
        let rows = self.rows(v);
        let changes: Vec<(Mark, String)> = match crate::audit::store::baseline_for(all, i) {
            Some((base, notes)) => {
                let d = diff::diff(&base, &cur.report);
                let head = match diff::summary(&d).as_str() {
                    "no changes" => "Nothing changed since the previous audit.".to_string(),
                    s => format!("Changed: {s}"),
                };
                std::iter::once((Mark::Section, head))
                    .chain(notes.into_iter().map(|n| (Mark::Same, n)))
                    .chain(std::iter::once((Mark::Same, String::new())))
                    .chain(d.into_iter().map(|l| {
                        (
                            match l.kind {
                                Kind::Section => Mark::Section,
                                Kind::Add => Mark::Add,
                                Kind::Remove => Mark::Remove,
                                Kind::Change => Mark::Change,
                                Kind::Same => Mark::Same,
                            },
                            l.text,
                        )
                    }))
                    .collect()
            }
            None => vec![(
                Mark::Same,
                "Nothing to compare against yet. The next audit diffs against this one."
                    .to_string(),
            )],
        };
        let page = Page {
            name: cur.name(),
            pos: (all.len() > 1).then_some((i + 1, all.len())),
            header: if i == 0 {
                "First audit: nothing is marked expected yet, so everything shows up once."
            } else {
                "Worth a look on this machine."
            },
            keys: "Enter = fix it (Claude helps) · x = expected on/off · A = ask Claude · c = audit again",
            rows: rows
                .iter()
                .map(|fd| Row {
                    finding: fd,
                    expected: is_expected(fd, b),
                })
                .collect(),
            empty: if cur.report.findings.is_empty() {
                "Nothing to report."
            } else {
                "No findings match the filter."
            },
            counts: (c.high, c.medium, c.low),
            not_collected: cur.report.errors.clone(),
            detail: &|fd, w| finding_lines(t, fd, w, "Enter"),
            changes_name: "Diff",
            changes_title: match prev {
                Some(p) => format!("{} → {}", strip_json(&p.name()), strip_json(&cur.name())),
                None => "first report".into(),
            },
            changes,
        };
        self.view.draw(f, area, t, &page);
    }
}

fn strip_json(s: &str) -> &str {
    s.strip_suffix(".json").unwrap_or(s)
}

impl Audit {
    pub fn ask(&self, v: &View) -> Result<crate::claude::Ask, String> {
        let rows = self.rows(v);
        let f = rows
            .get(self.view.cur.sel.min(rows.len().saturating_sub(1)))
            .ok_or("no finding selected (run an audit with Enter)")?;
        Ok(crate::claude::Ask::new(
            format!("audit · {}", f.message),
            format!(
                "A finding from sentry's security audit of my machine:\n{} [{}] {}\nsentry's generic explanation:\n  what: {}\n  why: {}\n  to do: {}\nevidence:\n{}",
                f.severity.as_str(),
                f.category,
                f.message,
                f.what,
                f.why,
                f.fix,
                f.evidence
            ),
            "Explain this on my machine specifically (check what you can) and tell me what to do.",
        ))
    }
}
