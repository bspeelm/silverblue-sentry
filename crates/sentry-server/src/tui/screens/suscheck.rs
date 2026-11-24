//! SusCheck: how a household's checks of suspicious mail and pages went, read from the
//! incidents folder SusCheck keeps on this server. A summary, the paired computers, the
//! latest checks; Enter reads one check in full, `o` fetches its picture for the desktop's
//! viewer, `m` marks whether SusCheck was right.
//!
//! Everything shown here was cleaned as it was parsed (`collect::suscheck::clean`), is
//! drawn as text and nothing else (a domain is never resolved, looked up or opened), and
//! never goes to Claude: `A` isn't offered on this screen.

use super::*;
use crate::collect::suscheck::{
    Check, Device, Fetched, Id, Incident, Part, Read, Suscheck, Tally, Verdict, said,
};
use crate::suscheck::RIGHT;

/// Why `A` does nothing here.
pub const NO_CLAUDE: &str = "never sent to Claude: private, and may carry an attacker's text";

#[derive(Default)]
pub struct Sus {
    pub cur: Cursor,
    /// The check whose record is in front (Enter; Esc goes back to the list).
    pub open: Option<Id>,
    /// How far its record is scrolled.
    pub scroll: u16,
    /// `seen` as it was when the screen was entered: checks after it are marked new for as
    /// long as it stays in view.
    pub after: Option<String>,
}

fn folder<'a>(v: &View<'a>) -> Option<&'a Suscheck> {
    v.s.suscheck.value.as_ref()?.as_ref()?.folder()
}

/// The checks the list shows: newest first, those the `/` filter matches.
pub fn rows<'a>(v: &View<'a>) -> Vec<&'a Check> {
    let Some(s) = folder(v) else {
        return Vec::new();
    };
    s.checks
        .iter()
        .rev()
        .filter(|c| {
            v.matches(&[
                c.id.as_str(),
                c.device.as_deref().unwrap_or(""),
                &c.outcome(),
                c.brand.as_deref().unwrap_or(""),
                c.domain.as_deref().unwrap_or(""),
                c.domain_check.as_deref().unwrap_or(""),
                c.kind.as_deref().unwrap_or(""),
            ])
        })
        .collect()
}

fn selected<'a>(v: &View<'a>) -> Option<&'a Check> {
    rows(v).into_iter().nth(v.cur)
}

/// The check the keys act on: the one open, else the one under the cursor.
fn target<'a>(open: Option<Id>, v: &View<'a>) -> Option<Id> {
    open.or_else(|| selected(v).map(|c| c.id))
}

/// What needs a look since you last did: checks that said "don't trust this", and checks
/// that failed. The screen's badge and Maintenance's row; counts, nothing else.
pub fn unseen(v: &View) -> (u32, u32) {
    folder(v).map_or((0, 0), |s| s.unseen(v.sus.seen.as_deref()))
}

pub fn badge(v: &View) -> Option<(String, Color)> {
    let (bad, failed) = unseen(v);
    match (bad, failed) {
        (0, 0) => None,
        (0, n) => Some((format!(" {n}"), v.t.yellow)),
        (b, n) => Some((format!(" {}", b + n), v.t.red)),
    }
}

/// The Dashboard's Status row, where SusCheck is configured: `(bad, text)`. Numbers only
/// (this row is among what `A` on the Dashboard sends).
pub fn status(v: &View) -> Option<(bool, String)> {
    v.cfg.suscheck.on()?;
    let read = v.s.suscheck.value.as_ref()?.as_ref()?;
    Some(match read {
        Read::Unreadable(_) => (true, "suscheck: its folder can't be read".into()),
        Read::Folder(s) => {
            let c = s.counts();
            let (bad, failed) = s.unseen(v.sus.seen.as_deref());
            let look = bad + failed;
            if let Some(age) = c.heartbeat_age_s.filter(|_| c.down()) {
                (true, format!("suscheck  down for {}", fmt::age(age)))
            } else {
                (
                    look > 0,
                    format!(
                        "suscheck  {} check{} this week · {look} to look at",
                        c.week.total,
                        if c.week.total == 1 { "" } else { "s" }
                    ),
                )
            }
        }
    })
}

pub fn hints(open: bool, v: &View) -> Hints {
    if v.cfg.suscheck.on().is_none() || folder(v).is_none() {
        return vec![("r", "read again")];
    }
    if open {
        return vec![
            ("Esc", "back"),
            ("j/k", "scroll"),
            ("o", "picture"),
            ("m", "mark"),
            ("x", "clear mark"),
        ];
    }
    vec![
        ("j/k", "select"),
        ("Enter", "the check"),
        ("o", "picture"),
        ("m", "mark"),
        ("x", "clear mark"),
        ("/", "filter"),
        ("r", "read again"),
    ]
}

/// Every key of the screen, for `?`.
pub fn help() -> Hints {
    vec![
        ("j/k", "select a check (in a check: scroll)"),
        (
            "Enter",
            "read the check in full: reasons, advice, what was read, searches",
        ),
        ("Esc", "back to the list"),
        (
            "o",
            "its picture, fetched to a private cache and opened in the desktop's viewer",
        ),
        (
            "m",
            "mark it: SusCheck was right, or what it should have said",
        ),
        ("x", "clear your mark"),
        ("/", "filter the checks"),
        ("r", "read the folder again (nothing is read on a timer)"),
        (
            "A",
            "not here: a household's checks are never sent to Claude",
        ),
    ]
}

fn when(at: Option<i64>) -> String {
    at.and_then(|s| jiff::Timestamp::from_second(s).ok())
        .map_or("?".into(), |t| {
            t.to_zoned(jiff::tz::TimeZone::system())
                .strftime("%b %d %H:%M")
                .to_string()
        })
}

fn secs(ms: u64) -> String {
    match ms {
        0..10_000 => format!("{:.1} s", ms as f64 / 1000.0),
        10_000..120_000 => format!("{} s", ms / 1000),
        _ => format!("{}m {}s", ms / 60_000, (ms % 60_000) / 1000),
    }
}

fn verdict_color(t: &Theme, c: &Check) -> Color {
    if c.error.is_some() {
        return t.mag;
    }
    match c.verdict() {
        Some(Verdict::Malicious) => t.red,
        Some(Verdict::Suspicious) => t.yellow,
        Some(Verdict::Safe) => t.green,
        None => t.fg,
    }
}

fn word_color(t: &Theme, verdict: &str) -> Color {
    match Verdict::of(verdict) {
        Some(Verdict::Malicious) => t.red,
        Some(Verdict::Suspicious) => t.yellow,
        Some(Verdict::Safe) => t.green,
        None => t.fg,
    }
}

impl Sus {
    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        if v.cfg.suscheck.on().is_none() {
            return Vec::new();
        }
        if a == Action::Refresh || a == Action::Check {
            return vec![Own::fetch(Kind::Suscheck)];
        }
        // A check is in front: the arrows scroll it, Esc closes it.
        if self.open.is_some() {
            match a {
                Action::Esc => {
                    self.open = None;
                    self.scroll = 0;
                    return vec![Own::SusClose.into()];
                }
                Action::Down => self.scroll = self.scroll.saturating_add(1),
                Action::Up => self.scroll = self.scroll.saturating_sub(1),
                Action::PageDown => self.scroll = self.scroll.saturating_add(10),
                Action::PageUp => self.scroll = self.scroll.saturating_sub(10),
                Action::Top => self.scroll = 0,
                _ => {}
            }
        } else if self.cur.nav(a, rows(v).len()) {
            return Vec::new();
        }
        let Some(id) = target(self.open, v) else {
            return Vec::new();
        };
        match a {
            Action::Enter if self.open.is_none() => {
                self.open = Some(id);
                self.scroll = 0;
                vec![Own::SusOpen(id).into()]
            }
            Action::Char('o') => vec![Own::SusPicture(id).into()],
            Action::Char('m') => vec![Effect::Choose(mark_choice(v, id))],
            Action::Char('x') => match v.sus.mark(&id) {
                Some(_) => vec![Own::SusMark(id, None).into()],
                None => vec![Effect::Toast("this check has no mark".into())],
            },
            _ => Vec::new(),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        let one = |f: &mut Frame, title: &str, lines: Vec<Line<'static>>| {
            let b = panel(t, "SusCheck", title.to_string());
            let r = inner(&b, area);
            f.render_widget(b, area);
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), r);
        };
        if v.cfg.suscheck.on().is_none() {
            return one(
                f,
                "not set up",
                vec![
                    Line::styled(
                        format!("No suscheck: block for {} in server_config.yaml.", v.name),
                        t.fg(),
                    ),
                    Line::raw(""),
                    Line::styled(
                        "Where SusCheck runs, it writes its incidents folder in \
                         /etc/suscheck/incidents.path; the Config tab's form has the settings \
                         (SusCheck).",
                        t.dim(),
                    ),
                ],
            );
        }
        let read = match &v.s.suscheck.value {
            Some(Some(r)) => r,
            _ => {
                return one(
                    f,
                    "reading",
                    vec![waiting(v, &v.s.suscheck, "SusCheck's incidents folder")],
                );
            }
        };
        let s = match read {
            Read::Folder(s) => s,
            Read::Unreadable(u) => {
                return one(
                    f,
                    "can't be read",
                    vec![
                        Line::styled(u.said(v.cfg.suscheck.ssh.is_some()), t.s(t.yellow)),
                        Line::raw(""),
                        Line::styled("r reads again.", t.dim()),
                    ],
                );
            }
        };
        let wide = area.width >= 120;
        let open = self.open.filter(|_| v.s.sus_open.is_some());
        if wide {
            let [left, right] =
                Layout::horizontal([Constraint::Length(48), Constraint::Min(40)]).areas(area);
            let [top, bottom] =
                Layout::vertical([Constraint::Length(15), Constraint::Min(4)]).areas(left);
            summary(f, top, v, s, false);
            computers(f, bottom, v, s);
            match open {
                Some(id) => self.incident(f, right, v, s, id),
                None => self.checks(f, right, v, s, true),
            }
        } else if let Some(id) = open {
            self.incident(f, area, v, s, id);
        } else {
            let rows = device_rows(s);
            let n = (rows.len() + rows.iter().filter(|d| !d.note.is_empty()).count()) as u16;
            let roomy = area.height >= 30;
            let [top, mid, rest] = Layout::vertical([
                Constraint::Length(8),
                Constraint::Length(if roomy { (n + 3).min(9) } else { 0 }),
                Constraint::Min(4),
            ])
            .areas(area);
            summary(f, top, v, s, true);
            if roomy {
                computers(f, mid, v, s);
            }
            self.checks(f, rest, v, s, false);
        }
    }

    fn checks(&mut self, f: &mut Frame, area: Rect, v: &View, s: &Suscheck, wide: bool) {
        let t = v.t;
        let list = rows(v);
        let mut detail = match s.index_newer {
            Some(n) => format!("schema {n}: not shown"),
            None => format!("{} shown, newest first", list.len()),
        };
        if s.skipped > 0 {
            detail += &format!(" · {} damaged line(s) skipped", s.skipped);
        }
        if let Some(e) = &v.s.suscheck.err {
            detail += &format!(" · last read failed: {e}");
        }
        let b = panel(t, "Checks", detail);
        let r = inner(&b, area);
        f.render_widget(b, area);
        if let Some(n) = s.index_newer {
            f.render_widget(
                Paragraph::new(vec![Line::styled(
                    format!(
                        "The index is written in schema {n}, which this sentry doesn't know \
                         (it knows 1): nothing of it is shown, rather than guessed. A newer \
                         sentry reads it."
                    ),
                    t.s(t.yellow),
                )])
                .wrap(Wrap { trim: false }),
                r,
            );
            return;
        }
        if list.is_empty() {
            let why = if v.filter.is_some() {
                "No check matches the filter (Esc clears it)."
            } else {
                "No checks yet."
            };
            f.render_widget(Paragraph::new(Line::styled(why, t.dim())), r);
            return;
        }
        let new = |c: &Check| self.after.as_deref().is_none_or(|a| c.id.as_str() > a);
        let table: Vec<Row> = list
            .iter()
            .map(|c| {
                let yours = match v.sus.mark(&c.id) {
                    Some(m) if m.verdict == RIGHT => ("✓", t.green),
                    Some(_) => ("✗", t.red),
                    None => ("", t.dim),
                };
                let mut verdict = c.outcome();
                if c.incomplete == Some(true) {
                    verdict += " ?";
                }
                let mut cells = vec![
                    Cell::from(if new(c) { "●" } else { "" }).style(t.s(t.cyan)),
                    Cell::from(when(c.at)).style(t.dim()),
                    Cell::from(c.device.clone().unwrap_or_else(|| "–".into())).style(t.fg()),
                    Cell::from(verdict).style(t.s(verdict_color(t, c))),
                ];
                if wide {
                    cells.push(Cell::from(c.brand.clone().unwrap_or_default()).style(t.fg()));
                }
                cells.push(Cell::from(c.domain.clone().unwrap_or_default()).style(t.fg()));
                if wide {
                    cells.push(
                        Cell::from(c.domain_check.as_deref().unwrap_or("").replace('_', " "))
                            .style(t.dim()),
                    );
                }
                cells.push(Cell::from(yours.0).style(t.s(yours.1)));
                Row::new(cells)
            })
            .collect();
        let (header, widths) = if wide {
            (
                vec![
                    "",
                    "When",
                    "Computer",
                    "It said",
                    "Brand",
                    "Domain",
                    "Domain check",
                    "",
                ],
                vec![
                    Constraint::Length(1),
                    Constraint::Length(12),
                    Constraint::Length(14),
                    Constraint::Length(26),
                    Constraint::Length(14),
                    Constraint::Fill(1),
                    Constraint::Length(13),
                    Constraint::Length(1),
                ],
            )
        } else {
            (
                vec!["", "When", "Computer", "It said", "Domain", ""],
                vec![
                    Constraint::Length(1),
                    Constraint::Length(12),
                    Constraint::Length(13),
                    Constraint::Length(26),
                    Constraint::Fill(1),
                    Constraint::Length(1),
                ],
            )
        };
        widgets::table(
            f,
            r,
            t,
            TableSpec {
                header,
                widths,
                rows: table,
                selected: Some(v.cur),
            },
        );
    }

    fn incident(&mut self, f: &mut Frame, area: Rect, v: &View, s: &Suscheck, id: Id) {
        let t = v.t;
        let check = s.checks.iter().find(|c| c.id == id);
        let title = match check {
            Some(c) => format!("{} · {}", when(c.at), c.device.as_deref().unwrap_or("–")),
            None => when(id.time()),
        };
        let b = panel(t, "Check", title);
        let r = inner(&b, area);
        f.render_widget(b, area);
        let mut lines = Vec::new();
        if let Some(c) = check {
            lines.extend(check_lines(v, c));
        }
        match v.s.sus_open.as_ref().filter(|o| o.id == id).map(|o| &o.got) {
            None | Some(None) => {
                lines.push(Line::styled("reading its record…", t.dim()));
            }
            Some(Some(Ok(Fetched::Expired))) => lines.push(Line::styled(
                "Expired: SusCheck has removed this check since the list was read (it keeps \
                 them for a while, then prunes). r reads the list again.",
                t.s(t.yellow),
            )),
            Some(Some(Err(e))) => lines.push(Line::styled(format!("Its record: {e}"), t.s(t.red))),
            Some(Some(Ok(Fetched::Ok(i)))) => lines.extend(incident_lines(v, i)),
        }
        let most = (lines.len() as u16).saturating_sub(1);
        self.scroll = self.scroll.min(most);
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .scroll((self.scroll, 0)),
            r,
        );
    }
}

/// `m`: SusCheck was right, or what it should have said. Kept on this machine only.
fn mark_choice(v: &View, id: Id) -> crate::tui::target::Choice {
    let t = v.t;
    let mut options = vec![(
        "SusCheck was right".to_string(),
        vec![Own::SusMark(id, Some(RIGHT.into())).into()],
    )];
    // (From the mildest: what it should have been.)
    for verdict in [Verdict::Safe, Verdict::Suspicious, Verdict::Malicious] {
        options.push((
            format!("wrong: it should have said \"{}\"", verdict.said()),
            vec![Own::SusMark(id, Some(verdict.word().into())).into()],
        ));
    }
    let mut c = crate::tui::target::Choice::numbered(t, "Mark this check", options);
    c.lines.push(Line::raw(""));
    c.lines.push(Line::styled(
        "Kept on this machine (the server's suscheck.toml): nothing is written to the server, \
         and SusCheck isn't told. x clears a mark.",
        t.dim(),
    ));
    c
}

fn row(t: &Theme, label: &str, text: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<18}"), t.dim()),
        Span::styled(text, t.fg()),
    ])
}

/// What the index says of the check: shown at once, before its record is in.
fn check_lines(v: &View, c: &Check) -> Vec<Line<'static>> {
    let t = v.t;
    let mut out = Vec::new();
    let mut verdict = vec![
        Span::styled(format!("{:<18}", "It said"), t.dim()),
        Span::styled(c.outcome(), t.s(verdict_color(t, c))),
    ];
    if let Some(conf) = &c.confidence {
        verdict.push(Span::styled(format!("  ({conf} confidence)"), t.dim()));
    }
    if c.incomplete == Some(true) {
        verdict.push(Span::styled(
            "  incomplete: key evidence wasn't visible or couldn't be confirmed",
            t.dim(),
        ));
    }
    out.push(Line::from(verdict));
    out.push(row(
        t,
        "Your mark",
        match v.sus.mark(&c.id) {
            Some(m) => format!("{} (x clears it)", m.said()),
            None => "none (m marks it)".into(),
        },
    ));
    let client = [c.client.as_deref(), c.app_version.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    out.push(row(
        t,
        "From",
        format!(
            "{}{} · took {}",
            c.device.as_deref().unwrap_or("an unnamed computer"),
            if client.is_empty() {
                String::new()
            } else {
                format!(" ({client})")
            },
            secs(c.duration_ms)
        ),
    ));
    out.push(Line::raw(""));
    out
}

fn bullets(t: &Theme, items: &[String]) -> Vec<Line<'static>> {
    items
        .iter()
        .map(|x| Line::styled(format!("  · {x}"), t.fg()))
        .collect()
}

fn head(t: &Theme, s: &str) -> Line<'static> {
    Line::styled(s.to_string(), t.s(t.cyan))
}

fn yes_no(b: Option<bool>) -> &'static str {
    match b {
        Some(true) => "yes",
        Some(false) => "no",
        None => "?",
    }
}

/// An advice code or a machine tag as words (`do_not_click` → `do not click`).
fn words(codes: &[String]) -> String {
    codes
        .iter()
        .map(|c| c.replace('_', " "))
        .collect::<Vec<_>>()
        .join(" · ")
}

/// The record in full: what the person was shown, what the model read and said, what
/// SusCheck's own rules and searches added, and how long each stage took.
fn incident_lines(v: &View, i: &Incident) -> Vec<Line<'static>> {
    let t = v.t;
    let mut out = Vec::new();
    let none = || Line::styled("  (none)", t.dim());
    if let Some(l) = &i.last {
        out.push(head(t, "Reasons shown"));
        match l.reasons.is_empty() {
            true => out.push(none()),
            false => out.extend(bullets(t, &l.reasons)),
        }
        out.push(row(t, "Advice shown", words(&l.advice)));
    } else {
        out.push(Line::styled(
            format!(
                "The check failed{}: nobody was shown a verdict.",
                i.error
                    .as_ref()
                    .map_or(String::new(), |e| format!(" ({e})"))
            ),
            t.s(t.mag),
        ));
    }
    // What the model said against what counted.
    if let (Some(j), Some(l)) = (&i.judgement, &i.last) {
        out.push(Line::raw(""));
        out.push(head(t, "The model against what counted"));
        let jv = j.verdict.as_deref().unwrap_or("?");
        let lv = l.verdict.as_deref().unwrap_or("?");
        out.push(Line::from(vec![
            Span::styled(format!("{:<18}", "The model"), t.dim()),
            Span::styled(said(jv).to_string(), t.s(word_color(t, jv))),
            Span::styled(
                format!(" ({})", j.confidence.as_deref().unwrap_or("?")),
                t.dim(),
            ),
        ]));
        out.push(Line::from(vec![
            Span::styled(format!("{:<18}", "What counted"), t.dim()),
            Span::styled(said(lv).to_string(), t.s(word_color(t, lv))),
            Span::styled(
                format!(" ({})", l.confidence.as_deref().unwrap_or("?")),
                t.dim(),
            ),
        ]));
        out.push(row(
            t,
            "SusCheck's rules",
            match (l.floors.is_empty(), l.floors_changed) {
                (true, _) => "none applied".into(),
                (false, Some(true)) => format!("{}: raised the verdict", words(&l.floors)),
                (false, _) => format!("{}: the verdict stood", words(&l.floors)),
            },
        ));
        if !j.red_flags.is_empty() {
            out.push(Line::styled("  its red flags", t.dim()));
            out.extend(bullets(t, &j.red_flags));
        }
        if !j.looks_normal.is_empty() {
            out.push(Line::styled("  what it found normal", t.dim()));
            out.extend(bullets(t, &j.looks_normal));
        }
    }
    if let Some(x) = &i.facts {
        out.push(Line::raw(""));
        out.push(head(t, "What it read from the picture"));
        let or = |o: &Option<String>| o.clone().unwrap_or_else(|| "–".into());
        out.push(row(
            t,
            "  kind",
            x.kind.as_deref().unwrap_or("?").replace('_', " "),
        ));
        out.push(row(t, "  claims to be", or(&x.claimed_brand)));
        if x.sender_name.is_some() || x.sender_address.is_some() {
            out.push(row(
                t,
                "  sender",
                format!("{} <{}>", or(&x.sender_name), or(&x.sender_address)),
            ));
        }
        if x.address_bar_domain.is_some() {
            out.push(row(t, "  address bar", or(&x.address_bar_domain)));
        }
        if !x.link_texts.is_empty() {
            out.push(row(t, "  links", x.link_texts.join(" · ")));
        }
        if !x.phone_numbers.is_empty() {
            out.push(row(t, "  phone numbers", x.phone_numbers.join(" · ")));
        }
        out.push(row(
            t,
            "  asks for",
            if x.asks_for.is_empty() {
                "nothing".into()
            } else {
                words(&x.asks_for)
            },
        ));
        out.push(row(
            t,
            "  pressure",
            format!(
                "urgency: {} · text addressed to an AI: {}",
                yes_no(x.urgency),
                yes_no(x.talks_to_ai)
            ),
        ));
    }
    if let Some(d) = &i.domain {
        out.push(Line::raw(""));
        out.push(head(t, "The domain (text only: never open it)"));
        let or = |o: &Option<String>| o.clone().unwrap_or_else(|| "none read".into());
        out.push(row(t, "  first reading", or(&d.first_reading)));
        out.push(row(t, "  second reading", or(&d.second_reading)));
        out.push(row(
            t,
            "  compared",
            format!(
                "{}{}{}{}",
                d.result.as_deref().unwrap_or("?").replace('_', " "),
                d.why
                    .as_ref()
                    .map_or(String::new(), |w| format!(" ({})", w.replace('_', " "))),
                d.shown
                    .as_ref()
                    .map_or(String::new(), |s| format!(" · on screen {s}")),
                d.real
                    .as_ref()
                    .map_or(String::new(), |s| format!(" · the real one {s}")),
            ),
        ));
    }
    if let Some(s) = &i.search {
        out.push(Line::raw(""));
        out.push(head(
            t,
            match s.ok {
                Some(false) => "Searches SusCheck ran (one failed or timed out)",
                _ => "Searches SusCheck ran",
            },
        ));
        if s.queries.is_empty() {
            out.push(none());
        }
        for q in &s.queries {
            out.push(row(t, &format!("  {}", q.kind), q.query.clone()));
            if q.hits.is_empty() {
                out.push(Line::styled("      nothing came back", t.dim()));
            }
            for h in &q.hits {
                out.push(Line::from(vec![
                    Span::styled(
                        format!("      {}", h.title.as_deref().unwrap_or("(no title)")),
                        t.fg(),
                    ),
                    Span::styled(
                        format!(
                            " · {} · {} engine{}",
                            h.domain.as_deref().unwrap_or("no domain"),
                            h.engines,
                            if h.engines == 1 { "" } else { "s" }
                        ),
                        t.dim(),
                    ),
                ]));
                if let Some(sn) = &h.snippet {
                    out.push(Line::styled(format!("        {sn}"), t.dim()));
                }
            }
        }
    }
    out.push(Line::raw(""));
    out.push(head(t, "How it ran"));
    out.push(row(
        t,
        "  model",
        format!(
            "{} · prompts {}",
            i.model.as_deref().unwrap_or("?"),
            i.prompt_version.as_deref().unwrap_or("?")
        ),
    ));
    out.push(row(
        t,
        "  time",
        format!(
            "{} in all{}",
            secs(i.duration_ms),
            i.stages
                .iter()
                .map(|(n, ms)| format!(" · {n} {}", secs(*ms)))
                .collect::<String>()
        ),
    ));
    out.push(row(
        t,
        "  picture",
        if i.screenshot {
            "kept: o fetches it to a private cache here and opens it (gone when sentry closes)"
                .into()
        } else {
            "none was kept".to_string()
        },
    ));
    out
}

/// The median of the completed checks' times, and the longest, in the last 30 days.
fn times(s: &Suscheck) -> Option<(u64, u64)> {
    let since = s.now - 30 * 86_400;
    let mut ms: Vec<u64> = s
        .checks
        .iter()
        .filter(|c| c.error.is_none() && c.at.is_some_and(|a| a >= since))
        .map(|c| c.duration_ms)
        .collect();
    ms.sort_unstable();
    Some((*ms.get(ms.len().checked_sub(1)? / 2)?, *ms.last()?))
}

fn pct(n: u32, of: u32) -> String {
    match of {
        0 => "–".into(),
        _ => format!("{n} of {of} ({}%)", (n * 100 + of / 2) / of),
    }
}

/// The service's line: alive (by the server's clock, never this machine's) or down.
fn service_line(t: &Theme, s: &Suscheck) -> Line<'static> {
    match (&s.status, s.heartbeat_age()) {
        (Part::Missing, _) => Line::styled("no status file yet: not started?", t.s(t.yellow)),
        (Part::Newer(n), _) => Line::styled(
            format!("status: schema {n}, which this sentry doesn't know"),
            t.s(t.yellow),
        ),
        (Part::Damaged, _) => Line::styled("status: not what the format says", t.s(t.yellow)),
        (Part::Ok(_), Some(age)) if age > crate::collect::suscheck::HEARTBEAT_S => Line::styled(
            format!("● down: no heartbeat for {}", fmt::age(age)),
            t.s(t.red),
        ),
        (Part::Ok(st), Some(age)) => Line::from(vec![
            Span::styled("● alive", t.s(t.green)),
            Span::styled(
                format!(
                    " {}{}",
                    fmt::ago(age),
                    st.retention_days
                        .map_or(String::new(), |d| format!(" · keeps checks {d} days"))
                ),
                t.dim(),
            ),
        ]),
        (Part::Ok(_), None) => Line::styled("no heartbeat in its status file", t.s(t.yellow)),
    }
}

fn summary(f: &mut Frame, area: Rect, v: &View, s: &Suscheck, brief: bool) {
    let t = v.t;
    let st = s.status.ok();
    let b = panel(
        t,
        "SusCheck",
        st.and_then(|x| x.version.clone()).unwrap_or_default(),
    );
    let r = inner(&b, area);
    f.render_widget(b, area);
    let (week, month) = (s.tally(7), s.tally(30));
    let (wrong, marked) = v.sus.marked();
    let typical = times(s);
    let mut lines: Vec<Line> = Vec::new();
    if brief {
        for (label, x) in [("7 days ", week), ("30 days", month)] {
            lines.push(Line::from(vec![
                Span::styled(format!("{label}  "), t.dim()),
                Span::styled(
                    format!(
                        "{} check{} · {} failed · {} incomplete · rules overrode the model {}×",
                        x.total,
                        if x.total == 1 { "" } else { "s" },
                        x.errors,
                        x.incomplete,
                        x.floors
                    ),
                    t.fg(),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::raw("         "),
                Span::styled(
                    format!("{} {}", x.malicious, Verdict::Malicious.said()),
                    t.s(t.red),
                ),
                Span::styled(" · ", t.dim()),
                Span::styled(
                    format!("{} {}", x.suspicious, Verdict::Suspicious.said()),
                    t.s(t.yellow),
                ),
                Span::styled(" · ", t.dim()),
                Span::styled(format!("{} {}", x.safe, Verdict::Safe.said()), t.s(t.green)),
            ]));
        }
        lines.push(Line::styled(
            format!(
                "{} computer(s) · typical time {} · you marked {wrong} wrong of {marked}",
                device_rows(s).len(),
                typical.map_or("–".into(), |(m, _)| secs(m)),
            ),
            t.dim(),
        ));
    } else {
        let num = |n: u32| format!("{n:>9}");
        let line = |label: &str, a: u32, b: u32, c: Color| {
            Line::from(vec![
                Span::styled(format!("{label:<26}"), t.s(c)),
                Span::styled(num(a), t.fg()),
                Span::styled(num(b), t.fg()),
            ])
        };
        lines.push(Line::styled(
            format!("{:<26}{:>9}{:>9}", "", "7 days", "30 days"),
            t.dim(),
        ));
        lines.push(line("checks", week.total, month.total, t.fg));
        for verdict in Verdict::ALL {
            let of = |x: &Tally| match verdict {
                Verdict::Malicious => x.malicious,
                Verdict::Suspicious => x.suspicious,
                Verdict::Safe => x.safe,
            };
            let c = match verdict {
                Verdict::Malicious => t.red,
                Verdict::Suspicious => t.yellow,
                Verdict::Safe => t.green,
            };
            lines.push(line(
                &format!(" {}", verdict.said()),
                of(&week),
                of(&month),
                c,
            ));
        }
        if week.other + month.other > 0 {
            lines.push(line(" another verdict", week.other, month.other, t.fg));
        }
        lines.push(line(" failed", week.errors, month.errors, t.mag));
        lines.push(row(
            t,
            "incomplete",
            pct(month.incomplete, month.completed()),
        ));
        lines.push(row(
            t,
            "rules overrode",
            format!("the model {}", pct(month.floors, month.completed())),
        ));
        lines.push(row(
            t,
            "typical time",
            typical.map_or("–".into(), |(m, max)| {
                format!("{} (longest {})", secs(m), secs(max))
            }),
        ));
        lines.push(row(
            t,
            "you marked",
            match marked {
                0 => "none yet (m on a check)".into(),
                _ => format!("{wrong} wrong of {marked}"),
            },
        ));
        if let Some(x) = st {
            lines.push(Line::styled(
                trunc(
                    &format!(
                        "model {} · prompts {}",
                        x.model.as_deref().unwrap_or("?"),
                        x.prompt_version.as_deref().unwrap_or("?")
                    ),
                    r.width as usize,
                ),
                t.dim(),
            ));
        }
    }
    lines.push(service_line(t, s));
    if s.cut() {
        lines.push(Line::styled(
            format!(
                "(the latest {} checks: older ones aren't counted)",
                s.recent
            ),
            t.dim(),
        ));
    }
    if let Some(n) = s.newer() {
        lines.push(Line::styled(
            format!("a file here is in schema {n}: a newer sentry reads it"),
            t.s(t.yellow),
        ));
    }
    f.render_widget(Paragraph::new(lines), r);
}

/// A computer as the panel lists it.
struct DeviceRow {
    name: String,
    client: String,
    checks: usize,
    seen: String,
    note: String,
    odd: bool,
}

/// A version as numbers, for telling an older app from a newer one.
fn version(v: &str) -> Vec<u64> {
    v.split(['.', '-', '+'])
        .map_while(|p| p.parse().ok())
        .collect()
}

/// The paired computers (and any the checks name that isn't paired any more), each with
/// how many of the checks read are its own, and what stands out about it.
fn device_rows(s: &Suscheck) -> Vec<DeviceRow> {
    let paired: &[Device] = s.devices.ok().map_or(&[], |d| d.as_slice());
    let count = |name: &str| {
        s.checks
            .iter()
            .filter(|c| c.device.as_deref() == Some(name))
            .count()
    };
    let newest = paired
        .iter()
        .filter(|d| d.client.as_deref() == Some("app"))
        .filter_map(|d| d.app_version.as_deref())
        .map(version)
        .max();
    let mut out: Vec<DeviceRow> = paired
        .iter()
        .map(|d| {
            let checks = count(&d.name);
            let idle = d.last_seen_at.map(|t| (s.now - t) / 86_400);
            let older = d.client.as_deref() == Some("app")
                && d.app_version
                    .as_deref()
                    .map(version)
                    .is_some_and(|v| newest.as_ref().is_some_and(|n| v < *n));
            let note = match idle {
                None if checks == 0 => "never used".to_string(),
                Some(days) if days >= 14 => format!("not seen for {days} days"),
                _ if older => "older app than the others".into(),
                _ if checks == 0 && !s.cut() => "never used".into(),
                _ => String::new(),
            };
            DeviceRow {
                name: d.name.clone(),
                client: [d.client.as_deref(), d.app_version.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" "),
                checks,
                seen: match d.last_seen_at {
                    Some(at) => fmt::ago(s.now - at),
                    None => "never".into(),
                },
                odd: !note.is_empty(),
                note,
            }
        })
        .collect();
    // A computer the checks name that isn't paired (any more).
    let mut gone: Vec<&str> = s
        .checks
        .iter()
        .filter_map(|c| c.device.as_deref())
        .filter(|n| !paired.iter().any(|d| d.name == *n))
        .collect();
    gone.sort_unstable();
    gone.dedup();
    for name in gone {
        out.push(DeviceRow {
            name: name.to_string(),
            client: String::new(),
            checks: count(name),
            seen: "–".into(),
            note: "not paired any more".into(),
            odd: false,
        });
    }
    out
}

fn computers(f: &mut Frame, area: Rect, v: &View, s: &Suscheck) {
    let t = v.t;
    let list = device_rows(s);
    let b = panel(
        t,
        "Computers",
        format!("{} paired", s.devices.ok().map_or(0, Vec::len)),
    );
    let r = inner(&b, area);
    f.render_widget(b, area);
    match &s.devices {
        Part::Newer(n) => {
            return f.render_widget(
                Paragraph::new(Line::styled(
                    format!("devices.json is in schema {n}, which this sentry doesn't know."),
                    t.s(t.yellow),
                ))
                .wrap(Wrap { trim: false }),
                r,
            );
        }
        Part::Damaged => {
            return f.render_widget(
                Paragraph::new(Line::styled(
                    "devices.json isn't what the format says.",
                    t.s(t.yellow),
                )),
                r,
            );
        }
        _ if list.is_empty() => {
            return f.render_widget(
                Paragraph::new(Line::styled("No computer is paired yet.", t.dim())),
                r,
            );
        }
        _ => {}
    }
    let mut lines = vec![Line::styled(
        format!(
            "{:<15}{:<10}{:>6}  {}",
            "Name", "Client", "Checks", "Last seen"
        ),
        t.dim(),
    )];
    for d in list {
        lines.push(Line::from(vec![
            Span::styled(format!("{:<15}", trunc(&d.name, 14)), t.fg()),
            Span::styled(format!("{:<10}", trunc(&d.client, 9)), t.dim()),
            Span::styled(format!("{:>6}  ", d.checks), t.fg()),
            Span::styled(d.seen, t.dim()),
        ]));
        if !d.note.is_empty() {
            lines.push(Line::styled(
                format!("  ↳ {}", d.note),
                if d.odd { t.s(t.yellow) } else { t.dim() },
            ));
        }
    }
    f.render_widget(Paragraph::new(lines), r);
}
