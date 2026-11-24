//! SusCheck: how a household's checks of suspicious mail and pages went, read from the
//! incidents folder SusCheck keeps on this server. A summary, the paired computers, the
//! latest checks; Enter reads one check in full, `o` fetches its picture for the desktop's
//! viewer, `m` marks whether SusCheck was right. A check made from an email file also
//! keeps a quarantined copy of the message's text on the server: that is said, and never
//! fetched or shown (no key reads it).
//!
//! Everything shown here was cleaned as it was parsed (`collect::suscheck::clean`), is
//! drawn as text and nothing else (a domain, an address or a link's target is never
//! resolved, looked up, opened or copied anywhere), and
//! never goes to Claude: `A` isn't offered on this screen.

use super::*;
use crate::collect::suscheck::{
    ACQUIRED, Check, Device, Fetched, INPUTS, Id, Incident, Part, Read, Suscheck, Tally,
    TrustedList, Verdict, input_parts, said,
};
use crate::suscheck::RIGHT;

/// What is said of an email's text (`message.txt`), and all sentry does with it.
pub const MESSAGE_KEPT: &str = "The email's text is kept on the server with this check \
    (quarantined). sentry doesn't show it.";

/// What a check said where its "be careful" rests on one thing only: the address couldn't
/// be confirmed, and nothing looked wrong (`final.unconfirmed_only`). The household was
/// shown a milder "be careful" for these.
pub const UNCONFIRMED: &str = "be careful: only because the address couldn't be confirmed";

/// What the summary says when the browser extension keeps falling back from the original
/// mail (the format's own test: `Suscheck::fallback`).
pub const FALLING_BACK: &str = "extension falling back: update its rules";

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
                &compared_cell(c),
                c.kind.as_deref().unwrap_or(""),
                c.sent().as_deref().unwrap_or(""),
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

/// Why `o` has nothing to fetch, where that is known without asking the server: the index
/// says the check was made without a picture, or its record (when it is the one open)
/// says none was kept. None: there may be one.
fn no_picture(v: &View, id: Id) -> Option<String> {
    let check = folder(v).and_then(|s| s.checks.iter().find(|c| c.id == id));
    if let Some(from) = check.and_then(Check::pictureless) {
        return Some(format!(
            "this check was made from {from}: there is no picture"
        ));
    }
    let open = v.s.sus_open.as_ref().filter(|o| o.id == id)?;
    let Some(Ok(Fetched::Ok(i))) = &open.got else {
        return None;
    };
    if i.screenshot {
        return None;
    }
    Some(match (&i.error, i.sent_picture()) {
        (Some(_), _) => "this check failed before a picture was kept: there is no picture".into(),
        (None, Some(false)) => "this check was made without a picture: there is none".into(),
        (None, _) => "no picture was kept for this check".into(),
    })
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
            // Nothing is asked of the server for a picture that was never there.
            Action::Char('o') => match no_picture(v, id) {
                Some(why) => vec![Effect::Toast(why)],
                None => vec![Own::SusPicture(id).into()],
            },
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
        // (The summary is as tall as what it has to say about the extension.)
        let month = s.tally(30);
        let extra = extension_lines(t, s, 200).len() as u16
            + u16::from(month.unconfirmed > 0)
            + u16::from(month.trusted > 0);
        // (The trusted senders have a panel where there is a list: up to three rows an entry.)
        let listed = s.trusted.ok().map(|l| l.senders.len() as u16);
        let newer = matches!(s.trusted, Part::Newer(_) | Part::Damaged);
        if wide {
            let [left, right] =
                Layout::horizontal([Constraint::Length(48), Constraint::Min(40)]).areas(area);
            let [top, bottom] =
                Layout::vertical([Constraint::Length(16 + extra), Constraint::Min(4)]).areas(left);
            summary(f, top, v, s, false);
            if listed.is_some() || newer {
                let rows = device_rows(s);
                let n = (rows.len() + rows.iter().filter(|d| !d.note.is_empty()).count()) as u16;
                let [mid, low] = Layout::vertical([
                    Constraint::Length((n + 3).min(bottom.height.saturating_sub(5))),
                    Constraint::Min(4),
                ])
                .areas(bottom);
                computers(f, mid, v, s);
                trusted(f, low, v, s);
            } else {
                computers(f, bottom, v, s);
            }
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
            // (And the trusted senders where the window is tall enough for all four.)
            let tall = area.height >= 36 && (listed.is_some() || newer);
            let [top, mid, low, rest] = Layout::vertical([
                Constraint::Length(9 + extra),
                Constraint::Length(if roomy { (n + 3).min(9) } else { 0 }),
                Constraint::Length(match tall {
                    true => (listed.unwrap_or(1) * 3 + 2).clamp(3, 8),
                    false => 0,
                }),
                Constraint::Min(4),
            ])
            .areas(area);
            summary(f, top, v, s, true);
            if roomy {
                computers(f, mid, v, s);
            }
            if tall {
                trusted(f, low, v, s);
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
        // What each was made from, in words; the column is as wide as the widest.
        let sent: Vec<String> = list
            .iter()
            .map(|c| c.sent().unwrap_or_else(|| "–".into()))
            .collect();
        let from = sent
            .iter()
            .map(|s| s.chars().count())
            .max()
            .unwrap_or(0)
            .clamp(7, 22) as u16;
        // The columns there is room for beside a readable domain: the brand goes first,
        // then the domain's check (both are in the check itself).
        // (The fixed columns and the gaps come to 59 beside From; the check's column
        // takes 14 more, the brand's 15: the domain keeps 18.)
        let (brand, compared) = match r.width.saturating_sub(from) {
            106.. => (true, true),
            91.. => (false, true),
            _ => (false, false),
        };
        let table: Vec<Row> = list
            .iter()
            .zip(sent)
            .map(|(c, sent)| {
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
                    cells.push(Cell::from(sent).style(t.dim()));
                }
                if wide && brand {
                    cells.push(Cell::from(c.brand.clone().unwrap_or_default()).style(t.fg()));
                }
                // A sender the owner trusts is marked in the comparison's column, and
                // beside the domain where that column has given way.
                let mut domain = c.domain.clone().unwrap_or_default();
                if c.trusted() && !(wide && compared) {
                    domain = format!("trusted: {domain}");
                }
                cells.push(Cell::from(domain).style(t.fg()));
                if wide && compared {
                    cells.push(Cell::from(compared_cell(c)).style(match c.trusted() {
                        true => t.s(t.green),
                        false => t.dim(),
                    }));
                }
                cells.push(Cell::from(yours.0).style(t.s(yours.1)));
                Row::new(cells)
            })
            .collect();
        let (header, widths) = if wide {
            let mut header = vec!["", "When", "Computer", "It said", "From"];
            let mut widths = vec![
                Constraint::Length(1),
                Constraint::Length(12),
                Constraint::Length(14),
                Constraint::Length(26),
                Constraint::Length(from),
            ];
            if brand {
                header.push("Brand");
                widths.push(Constraint::Length(14));
            }
            header.push("Domain");
            widths.push(Constraint::Fill(1));
            if compared {
                header.push("Domain check");
                widths.push(Constraint::Length(13));
            }
            header.push("");
            widths.push(Constraint::Length(1));
            (header, widths)
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
        let got = v.s.sus_open.as_ref().filter(|o| o.id == id).map(|o| &o.got);
        // (The index doesn't say a verdict is the milder one: the record does, once in.)
        let mild = match got {
            Some(Some(Ok(Fetched::Ok(i)))) => Some(i.unconfirmed_only().then(|| kind_of(i))),
            _ => None,
        };
        if let Some(c) = check {
            lines.extend(check_lines(v, c, mild));
        }
        match got {
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
        // How far it scrolls: by the rows the lines take once wrapped (a long line may
        // break early at a word, so each is counted a little narrower than the panel).
        let width = usize::from(r.width.max(20));
        let rows: usize = lines
            .iter()
            .map(|l| match l.width() {
                w if w <= width => 1,
                w => w.div_ceil(width - 16),
            })
            .sum();
        let most = u16::try_from(rows).unwrap_or(u16::MAX).saturating_sub(1);
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

/// Why a record's "be careful" couldn't be confirmed, where it says.
fn kind_of(i: &Incident) -> Option<&str> {
    i.last.as_ref()?.unconfirmed_kind.as_deref()
}

/// What the index says of the check: shown at once, before its record is in.
///
/// `mild`: what the check's own record says of its "be careful", once it is in (`Some`):
/// only because the address couldn't be confirmed (`Some`, with why where it says), or
/// not (`None`). Until then the index's word stands.
fn check_lines(v: &View, c: &Check, mild: Option<Option<Option<&str>>>) -> Vec<Line<'static>> {
    let t = v.t;
    let mut out = Vec::new();
    let plain = c.error.is_none() && c.verdict() == Some(Verdict::Suspicious);
    let said = match mild {
        Some(Some(kind)) if plain => unconfirmed(kind).to_string(),
        Some(None) if plain => Verdict::Suspicious.said().to_string(),
        _ => c.outcome(),
    };
    let mut verdict = vec![
        Span::styled(format!("{:<18}", "It said"), t.dim()),
        Span::styled(said, t.s(verdict_color(t, c))),
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
    if let Some(sent) = c.sent() {
        out.push(row(t, "Made from", sent));
    }
    if let Some(how) = &c.acquired_by {
        out.push(row(t, "Obtained", obtained(how)));
    }
    out.push(Line::raw(""));
    out
}

/// How the message reached SusCheck where the browser extension brought it
/// (`acquired_by`), in words. The extension's own account of what it did.
fn obtained(how: &str) -> String {
    match how {
        "original" => "by the browser extension: the original message, fetched from the mail site",
        "page" => {
            "by the browser extension: only the sender, subject and links, read off the mail \
             page (a fallback)"
        }
        "paste" => {
            "by the browser extension: it couldn't get the message and asked for a paste (a \
             fallback)"
        }
        "picture" => "by the browser extension: only a picture of the tab (a fallback)",
        _ => return how.replace('_', " "),
    }
    .to_string()
}

/// What the browser extension says the mail program showed for the message
/// (`mail_label`), in words: its claim, which SusCheck didn't check.
fn mail_label(label: &str) -> String {
    match label {
        "spam" => "the mail site had it in spam (the extension's word: not checked)",
        "phishing_warning" => {
            "the mail site showed a phishing warning (the extension's word: not checked)"
        }
        "none" => "the extension saw neither a spam nor a phishing label on it",
        _ => return label.replace('_', " "),
    }
    .to_string()
}

/// What the summary has to say about the browser extension, where a check came through
/// it: how many it got as the original mail and by each fallback (of the checks read),
/// and that it keeps falling back when the format's test says so.
fn extension_lines(t: &Theme, s: &Suscheck, width: usize) -> Vec<Line<'static>> {
    let n = |how: &str| {
        s.checks
            .iter()
            .filter(|c| c.acquired_by.as_deref() == Some(how))
            .count()
    };
    let original = n("original");
    let fell: Vec<String> = ACQUIRED
        .iter()
        .filter(|(how, _)| *how != "original" && n(how) > 0)
        .map(|(how, said)| format!("{said} {}", n(how)))
        .collect();
    let back: usize = ACQUIRED
        .iter()
        .filter(|(how, _)| *how != "original")
        .map(|(how, _)| n(how))
        .sum();
    let mut out = Vec::new();
    if original + back > 0 {
        let label = "by extension: ";
        let mut said = format!("{original} original");
        if back > 0 {
            said += &format!(" · {back} fell back");
            // (How each fell back, where there is room: the side panel has none.)
            let how = format!(" ({})", fell.join(" · "));
            if label.len() + said.len() + how.len() <= width {
                said += &how;
            }
        }
        out.push(Line::from(vec![
            Span::styled(label, t.dim()),
            Span::styled(trunc(&said, width.saturating_sub(label.len())), t.fg()),
        ]));
    }
    if s.fallback().is_some() {
        out.push(Line::styled(trunc(FALLING_BACK, width), t.s(t.yellow)));
    }
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

/// A rule of SusCheck's (`final.floors`) as a short phrase, by what the format says each
/// means. One this sentry has no words for is shown as it is (already cleaned), its
/// underscores as spaces. (The tag of a comparison is [`why`]'s.)
fn tag(code: &str) -> String {
    match code {
        "digit_in_name" => "a digit where the name has a letter",
        "talks_to_ai" => "text written to steer an AI",
        "lookalike" => "the address imitates the real one",
        "close_imitation" => "one small change from the real address",
        "mismatch_risky" => "a different address, and it asks for something risky",
        "public_ip" => "a public IP address, not a name",
        "unknown" => "the address couldn't be compared",
        "weak_match_risky" => "matched by web search only, and it asks for something risky",
        "safe_needs_match" => "no warning signs, but the address isn't a match",
        "search_down" => "the web search couldn't help",
        "brand_address_risky" => {
            "the address carries the company's name without being its own, with a risky ask or pressure"
        }
        "model_without_grounds" => "the model's \"don't trust this\" had no concrete ground: lowered",
        "model_worry_without_grounds" => "the model's worry had no warning-level ground: set aside",
        "not_readable" => "not readable as an email or a web page",
        "picture_only" => "the address was only read from a picture",
        "link_text_mismatch" => "a link's text is an address, and it leads to another",
        "link_lookalike" => "a link leads to an address one small change from a genuine one",
        "link_mailto_mismatch" => "a link's text is an email address, and it writes to another",
        "link_odd_target" => "a link that doesn't lead to an ordinary named site",
        "links_unchecked" => "more links than SusCheck analyses",
        "reply_to_differs" => "replies go to another domain",
        "display_name_address" => "the sender's name shows another address",
        "auth_failed" => "the mail's reported checks failed",
        "risky_attachment" => "an attachment named like a program or a script",
        "trusted_unauthenticated" => {
            "claims a sender you trust, which the mail server couldn't confirm"
        }
        "sender_not_brand_domain" => "a confirmed sender, but not at the company's own address",
        "message_faults" => {
            "put together in a broken way ordinary mail programs don't produce (a remark)"
        }
        "mail_label_spam" => "the mail site had already put it in spam",
        "mail_label_phishing" => "the mail site itself warned of phishing",
        "sender_domain_not_real" => "the sender's domain can't exist",
        "link_shared_hosting" => "a link to a platform anyone can publish on, or a shortener",
        "body_is_one_link" => "most of the message is one link",
        "freemail_sender" => "sent from a free personal mail address, not a company's",
        "freemail_invoice_attachment" => {
            "a bill as an attachment from a personal address, with signs of a made-up sender"
        }
        "freemail_invoice_mild" => "a bill as an attachment from a personal address",
        "return_path_differs" => "bounces go to another domain",
        "display_name_is_recipient" => "the sender's name is the start of the recipient's address",
        _ => return code.replace('_', " "),
    }
    .to_string()
}

/// How the address compared with the brand's real one (`domain_check`, `check.result`),
/// by the format's one line for each. One this sentry has no words for is shown as it is.
fn compared(result: &str) -> String {
    match result {
        "match_trusted" => {
            "one the owner listed for this brand, or a trusted sender the mail system confirmed"
        }
        "match_search" => "the address web search agrees is the brand's own",
        "lookalike" => "it imitates a genuine address",
        "mismatch" => {
            "not the genuine address: another one, a public IP, a shared platform or related service"
        }
        "unknown" => "nothing could be confirmed either way",
        "local" => "a private or loopback address on the home network",
        _ => return result.replace('_', " "),
    }
    .to_string()
}

/// What the list's Domain check column says of a check: a sender the owner trusts (and
/// the mail system confirmed) is `trusted`, anything else the comparison in a word or two.
fn compared_cell(c: &Check) -> String {
    match c.trusted() {
        true => "trusted".into(),
        false => c
            .domain_check
            .as_deref()
            .map(compared_short)
            .unwrap_or_default(),
    }
}

/// The milder "be careful" as the open check says it, by why the address couldn't be
/// confirmed (`final.unconfirmed_kind`); a kind this sentry has no words for, or none, is
/// [`UNCONFIRMED`].
fn unconfirmed(kind: Option<&str>) -> &'static str {
    match kind {
        Some("picture") => "be careful: the address was only read from a picture",
        Some("other_domain") => {
            "be careful: a confirmed sender, but not at the company's own address"
        }
        Some("small_sender") => "be careful: nobody could confirm this sender independently",
        Some("personal_address") => {
            "be careful: a personal mailbox; only you know if you know them"
        }
        Some("platform_sender") => {
            "be careful: sent through a service for someone; replies go to them"
        }
        _ => UNCONFIRMED,
    }
}

/// A kind of strong evidence SusCheck's code found (`final.strong_evidence`): what alone
/// makes its rules say "don't trust this".
fn strong(kind: &str) -> String {
    match kind {
        "close_imitation" => {
            "the address is a character away from a genuine one, or hides behind real@other"
        }
        "link_close_imitation" => "a link leads to such an imitation of a genuine address",
        "link_text_close_imitation" => "a link shows a web address and leads to an imitation of it",
        "sender_cannot_exist" => {
            "the sender's domain can't exist, and something else is wrong with the message"
        }
        "freemail_throwaway_invoice" => "a bill as an attachment from a throwaway personal address",
        _ => return kind.replace('_', " "),
    }
    .to_string()
}

/// What decided that the address belongs with the company it was compared to
/// (`domain.related_by`), in words.
fn related_by(what: &str) -> String {
    match what {
        "family" => "SusCheck's fixed table of related domains and list hosts",
        "search" => "the search for the domain",
        _ => return what.replace('_', " "),
    }
    .to_string()
}

/// The one word the model was given for how the comparison came out (`domain.judge_word`),
/// in words.
fn judge_word(word: &str) -> String {
    match word {
        "match" => "a match",
        "lookalike" => "an imitation",
        "mismatch" => "a different address",
        "unknown" => "unknown",
        "local_device" => "a device on the home network",
        "unconfirmed" => "unconfirmed: a small sender nobody could confirm",
        "personal_address" => "a personal mailbox",
        "other_domain" => "sent through another address than the company's own",
        _ => return word.replace('_', " "),
    }
    .to_string()
}

/// The same in a word or two, for the list's column.
fn compared_short(result: &str) -> String {
    match result {
        "match_trusted" => "owner's list",
        "match_search" => "search agrees",
        "lookalike" => "imitation",
        "mismatch" => "different",
        "unknown" => "unconfirmed",
        "local" => "home network",
        _ => return result.replace('_', " "),
    }
    .to_string()
}

/// How that result was reached (`check.why`), by the format's one line for each of its
/// twenty tags. `digit_in_name` is also a rule's name: there it is [`rule`]'s to word.
fn why(code: &str) -> String {
    match code {
        "exact" => "exactly the genuine domain",
        "trusted_sender" => "on the owner's trusted senders list, and the mail system confirmed it",
        "trusted_unauthenticated" => {
            "on the trusted senders list, but the mail system didn't confirm it: not treated as trusted"
        }
        "punycode" => "part of it is written in punycode, which draws look-alike letters",
        "userinfo" => "a name and an @ before the host, which hides where it goes",
        "confusable" => {
            "it is the genuine address once look-alike characters are read as what they imitate"
        }
        "edit_distance" => {
            "a character or two changed, added, dropped, doubled or swapped from the genuine address"
        }
        "brand_in_subdomain" => "the genuine name is used as a subdomain of another domain",
        "brand_in_label" => "the genuine name is a word inside another domain's name, or at its start or end",
        "brand_in_address" => {
            "a confirmed sender whose address only carries the company's name inside another one"
        }
        "shared_platform" => {
            "a platform where anyone can have an address or a page: it is whoever set it up"
        }
        "same_owner" => "another of the confirmed company's own domains, and the mail system confirmed it",
        "same_owner_unconfirmed" => {
            "another domain of the confirmed company, but not one of its mail domains, or unconfirmed"
        }
        "related_service" => "search found the company's own site talking about or hosting this domain",
        "match_unconfirmed" => {
            "it equals the one search result found, and one result isn't confirmation"
        }
        "different" => "unrelated to the confirmed genuine address",
        "public_ip" => "a public IP address, not a name",
        "private_ip" => "a private or loopback IP address",
        "no_domain" => "no usable address was read or supplied",
        "no_candidates" => {
            "nothing to compare it with: no owner's entry, no search result for the brand"
        }
        "no_confirmed_candidate" => "search confirmed no candidate, and it matches none of them",
        "readings_differ" => "two readings of the address in the picture disagreed",
        "ocr_differs" => "a match withdrawn: the text recogniser read another address",
        "shapes_differ" => {
            "a match withdrawn: the letter shapes in the picture can't spell the address read"
        }
        "digit_in_name" => "a search match withdrawn: a digit stands where the brand has a letter",
        "freemail" => "a free personal mailbox: there is no company address to compare with",
        "not_a_real_domain" => "the sender's domain can't exist",
        _ => return code.replace('_', " "),
    }
    .to_string()
}

/// A rule as [`tag`] words it, in the record it stands in: `digit_in_name` was a wider
/// rule (any digit with a letter on each side) in records from before `domain.digit_rule`.
fn rule(code: &str, i: &Incident) -> String {
    let reworked = i.domain.as_ref().is_some_and(|d| d.digit_rule.is_some());
    let reply = i.last.as_ref().and_then(|l| l.reply_to_differs.as_deref());
    match (code, reply) {
        ("digit_in_name", _) if !reworked => "a digit inside a word of the address".into(),
        // (Where the record says how it was treated; one from before doesn't.)
        ("reply_to_differs", Some("remark")) => format!("{} (a remark)", tag(code)),
        ("reply_to_differs", Some("warning")) => format!("{} (a warning)", tag(code)),
        ("reply_to_differs", Some(other)) => {
            format!("{} ({})", tag(code), other.replace('_', " "))
        }
        _ => tag(code),
    }
}

/// What code found about a link (`links[].flags`), in words.
fn link_flag(code: &str) -> String {
    match code {
        "text_mismatch" => "its text is another address",
        "imitates_text" => "imitates the address in its text",
        "mailto_mismatch" => "its text is an email address, and it writes to another",
        "lookalike" => "imitates the real address",
        "close_imitation" => "one small change from the real one",
        "userinfo" => "a name and an @ in front of the address",
        "punycode" => "punycode",
        "ip_address" => "a bare IP address",
        "odd_scheme" => "an unusual scheme",
        "unreadable" => "not a readable address",
        "no_target" => "a relative link: it leads nowhere by itself",
        "shared_hosting" => "a platform anyone can publish on, or a shortener",
        _ => return code.replace('_', " "),
    }
    .to_string()
}

/// A word that describes a link and decides nothing (`links[].notes`), in words.
fn link_note(code: &str) -> String {
    match code {
        "tracked" => "through the message's own click-tracking host",
        "brand_in_address" => "carries a genuine name inside another address",
        _ => return code.replace('_', " "),
    }
    .to_string()
}

/// Where the address the verdict rests on came from (`domain.source`), in words.
fn source_said(source: &str) -> String {
    match source {
        "email_header" => "the email's own header",
        "window" => "read out of the window by the app",
        "screenshot" => "read from the picture",
        _ => return source.replace('_', " "),
    }
    .to_string()
}

/// Which field of the model's reading of the picture gave the first reading
/// (`domain.first_reading_from`), in words.
fn read_in(field: &str) -> String {
    match field {
        "sender_address" => "the sender's address",
        "sender_host" => "the sender field, which held a bare host and no @",
        "address_bar" => "the address bar",
        _ => return field.replace('_', " "),
    }
    .to_string()
}

/// What the digit rule found (`domain.digit_rule`), in words. `clear` is no more than
/// that the rule looked: never that the address is genuine.
fn digit_rule(found: &str) -> String {
    match found {
        "fired" => "a digit stands where the name has a letter",
        "clear" => {
            "looked, and found no digit in a letter's place (the address may still not be genuine)"
        }
        "not_evaluated" => {
            "couldn't look: no trustworthy text of the address, or nothing to hold it against"
        }
        _ => return found.replace('_', " "),
    }
    .to_string()
}

/// A fact SusCheck's code worked out about the message (`email.signals`), in words.
fn signal(key: &str) -> String {
    match key {
        "body_nearly_empty" => "an attachment, and almost no text",
        "random_address" => "the sender's address looks machine-made",
        "names_disagree" => "the sender's name isn't the person the message names",
        "money_wording" => "words about money (payment, invoice, order…)",
        "return_path_differs" => "bounces go to another domain",
        "body_is_one_link" => "most of the message is one link",
        "display_name_is_recipient" => "the sender's name is the start of the recipient's address",
        "name_matches_address" => {
            "the sender's name is its own domain's name (and it passed DMARC)"
        }
        "mailing_list" => "it has a mailing-list header (anyone can write one)",
        _ => return key.replace('_', " "),
    }
    .to_string()
}

/// A search SusCheck ran (`search.queries[].kind`, `search.failed`), in words.
fn query(kind: &str) -> String {
    match kind {
        "official" => "the official site",
        "official2" => "the official site, by the sender's name",
        "domain" => "what the domain is",
        "phone" => "the phone number",
        _ => return kind.replace('_', " "),
    }
    .to_string()
}

/// "and N more", where a list was cut (`note`: what else is to be said of the count).
fn and_more(t: &Theme, n: u64, note: &str) -> Option<Line<'static>> {
    (n > 0).then(|| Line::styled(format!("  and {n} more{note}"), t.dim()))
}

/// The email as SusCheck's code read its headers. Text and nothing else: an address is
/// never resolved, opened or copied anywhere.
fn email_lines(
    t: &Theme,
    e: &crate::collect::suscheck::Email,
    label: Option<&str>,
) -> Vec<Line<'static>> {
    let mut out = vec![head(t, "The email (its headers, read by SusCheck's code)")];
    out.push(row(
        t,
        "  from",
        format!(
            "{} <{}>",
            e.from_name.as_deref().unwrap_or("–"),
            e.from_address.as_deref().unwrap_or("no readable address")
        ),
    ));
    // What stood where an address should have: text, as everything here.
    if let Some(w) = &e.from_written {
        out.push(row(t, "  written as", w.clone()));
    }
    if let Some(provider) = &e.freemail {
        out.push(row(
            t,
            "  sent from",
            format!("a free personal mail address ({provider}), not a company's"),
        ));
    }
    // Where replies and bounces go, when that isn't where it says it is from.
    for (label, to) in [
        ("  replies go to", &e.reply_to),
        ("  bounces go to", &e.return_path),
    ] {
        if let Some(a) = to.as_ref().filter(|a| {
            e.from_address
                .as_ref()
                .is_none_or(|f| !f.eq_ignore_ascii_case(a))
        }) {
            out.push(row(t, label, a.clone()));
        }
    }
    out.push(row(
        t,
        "  subject",
        e.subject.clone().unwrap_or_else(|| "–".into()),
    ));
    out.push(row(
        t,
        "  date",
        e.date.clone().unwrap_or_else(|| "–".into()),
    ));
    out.push(row(
        t,
        "  authentication",
        format!(
            "{} (as the message reports it)",
            ["spf", "dkim", "dmarc"]
                .iter()
                .zip(&e.auth)
                .map(|(k, v)| format!("{k} {}", v.as_deref().unwrap_or("not stated")))
                .collect::<Vec<_>>()
                .join(" · ")
        ),
    ));
    if e.attachments_total == 0 {
        out.push(row(t, "  attachments", "none".into()));
    } else {
        out.push(row(
            t,
            "  attachments",
            format!("{} (declared; none is kept)", e.attachments_total),
        ));
        for a in &e.attachments {
            out.push(Line::styled(
                format!(
                    "  · {} ({}, {})",
                    a.name.as_deref().unwrap_or("(no name)"),
                    a.kind.as_deref().unwrap_or("no type"),
                    a.size.map_or("size unknown".into(), fmt::bytes)
                ),
                t.fg(),
            ));
        }
        out.extend(and_more(
            t,
            e.attachments_total
                .saturating_sub(e.attachments.len() as u64),
            "",
        ));
    }
    if let Some(n) = e.links_total {
        out.push(row(t, "  links", n.to_string()));
    }
    if e.aimed_at_ai == Some(true) {
        out.push(Line::styled("  has text addressed to an AI", t.s(t.yellow)));
    }
    if let Some(label) = label {
        out.push(row(t, "  mail site", mail_label(label)));
    }
    // Faults in how the message was put together: SusCheck's own fixed words, recorded
    // only. A record that doesn't have them doesn't say (which isn't "none").
    if let Some(faults) = &e.defects {
        let said = |w: &[&str]| {
            w.iter()
                .map(|x| x.replace('_', " "))
                .collect::<Vec<_>>()
                .join(" · ")
        };
        out.push(row(
            t,
            "  faults",
            match faults.is_empty() {
                true => "none in how the message was put together".into(),
                false => format!(
                    "{} (in how the message was put together; recorded only)",
                    said(&faults.iter().map(String::as_str).collect::<Vec<_>>())
                ),
            },
        ));
        let (notable, own) = e.notable();
        if !notable.is_empty() {
            out.push(row(
                t,
                "  notable",
                format!(
                    "{} ({})",
                    said(&notable),
                    match own {
                        true => "ordinary mail programs don't write these; the model was told",
                        false => "by today's list; then they were recorded and had no effect",
                    }
                ),
            ));
        }
    }
    if !e.signals.is_empty() {
        out.push(Line::styled(
            "  what SusCheck's code noticed (hints, never proof)",
            t.dim(),
        ));
        out.extend(bullets(
            t,
            &e.signals.iter().map(|k| signal(k)).collect::<Vec<_>>(),
        ));
    }
    out
}

/// The links SusCheck's code analysed: text → where it leads. The target is a domain as
/// SusCheck stored it (defanged): shown as it is, never resolved, opened or copied.
fn link_lines(t: &Theme, i: &Incident) -> Vec<Line<'static>> {
    let Some(links) = &i.links else {
        return Vec::new();
    };
    let mut out = vec![head(t, "Links (text only: never open one)")];
    if links.is_empty() {
        out.push(Line::styled("  (none)", t.dim()));
    }
    for l in links {
        let scheme = match l.scheme.as_deref() {
            None => "?".to_string(),
            Some("none") => "no scheme".into(),
            Some("other") => "another scheme".into(),
            Some(s) => s.to_string(),
        };
        let flagged = !l.flags.is_empty();
        let mut spans = vec![
            Span::styled(
                format!("  · {}", l.text.as_deref().unwrap_or("(no text)")),
                t.fg(),
            ),
            Span::styled(" → ", t.dim()),
            Span::styled(
                l.target.clone().unwrap_or_else(|| "no address".into()),
                if flagged { t.s(t.yellow) } else { t.fg() },
            ),
            Span::styled(format!(" · {scheme}"), t.dim()),
        ];
        if flagged {
            spans.push(Span::styled(
                format!(
                    " · {}",
                    l.flags
                        .iter()
                        .map(|f| link_flag(f))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                t.s(t.yellow),
            ));
        }
        // Notes describe a link and decide nothing: never a warning's colour.
        if !l.notes.is_empty() {
            spans.push(Span::styled(
                format!(
                    " · note: {}",
                    l.notes
                        .iter()
                        .map(|n| link_note(n))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                t.dim(),
            ));
        }
        out.push(Line::from(spans));
    }
    match i.links_left() {
        // The record says how the rest split: left out at a limit, or exact repeats.
        Some((cut, repeats)) => {
            out.extend(and_more(t, cut, ", left out at a limit"));
            if repeats > 0 {
                out.push(Line::styled(
                    format!(
                        "  {repeats} more {} of a link already listed or counted",
                        if repeats == 1 {
                            "was an exact repeat"
                        } else {
                            "were exact repeats"
                        },
                    ),
                    t.dim(),
                ));
            }
        }
        // (A record from before the split was written: its own count is from before
        // exact repeats were merged into one line.)
        None => {
            let note = match i.links_total {
                Some(_) => ", exact repeats of these included",
                None => "",
            };
            out.extend(and_more(t, i.links_more(), note));
        }
    }
    out
}

/// What the record's first part is called: what the model read, and from what.
fn read_from(i: &Incident) -> &'static str {
    match (i.sent_picture(), i.sent_email()) {
        (Some(false), true) => "What it read from the message",
        (Some(false), false) => "What it read from the page",
        _ => "What it read from the picture",
    }
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
            Span::styled(
                match i.unconfirmed_only() {
                    true => unconfirmed(kind_of(i)).to_string(),
                    false => said(lv).to_string(),
                },
                t.s(word_color(t, lv)),
            ),
            Span::styled(
                format!(" ({})", l.confidence.as_deref().unwrap_or("?")),
                t.dim(),
            ),
        ]));
        // A rule or two on the line; more as a list (a check of an email file has many).
        // The rules can raise the model's verdict, and in later records lower it: which
        // way is told by the two verdicts, where both are known.
        let rank = |v: &str| {
            Verdict::of(v).map(|v| match v {
                Verdict::Safe => 0,
                Verdict::Suspicious => 1,
                Verdict::Malicious => 2,
            })
        };
        let did = match (l.floors_changed, rank(jv), rank(lv)) {
            (Some(true), Some(a), Some(b)) if b > a => "raised the verdict",
            (Some(true), Some(a), Some(b)) if b < a => "lowered the verdict",
            (Some(true), _, _) => "changed the verdict",
            _ => "the verdict stood",
        };
        let rules: Vec<String> = l.floors.iter().map(|f| rule(f, i)).collect();
        let one = format!("{}: {did}", rules.join(" · "));
        match rules.len() {
            0 => out.push(row(t, "SusCheck's rules", "none applied".into())),
            // (One or two on the row, where they fit it.)
            1 | 2 if one.chars().count() <= 84 => out.push(row(t, "SusCheck's rules", one)),
            _ => {
                out.push(row(t, "SusCheck's rules", format!("{did}:")));
                out.extend(bullets(t, &rules));
            }
        }
        // The model's own verdict lowered for want of a ground, where the record says so.
        if l.model_capped {
            out.push(row(
                t,
                "Model lowered",
                "it said \"don't trust this\" with no concrete ground: lowered to \"be careful\""
                    .into(),
            ));
        }
        if l.model_softened {
            out.push(row(
                t,
                "Model set aside",
                "its worry had no warning-level ground: judged as if it had seen nothing wrong"
                    .into(),
            ));
        }
        // Who said "don't trust this": SusCheck's rules do only on strong evidence, so
        // with none it is the model's own verdict. (A record from before doesn't say:
        // older rules applied.)
        match &l.strong_evidence {
            Some(kinds) if !kinds.is_empty() => {
                out.push(row(
                    t,
                    "Strong evidence",
                    "found by SusCheck's own rules, which alone say \"don't trust this\":".into(),
                ));
                out.extend(bullets(
                    t,
                    &kinds.iter().map(|k| strong(k)).collect::<Vec<_>>(),
                ));
            }
            Some(_) if Verdict::of(lv) == Some(Verdict::Malicious) => out.push(row(
                t,
                "Strong evidence",
                "none found by SusCheck's rules: \"don't trust this\" is the model's own verdict"
                    .into(),
            )),
            _ => {}
        }
        if l.trusted_sender {
            out.push(Line::from(vec![
                Span::styled(format!("{:<18}", "Trusted sender"), t.dim()),
                Span::styled(
                    "on the owner's trusted list when it was checked, and confirmed by the mail system",
                    t.s(t.green),
                ),
            ]));
        }
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
        out.push(head(t, read_from(i)));
        let or = |o: &Option<String>| o.clone().unwrap_or_else(|| "–".into());
        out.push(row(
            t,
            "  kind",
            x.kind.as_deref().unwrap_or("?").replace('_', " "),
        ));
        out.push(row(t, "  claims to be", or(&x.claimed_brand)));
        // Who read what: with an email file the sender is the header's, with the window's
        // address the address bar is the window's; the link texts are always the model's.
        if x.sender_name.is_some() || x.sender_address.is_some() {
            out.push(row(
                t,
                "  sender",
                format!(
                    "{} <{}>{}",
                    or(&x.sender_name),
                    or(&x.sender_address),
                    match i.sent_email() {
                        true => " (the header's exact values)",
                        false => "",
                    }
                ),
            ));
        }
        if x.address_bar_domain.is_some() {
            out.push(row(
                t,
                "  address bar",
                format!(
                    "{}{}",
                    or(&x.address_bar_domain),
                    // (From the mail site's window nothing is put here: with a picture it
                    // is the model's reading of the address bar, the mail site's own.)
                    match (i.mail_window(), i.sent_page()) {
                        (true, _) =>
                            " (read in the picture: the mail site's own, not the sender's)",
                        (false, true) => " (the window's exact address)",
                        (false, false) => "",
                    }
                ),
            ));
        }
        if !x.link_texts.is_empty() {
            out.push(row(
                t,
                "  links",
                format!(
                    "{}{}",
                    x.link_texts.join(" · "),
                    match i.links {
                        Some(_) => " (the model's reading: go by Links below)",
                        None => "",
                    }
                ),
            ));
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
                "urgency: {} · text addressed to an AI: {}{}",
                yes_no(x.urgency),
                yes_no(x.talks_to_ai),
                // (Also yes when the model missed it and the phrase list didn't.)
                match i.email.as_ref().and_then(|e| e.aimed_at_ai) {
                    Some(true) if x.talks_to_ai == Some(true) =>
                        " (SusCheck's phrase list found some)",
                    _ => "",
                }
            ),
        ));
    }
    // Where the address came from. A record in the old shape doesn't say: a picture.
    if let Some((d, source)) = i
        .domain
        .as_ref()
        .map(|d| (d, d.source.as_deref().unwrap_or("screenshot")))
    {
        out.push(Line::raw(""));
        out.push(head(t, "Where the address came from"));
        let exact = source != "screenshot";
        out.push(row(
            t,
            "  source",
            format!(
                "{}{}",
                source_said(source),
                match source {
                    "email_header" | "window" => ": exact text, not a reading",
                    "screenshot" => ": a reading by the model, not exact text",
                    _ => "",
                }
            ),
        ));
        match &d.exact {
            Some(x) => out.push(row(t, "  exact address", x.clone())),
            None if exact => out.push(row(t, "  exact address", "none usable in it".into())),
            None => {}
        }
        // What the model read in the picture all the same, when it was something else.
        if let Some(read) = d
            .first_reading
            .as_ref()
            .filter(|r| exact && d.shown.as_ref().is_some_and(|s| s != *r))
        {
            out.push(row(
                t,
                "  the model read",
                format!("{read} in the picture (not used)"),
            ));
        }
        // (A registrable domain, held against the first reading's own, as the shuffled
        // reading below.)
        if let Some(ocr) = d
            .ocr_reading
            .as_ref()
            .filter(|o| Incident::same_domain(d.first_reading.as_deref(), o) != Some(true))
        {
            out.push(row(t, "  text recogniser", format!("read {ocr}")));
        }
        if let Some(field) = &d.first_reading_from {
            out.push(row(
                t,
                "  first read in",
                format!("{} (the model's reading of the picture)", read_in(field)),
            ));
        }
        // The letter shapes found in the picture, against the first reading: only when
        // they can't spell it does it count; touching letters are said as what they are.
        match d.shape_fit.as_deref() {
            None | Some("fits") => {}
            Some("differs") => out.push(Line::from(vec![
                Span::styled(format!("{:<18}", "  letter shapes"), t.dim()),
                Span::styled(
                    "can't spell the address the model read: that takes a match away",
                    t.s(t.yellow),
                ),
            ])),
            Some("touching") => out.push(row(
                t,
                "  letter shapes",
                "fit only with letters drawn touching (common at small sizes: it means nothing)"
                    .into(),
            )),
            Some(other) => out.push(row(t, "  letter shapes", other.replace('_', " "))),
        }
        if let Some(read) = d
            .shuffled_reading
            .as_ref()
            .filter(|r| Incident::same_domain(d.first_reading.as_deref(), r) != Some(true))
        {
            out.push(row(
                t,
                "  shuffled",
                format!("read {read} (shown the letter shapes one by one, out of order)"),
            ));
        }
        if let Some(found) = &d.digit_rule {
            out.push(row(t, "  digit rule", digit_rule(found)));
        }
    }
    if let Some(e) = &i.email {
        out.push(Line::raw(""));
        out.extend(email_lines(t, e, i.mail_label.as_deref()));
    } else if let Some(label) = &i.mail_label {
        // (No email file, as when the extension could only read the page.)
        out.push(Line::raw(""));
        out.push(row(t, "Mail site", mail_label(label)));
    }
    if i.message {
        out.push(Line::styled(MESSAGE_KEPT, t.dim()));
    }
    if i.links.is_some() {
        out.push(Line::raw(""));
        out.extend(link_lines(t, i));
    }
    if let Some(p) = &i.page {
        out.push(Line::raw(""));
        // Read by the browser extension, the window is the mail site's: its address is
        // the mail site's own, and never the one the verdict rests on.
        let mail = i.mail_window();
        out.push(head(
            t,
            match mail {
                true => "The page (the mail site's window, as the browser extension read it)",
                false => "The page (as the app read the window)",
            },
        ));
        out.push(row(
            t,
            "  address",
            match (mail, p.url_domain.as_deref()) {
                (true, Some(d)) => {
                    format!("{d} (the mail site's own: never the sender's, never compared)")
                }
                // (Today's extension leaves it out.)
                (true, None) => {
                    "not sent (it would be the mail site's own, never the sender's)".into()
                }
                (false, Some(d)) => d.to_string(),
                (false, None) => "none usable".into(),
            },
        ));
        out.push(row(
            t,
            "  title",
            p.title.clone().unwrap_or_else(|| "–".into()),
        ));
        out.push(row(
            t,
            "  links",
            p.links_total
                .map_or("no list was sent".into(), |n| n.to_string()),
        ));
        if let Some(s) = &p.source {
            out.push(row(
                t,
                "  read through",
                match s.as_str() {
                    "extension" => "the browser extension".into(),
                    s => s.replace('_', " "),
                },
            ));
        }
    }
    if let Some(d) = &i.domain {
        out.push(Line::raw(""));
        out.push(head(t, "The domain (text only: never open it)"));
        let or = |o: &Option<String>| o.clone().unwrap_or_else(|| "none read".into());
        // (No picture, no readings of one.)
        if i.sent_picture() != Some(false) {
            out.push(row(t, "  first reading", or(&d.first_reading)));
            // (Both are full hosts, and the same only when they are the same text.)
            let differ = match (&d.first_reading, &d.second_reading) {
                (Some(a), Some(b)) => !a.eq_ignore_ascii_case(b),
                _ => false,
            };
            out.push(row(
                t,
                "  second reading",
                format!(
                    "{}{}",
                    or(&d.second_reading),
                    if differ {
                        " (differs from the first)"
                    } else {
                        ""
                    }
                ),
            ));
        }
        out.push(row(
            t,
            "  compared",
            d.result.as_deref().map_or("?".into(), compared),
        ));
        if let Some(w) = &d.why {
            out.push(row(
                t,
                "  because",
                match (w.as_str(), d.result.as_deref()) {
                    // (As a comparison's tag it is a search match withdrawn; a record
                    // from before the rule was reworked gets the old rule's words.)
                    ("digit_in_name", _) if d.digit_rule.is_none() => rule(w, i),
                    _ => why(w),
                },
            ));
        }
        if let Some(what) = &d.related_by {
            out.push(row(
                t,
                "  related by",
                format!("{} (what related them)", related_by(what)),
            ));
        }
        if let Some(w) = &d.judge_word {
            out.push(row(
                t,
                "  put to model",
                format!("as {} (as told: not a second result)", judge_word(w)),
            ));
        }
        if d.shown.is_some() || d.real.is_some() {
            out.push(row(
                t,
                "  addresses",
                [
                    d.shown.as_ref().map(|s| format!("on screen {s}")),
                    d.real.as_ref().map(|s| format!("the real one {s}")),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" · "),
            ));
        }
    }
    if let Some(s) = &i.search {
        out.push(Line::raw(""));
        // What `ok: false` means went by the record's time: any search failed (a record
        // without `failed`), the official site's did (one with `failed`), the search as
        // a whole couldn't help (one that also lists what was `empty`).
        out.push(head(
            t,
            match (s.ok, &s.failed, &s.empty) {
                (Some(false), Some(_), Some(_)) => {
                    "Searches SusCheck ran (the search as a whole couldn't help)"
                }
                (Some(false), Some(_), None) => {
                    "Searches SusCheck ran (the one for the official site failed or came back empty)"
                }
                (Some(false), None, _) => "Searches SusCheck ran (one failed or timed out)",
                _ => "Searches SusCheck ran",
            },
        ));
        if s.queries.is_empty() {
            out.push(none());
        }
        if s.domain_vouched == Some(true) {
            out.push(Line::styled(
                "  the company's own site talks about or hosts the sender's domain (this only softens the check)",
                t.dim(),
            ));
        }
        let failed = s.failed.as_deref().unwrap_or(&[]);
        if !failed.is_empty() {
            out.push(Line::from(vec![
                Span::styled(format!("{:<18}", "  failed"), t.dim()),
                Span::styled(
                    format!(
                        "{} (failed or timed out)",
                        failed
                            .iter()
                            .map(|k| query(k))
                            .collect::<Vec<_>>()
                            .join(" · ")
                    ),
                    t.s(t.yellow),
                ),
            ]));
        }
        // A kind said to have found nothing that no query here has (one this sentry
        // doesn't know): said as it is. The others say so under their own query.
        let empty = s.empty.as_deref().unwrap_or(&[]);
        let stray: Vec<String> = empty
            .iter()
            .filter(|k| !s.queries.iter().any(|q| &q.kind == *k))
            .map(|k| query(k))
            .collect();
        if !stray.is_empty() {
            out.push(row(t, "  found nothing", stray.join(" · ")));
        }
        // The engines that didn't answer: a note about the search service, nothing more.
        if let Some(names) = s.unresponsive.as_ref().filter(|n| !n.is_empty()) {
            out.push(row(
                t,
                "  not answering",
                format!(
                    "{} (search engines that didn't answer some query: a note, it decides nothing)",
                    names.join(" · ")
                ),
            ));
        }
        for q in &s.queries {
            out.push(row(t, &format!("  {}", q.kind), q.query.clone()));
            if q.hits.is_empty() {
                out.push(Line::styled(
                    match (failed.contains(&q.kind), empty.contains(&q.kind)) {
                        (true, _) => "      failed or timed out",
                        (false, true) => "      answered, and found nothing",
                        // (A record from before the two were told apart, or one that
                        // lists the query under neither.)
                        (false, false) => "      nothing came back",
                    },
                    t.dim(),
                ));
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
    // A stage that ran is a time, however short; one that didn't is said so.
    out.push(row(
        t,
        "  time",
        format!(
            "{} in all{}",
            secs(i.duration_ms),
            i.stages
                .iter()
                .filter_map(|(n, ms)| Some(format!(" · {n} {}", secs((*ms)?))))
                .collect::<String>(),
        ),
    ));
    let not: Vec<&str> = i
        .stages
        .iter()
        .filter(|(_, ms)| ms.is_none())
        .map(|(n, _)| *n)
        .collect();
    if !not.is_empty() {
        out.push(row(t, "  not run", not.join(", ")));
    }
    out.push(row(
        t,
        "  picture",
        if i.screenshot {
            "kept: o fetches it to a private cache here and opens it (gone when sentry closes)"
                .into()
        } else {
            match (&i.error, i.sent_picture()) {
                (None, Some(false)) => "none: this check was made without one".to_string(),
                _ => "none was kept".to_string(),
            }
        },
    ));
    out
}

/// The checks of the last 7 and 30 days by what they were made from, in one line:
/// `picture 4/6 · email 1/1 · page address 1/1` (a check made from two counts under both;
/// one with nothing recorded under none; a value this sentry doesn't know under `other`).
fn made_from(s: &Suscheck, short: bool) -> String {
    // (picture, email, page address, other), for 7 and for 30 days.
    let mut n = [[0u32; 2]; 4];
    for (span, days) in [7, 30].into_iter().enumerate() {
        let since = s.now - days * 86_400;
        for c in s.checks.iter().filter(|c| c.at.is_some_and(|a| a >= since)) {
            let Some(input) = c.input.as_deref() else {
                continue;
            };
            match input_parts(input) {
                Some(parts) => {
                    for (k, (word, _)) in INPUTS.iter().enumerate() {
                        n[k][span] += u32::from(parts.contains(word));
                    }
                }
                None => n[3][span] += 1,
            }
        }
    }
    let mut out: Vec<String> = INPUTS
        .iter()
        .zip(&n)
        .map(|((_, said), [week, month])| {
            let said = said.split(' ').next().filter(|_| short).unwrap_or(said);
            format!("{said} {week}/{month}")
        })
        .collect();
    if n[3][1] > 0 {
        out.push(format!("other {}/{}", n[3][0], n[3][1]));
    }
    match short {
        true => out.join(" · "),
        false => format!("{} (7/30 days)", out.join(" · ")),
    }
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
    // (The side panel is narrow: shorter words there, under its own 7 / 30 days header.)
    let label = if brief { "made from  " } else { "from: " };
    let sent = Line::from(vec![
        Span::styled(label, t.dim()),
        Span::styled(
            trunc(
                &made_from(s, !brief),
                (r.width as usize).saturating_sub(label.len()),
            ),
            t.fg(),
        ),
    ]);
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
        if month.unconfirmed > 0 {
            lines.push(Line::styled(
                format!(
                    "         of the be careful, only unconfirmed: {}/{} (7/30 days)",
                    week.unconfirmed, month.unconfirmed
                ),
                t.dim(),
            ));
        }
        if month.trusted > 0 {
            lines.push(Line::styled(
                format!(
                    "         from a trusted sender: {}/{} (7/30 days)",
                    week.trusted, month.trusted
                ),
                t.dim(),
            ));
        }
        lines.push(sent);
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
            if verdict == Verdict::Safe && month.trusted > 0 {
                lines.push(Line::from(vec![
                    Span::styled(format!("{:<26}", "  from a trusted sender"), t.dim()),
                    Span::styled(num(week.trusted), t.dim()),
                    Span::styled(num(month.trusted), t.dim()),
                ]));
            }
            // (Where the index says so: older lines don't.)
            if verdict == Verdict::Suspicious && month.unconfirmed > 0 {
                lines.push(Line::from(vec![
                    Span::styled(format!("{:<26}", "  of them only unconfirmed"), t.dim()),
                    Span::styled(num(week.unconfirmed), t.dim()),
                    Span::styled(num(month.unconfirmed), t.dim()),
                ]));
            }
        }
        if week.other + month.other > 0 {
            lines.push(line(" another verdict", week.other, month.other, t.fg));
        }
        lines.push(line(" failed", week.errors, month.errors, t.mag));
        lines.push(sent);
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
    lines.extend(extension_lines(t, s, r.width as usize));
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
    // What an entry reports as its version, when it is one (it starts with a digit): a
    // `web` entry says `web` or nothing until a check has come through the browser
    // extension in that profile, then the extension's version. Versions are compared
    // among entries of the same client only: the app's and the extension's are not one
    // series.
    let ver = |d: &Device| {
        d.app_version
            .as_deref()
            .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
            .map(version)
    };
    let newest = |client: Option<&str>| {
        paired
            .iter()
            .filter(|d| d.client.as_deref() == client)
            .filter_map(ver)
            .max()
    };
    let mut out: Vec<DeviceRow> = paired
        .iter()
        .map(|d| {
            let checks = count(&d.name);
            let idle = d.last_seen_at.map(|t| (s.now - t) / 86_400);
            let web = d.client.as_deref() == Some("web");
            let older = ver(d).is_some_and(|v| newest(d.client.as_deref()).is_some_and(|n| v < n));
            let (note, odd) = match idle {
                None if checks == 0 => ("never used".to_string(), true),
                Some(days) if days >= 14 => (format!("not seen for {days} days"), true),
                _ if older && web => ("older extension than the others".into(), true),
                _ if older => ("older app than the others".into(), true),
                _ if checks == 0 && !s.cut() => ("never used".into(), true),
                // (Not old: no check has come through the extension in that profile.)
                _ if web && ver(d).is_none() => {
                    ("a browser profile: no extension seen yet".into(), false)
                }
                _ => (String::new(), false),
            };
            // An owner computer may change the trusted senders: said beside whatever
            // else stands out about it.
            let note = match (d.owner, note.is_empty()) {
                (true, true) => "owner: may change the trusted senders".to_string(),
                (true, false) => format!("owner; {note}"),
                (false, _) => note,
            };
            DeviceRow {
                name: d.name.clone(),
                client: match (d.client.as_deref(), ver(d).is_some()) {
                    // (`web web` says nothing: the word stands alone until there is a
                    // version, which is the extension's.)
                    (Some("web"), true) => {
                        format!("ext {}", d.app_version.as_deref().unwrap_or(""))
                    }
                    (Some("web"), false) => "web".into(),
                    (client, _) => [client, d.app_version.as_deref()]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join(" "),
                },
                checks,
                seen: match d.last_seen_at {
                    Some(at) => fmt::ago(s.now - at),
                    None => "never".into(),
                },
                odd,
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

/// The senders the owner trusts now: what, its label, when it was added and by which
/// computer (or the command line). The list as it is, never a history; text and nothing
/// else (a domain or an address here is never resolved, opened or copied).
fn trusted(f: &mut Frame, area: Rect, v: &View, s: &Suscheck) {
    let t = v.t;
    let list: Option<&TrustedList> = s.trusted.ok();
    let b = panel(
        t,
        "Trusted senders",
        match list {
            Some(l) => format!("{} now", l.total()),
            None => "not shown".into(),
        },
    );
    let r = inner(&b, area);
    f.render_widget(b, area);
    let Some(list) = list else {
        let why = match &s.trusted {
            Part::Newer(n) => {
                format!("trusted.json is in schema {n}, which this sentry doesn't know.")
            }
            _ => "trusted.json isn't what the format says.".into(),
        };
        return f.render_widget(
            Paragraph::new(Line::styled(why, t.s(t.yellow))).wrap(Wrap { trim: false }),
            r,
        );
    };
    if list.senders.is_empty() {
        return f.render_widget(
            Paragraph::new(Line::styled("No sender is trusted now.", t.dim())),
            r,
        );
    }
    let width = r.width as usize;
    // An entry is what it is, its label where it has one, and when and by whom it was
    // added. Where they don't all fit, the last row says how many more there are.
    let entries: Vec<Vec<Line>> = list
        .senders
        .iter()
        .map(|x| {
            let what = match x.kind.as_deref() {
                Some(other) => other.replace('_', " "),
                None => "?".into(),
            };
            let mut rows = vec![Line::from(vec![
                Span::styled(
                    trunc(&x.value, width.saturating_sub(what.chars().count() + 3)),
                    t.fg(),
                ),
                Span::styled(format!(" ({what})"), t.dim()),
            ])];
            if let Some(label) = &x.label {
                rows.push(Line::styled(trunc(&format!("  ↳ {label}"), width), t.dim()));
            }
            rows.push(Line::styled(
                trunc(
                    &format!(
                        "    added {} by {}",
                        when(x.added_at),
                        match x.added_by.as_deref() {
                            Some("command line") => "the command line",
                            Some(who) => who,
                            None => "?",
                        }
                    ),
                    width,
                ),
                t.dim(),
            ));
            rows
        })
        .collect();
    let room = (r.height as usize).max(1);
    let all: usize = entries.iter().map(Vec::len).sum();
    let whole = all <= room && list.more == 0;
    let mut lines: Vec<Line> = Vec::new();
    let mut shown = 0;
    for rows in entries {
        // (One row is kept for "and N more" when not everything fits.)
        if !whole && lines.len() + rows.len() + 1 > room {
            break;
        }
        lines.extend(rows);
        shown += 1;
    }
    let rest = (list.total() as usize).saturating_sub(shown);
    if rest > 0 {
        lines.push(Line::styled(format!("and {rest} more"), t.dim()));
    }
    f.render_widget(Paragraph::new(lines), r);
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
