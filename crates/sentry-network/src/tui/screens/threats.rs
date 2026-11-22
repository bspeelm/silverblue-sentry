//! Security as a list you act on (the screen's first view; `d` shows the numbers, which is
//! `super::security`): "Needs attention" in plain sentences with the cursor, "How you're
//! covered" under it, "Blocked by you" when something is, and beside them the selected
//! row's detail with the panel that holds its evidence.
//!
//! The rows and the posture are `crate::security::{attention, posture}` over what the
//! store holds. The keys are Maintenance's (`maintlist::Verbs`): Enter does what the row
//! names, `x`/`b` expected, `z` later, `o` everything, `A` Claude. A row that is an audit
//! finding is dismissed through the same baseline and later list as on Maintenance.
//!
//! Enter never toggles anything: it starts the `security-action` workflow (its first step
//! shows the plan and only reads; its second, the one Enter there, makes the change
//! through the guard), asks one question first where there is a real choice, or opens a
//! session with Claude for what has no fixed remedy.

use std::collections::BTreeMap;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row as TRow};

use super::filter::{self, Filtered};
use super::security::{self as panels, Security};
use super::{Hints, View};
use crate::security::actions::Do;
use crate::security::attention::{self, DevRef, Kind, lasting};
use crate::security::blocks::{self, Dev, Door, Note, Reach, Shut};
use crate::security::gather::{self, More};
use crate::security::{Act, Cover, Picture, Rank, Row, State, Subject, posture};
use crate::tui::target::{Effect, Modal, NetworkTarget, Own};
use sentry_app::effect::{self, OwnPrompt, Prompt, WfCmd};
use sentry_app::shared::Shared;
use sentry_app::target::Cx;
use sentry_core::tui::keys::Action as Key;
use sentry_core::tui::maintlist::{self, Dismiss, Verbs};
use sentry_core::tui::modal::Choice;
use sentry_core::tui::widgets::{self, TableSpec, inner, panel, trunc, wrap};

/// The workflow every action runs as.
pub const WORKFLOW: &str = "security-action";
/// The one a new Wi-Fi password runs as (it asks before it is kept).
pub const GUARDED: &str = "guarded-change";

/// What the list asks the target for.
#[derive(Clone, Debug)]
pub enum Want {
    /// Start the action's workflow, first noting on this machine who or what it is about.
    Start {
        act: Do,
        dev: Option<DevRef>,
        /// A pause: when it ends (epoch seconds).
        until: Option<i64>,
        why: String,
        /// A forward being switched off: its name.
        door: Option<String>,
    },
    /// The answer to "a name for …".
    Name { mac: String, label: String },
    /// The answer to "the new Wi-Fi password".
    WifiKey { sections: Vec<String> },
    /// The family filter on exactly the action's devices: first noting who the ticked ones
    /// are, then the workflow.
    Filter { act: Do, devs: Vec<DevRef> },
    /// A filter this machine and the router disagree about: noted here (`keep`) or
    /// forgotten here. Nothing on the router changes.
    FilterNote { tag: String, keep: bool },
}

impl Want {
    /// What is typed for it is a secret: shown as dots.
    pub fn secret(&self) -> bool {
        matches!(self, Want::WifiKey { .. })
    }

    fn fx(self) -> Effect {
        Effect::own(Own::Security(self))
    }
}

/// Everything the view is made of, from what was read so far.
pub struct Built {
    pub picture: Picture,
    /// Every row not marked expected and not put off, in the list's order, several of
    /// one kind as one (`attention::arrange`).
    pub rows: Vec<Row>,
    pub posture: Vec<crate::security::Line>,
    pub shut: Vec<Shut>,
    /// "Filtered by you": the entry that chooses, then each device filtered.
    pub filtered: Vec<Filtered>,
}

fn today(v: &View) -> jiff::civil::Date {
    v.now.to_zoned(jiff::tz::TimeZone::UTC).date()
}

/// Whether enough was read to say anything.
fn read_any(v: &View) -> bool {
    v.s.uci.value.is_some() || v.s.clients.is_some() || v.s.flows.value.is_some()
}

pub fn built(v: &View) -> Built {
    let s = v.s;
    let read = panels::read(v);
    let picture = Picture::of(&read);
    let found = gather::findings(
        v.name,
        v.cfg,
        &v.sh.baseline,
        &read,
        More {
            services: s.services.value.as_ref(),
            crowdsec: s.crowdsec.value.as_ref().and_then(|c| c.as_ref()),
            listeners: s.listeners.value.as_deref(),
        },
        v.now,
    );
    let guard = server_guard(v);
    let state = State {
        network: v.name,
        read,
        picture: &picture,
        findings: &found,
        expected: &v.sh.baseline.findings,
        blocks: &s.blocks,
        bouncer: s.crowdsec.value.as_ref().and_then(|c| c.as_ref()),
        server_guard: guard.as_ref(),
        now: v.now.as_second(),
    };
    let day = today(v);
    let later = |r: &Row| v.sh.later.get(&r.key).is_none_or(|d| *d <= day);
    let mut rows = attention::raw(&state);
    attention::audit_rows(&v.sh.sec, &crate::tui::id_of(v.name), &state, &mut rows);
    // Put off one by one, then as the one row several of a kind make.
    rows.retain(later);
    let mut rows = attention::arrange(rows, v.group.as_deref());
    rows.retain(later);
    let mut posture = posture(&state);
    // The audit of the whole system: when it last ran, and the key that shows it.
    posture.push(crate::security::Line {
        what: "audit",
        state: match v.sh.sec_last {
            Some(at) if v.secs_since(at) <= 45 * 86_400 => Cover::Ok,
            Some(_) => Cover::Weak,
            None => Cover::Unknown,
        },
        text: match v.sh.sec_last {
            Some(at) => format!(
                "The security audit of every target: {} · S shows it",
                sentry_app::secaudit::audited(v.now, at)
            ),
            None => "The security audit of every target has never run · S runs it".into(),
        },
    });
    let shut = s
        .uci
        .value
        .as_ref()
        .map(|u| blocks::shut(u, &s.blocks))
        .unwrap_or_default();
    Built {
        picture,
        rows,
        posture,
        shut,
        filtered: filter::filtered(v),
    }
}

/// What a server's own guard says, when the window has a server that has one: read by
/// name from what that target says of itself (the app carries it; this crate knows no
/// server). Whether the router enforces its bans is the router's own bouncer.
pub fn server_guard(v: &View) -> Option<crate::security::attention::ServerGuard> {
    let sys = v
        .system
        .iter()
        .find(|s| s.line.fact("guard.running") == Some("true"))?;
    Some(crate::security::attention::ServerGuard {
        server: sys.peer.title.clone(),
        banned_today: sys.line.fact("guard.blocked").and_then(|n| n.parse().ok()),
        scenarios: sys
            .line
            .fact("guard.scenarios")
            .unwrap_or("")
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
        enforced_here: match v.s.crowdsec.value.as_ref() {
            None => None,
            Some(None) => Some(false),
            Some(Some(b)) => Some(b.on() && b.age_s.is_some()),
        },
    })
}

fn listed_of<'a>(rows: &'a [Row], v: &View) -> Vec<&'a Row> {
    rows.iter()
        .filter(|r| v.everything || !r.can_wait)
        .filter(|r| {
            // (Several as one: found by what any of them says.)
            let among = r
                .members()
                .iter()
                .map(|m| m.title.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            v.matches(&[&r.title, &r.why, r.rank.word(), &among])
        })
        .collect()
}

impl Built {
    /// The list being gone through (`View::group`): the one row several of a kind make.
    pub fn open(&self, v: &View) -> Option<&Row> {
        let key = v.group.as_deref()?;
        self.rows
            .iter()
            .find(|r| r.key == key && !r.members().is_empty())
    }

    /// The page's own list, whatever is open over it: what its numbers count.
    pub fn main(&self, v: &View) -> Vec<&Row> {
        listed_of(&self.rows, v)
    }

    /// The rows listed: what needs you (everything with `o`), filtered; of a list being
    /// gone through, its rows. With it, how many wait unseen.
    pub fn listed(&self, v: &View) -> (Vec<&Row>, usize) {
        if let Some(g) = self.open(v) {
            // (A filter that found the row and fits none of its rows hides none.)
            let rows = match listed_of(g.members(), v) {
                none if none.is_empty() => g.members().iter().collect(),
                some => some,
            };
            return (rows, 0);
        }
        let waiting = self.rows.iter().filter(|r| r.can_wait).count();
        (self.main(v), if v.everything { 0 } else { waiting })
    }

    /// The rows that ask something of you now (the strip's count, the Dashboard's row).
    pub fn asking(&self) -> (usize, usize) {
        let n = |rank| {
            self.rows
                .iter()
                .filter(|r| r.rank == rank && !r.can_wait)
                .count()
        };
        (n(Rank::Now), n(Rank::Look))
    }
}

/// The row at the cursor: one that needs attention (they come first), or something shut.
pub enum Sel<'a> {
    Row(&'a Row),
    Shut(&'a Shut),
    Filter(&'a Filtered),
}

pub fn sel<'a>(v: &View, b: &'a Built) -> Option<Sel<'a>> {
    let (rows, _) = b.listed(v);
    if let Some(r) = rows.get(v.cur) {
        return Some(Sel::Row(r));
    }
    let at = v.cur - rows.len();
    if let Some(s) = b.shut.get(at) {
        return Some(Sel::Shut(s));
    }
    b.filtered.get(at - b.shut.len()).map(Sel::Filter)
}

pub fn count(v: &View) -> usize {
    let b = built(v);
    b.listed(v).0.len() + b.shut.len() + b.filtered.len()
}

/// What the row at the cursor is, to find it again when the list changes.
pub fn row_key(v: &View) -> Option<String> {
    let b = built(v);
    Some(match sel(v, &b)? {
        Sel::Row(r) => r.key.clone(),
        Sel::Shut(s) => s.key(),
        Sel::Filter(f) => f.key(),
    })
}

/// Where a row is now (None: gone).
pub fn position(v: &View, key: &str) -> Option<usize> {
    let b = built(v);
    let (rows, _) = b.listed(v);
    rows.iter()
        .position(|r| r.key == key)
        .or_else(|| {
            b.shut
                .iter()
                .position(|s| s.key() == key)
                .map(|i| rows.len() + i)
        })
        .or_else(|| {
            b.filtered
                .iter()
                .position(|s| s.key() == key)
                .map(|i| rows.len() + b.shut.len() + i)
        })
}

fn claude() -> bool {
    sentry_core::claude::available()
}

/// What Enter is called on a row.
fn enter_word(a: &Act) -> &'static str {
    match a {
        // A session is Claude's: without Claude Code, Enter shows the evidence.
        Act::Finding(_) | Act::Server { .. } if !claude() => "the numbers",
        Act::Audit { asks: false, .. } if !claude() => "the report",
        a => a.enter(),
    }
}

/// The keys the selected row takes.
pub fn verbs(v: &View, b: &Built) -> Option<Verbs> {
    Some(match sel(v, b)? {
        Sel::Row(r) => Verbs {
            enter: enter_word(&r.act),
            // A pause that ended isn't something to expect: it is lifted or put off. Nor
            // are several rows as one: each of them is.
            dismiss: expectable(&r.act).then_some(Dismiss::Expected),
            ..Default::default()
        },
        Sel::Shut(Shut::Device { .. }) => Verbs {
            enter: "unblock",
            ..Default::default()
        },
        Sel::Shut(Shut::Door { .. }) => Verbs {
            enter: "open again",
            ..Default::default()
        },
        Sel::Filter(Filtered::Choose { .. }) => Verbs {
            enter: "choose devices",
            ..Default::default()
        },
        Sel::Filter(Filtered::Device { .. }) => Verbs {
            enter: "take it off",
            ..Default::default()
        },
    })
}

/// Whether a row can be marked expected.
fn expectable(a: &Act) -> bool {
    !matches!(
        a,
        Act::Unblock { .. } | Act::Group { .. } | Act::FilterDrift { .. } | Act::FilterRepair
    )
}

/// The key bar: the row's keys (`A` is named by the frame), then the screen's.
pub fn hints(v: &View) -> Hints {
    let b = built(v);
    let mut h: Hints = match (verbs(v, &b), sel(v, &b)) {
        (Some(vb), Some(Sel::Row(_))) => maintlist::hints(&vb, 0)
            .into_iter()
            .filter(|(k, _)| *k != "A")
            .collect(),
        // Something shut is lifted; it isn't put off.
        (Some(vb), Some(Sel::Shut(_) | Sel::Filter(_))) => vec![("Enter", vb.enter)],
        _ => Vec::new(),
    };
    if b.open(v).is_some() {
        h.push(("Esc", "back"));
    }
    if v.everything || b.listed(v).1 > 0 {
        h.push(("o", maintlist::everything_word(v.everything)));
    }
    h.extend([
        ("S", "audit"),
        ("d", "numbers"),
        ("r", "read again"),
        ("v", "records"),
    ]);
    h
}

/// `?` on the list.
pub fn help() -> Hints {
    vec![
        (
            "Enter",
            "what the row's second line says: shown first, never a bare switch",
        ),
        (
            "order",
            "happening now, known holes, weak logins, protection off, layout, recovery, housekeeping",
        ),
        (
            "N devices",
            "several of one kind are one row: Enter lists them, Esc comes back",
        ),
        (
            "x / b",
            "expected: off this list and Maintenance's (b: no box)",
        ),
        ("z", "look again later: 7, 30 or 90 days"),
        ("o", "everything: what is only good to know too"),
        ("A", "ask Claude about what the screen shows"),
        (
            "S",
            "the security audit of every target: its report, S there runs it",
        ),
        ("d", "the numbers behind it (? there: what each is not)"),
        ("r / v", "read everything again / records and the log"),
        (
            "changes",
            "through the guard: undone by the router if it goes quiet",
        ),
        (
            "pauses",
            "no timer on the router: a row here offers to lift one",
        ),
        (
            "filter",
            "Filtered by you › Choose devices: tick them, Enter applies all as one change",
        ),
        (
            "not seen",
            "what is inside the traffic; devices on one switch",
        ),
    ]
}

/// The count beside the screen's name: what asks something of you.
pub fn badge(v: &View) -> Option<(String, Color)> {
    if !read_any(v) {
        return None;
    }
    match built(v).asking() {
        (0, 0) => None,
        (0, n) => Some((format!(" {n}"), v.t.yellow)),
        (n, m) => Some((format!(" {}", n + m), v.t.red)),
    }
}

/// The Dashboard's Status row: how many rows need attention, from what Security last read
/// (nothing is read for this). None until it has read something.
pub fn status(v: &View) -> Option<(String, bool)> {
    if v.s.counters.value.is_none() && v.s.flows.value.is_none() {
        return None;
    }
    Some(match built(v).asking() {
        (0, 0) => ("all quiet".to_string(), false),
        (now, look) => (
            match now + look {
                1 => "1 needs attention".to_string(),
                n => format!("{n} need attention"),
            },
            now > 0,
        ),
    })
}

fn start(act: Do) -> Vec<Effect> {
    vec![
        Want::Start {
            act,
            dev: None,
            until: None,
            why: String::new(),
            door: None,
        }
        .fx(),
    ]
}

/// Tomorrow morning at seven, by this machine's clock.
fn tomorrow_morning(now: jiff::Timestamp) -> i64 {
    let z = now.to_zoned(jiff::tz::TimeZone::system());
    z.date()
        .tomorrow()
        .ok()
        .and_then(|d| d.at(7, 0, 0, 0).to_zoned(z.time_zone().clone()).ok())
        .map_or(now.as_second() + 86_400, |t| t.timestamp().as_second())
}

/// Enter on a device: what to do about it, as one question.
fn device_choice(v: &View, row: &Row, dev: &DevRef) -> Vec<Effect> {
    let t = v.t;
    let client =
        v.s.clients
            .iter()
            .flatten()
            .find(|c| c.mac.as_deref() == Some(dev.mac.as_str()));
    let leave = client.is_some_and(|c| c.leave_alone);
    let block = |reach: Reach, until: Option<i64>, why: &str| {
        vec![
            Want::Start {
                act: Do::Block {
                    tag: dev.tag.clone(),
                    reach,
                },
                dev: Some(dev.clone()),
                until,
                why: why.to_string(),
                door: None,
            }
            .fx(),
        ]
    };
    let now = v.now.as_second();
    let mut options: Vec<(String, Vec<Effect>)> = Vec::new();
    if !dev.named {
        options.push((
            "It's mine: give it a name".into(),
            vec![Effect::Prompt(
                Prompt::Own(OwnPrompt {
                    label: format!("A name for {}: ", dev.label),
                    enter: "name it",
                    workflow: None,
                    defaults: false,
                    own: effect::Own(std::rc::Rc::new(Own::Security(Want::Name {
                        mac: dev.mac.clone(),
                        label: dev.label.clone(),
                    }))),
                }),
                String::new(),
            )],
        ));
    }
    if !leave {
        options.push((
            "Block it from the internet (it stays on your network)".into(),
            block(Reach::Internet, None, "blocked from Security"),
        ));
        options.push((
            "Block it from everything, the router included".into(),
            block(Reach::Everything, None, "blocked from Security"),
        ));
        options.push((
            "Pause its internet for an hour".into(),
            block(Reach::Internet, Some(now + 3600), "paused for an hour"),
        ));
        options.push((
            "Pause its internet until tomorrow morning".into(),
            block(
                Reach::Internet,
                Some(tomorrow_morning(v.now)),
                "paused until the morning",
            ),
        ));
        if dev.wifi.is_some() {
            options.push((
                "Send it off the Wi-Fi for ten minutes".into(),
                vec![
                    Want::Start {
                        act: Do::Kick {
                            tag: dev.tag.clone(),
                            secs: 600,
                        },
                        dev: Some(dev.clone()),
                        until: None,
                        why: String::new(),
                        door: None,
                    }
                    .fx(),
                ],
            ));
        }
    }
    let week = today(v)
        .checked_add(jiff::Span::new().days(7))
        .unwrap_or(today(v));
    options.push((
        "Look again in a week".into(),
        vec![Effect::Snooze(row.key.clone(), week)],
    ));
    let mut c = Choice::numbered(
        t,
        &format!("What to do about {}", trunc(&dev.label, 30)),
        options,
    );
    let mut lines: Vec<Line<'static>> = row
        .seen
        .iter()
        .map(|s| Line::styled(s.clone(), t.dim()))
        .collect();
    lines.push(Line::raw(""));
    lines.append(&mut c.lines);
    lines.push(Line::raw(""));
    if leave {
        lines.push(Line::styled(
            "network_config.yaml says to leave this device alone: sentry blocks nothing of it.",
            t.s(t.yellow),
        ));
    } else {
        for l in [
            "Blocking and pausing are firewall rules by MAC, made through the guard:",
            "you see the plan first, and the router undoes the change by itself if",
            "it stops answering. A pause has no timer on the router: when it ends,",
            "a row here offers to lift it.",
        ] {
            lines.push(Line::styled(l, t.dim()));
        }
    }
    c.lines = lines;
    vec![Effect::Choose(c)]
}

/// Which Wi-Fi a new password is for: every access point of one name is changed together.
fn wifi_choice(v: &View, row: &Row) -> Vec<Effect> {
    let t = v.t;
    let mut by_ssid: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for w in v.s.uci.value.iter().flat_map(|u| u.wifi()) {
        if !w.disabled && w.key {
            by_ssid.entry(w.ssid).or_default().push(w.section);
        }
    }
    if by_ssid.is_empty() {
        return vec![Effect::Toast(
            "no Wi-Fi with a password is switched on: nothing to change".into(),
        )];
    }
    let ask = |ssid: &str, sections: &[String]| {
        Effect::Prompt(
            Prompt::Own(OwnPrompt {
                label: format!("The new password for {ssid} (8–63 characters): "),
                enter: "set it",
                workflow: None,
                defaults: false,
                own: effect::Own(std::rc::Rc::new(Own::Security(Want::WifiKey {
                    sections: sections.to_vec(),
                }))),
            }),
            String::new(),
        )
    };
    let week = today(v)
        .checked_add(jiff::Span::new().days(7))
        .unwrap_or(today(v));
    let mut options: Vec<(String, Vec<Effect>)> = by_ssid
        .iter()
        .map(|(ssid, sections)| {
            (
                format!("Change the password of {ssid}"),
                vec![ask(ssid, sections)],
            )
        })
        .collect();
    options.push((
        "Look again in a week".into(),
        vec![Effect::Snooze(row.key.clone(), week)],
    ));
    let mut c = Choice::numbered(t, "The Wi-Fi password", options);
    for l in [
        "",
        "A new password is the real fix when the old one may be out: every",
        "device then needs it typed in again. It is typed here as dots and never",
        "written down. The change goes through the guard and waits for your",
        "\"keep\": check that a device can join with the new password first; with",
        "no answer the router takes it back by itself.",
    ] {
        c.lines.push(Line::styled(l, t.dim()));
    }
    vec![Effect::Choose(c)]
}

/// Enter on a row.
fn enter(v: &View, row: &Row, sec: &mut Security) -> Vec<Effect> {
    let t = v.t;
    match &row.act {
        Act::Group { .. } => {
            sec.group = Some(row.key.clone());
            sec.cur.sel = 0;
            sec.sel = None;
            Vec::new()
        }
        Act::Device(dev) => device_choice(v, row, dev),
        Act::Unblock { tag } => start(Do::Unblock { tag: tag.clone() }),
        Act::Forward { section, name } => {
            let off = Want::Start {
                act: Do::ForwardOff {
                    section: section.clone(),
                },
                dev: None,
                until: None,
                why: String::new(),
                door: Some(name.clone()),
            };
            let mut c = Choice::numbered(
                t,
                &format!("The door {name}"),
                vec![
                    (
                        "Close it for now (it can be opened again from here)".into(),
                        vec![off.fx()],
                    ),
                    (
                        "Remove it from the router".into(),
                        start(Do::ForwardRemove {
                            section: section.clone(),
                        }),
                    ),
                    (
                        "It is meant to be open: expected".into(),
                        vec![Effect::own(Own::Expected(row.id.clone(), true))],
                    ),
                ],
            );
            c.lines.push(Line::raw(""));
            c.lines.push(Line::styled(
                "Closing and removing go through the guard: you see the plan first.",
                t.dim(),
            ));
            vec![Effect::Choose(c)]
        }
        Act::SshKeys => start(Do::SshKeys),
        Act::AdminHttps => start(Do::AdminHttps),
        Act::Blocklist {
            stale: true,
            scheduled: Some(false),
        } => vec![Effect::Choose(Choice::numbered(
            t,
            "The list of bad sites",
            vec![
                ("Fetch it again now".into(), start(Do::ListRefresh)),
                (
                    "Turn on its own scheduled update".into(),
                    start(Do::ListSchedule),
                ),
            ],
        ))],
        Act::Blocklist { stale: true, .. } => start(Do::ListRefresh),
        Act::Blocklist { .. } => start(Do::ListSchedule),
        Act::WifiKey => wifi_choice(v, row),
        Act::FilterDrift { tag, on_router } => drift_choice(v, row, tag, *on_router),
        Act::FilterRepair => filter::start(
            filter::on_router(v).into_iter().map(|f| f.tag).collect(),
            Vec::new(),
        ),
        // The audit's own: a session across whatever targets it names, or your answer.
        Act::Audit { id, asks } if *asks || claude() => vec![Effect::SecItem(id.clone())],
        Act::Audit { .. } => vec![Effect::SecShow],
        // Where the item's row on Maintenance goes: the backup, the packages' workflow,
        // the firmware's (its draft box first, or why it isn't offered yet).
        Act::Maint(kind) => super::maint::item_enter(v, *kind),
        // What has no fixed remedy: a session with Claude plans it, you approve.
        Act::Finding(_) | Act::Server { .. } if claude() => match crate::tui::ask::scrub(v) {
            Ok(_) => vec![Effect::ApplyAsk],
            Err(why) => vec![Effect::Toast(why)],
        },
        Act::Finding(_) | Act::Server { .. } | Act::Evidence => {
            sec.panels = true;
            vec![Effect::Toast(
                "the numbers behind it · d brings the list back".into(),
            )]
        }
    }
}

/// What a session for the selected row is asked (`Asks::apply_ask` on this screen).
pub fn apply_ask(v: &View) -> Option<sentry_core::claude::Ask> {
    let b = built(v);
    let Sel::Row(row) = sel(v, &b)? else {
        return None;
    };
    let brief = format!(
        "Why it matters: {}\nWhat was seen:\n{}",
        row.why,
        row.seen.join("\n")
    );
    match &row.act {
        Act::Finding(id) => {
            let read = panels::read(v);
            let found = gather::findings(
                v.name,
                v.cfg,
                &v.sh.baseline,
                &read,
                More {
                    services: v.s.services.value.as_ref(),
                    crowdsec: v.s.crowdsec.value.as_ref().and_then(|c| c.as_ref()),
                    listeners: v.s.listeners.value.as_deref(),
                },
                v.now,
            );
            match found.iter().find(|f| &f.id == id) {
                Some(f) => crate::tui::ask::apply_finding(v, f),
                None => crate::tui::ask::apply_brief(v, &row.key, &row.title, &brief),
            }
        }
        // The seam: its plan spans the server and the router, which the cross-target
        // session carries out.
        Act::Server { brief: said } => {
            crate::tui::ask::apply_brief(v, &row.key, &row.title, &format!("{brief}\n{said}"))
        }
        Act::Audit { id, asks: false } => {
            v.sh.sec
                .iter()
                .find(|i| &i.id == id)
                .map(|i| crate::tui::ask::apply_audit(v, i))
        }
        _ => None,
    }
}

/// Enter on a filter the router and this machine disagree about.
fn drift_choice(v: &View, row: &Row, tag: &str, on_router: bool) -> Vec<Effect> {
    let note = |keep: bool| {
        vec![Effect::own(Own::Security(Want::FilterNote {
            tag: tag.to_string(),
            keep,
        }))]
    };
    let options: Vec<(String, Vec<Effect>)> = if on_router {
        vec![
            ("Keep it: note it here as filtered".into(), note(true)),
            (
                "Take it off the router (its plan first)".into(),
                filter::lift(v, tag),
            ),
        ]
    } else {
        vec![
            (
                "Put it back on the router (its plan first)".into(),
                filter::put_back(v, tag),
            ),
            ("Forget it here: it isn't filtered".into(), note(false)),
        ]
    };
    let mut c = Choice::numbered(v.t, &trunc(&row.title, 60), options);
    c.lines.push(Line::raw(""));
    c.lines.push(Line::styled(
        "Noting or forgetting changes nothing on the router.",
        v.t.dim(),
    ));
    vec![Effect::Choose(c)]
}

/// A key on the list (moving is the cursor's).
pub fn handle(sec: &mut Security, a: Key, v: &View) -> Vec<Effect> {
    let t = v.t;
    // The family filter's list, open in the list's place.
    if let Some(m) = sec.filter.as_mut() {
        let (close, fx) = filter::handle(m, a, v);
        if close {
            sec.filter = None;
        }
        return fx;
    }
    let b = built(v);
    let picked = sel(v, &b);
    match a {
        // A list being gone through: back to the page, on the row that opened it.
        Key::Esc if v.group.is_some() => {
            let key = sec.group.take();
            if let Some(i) = b.main(v).iter().position(|r| Some(&r.key) == key.as_ref()) {
                sec.cur.sel = i;
            }
            sec.sel = key;
            Vec::new()
        }
        Key::Refresh | Key::Check => panels::read_again(),
        Key::Char('o') => vec![Effect::Everything],
        Key::Char('v') => vec![Effect::LogOpen(None)],
        Key::Enter => match picked {
            Some(Sel::Row(r)) => enter(v, r, sec),
            Some(Sel::Shut(Shut::Device { tag, .. })) => start(Do::Unblock { tag: tag.clone() }),
            Some(Sel::Shut(Shut::Door { section, .. })) => start(Do::ForwardOn {
                section: section.clone(),
            }),
            Some(Sel::Filter(Filtered::Choose { .. })) => {
                sec.filter = Some(filter::open(v));
                Vec::new()
            }
            Some(Sel::Filter(Filtered::Device { tag, .. })) => filter::lift(v, tag),
            None => Vec::new(),
        },
        Key::Char(c @ ('x' | 'b' | 'z')) => {
            let Some(Sel::Row(r)) = picked else {
                return match picked {
                    Some(_) => vec![Effect::Toast(
                        "Enter lifts it: there is nothing to put off or expect".into(),
                    )],
                    None => Vec::new(),
                };
            };
            let can = expectable(&r.act);
            match c {
                'x' | 'b' if !can => vec![Effect::Toast(maintlist::NOTHING_TO_DISMISS.into())],
                'x' => vec![Effect::Confirm(Modal {
                    title: "Mark it expected".into(),
                    color: t.yellow,
                    lines: vec![
                        Line::styled(r.title.clone(), t.fg()),
                        Line::styled(
                            "It stops being listed here and on Maintenance (the network's baseline.toml). Records › Later takes it back.",
                            t.dim(),
                        ),
                    ],
                    yes: Some((
                        "yes".into(),
                        vec![Effect::own(Own::Expected(r.id.clone(), true))],
                    )),
                })],
                'b' => vec![Effect::own(Own::Expected(r.id.clone(), true))],
                _ => vec![Effect::Choose(maintlist::later_choice(
                    t,
                    &r.title,
                    today(v),
                    |_, until| vec![Effect::Snooze(r.key.clone(), until)],
                ))],
            }
        }
        _ => Vec::new(),
    }
}

/// What the target does for the list: note who an action is about, then start it.
pub fn on_own(tg: &mut NetworkTarget, w: &Want, sh: &Shared, cx: &Cx) -> Vec<Effect> {
    let toast = |s: String| vec![Effect::Toast(s)];
    let (act, dev, until, why, door) = match w {
        Want::Start {
            act,
            dev,
            until,
            why,
            door,
        } => (act, dev.as_slice(), until, why.as_str(), door),
        Want::Filter { act, devs } => (act, devs.as_slice(), &None, "", &None),
        Want::FilterNote { tag, keep } => return filter_note(tg, tag, *keep, cx),
        _ => return Vec::new(),
    };
    if cx.run.is_some_and(|r| !r.done()) {
        return toast("a workflow is already in progress (0 shows it): one at a time".into());
    }
    if !sh.workflows.iter().any(|x| x == WORKFLOW) {
        return toast(format!(
            "this network has no workflow {WORKFLOW} (its own workflows replace the seeded ones: copy it there)"
        ));
    }
    let now = cx.now.as_second();
    let b = &mut tg.store.blocks;
    let before = b.clone();
    for d in dev {
        b.device.insert(
            d.tag.clone(),
            Dev {
                mac: d.mac.clone(),
                label: d.label.clone(),
                zone: d.zone.clone(),
                wifi: d.wifi.clone(),
            },
        );
    }
    match act {
        Do::Block { tag, reach } => {
            b.block.insert(
                tag.clone(),
                Note {
                    since: now,
                    until: *until,
                    reach: *reach,
                    why: why.to_string(),
                },
            );
        }
        Do::ForwardOff { section } => {
            b.door.insert(
                section.clone(),
                Door {
                    name: door.clone().unwrap_or_default(),
                    since: now,
                },
            );
        }
        _ => {}
    }
    if *b != before
        && !cx.offline
        && let Err(e) = b.save(&tg.router.scope)
    {
        return toast(format!("couldn't note it here (blocks.toml): {e}"));
    }
    vec![Effect::Wf(WfCmd::BeginWith(
        WORKFLOW.into(),
        BTreeMap::from([("action".to_string(), act.word())]),
    ))]
}

/// A prompt of the list's was answered: a device's name, a new Wi-Fi password.
pub fn on_prompt(tg: &mut NetworkTarget, w: &Want, answer: Option<&str>, cx: &Cx) -> Vec<Effect> {
    let toast = |s: String| vec![Effect::Toast(s)];
    let Some(answer) = answer else {
        return Vec::new();
    };
    match w {
        Want::Name { mac, label } => {
            let scope = tg.router.scope.clone();
            let mut names = if cx.offline {
                Default::default()
            } else {
                crate::security::names::Names::load(&scope)
            };
            let name = match names.set(mac, answer, cx.now.as_second()) {
                Ok(n) => n,
                Err(why) => return toast(format!("not named: {why}")),
            };
            if !cx.offline
                && let Err(e) = names.save(&scope)
            {
                return toast(format!("couldn't save the name (names.toml): {e}"));
            }
            // From now on it is a device the config knows, wherever clients are shown.
            let same = |m: Option<&str>| m.and_then(crate::config::mac).as_deref() == Some(mac);
            let devices = &mut std::sync::Arc::make_mut(&mut tg.router.cfg).devices;
            match devices.iter_mut().find(|d| same(d.mac.as_deref())) {
                Some(d) => d.name = Some(name.clone()),
                None => devices.push(crate::config::Device {
                    name: Some(name.clone()),
                    mac: Some(mac.clone()),
                    ..Default::default()
                }),
            }
            for c in tg.store.clients.iter_mut().flatten() {
                if same(c.mac.as_deref()) {
                    c.name = Some(name.clone());
                    c.known = true;
                    c.flagged = false;
                }
            }
            toast(format!(
                "{label} is now \"{name}\" on every screen, and no longer listed as unknown (names.toml; network_config.yaml is yours and untouched)"
            ))
        }
        Want::WifiKey { sections } => {
            let lines = match crate::security::actions::wifi_key_lines(sections, answer) {
                Ok(l) => l,
                Err(why) => return toast(format!("not changed: {why}")),
            };
            if cx.run.is_some_and(|r| !r.done()) {
                return toast(
                    "a workflow is already in progress (0 shows it): one at a time".into(),
                );
            }
            vec![Effect::Wf(WfCmd::BeginWith(
                GUARDED.into(),
                BTreeMap::from([
                    ("configs".to_string(), "wireless".to_string()),
                    ("lines".to_string(), lines),
                    ("services".to_string(), "wifi".to_string()),
                    ("alters_wan".to_string(), "no".to_string()),
                ]),
            ))]
        }
        Want::Start { .. } | Want::Filter { .. } | Want::FilterNote { .. } => Vec::new(),
    }
}

/// A filter noted here as the router has it, or forgotten here: nothing on the router.
fn filter_note(tg: &mut NetworkTarget, tag: &str, keep: bool, cx: &Cx) -> Vec<Effect> {
    let b = &mut tg.store.blocks;
    if keep {
        b.filter
            .entry(tag.to_string())
            .or_insert(crate::security::blocks::Filtered {
                since: cx.now.as_second(),
                service: crate::security::family::service().id.into(),
            });
    } else {
        b.filter.remove(tag);
    }
    if !cx.offline
        && let Err(e) = b.save(&tg.router.scope)
    {
        return vec![Effect::Toast(format!(
            "couldn't note it here (blocks.toml): {e}"
        ))];
    }
    vec![Effect::Toast(
        if keep {
            "noted here as filtered (the router is as it was)"
        } else {
            "forgotten here (the router is as it was)"
        }
        .into(),
    )]
}

/// How many selectable rows come before "Filtered by you".
fn rows_len_before(b: &Built, v: &View) -> usize {
    b.listed(v).0.len() + b.shut.len()
}

fn rank_color(t: &sentry_core::tui::theme::Theme, r: Rank) -> Color {
    match r {
        Rank::Now => t.red,
        Rank::Look => t.yellow,
        Rank::Note => t.dim,
    }
}

/// What Enter does on a row, as a sentence for the detail.
fn enter_says(a: &Act) -> &'static str {
    match a {
        Act::Device(_) => {
            "Enter: decide. Name it, block it, pause it, or put it off; blocking shows its plan first."
        }
        Act::Unblock { .. } => {
            "Enter: unblock it (removes exactly the rule sentry added, through the guard)."
        }
        Act::Forward { .. } => "Enter: close it, remove it, or say it is meant to be open.",
        Act::SshKeys => {
            "Enter: turn password logins off. sentry first proves its own key login on a new connection, and again before the change is kept."
        }
        Act::AdminHttps => {
            "Enter: send the admin page to HTTPS. Kept only if the page still answers on HTTPS from here."
        }
        Act::Blocklist { stale: true, .. } => {
            "Enter: fetch the list again (the package's own download; names don't resolve for a few seconds)."
        }
        Act::Blocklist { .. } => "Enter: turn on the package's own scheduled update.",
        Act::WifiKey => {
            "Enter: change the Wi-Fi password (typed as dots, through the guard, kept only when you say so)."
        }
        Act::Finding(_) if claude() => {
            "Enter: a session with Claude. It reads the router, plans the fix, you approve; a config change goes through the guard."
        }
        Act::Server { .. } if claude() => {
            "Enter: one session with Claude across the server and the router. It reads both, shows one plan with each step on the device it belongs to, and you approve it once."
        }
        Act::Audit { asks: true, .. } => {
            "From the security audit. Enter: yes, no, or you don't know; the audit's list follows your answer."
        }
        Act::Audit { .. } if claude() => {
            "From the security audit (S shows it). Enter: a session with Claude that fixes it, on whichever devices it takes; you approve its plan first."
        }
        Act::Audit { .. } => "From the security audit. Enter: its report.",
        Act::Maint(_) => {
            "From the security audit. Enter does it, as its row on Maintenance (6) does."
        }
        Act::Group {
            kind: Kind::Devices,
            ..
        } => {
            "Enter: the list of them. Each is its own decision there (name it, block it, pause it, put it off); the list stays open as you go, Esc comes back."
        }
        Act::Group {
            kind: Kind::Doors | Kind::Asks,
            ..
        } => {
            "Enter: the list of them. Answer each with yes, no, or you don't know; the list stays open as you go, Esc comes back."
        }
        Act::Group { .. } => "Enter: the list of them, each with its own numbers. Esc comes back.",
        Act::FilterDrift {
            on_router: true, ..
        } => {
            "Enter: keep it (noted here, nothing changes on the router), or take it off the router (its plan first)."
        }
        Act::FilterDrift { .. } => {
            "Enter: put it back on the router (its plan first), or forget it here."
        }
        Act::FilterRepair => {
            "Enter: the filter again on the same devices, which puts sentry's rules back in front (its plan first, through the guard)."
        }
        Act::Finding(_) | Act::Server { .. } | Act::Evidence => {
            "Enter: the numbers behind it. Nothing here needs changing on the router."
        }
    }
}

fn when(now: i64, at: i64) -> String {
    if at == now {
        "just now".to_string()
    } else if at > now {
        format!("in {}", lasting((at - now) as u64))
    } else {
        format!("{} ago", lasting((now - at) as u64))
    }
}

fn detail_lines(v: &View, picked: Option<Sel>, w: usize) -> Vec<Line<'static>> {
    let t = v.t;
    let now = v.now.as_second();
    let mut l: Vec<Line<'static>> = Vec::new();
    match picked {
        None => l.push(Line::styled(
            "Nothing selected. d shows the numbers behind this page.",
            t.dim(),
        )),
        Some(Sel::Row(r)) => {
            l.push(Line::styled(
                r.rank.word().to_string(),
                t.s(rank_color(t, r.rank)),
            ));
            l.extend(
                wrap(&r.title, w)
                    .into_iter()
                    .map(|x| Line::styled(x, t.fg())),
            );
            l.push(Line::raw(""));
            l.extend(wrap(&r.why, w).into_iter().map(|x| Line::styled(x, t.fg())));
            if !r.seen.is_empty() {
                l.push(Line::raw(""));
                for s in &r.seen {
                    l.extend(wrap(s, w).into_iter().map(|x| Line::styled(x, t.dim())));
                }
            }
            l.push(Line::raw(""));
            l.extend(
                wrap(
                    match &r.act {
                        Act::Finding(_) | Act::Server { .. } if !claude() => {
                            enter_says(&Act::Evidence)
                        }
                        a => enter_says(a),
                    },
                    w,
                )
                .into_iter()
                .map(|x| Line::styled(x, t.s(t.cyan))),
            );
        }
        Some(Sel::Shut(Shut::Device {
            label,
            reach,
            since,
            until,
            why,
            ..
        })) => {
            l.push(Line::styled(
                format!("{label} is blocked from {}", reach.says()),
                t.fg(),
            ));
            l.push(Line::raw(""));
            match since {
                Some(at) => l.push(Line::styled(format!("since {}", when(now, *at)), t.dim())),
                None => l.push(Line::styled(
                    "sentry's rule is on the router; this machine has no note of when it was made",
                    t.dim(),
                )),
            }
            if let Some(u) = until {
                l.push(Line::styled(
                    format!("a pause: it ends {}", when(now, *u)),
                    t.s(if *u <= now { t.yellow } else { t.dim }),
                ));
            }
            if !why.is_empty() {
                l.push(Line::styled(why.clone(), t.dim()));
            }
            l.push(Line::raw(""));
            l.extend(
                wrap(enter_says(&Act::Unblock { tag: String::new() }), w)
                    .into_iter()
                    .map(|x| Line::styled(x, t.s(t.cyan))),
            );
        }
        Some(Sel::Filter(Filtered::Choose { n })) => {
            let svc = crate::security::family::service();
            l.push(Line::styled(
                format!(
                    "The family filter ({}): on {}",
                    svc.name,
                    match n {
                        0 => "no device".to_string(),
                        1 => "1 device".to_string(),
                        n => format!("{n} devices"),
                    }
                ),
                t.fg(),
            ));
            l.push(Line::raw(""));
            for s in [
                format!(
                    "The devices you tick have their name lookups answered by {} instead of \
                     the router, so adult and other unwanted sites don't open on them. Every \
                     other device is left as it is.",
                    svc.name
                ),
                crate::security::actions::FILTER_LIMITS.to_string(),
                "A filtered device's lookups skip the router's own blocklist; the family \
                 service blocks malware and scam sites too."
                    .to_string(),
            ] {
                l.extend(wrap(&s, w).into_iter().map(|x| Line::styled(x, t.dim())));
            }
            if let Some(why) = filter::refused(v, "lan") {
                l.push(Line::raw(""));
                l.extend(
                    wrap(&format!("It can't work on this router yet: {why}."), w)
                        .into_iter()
                        .map(|x| Line::styled(x, t.s(t.yellow))),
                );
            } else if !filter::taken(v)
                && v.s
                    .counters
                    .value
                    .as_ref()
                    .is_some_and(|c| !crate::security::family::hijacked(c, "lan").is_empty())
            {
                l.push(Line::raw(""));
                l.extend(
                    wrap(
                        "On this router the first use includes a one-time step: sentry takes \
                         over from the DNS proxy the forcing of every device's lookups \
                         through the router (nothing changes for the others), so the devices \
                         you pick can come first.",
                        w,
                    )
                    .into_iter()
                    .map(|x| Line::styled(x, t.s(t.cyan))),
                );
            }
            l.push(Line::raw(""));
            l.extend(
                wrap(
                    "Enter: the list of devices. Tick the ones to filter; Enter there shows \
                     the plan for all of them as one change.",
                    w,
                )
                .into_iter()
                .map(|x| Line::styled(x, t.s(t.cyan))),
            );
        }
        Some(Sel::Filter(Filtered::Device { label, since, .. })) => {
            l.push(Line::styled(
                format!("{label}'s name lookups are filtered"),
                t.fg(),
            ));
            l.push(Line::raw(""));
            match since {
                Some(at) => l.push(Line::styled(format!("since {}", when(now, *at)), t.dim())),
                None => l.push(Line::styled(
                    "sentry's rules are on the router; this machine has no note of when",
                    t.dim(),
                )),
            }
            l.push(Line::raw(""));
            l.extend(
                wrap(
                    &format!(
                        "sentry can't test from the device itself: open {} on it; it should \
                         be blocked.",
                        crate::security::family::service().blocked_test
                    ),
                    w,
                )
                .into_iter()
                .map(|x| Line::styled(x, t.dim())),
            );
            l.push(Line::raw(""));
            l.push(Line::styled(
                "Enter: take it off (exactly sentry's rules for it, through the guard).",
                t.s(t.cyan),
            ));
        }
        Some(Sel::Shut(Shut::Door { name, since, .. })) => {
            l.push(Line::styled(
                format!("The door {name} is closed (switched off, still in the config)"),
                t.fg(),
            ));
            l.push(Line::styled(
                format!("closed from here {}", when(now, *since)),
                t.dim(),
            ));
            l.push(Line::raw(""));
            l.push(Line::styled(
                "Enter: open it again (through the guard).",
                t.s(t.cyan),
            ));
        }
    }
    l
}

fn cover_mark(t: &sentry_core::tui::theme::Theme, c: Cover) -> (&'static str, Color) {
    match c {
        Cover::Ok => ("✓", t.green),
        Cover::Weak => ("!", t.yellow),
        Cover::Off => ("✗", t.red),
        Cover::Unknown => ("?", t.dim),
    }
}

/// A sentence in at most two lines of `w`.
fn two_lines(s: &str, w: usize) -> Vec<String> {
    let mut l = wrap(s, w.max(8));
    if l.len() > 2 {
        let rest = l.split_off(1).join(" ");
        l.push(trunc(&rest, w.max(8)));
    }
    l
}

/// `compact` (a small window): what is fine is one count, the rest a line each, so the
/// list above keeps its room.
fn posture_lines(
    v: &View,
    posture: &[crate::security::Line],
    w: usize,
    compact: bool,
) -> Vec<Line<'static>> {
    let t = v.t;
    let mut out = Vec::new();
    let fine = posture.iter().filter(|p| p.state == Cover::Ok).count();
    for p in posture {
        if compact && p.state == Cover::Ok && fine > 1 {
            continue;
        }
        let (mark, c) = cover_mark(t, p.state);
        let st = if p.state == Cover::Unknown {
            t.dim()
        } else {
            t.fg()
        };
        let text = match compact {
            true => vec![trunc(&p.text, w.saturating_sub(7).max(8))],
            false => two_lines(&p.text, w.saturating_sub(7)),
        };
        for (i, text) in text.into_iter().enumerate() {
            out.push(if i == 0 {
                Line::from(vec![
                    Span::styled(format!("{mark} "), t.s(c)),
                    Span::styled(format!("{:<5}", p.state.word()), t.s(c)),
                    Span::styled(text, st),
                ])
            } else {
                Line::from(vec![Span::raw("       "), Span::styled(text, st)])
            });
        }
    }
    if compact && fine > 1 {
        out.push(Line::from(vec![
            Span::styled("✓ ", t.s(t.green)),
            Span::styled("ok   ", t.s(t.green)),
            Span::styled(
                format!("{fine} other parts are fine (a taller window lists them)"),
                t.fg(),
            ),
        ]));
    }
    out
}

fn shut_cells(v: &View, s: &Shut) -> Vec<Cell<'static>> {
    let t = v.t;
    let now = v.now.as_second();
    match s {
        Shut::Device {
            label,
            reach,
            since,
            until,
            ..
        } => vec![
            Cell::from(label.clone()).style(t.fg()),
            Cell::from(format!("from {}", reach.word())).style(t.dim()),
            Cell::from(match (until, since) {
                (Some(u), _) if *u <= now => "pause ended".to_string(),
                (Some(u), _) => format!("paused, ends {}", when(now, *u)),
                (None, Some(at)) => format!("since {}", when(now, *at)),
                (None, None) => String::new(),
            })
            .style(t.s(if until.is_some_and(|u| u <= now) {
                t.yellow
            } else {
                t.dim
            })),
        ],
        Shut::Door { name, since, .. } => vec![
            Cell::from(format!("door {name}")).style(t.fg()),
            Cell::from("closed").style(t.dim()),
            Cell::from(format!("since {}", when(now, *since))).style(t.dim()),
        ],
    }
}

/// The panel that holds the selected row's evidence.
fn evidence(sec: &mut Security, f: &mut Frame, area: Rect, v: &View, b: &Built, s: &Subject) {
    let t = v.t;
    let p = &b.picture;
    let w = area.width.saturating_sub(4) as usize;
    let (name, lines) = match s {
        Subject::Egress(key) => {
            let at = key.as_ref().and_then(|k| {
                panels::rows(v, p, sec.sort)
                    .iter()
                    .position(|d| &d.key == k)
            });
            return sec.egress(f, area, v, p, Some(at));
        }
        Subject::Ingress => ("Ingress", panels::ingress_lines(v, p, w, false)),
        Subject::Zones => ("Segmentation", panels::seg_lines(v, p, w, false)),
        Subject::Dns => ("DNS", panels::dns_lines(v, p, w)),
        Subject::Wifi => ("Wi-Fi", panels::wifi_lines(v, p, w)),
        Subject::None => return,
    };
    let bl = panel(t, name, "the numbers · d shows them all");
    let r = inner(&bl, area);
    f.render_widget(bl, area);
    f.render_widget(Paragraph::new(lines), r);
}

/// How tall a subject's panel wants to be.
fn evidence_height(v: &View, b: &Built, s: &Subject, w: usize) -> u16 {
    let p = &b.picture;
    let n = match s {
        Subject::None => return 0,
        Subject::Egress(_) => p.devices.len().min(8) + 1,
        Subject::Ingress => panels::ingress_lines(v, p, w, false).len(),
        Subject::Zones => panels::seg_lines(v, p, w, false).len(),
        Subject::Dns => panels::dns_lines(v, p, w).len(),
        Subject::Wifi => panels::wifi_lines(v, p, w).len(),
    };
    n as u16 + 2
}

pub fn render(sec: &mut Security, f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    // The family filter's list, in the list's place.
    if let Some(m) = sec.filter.as_mut() {
        let wide = area.width >= 120;
        if wide {
            let [l, r] =
                Layout::horizontal([Constraint::Ratio(55, 100), Constraint::Ratio(45, 100)])
                    .spacing(1)
                    .areas(area);
            return filter::render(m, f, l, Some(r), v);
        }
        let detail = match area.height {
            24.. => 11,
            16.. => 7,
            _ => 0,
        };
        let [l, d] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(detail)]).areas(area);
        return filter::render(m, f, l, (detail > 0).then_some(d), v);
    }
    let b = built(v);
    // A list that was gone through to its end is closed.
    if v.group.is_some() && b.open(v).is_none() {
        sec.group = None;
    }
    let (rows, waiting) = b.listed(v);
    let picked = sel(v, &b);
    let subject = match &picked {
        Some(Sel::Row(r)) => r.subject.clone(),
        _ => Subject::None,
    };
    let wide = area.width >= 120;
    let (left, right) = if wide {
        let [l, r] = Layout::horizontal([Constraint::Ratio(55, 100), Constraint::Ratio(45, 100)])
            .spacing(1)
            .areas(area);
        (l, Some(r))
    } else {
        (area, None)
    };
    // The left column: the list, how the network is covered, what is shut. A sentence
    // that doesn't fit its line takes a second.
    let text_w = left.width.saturating_sub(4) as usize;
    let shut_h = if b.shut.is_empty() {
        0
    } else {
        b.shut.len() as u16 + 3
    };
    // (No header: its rows say what they are. On a small window it is one line.)
    let filt_h = if b.filtered.is_empty() {
        0
    } else {
        b.filtered.len() as u16 + 2
    };
    // A row is two lines: what it is, and under it what Enter does.
    let open = b.open(v);
    let start = match open {
        Some(_) => 0,
        None => attention::start_here(rows.iter().copied()),
    };
    let then = open.is_none() && start > 0 && rows.len() > start;
    let want = (rows.len() * 2).max(1) as u16 + then as u16 + 3;
    // The cover in full where the list still fits above it; else what is fine as a count.
    // (Over a list being gone through the page's numbers aren't in view: said in full.)
    let pointed = match open {
        Some(_) => b.posture.clone(),
        None => attention::pointed(&b.posture, &b.main(v)),
    };
    let full = posture_lines(v, &pointed, text_w, false);
    let fits = left.height >= 30 && want + full.len() as u16 + 2 + shut_h + filt_h <= left.height;
    let cover = match fits {
        true => full,
        false => posture_lines(v, &pointed, text_w, true),
    };
    let cover_h = if cover.is_empty() {
        0
    } else {
        cover.len() as u16 + 2
    };
    let room = left.height.saturating_sub(cover_h + shut_h + filt_h);
    // Narrow: the detail has the last lines, where there is room for it.
    let detail_h = if wide || left.height < 20 { 0 } else { 7 };
    let list_h = if wide {
        want.min(room).max(5.min(left.height))
    } else {
        room.saturating_sub(detail_h).max(5.min(left.height))
    };
    let [list_a, cover_a, shut_a, filt_a, rest_a] = Layout::vertical([
        Constraint::Length(list_h),
        Constraint::Length(cover_h),
        Constraint::Length(shut_h),
        Constraint::Length(filt_h),
        Constraint::Fill(1),
    ])
    .areas(left);

    let (now, look) = b.asking();
    let note = if !read_any(v) {
        String::new()
    } else {
        let mut said = vec![match (now + look, rows.len()) {
            (0, 0) => "nothing needs you".to_string(),
            (_, n) => format!("{n}"),
        }];
        if waiting > 0 {
            said.push(format!("o shows {waiting} good to know"));
        }
        said.join(" · ")
    };
    let heading = match open.map(|g| &g.act) {
        Some(Act::Group { kind, .. }) => kind.heading(rows.len()),
        _ => "Needs attention".to_string(),
    };
    let bl = panel(
        t,
        &heading,
        match open {
            Some(_) => "Esc back".to_string(),
            None => note,
        },
    );
    let r = inner(&bl, list_a);
    f.render_widget(bl, list_a);
    sec.cur.page = r.height.saturating_sub(1) as usize;
    if rows.is_empty() {
        let said = if !read_any(v) {
            match &v.s.unreachable {
                Some(_) => "not reachable".to_string(),
                None => "reading…".to_string(),
            }
        } else if v.filter.is_some() {
            maintlist::NO_MATCH.to_string()
        } else {
            "✓ Nothing needs you. How the network is covered is below.".to_string()
        };
        let st = if read_any(v) && v.filter.is_none() {
            t.s(t.green)
        } else {
            t.dim()
        };
        widgets::placeholder(f, r, t, &[(said.as_str(), st)]);
    } else {
        // (A list being gone through has no numbers or levels: its rows are equals.)
        let margin: [u16; 2] = if open.is_some() { [0, 0] } else { [3, 8] };
        let tw = text_w
            .saturating_sub(margin.iter().map(|m| *m as usize + 1).sum())
            .max(8);
        let mut table: Vec<TRow> = Vec::new();
        for (i, x) in rows.iter().enumerate() {
            if then && i == start {
                table.push(TRow::new(vec![
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from("Then").style(t.dim()),
                ]));
            }
            let (n, rank) = match open {
                Some(_) => (String::new(), Cell::from("")),
                None => (
                    format!("{:>2}.", i + 1),
                    Cell::from(x.rank.word()).style(t.s(rank_color(t, x.rank))),
                ),
            };
            table.push(
                TRow::new(vec![
                    Cell::from(n).style(if i < start { t.fg() } else { t.dim() }),
                    rank,
                    Cell::from(ratatui::text::Text::from(
                        match attention::two_lines(&x.title, &x.step(claude()), tw) {
                            (a, b, true) => vec![Line::styled(a, t.fg()), Line::styled(b, t.dim())],
                            (a, b, false) => vec![Line::styled(a, t.fg()), Line::styled(b, t.fg())],
                        },
                    )),
                ])
                .height(2),
            );
        }
        let head = match (open, start) {
            (Some(_), _) => "Each is its own decision: the list stays open as you go",
            (None, 0) => "Nothing urgent. When you have time",
            (None, _) => "Start here",
        };
        widgets::table(
            f,
            r,
            t,
            TableSpec {
                header: vec!["", "", head],
                widths: vec![
                    Constraint::Length(margin[0]),
                    Constraint::Length(margin[1]),
                    Constraint::Fill(1),
                ],
                rows: table,
                selected: (v.cur < rows.len()).then_some(v.cur + (then && v.cur >= start) as usize),
            },
        );
    }

    if cover_a.height >= 3 {
        let bl = panel(t, "How you're covered", "");
        let r = inner(&bl, cover_a);
        f.render_widget(bl, cover_a);
        f.render_widget(Paragraph::new(cover), r);
    }
    if shut_a.height >= 3 {
        let bl = panel(t, "Blocked by you", format!("{}", b.shut.len()));
        let r = inner(&bl, shut_a);
        f.render_widget(bl, shut_a);
        widgets::table(
            f,
            r,
            t,
            TableSpec {
                header: vec!["what", "", "when"],
                widths: vec![
                    Constraint::Fill(2),
                    Constraint::Length(16),
                    Constraint::Fill(2),
                ],
                rows: b.shut.iter().map(|s| TRow::new(shut_cells(v, s))).collect(),
                selected: v.cur.checked_sub(rows.len()).filter(|i| *i < b.shut.len()),
            },
        );
    }

    if filt_a.height >= 3 {
        let n = b.filtered.len().saturating_sub(1);
        let bl = panel(
            t,
            "Filtered by you",
            match n {
                0 => "family filter: no device".to_string(),
                1 => "family filter: 1 device".to_string(),
                n => format!("family filter: {n} devices"),
            },
        );
        let r = inner(&bl, filt_a);
        f.render_widget(bl, filt_a);
        let now = v.now.as_second();
        let rows: Vec<TRow> = b
            .filtered
            .iter()
            .map(|x| match x {
                Filtered::Choose { .. } => TRow::new(vec![
                    Cell::from("Choose devices…").style(t.s(t.cyan)),
                    Cell::from("").style(t.dim()),
                    Cell::from("").style(t.dim()),
                ]),
                Filtered::Device { label, since, .. } => TRow::new(vec![
                    Cell::from(label.clone()).style(t.fg()),
                    Cell::from("filtered").style(t.dim()),
                    Cell::from(
                        since
                            .map(|at| format!("since {}", when(now, at)))
                            .unwrap_or_default(),
                    )
                    .style(t.dim()),
                ]),
            })
            .collect();
        let table = ratatui::widgets::Table::new(
            rows,
            [
                Constraint::Fill(2),
                Constraint::Length(16),
                Constraint::Fill(2),
            ],
        )
        .column_spacing(1)
        .row_highlight_style(ratatui::style::Style::new().bg(t.sel_bg));
        let mut st = ratatui::widgets::TableState::default().with_selected(
            v.cur
                .checked_sub(rows_len_before(&b, v))
                .filter(|i| *i < b.filtered.len()),
        );
        f.render_stateful_widget(table, r, &mut st);
    }

    let draw_detail = |f: &mut Frame, a: Rect, picked: Option<Sel>| {
        if a.height < 3 {
            return;
        }
        let bl = panel(t, "Details", "");
        let r = inner(&bl, a);
        f.render_widget(bl, a);
        f.render_widget(Paragraph::new(detail_lines(v, picked, r.width as usize)), r);
    };
    match right {
        Some(right) => {
            let w = right.width.saturating_sub(4) as usize;
            let ev = evidence_height(v, &b, &subject, w).min(right.height / 2);
            let [detail_a, ev_a] =
                Layout::vertical([Constraint::Fill(1), Constraint::Length(ev)]).areas(right);
            draw_detail(f, detail_a, picked);
            if ev_a.height >= 3 {
                evidence(sec, f, ev_a, v, &b, &subject);
            }
        }
        None => draw_detail(f, rest_a, picked),
    }
}
