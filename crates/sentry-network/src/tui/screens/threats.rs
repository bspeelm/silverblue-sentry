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

use super::security::{self as panels, Security};
use super::{Hints, View};
use crate::security::actions::Do;
use crate::security::attention::{DevRef, lasting};
use crate::security::blocks::{self, Dev, Door, Note, Reach, Shut};
use crate::security::gather::{self, More};
use crate::security::{Act, Cover, Picture, Rank, Row, State, Subject, attention, posture};
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
    /// Every row not marked expected and not put off, most urgent first.
    pub rows: Vec<Row>,
    pub posture: Vec<crate::security::Line>,
    pub shut: Vec<Shut>,
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
    let mut rows = attention(&state);
    audit_rows(v, &state, &mut rows);
    rows.retain(|r| v.sh.later.get(&r.key).is_none_or(|d| *d <= day));
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
    }
}

/// What a server's own guard says, when the window has a server that has one: read by
/// name from what that target says of itself (the app carries it; this crate knows no
/// server). Whether the router enforces its bans is the router's own bouncer.
pub fn server_guard(v: &View) -> Option<crate::security::attention::ServerGuard> {
    let sys = v
        .system
        .iter()
        .find(|s| s.line.fact("guard.blocked").is_some())?;
    Some(crate::security::attention::ServerGuard {
        server: sys.peer.title.clone(),
        banned_today: sys.line.fact("guard.blocked")?.parse().ok()?,
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

/// The page's own row that is already about an audit item's subject, by its key (a
/// prefix), for the items that are this network's.
fn audit_subject(i: &sentry_core::secaudit::Item) -> Option<String> {
    let what = i.id.split(':').nth(1).unwrap_or("");
    Some(
        match what {
            "ssh-password" => "finding:net:ssh:password",
            "admin-http" => "finding:net:luci:http",
            "unknown-devices" => "finding:net:client:",
            "crossing" => "finding:net:flow:",
            "dns-filter" => "sec:blocklist",
            "wan-input" => "finding:net:zone:",
            "watch" => "finding:net:crowdsec:",
            // A door the page lists as one you haven't listed: `sec:door:<net>:<proto>:<port>`.
            "door" => {
                let mut end = i.id.rsplit(':');
                let (port, proto) = (end.next()?, end.next()?);
                return Some(format!("finding:net:forward:{proto}:{port}"));
            }
            _ => return None,
        }
        .to_string(),
    )
}

/// The security audit's items this page lists (`Shared::sec`), joined with its own rows by
/// subject: where the page already has the row (it has the action), that row takes the
/// audit's why and its urgency and the item gets none; where the page's row was marked
/// expected, the item stays away too; the rest become rows of their own. What Maintenance
/// does (firmware, packages, the backup) is a row whose Enter goes there.
fn audit_rows(v: &View, s: &State, rows: &mut Vec<Row>) {
    use sentry_core::secaudit::State as St;
    let me = crate::tui::id_of(v.name);
    for i in &v.sh.sec {
        let own = i.targets.len() <= 1 || i.targets.contains(&me);
        let what = i.id.split(':').nth(1).unwrap_or("");
        let rank = match i.state {
            St::DoFirst => Rank::Now,
            _ => Rank::Look,
        };
        if let Some(prefix) = audit_subject(i).filter(|_| own || what == "watch") {
            let prefix = prefix.as_str();
            if let Some(r) = rows.iter_mut().find(|r| r.key.starts_with(prefix)) {
                r.rank = r.rank.min(rank);
                r.can_wait = false;
                if !i.why.is_empty() && !r.why.contains(&i.why) {
                    r.why = format!("{} {}", i.why, r.why);
                }
                continue;
            }
            // The page read it and has no row: expected, or no longer so.
            let id = prefix.trim_start_matches("finding:");
            let expected = s
                .findings
                .iter()
                .any(|f| f.id.starts_with(id) && f.expected)
                || s.expected
                    .iter()
                    .any(|g| sentry_core::baseline::glob(g, id.trim_end_matches(':')));
            let read = match what {
                "unknown-devices" => s.read.clients.is_some(),
                "dns-filter" => s.read.dns.is_some(),
                _ => false,
            };
            // (A door you listed is still the audit's to judge: what answers behind it.)
            if (expected || read) && what != "door" {
                continue;
            }
        }
        let key = sentry_app::secaudit::row_key(&i.id);
        if s.expected
            .iter()
            .any(|g| sentry_core::baseline::glob(g, &key))
        {
            continue;
        }
        let maint = matches!(what, "firmware" | "packages" | "backup") && own;
        rows.push(Row {
            id: key.clone(),
            key,
            rank,
            title: i.title.clone(),
            why: match (i.state, i.fix.is_empty()) {
                (St::Ask, _) => {
                    "The security audit can't read this: only you know. Enter answers it."
                        .to_string()
                }
                (_, true) => i.why.clone(),
                (_, false) => format!("{} What it takes: {}", i.why, i.fix),
            },
            seen: i.evidence.clone(),
            act: if maint {
                Act::Maint
            } else {
                Act::Audit {
                    id: i.id.clone(),
                    asks: i.state == St::Ask,
                }
            },
            subject: Subject::None,
            can_wait: false,
        });
    }
    rows.sort_by_key(|r| r.rank);
}

impl Built {
    /// The rows listed: what needs you (everything with `o`), filtered. With it, how many
    /// wait unseen.
    pub fn listed(&self, v: &View) -> (Vec<&Row>, usize) {
        let waiting = self.rows.iter().filter(|r| r.can_wait).count();
        let rows = self
            .rows
            .iter()
            .filter(|r| v.everything || !r.can_wait)
            .filter(|r| v.matches(&[&r.title, &r.why, r.rank.word()]))
            .collect();
        (rows, if v.everything { 0 } else { waiting })
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
}

pub fn sel<'a>(v: &View, b: &'a Built) -> Option<Sel<'a>> {
    let (rows, _) = b.listed(v);
    if let Some(r) = rows.get(v.cur) {
        return Some(Sel::Row(r));
    }
    b.shut.get(v.cur - rows.len()).map(Sel::Shut)
}

pub fn count(v: &View) -> usize {
    let b = built(v);
    b.listed(v).0.len() + b.shut.len()
}

/// What the row at the cursor is, to find it again when the list changes.
pub fn row_key(v: &View) -> Option<String> {
    let b = built(v);
    Some(match sel(v, &b)? {
        Sel::Row(r) => r.key.clone(),
        Sel::Shut(s) => s.key(),
    })
}

/// Where a row is now (None: gone).
pub fn position(v: &View, key: &str) -> Option<usize> {
    let b = built(v);
    let (rows, _) = b.listed(v);
    rows.iter().position(|r| r.key == key).or_else(|| {
        b.shut
            .iter()
            .position(|s| s.key() == key)
            .map(|i| rows.len() + i)
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
            // A pause that ended isn't something to expect: it is lifted or put off.
            dismiss: (!matches!(r.act, Act::Unblock { .. })).then_some(Dismiss::Expected),
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
    })
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
        (Some(vb), Some(Sel::Shut(_))) => vec![("Enter", vb.enter)],
        _ => Vec::new(),
    };
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
            "what the row says: shown first, never a bare switch",
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
        // The audit's own: a session across whatever targets it names, or your answer.
        Act::Audit { id, asks } if *asks || claude() => vec![Effect::SecItem(id.clone())],
        Act::Audit { .. } => vec![Effect::SecShow],
        Act::Maint => vec![
            Effect::Goto(sentry_core::tui::ScreenId::Maint),
            Effect::Toast("Maintenance does it: its row is in the list here".into()),
        ],
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

/// A key on the list (moving is the cursor's).
pub fn handle(sec: &mut Security, a: Key, v: &View) -> Vec<Effect> {
    let t = v.t;
    let b = built(v);
    let picked = sel(v, &b);
    match a {
        Key::Refresh | Key::Check => panels::read_again(),
        Key::Char('o') => vec![Effect::Everything],
        Key::Char('v') => vec![Effect::LogOpen(None)],
        Key::Enter => match picked {
            Some(Sel::Row(r)) => enter(v, r, sec),
            Some(Sel::Shut(Shut::Device { tag, .. })) => start(Do::Unblock { tag: tag.clone() }),
            Some(Sel::Shut(Shut::Door { section, .. })) => start(Do::ForwardOn {
                section: section.clone(),
            }),
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
            let can = !matches!(r.act, Act::Unblock { .. });
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
    let Want::Start {
        act,
        dev,
        until,
        why,
        door,
    } = w
    else {
        return Vec::new();
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
    if let Some(d) = dev {
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
                    why: why.clone(),
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
        Want::Start { .. } => Vec::new(),
    }
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
        Act::Maint => "From the security audit. Enter: Maintenance (6), where it is done.",
        Act::Finding(_) | Act::Server { .. } | Act::Evidence => {
            "Enter: the numbers behind it. Nothing here needs changing on the router."
        }
    }
}

fn when(now: i64, at: i64) -> String {
    if at >= now {
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

fn posture_lines(v: &View, b: &Built, w: usize) -> Vec<Line<'static>> {
    let t = v.t;
    let mut out = Vec::new();
    for p in &b.posture {
        let (mark, c) = cover_mark(t, p.state);
        let st = if p.state == Cover::Unknown {
            t.dim()
        } else {
            t.fg()
        };
        for (i, text) in two_lines(&p.text, w.saturating_sub(7))
            .into_iter()
            .enumerate()
        {
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
    let b = built(v);
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
    let cover = posture_lines(v, &b, text_w);
    let cover_h = if cover.is_empty() {
        0
    } else {
        cover.len() as u16 + 2
    };
    let shut_h = if b.shut.is_empty() {
        0
    } else {
        b.shut.len() as u16 + 3
    };
    let titles: Vec<Vec<String>> = rows
        .iter()
        .map(|x| two_lines(&x.title, text_w.saturating_sub(9)))
        .collect();
    let want = titles.iter().map(Vec::len).sum::<usize>().max(1) as u16 + 3;
    let room = left.height.saturating_sub(cover_h + shut_h);
    // Narrow: the detail has the last lines, where there is room for it.
    let detail_h = if wide || left.height < 20 { 0 } else { 7 };
    let list_h = if wide {
        want.min(room).max(5.min(left.height))
    } else {
        room.saturating_sub(detail_h).max(5.min(left.height))
    };
    let [list_a, cover_a, shut_a, rest_a] = Layout::vertical([
        Constraint::Length(list_h),
        Constraint::Length(cover_h),
        Constraint::Length(shut_h),
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
    let bl = panel(t, "Needs attention", note);
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
        let table: Vec<TRow> = rows
            .iter()
            .zip(&titles)
            .map(|(x, title)| {
                TRow::new(vec![
                    Cell::from(x.rank.word()).style(t.s(rank_color(t, x.rank))),
                    Cell::from(title.join("\n")).style(t.fg()),
                ])
                .height(title.len().max(1) as u16)
            })
            .collect();
        widgets::table(
            f,
            r,
            t,
            TableSpec {
                header: vec!["", "What"],
                widths: vec![Constraint::Length(8), Constraint::Fill(1)],
                rows: table,
                selected: (v.cur < rows.len()).then_some(v.cur),
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
                selected: v.cur.checked_sub(rows.len()),
            },
        );
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
