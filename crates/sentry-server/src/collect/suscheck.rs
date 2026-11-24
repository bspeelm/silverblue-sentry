//! SusCheck, where a server runs it: how a household's checks of suspicious mail and pages
//! went. SusCheck (a separate project) keeps every check as an incident in one folder and
//! publishes that folder's format (schema 1); this reads it and nothing else. Nothing is
//! ever written, moved or deleted there, nothing runs as root, and a folder this login may
//! not read is said so, never got at another way.
//!
//! **Everything in the folder is hostile.** The text was written by a model that had just
//! read whatever a scammer put on screen, and the pictures are a household's private mail.
//! So: an id is checked against its grammar wherever a path is made from it ([`Id`], the
//! only way one is held); every string goes through [`clean`] before it is kept; a line
//! that is too long, isn't JSON or has a bad id is skipped and counted; a schema this
//! sentry doesn't know is said and nothing of that file is shown; nothing found in a record
//! is ever run, opened, fetched or looked up; and none of it goes to Claude, into a stored
//! report, a log entry or a prompt. What leaves this module for those is [`Counts`]: numbers.
//!
//! A check can be made from a screenshot, from the email itself as a file, from the page's
//! address as SusCheck's desktop app reads it out of the window, or from several of these.
//! The record then has the email's headers, the links (text and where each leads, stored
//! defanged) and the page; and the folder may hold `message.txt`, a quarantined copy of
//! the message's text. **That file is never read here**: [`path_of`] has no name for it.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::remote::{Remote, SrvError};
use sentry_core::exec::{ExecError, sh_quote};

/// The schema this reader knows.
pub const SCHEMA: i64 = 1;
/// An index line is at most this long, its newline included.
pub const LINE_MAX: usize = 1024;
/// The most of an incident's record that is read.
pub const INCIDENT_MAX: usize = 262_144;
/// The most of a picture that is fetched.
pub const PICTURE_MAX: u64 = 16 * 1024 * 1024;
/// No heartbeat for this long (by the server's clock): the service is stopped or stuck.
pub const HEARTBEAT_S: i64 = 300;
/// This many failed checks in a day is worth a finding.
pub const ERRORS_A_DAY: u32 = 3;
/// SusCheck's pointer to its folder (world-readable, one line).
pub const POINTER: &str = "/etc/suscheck/incidents.path";

const PNG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// An incident's id, proven to be `[0-9]{8}T[0-9]{6}Z-[a-z0-9]{4}`: the whole string, ASCII.
/// The only form an id is kept in, so a path can only ever be made from one that passed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id([u8; 21]);

impl Id {
    /// None for anything but the grammar: never trimmed, never repaired.
    pub fn parse(s: &str) -> Option<Id> {
        let b = s.as_bytes();
        if b.len() != 21 {
            return None;
        }
        let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
        let tail = b[17..]
            .iter()
            .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase());
        if !(digits(0..8)
            && b[8] == b'T'
            && digits(9..15)
            && b[15] == b'Z'
            && b[16] == b'-'
            && tail)
        {
            return None;
        }
        let mut id = [0u8; 21];
        id.copy_from_slice(b);
        Some(Id(id))
    }

    pub fn as_str(&self) -> &str {
        // (Every byte passed the grammar: ASCII.)
        std::str::from_utf8(&self.0).unwrap_or("")
    }

    /// When the check was received (the id's first part, UTC), in epoch seconds. None for
    /// digits that aren't a date.
    pub fn time(&self) -> Option<i64> {
        let s = self.as_str();
        format!(
            "{}-{}-{}T{}:{}:{}Z",
            &s[0..4],
            &s[4..6],
            &s[6..8],
            &s[9..11],
            &s[11..13],
            &s[13..15]
        )
        .parse::<jiff::Timestamp>()
        .ok()
        .map(|t| t.as_second())
    }
}

impl std::fmt::Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A Unicode format character (category Cf: direction overrides and isolates, zero-width
/// characters, the byte-order mark, invisible operators, tags), a private-use character or
/// a noncharacter. Written out: no table of categories is at hand, so a code point Unicode
/// hasn't assigned yet is not caught here (a terminal draws those as a box).
fn invisible(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFF0..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0000..=0xE0FFF
            // Private use, and the noncharacters.
            | 0xE000..=0xF8FF
            | 0xF0000..=0x10FFFF
            | 0xFDD0..=0xFDEF
    ) || (c as u32) & 0xFFFE == 0xFFFE
}

/// The one way a string from the folder is made fit to keep and draw: terminal escape
/// sequences go whole (CSI, OSC and the two-character ones), then every control character,
/// format character (direction overrides, zero-width), private-use character and
/// noncharacter; a line break, a tab or a Unicode line or paragraph separator is a space.
/// SusCheck does this when it writes; a reader does it again and relies on neither.
pub fn clean(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => match chars.next() {
                // CSI: parameters and intermediates, then one final byte.
                Some('[') => {
                    for c in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&c) {
                            break;
                        }
                    }
                }
                // OSC, and the other strings (DCS, SOS, PM, APC): up to BEL or ESC \.
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    while let Some(c) = chars.next() {
                        if c == '\x07' || c == '\u{9c}' {
                            break;
                        }
                        if c == '\x1b' {
                            chars.next_if_eq(&'\\');
                            break;
                        }
                    }
                }
                // A two-character sequence (or a lone ESC at the end): both go.
                _ => {}
            },
            // The 8-bit CSI: its parameters go with it.
            '\u{9b}' => {
                for c in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&c) {
                        break;
                    }
                }
            }
            '\n' | '\r' | '\t' | '\x0b' | '\x0c' | '\u{85}' | '\u{2028}' | '\u{2029}' => {
                out.push(' ')
            }
            c if c.is_control() || invisible(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// A string from a record: cleaned, cut to `cap` characters, None when it isn't a string
/// or nothing is left of it.
fn text(v: &Value, cap: usize) -> Option<String> {
    let s = clean(v.as_str()?);
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    Some(match s.char_indices().nth(cap) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_string(),
    })
}

fn texts(v: &Value, cap: usize, most: usize) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| text(x, cap))
        .take(most)
        .collect()
}

/// An RFC 3339 time, in epoch seconds.
fn time(v: &Value) -> Option<i64> {
    v.as_str()?
        .parse::<jiff::Timestamp>()
        .ok()
        .map(|t| t.as_second())
}

/// What SusCheck concluded, as the household was told it. `likely_safe` is never "safe":
/// the check found no warning signs, which is all it can say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Verdict {
    Malicious,
    Suspicious,
    Safe,
}

impl Verdict {
    pub const ALL: [Verdict; 3] = [Verdict::Malicious, Verdict::Suspicious, Verdict::Safe];

    /// One of the three known values; anything else is not treated as any of them.
    pub fn of(word: &str) -> Option<Verdict> {
        match word {
            "likely_malicious" => Some(Verdict::Malicious),
            "suspicious" => Some(Verdict::Suspicious),
            "likely_safe" => Some(Verdict::Safe),
            _ => None,
        }
    }

    /// The format's word (what a mark is kept as).
    pub fn word(self) -> &'static str {
        match self {
            Verdict::Malicious => "likely_malicious",
            Verdict::Suspicious => "suspicious",
            Verdict::Safe => "likely_safe",
        }
    }

    /// As the household saw it.
    pub fn said(self) -> &'static str {
        match self {
            Verdict::Malicious => "don't trust this",
            Verdict::Suspicious => "be careful",
            Verdict::Safe => "no obvious warning signs",
        }
    }
}

/// A verdict as the screen says it: the household's words for a known one, the value as
/// it is (already cleaned) for one this sentry doesn't know.
pub fn said(verdict: &str) -> &str {
    match Verdict::of(verdict) {
        Some(v) => v.said(),
        None => verdict,
    }
}

/// One line of the index: the summary of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub id: Id,
    /// When it was received (from the id), epoch seconds.
    pub at: Option<i64>,
    pub device: Option<String>,
    pub client: Option<String>,
    pub app_version: Option<String>,
    pub kind: Option<String>,
    /// Who the content claims to be from: attacker-influenced text.
    pub brand: Option<String>,
    /// The domain that was on screen. Text: never resolved, looked up or opened.
    pub domain: Option<String>,
    pub domain_check: Option<String>,
    /// `likely_safe` / `suspicious` / `likely_malicious`, or a value this sentry doesn't
    /// know, kept as text.
    pub verdict: Option<String>,
    pub confidence: Option<String>,
    pub incomplete: Option<bool>,
    /// SusCheck's fixed rules raised the verdict above the model's.
    pub floors_changed: Option<bool>,
    pub duration_ms: u64,
    /// Why it failed (`model`, `server`, `cancelled`, …); None for a completed check.
    pub error: Option<String>,
    /// What the person sent, as the index says it (`image`, `email`, `image+page`, …; a
    /// value this sentry doesn't know is kept as text), whatever happened next: a check
    /// that failed has it too. A line from before the field was there is `image`: a picture
    /// was all there was. None: not a string (today's writer never leaves it null).
    pub input: Option<String>,
}

/// The inputs a check can be made from, in the format's order, each in plain words.
pub const INPUTS: [(&str, &str); 3] = [
    ("image", "picture"),
    ("email", "email"),
    ("page", "page address"),
];

/// The parts of an index line's `input` when every one of them is known (`image+page` →
/// `["image", "page"]`); None for anything else.
pub fn input_parts(input: &str) -> Option<Vec<&'static str>> {
    let parts: Option<Vec<&'static str>> = input
        .split('+')
        .map(|p| INPUTS.iter().find(|(w, _)| *w == p).map(|(w, _)| *w))
        .collect();
    parts.filter(|p| !p.is_empty())
}

/// `input` in plain words: `picture`, `email`, `picture + page address`. A value this
/// sentry doesn't know is shown as it is (already cleaned).
pub fn input_said(input: &str) -> String {
    match input_parts(input) {
        Some(parts) => parts
            .iter()
            .filter_map(|p| INPUTS.iter().find(|(w, _)| w == p).map(|(_, said)| *said))
            .collect::<Vec<_>>()
            .join(" + "),
        None => input.to_string(),
    }
}

impl Check {
    pub fn verdict(&self) -> Option<Verdict> {
        self.verdict.as_deref().and_then(Verdict::of)
    }

    /// What the list says in the verdict's column.
    pub fn outcome(&self) -> String {
        match (&self.error, &self.verdict) {
            (Some(e), _) => format!("failed ({e})"),
            (None, Some(v)) => said(v).to_string(),
            (None, None) => "no verdict".into(),
        }
    }

    /// What was sent, in plain words; None when nothing usable was recorded.
    pub fn sent(&self) -> Option<String> {
        self.input.as_deref().map(input_said)
    }

    /// The check was made without a picture, as far as the index says: what it was made
    /// from instead, in words. None when a picture was sent, or the value isn't known.
    pub fn pictureless(&self) -> Option<&'static str> {
        let parts = input_parts(self.input.as_deref()?)?;
        match (
            parts.contains(&"image"),
            parts.contains(&"email"),
            parts.contains(&"page"),
        ) {
            (true, _, _) => None,
            (false, true, false) => Some("the email itself"),
            (false, false, _) => Some("the page's address alone"),
            (false, true, true) => Some("the email and the page's address"),
        }
    }
}

/// `status.json`: the service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    pub version: Option<String>,
    pub model: Option<String>,
    pub prompt_version: Option<String>,
    pub retention_days: Option<u32>,
    pub started_at: Option<i64>,
    /// The heartbeat: rewritten every two minutes while the service runs.
    pub alive_at: Option<i64>,
    pub last_check_at: Option<i64>,
}

/// One paired computer (`devices.json`: the public copy, never a token).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Device {
    pub name: String,
    pub os: Option<String>,
    pub client: Option<String>,
    pub app_version: Option<String>,
    pub paired_at: Option<i64>,
    pub last_seen_at: Option<i64>,
}

/// One of the folder's files, as far as it could be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part<T> {
    /// Not there (a fresh install has no status, devices or index yet).
    Missing,
    /// A schema this sentry doesn't know: said, and nothing of the file is shown.
    Newer(i64),
    /// There, and not what the format says.
    Damaged,
    Ok(T),
}

impl<T> Part<T> {
    pub fn ok(&self) -> Option<&T> {
        match self {
            Part::Ok(t) => Some(t),
            _ => None,
        }
    }

    fn newer(&self) -> Option<i64> {
        match self {
            Part::Newer(n) => Some(*n),
            _ => None,
        }
    }
}

/// The folder as one read found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suscheck {
    /// The server's clock when it was read (epoch seconds): what the heartbeat and every
    /// "ago" is measured against, never this machine's.
    pub now: i64,
    pub status: Part<Status>,
    pub devices: Part<Vec<Device>>,
    /// The latest checks, oldest first (the index's own order).
    pub checks: Vec<Check>,
    /// The index has lines of a schema this sentry doesn't know: none of it is shown.
    pub index_newer: Option<i64>,
    /// Index lines left out: too long, not JSON, or an id outside the grammar.
    pub skipped: u32,
    /// How many lines were asked for (`suscheck.recent`): with that many read, there may be
    /// older ones this doesn't count.
    pub recent: u32,
}

/// Why the folder couldn't be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Unreadable {
    /// The configured folder isn't there.
    NoFolder,
    /// It is there and this login may not read it: it isn't in the folder's group.
    NotInGroup,
}

impl Unreadable {
    /// Plainly, for the screen and the finding. `own`: the folder has a login of its own.
    pub fn said(self, own: bool) -> String {
        let who = if own {
            "the login suscheck.ssh names"
        } else {
            "this server's login"
        };
        match self {
            Unreadable::NoFolder => {
                "the incidents folder isn't there (suscheck.dir): SusCheck writes where it \
                 keeps them in /etc/suscheck/incidents.path"
                    .into()
            }
            Unreadable::NotInGroup => format!(
                "{who} is not in its group: the incidents folder can't be read. Add that \
                 login to the folder's group on the server; sentry doesn't look for another \
                 way in"
            ),
        }
    }
}

/// What one read came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    Unreadable(Unreadable),
    Folder(Box<Suscheck>),
}

impl Read {
    pub fn folder(&self) -> Option<&Suscheck> {
        match self {
            Read::Folder(s) => Some(s),
            Read::Unreadable(_) => None,
        }
    }

    pub fn counts(&self) -> Counts {
        match self {
            Read::Unreadable(u) => Counts {
                unreadable: Some(*u),
                ..Default::default()
            },
            Read::Folder(s) => s.counts(),
        }
    }
}

/// How many checks of a stretch of time ended how.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tally {
    pub total: u32,
    pub malicious: u32,
    pub suspicious: u32,
    pub safe: u32,
    /// A verdict this sentry doesn't know, or none.
    pub other: u32,
    pub errors: u32,
    /// Completed, with key evidence not visible or not confirmed.
    pub incomplete: u32,
    /// Completed, with SusCheck's fixed rules raising the model's verdict.
    pub floors: u32,
}

impl Tally {
    pub fn completed(&self) -> u32 {
        self.total - self.errors
    }

    fn add(&mut self, c: &Check) {
        self.total += 1;
        if c.error.is_some() {
            self.errors += 1;
            return;
        }
        match c.verdict() {
            Some(Verdict::Malicious) => self.malicious += 1,
            Some(Verdict::Suspicious) => self.suspicious += 1,
            Some(Verdict::Safe) => self.safe += 1,
            None => self.other += 1,
        }
        self.incomplete += u32::from(c.incomplete == Some(true));
        self.floors += u32::from(c.floors_changed == Some(true));
    }
}

/// **All that ever leaves for a stored report, a finding, a prompt or the command line:**
/// numbers, the schema, and the service's own version. No brand, domain, computer's name,
/// reason or id.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Counts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<Unreadable>,
    /// A schema one of the files has that this sentry doesn't know.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<i64>,
    /// SusCheck's version, as its status file says it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Seconds since the heartbeat, by the server's clock. None: no status file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat_age_s: Option<i64>,
    pub day: Tally,
    pub week: Tally,
    pub month: Tally,
    pub computers: u32,
    /// Index lines skipped as damaged.
    pub skipped: u32,
}

impl Counts {
    /// The service is stopped or stuck: its heartbeat is older than five minutes.
    pub fn down(&self) -> bool {
        self.heartbeat_age_s.is_some_and(|a| a > HEARTBEAT_S)
    }
}

impl Suscheck {
    /// The checks of the last `days` days by the server's clock.
    pub fn tally(&self, days: i64) -> Tally {
        let since = self.now - days * 86_400;
        let mut t = Tally::default();
        for c in self
            .checks
            .iter()
            .filter(|c| c.at.is_some_and(|a| a >= since))
        {
            t.add(c);
        }
        t
    }

    /// Seconds since the heartbeat.
    pub fn heartbeat_age(&self) -> Option<i64> {
        Some(self.now - self.status.ok()?.alive_at?)
    }

    /// A schema one of the files has that this sentry doesn't know.
    pub fn newer(&self) -> Option<i64> {
        self.index_newer
            .or(self.status.newer())
            .or(self.devices.newer())
    }

    /// Every read took as many lines as were asked for: older checks may not be counted.
    pub fn cut(&self) -> bool {
        self.checks.len() as u32 + self.skipped >= self.recent
    }

    /// The checks newer than `seen` (the newest id looked at; None: never) that said
    /// "don't trust this", and those that failed: (malicious, errors).
    pub fn unseen(&self, seen: Option<&str>) -> (u32, u32) {
        let new = self
            .checks
            .iter()
            .filter(|c| seen.is_none_or(|s| c.id.as_str() > s));
        let (mut bad, mut failed) = (0, 0);
        for c in new {
            if c.error.is_some() {
                failed += 1;
            } else if c.verdict() == Some(Verdict::Malicious) {
                bad += 1;
            }
        }
        (bad, failed)
    }

    /// The newest check's id.
    pub fn newest(&self) -> Option<Id> {
        self.checks.iter().map(|c| c.id).max()
    }

    pub fn counts(&self) -> Counts {
        Counts {
            unreadable: None,
            schema: self.newer(),
            version: self
                .status
                .ok()
                .and_then(|s| s.version.clone())
                // (Its own version, not a household's text; still only what a version is.)
                .filter(|v| v.len() <= 40 && v.chars().all(|c| c.is_ascii_graphic())),
            heartbeat_age_s: self.heartbeat_age(),
            day: self.tally(1),
            week: self.tally(7),
            month: self.tally(30),
            computers: self.devices.ok().map_or(0, |d| d.len() as u32),
            skipped: self.skipped,
        }
    }
}

/// The schema of a parsed file: `Ok` when it is the one known.
fn schema_of<T>(v: &Value) -> Result<(), Part<T>> {
    match v.get("schema").and_then(Value::as_i64) {
        Some(SCHEMA) => Ok(()),
        Some(n) => Err(Part::Newer(n)),
        None => Err(Part::Damaged),
    }
}

fn object<T>(text: &str) -> Result<Value, Part<T>> {
    if text.trim().is_empty() {
        return Err(Part::Missing);
    }
    match serde_json::from_str::<Value>(text) {
        Ok(v) if v.is_object() => Ok(v),
        _ => Err(Part::Damaged),
    }
}

pub fn parse_status(body: &str) -> Part<Status> {
    let v = match object(body) {
        Ok(v) => v,
        Err(p) => return p,
    };
    if let Err(p) = schema_of(&v) {
        return p;
    }
    Part::Ok(Status {
        version: text(&v["version"], 40),
        model: text(&v["model"], 120),
        prompt_version: text(&v["prompt_version"], 40),
        retention_days: v["retention_days"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok()),
        started_at: time(&v["started_at"]),
        alive_at: time(&v["alive_at"]),
        last_check_at: time(&v["last_check_at"]),
    })
}

pub fn parse_devices(body: &str) -> Part<Vec<Device>> {
    let v = match object(body) {
        Ok(v) => v,
        Err(p) => return p,
    };
    if let Err(p) = schema_of(&v) {
        return p;
    }
    let Some(list) = v["devices"].as_array() else {
        return Part::Damaged;
    };
    Part::Ok(
        list.iter()
            .take(256)
            .filter_map(|d| {
                Some(Device {
                    name: text(&d["name"], 40)?,
                    os: text(&d["os"], 40),
                    client: text(&d["client"], 20),
                    app_version: text(&d["app_version"], 20),
                    paired_at: time(&d["paired_at"]),
                    last_seen_at: time(&d["last_seen_at"]),
                })
            })
            .collect(),
    )
}

/// One index line. `Err(Some(n))`: a schema this sentry doesn't know; `Err(None)`: damaged
/// (too long, not a JSON object, no schema, an id outside the grammar).
pub fn parse_line(line: &str) -> Result<Check, Option<i64>> {
    if line.len() + 1 > LINE_MAX {
        return Err(None);
    }
    let v: Value = serde_json::from_str(line).map_err(|_| None)?;
    if !v.is_object() {
        return Err(None);
    }
    match v.get("schema").and_then(Value::as_i64) {
        Some(SCHEMA) => {}
        Some(n) => return Err(Some(n)),
        None => return Err(None),
    }
    let id = v["id"].as_str().and_then(Id::parse).ok_or(None)?;
    Ok(Check {
        id,
        at: id.time(),
        device: text(&v["device"], 40),
        client: text(&v["client"], 20),
        app_version: text(&v["app_version"], 20),
        kind: text(&v["kind"], 20),
        brand: text(&v["brand"], 60),
        domain: text(&v["domain"], 100),
        domain_check: text(&v["domain_check"], 30),
        verdict: text(&v["verdict"], 30),
        confidence: text(&v["confidence"], 20),
        incomplete: v["incomplete"].as_bool(),
        floors_changed: v["floors_changed_verdict"].as_bool(),
        duration_ms: v["duration_ms"].as_u64().unwrap_or(0).min(86_400_000),
        error: text(&v["error"], 120),
        // The last key, added later: a line without it is from when a picture was all a
        // check could be made from. There and not a string: nothing usable.
        input: match v.get("input") {
            None => Some("image".into()),
            Some(x) => text(x, 24),
        },
    })
}

/// The index's lines: the checks (oldest first, as written), a schema it has that this
/// sentry doesn't know (then no checks), and how many lines were skipped.
pub fn parse_index(body: &str) -> (Vec<Check>, Option<i64>, u32) {
    let (mut checks, mut newer, mut skipped) = (Vec::new(), None, 0);
    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        match parse_line(line) {
            Ok(c) => checks.push(c),
            Err(Some(n)) => newer = Some(n),
            Err(None) => skipped += 1,
        }
    }
    if newer.is_some() {
        checks.clear();
    }
    (checks, newer, skipped)
}

/// What the one exec printed, cut at its section lines (`@@<mark>:<name>`; `mark` is made
/// for the call, so no file's own text can pass for one).
pub fn parse(out: &str, mark: &str, recent: u32) -> Result<Read, String> {
    let head = format!("@@{mark}:");
    let mut parts: Vec<(&str, String)> = Vec::new();
    for line in out.lines() {
        if let Some(name) = line.strip_prefix(&head) {
            parts.push((name.trim(), String::new()));
        } else if let Some((_, body)) = parts.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    let part = |name: &str| {
        parts
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, b)| b.as_str())
    };
    if part("nofolder").is_some() {
        return Ok(Read::Unreadable(Unreadable::NoFolder));
    }
    if part("denied").is_some() {
        return Ok(Read::Unreadable(Unreadable::NotInGroup));
    }
    let now = part("now")
        .and_then(|t| t.trim().parse::<i64>().ok())
        .ok_or("the server's clock wasn't read")?;
    let (checks, index_newer, skipped) = parse_index(part("index").unwrap_or(""));
    Ok(Read::Folder(Box::new(Suscheck {
        now,
        status: parse_status(part("status").unwrap_or("")),
        devices: parse_devices(part("devices").unwrap_or("")),
        checks,
        index_newer,
        skipped,
        recent,
    })))
}

/// The one command: the server's clock, then the three files as they are. Tells "not
/// there" from "may not read it" itself, so neither is ever guessed from an error's words.
pub fn script(dir: &str, recent: u32, mark: &str) -> String {
    let d = sh_quote(dir.trim_end_matches('/'));
    // (A line is at most 1024 bytes; a file that isn't the format is cut there anyway.)
    let most = u64::from(recent) * LINE_MAX as u64;
    format!(
        "d={d}; m='@@{mark}:'\n\
         echo \"${{m}}now\"; date -u +%s\n\
         [ -d \"$d\" ] || {{ echo \"${{m}}nofolder\"; exit 0; }}\n\
         [ -r \"$d\" ] && [ -x \"$d\" ] || {{ echo \"${{m}}denied\"; exit 0; }}\n\
         for f in status.json devices.json index.jsonl; do\n\
         [ ! -e \"$d/$f\" ] || [ -r \"$d/$f\" ] || {{ echo \"${{m}}denied\"; exit 0; }}\n\
         done\n\
         echo \"${{m}}status\"; [ ! -f \"$d/status.json\" ] || head -c 65536 \"$d/status.json\"; echo\n\
         echo \"${{m}}devices\"; [ ! -f \"$d/devices.json\" ] || head -c 262144 \"$d/devices.json\"; echo\n\
         echo \"${{m}}index\"; [ ! -f \"$d/index.jsonl\" ] || tail -n {recent} \"$d/index.jsonl\" | head -c {most}; echo\n\
         true"
    )
}

/// A mark for one call's section lines: nothing a file could have been written to hold.
fn fresh_mark() -> String {
    use std::hash::{BuildHasher, Hasher};
    let h = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    format!("{h:016x}")
}

/// Who reads the folder, where it is and how much of the index: None when the server has
/// no `suscheck:` block. The login is `suscheck.ssh` when that is set (one in the folder's
/// group, which the server's ordinary login then isn't), else the server's own; either
/// way a login with no sudo list at all: nothing here ever runs as root.
pub fn reader(r: &Remote) -> Option<(sentry_app::remote::Remote, String, u32)> {
    let s = &r.cfg.suscheck;
    let dir = s.on()?.trim_end_matches('/').to_string();
    let host = s.ssh.as_deref().unwrap_or(r.host);
    Some((
        sentry_app::remote::Remote::new(
            &r.name,
            host,
            &r.name,
            sentry_app::remote::Privilege::sudo(&[]),
        ),
        dir,
        s.recent.clamp(1, crate::config::SUSCHECK_RECENT_MAX),
    ))
}

/// The folder has a login of its own.
pub fn own_login(r: &Remote) -> bool {
    r.cfg.suscheck.ssh.is_some()
}

/// The reader's login failing isn't the server being unreachable: said as what it is.
fn through(r: &Remote, e: SrvError) -> SrvError {
    match e {
        SrvError::Unreachable(m) if own_login(r) => SrvError::Failed(format!(
            "the login suscheck.ssh names couldn't connect: {m}"
        )),
        e => e,
    }
}

/// None when the server has no `suscheck:` block. One exec, no sudo.
pub fn collect(r: &Remote) -> Result<Option<Read>, SrvError> {
    let Some((reader, dir, recent)) = reader(r) else {
        return Ok(None);
    };
    let mark = fresh_mark();
    let out = reader
        .output(&reader.sh(&script(&dir, recent, &mark)))
        .map_err(|e| through(r, e))?;
    parse(&out, &mark, recent)
        .map(Some)
        .map_err(SrvError::Parse)
}

/// What a fetch of one incident's file came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched<T> {
    /// Its folder is gone: SusCheck pruned it (30 days, or by hand) since the index was
    /// read. Not an error.
    Expired,
    Ok(T),
}

/// A file of one incident, on the server. The id is checked against its grammar again
/// here, where the path is made: nothing else can become part of a path. Two names and
/// no other: **never `message.txt`**, the quarantined text of a household member's mail,
/// which sentry has no way to read.
pub fn path_of(dir: &str, id: &Id, file: &str) -> Option<String> {
    let id = Id::parse(id.as_str())?;
    let file = ["incident.json", "screenshot.png"]
        .into_iter()
        .find(|f| *f == file)?;
    Some(format!("{}/{id}/{file}", dir.trim_end_matches('/')))
}

fn gone(stderr: &str) -> bool {
    stderr.contains("No such file or directory")
}

fn denied(stderr: &str) -> bool {
    stderr.contains("Permission denied")
}

fn refused(r: &Remote) -> SrvError {
    SrvError::Failed(Unreadable::NotInGroup.said(own_login(r)))
}

/// One incident's record: `head -c` of it (its size has no cap of its own), parsed.
pub fn incident(r: &Remote, id: Id) -> Result<Fetched<Box<Incident>>, SrvError> {
    let Some((reader, dir, _)) = reader(r) else {
        return Err(SrvError::Failed(
            "no suscheck: block for this server".into(),
        ));
    };
    let path = path_of(&dir, &id, "incident.json")
        .ok_or_else(|| SrvError::Failed("not an incident id".into()))?;
    let cmd = reader
        .cmd("head")
        .args(["-c", &INCIDENT_MAX.to_string(), "--", &path]);
    let o = cmd.run().map_err(|e| through(r, e.into()))?;
    if o.code != 0 {
        return match () {
            _ if gone(&o.stderr) => Ok(Fetched::Expired),
            _ if denied(&o.stderr) => Err(refused(r)),
            _ => Err(SrvError::Failed(
                "the incident's record couldn't be read".into(),
            )),
        };
    }
    if o.stdout.len() >= INCIDENT_MAX {
        return Err(SrvError::Parse(format!(
            "the incident's record is over {} KiB: not shown",
            INCIDENT_MAX / 1024
        )));
    }
    parse_incident(&o.stdout, id)
        .map(|i| Fetched::Ok(Box::new(i)))
        .map_err(SrvError::Parse)
}

/// Where this machine keeps the pictures it fetched, for as long as the window is open:
/// `<cache>/suscheck/<server>/`, private to the user.
pub fn cache_dir(server: &str) -> PathBuf {
    sentry_core::paths::cache_dir()
        .join("suscheck")
        .join(server)
}

/// That directory, made, and private from its parent down (`<cache>/suscheck` is 0700 too).
pub fn private_cache(server: &str) -> Result<PathBuf, SrvError> {
    let dir = cache_dir(server);
    let io = |e: std::io::Error| SrvError::Failed(format!("the picture's cache: {e}"));
    std::fs::create_dir_all(&dir).map_err(io)?;
    for d in [dir.parent(), Some(dir.as_path())].into_iter().flatten() {
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).map_err(io)?;
    }
    Ok(dir)
}

/// Every picture fetched for this server goes: at the window's start (whatever a crash
/// left) and when it closes.
pub fn empty_cache(server: &str) {
    let _ = std::fs::remove_dir_all(cache_dir(server));
}

/// Takes a picture's bytes as they arrive: no more than [`PICTURE_MAX`], and only what
/// starts as a PNG. Failing ends the command that feeds it.
struct PngSink {
    file: std::fs::File,
    total: u64,
    head: Vec<u8>,
}

impl Write for PngSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.total + buf.len() as u64 > PICTURE_MAX {
            return Err(std::io::Error::other("the picture is over 16 MB"));
        }
        if self.head.len() < PNG.len() {
            let want = PNG.len() - self.head.len();
            self.head.extend_from_slice(&buf[..want.min(buf.len())]);
            if self.head[..] != PNG[..self.head.len()] {
                return Err(std::io::Error::other("it isn't a PNG picture"));
            }
        }
        self.file.write_all(buf)?;
        self.total += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// One incident's picture, fetched as raw bytes into `into` (made private: 0700, the file
/// 0600) and checked as it arrives. Whatever goes wrong, no file is left. The picture is a
/// household member's mail or page: it stays in that directory until the window closes.
pub fn picture(r: &Remote, id: Id, into: &Path) -> Result<Fetched<PathBuf>, SrvError> {
    let Some((reader, dir, _)) = reader(r) else {
        return Err(SrvError::Failed(
            "no suscheck: block for this server".into(),
        ));
    };
    let path = path_of(&dir, &id, "screenshot.png")
        .ok_or_else(|| SrvError::Failed("not an incident id".into()))?;
    let io = |e: std::io::Error| SrvError::Failed(format!("the picture's cache: {e}"));
    std::fs::create_dir_all(into).map_err(io)?;
    std::fs::set_permissions(into, std::fs::Permissions::from_mode(0o700)).map_err(io)?;
    let dest = into.join(format!("{id}.png"));
    let _ = std::fs::remove_file(&dest);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&dest)
        .map_err(io)?;
    let mut sink = PngSink {
        file,
        total: 0,
        head: Vec::new(),
    };
    let cmd = reader
        .cmd("cat")
        .args(["--", &path])
        .timeout(Some(std::time::Duration::from_secs(60)));
    let res = cmd.bytes_to(&mut sink);
    let whole = sink.head.len() == PNG.len();
    drop(sink);
    let out = match res {
        Ok(_) if whole => Ok(Fetched::Ok(dest.clone())),
        Ok(_) => Err(SrvError::Failed("it isn't a PNG picture".into())),
        Err(ExecError::Failed { stderr, .. }) if gone(&stderr) => Ok(Fetched::Expired),
        Err(ExecError::Failed { stderr, .. }) if denied(&stderr) => Err(refused(r)),
        Err(ExecError::Failed { .. }) => {
            Err(SrvError::Failed("the picture couldn't be read".into()))
        }
        Err(ExecError::Io(e)) => Err(SrvError::Failed(format!("not kept: {e}"))),
        Err(e) => Err(through(r, e.into())),
    };
    if !matches!(out, Ok(Fetched::Ok(_))) {
        let _ = std::fs::remove_file(&dest);
    }
    out
}

/// What the model copied from the picture or noted from the message's text: its reading
/// of attacker content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    pub kind: Option<String>,
    pub claimed_brand: Option<String>,
    pub sender_name: Option<String>,
    pub sender_address: Option<String>,
    pub address_bar_domain: Option<String>,
    pub link_texts: Vec<String>,
    pub phone_numbers: Vec<String>,
    pub asks_for: Vec<String>,
    pub urgency: Option<bool>,
    pub talks_to_ai: Option<bool>,
}

/// Both readings of the domain, and how it compared with the brand's real one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Domain {
    pub first_reading: Option<String>,
    pub second_reading: Option<String>,
    /// What a plain text recogniser (not the model) read in the same place, when it found
    /// an address close to the model's.
    pub ocr_reading: Option<String>,
    /// Whether the text recogniser was run. None: a record from before there was one.
    pub ocr_available: Option<bool>,
    /// Where the address the verdict rests on came from: `email_header`, `window`,
    /// `screenshot`, or a value this sentry doesn't know. None: an older record (a picture).
    pub source: Option<String>,
    /// The full host taken as exact text (an email's From header, the window's address).
    /// Text: never resolved, looked up or opened.
    pub exact: Option<String>,
    pub result: Option<String>,
    pub shown: Option<String>,
    pub real: Option<String>,
    pub why: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hit {
    pub title: Option<String>,
    pub snippet: Option<String>,
    pub domain: Option<String>,
    pub engines: u64,
}

/// A search SusCheck ran (its own template, never the model's words) and what came back
/// (titles and snippets from the open web, which may be planted).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    pub kind: String,
    pub query: String,
    pub hits: Vec<Hit>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Search {
    pub ok: Option<bool>,
    pub queries: Vec<Query>,
}

/// The model's own answer, before SusCheck's rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Judgement {
    pub red_flags: Vec<String>,
    pub looks_normal: Vec<String>,
    pub incomplete: Option<bool>,
    pub confidence: Option<String>,
    pub verdict: Option<String>,
    pub advice: Vec<String>,
}

/// What the person was shown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Final {
    pub verdict: Option<String>,
    pub confidence: Option<String>,
    pub incomplete: Option<bool>,
    pub reasons: Vec<String>,
    pub advice: Vec<String>,
    pub floors: Vec<String>,
    pub floors_changed: Option<bool>,
}

/// One attachment as the message declared it. Nothing else of it exists anywhere: SusCheck
/// never decodes or stores one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attachment {
    /// The declared file name: attacker text.
    pub name: Option<String>,
    /// The declared media type.
    pub kind: Option<String>,
    /// Bytes as encoded inside the message.
    pub size: Option<u64>,
}

/// What SusCheck's code read from an email file's headers. The name and the subject are
/// attacker text; the addresses are real and not defanged: text, never resolved or opened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Email {
    pub from_name: Option<String>,
    pub from_address: Option<String>,
    pub reply_to: Option<String>,
    pub return_path: Option<String>,
    pub subject: Option<String>,
    pub date: Option<String>,
    /// `spf`, `dkim`, `dmarc` as the message's topmost header reports them (None: not
    /// stated).
    pub auth: [Option<String>; 3],
    /// At most [`ATTACHMENTS_MAX`].
    pub attachments: Vec<Attachment>,
    /// How many the message had (never less than those listed).
    pub attachments_total: u64,
    pub links_total: Option<u64>,
    pub aimed_at_ai: Option<bool>,
}

/// One link of the email or of the page's list, as SusCheck's code analysed it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Link {
    /// Its visible text: attacker text, defanged by SusCheck.
    pub text: Option<String>,
    pub scheme: Option<String>,
    /// Where it leads: a registrable domain or an IP address, stored defanged
    /// (`examp1epay[.]test`). Shown as it is: never resolved, opened or copied anywhere.
    pub target: Option<String>,
    pub flags: Vec<String>,
}

/// What the desktop app reported about the window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    pub source: Option<String>,
    /// The window's address as a registrable domain or IP, stored defanged.
    pub url_domain: Option<String>,
    /// The window's title: attacker text.
    pub title: Option<String>,
    pub links_total: Option<u64>,
}

/// The most attachments and links of one record that are kept (the format's own limits).
pub const ATTACHMENTS_MAX: usize = 20;
pub const LINKS_MAX: usize = 50;

/// One check in full: enough to judge how SusCheck behaved. Every part may be missing (a
/// check that failed stopped somewhere).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incident {
    pub id: Id,
    pub device: Option<String>,
    pub client: Option<String>,
    pub app_version: Option<String>,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub model: Option<String>,
    pub prompt_version: Option<String>,
    /// Each stage the record names, in the order they run: its milliseconds (0: it ran,
    /// in under one), or None for a stage that did not run. A record in the old shape wrote
    /// 0 for one that did not run: read as None there.
    pub stages: Vec<(&'static str, Option<u64>)>,
    pub facts: Option<Facts>,
    pub domain: Option<Domain>,
    pub search: Option<Search>,
    pub judgement: Option<Judgement>,
    pub last: Option<Final>,
    /// Which inputs were sent (`image`, `email`, `page`), on a check that failed too. A
    /// record in the old shape has no such key and is `image`: a picture was all there
    /// was. Empty: the key is there and isn't a list of words.
    pub input: Vec<String>,
    /// Read from an email file's headers by SusCheck's code. None: no email file was sent.
    pub email: Option<Email>,
    /// The links of the email (first) and of the page's list, exact repeats merged. None:
    /// there was no link list.
    pub links: Option<Vec<Link>>,
    /// How many links there were in all, before exact repeats were merged and before the
    /// list was cut. None: no list, or a record from before the count was written.
    pub links_total: Option<u64>,
    pub page: Option<Page>,
    /// Whether a picture was kept.
    pub screenshot: bool,
    /// Whether the folder holds `message.txt`, the quarantined text of the email. Only
    /// that it is there: **sentry never reads it** (see [`path_of`]).
    pub message: bool,
}

impl Incident {
    /// How many links there were beyond the ones listed: the record's own count less the
    /// list (exact repeats of a listed link are among them: the count is from before they
    /// were merged). A record from before that count was written: the email's and the
    /// page's counts together, less the list.
    pub fn links_more(&self) -> u64 {
        let listed = self.links.as_ref().map_or(0, Vec::len) as u64;
        let total = self.links_total.unwrap_or_else(|| {
            let email = self.email.as_ref().and_then(|e| e.links_total);
            let page = self.page.as_ref().and_then(|p| p.links_total);
            email.unwrap_or(0).saturating_add(page.unwrap_or(0))
        });
        total.saturating_sub(listed)
    }

    /// Whether `what` was among the inputs sent. None: the record doesn't say.
    fn sent(&self, what: &str) -> Option<bool> {
        (!self.input.is_empty()).then(|| self.input.iter().any(|i| i == what))
    }

    /// A picture was among what was sent. None: the record doesn't say.
    pub fn sent_picture(&self) -> Option<bool> {
        self.sent("image")
    }

    pub fn sent_email(&self) -> bool {
        self.sent("email") == Some(true) || self.email.is_some()
    }

    /// The window's own address was among what was sent.
    pub fn sent_page(&self) -> bool {
        self.sent("page") == Some(true) || self.page.is_some()
    }
}

/// `<id>/incident.json`, read defensively: every string cleaned and cut, every list
/// capped, unknown fields ignored, a missing part left out. The model's raw replies
/// (`model_raw`) aren't kept at all. `id` is the one asked for: a record that names
/// another isn't it.
pub fn parse_incident(record: &str, id: Id) -> Result<Incident, String> {
    let v: Value =
        serde_json::from_str(record).map_err(|_| "the incident's record isn't JSON".to_string())?;
    if !v.is_object() {
        return Err("the incident's record isn't what the format says".into());
    }
    match v.get("schema").and_then(Value::as_i64) {
        Some(SCHEMA) => {}
        Some(n) => {
            return Err(format!(
                "the incident's record has schema {n}, which this sentry doesn't know: not shown"
            ));
        }
        None => return Err("the incident's record has no schema".into()),
    }
    if v["id"].as_str().and_then(Id::parse) != Some(id) {
        return Err("the record is another incident's".into());
    }
    let t = |x: &Value| text_of(x);
    let obj = |x: &Value| x.is_object();
    // The old shape (the first release's): no `input` key, nor any field added since.
    let old = v.get("input").is_none();
    let facts = obj(&v["facts"]).then(|| {
        let f = &v["facts"];
        Facts {
            kind: t(&f["kind"]),
            claimed_brand: t(&f["claimed_brand"]),
            sender_name: t(&f["sender_name"]),
            sender_address: t(&f["sender_address"]),
            address_bar_domain: t(&f["address_bar_domain"]),
            link_texts: texts(&f["link_texts"], 200, 5),
            phone_numbers: texts(&f["phone_numbers"], 60, 5),
            asks_for: texts(&f["asks_for"], 30, 12),
            urgency: f["urgency"].as_bool(),
            talks_to_ai: f["talks_to_ai"].as_bool(),
        }
    });
    let domain = obj(&v["domain"]).then(|| {
        let d = &v["domain"];
        Domain {
            first_reading: t(&d["first_reading"]),
            second_reading: t(&d["second_reading"]),
            ocr_reading: t(&d["ocr_reading"]),
            ocr_available: d["ocr_available"].as_bool(),
            source: text(&d["source"], 30),
            exact: text(&d["exact"], 260),
            result: t(&d["check"]["result"]),
            shown: t(&d["check"]["shown"]),
            real: t(&d["check"]["real"]),
            why: t(&d["check"]["why"]),
        }
    });
    let search = obj(&v["search"]).then(|| {
        let s = &v["search"];
        let queries = s["queries"]
            .as_array()
            .into_iter()
            .flatten()
            .take(3)
            .filter_map(|q| {
                let kind = t(&q[0])?;
                let hits = s["results"][kind.as_str()]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .take(5)
                    .map(|h| Hit {
                        title: text(&h["title"], 120),
                        snippet: text(&h["snippet"], 200),
                        domain: text(&h["domain"], 100),
                        engines: h["engines"].as_u64().unwrap_or(0),
                    })
                    .collect();
                Some(Query {
                    query: t(&q[1]).unwrap_or_default(),
                    kind,
                    hits,
                })
            })
            .collect();
        Search {
            ok: s["ok"].as_bool(),
            queries,
        }
    });
    let judgement = obj(&v["judgement"]).then(|| {
        let j = &v["judgement"];
        Judgement {
            red_flags: texts(&j["red_flags"], 200, 8),
            looks_normal: texts(&j["looks_normal"], 200, 5),
            incomplete: j["incomplete"].as_bool(),
            confidence: text(&j["confidence"], 20),
            verdict: text(&j["verdict"], 30),
            advice: texts(&j["advice"], 40, 8),
        }
    });
    let last = obj(&v["final"]).then(|| {
        let f = &v["final"];
        Final {
            verdict: text(&f["verdict"], 30),
            confidence: text(&f["confidence"], 20),
            incomplete: f["incomplete"].as_bool(),
            reasons: texts(&f["reasons"], 200, 8),
            advice: texts(&f["advice"], 40, 8),
            floors: texts(&f["floors"], 40, 12),
            floors_changed: f["floors_changed_verdict"].as_bool(),
        }
    });
    let count = |x: &Value| x.as_u64().map(|n| n.min(1_000_000));
    let email = obj(&v["email"]).then(|| {
        let e = &v["email"];
        let attachments: Vec<Attachment> = e["attachments"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|a| a.is_object())
            .take(ATTACHMENTS_MAX)
            .map(|a| Attachment {
                name: text(&a["name"], 130),
                kind: text(&a["type"], 90),
                size: a["size"].as_u64(),
            })
            .collect();
        Email {
            from_name: text(&e["from_name"], 210),
            from_address: text(&e["from_address"], 260),
            reply_to: text(&e["reply_to"], 260),
            return_path: text(&e["return_path"], 260),
            subject: text(&e["subject"], 310),
            date: text(&e["date"], 64),
            auth: ["spf", "dkim", "dmarc"].map(|k| text(&e["auth"][k], 20)),
            attachments_total: count(&e["attachments_total"])
                .unwrap_or(0)
                .max(attachments.len() as u64),
            attachments,
            links_total: count(&e["links_total"]),
            aimed_at_ai: e["aimed_at_ai"].as_bool(),
        }
    });
    let links = v["links"].as_array().map(|list| {
        list.iter()
            .filter(|l| l.is_object())
            .take(LINKS_MAX)
            .map(|l| Link {
                // (The format's caps are on the plain value; what is stored is that
                // value defanged, up to twice as long: 400 and 200.)
                text: text(&l["text"], 410),
                scheme: text(&l["scheme"], 20),
                target: text(&l["target_domain"], 210),
                flags: texts(&l["flags"], 30, 12),
            })
            .collect()
    });
    let page = obj(&v["page"]).then(|| {
        let p = &v["page"];
        Page {
            source: text(&p["source"], 24),
            url_domain: text(&p["url_domain"], 210),
            title: text(&p["title"], 210),
            links_total: count(&p["links_total"]),
        }
    });
    Ok(Incident {
        id,
        device: text(&v["device"], 40),
        client: text(&v["client"], 20),
        app_version: text(&v["app_version"], 20),
        duration_ms: v["duration_ms"].as_u64().unwrap_or(0).min(86_400_000),
        error: text(&v["error"], 120),
        model: text(&v["model"], 120),
        prompt_version: text(&v["prompt_version"], 40),
        stages: ["extract", "reread", "ocr", "search", "judge"]
            .into_iter()
            .filter_map(|s| match v["stages_ms"].get(s)? {
                Value::Null => Some((s, None)),
                // (The old shape's 0 is "did not run"; today's is "under a millisecond".)
                ms => Some((s, Some(ms.as_u64()?).filter(|ms| *ms > 0 || !old))),
            })
            .collect(),
        facts,
        domain,
        search,
        judgement,
        last,
        input: match v.get("input") {
            None => vec!["image".into()],
            Some(x) => texts(x, 16, 6),
        },
        email,
        links_total: links.as_ref().and_then(|_| count(&v["links_total"])),
        links,
        page,
        screenshot: v["screenshot"].as_bool().unwrap_or(false),
        message: v["message"].as_bool().unwrap_or(false),
    })
}

/// A string of an incident's record, at the longest the format gives any of them.
fn text_of(v: &Value) -> Option<String> {
    text(v, 320)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::fixture;
    use super::*;

    pub(crate) const MARK: &str = "0123456789abcdef";

    /// What the one exec prints for the published samples, read at `now`.
    pub(crate) fn sample_out(now: &str) -> String {
        let now: jiff::Timestamp = now.parse().unwrap();
        format!(
            "@@{MARK}:now\n{}\n@@{MARK}:status\n{}\n@@{MARK}:devices\n{}\n@@{MARK}:index\n{}\n",
            now.as_second(),
            fixture("suscheck/status.json"),
            fixture("suscheck/devices.json"),
            fixture("suscheck/index.jsonl")
        )
    }

    /// The published samples, read at 2026-11-05 12:02 UTC by the server's clock.
    pub(crate) fn sample() -> Suscheck {
        match parse(&sample_out("2026-11-05T12:02:00Z"), MARK, 200).unwrap() {
            Read::Folder(s) => *s,
            r => panic!("{r:?}"),
        }
    }

    pub(crate) fn sample_incident(id: &str) -> Incident {
        parse_incident(
            &fixture(&format!("suscheck/{id}/incident.json")),
            Id::parse(id).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn an_id_is_the_grammar_and_nothing_else() {
        let good = "20261101T091500Z-a1b2";
        assert_eq!(Id::parse(good).unwrap().as_str(), good);
        assert_eq!(
            Id::parse(good).unwrap().time(),
            Some(
                "2026-11-01T09:15:00Z"
                    .parse::<jiff::Timestamp>()
                    .unwrap()
                    .as_second()
            )
        );
        for bad in [
            "",
            "20261101T091500Z-a1b",
            "20261101T091500Z-a1b2c",
            "20261101T091500Z-A1B2",
            "20261101T091500Z-a1b2\n",
            " 20261101T091500Z-a1b2",
            "20261101t091500Z-a1b2",
            "20261101T091500z-a1b2",
            "20261101T091500Z_a1b2",
            "2026110١T091500Z-a1b2",
            "２0261101T091500Z-a1b2",
            "20261101T091500Z-a1b/",
            "20261101T091500Z-..b2",
            "../../../../etc/passwd",
            "20261101T091500Z-a1\0b",
            "20261101T09150０Z-a1b",
        ] {
            assert_eq!(Id::parse(bad), None, "{bad:?}");
        }
        // Digits that are no date are still only digits: a path made of them is harmless,
        // and its time is unknown.
        let odd = Id::parse("99999999T999999Z-zzzz").unwrap();
        assert_eq!(odd.time(), None);
        // A path is made only from an id and one of the two file names.
        let id = Id::parse(good).unwrap();
        assert_eq!(
            path_of("/srv/x/", &id, "incident.json").unwrap(),
            "/srv/x/20261101T091500Z-a1b2/incident.json"
        );
        assert_eq!(path_of("/srv/x", &id, "../status.json"), None);
        assert_eq!(path_of("/srv/x", &id, "index.jsonl"), None);
        // The quarantined text of an email is a name of the folder's, and never one a
        // path is made to: sentry has no way to read it.
        assert_eq!(path_of("/srv/x", &id, "message.txt"), None);
        assert!(path_of("/srv/x", &id, "screenshot.png").is_some());
    }

    #[test]
    fn every_string_is_cleaned_of_what_a_terminal_would_act_on() {
        for (hostile, want) in [
            ("plain text", "plain text"),
            // Colours, cursor moves, the clear-screen: gone whole, not just their ESC.
            ("a\x1b[31mred\x1b[0m b", "ared b"),
            ("a\x1b[2J\x1b[Hb", "ab"),
            ("a\x1b[?1049hb", "ab"),
            // A window title, a hyperlink: gone with what they carry.
            ("a\x1b]0;owned\x07b", "ab"),
            (
                "a\x1b]8;;http://example.test\x1b\\link\x1b]8;;\x1b\\b",
                "alinkb",
            ),
            // The 8-bit forms, and a string that never ends.
            ("a\u{9b}31mb", "ab"),
            ("a\x1bPq#0;2;0;0;0\x1b\\b", "ab"),
            ("a\x1b]never ends", "a"),
            ("a\x1b", "a"),
            // Control characters; line breaks and tabs are a space.
            ("a\0b\x07c\x08d\x7fe", "abcde"),
            ("a\nb\r\nc\td", "a b  c d"),
            ("a\u{2028}b\u{2029}c\u{85}d", "a b c d"),
            // Direction overrides and isolates (a name that reads backwards), zero-width
            // characters, the byte-order mark, a soft hyphen, tags, private use.
            ("exe.\u{202e}gnp.elif", "exe.gnp.elif"),
            ("a\u{2066}b\u{2069}c\u{200f}d\u{061c}e", "abcde"),
            ("pay\u{200b}pal\u{200d}\u{feff}\u{00ad}", "paypal"),
            ("a\u{e0001}\u{e0041}b\u{e000}c\u{f0000}d\u{fffe}e", "abcde"),
            // What is only unusual stays: other scripts, accents, an emoji.
            ("Ünïcödé — ок 好 👍", "Ünïcödé — ок 好 👍"),
        ] {
            assert_eq!(clean(hostile), want, "{hostile:?}");
        }
        // Whatever goes in, nothing a terminal acts on comes out.
        let all: String = (0u32..0x3000).filter_map(char::from_u32).collect();
        assert!(!clean(&all).chars().any(|c| c.is_control() || invisible(c)));
    }

    #[test]
    fn the_samples_parse_to_what_the_format_says() {
        let s = sample();
        assert_eq!(s.checks.len(), 8);
        assert_eq!((s.skipped, s.index_newer, s.newer()), (0, None, None));
        // The oldest is a line in the old shape (it ends at `error`): a picture's.
        let old = &s.checks[0];
        assert_eq!(old.id.as_str(), "20261030T184512Z-b0a1");
        assert_eq!(
            (old.verdict(), old.error.as_deref()),
            (Some(Verdict::Safe), None)
        );
        assert_eq!(old.input.as_deref(), Some("image"));
        let first = &s.checks[1];
        assert_eq!(first.id.as_str(), "20261101T091500Z-a1b2");
        assert_eq!(first.device.as_deref(), Some("Kitchen iMac"));
        assert_eq!(first.domain.as_deref(), Some("examp1e-pay.test"));
        assert_eq!(first.verdict(), Some(Verdict::Malicious));
        assert_eq!(first.outcome(), "don't trust this");
        assert_eq!(first.floors_changed, Some(true));
        // An empty `app_version` is none; a failed check has an error and no verdict.
        assert_eq!(s.checks[2].app_version, None);
        let failed = &s.checks[5];
        assert_eq!(
            (failed.verdict.as_deref(), failed.error.as_deref()),
            (None, Some("model"))
        );
        assert_eq!(failed.outcome(), "failed (model)");
        // Never "safe".
        assert_eq!(s.checks[3].outcome(), "no obvious warning signs");
        // What each was made from: the index's word, and plain words for it. The check
        // that failed says what it was given too.
        let sent: Vec<Option<String>> = s.checks.iter().map(Check::sent).collect();
        let said = |w: &str| Some(w.to_string());
        assert_eq!(
            sent,
            [
                said("picture"),
                said("picture"),
                said("picture"),
                said("picture"),
                said("picture"),
                said("picture"),
                said("email"),
                said("picture + page address"),
            ]
        );
        assert_eq!(s.checks[6].input.as_deref(), Some("email"));
        assert_eq!(s.checks[6].pictureless(), Some("the email itself"));
        assert_eq!(s.checks[7].pictureless(), None);
        assert_eq!(s.checks[5].pictureless(), None);
        let st = s.status.ok().unwrap();
        assert_eq!(st.version.as_deref(), Some("0.1.0"));
        assert_eq!(st.retention_days, Some(30));
        assert_eq!(s.heartbeat_age(), Some(120));
        let d = s.devices.ok().unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(
            (d[1].name.as_str(), d[1].app_version.as_deref()),
            ("Study laptop", None)
        );
        // Counts: by the server's clock, the last day has the failed check and the two
        // of that morning.
        let c = s.counts();
        assert_eq!(
            c.week,
            Tally {
                total: 8,
                malicious: 3,
                suspicious: 2,
                safe: 2,
                other: 0,
                errors: 1,
                incomplete: 1,
                floors: 3,
            }
        );
        assert_eq!((c.day.total, c.day.errors, c.computers), (3, 1, 2));
        assert!(!c.down());
        // Since the first lookalike was looked at: two more said "don't trust this", one
        // failed.
        assert_eq!(s.unseen(None), (3, 1));
        assert_eq!(s.unseen(Some("20261030T184512Z-b0a1")), (3, 1));
        assert_eq!(s.unseen(Some("20261101T091500Z-a1b2")), (2, 1));
        assert_eq!(s.unseen(Some("20261104T194103Z-j9k0")), (2, 0));
        assert_eq!(s.unseen(Some("20261105T103045Z-p6q8")), (0, 0));
    }

    #[test]
    fn what_isnt_the_format_is_skipped_counted_or_said() {
        let good = fixture("suscheck/index.jsonl");
        let line = good.lines().nth(1).unwrap();
        let with = |from: &str, to: &str| line.replacen(from, to, 1);
        // A bad id, an over-long line, not JSON, not an object, no schema: skipped, counted.
        let long = with("Example Pay", &"x".repeat(1024));
        let text = [
            line,
            &with("20261101T091500Z-a1b2", "../../../etc/passwd"),
            &with("20261101T091500Z-a1b2", "20261101T091500Z-A1B2"),
            &with("20261101T091500Z-a1b2", "20261101T091500Z-a1b2 "),
            &long,
            "{not json",
            "[1,2]",
            &with("\"schema\":1,", ""),
            &with("\"schema\":1", "\"schema\":\"1\""),
        ]
        .join("\n");
        let (checks, newer, skipped) = parse_index(&text);
        assert_eq!((checks.len(), newer, skipped), (1, None, 8));
        // A line exactly at the limit is taken; one byte over is not.
        let pad = |n: usize| {
            with(
                "Example Pay",
                &"x".repeat(n - line.len() + "Example Pay".len()),
            )
        };
        assert_eq!(pad(LINE_MAX - 1).len() + 1, LINE_MAX);
        assert!(parse_line(&pad(LINE_MAX - 1)).is_ok());
        assert_eq!(parse_line(&pad(LINE_MAX)), Err(None));
        // A newer schema: said, and nothing else of the file is shown.
        let newer = [line, &with("\"schema\":1", "\"schema\":2")].join("\n");
        assert_eq!(parse_index(&newer), (Vec::new(), Some(2), 0));
        assert_eq!(
            parse_status("{\"schema\": 3, \"version\": \"9\"}"),
            Part::Newer(3)
        );
        assert_eq!(
            parse_devices("{\"schema\": 2, \"devices\": []}"),
            Part::Newer(2)
        );
        assert_eq!(parse_status(""), Part::Missing);
        assert_eq!(parse_status("{\"version\": \"1\"}"), Part::Damaged);
        assert_eq!(parse_devices("{\"schema\": 1}"), Part::Damaged);
        assert_eq!(parse_status("nope"), Part::Damaged);
        // Unknown fields are ignored; an unknown enum value is kept as text and is not
        // any known verdict.
        let odd = with("\"likely_malicious\"", "\"quarantined\"")
            .replacen(
                "\"schema\":1,",
                "\"schema\":1,\"added_later\":{\"x\":[1]},",
                1,
            )
            .replacen("\"lookalike\"", "\"homoglyph\"", 1);
        let c = parse_line(&odd).unwrap();
        assert_eq!(
            (c.verdict.as_deref(), c.verdict()),
            (Some("quarantined"), None)
        );
        assert_eq!(c.outcome(), "quarantined");
        assert_eq!(c.domain_check.as_deref(), Some("homoglyph"));
        let mut t = Tally::default();
        t.add(&c);
        assert_eq!((t.other, t.malicious), (1, 0));
        // Hostile strings in a line that is otherwise the format: cleaned as they're kept.
        let hostile = with("Example Pay", "\\u001b[2JExam\\u202eple\\u0007 Pay\\u200b").replacen(
            "Kitchen iMac",
            "Kit\\u001b]0;x\\u0007chen\\nMac",
            1,
        );
        let c = parse_line(&hostile).unwrap();
        assert_eq!(c.brand.as_deref(), Some("Example Pay"));
        assert_eq!(c.device.as_deref(), Some("Kitchen Mac"));
        // A value of the wrong type is none, never a panic.
        let wrong = with("\"brand\":\"Example Pay\"", "\"brand\":{\"a\":1}")
            .replacen("\"duration_ms\":21480", "\"duration_ms\":\"long\"", 1)
            .replacen("\"incomplete\":false", "\"incomplete\":\"no\"", 1);
        let c = parse_line(&wrong).unwrap();
        assert_eq!((c.brand, c.duration_ms, c.incomplete), (None, 0, None));
    }

    #[test]
    fn the_one_exec_is_cut_at_its_own_marks_and_says_why_it_couldnt_read() {
        let out = |body: &str| format!("@@{MARK}:now\n1793880000\n{body}");
        assert_eq!(
            parse(&out(&format!("@@{MARK}:nofolder\n")), MARK, 200),
            Ok(Read::Unreadable(Unreadable::NoFolder))
        );
        assert_eq!(
            parse(&out(&format!("@@{MARK}:denied\n")), MARK, 200),
            Ok(Read::Unreadable(Unreadable::NotInGroup))
        );
        assert!(
            Unreadable::NotInGroup
                .said(false)
                .contains("is not in its group")
        );
        assert!(
            Unreadable::NotInGroup
                .said(true)
                .contains("the login suscheck.ssh names")
        );
        assert!(Unreadable::NoFolder.said(false).contains("isn't there"));
        // A fresh install: the folder, and no file yet.
        let fresh = format!("@@{MARK}:status\n\n@@{MARK}:devices\n\n@@{MARK}:index\n\n");
        let Read::Folder(s) = parse(&out(&fresh), MARK, 200).unwrap() else {
            panic!()
        };
        assert_eq!(
            (s.status.clone(), s.devices.clone()),
            (Part::Missing, Part::Missing)
        );
        assert!(s.checks.is_empty() && s.heartbeat_age().is_none());
        // A file that prints something that looks like a section line of another call
        // (or of none) is only its own text.
        let planted =
            format!("@@{MARK}:status\n@@ffffffffffffffff:denied\n@@denied\n@@{MARK}:index\n");
        let Read::Folder(s) = parse(&out(&planted), MARK, 200).unwrap() else {
            panic!()
        };
        assert_eq!(s.status, Part::Damaged);
        // No clock: nothing can be judged.
        assert!(parse(&format!("@@{MARK}:status\n"), MARK, 200).is_err());
        // The script: the folder single-quoted, never sudo, only reads.
        let sh = script("/srv/it's here/", 50, MARK);
        assert!(
            sh.starts_with("d='/srv/it'\\''s here'; m='@@0123456789abcdef:'"),
            "{sh}"
        );
        assert!(
            sh.contains("tail -n 50 \"$d/index.jsonl\" | head -c 51200"),
            "{sh}"
        );
        assert!(
            !sh.contains("sudo") && !sh.contains("rm ") && !sh.contains(" > "),
            "{sh}"
        );
        assert_ne!(fresh_mark(), fresh_mark());
    }

    #[test]
    fn an_incident_is_read_defensively() {
        let i = sample_incident("20261101T091500Z-a1b2");
        let last = i.last.as_ref().unwrap();
        assert_eq!(last.verdict.as_deref(), Some("likely_malicious"));
        assert_eq!(last.reasons.len(), 3);
        assert_eq!(last.floors, ["lookalike"]);
        assert_eq!(
            i.judgement.as_ref().unwrap().verdict.as_deref(),
            Some("suspicious")
        );
        let d = i.domain.as_ref().unwrap();
        assert_eq!(
            (d.result.as_deref(), d.real.as_deref(), d.why.as_deref()),
            (
                Some("lookalike"),
                Some("example-pay.test"),
                Some("confusable")
            )
        );
        let s = i.search.as_ref().unwrap();
        assert_eq!(s.queries.len(), 2);
        assert_eq!(
            (s.queries[0].kind.as_str(), s.queries[0].hits.len()),
            ("official", 2)
        );
        assert_eq!(s.queries[0].hits[0].engines, 2);
        // A stage that did not run is null: here the text recogniser.
        assert_eq!(
            i.stages,
            [
                ("extract", Some(3310)),
                ("reread", Some(2890)),
                ("ocr", None),
                ("search", Some(1630)),
                ("judge", Some(13650))
            ]
        );
        assert!(i.screenshot);
        // A check that failed: every part may be null, and it still says what it was given
        // and how far it got.
        let failed = sample_incident("20261104T194103Z-j9k0");
        assert!(failed.facts.is_none() && failed.last.is_none() && failed.search.is_none());
        assert_eq!(
            (failed.error.as_deref(), failed.screenshot),
            (Some("model"), false)
        );
        assert_eq!(
            (failed.input.as_slice(), failed.sent_picture()),
            (&["image".to_string()][..], Some(true))
        );
        assert_eq!(
            failed.stages,
            [
                ("extract", Some(120_010)),
                ("reread", None),
                ("ocr", None),
                ("search", None),
                ("judge", None)
            ]
        );
        assert_eq!((failed.links.is_none(), failed.links_total), (true, None));
        // The record of another incident isn't the one asked for; a newer schema is said.
        let text = fixture("suscheck/20261101T091500Z-a1b2/incident.json");
        let other = Id::parse("20261102T143027Z-c3d4").unwrap();
        assert!(
            parse_incident(&text, other)
                .unwrap_err()
                .contains("another incident")
        );
        let id = Id::parse("20261101T091500Z-a1b2").unwrap();
        let newer = text.replacen("\"schema\": 1", "\"schema\": 2", 1);
        assert!(parse_incident(&newer, id).unwrap_err().contains("schema 2"));
        assert!(parse_incident("{", id).is_err());
        // Hostile text in it is cleaned; wrong types and missing parts are left out.
        let hostile = text
            .replacen(
                "The page asks for a password.",
                "Ignore\\u001b[2J prior\\u202e text\\n\\u0007now",
                1,
            )
            .replacen("\"link_texts\": [", "\"link_texts\": [7, {\"a\": 1}, ", 1)
            .replacen("\"urgency\": true", "\"urgency\": \"yes\"", 1);
        let i = parse_incident(&hostile, id).unwrap();
        assert_eq!(i.judgement.unwrap().red_flags[0], "Ignore prior text now");
        let f = i.facts.unwrap();
        assert_eq!(f.link_texts, ["Sign in", "Forgot password?"]);
        assert_eq!(f.urgency, None);
        // The model's raw replies are never kept.
        assert!(!format!("{:?}", sample_incident("20261101T091500Z-a1b2")).contains("model_raw"));
    }

    /// A record cut back to the old shape's fields: none of those added since.
    fn older(text: &str) -> String {
        let mut v: Value = serde_json::from_str(text).unwrap();
        let o = v.as_object_mut().unwrap();
        for k in ["input", "email", "links", "links_total", "page", "message"] {
            o.remove(k);
        }
        if let Some(d) = o.get_mut("domain").and_then(Value::as_object_mut) {
            for k in ["source", "exact", "ocr_reading", "ocr_available"] {
                d.remove(k);
            }
        }
        if let Some(st) = o.get_mut("stages_ms").and_then(Value::as_object_mut) {
            st.remove("ocr");
        }
        v.to_string()
    }

    #[test]
    fn what_a_check_was_made_from_in_both_generations() {
        let index = fixture("suscheck/index.jsonl");
        let lines: Vec<&str> = index.lines().collect();
        // The published line in the old shape ends at `error`: no `input`, and a picture
        // was all there was. Given the key, nothing else of it reads differently.
        assert!(lines[0].ends_with("\"error\":null}") && !lines[0].contains("input"));
        let then = parse_line(lines[0]).unwrap();
        assert_eq!(then.input.as_deref(), Some("image"));
        assert_eq!(then.pictureless(), None);
        let now = lines[0].replacen("\"error\":null}", "\"error\":null,\"input\":\"image\"}", 1);
        assert_eq!(parse_line(&now).unwrap(), then);
        // A check that failed says what it was given.
        assert!(lines[5].contains("\"error\":\"model\",\"input\":\"image\""));
        assert_eq!(
            parse_line(lines[5]).unwrap().input.as_deref(),
            Some("image")
        );
        // There and null (today's writer never does): none, not a picture.
        let null = lines[5].replacen("\"input\":\"image\"", "\"input\":null", 1);
        assert_eq!(parse_line(&null).unwrap().input, None);
        // Every combination the format names, in plain words; one it doesn't is shown as
        // it is, cleaned and cut, and is no known kind.
        for (word, said, without) in [
            ("image", "picture", None),
            ("email", "email", Some("the email itself")),
            ("image+email", "picture + email", None),
            ("image+page", "picture + page address", None),
            (
                "email+page",
                "email + page address",
                Some("the email and the page's address"),
            ),
            ("page", "page address", Some("the page's address alone")),
            ("image+email+page", "picture + email + page address", None),
            ("fax", "fax", None),
            ("image+fax", "image+fax", None),
            ("", "", None),
        ] {
            let line =
                lines[1].replacen("\"input\":\"image\"", &format!("\"input\":\"{word}\""), 1);
            let c = parse_line(&line).unwrap();
            match word {
                "" => assert_eq!(c.input, None),
                _ => assert_eq!(c.sent().as_deref(), Some(said), "{word}"),
            }
            assert_eq!(c.pictureless(), without, "{word}");
        }
        let odd = lines[1].replacen(
            "\"input\":\"image\"",
            "\"input\":\"im\\u001b[2Jage\\u202e+\\nscan of a very long kind of thing\"",
            1,
        );
        assert_eq!(
            parse_line(&odd).unwrap().input.as_deref(),
            Some("image+ scan of a very lo…")
        );
        let wrong = lines[1].replacen("\"input\":\"image\"", "\"input\":[\"image\"]", 1);
        assert_eq!(parse_line(&wrong).unwrap().input, None);

        // The records. The published one in the old shape, byte for byte as the first
        // release wrote it: none of the later fields, and it reads as a picture's.
        let old_text = fixture("suscheck/20261030T184512Z-b0a1/incident.json");
        for later in [
            "\"input\":",
            "\"email\":",
            "\"links\":",
            "\"links_total\":",
            "\"page\":",
            "\"message\":",
            "\"source\":",
            "\"exact\":",
            "\"ocr",
        ] {
            assert!(!old_text.contains(later), "{later}");
        }
        let old = sample_incident("20261030T184512Z-b0a1");
        assert_eq!(old.input, ["image"]);
        assert_eq!(
            (old.sent_picture(), old.sent_email(), old.sent_page()),
            (Some(true), false, false)
        );
        assert!(old.email.is_none() && old.links.is_none() && old.page.is_none());
        assert_eq!((old.links_total, old.links_more()), (None, 0));
        assert_eq!((old.screenshot, old.message), (true, false));
        assert_eq!(old.prompt_version.as_deref(), Some("1"));
        let d = old.domain.as_ref().unwrap();
        assert_eq!(
            (
                d.source.as_deref(),
                d.exact.as_deref(),
                d.ocr_reading.as_deref(),
                d.ocr_available
            ),
            (None, None, None, None)
        );
        assert_eq!(
            (
                d.first_reading.as_deref(),
                d.result.as_deref(),
                d.why.as_deref()
            ),
            (
                Some("shop.example.com"),
                Some("match_search"),
                Some("exact")
            )
        );
        // No `ocr` key: the stage isn't named at all (there was no text recogniser).
        assert_eq!(
            old.stages,
            [
                ("extract", Some(3190)),
                ("reread", Some(2740)),
                ("search", Some(1480)),
                ("judge", Some(9850))
            ]
        );
        assert_eq!(
            old.last.as_ref().unwrap().verdict.as_deref(),
            Some("likely_safe")
        );
        // The old shape wrote 0 for a stage that did not run; today's 0 ran, in under a
        // millisecond, and null is what did not run.
        let id = Id::parse("20261030T184512Z-b0a1").unwrap();
        let zero = old_text.replacen("\"reread\": 2740", "\"reread\": 0", 1);
        assert_eq!(
            parse_incident(&zero, id).unwrap().stages[1],
            ("reread", None)
        );
        let id = Id::parse("20261101T091500Z-a1b2").unwrap();
        let text = fixture("suscheck/20261101T091500Z-a1b2/incident.json");
        let zero = text.replacen("\"reread\": 2890", "\"reread\": 0", 1);
        assert_eq!(
            parse_incident(&zero, id).unwrap().stages[1],
            ("reread", Some(0))
        );
        let odd = text
            .replacen("\"reread\": 2890", "\"reread\": \"fast\"", 1)
            .replacen("\"search\": 1630", "\"search\": -4", 1);
        assert_eq!(
            parse_incident(&odd, id)
                .unwrap()
                .stages
                .iter()
                .map(|s| s.0)
                .collect::<Vec<_>>(),
            ["extract", "ocr", "judge"]
        );
        // Every sample of today's shape, cut back to the old shape's fields, still reads:
        // a picture's, with what both shapes have unchanged.
        for id in [
            "20261101T091500Z-a1b2",
            "20261102T143027Z-c3d4",
            "20261103T080542Z-e5f6",
            "20261103T172009Z-g7h8",
            "20261104T194103Z-j9k0",
            "20261105T081233Z-k2m4",
            "20261105T103045Z-p6q8",
        ] {
            let text = fixture(&format!("suscheck/{id}/incident.json"));
            let now = sample_incident(id);
            let then = parse_incident(&older(&text), Id::parse(id).unwrap()).unwrap();
            assert_eq!(then.input, ["image"], "{id}");
            assert!(then.email.is_none() && then.links.is_none(), "{id}");
            assert!(then.page.is_none() && !then.message && then.links_total.is_none());
            assert!(
                then.domain
                    .as_ref()
                    .is_none_or(|d| d.source.is_none() && d.exact.is_none())
            );
            assert_eq!(
                (&then.last, &then.judgement, &then.facts, &then.search),
                (&now.last, &now.judgement, &now.facts, &now.search),
                "{id}"
            );
            assert_eq!((&then.error, then.screenshot), (&now.error, now.screenshot));
        }
    }

    #[test]
    fn an_email_its_links_and_the_page_are_read_defensively() {
        // The email file: its headers, its links, no picture, the message's text kept.
        let i = sample_incident("20261105T081233Z-k2m4");
        assert_eq!(i.input, ["email"]);
        assert_eq!((i.screenshot, i.message), (false, true));
        assert_eq!((i.sent_picture(), i.sent_email()), (Some(false), true));
        let d = i.domain.as_ref().unwrap();
        assert_eq!(
            (d.source.as_deref(), d.exact.as_deref(), d.ocr_available),
            (
                Some("email_header"),
                Some("account-alerts.test"),
                Some(false)
            )
        );
        assert_eq!(
            (d.first_reading.as_deref(), d.ocr_reading.as_deref()),
            (None, None)
        );
        let e = i.email.as_ref().unwrap();
        assert_eq!(e.from_name.as_deref(), Some("service@example-pay.test"));
        assert_eq!(
            e.from_address.as_deref(),
            Some("notice@account-alerts.test")
        );
        assert_eq!(
            (e.reply_to.as_deref(), e.return_path.as_deref()),
            (Some("desk@billing-desk.test"), None)
        );
        assert_eq!(
            e.subject.as_deref(),
            Some("Your Example Pay statement is ready")
        );
        assert_eq!(e.date.as_deref(), Some("Thu, 05 Nov 2026 08:10:00 +0000"));
        let auth: Vec<&str> = e.auth.iter().map(|a| a.as_deref().unwrap()).collect();
        assert_eq!(auth, ["fail", "none", "fail"]);
        assert_eq!(
            e.attachments,
            [Attachment {
                name: Some("statement.pdf.htm".into()),
                kind: Some("text/html".into()),
                size: Some(92),
            }]
        );
        assert_eq!((e.attachments_total, e.links_total), (1, Some(2)));
        assert_eq!(e.aimed_at_ai, Some(false));
        let links = i.links.as_ref().unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(
            links[0],
            Link {
                text: Some("example-pay[.]test".into()),
                scheme: Some("https".into()),
                // As stored: defanged, and never made anything else of.
                target: Some("account-alerts[.]test".into()),
                flags: vec!["text_mismatch".into()],
            }
        );
        assert_eq!((i.links_total, i.links_more()), (Some(2), 0));
        assert!(i.page.is_none());
        // The address came as exact text: no second reading, no text recogniser.
        assert_eq!(
            i.stages,
            [
                ("extract", Some(2950)),
                ("reread", None),
                ("ocr", None),
                ("search", Some(1710)),
                ("judge", Some(9840))
            ]
        );
        assert!(
            i.last
                .as_ref()
                .unwrap()
                .floors
                .contains(&"link_text_mismatch".to_string())
        );
        // The picture beside the window's exact address.
        let p = sample_incident("20261105T103045Z-p6q8");
        assert_eq!(p.input, ["image", "page"]);
        assert_eq!(
            (p.screenshot, p.message, p.sent_picture()),
            (true, false, Some(true))
        );
        let d = p.domain.as_ref().unwrap();
        assert_eq!(
            (
                d.source.as_deref(),
                d.exact.as_deref(),
                d.first_reading.as_deref()
            ),
            (
                Some("window"),
                Some("examp1e-pay.test"),
                Some("example-pay.test")
            )
        );
        assert_eq!(
            p.page,
            Some(Page {
                source: Some("accessibility".into()),
                url_domain: Some("examp1e-pay[.]test".into()),
                title: Some("Example Pay - Sign in".into()),
                links_total: Some(2),
            })
        );
        assert!(p.email.is_none() && p.links.as_ref().unwrap().len() == 2);
        assert_eq!((p.links_total, p.links_more()), (Some(2), 0));

        // Hostile and broken: every string cleaned and cut at sentry's own cap, lists cut
        // at theirs with the rest counted from the totals, wrong types left out. Never a
        // failure.
        let id = Id::parse("20261105T081233Z-k2m4").unwrap();
        let text = fixture("suscheck/20261105T081233Z-k2m4/incident.json");
        let mut v: Value = serde_json::from_str(&text).unwrap();
        let long = "x".repeat(5000);
        v["email"]["subject"] = format!("Sub\u{1b}[2Jject\u{202e}\n{long}").into();
        v["email"]["from_name"] = format!("Na\u{1b}]0;t\u{7}me\u{200b} {long}").into();
        v["email"]["from_address"] = format!("a@{long}").into();
        v["email"]["reply_to"] = 7.into();
        v["email"]["return_path"] = serde_json::json!({"a": 1});
        v["email"]["date"] = long.clone().into();
        v["email"]["auth"] = serde_json::json!({"spf": "pa\u{7}ss", "dkim": 3, "dmarc": long});
        v["email"]["attachments"] = Value::Array(
            (0..30)
                .map(|n| serde_json::json!({"name": format!("f{n}\u{202e}.{long}"), "type": long, "size": "big"}))
                .chain([Value::Null, 4.into()])
                .collect(),
        );
        v["email"]["attachments_total"] = 45.into();
        v["email"]["links_total"] = 300.into();
        v["links_total"] = 320.into();
        v["email"]["aimed_at_ai"] = "yes".into();
        v["links"] = Value::Array(
            (0..80)
                .map(|n| {
                    serde_json::json!({
                        "text": format!("t{n}\u{1b}[31m {long}"),
                        "scheme": "java\nscript",
                        "target_domain": format!("d{n}[.]{long}"),
                        "flags": ["text_mismatch", 9, "new\u{7}_flag", null],
                    })
                })
                .chain(["not a link".into()])
                .collect(),
        );
        v["page"] = serde_json::json!({"title": format!("Ti\u{9b}31mtle {long}"), "url_domain": 5, "links_total": -3});
        v["domain"]["exact"] = long.clone().into();
        v["domain"]["source"] = "carrier\u{7}_pigeon".into();
        v["domain"]["ocr_available"] = "no".into();
        v["input"] = serde_json::json!(["email", 3, "sm\u{1b}[2Joke signal that is long", null]);
        v["message"] = "true".into();
        let i = parse_incident(&v.to_string(), id).unwrap();
        let len = |s: &Option<String>| s.as_ref().unwrap().chars().count();
        let e = i.email.as_ref().unwrap();
        assert!(e.subject.as_ref().unwrap().starts_with("Subject xxx"));
        assert_eq!(len(&e.subject), 311);
        assert!(e.from_name.as_ref().unwrap().starts_with("Name xxx"));
        assert_eq!(
            (len(&e.from_name), len(&e.from_address), len(&e.date)),
            (211, 261, 65)
        );
        assert_eq!((&e.reply_to, &e.return_path), (&None, &None));
        assert_eq!(e.auth[0].as_deref(), Some("pass"));
        assert_eq!((e.auth[1].as_deref(), len(&e.auth[2])), (None, 21));
        assert_eq!(
            (e.attachments.len(), e.attachments_total),
            (ATTACHMENTS_MAX, 45)
        );
        let a = &e.attachments[0];
        assert!(a.name.as_ref().unwrap().starts_with("f0.xxx"));
        assert_eq!((len(&a.name), len(&a.kind), a.size), (131, 91, None));
        assert_eq!((e.links_total, e.aimed_at_ai), (Some(300), None));
        let links = i.links.as_ref().unwrap();
        // "And N more" is the record's own count less the list.
        assert_eq!((links.len(), i.links_more()), (LINKS_MAX, 270));
        assert!(links[0].text.as_ref().unwrap().starts_with("t0 xxx"));
        // (A little over what the format stores: 400 and 200, the defanged lengths.)
        assert_eq!((len(&links[0].text), len(&links[0].target)), (411, 211));
        assert_eq!(links[0].scheme.as_deref(), Some("java script"));
        assert_eq!(links[0].flags, ["text_mismatch", "new_flag"]);
        let p = i.page.as_ref().unwrap();
        assert!(p.title.as_ref().unwrap().starts_with("Title xxx"));
        assert_eq!(
            (len(&p.title), &p.url_domain, p.links_total),
            (211, &None, None)
        );
        let d = i.domain.as_ref().unwrap();
        assert_eq!(
            (len(&d.exact), d.source.as_deref(), d.ocr_available),
            (261, Some("carrier_pigeon"), None)
        );
        assert_eq!(i.input, ["email", "smoke signal tha…"]);
        assert!(!i.message, "only `true` says the text is there");
        let all = format!("{i:?}");
        assert!(
            !all.chars()
                .any(|c| c == '\u{1b}' || c == '\u{7}' || invisible(c)),
            "{all}"
        );
        // A total that says fewer than are listed is not believed below the list.
        v["email"]["attachments_total"] = 2.into();
        v["links_total"] = 7.into();
        let i = parse_incident(&v.to_string(), id).unwrap();
        assert_eq!(i.links_more(), 0);
        assert_eq!(i.email.unwrap().attachments_total, ATTACHMENTS_MAX as u64);
        // A record from before the count was written (or with something else in its
        // place): the email's and the page's counts together, less the list.
        for gone in [None, Some(Value::Null), Some("many".into())] {
            let mut w = v.clone();
            match gone {
                None => drop(w.as_object_mut().unwrap().remove("links_total")),
                Some(x) => w["links_total"] = x,
            }
            let i = parse_incident(&w.to_string(), id).unwrap();
            assert_eq!((i.links_total, i.links_more()), (None, 250));
            w["page"]["links_total"] = 40.into();
            assert_eq!(
                parse_incident(&w.to_string(), id).unwrap().links_more(),
                290
            );
        }
        // What the format stores at its longest is kept whole: a link's text of 400, a
        // target and a page's address of 200 (the plain value's cap, defanged).
        let mut w: Value = serde_json::from_str(&text).unwrap();
        w["links"][0]["text"] = "t[.]".repeat(100).into();
        w["links"][0]["target_domain"] = "d[.]".repeat(50).into();
        w["page"] = serde_json::json!({"url_domain": "p[.]".repeat(50)});
        let i = parse_incident(&w.to_string(), id).unwrap();
        let l = &i.links.as_ref().unwrap()[0];
        assert_eq!(l.text.as_deref(), Some("t[.]".repeat(100).as_str()));
        assert_eq!(l.target.as_deref(), Some("d[.]".repeat(50).as_str()));
        assert_eq!(
            i.page.unwrap().url_domain.as_deref(),
            Some("p[.]".repeat(50).as_str())
        );
        // Each block null, or not an object: left out, the rest read.
        for block in ["email", "links", "page", "domain", "input"] {
            for bad in [Value::Null, "text".into(), 3.into()] {
                let mut w: Value = serde_json::from_str(&text).unwrap();
                w[block] = bad;
                let i = parse_incident(&w.to_string(), id).unwrap();
                assert!(i.last.is_some(), "{block}");
                match block {
                    "email" => assert!(i.email.is_none()),
                    "links" => assert!(i.links.is_none()),
                    "page" => assert!(i.page.is_none()),
                    "domain" => assert!(i.domain.is_none()),
                    // (There, and not a list of words: nothing is made of it. Only a
                    // record without the key is the old shape's picture.)
                    _ => assert!(i.input.is_empty() && i.sent_picture().is_none()),
                }
            }
        }
        // An email block with nothing in it.
        let mut w: Value = serde_json::from_str(&text).unwrap();
        w["email"] = serde_json::json!({});
        let e = parse_incident(&w.to_string(), id).unwrap().email.unwrap();
        assert_eq!(e, Email::default());
    }

    #[test]
    fn a_picture_is_taken_only_as_a_png_and_only_so_much() {
        let dir = std::env::temp_dir().join(format!("sentry-sus-sink-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sink = |name: &str| PngSink {
            file: std::fs::File::create(dir.join(name)).unwrap(),
            total: 0,
            head: Vec::new(),
        };
        let png = std::fs::read(format!(
            "{}/../../tests/fixtures/server/suscheck/20261101T091500Z-a1b2/screenshot.png",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        // The sample, in small pieces (the signature arrives split).
        let mut s = sink("ok");
        for chunk in png.chunks(3) {
            s.write_all(chunk).unwrap();
        }
        assert_eq!((s.total, s.head.len()), (png.len() as u64, 8));
        // Not a PNG: refused at the first bytes that say so.
        let mut s = sink("html");
        assert!(s.write_all(b"<html>").is_err());
        let mut s = sink("near");
        s.write_all(&PNG[..4]).unwrap();
        assert!(s.write_all(b"oops").is_err());
        // Too much: refused as it passes the cap, whatever the file claims to be.
        let mut s = sink("big");
        s.write_all(&PNG).unwrap();
        let block = vec![0u8; 1024 * 1024];
        let mut wrote = 0;
        let err = loop {
            match s.write_all(&block) {
                Ok(()) => wrote += 1,
                Err(e) => break e,
            }
            assert!(wrote <= 16, "never stopped");
        };
        assert!(err.to_string().contains("over 16 MB"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
