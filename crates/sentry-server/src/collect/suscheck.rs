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
/// here, where the path is made: nothing else can become part of a path.
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

/// What the model copied from the picture: its reading of attacker content.
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
    /// Milliseconds per stage, in the order they run.
    pub stages: Vec<(&'static str, u64)>,
    pub facts: Option<Facts>,
    pub domain: Option<Domain>,
    pub search: Option<Search>,
    pub judgement: Option<Judgement>,
    pub last: Option<Final>,
    /// Whether a picture was kept.
    pub screenshot: bool,
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
    Ok(Incident {
        id,
        device: text(&v["device"], 40),
        client: text(&v["client"], 20),
        app_version: text(&v["app_version"], 20),
        duration_ms: v["duration_ms"].as_u64().unwrap_or(0).min(86_400_000),
        error: text(&v["error"], 120),
        model: text(&v["model"], 120),
        prompt_version: text(&v["prompt_version"], 40),
        stages: ["extract", "reread", "search", "judge"]
            .into_iter()
            .filter_map(|s| Some((s, v["stages_ms"][s].as_u64()?)))
            .collect(),
        facts,
        domain,
        search,
        judgement,
        last,
        screenshot: v["screenshot"].as_bool().unwrap_or(false),
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
        assert_eq!(s.checks.len(), 5);
        assert_eq!((s.skipped, s.index_newer, s.newer()), (0, None, None));
        let first = &s.checks[0];
        assert_eq!(first.id.as_str(), "20261101T091500Z-a1b2");
        assert_eq!(first.device.as_deref(), Some("Kitchen iMac"));
        assert_eq!(first.domain.as_deref(), Some("examp1e-pay.test"));
        assert_eq!(first.verdict(), Some(Verdict::Malicious));
        assert_eq!(first.outcome(), "don't trust this");
        assert_eq!(first.floors_changed, Some(true));
        // An empty `app_version` is none; a failed check has an error and no verdict.
        assert_eq!(s.checks[1].app_version, None);
        let failed = &s.checks[4];
        assert_eq!(
            (failed.verdict.as_deref(), failed.error.as_deref()),
            (None, Some("model"))
        );
        assert_eq!(failed.outcome(), "failed (model)");
        // Never "safe".
        assert_eq!(s.checks[2].outcome(), "no obvious warning signs");
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
        // Counts: by the server's clock, the last day has only the failed check.
        let c = s.counts();
        assert_eq!(
            c.week,
            Tally {
                total: 5,
                malicious: 1,
                suspicious: 2,
                safe: 1,
                other: 0,
                errors: 1,
                incomplete: 1,
                floors: 1,
            }
        );
        assert_eq!((c.day.total, c.day.errors, c.computers), (1, 1, 2));
        assert!(!c.down());
        // Since the first check was looked at: nothing more said "don't trust this", one failed.
        assert_eq!(s.unseen(None), (1, 1));
        assert_eq!(s.unseen(Some("20261101T091500Z-a1b2")), (0, 1));
        assert_eq!(s.unseen(Some("20261104T194103Z-j9k0")), (0, 0));
    }

    #[test]
    fn what_isnt_the_format_is_skipped_counted_or_said() {
        let good = fixture("suscheck/index.jsonl");
        let line = good.lines().next().unwrap();
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
        assert_eq!(
            i.stages,
            [
                ("extract", 3310),
                ("reread", 2890),
                ("search", 1630),
                ("judge", 13650)
            ]
        );
        assert!(i.screenshot);
        // A check that failed: every part may be null.
        let failed = sample_incident("20261104T194103Z-j9k0");
        assert!(failed.facts.is_none() && failed.last.is_none() && failed.search.is_none());
        assert_eq!(
            (failed.error.as_deref(), failed.screenshot),
            (Some("model"), false)
        );
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
