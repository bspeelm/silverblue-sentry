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
//!
//! The format grows without a schema change, and every addition is read the same way: a
//! part that is missing, null or not what the format says is left out; a value this sentry
//! has no words for is kept as cleaned text and never taken for a known one; a boolean
//! counts only when it is literally `true`.

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
    cut(v.as_str()?, cap)
}

/// The same for text that is not a value: an object's key.
fn cut(s: &str, cap: usize) -> Option<String> {
    let s = clean(s);
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
    /// How the message reached SusCheck, where the browser extension brought it:
    /// `original` (the raw message, fetched from the mail site), or one of its fallbacks,
    /// `page`, `paste`, `picture`; a value this sentry doesn't know is kept as text. None:
    /// made by hand on the page or sent by the desktop app (null), or a line from before
    /// the key was written. The extension's own account of what it did.
    pub acquired_by: Option<String>,
    /// The record's `final.unconfirmed_only`, copied to the index: the "be careful" is only
    /// because the address couldn't be confirmed. None: unknown (an older line without the
    /// key, a failed check, or not a boolean), which is not the same as false: the record
    /// says.
    pub unconfirmed_only: Option<bool>,
    /// Why that address couldn't be confirmed (`picture`, `other_domain`, `small_sender`,
    /// `personal_address`, or a value this sentry doesn't know). None: the line doesn't
    /// say (null, or an older line).
    pub unconfirmed_kind: Option<String>,
    /// The record's `final.trusted_sender`: the sender was on the owner's trusted list
    /// and the mail system confirmed it. Null and a missing key are false.
    pub trusted_sender: Option<bool>,
}

/// What the list says for a "be careful" that is only because the address couldn't be
/// confirmed, where the line doesn't say why (or says it in a word this sentry doesn't
/// know).
pub const UNCONFIRMED_SHORT: &str = "be careful (unconfirmed)";

/// The same where it says why (`unconfirmed_kind`), short enough for the list's column.
pub fn unconfirmed_short(kind: Option<&str>) -> &'static str {
    match kind {
        Some("picture") => "be careful (picture only)",
        Some("other_domain") => "be careful (other domain)",
        Some("small_sender") => "be careful (small sender)",
        Some("personal_address") => "be careful (personal)",
        _ => UNCONFIRMED_SHORT,
    }
}

/// The faults in how a message was put together that mainstream mail software doesn't
/// write by accident (`email.defects`' notable set, as the format lists it today). A record
/// that says which of its own were notable is believed over this.
pub const NOTABLE_DEFECTS: [&str; 7] = [
    "bad_header",
    "bad_header_encoding",
    "nul_bytes",
    "bad_multipart",
    "no_closing_boundary",
    "text_outside_parts",
    "bad_base64",
];
/// The most fault words of one record that are kept.
pub const DEFECTS_MAX: usize = 20;
/// The most trusted senders that are kept (the format's own limit is 500).
pub const TRUSTED_MAX: usize = 200;

/// How the browser extension can have got a message (`acquired_by`), each in a word for
/// the summary: the original, then its fallbacks in decreasing strength.
pub const ACQUIRED: [(&str, &str); 4] = [
    ("original", "original"),
    ("page", "page"),
    ("paste", "paste"),
    ("picture", "picture"),
];

/// The browser extension is falling back from the original mail: what
/// [`Suscheck::fallback`] found. Numbers only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fallback {
    /// The latest checks through the extension, in a row, that weren't the original mail.
    pub run: u32,
    /// Those of the last 24 hours by the server's clock.
    pub day: u32,
}

/// The format's own test for "the mail site has changed", over the index lines that came
/// through the browser extension, oldest first: `(when, was it the original mail)`. It
/// holds when the latest three are all not the original, or every one of the last 24
/// hours is not and there are at least two of them, while some earlier line was the
/// original. One fallback by itself means little. Pure.
pub fn fallback_of(now: i64, lines: &[(Option<i64>, bool)]) -> Option<Fallback> {
    let run = lines
        .iter()
        .rev()
        .take_while(|(_, original)| !original)
        .count();
    // (Every line after the last original is a fallback: one was earlier exactly when
    // the run isn't the whole list.)
    if run == lines.len() {
        return None;
    }
    let today: Vec<bool> = lines
        .iter()
        .filter(|(at, _)| at.is_some_and(|a| a >= now - 86_400))
        .map(|(_, original)| *original)
        .collect();
    let day = today.len();
    let all_day = day >= 2 && today.iter().all(|original| !original);
    (run >= 3 || all_day).then_some(Fallback {
        run: run as u32,
        day: if all_day { day as u32 } else { 0 },
    })
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

    /// The index says this "be careful" is only because the address couldn't be
    /// confirmed. Never for another verdict, whatever the line says; false where the
    /// line doesn't say (the record does).
    pub fn mild(&self) -> bool {
        self.unconfirmed_only == Some(true)
            && self.error.is_none()
            && self.verdict() == Some(Verdict::Suspicious)
    }

    /// The check rests on a sender the owner trusts and the mail system confirmed. Only a
    /// literal `true` on a completed check; a line that doesn't say is false.
    pub fn trusted(&self) -> bool {
        self.trusted_sender == Some(true) && self.error.is_none()
    }

    /// What the list says in the verdict's column.
    pub fn outcome(&self) -> String {
        match (&self.error, &self.verdict) {
            (Some(e), _) => format!("failed ({e})"),
            (None, Some(_)) if self.mild() => {
                unconfirmed_short(self.unconfirmed_kind.as_deref()).into()
            }
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
    /// An owner computer: one that may add to and remove from the trusted senders list.
    /// Only a literal `true`; a file from before doesn't say, which is false.
    pub owner: bool,
}

/// One sender the owner has chosen to trust (`trusted.json`: the list as it is now, never
/// a history). The label may be a display name from a message: attacker-influenced text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trusted {
    /// `domain` (every address there) or `address` (one), or a value this sentry doesn't
    /// know.
    pub kind: Option<String>,
    /// The domain or the address. Not defanged: text, never resolved, looked up or opened.
    pub value: String,
    pub label: Option<String>,
    pub added_at: Option<i64>,
    /// The owner computer that added it, or `command line`.
    pub added_by: Option<String>,
}

/// The trusted senders as read: at most [`TRUSTED_MAX`], and how many more the file had.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedList {
    pub senders: Vec<Trusted>,
    pub more: u32,
}

impl TrustedList {
    /// How many the file lists.
    pub fn total(&self) -> u32 {
        self.senders.len() as u32 + self.more
    }
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
    /// The senders the owner trusts now. Missing: no list (none was ever trusted here, or
    /// a SusCheck from before there was one), which is not an error.
    pub trusted: Part<TrustedList>,
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
    /// Completed, and resting on a sender the owner trusts (where the index says so).
    #[serde(default)]
    pub trusted: u32,
    pub suspicious: u32,
    /// Of the suspicious, those the index says are only because the address couldn't be
    /// confirmed (older lines don't say: not counted here).
    #[serde(default)]
    pub unconfirmed: u32,
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
            Some(Verdict::Suspicious) => {
                self.suspicious += 1;
                self.unconfirmed += u32::from(c.mild());
            }
            Some(Verdict::Safe) => self.safe += 1,
            None => self.other += 1,
        }
        self.trusted += u32::from(c.trusted());
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
    /// How many senders the owner trusts now (the number alone: never who).
    pub trusted: u32,
    /// Index lines skipped as damaged.
    pub skipped: u32,
    /// The browser extension is falling back from the original mail (the format's own
    /// test: see [`fallback_of`]). None: it isn't, or no check came through it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback: Option<Fallback>,
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
            .or(self.trusted.newer())
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

    /// The browser extension is falling back from the original mail: the mail site's
    /// pages probably changed, and the extension's rules need updating. Only lines that
    /// say how the extension got the message count: one made by hand or by the desktop
    /// app (null), an older line without the key, and a value this sentry doesn't know
    /// (the format says none is ever written) are left out.
    pub fn fallback(&self) -> Option<Fallback> {
        let lines: Vec<(Option<i64>, bool)> = self
            .checks
            .iter()
            .filter_map(|c| {
                let how = c.acquired_by.as_deref()?;
                ACQUIRED
                    .iter()
                    .any(|(w, _)| *w == how)
                    .then_some((c.at, how == "original"))
            })
            .collect();
        fallback_of(self.now, &lines)
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
            trusted: self.trusted.ok().map_or(0, TrustedList::total),
            skipped: self.skipped,
            fallback: self.fallback(),
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
                    owner: d["owner"].as_bool() == Some(true),
                })
            })
            .collect(),
    )
}

/// `trusted.json`. An entry without a value isn't one; what is past [`TRUSTED_MAX`] is
/// counted, not kept.
pub fn parse_trusted(body: &str) -> Part<TrustedList> {
    let v = match object(body) {
        Ok(v) => v,
        Err(p) => return p,
    };
    if let Err(p) = schema_of(&v) {
        return p;
    }
    let Some(list) = v["senders"].as_array() else {
        return Part::Damaged;
    };
    let senders: Vec<Trusted> = list
        .iter()
        .take(TRUSTED_MAX)
        .filter_map(|x| {
            Some(Trusted {
                value: text(&x["value"], 260)?,
                kind: text(&x["kind"], 16),
                label: text(&x["label"], 84),
                added_at: time(&x["added_at"]),
                added_by: text(&x["added_by"], 40),
            })
        })
        .collect();
    Part::Ok(TrustedList {
        more: list.len().saturating_sub(TRUSTED_MAX).min(100_000) as u32,
        senders,
    })
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
        // The last key, added with the browser extension: missing is the same as null.
        acquired_by: text(&v["acquired_by"], 16),
        // A boolean, null on a failed check, absent on an older line.
        unconfirmed_only: v["unconfirmed_only"].as_bool(),
        unconfirmed_kind: text(&v["unconfirmed_kind"], 24),
        trusted_sender: v["trusted_sender"].as_bool(),
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
        trusted: parse_trusted(part("trusted").unwrap_or("")),
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
         for f in status.json devices.json trusted.json index.jsonl; do\n\
         [ ! -e \"$d/$f\" ] || [ -r \"$d/$f\" ] || {{ echo \"${{m}}denied\"; exit 0; }}\n\
         done\n\
         echo \"${{m}}status\"; [ ! -f \"$d/status.json\" ] || head -c 65536 \"$d/status.json\"; echo\n\
         echo \"${{m}}devices\"; [ ! -f \"$d/devices.json\" ] || head -c 262144 \"$d/devices.json\"; echo\n\
         echo \"${{m}}trusted\"; [ ! -f \"$d/trusted.json\" ] || head -c 524288 \"$d/trusted.json\"; echo\n\
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
    /// Which field of the model's reading of the picture gave the first reading
    /// (`sender_address`, `sender_host`, `address_bar`, or a value this sentry doesn't know).
    pub first_reading_from: Option<String>,
    /// Whether the letter shapes found in the picture could spell the first reading, judged
    /// by code: `fits`, `touching` (means nothing), `differs` (it takes a match away).
    pub shape_fit: Option<String>,
    /// What the model read when shown those letter shapes one by one, out of order.
    pub shuffled_reading: Option<String>,
    /// Whether the digit rule could look, and what it found: `fired`, `clear`,
    /// `not_evaluated`. None: a record from before the rule was reworked.
    pub digit_rule: Option<String>,
    /// The one word the model was given, in its second pass, for how the comparison came
    /// out (`match`, `lookalike`, `mismatch`, `unknown`, `local_device`, `unconfirmed`,
    /// `personal_address`, `other_domain`). Not a second result.
    pub judge_word: Option<String>,
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
    /// False only when a search for the official site failed (a record without `failed`,
    /// from before: when any search did).
    pub ok: Option<bool>,
    pub queries: Vec<Query>,
    /// The kind of each query that failed or timed out. None: a record from before that
    /// was written.
    pub failed: Option<Vec<String>>,
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
    /// The verdict is `suspicious` only because the address could not be confirmed, and
    /// nothing looked wrong: the person was shown a milder "be careful". Only a literal
    /// `true` says so; a record without it (from before) doesn't.
    pub unconfirmed_only: bool,
    /// Why the address couldn't be confirmed, where that is all the verdict rests on.
    pub unconfirmed_kind: Option<String>,
    /// The sender was on the owner's trusted list, the mail system confirmed it, and that
    /// is what the check rests on. Only a literal `true`.
    pub trusted_sender: bool,
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
    /// What was written in the From header where no address could be read from it. Not
    /// defanged: text, never resolved.
    pub from_written: Option<String>,
    /// The free personal mail provider the sender uses, by SusCheck's own short list.
    pub freemail: Option<String>,
    /// The small facts SusCheck's code worked out about the message that are true (only
    /// a literal `true` counts), by their keys: those the format names, in its order, then
    /// any other, as cleaned text. Hints, never proof. At most [`SIGNALS_MAX`].
    pub signals: Vec<String>,
    /// Faults in how the message was put together, as SusCheck's own fixed words (a word
    /// this sentry doesn't know is kept as cleaned text). At most [`DEFECTS_MAX`]. None:
    /// not recorded, which is unknown and not the same as no faults.
    pub defects: Option<Vec<String>>,
    /// Those of them the record itself calls notable (the model was told, and the remark
    /// `message_faults` written). None: the record doesn't say.
    pub defects_notable: Option<Vec<String>>,
}

impl Email {
    /// The notable faults: the record's own list where it has one (the split as it was
    /// for that record), else those of its faults in today's notable set; a word in
    /// neither set is minor. The bool: the record said so itself.
    pub fn notable(&self) -> (Vec<&str>, bool) {
        match (&self.defects_notable, &self.defects) {
            (Some(n), _) => (n.iter().map(String::as_str).collect(), true),
            (None, Some(d)) => (
                d.iter()
                    .map(String::as_str)
                    .filter(|w| NOTABLE_DEFECTS.contains(w))
                    .collect(),
                false,
            ),
            (None, None) => (Vec::new(), false),
        }
    }
}

/// `email.signals` as the format names them, in its order.
pub const SIGNALS: [&str; 8] = [
    "body_nearly_empty",
    "random_address",
    "names_disagree",
    "money_wording",
    "return_path_differs",
    "body_is_one_link",
    "display_name_is_recipient",
    "name_matches_address",
];
/// The most signals of one record that are kept.
pub const SIGNALS_MAX: usize = 16;

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
    /// How many of those were exact repeats of an earlier link and were merged into it.
    /// None: no list, or a record from before the count was written.
    pub links_merged: Option<u64>,
    pub page: Option<Page>,
    /// How the message reached SusCheck (as [`Check::acquired_by`]). None: by hand, the
    /// desktop app, or a record from before the browser extension.
    pub acquired_by: Option<String>,
    /// What the browser extension says the mail program showed for the message: `spam`,
    /// `phishing_warning`, `none` (it looked and saw neither), or a value this sentry
    /// doesn't know. The client's word: SusCheck checked none of it. None: nothing
    /// reported.
    pub mail_label: Option<String>,
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

    /// The links that are not in the list, where the record says how they split: (left
    /// out at a limit, exact repeats merged into one already listed or counted). The
    /// format's own sum: `links_total - links_merged - len(links)` at a limit. Neither is
    /// believed past what the total leaves beyond the list. None: a record without
    /// `links_merged` (see [`Incident::links_more`]).
    pub fn links_left(&self) -> Option<(u64, u64)> {
        let listed = self.links.as_ref()?.len() as u64;
        let beyond = self.links_total?.saturating_sub(listed);
        let merged = self.links_merged?.min(beyond);
        Some((beyond - merged, merged))
    }

    /// The person was shown the milder "be careful": the verdict is `suspicious` only
    /// because the address couldn't be confirmed. Never for any other verdict, whatever
    /// the record says.
    pub fn unconfirmed_only(&self) -> bool {
        self.last.as_ref().is_some_and(|l| {
            l.unconfirmed_only
                && l.verdict.as_deref().and_then(Verdict::of) == Some(Verdict::Suspicious)
        })
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

    /// Whether a reading that is a registrable domain (the text recogniser's, the shuffled
    /// letter shapes') is the first reading's own: SusCheck compares it with the
    /// registrable domain of the first reading, which is a full host. Without a list of
    /// public suffixes here: the same text, or the first reading ends with a dot and it.
    /// None: there is no first reading to hold it against.
    pub fn same_domain(first: Option<&str>, domain: &str) -> Option<bool> {
        let first = first?.to_ascii_lowercase();
        let domain = domain.to_ascii_lowercase();
        Some(first == domain || first.ends_with(&format!(".{domain}")))
    }

    /// The window was the mail site's, read by the browser extension: its address is the
    /// mail site's own and never the one the verdict rests on.
    pub fn mail_window(&self) -> bool {
        self.page
            .as_ref()
            .is_some_and(|p| p.source.as_deref() == Some("extension"))
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
            first_reading_from: text(&d["first_reading_from"], 30),
            shape_fit: text(&d["shape_fit"], 30),
            shuffled_reading: t(&d["shuffled_reading"]),
            digit_rule: text(&d["digit_rule"], 30),
            judge_word: text(&d["judge_word"], 24),
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
            failed: s["failed"].is_array().then(|| texts(&s["failed"], 20, 6)),
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
            unconfirmed_only: f["unconfirmed_only"].as_bool() == Some(true),
            unconfirmed_kind: text(&f["unconfirmed_kind"], 24),
            trusted_sender: f["trusted_sender"].as_bool() == Some(true),
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
        // Only a literal `true` is a signal. The ones the format names come first, in its
        // order; a key it doesn't name is kept as cleaned text.
        let on = |k: &str| e["signals"][k].as_bool() == Some(true);
        let signals: Vec<String> = SIGNALS
            .iter()
            .filter(|k| on(k))
            .map(|k| k.to_string())
            .chain(
                e["signals"]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .filter(|(k, v)| v.as_bool() == Some(true) && !SIGNALS.contains(&k.as_str()))
                    .filter_map(|(k, _)| cut(k, 40)),
            )
            .take(SIGNALS_MAX)
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
            from_written: text(&e["from_written"], 260),
            freemail: text(&e["freemail"], 24),
            signals,
            defects: e["defects"]
                .is_array()
                .then(|| texts(&e["defects"], 30, DEFECTS_MAX)),
            defects_notable: e["defects_notable"]
                .is_array()
                .then(|| texts(&e["defects_notable"], 30, DEFECTS_MAX)),
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
        stages: [
            "extract", "reread", "ocr", "shapes", "shuffle", "search", "judge",
        ]
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
        links_merged: links.as_ref().and_then(|_| count(&v["links_merged"])),
        links,
        page,
        acquired_by: text(&v["acquired_by"], 16),
        mail_label: text(&v["mail_label"], 24),
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
            "@@{MARK}:now\n{}\n@@{MARK}:status\n{}\n@@{MARK}:devices\n{}\n@@{MARK}:trusted\n{}\n@@{MARK}:index\n{}\n",
            now.as_second(),
            fixture("suscheck/status.json"),
            fixture("suscheck/devices.json"),
            fixture("suscheck/trusted.json"),
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
        assert_eq!(s.checks.len(), 11);
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
        assert_eq!(s.checks[8].outcome(), "no obvious warning signs");
        // A genuine page seen only in a picture is "be careful", never more: the index
        // doesn't say it is the milder kind (the record does).
        assert_eq!(s.checks[3].id.as_str(), "20261103T080542Z-e5f6");
        assert_eq!(
            (s.checks[3].verdict(), s.checks[3].domain_check.as_deref()),
            (Some(Verdict::Suspicious), Some("match_trusted"))
        );
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
                said("email + page address"),
                said("email"),
                said("email"),
            ]
        );
        assert_eq!(
            s.checks[8].pictureless(),
            Some("the email and the page's address")
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
        // Three computers: a browser only ever used by hand (it says `web`, which is no
        // version), the desktop app, and the browser the extension's check came from.
        assert_eq!(d.len(), 3);
        let seen: Vec<(&str, Option<&str>, Option<&str>)> = d
            .iter()
            .map(|x| {
                (
                    x.name.as_str(),
                    x.client.as_deref(),
                    x.app_version.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                ("Hallway PC", Some("web"), Some("web")),
                ("Kitchen iMac", Some("app"), Some("0.1.0")),
                ("Study laptop", Some("web"), Some("0.2.0")),
            ]
        );
        // A check made by hand on the page reports no version; the extension's has its own.
        assert_eq!(s.checks[2].device.as_deref(), Some("Hallway PC"));
        assert_eq!(s.checks[9].app_version.as_deref(), Some("0.2.0"));
        // The index says which "be careful" is only an unconfirmed address: true on one
        // line, false on the other completed ones, null on the failed one, and no key at
        // all on the oldest (unknown, which is not false).
        let known: Vec<Option<bool>> = s.checks.iter().map(|c| c.unconfirmed_only).collect();
        assert_eq!(known[0], None);
        assert_eq!(known[3], Some(true));
        assert_eq!(known[5], None);
        assert_eq!(
            known.iter().filter(|k| **k == Some(false)).count(),
            8,
            "{known:?}"
        );
        assert!(s.checks[3].mild() && s.checks[3].outcome() == "be careful (picture only)");
        assert!(!s.checks[2].mild() && s.checks[2].outcome() == "be careful");
        assert!(s.checks.iter().filter(|c| c.mild()).count() == 1);
        // Counts: by the server's clock, the last day has the failed check and the four
        // of that morning.
        let c = s.counts();
        assert_eq!(
            c.week,
            Tally {
                total: 11,
                malicious: 3,
                trusted: 1,
                suspicious: 3,
                unconfirmed: 1,
                safe: 4,
                other: 0,
                errors: 1,
                incomplete: 1,
                floors: 4,
            }
        );
        assert_eq!((c.day.total, c.day.errors, c.computers), (6, 1, 3));
        assert_eq!(c.trusted, 2);
        assert!(!c.down());
        // Since the first lookalike was looked at: two more said "don't trust this", one
        // failed.
        assert_eq!(s.unseen(None), (3, 1));
        assert_eq!(s.unseen(Some("20261030T184512Z-b0a1")), (3, 1));
        assert_eq!(s.unseen(Some("20261101T091500Z-a1b2")), (2, 1));
        assert_eq!(s.unseen(Some("20261104T194103Z-j9k0")), (2, 0));
        assert_eq!(s.unseen(Some("20261105T103045Z-p6q8")), (0, 0));
        // What needs a look is what said "don't trust this" or failed: a "be careful",
        // the milder kind included, never is.
        assert_eq!(s.unseen(Some("20261102T143027Z-c3d4")), (2, 1));
        assert_eq!(
            s.newest().map(|i| i.to_string()).as_deref(),
            Some("20261105T115934Z-w8x2")
        );
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
                ("shapes", None),
                ("shuffle", None),
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
                ("shapes", None),
                ("shuffle", None),
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
        for k in [
            "input",
            "email",
            "links",
            "links_total",
            "links_merged",
            "page",
            "message",
            "acquired_by",
            "mail_label",
        ] {
            o.remove(k);
        }
        if let Some(d) = o.get_mut("domain").and_then(Value::as_object_mut) {
            for k in [
                "source",
                "exact",
                "ocr_reading",
                "ocr_available",
                "first_reading_from",
                "shape_fit",
                "shuffled_reading",
                "digit_rule",
            ] {
                d.remove(k);
            }
        }
        if let Some(st) = o.get_mut("stages_ms").and_then(Value::as_object_mut) {
            for k in ["ocr", "shapes", "shuffle"] {
                st.remove(k);
            }
        }
        if let Some(f) = o.get_mut("final").and_then(Value::as_object_mut) {
            for k in ["unconfirmed_only", "unconfirmed_kind", "trusted_sender"] {
                f.remove(k);
            }
        }
        if let Some(d) = o.get_mut("domain").and_then(Value::as_object_mut) {
            d.remove("judge_word");
        }
        if let Some(f) = o.get_mut("search").and_then(Value::as_object_mut) {
            f.remove("failed");
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
        assert!(!lines[0].contains("acquired_by"));
        let then = parse_line(lines[0]).unwrap();
        assert_eq!(then.input.as_deref(), Some("image"));
        assert_eq!(then.acquired_by, None);
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
            "\"links_merged\":",
            "\"first_reading_from\":",
            "\"shape_fit\":",
            "\"shuffled_reading\":",
            "\"digit_rule\":",
            "\"shapes\":",
            "\"shuffle\":",
            "\"unconfirmed_only\":",
            "\"failed\":",
            "\"signals\":",
            "\"acquired_by\":",
            "\"mail_label\":",
            "\"judge_word\":",
            "\"trusted_sender\":",
            "\"unconfirmed_kind\":",
            "\"defects",
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
        assert_eq!((old.links_merged, old.links_left()), (None, None));
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
                d.first_reading_from.as_deref(),
                d.shape_fit.as_deref(),
                d.shuffled_reading.as_deref(),
                d.digit_rule.as_deref()
            ),
            (None, None, None, None)
        );
        // A picture alone could still be "no obvious warning signs" then, and no search
        // was listed as failed.
        assert!(!old.unconfirmed_only());
        assert_eq!(old.search.as_ref().unwrap().failed, None);
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
            ["extract", "ocr", "shapes", "shuffle", "judge"]
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
            "20261105T114502Z-r3s5",
            "20261105T115821Z-t4v6",
            "20261105T115934Z-w8x2",
        ] {
            let text = fixture(&format!("suscheck/{id}/incident.json"));
            let mut now = sample_incident(id);
            // (What a record from before doesn't say: the milder verdict, which searches
            // failed.)
            if let Some(l) = &mut now.last {
                l.unconfirmed_only = false;
                l.unconfirmed_kind = None;
                l.trusted_sender = false;
            }
            if let Some(s) = &mut now.search {
                s.failed = None;
            }
            let then = parse_incident(&older(&text), Id::parse(id).unwrap()).unwrap();
            assert_eq!(then.input, ["image"], "{id}");
            assert!(then.email.is_none() && then.links.is_none(), "{id}");
            assert!(then.page.is_none() && !then.message && then.links_total.is_none());
            assert!(then.links_merged.is_none() && !then.unconfirmed_only());
            assert!(then.acquired_by.is_none() && then.mail_label.is_none());
            assert!(then.domain.as_ref().is_none_or(|d| {
                d.source.is_none()
                    && d.exact.is_none()
                    && d.digit_rule.is_none()
                    && d.shape_fit.is_none()
                    && d.shuffled_reading.is_none()
                    && d.first_reading_from.is_none()
                    && d.judge_word.is_none()
            }));
            assert!(
                then.stages
                    .iter()
                    .all(|(n, _)| !["ocr", "shapes", "shuffle"].contains(n))
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
        // What code worked out: the one signal that is true, no provider, nothing written
        // in an address's place.
        assert_eq!(e.signals, ["money_wording"]);
        assert_eq!((&e.from_written, &e.freemail), (&None, &None));
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
        assert_eq!((i.links_merged, i.links_left()), (Some(0), Some((0, 0))));
        assert!(i.page.is_none());
        // The address came as exact text: no second reading, no text recogniser.
        assert_eq!(
            i.stages,
            [
                ("extract", Some(2950)),
                ("reread", None),
                ("ocr", None),
                ("shapes", None),
                ("shuffle", None),
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

    /// The format's later revision (still schema 1): the milder verdict, how the links
    /// that aren't listed split, what code noticed about an email, which searches failed,
    /// and what the picture's letter shapes and the digit rule said of the address.
    #[test]
    fn the_later_revision_is_read_defensively() {
        // A genuine page seen only in a picture: "be careful", and only because the
        // address couldn't be confirmed.
        let p = sample_incident("20261103T080542Z-e5f6");
        let last = p.last.as_ref().unwrap();
        assert_eq!(
            (last.verdict.as_deref(), last.confidence.as_deref()),
            (Some("suspicious"), Some("low"))
        );
        assert_eq!(last.floors, ["picture_only"]);
        assert!(last.unconfirmed_only && p.unconfirmed_only());
        assert!(last.advice.contains(&"check_with_file_or_app".to_string()));
        assert_eq!(
            p.judgement.as_ref().unwrap().verdict.as_deref(),
            Some("likely_safe")
        );
        let d = p.domain.as_ref().unwrap();
        assert_eq!(
            (
                d.result.as_deref(),
                d.digit_rule.as_deref(),
                d.shape_fit.as_deref(),
                d.shuffled_reading.as_deref(),
                d.first_reading_from.as_deref()
            ),
            (
                Some("match_trusted"),
                Some("not_evaluated"),
                None,
                None,
                Some("address_bar")
            )
        );
        // Every other sample says it isn't the milder kind.
        for id in [
            "20261030T184512Z-b0a1",
            "20261101T091500Z-a1b2",
            "20261102T143027Z-c3d4",
            "20261103T172009Z-g7h8",
            "20261104T194103Z-j9k0",
            "20261105T081233Z-k2m4",
            "20261105T103045Z-p6q8",
            "20261105T114502Z-r3s5",
            "20261105T115821Z-t4v6",
        ] {
            assert!(!sample_incident(id).unconfirmed_only(), "{id}");
        }
        assert!(!sample_incident("20261105T115934Z-w8x2").unconfirmed_only());
        // The window's address: which field the model's own reading came from, and the
        // digit rule firing on the exact text.
        let w = sample_incident("20261105T103045Z-p6q8");
        let d = w.domain.as_ref().unwrap();
        assert_eq!(
            (d.first_reading_from.as_deref(), d.digit_rule.as_deref()),
            (Some("address_bar"), Some("fired"))
        );
        assert_eq!(w.search.as_ref().unwrap().failed.as_deref(), Some(&[][..]));
        assert_eq!(w.prompt_version.as_deref(), Some("5"));
        // An email checked with the mail window it was open in: both supply links, and
        // three were exact repeats. Nothing was left out at a limit.
        let both = sample_incident("20261105T114502Z-r3s5");
        assert_eq!(both.input, ["email", "page"]);
        assert_eq!(
            (both.screenshot, both.message, both.sent_picture()),
            (false, true, Some(false))
        );
        assert_eq!(
            (
                both.links.as_ref().unwrap().len(),
                both.links_total,
                both.links_merged
            ),
            (4, Some(7), Some(3))
        );
        assert_eq!(both.links_left(), Some((0, 3)));
        assert_eq!(
            both.last.as_ref().unwrap().verdict.as_deref(),
            Some("likely_safe")
        );
        assert_eq!(both.email.as_ref().unwrap().signals, ["money_wording"]);
        // A second search for the official site, by the sender's name; a rule and fields
        // this sentry has no words for are kept as text or ignored.
        let news = sample_incident("20261105T115821Z-t4v6");
        let kinds: Vec<&str> = news
            .search
            .as_ref()
            .unwrap()
            .queries
            .iter()
            .map(|q| q.kind.as_str())
            .collect();
        assert_eq!(kinds, ["official", "official2", "domain"]);
        assert_eq!(news.last.as_ref().unwrap().floors, ["mail_label_spam"]);
        assert_eq!(news.links_left(), Some((0, 0)));

        // Hostile and broken, field by field. Never a failure.
        let id = Id::parse("20261105T081233Z-k2m4").unwrap();
        let text = fixture("suscheck/20261105T081233Z-k2m4/incident.json");
        let long = "x".repeat(5000);
        let len = |s: &Option<String>| s.as_ref().unwrap().chars().count();
        let mut v: Value = serde_json::from_str(&text).unwrap();
        v["email"]["from_written"] = format!("wr\u{1b}[2Jit\u{202e}ten\n{long}").into();
        v["email"]["freemail"] = format!("G\u{7}mail {long}").into();
        v["email"]["signals"] = serde_json::json!({
            "money_wording": "true",
            "random_address": 1,
            "names_disagree": true,
            "body_nearly_empty": true,
            "name_matches_address": null,
            "sig\u{1b}[31mnal_from\u{200b}_next_year": true,
            "another_new_one": false,
            format!("long_{long}"): true,
        });
        v["domain"]["first_reading_from"] = format!("fo\u{7}oter {long}").into();
        v["domain"]["shape_fit"] = "dif\u{1b}[2Jfers\u{202e}".into();
        v["domain"]["shuffled_reading"] = format!("sh\u{9b}31muffled.{long}").into();
        v["domain"]["digit_rule"] = serde_json::json!(["fired"]);
        v["search"]["failed"] = serde_json::json!(
            ["domain", 4, "pho\u{7}ne", null, {"a": 1}, long, "a", "b", "c", "d", "e"]
        );
        v["final"]["unconfirmed_only"] = "true".into();
        v["links_total"] = 500.into();
        v["links_merged"] = 120.into();
        v["stages_ms"]["shapes"] = 0.into();
        v["stages_ms"]["shuffle"] = "soon".into();
        let i = parse_incident(&v.to_string(), id).unwrap();
        let e = i.email.as_ref().unwrap();
        assert!(e.from_written.as_ref().unwrap().starts_with("written xxx"));
        assert_eq!((len(&e.from_written), len(&e.freemail)), (261, 25));
        assert!(e.freemail.as_ref().unwrap().starts_with("Gmail xxx"));
        // Only a literal `true` is a signal: the format's own first, in its order, then
        // one it doesn't name, cleaned and cut.
        assert_eq!(e.signals.len(), 4);
        assert_eq!(e.signals[..2], ["body_nearly_empty", "names_disagree"]);
        assert!(e.signals.contains(&"signal_from_next_year".to_string()));
        assert!(e.signals.iter().any(|s| s.chars().count() == 41));
        let d = i.domain.as_ref().unwrap();
        assert!(
            d.first_reading_from
                .as_ref()
                .unwrap()
                .starts_with("footer x")
        );
        assert_eq!(len(&d.first_reading_from), 31);
        assert_eq!(d.shape_fit.as_deref(), Some("differs"));
        assert!(
            d.shuffled_reading
                .as_ref()
                .unwrap()
                .starts_with("shuffled.x")
        );
        assert_eq!((len(&d.shuffled_reading), &d.digit_rule), (321, &None));
        let failed = i.search.as_ref().unwrap().failed.as_ref().unwrap();
        assert_eq!(failed.len(), 6);
        assert_eq!(failed[..2], ["domain", "phone"]);
        assert_eq!(failed[2].chars().count(), 21);
        // The milder verdict is said only by a literal `true`, and only of "be careful".
        assert!(!i.last.as_ref().unwrap().unconfirmed_only && !i.unconfirmed_only());
        v["final"]["unconfirmed_only"] = true.into();
        let i = parse_incident(&v.to_string(), id).unwrap();
        assert_eq!(
            i.last.as_ref().unwrap().verdict.as_deref(),
            Some("likely_malicious")
        );
        assert!(i.last.as_ref().unwrap().unconfirmed_only && !i.unconfirmed_only());
        // The format's own sum: 500 in all, 120 exact repeats, 2 listed: 378 at a limit.
        assert_eq!(i.links_left(), Some((378, 120)));
        assert_eq!(
            i.stages
                .iter()
                .filter(|s| ["shapes", "shuffle"].contains(&s.0))
                .collect::<Vec<_>>(),
            [&("shapes", Some(0))]
        );
        let all = format!("{i:?}");
        assert!(
            !all.chars()
                .any(|c| c == '\u{1b}' || c == '\u{7}' || invisible(c)),
            "{all}"
        );
        // More repeats than the total leaves beyond the list aren't believed; a count that
        // isn't one, or no list at all, and nothing is said of how they split.
        v["links_merged"] = 9000.into();
        assert_eq!(
            parse_incident(&v.to_string(), id).unwrap().links_left(),
            Some((0, 498))
        );
        v["links_total"] = 1.into();
        assert_eq!(
            parse_incident(&v.to_string(), id).unwrap().links_left(),
            Some((0, 0))
        );
        for gone in [Value::Null, "three".into(), (-3).into()] {
            let mut w = v.clone();
            w["links_merged"] = gone;
            let i = parse_incident(&w.to_string(), id).unwrap();
            assert_eq!((i.links_merged, i.links_left()), (None, None));
        }
        v["links"] = Value::Null;
        let i = parse_incident(&v.to_string(), id).unwrap();
        assert_eq!((i.links_merged, i.links_left()), (None, None));
        // Each new part null, or not what the format says: left out, the rest read.
        for (block, key) in [
            ("email", "signals"),
            ("email", "from_written"),
            ("email", "freemail"),
            ("search", "failed"),
            ("final", "unconfirmed_only"),
            ("domain", "shape_fit"),
            ("domain", "shuffled_reading"),
            ("domain", "digit_rule"),
            ("domain", "first_reading_from"),
        ] {
            for bad in [Value::Null, 3.into(), serde_json::json!({"a": [1]})] {
                let mut w: Value = serde_json::from_str(&text).unwrap();
                w[block][key] = bad;
                let i = parse_incident(&w.to_string(), id).unwrap();
                let (e, d) = (i.email.as_ref().unwrap(), i.domain.as_ref().unwrap());
                match key {
                    "signals" => assert!(e.signals.is_empty()),
                    "from_written" => assert!(e.from_written.is_none()),
                    "freemail" => assert!(e.freemail.is_none()),
                    "failed" => assert!(i.search.as_ref().unwrap().failed.is_none()),
                    "unconfirmed_only" => assert!(!i.unconfirmed_only()),
                    "shape_fit" => assert!(d.shape_fit.is_none()),
                    "shuffled_reading" => assert!(d.shuffled_reading.is_none()),
                    "digit_rule" => assert!(d.digit_rule.is_none()),
                    _ => assert!(d.first_reading_from.is_none()),
                }
                assert!(i.last.is_some() && i.links.is_some(), "{block}.{key}");
            }
        }
    }

    /// How a message reached SusCheck where the browser extension brought it, what the
    /// mail site showed for it, and the format's test for "the mail site has changed".
    #[test]
    fn how_the_mail_was_obtained_and_when_the_extension_is_falling_back() {
        let s = sample();
        // Nine made by hand or by the app (the oldest has no such key); the newsletter
        // came through the extension as the original message, out of the spam folder.
        let how: Vec<Option<&str>> = s.checks.iter().map(|c| c.acquired_by.as_deref()).collect();
        assert_eq!(how[..9], [None; 9]);
        assert_eq!(how[9], Some("original"));
        assert_eq!(how[10], None);
        let news = sample_incident("20261105T115821Z-t4v6");
        assert_eq!(
            (news.acquired_by.as_deref(), news.mail_label.as_deref()),
            (Some("original"), Some("spam"))
        );
        // The spam label is a remark: the verdict stood.
        let last = news.last.as_ref().unwrap();
        assert_eq!(last.floors, ["mail_label_spam"]);
        assert_eq!(
            (last.verdict.as_deref(), last.floors_changed),
            (Some("likely_safe"), Some(false))
        );
        let other = sample_incident("20261105T114502Z-r3s5");
        assert_eq!((&other.acquired_by, &other.mail_label), (&None, &None));
        assert!(!other.mail_window() && !news.mail_window());
        // One original and nothing after it: no fallback.
        assert_eq!((s.fallback(), s.counts().fallback), (None, None));

        // The rule, as the format gives it. `o`: the original; `f`: a fallback; the
        // number is how many hours ago (by the server's clock).
        let now = 1_000_000;
        let held = |spec: &[(char, i64)]| {
            let lines: Vec<(Option<i64>, bool)> = spec
                .iter()
                .map(|(kind, hours)| (Some(now - hours * 3600), *kind == 'o'))
                .collect();
            fallback_of(now, &lines)
        };
        let both = |run, day| Some(Fallback { run, day });
        for (what, spec, want) in [
            ("nothing through the extension", &[][..], None),
            (
                "only originals",
                &[('o', 90), ('o', 50), ('o', 2)][..],
                None,
            ),
            // The latest three, after an earlier original.
            (
                "three fallbacks after an original",
                &[('o', 200), ('f', 150), ('f', 100), ('f', 50)][..],
                both(3, 0),
            ),
            (
                "five, older than a day",
                &[
                    ('o', 300),
                    ('f', 250),
                    ('f', 200),
                    ('f', 150),
                    ('f', 100),
                    ('f', 50),
                ][..],
                both(5, 0),
            ),
            // Fewer than three, and not two within the day: one fallback means little.
            ("one fallback", &[('o', 100), ('f', 50)][..], None),
            ("one fallback today", &[('o', 100), ('f', 2)][..], None),
            (
                "two, one of them today",
                &[('o', 100), ('f', 50), ('f', 2)][..],
                None,
            ),
            // An original among the latest three.
            (
                "an original among the latest three",
                &[('o', 300), ('f', 200), ('f', 150), ('o', 100), ('f', 50)][..],
                None,
            ),
            (
                "the latest is the original",
                &[('f', 200), ('f', 150), ('f', 100), ('o', 50)][..],
                None,
            ),
            // No earlier original: the extension never got one here, so nothing changed.
            (
                "no earlier original",
                &[('f', 150), ('f', 100), ('f', 50)][..],
                None,
            ),
            (
                "no earlier original, today",
                &[('f', 5), ('f', 2)][..],
                None,
            ),
            // Every one of the last 24 hours, at least two of them.
            (
                "two today after an original",
                &[('o', 100), ('f', 5), ('f', 2)][..],
                both(2, 2),
            ),
            (
                "an original earlier today",
                &[('o', 20), ('f', 5), ('f', 2)][..],
                None,
            ),
            (
                "three, two of them today",
                &[('o', 100), ('f', 50), ('f', 5), ('f', 2)][..],
                both(3, 2),
            ),
        ] {
            assert_eq!(held(spec), want, "{what}");
        }
        // A line whose id is no date is in no day, and still one of the latest three.
        let undated = [
            (Some(now - 400_000), true),
            (None, false),
            (None, false),
            (Some(now - 60), false),
        ];
        assert_eq!(fallback_of(now, &undated), both(3, 0));

        // From the index: null, a missing key and a value the format doesn't name are
        // left out, wherever they stand; a failed check says how it was got and counts.
        let index = fixture("suscheck/index.jsonl");
        let last = index.lines().nth(9).unwrap();
        let line = |n: u32, how: &str| {
            let at = format!("202611{:02}T1200{:02}Z-aaaa", 1 + n / 60, n % 60);
            let l = last.replacen("20261105T115821Z-t4v6", &at, 1);
            match how {
                "missing" => l.replacen(",\"acquired_by\":\"original\"", "", 1),
                "null" => l.replacen("\"acquired_by\":\"original\"", "\"acquired_by\":null", 1),
                "failed" => l
                    .replacen("\"error\":null", "\"error\":\"model\"", 1)
                    .replacen(
                        "\"acquired_by\":\"original\"",
                        "\"acquired_by\":\"paste\"",
                        1,
                    ),
                how => l.replacen("\"original\"", &format!("\"{how}\""), 1),
            }
        };
        let read = |hows: &[&str]| {
            let body: String = hows
                .iter()
                .enumerate()
                .map(|(n, how)| line(n as u32, how) + "\n")
                .collect();
            let (checks, newer, skipped) = parse_index(&body);
            assert_eq!((checks.len(), newer, skipped), (hows.len(), None, 0));
            Suscheck {
                // (Long after: none of them is of the last day.)
                now: sample().now + 30 * 86_400,
                checks,
                ..sample()
            }
        };
        assert_eq!(
            read(&["original", "page", "paste", "picture"]).fallback(),
            both(3, 0)
        );
        assert_eq!(
            read(&[
                "original", "page", "null", "failed", "missing", "picture", "null"
            ])
            .fallback(),
            both(3, 0)
        );
        assert_eq!(
            read(&["original", "page", "null", "picture", "missing"]).fallback(),
            None
        );
        assert_eq!(read(&["null", "page", "paste", "picture"]).fallback(), None);
        assert_eq!(
            read(&["missing", "page", "paste", "picture"]).fallback(),
            None
        );
        // A word the format doesn't name is no known way: neither the original nor a
        // fallback, so it neither makes the three nor stands for the earlier original.
        assert_eq!(
            read(&["original", "page", "carrier", "paste"]).fallback(),
            None
        );
        assert_eq!(
            read(&["original", "page", "carrier", "paste", "picture"]).fallback(),
            both(3, 0)
        );
        assert_eq!(
            read(&["carrier", "page", "paste", "picture"]).fallback(),
            None
        );
        assert_eq!(
            read(&["original", "page", "paste", "original"]).fallback(),
            None
        );
        // What leaves for a report is those two numbers.
        let c = read(&["original", "page", "paste", "picture"]).counts();
        let text = serde_json::to_string(&c).unwrap();
        assert!(
            text.contains("\"fallback\":{\"run\":3,\"day\":0}"),
            "{text}"
        );
        assert!(
            !serde_json::to_string(&sample().counts())
                .unwrap()
                .contains("fallback")
        );
        // Hostile and broken values: cleaned, cut, or nothing. Never a failure.
        let odd = last.replacen(
            "\"original\"",
            "\"ori\\u001b[2Jgi\\u202enal of a long kind\"",
            1,
        );
        assert_eq!(
            parse_line(&odd).unwrap().acquired_by.as_deref(),
            Some("original of a lo…")
        );
        for bad in ["7", "[\"original\"]", "{\"a\":1}", "true", "\"\""] {
            let l = last.replacen(
                "\"acquired_by\":\"original\"",
                &format!("\"acquired_by\":{bad}"),
                1,
            );
            assert_eq!(parse_line(&l).unwrap().acquired_by, None, "{bad}");
        }
        let id = Id::parse("20261105T115821Z-t4v6").unwrap();
        let text = fixture("suscheck/20261105T115821Z-t4v6/incident.json");
        let mut v: Value = serde_json::from_str(&text).unwrap();
        v["acquired_by"] = "pa\u{7}ge\u{202e}".into();
        v["mail_label"] = format!("phi\u{1b}[31mshing_{}", "x".repeat(900)).into();
        v["page"] = serde_json::json!({"source": "exten\u{7}sion", "url_domain": "mail[.]example"});
        let i = parse_incident(&v.to_string(), id).unwrap();
        assert_eq!(i.acquired_by.as_deref(), Some("page"));
        assert_eq!(i.mail_label.as_ref().unwrap().chars().count(), 25);
        assert!(i.mail_label.as_ref().unwrap().starts_with("phishing_x"));
        assert!(i.mail_window());
        for bad in [Value::Null, 3.into(), serde_json::json!(["spam"])] {
            v["acquired_by"] = bad.clone();
            v["mail_label"] = bad;
            let i = parse_incident(&v.to_string(), id).unwrap();
            assert_eq!((&i.acquired_by, &i.mail_label), (&None, &None));
            assert!(i.last.is_some());
        }
    }

    /// The index's `unconfirmed_only`: a boolean says, anything else is unknown; and it
    /// is believed only beside a completed "be careful".
    #[test]
    fn the_index_says_which_be_careful_is_only_an_unconfirmed_address() {
        let index = fixture("suscheck/index.jsonl");
        let line = index.lines().nth(3).unwrap();
        const TAIL: &str =
            ",\"unconfirmed_only\":true,\"unconfirmed_kind\":\"picture\",\"trusted_sender\":false}";
        assert!(line.ends_with(TAIL));
        let with = |to: &str| parse_line(&line.replacen(TAIL, to, 1)).unwrap();
        for (to, want, said) in [
            (TAIL, Some(true), "be careful (picture only)"),
            // The other kinds, each short enough for the list; none, or a word this
            // sentry doesn't know, is the plain "unconfirmed".
            (
                ",\"unconfirmed_only\":true,\"unconfirmed_kind\":\"other_domain\"}",
                Some(true),
                "be careful (other domain)",
            ),
            (
                ",\"unconfirmed_only\":true,\"unconfirmed_kind\":\"small_sender\"}",
                Some(true),
                "be careful (small sender)",
            ),
            (
                ",\"unconfirmed_only\":true,\"unconfirmed_kind\":\"personal_address\"}",
                Some(true),
                "be careful (personal)",
            ),
            (
                ",\"unconfirmed_only\":true,\"unconfirmed_kind\":null}",
                Some(true),
                UNCONFIRMED_SHORT,
            ),
            (",\"unconfirmed_only\":true}", Some(true), UNCONFIRMED_SHORT),
            (
                ",\"unconfirmed_only\":true,\"unconfirmed_kind\":\"by_owl\"}",
                Some(true),
                UNCONFIRMED_SHORT,
            ),
            (
                ",\"unconfirmed_only\":true,\"unconfirmed_kind\":[\"picture\"]}",
                Some(true),
                UNCONFIRMED_SHORT,
            ),
            // A kind beside a "be careful" that isn't the milder one says nothing.
            (
                ",\"unconfirmed_only\":false,\"unconfirmed_kind\":\"picture\"}",
                Some(false),
                "be careful",
            ),
            // Unknown, never false: null, no key, and what isn't a boolean.
            (",\"unconfirmed_only\":null}", None, "be careful"),
            ("}", None, "be careful"),
            (",\"unconfirmed_only\":\"true\"}", None, "be careful"),
            (",\"unconfirmed_only\":1}", None, "be careful"),
            (",\"unconfirmed_only\":[true]}", None, "be careful"),
        ] {
            let c = with(to);
            assert_eq!(c.unconfirmed_only, want, "{to}");
            assert_eq!(c.mild(), said != "be careful", "{to}");
            assert_eq!(c.outcome(), said, "{to}");
            // (Every word fits the list's column of 26.)
            assert!(said.chars().count() <= 26, "{said}");
        }
        // Beside another verdict, or on a check that failed, the line isn't believed.
        let other =
            parse_line(&line.replacen("\"suspicious\"", "\"likely_malicious\"", 1)).unwrap();
        assert!(!other.mild() && other.outcome() == "don't trust this");
        let failed =
            parse_line(&line.replacen("\"error\":null", "\"error\":\"model\"", 1)).unwrap();
        assert!(!failed.mild() && failed.outcome() == "failed (model)");
        // The tallies tell the two apart where the index does, and nothing else moves:
        // it is still a "be careful", and never something to look at.
        let s = sample();
        let week = s.tally(7);
        assert_eq!((week.suspicious, week.unconfirmed), (3, 1));
        let mut older = s.clone();
        for c in &mut older.checks {
            c.unconfirmed_only = None;
        }
        let then = older.tally(7);
        assert_eq!((then.suspicious, then.unconfirmed), (3, 0));
        assert_eq!(s.unseen(None), older.unseen(None));
        // A stored report from before the count reads back.
        let old: Tally = serde_json::from_str(
            "{\"total\":2,\"malicious\":0,\"suspicious\":2,\"safe\":0,\"other\":0,\"errors\":0,\"incomplete\":0,\"floors\":0}",
        )
        .unwrap();
        assert_eq!((old.suspicious, old.unconfirmed), (2, 0));
        // Which readings are held against which: the two readings of the picture are full
        // hosts; the text recogniser's and the shuffled one are registrable domains, the
        // first reading's own when it is that text or the end of it after a dot.
        for (first, domain, want) in [
            (Some("www.example-pay.test"), "example-pay.test", Some(true)),
            (Some("example-pay.test"), "example-pay.test", Some(true)),
            (Some("WWW.Example-Pay.test"), "example-pay.TEST", Some(true)),
            (
                Some("www.example-pay.test"),
                "examp1e-pay.test",
                Some(false),
            ),
            (Some("notexample-pay.test"), "example-pay.test", Some(false)),
            (
                Some("example-pay.test"),
                "www.example-pay.test",
                Some(false),
            ),
            (None, "example-pay.test", None),
        ] {
            assert_eq!(
                Incident::same_domain(first, domain),
                want,
                "{first:?} {domain}"
            );
        }
    }

    /// The two generations the samples don't hold, each as a record made by hand from the
    /// format's list of what it added (synthetic values). A reader decides field by field:
    /// nothing is inferred from `prompt_version` or the date.
    #[test]
    fn the_generations_between_the_first_and_today_read_field_by_field() {
        // Generation 2 (exact text): the index line ends at `input`.
        let line2 = r#"{"schema":1,"id":"20260901T101010Z-g2g2","time":"2026-09-01T10:10:10Z","device":"Den PC","client":"web","app_version":"","kind":"email","brand":"Example Pay","domain":"example-pay.test","domain_check":"match_search","verdict":"suspicious","confidence":"medium","incomplete":false,"floors_changed_verdict":true,"duration_ms":9000,"error":null,"input":"email"}"#;
        let c = parse_line(line2).unwrap();
        assert_eq!(c.input.as_deref(), Some("email"));
        assert_eq!(
            (&c.acquired_by, c.unconfirmed_only, c.mild()),
            (&None, None, false)
        );
        assert_eq!(c.outcome(), "be careful");
        let gen2 = serde_json::json!({
            "schema": 1, "id": "20260901T101010Z-g2g2", "time": "2026-09-01T10:10:10Z",
            "device": "Den PC", "client": "web", "app_version": "", "duration_ms": 9000,
            "error": null, "model": "example-vision:1b",
            // (Whatever it says: nothing is read off it.)
            "prompt_version": "3",
            "stages_ms": {"extract": 2000, "reread": null, "ocr": 0, "search": 1500, "judge": 5500},
            "facts": {"kind": "email", "claimed_brand": "Example Pay", "sender_name": "Example Pay",
                "sender_address": "service@examp1e-pay.test", "address_bar_domain": null,
                "link_texts": ["Pay now"], "phone_numbers": [], "asks_for": ["payment"],
                "urgency": false, "talks_to_ai": false},
            "domain": {"first_reading": null, "second_reading": null, "ocr_reading": null,
                "ocr_available": false,
                "check": {"result": "unknown", "shown": "examp1e-pay.test",
                    "real": "example-pay.test", "why": "digit_in_name"},
                "source": "email_header", "exact": "examp1e-pay.test"},
            "search": {"ok": false, "queries": [["official", "\"Example Pay\" official website"]],
                "results": {"official": []}},
            "judgement": {"red_flags": [], "looks_normal": [], "incomplete": false,
                "confidence": "medium", "verdict": "likely_safe", "advice": []},
            "model_raw": {"extract": "{}", "judge": "{}"},
            "final": {"verdict": "suspicious", "confidence": "medium", "incomplete": true,
                "reasons": ["The address has a number in the middle of a word."],
                "advice": ["do_not_pay", "ask_for_help"],
                "floors": ["digit_in_name", "unknown", "search_down"],
                "floors_changed_verdict": true},
            "input": ["email"],
            "email": {"from_name": "Example Pay", "from_address": "service@examp1e-pay.test",
                "reply_to": null, "return_path": null, "subject": "Invoice",
                "date": "Tue, 01 Sep 2026 10:00:00 +0000",
                "auth": {"spf": "pass", "dkim": null, "dmarc": "none"},
                "attachments": [], "attachments_total": 0, "links_total": 3, "aimed_at_ai": false},
            "links": [{"text": "Pay now", "scheme": "https",
                "target_domain": "examp1e-pay[.]test", "flags": []}],
            "links_total": 3, "page": null, "screenshot": false, "message": true
        });
        let id2 = Id::parse("20260901T101010Z-g2g2").unwrap();
        let i = parse_incident(&gen2.to_string(), id2).unwrap();
        assert_eq!(i.input, ["email"]);
        assert!(i.message && !i.screenshot && i.sent_email());
        // Null is a stage that did not run, 0 one that ran (not the first release's 0);
        // the later stages aren't named at all.
        assert_eq!(
            i.stages,
            [
                ("extract", Some(2000)),
                ("reread", None),
                ("ocr", Some(0)),
                ("search", Some(1500)),
                ("judge", Some(5500))
            ]
        );
        let d = i.domain.as_ref().unwrap();
        assert_eq!(
            (d.source.as_deref(), d.exact.as_deref(), d.ocr_available),
            (Some("email_header"), Some("examp1e-pay.test"), Some(false))
        );
        // What generation 3 added isn't there: each missing field as the format says.
        assert_eq!(
            (
                &d.shape_fit,
                &d.shuffled_reading,
                &d.digit_rule,
                &d.first_reading_from
            ),
            (&None, &None, &None, &None)
        );
        assert!(!i.unconfirmed_only());
        assert_eq!(
            (i.links_merged, i.links_left(), i.links_more()),
            (None, None, 2)
        );
        let search = i.search.as_ref().unwrap();
        assert_eq!((search.ok, &search.failed), (Some(false), &None));
        let e = i.email.as_ref().unwrap();
        assert!(e.signals.is_empty() && e.from_written.is_none() && e.freemail.is_none());
        assert_eq!(e.auth[0].as_deref(), Some("pass"));
        assert_eq!((&i.acquired_by, &i.mail_label), (&None, &None));

        // Generation 3 (the picture cap and the extra readings): the index line still ends
        // at `input`, so whether its "be careful" is the milder kind is unknown there, and
        // the record says.
        let line3 = r#"{"schema":1,"id":"20261001T101010Z-g3g3","time":"2026-10-01T10:10:10Z","device":"Den PC","client":"app","app_version":"0.1.0","kind":"web_page","brand":"Example","domain":"example.com","domain_check":"match_search","verdict":"suspicious","confidence":"low","incomplete":false,"floors_changed_verdict":true,"duration_ms":16000,"error":null,"input":"image"}"#;
        let c = parse_line(line3).unwrap();
        assert_eq!((c.unconfirmed_only, c.mild()), (None, false));
        assert_eq!(
            (c.outcome(), &c.acquired_by),
            ("be careful".to_string(), &None)
        );
        let gen3 = serde_json::json!({
            "schema": 1, "id": "20261001T101010Z-g3g3", "time": "2026-10-01T10:10:10Z",
            "device": "Den PC", "client": "app", "app_version": "0.1.0", "duration_ms": 16000,
            "error": null, "model": "example-vision:1b",
            // (A build from the middle of the generation: nothing is read off this.)
            "prompt_version": "2",
            "stages_ms": {"extract": 3000, "reread": 2500, "ocr": 40, "shapes": 0,
                "shuffle": 2100, "search": 1400, "judge": 7000},
            "facts": {"kind": "web_page", "claimed_brand": "Example", "sender_name": null,
                "sender_address": null, "address_bar_domain": "www.example.com",
                "link_texts": [], "phone_numbers": [], "asks_for": [], "urgency": false,
                "talks_to_ai": false},
            "domain": {"first_reading": "www.example.com", "second_reading": "www.example.com",
                "ocr_reading": "example.com", "ocr_available": true, "shape_fit": "touching",
                "shuffled_reading": "example.com", "digit_rule": "clear",
                "check": {"result": "match_search", "shown": "example.com",
                    "real": "example.com", "why": "exact"},
                "first_reading_from": "address_bar", "source": "screenshot", "exact": null},
            "search": {"ok": true,
                "queries": [["official", "\"Example\" official website"],
                    ["official2", "\"Example Shop\" official website"]],
                "results": {"official": [], "official2": []}, "failed": ["official2"]},
            "judgement": {"red_flags": [], "looks_normal": [], "incomplete": false,
                "confidence": "medium", "verdict": "likely_safe", "advice": ["no_action_needed"]},
            "model_raw": {"extract": "{}", "judge": "{}"},
            "final": {"verdict": "suspicious", "confidence": "low", "incomplete": false,
                "reasons": ["I could only read the address from a picture."],
                "advice": ["check_with_file_or_app", "type_address_yourself"],
                "floors": ["picture_only"], "floors_changed_verdict": true,
                "unconfirmed_only": true},
            "input": ["image"], "email": null, "links": null, "links_total": null,
            "links_merged": null, "page": null, "screenshot": true, "message": false
        });
        let id3 = Id::parse("20261001T101010Z-g3g3").unwrap();
        let i = parse_incident(&gen3.to_string(), id3).unwrap();
        assert!(
            i.unconfirmed_only(),
            "the record says what its index line doesn't"
        );
        let d = i.domain.as_ref().unwrap();
        assert_eq!(
            (
                d.shape_fit.as_deref(),
                d.shuffled_reading.as_deref(),
                d.digit_rule.as_deref(),
                d.first_reading_from.as_deref()
            ),
            (
                Some("touching"),
                Some("example.com"),
                Some("clear"),
                Some("address_bar")
            )
        );
        // The shuffled and the recogniser's readings are the first reading's own domain.
        for reading in [&d.shuffled_reading, &d.ocr_reading] {
            assert_eq!(
                Incident::same_domain(d.first_reading.as_deref(), reading.as_deref().unwrap()),
                Some(true)
            );
        }
        assert_eq!(i.stages.len(), 7);
        assert_eq!(i.stages[3], ("shapes", Some(0)));
        assert_eq!(
            i.search.as_ref().unwrap().failed.as_deref(),
            Some(&["official2".to_string()][..])
        );
        assert_eq!((i.links_merged, i.links_left()), (None, None));
        assert_eq!((&i.acquired_by, &i.mail_label), (&None, &None));
        // The same record claiming another prompt version or id date reads the same.
        let mut other = gen3.clone();
        other["prompt_version"] = "1".into();
        let j = parse_incident(&other.to_string(), id3).unwrap();
        assert_eq!(
            (&j.stages, &j.domain, &j.last),
            (&i.stages, &i.domain, &i.last)
        );
        // And the first release's shape is told by the missing `input` key alone: this one
        // without it has its 0 read as "did not run".
        other.as_object_mut().unwrap().remove("input");
        let j = parse_incident(&other.to_string(), id3).unwrap();
        assert_eq!(j.stages[3], ("shapes", None));
        assert_eq!(j.input, ["image"]);
    }

    /// The senders the owner trusts (`trusted.json`: the list as it is now), the owner
    /// computers, and what a record says of a trusted sender, of why an address couldn't
    /// be confirmed, of how the comparison was put to the model and of a message's faults.
    #[test]
    fn trusted_senders_owners_and_what_the_latest_records_add() {
        let s = sample();
        let list = s.trusted.ok().unwrap();
        assert_eq!((list.senders.len(), list.more, list.total()), (2, 0, 2));
        let at = |t: &str| Some(t.parse::<jiff::Timestamp>().unwrap().as_second());
        assert_eq!(
            list.senders,
            [
                Trusted {
                    kind: Some("domain".into()),
                    value: "riverside-allotments.test".into(),
                    label: Some("Riverside Allotments".into()),
                    added_at: at("2026-11-04T18:20:05Z"),
                    added_by: Some("Kitchen iMac".into()),
                },
                Trusted {
                    kind: Some("address".into()),
                    value: "jo-bloggs@freemail.test".into(),
                    label: Some("Jo Bloggs".into()),
                    added_at: at("2026-11-04T18:31:40Z"),
                    added_by: Some("command line".into()),
                },
            ]
        );
        // What leaves for a report is how many, never who.
        let counts = serde_json::to_string(&s.counts()).unwrap();
        assert!(counts.contains("\"trusted\":2"), "{counts}");
        assert!(
            !counts.contains("riverside") && !counts.contains("Jo"),
            "{counts}"
        );
        // One owner computer.
        let owners: Vec<&str> = s
            .devices
            .ok()
            .unwrap()
            .iter()
            .filter(|d| d.owner)
            .map(|d| d.name.as_str())
            .collect();
        assert_eq!(owners, ["Kitchen iMac"]);
        // No file: no list, and nothing wrong. A fresh install, and one from before.
        assert_eq!(parse_trusted(""), Part::Missing);
        let out = format!("@@{MARK}:now\n1793880000\n@@{MARK}:status\n\n@@{MARK}:index\n");
        let Read::Folder(f) = parse(&out, MARK, 200).unwrap() else {
            panic!()
        };
        assert_eq!(
            (f.trusted.clone(), f.counts().trusted, f.newer()),
            (Part::Missing, 0, None)
        );
        // A schema this sentry doesn't know: said, nothing of it shown or counted.
        let text = fixture("suscheck/trusted.json");
        let newer = parse_trusted(&text.replacen("\"schema\": 1", "\"schema\": 2", 1));
        assert_eq!(newer, Part::Newer(2));
        let folder = Suscheck {
            trusted: newer,
            ..sample()
        };
        assert_eq!(
            (
                folder.newer(),
                folder.counts().schema,
                folder.counts().trusted
            ),
            (Some(2), Some(2), 0)
        );
        for damaged in [
            "nope",
            "[1]",
            "{\"senders\": []}",
            "{\"schema\": 1}",
            "{\"schema\": 1, \"senders\": 4}",
        ] {
            assert_eq!(parse_trusted(damaged), Part::Damaged, "{damaged}");
        }
        assert_eq!(
            parse_trusted("{\"schema\": 1, \"senders\": []}"),
            Part::Ok(TrustedList::default())
        );
        // Hostile and broken entries: cleaned, cut, or left out; past the cap, counted.
        let long = "x".repeat(900);
        let mut v: Value = serde_json::from_str(&text).unwrap();
        v["senders"] = Value::Array(
            [
                serde_json::json!({"kind": "do\u{1b}[2Jmain\u{202e}", "value": format!("ev\u{7}il.{long}"),
                    "label": format!("Ig\u{1b}]0;x\u{7}nore\nprior {long}"), "added_at": "soon",
                    "added_by": format!("Kit\u{200b}chen {long}")}),
                serde_json::json!({"kind": 3, "value": "plain.test", "label": "", "added_by": null}),
                serde_json::json!({"kind": "address", "value": 7}),
                serde_json::json!("not an entry"),
                Value::Null,
            ]
            .into_iter()
            .chain((0..300).map(|n| serde_json::json!({"kind": "domain", "value": format!("d{n}.test")})))
            .collect(),
        );
        let Part::Ok(l) = parse_trusted(&v.to_string()) else {
            panic!()
        };
        let len = |s: &Option<String>| s.as_ref().unwrap().chars().count();
        let first = &l.senders[0];
        assert_eq!(first.kind.as_deref(), Some("domain"));
        assert!(first.value.starts_with("evil.xxx") && first.value.chars().count() == 261);
        assert!(
            first
                .label
                .as_ref()
                .unwrap()
                .starts_with("Ignore prior xxx")
        );
        assert_eq!(
            (len(&first.label), len(&first.added_by), first.added_at),
            (85, 41, None)
        );
        assert_eq!(
            l.senders[1],
            Trusted {
                value: "plain.test".into(),
                ..Default::default()
            }
        );
        // (Three of the first 200 weren't entries; 105 were past the cap.)
        assert_eq!(
            (l.senders.len(), l.more, l.total()),
            (TRUSTED_MAX - 3, 105, 302)
        );
        let all = format!("{l:?}");
        assert!(
            !all.chars()
                .any(|c| c == '\u{1b}' || c == '\u{7}' || invisible(c))
        );
        // An owner is said only by a literal `true`; a file from before doesn't say.
        let devices = fixture("suscheck/devices.json");
        for (to, want) in [
            ("true", true),
            ("false", false),
            ("\"true\"", false),
            ("1", false),
            ("null", false),
        ] {
            let d =
                parse_devices(&devices.replacen("\"owner\": true", &format!("\"owner\": {to}"), 1));
            assert_eq!(d.ok().unwrap()[1].owner, want, "{to}");
        }
        let before = devices
            .replace(",\n   \"owner\": true", "")
            .replace(",\n   \"owner\": false", "");
        assert!(!before.contains("owner"));
        assert!(
            parse_devices(&before)
                .ok()
                .unwrap()
                .iter()
                .all(|d| !d.owner)
        );

        // The index: a trusted sender on the newest line; null (the failed check) and a
        // missing key (the oldest line) are false.
        let trusted: Vec<bool> = s.checks.iter().map(Check::trusted).collect();
        assert_eq!(trusted.iter().filter(|t| **t).count(), 1);
        assert!(trusted[10] && s.checks[10].outcome() == "no obvious warning signs");
        assert_eq!(
            (s.checks[5].trusted_sender, s.checks[0].trusted_sender),
            (None, None)
        );
        assert_eq!(s.checks[3].unconfirmed_kind.as_deref(), Some("picture"));
        assert!(s.checks[..3].iter().all(|c| c.unconfirmed_kind.is_none()));
        let index = fixture("suscheck/index.jsonl");
        let line = index.lines().nth(10).unwrap();
        assert!(line.ends_with("\"trusted_sender\":true}"));
        for bad in ["\"true\"", "1", "null", "[true]"] {
            let l = line.replacen(
                "\"trusted_sender\":true",
                &format!("\"trusted_sender\":{bad}"),
                1,
            );
            assert!(!parse_line(&l).unwrap().trusted(), "{bad}");
        }
        let failed = line.replacen("\"error\":null", "\"error\":\"model\"", 1);
        assert!(!parse_line(&failed).unwrap().trusted());

        // The record of the club's notice: trusted, and that is what it rests on.
        let club = sample_incident("20261105T115934Z-w8x2");
        let last = club.last.as_ref().unwrap();
        assert!(last.trusted_sender && last.unconfirmed_kind.is_none());
        assert_eq!(last.verdict.as_deref(), Some("likely_safe"));
        let d = club.domain.as_ref().unwrap();
        assert_eq!(
            (
                d.result.as_deref(),
                d.why.as_deref(),
                d.judge_word.as_deref()
            ),
            (Some("match_trusted"), Some("trusted_sender"), Some("match"))
        );
        let e = club.email.as_ref().unwrap();
        assert_eq!(
            (e.defects.as_deref(), e.defects_notable.as_deref()),
            (Some(&[][..]), Some(&[][..]))
        );
        assert!(club.message && !club.screenshot);
        // The picture-only check says why it couldn't be confirmed.
        let alone = sample_incident("20261103T080542Z-e5f6");
        assert_eq!(
            alone.last.as_ref().unwrap().unconfirmed_kind.as_deref(),
            Some("picture")
        );
        assert_eq!(
            alone.domain.as_ref().unwrap().judge_word.as_deref(),
            Some("match")
        );
        // The badly built email: one notable fault, as the record says, and the remark.
        let bad = sample_incident("20261105T081233Z-k2m4");
        let e = bad.email.as_ref().unwrap();
        assert_eq!(
            e.defects.as_deref(),
            Some(&["no_closing_boundary".to_string()][..])
        );
        assert_eq!(e.notable(), (vec!["no_closing_boundary"], true));
        assert_eq!(
            bad.last.as_ref().unwrap().floors.last().map(String::as_str),
            Some("message_faults")
        );
        // A failed check and a picture have neither; the old shape has none of it.
        assert!(
            sample_incident("20261104T194103Z-j9k0")
                .domain
                .is_none_or(|d| d.judge_word.is_none())
        );
        let old = sample_incident("20261030T184512Z-b0a1");
        assert!(
            old.domain.as_ref().unwrap().judge_word.is_none()
                && !old.last.as_ref().unwrap().trusted_sender
        );

        // Hostile and broken, field by field.
        let id = Id::parse("20261105T081233Z-k2m4").unwrap();
        let text = fixture("suscheck/20261105T081233Z-k2m4/incident.json");
        let mut v: Value = serde_json::from_str(&text).unwrap();
        v["final"]["trusted_sender"] = "true".into();
        v["final"]["unconfirmed_kind"] = format!("pic\u{1b}[2Jture_{long}").into();
        v["domain"]["judge_word"] = format!("ma\u{7}tch\u{202e} {long}").into();
        v["email"]["defects"] = Value::Array(
            [
                "bad_base64".into(),
                4.into(),
                "ot\u{7}her".into(),
                Value::Null,
                "fault_from_next_year".into(),
                long.clone().into(),
            ]
            .into_iter()
            .chain((0..40).map(|n| format!("f{n}").into()))
            .collect(),
        );
        v.as_object_mut().unwrap()["email"]
            .as_object_mut()
            .unwrap()
            .remove("defects_notable");
        let i = parse_incident(&v.to_string(), id).unwrap();
        let last = i.last.as_ref().unwrap();
        assert!(!last.trusted_sender);
        assert_eq!(last.unconfirmed_kind.as_ref().unwrap().chars().count(), 25);
        assert!(
            last.unconfirmed_kind
                .as_ref()
                .unwrap()
                .starts_with("picture_x")
        );
        let d = i.domain.as_ref().unwrap();
        assert!(d.judge_word.as_ref().unwrap().starts_with("match x"));
        assert_eq!(d.judge_word.as_ref().unwrap().chars().count(), 25);
        let e = i.email.as_ref().unwrap();
        let faults = e.defects.as_ref().unwrap();
        assert_eq!(faults.len(), DEFECTS_MAX);
        assert_eq!(faults[..3], ["bad_base64", "other", "fault_from_next_year"]);
        assert_eq!(faults[3].chars().count(), 31);
        // A record with faults and no word on which were notable (the last builds before
        // the split): today's notable set says, and a word in neither set is minor.
        assert_eq!(e.defects_notable, None);
        assert_eq!(e.notable(), (vec!["bad_base64"], false));
        // The record's own split is believed over today's sets.
        v["email"]["defects_notable"] = serde_json::json!(["other"]);
        let i = parse_incident(&v.to_string(), id).unwrap();
        assert_eq!(i.email.as_ref().unwrap().notable(), (vec!["other"], true));
        for (block, key) in [
            ("email", "defects"),
            ("email", "defects_notable"),
            ("domain", "judge_word"),
            ("final", "unconfirmed_kind"),
            ("final", "trusted_sender"),
        ] {
            for wrong in [Value::Null, 3.into(), serde_json::json!({"a": 1})] {
                let mut w: Value = serde_json::from_str(&text).unwrap();
                w[block][key] = wrong;
                let i = parse_incident(&w.to_string(), id).unwrap();
                let (e, d, l) = (
                    i.email.as_ref().unwrap(),
                    i.domain.as_ref().unwrap(),
                    i.last.as_ref().unwrap(),
                );
                match key {
                    // (Not recorded is unknown: not "no faults".)
                    "defects" => {
                        assert!(e.defects.is_none() && e.notable().0 == ["no_closing_boundary"])
                    }
                    "defects_notable" => assert!(
                        e.defects_notable.is_none()
                            && e.notable() == (vec!["no_closing_boundary"], false)
                    ),
                    "judge_word" => assert!(d.judge_word.is_none()),
                    "unconfirmed_kind" => assert!(l.unconfirmed_kind.is_none()),
                    _ => assert!(!l.trusted_sender),
                }
            }
        }
        let mut w: Value = serde_json::from_str(&text).unwrap();
        w["email"].as_object_mut().unwrap().remove("defects");
        w["email"]
            .as_object_mut()
            .unwrap()
            .remove("defects_notable");
        let e = parse_incident(&w.to_string(), id).unwrap().email.unwrap();
        assert_eq!(
            (e.defects.clone(), e.notable()),
            (None, (Vec::new(), false))
        );

        // The two later generations the samples don't hold, made by hand from the newest
        // records by taking away what came after each (the earlier two are in
        // `the_generations_between_the_first_and_today_read_field_by_field`). Field by
        // field: nothing is read off `prompt_version`.
        // Generation 4 (the browser extension): no trusted senders, kinds or faults.
        let index = fixture("suscheck/index.jsonl");
        let line4 = index.lines().nth(9).unwrap().replacen(
            ",\"unconfirmed_kind\":null,\"trusted_sender\":false",
            "",
            1,
        );
        assert!(line4.ends_with("\"unconfirmed_only\":false}"));
        let c = parse_line(&line4).unwrap();
        assert_eq!(
            (c.acquired_by.as_deref(), c.trusted(), &c.unconfirmed_kind),
            (Some("original"), false, &None)
        );
        let strip = |text: &str, generation: u8| {
            let mut v: Value = serde_json::from_str(text).unwrap();
            v["prompt_version"] = "9".into();
            v["email"]
                .as_object_mut()
                .unwrap()
                .remove("defects_notable");
            v["final"]["floors"]
                .as_array_mut()
                .unwrap()
                .retain(|f| f != "message_faults");
            if generation == 4 {
                v["email"].as_object_mut().unwrap().remove("defects");
                v["domain"].as_object_mut().unwrap().remove("judge_word");
                for k in ["trusted_sender", "unconfirmed_kind"] {
                    v["final"].as_object_mut().unwrap().remove(k);
                }
            }
            v.to_string()
        };
        let news = Id::parse("20261105T115821Z-t4v6").unwrap();
        let g4 = parse_incident(
            &strip(&fixture("suscheck/20261105T115821Z-t4v6/incident.json"), 4),
            news,
        )
        .unwrap();
        assert_eq!(
            (g4.acquired_by.as_deref(), g4.mail_label.as_deref()),
            (Some("original"), Some("spam"))
        );
        let (l, d, e) = (
            g4.last.as_ref().unwrap(),
            g4.domain.as_ref().unwrap(),
            g4.email.as_ref().unwrap(),
        );
        assert!(!l.trusted_sender && l.unconfirmed_kind.is_none() && d.judge_word.is_none());
        assert_eq!(
            (e.defects.clone(), e.notable()),
            (None, (Vec::new(), false))
        );
        assert_eq!(e.signals, ["money_wording"]);
        // Generation 5 (trusted senders and kinds; in its last builds, faults recorded
        // with no word on which were notable, and no remark).
        let g5 = parse_incident(&strip(&text, 5), id).unwrap();
        let e = g5.email.as_ref().unwrap();
        assert_eq!(e.notable(), (vec!["no_closing_boundary"], false));
        assert!(
            !g5.last
                .as_ref()
                .unwrap()
                .floors
                .contains(&"message_faults".to_string())
        );
        assert_eq!(
            g5.domain.as_ref().unwrap().judge_word.as_deref(),
            Some("mismatch")
        );
        let club5 = parse_incident(
            &strip(&fixture("suscheck/20261105T115934Z-w8x2/incident.json"), 5),
            Id::parse("20261105T115934Z-w8x2").unwrap(),
        )
        .unwrap();
        assert!(club5.last.as_ref().unwrap().trusted_sender);
        assert_eq!(
            club5.email.as_ref().unwrap().defects.as_deref(),
            Some(&[][..])
        );
        // And the script reads the list in the same one exec.
        let sh = script("/srv/x", 50, MARK);
        assert!(
            sh.contains("for f in status.json devices.json trusted.json index.jsonl"),
            "{sh}"
        );
        assert!(
            sh.contains("echo \"${m}trusted\"; [ ! -f \"$d/trusted.json\" ] || head -c 524288"),
            "{sh}"
        );
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
