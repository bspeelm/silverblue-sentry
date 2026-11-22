//! Backups of the router's configuration, encrypted before they touch this machine's disk.
//!
//! The router makes the archive (`sysupgrade --create-backup -`: a read, it writes nothing
//! there) and its bytes go from ssh straight into the age encryptor (the `age` crate, built
//! in: no `age` binary is needed) and on into a temporary file in the backups directory,
//! renamed into place when all of it arrived. sentry holds only public recipients
//! (`backup.recipients`), so it can make a backup and tell whether the config changed
//! without ever being able to read one.
//!
//! `<data>/networks/<name>/backups/` (0700) holds, for each backup:
//! - `<stamp>-<release>.tar.gz.age` (0600): the archive, encrypted;
//! - `<stamp>.manifest`: `<tag>  <path>` for every file in it, the tag a keyed hash
//!   ([`Salt::tag`]) of the file's sha256, never the hash itself (some of those files are
//!   secrets, and a plain hash of a short one can be guessed at);
//! - `<stamp>.uci`: the configuration as `uci show` gives it, secrets already tags.
//!
//! The two plain files are what "changed since the last backup" is read from: nothing is
//! decrypted for it. Everything that runs `sysupgrade` there takes its [`Turn`] first: two
//! at once spoil each other. That directory holds the Wi-Fi passphrase and the router's private
//! keys (encrypted): Claude's profiles must deny it ([`backups_dir`]).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::collect::CollectError;
use crate::collect::uci::Uci;
use crate::redact::{self, Salt};
use crate::remote::Router;
use sentry_app::remote::Remote;

/// Where a network's backups are kept. Never readable by Claude: a profile built for a
/// network denies this directory.
pub fn backups_dir(scope: &str) -> PathBuf {
    sentry_core::maint::data_root(scope).join("backups")
}

/// What a backup can't be made without, said the same everywhere.
pub const NO_RECIPIENTS: &str = "no backup recipient: set backup.recipients in \
     network_config.yaml (`sentry-network backup key <file>` makes a key and prints its line)";

/// The archive, from the router's stdout.
pub const CREATE: &[&str] = &["--create-backup", "-"];

/// Every file a backup holds, with its sha256.
pub const DIGEST: &str = "sysupgrade -l | xargs sha256sum";

/// How an age file starts.
const AGE_MAGIC: &[u8] = b"age-encryption.org/v1\n";

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum Error {
    /// Nothing to encrypt to: the config names no recipient.
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Failed(String),
}

fn failed(e: impl std::fmt::Display) -> Error {
    Error::Failed(e.to_string())
}

// ---- recipients

/// One `backup.recipients` entry as recipients: an age public key (`age1…`), or a file
/// holding one a line (`#` comments). ssh keys aren't taken: that would build in RSA and
/// the ssh key formats for something `backup key` does in one line.
pub fn recipient(entry: &str) -> Result<Vec<age::x25519::Recipient>, String> {
    let e = entry.trim();
    let one = |s: &str| {
        s.parse::<age::x25519::Recipient>()
            .map_err(|_| format!("`{s}` isn't a whole age recipient (age1… is 62 characters)"))
    };
    if e.starts_with("age1") {
        return Ok(vec![one(e)?]);
    }
    if e.starts_with("ssh-") {
        return Err(format!(
            "`{}…` is an ssh key: backups take age recipients only (age1…); \
             `sentry-network backup key <file>` makes one",
            e.chars().take(20).collect::<String>()
        ));
    }
    if e.starts_with('/') || e.starts_with('~') {
        let p = match e.strip_prefix("~/") {
            Some(rest) => sentry_core::paths::home().join(rest),
            None => PathBuf::from(e),
        };
        let text =
            std::fs::read_to_string(&p).map_err(|_| format!("recipient file {e} isn't there"))?;
        if text.contains("AGE-SECRET-KEY-") {
            return Err(format!(
                "{e} holds a secret key: name its public key (the `# public key:` line) instead"
            ));
        }
        let found: Vec<_> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(one)
            .collect::<Result<_, _>>()
            .map_err(|err| format!("{e}: {err}"))?;
        if found.is_empty() {
            return Err(format!("recipient file {e} holds no age recipient"));
        }
        return Ok(found);
    }
    Err(format!(
        "`{e}` isn't an age recipient (age1…) or a file holding one"
    ))
}

/// Everyone a backup is encrypted to. None configured: [`Error::Unavailable`].
pub fn recipients(cfg: &[String]) -> Result<Vec<age::x25519::Recipient>, Error> {
    if cfg.is_empty() {
        return Err(Error::Unavailable(NO_RECIPIENTS.into()));
    }
    let mut out = Vec::new();
    for e in cfg {
        out.extend(recipient(e).map_err(Error::Failed)?);
    }
    Ok(out)
}

// ---- what's kept

/// One backup in the directory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Kept {
    /// `20261026T115500Z`: its name, and its sidecars'.
    pub stamp: String,
    pub at: Timestamp,
    /// The release the router ran.
    pub release: String,
    pub size: u64,
    pub path: PathBuf,
}

const SUFFIX: &str = ".tar.gz.age";

pub fn stamp(at: Timestamp) -> String {
    at.strftime("%Y%m%dT%H%M%SZ").to_string()
}

fn stamp_time(stamp: &str) -> Option<Timestamp> {
    let b = stamp.as_bytes();
    if b.len() != 16 || !stamp.is_ascii() || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    format!(
        "{}-{}-{}T{}:{}:{}Z",
        &stamp[..4],
        &stamp[4..6],
        &stamp[6..8],
        &stamp[9..11],
        &stamp[11..13],
        &stamp[13..15]
    )
    .parse()
    .ok()
}

/// A release as part of a file name.
fn release_word(release: &str) -> String {
    let w: String = release
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_'))
        .collect();
    if w.is_empty() { "unknown".into() } else { w }
}

pub fn file_name(at: Timestamp, release: &str) -> String {
    format!("{}-{}{SUFFIX}", stamp(at), release_word(release))
}

fn sidecar(dir: &Path, stamp: &str, what: &str) -> PathBuf {
    dir.join(format!("{stamp}.{what}"))
}

/// The backups in a directory, newest first.
pub fn list_in(dir: &Path) -> Vec<Kept> {
    let mut out: Vec<Kept> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let rest = name.strip_suffix(SUFFIX)?;
            let (stamp, release) = rest.split_once('-')?;
            Some(Kept {
                at: stamp_time(stamp)?,
                stamp: stamp.to_string(),
                release: release.to_string(),
                size: e.metadata().ok()?.len(),
                path: e.path(),
            })
        })
        .collect();
    out.sort_by(|a, b| b.stamp.cmp(&a.stamp));
    out
}

pub fn list(scope: &str) -> Vec<Kept> {
    list_in(&backups_dir(scope))
}

/// Which backups go: all but the `keep` newest and the first of each month of the last
/// year. `kept`: newest first.
pub fn prune(kept: &[Kept], keep: usize, now: Timestamp) -> Vec<&Kept> {
    let year_ago = now.as_second() - 366 * 86_400;
    let month = |k: &Kept| k.stamp[..6].to_string();
    // The first of each month: the oldest with that month's stamp.
    let mut firsts: BTreeMap<String, &str> = BTreeMap::new();
    for k in kept.iter().filter(|k| k.at.as_second() >= year_ago) {
        let e = firsts.entry(month(k)).or_insert(&k.stamp);
        if k.stamp.as_str() < *e {
            *e = &k.stamp;
        }
    }
    kept.iter()
        .enumerate()
        .filter(|(i, k)| *i >= keep.max(1) && firsts.get(&month(k)) != Some(&k.stamp.as_str()))
        .map(|(_, k)| k)
        .collect()
}

/// Remove what retention lets go, each with its sidecars. How many went.
pub fn prune_dir(dir: &Path, keep: usize, now: Timestamp) -> usize {
    let kept = list_in(dir);
    let gone = prune(&kept, keep, now);
    for k in &gone {
        let _ = std::fs::remove_file(&k.path);
        let _ = std::fs::remove_file(sidecar(dir, &k.stamp, "manifest"));
        let _ = std::fs::remove_file(sidecar(dir, &k.stamp, "uci"));
    }
    gone.len()
}

// ---- the manifest

/// Every file of a backup with the tag of its sha256.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Manifest(pub BTreeMap<String, String>);

impl Manifest {
    /// `sha256sum`'s lines (`<64 hex>  <path>`), each hash tagged as it's read.
    pub fn parse(sums: &str, salt: &Salt) -> Self {
        Self(
            sums.lines()
                .filter_map(|l| {
                    let (hash, path) = l.split_once(char::is_whitespace)?;
                    let ok = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
                    let path = path.trim_start().trim_start_matches('*');
                    (ok && !path.is_empty()).then(|| (path.to_string(), salt.tag(hash)))
                })
                .collect(),
        )
    }

    pub fn to_text(&self) -> String {
        self.0.iter().map(|(p, t)| format!("{t}  {p}\n")).collect()
    }

    pub fn from_text(text: &str) -> Self {
        Self(
            text.lines()
                .filter_map(|l| {
                    let (tag, path) = l.split_once("  ")?;
                    redact::is_tag(tag).then(|| (path.to_string(), tag.to_string()))
                })
                .collect(),
        )
    }

    /// The files that differ in `now` (changed, new or gone), by path.
    pub fn changed(&self, now: &Manifest) -> Vec<String> {
        let mut out: Vec<String> = now
            .0
            .iter()
            .filter(|(p, t)| self.0.get(*p) != Some(t))
            .map(|(p, _)| p.clone())
            .chain(
                self.0
                    .keys()
                    .filter(|p| !now.0.contains_key(*p))
                    .map(|p| format!("{p} (gone)")),
            )
            .collect();
        out.sort();
        out
    }
}

/// One `sysupgrade` at a time on a router. It keeps its list of files in a fixed place
/// there (`/tmp/sysupgrade.conffiles`), so two at once (the audit's digest and a backup
/// being made, a workflow's check and the screen's own read) spoil each other's list: a
/// digest comes back with files that aren't there, or an archive is made from half a list.
/// Everything here that runs it holds this lock, a file beside the network's data on this
/// machine (nothing is left on the router), across threads and across processes (the
/// workflow's steps are processes of their own).
pub struct Turn(#[allow(dead_code)] std::fs::File);

pub fn turn(scope: &str) -> std::io::Result<Turn> {
    let dir = sentry_core::maint::data_root(scope);
    std::fs::create_dir_all(&dir)?;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("sysupgrade.lock"))?;
    f.lock()?;
    Ok(Turn(f))
}

/// What a backup made now would hold.
pub fn digest(r: &Remote, salt: &Salt) -> Result<Manifest, CollectError> {
    let _turn = turn(&r.scope).map_err(|e| CollectError::Failed(e.to_string()))?;
    digest_in_turn(r, salt)
}

/// The same, for a caller that holds the [`Turn`].
fn digest_in_turn(r: &Remote, salt: &Salt) -> Result<Manifest, CollectError> {
    let out = crate::collect::output_needing(r, "sysupgrade", DIGEST)?;
    let m = Manifest::parse(&out, salt);
    if m.0.is_empty() {
        return Err(CollectError::Parse("sysupgrade -l listed no files".into()));
    }
    Ok(m)
}

// ---- the configuration, by option

/// The configuration as lines to compare: `pkg.section.option` → its values, and
/// `pkg.section` → its type.
pub fn flat(u: &Uci) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (pkg, secs) in &u.configs {
        for s in secs {
            out.insert(format!("{pkg}.{}", s.name), s.kind.clone());
            for (opt, vals) in &s.opts {
                out.insert(format!("{pkg}.{}.{opt}", s.name), vals.join(" "));
            }
        }
    }
    out
}

fn uci_text(flat: &BTreeMap<String, String>) -> String {
    flat.iter()
        .map(|(k, v)| format!("{k}={}\n", v.replace('\\', "\\\\").replace('\n', "\\n")))
        .collect()
}

fn uci_from_text(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.replace("\\n", "\n").replace("\\\\", "\\")))
        .collect()
}

/// What changed, by option. A secret's value never shows (only that it changed); anything
/// else shows what it was and is.
pub fn diff(old: &BTreeMap<String, String>, new: &BTreeMap<String, String>) -> Vec<String> {
    let secret = |k: &str, vals: &[Option<&String>]| {
        redact::secret(k)
            || vals
                .iter()
                .flatten()
                .any(|v| v.split(' ').any(redact::is_tag))
    };
    // A section's own line (two parts: its type) only says it came or went.
    let section = |k: &str| k.matches('.').count() == 1;
    let mut out = Vec::new();
    for (k, v) in new {
        match old.get(k) {
            Some(o) if o == v => {}
            Some(o) if secret(k, &[Some(o), Some(v)]) => out.push(format!("{k} changed")),
            Some(o) => out.push(format!("{k}: {o} → {v}")),
            None if section(k) => out.push(format!("{k} added ({v})")),
            None if secret(k, &[Some(v)]) => out.push(format!("{k} added")),
            None => out.push(format!("{k} added: {v}")),
        }
    }
    for (k, o) in old {
        if new.contains_key(k) {
            continue;
        }
        if section(k) || secret(k, &[Some(o)]) {
            out.push(format!("{k} removed"));
        } else {
            out.push(format!("{k} removed (was {o})"));
        }
    }
    out.sort();
    out
}

// ---- how things stand

/// What differs between the newest backup and the router now.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Changed {
    /// Files of the backup that differ (their paths).
    pub files: Vec<String>,
    /// The options that differ, where the configs read cover them.
    pub options: Vec<String>,
}

impl Changed {
    pub fn any(&self) -> bool {
        !self.files.is_empty()
    }
}

/// The backups there are, against the router as it is now.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Status {
    /// The config names someone to encrypt to.
    pub recipients: bool,
    pub count: usize,
    pub newest: Option<Kept>,
    /// Against the newest (none: there is none, or it has no manifest to compare with).
    pub changed: Option<Changed>,
}

impl Status {
    /// The config differs from the newest backup, or there is none.
    pub fn unsaved(&self) -> bool {
        self.newest.is_none() || self.changed.as_ref().is_some_and(Changed::any)
    }
}

/// Compare what's kept in `dir` with the router now (`now`: its files; `uci`: its config).
pub fn status_in(dir: &Path, recipients: bool, now: &Manifest, uci: Option<&Uci>) -> Status {
    let kept = list_in(dir);
    let newest = kept.first().cloned();
    let changed = newest.as_ref().and_then(|k| {
        let old = std::fs::read_to_string(sidecar(dir, &k.stamp, "manifest")).ok()?;
        let files = Manifest::from_text(&old).changed(now);
        let options = match (
            std::fs::read_to_string(sidecar(dir, &k.stamp, "uci")).ok(),
            uci,
        ) {
            (Some(old), Some(u)) if !files.is_empty() => diff(&uci_from_text(&old), &flat(u)),
            _ => Vec::new(),
        };
        Some(Changed { files, options })
    });
    Status {
        recipients,
        count: kept.len(),
        newest,
        changed,
    }
}

/// Read the router (its files' digest; `uci` when the caller has it already) and compare.
pub fn status(r: &Router, uci: Option<&Uci>) -> Result<Status, CollectError> {
    let salt = Salt::load(&r.scope).map_err(|e| CollectError::Failed(e.to_string()))?;
    let now = digest(r, &salt)?;
    Ok(status_in(
        &backups_dir(&r.scope),
        !r.cfg.backup.recipients.is_empty(),
        &now,
        uci,
    ))
}

// ---- making one

fn private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

fn private_file(path: &Path, new: bool) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true);
    if new {
        o.create_new(true);
    } else {
        o.create(true).truncate(true);
    }
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path)
}

/// A file that goes away unless it's kept.
struct Temp(Option<PathBuf>);

impl Drop for Temp {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// What goes into the encryptor: counted, and its first bytes looked at (a backup is a
/// gzip stream).
struct Plain<W: Write> {
    to: W,
    n: u64,
    head: [u8; 2],
}

impl<W: Write> Write for Plain<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.to.write(buf)?;
        for b in &buf[..n] {
            if self.n < 2 {
                self.head[self.n as usize] = *b;
            }
            self.n += 1;
        }
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.to.flush()
    }
}

/// Encrypt what `source` writes to `to`, into `dir/name`: through the encryptor into a
/// temporary file there, renamed when all of it arrived. The plain bytes exist only in
/// memory, a chunk at a time. Whatever fails, the temporary file is removed. Returns the
/// file and how many plain bytes went in.
pub fn create(
    dir: &Path,
    name: &str,
    to: &[age::x25519::Recipient],
    source: impl FnOnce(&mut dyn Write) -> Result<(), String>,
) -> Result<(PathBuf, u64), Error> {
    if to.is_empty() {
        return Err(Error::Unavailable(NO_RECIPIENTS.into()));
    }
    private_dir(dir).map_err(|e| failed(format!("{}: {e}", dir.display())))?;
    let path = dir.join(name);
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let file = private_file(&tmp, true).map_err(|e| failed(format!("{}: {e}", tmp.display())))?;
    let mut guard = Temp(Some(tmp.clone()));
    let enc = age::Encryptor::with_recipients(to.iter().map(|r| r as &dyn age::Recipient))
        .map_err(failed)?;
    let mut plain = Plain {
        to: enc
            .wrap_output(std::io::BufWriter::new(file))
            .map_err(failed)?,
        n: 0,
        head: [0; 2],
    };
    source(&mut plain).map_err(Error::Failed)?;
    if plain.n == 0 {
        return Err(failed("the router sent nothing"));
    }
    if plain.head != [0x1f, 0x8b] {
        return Err(failed(
            "what the router sent isn't a backup archive (not gzip)",
        ));
    }
    let n = plain.n;
    let file = plain
        .to
        .finish()
        .and_then(|b| b.into_inner().map_err(|e| e.into_error()))
        .map_err(failed)?;
    file.sync_all().map_err(failed)?;
    drop(file);
    std::fs::rename(&tmp, &path).map_err(failed)?;
    guard.0 = None;
    Ok((path, n))
}

fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    private_file(path, false)?.write_all(text.as_bytes())
}

/// The plain sidecars of the backup with this stamp.
pub fn write_sidecars(
    dir: &Path,
    stamp: &str,
    m: &Manifest,
    uci: Option<&Uci>,
) -> Result<(), Error> {
    write_private(&sidecar(dir, stamp, "manifest"), &m.to_text()).map_err(failed)?;
    if let Some(u) = uci {
        write_private(&sidecar(dir, stamp, "uci"), &uci_text(&flat(u))).map_err(failed)?;
    }
    Ok(())
}

/// A backup just made.
#[derive(Debug, Clone, PartialEq)]
pub struct Made {
    pub path: PathBuf,
    /// The encrypted file's size, and the archive's.
    pub size: u64,
    pub plain: u64,
    pub files: usize,
    /// The backup before this one (none: this is the first), and what changed since it
    /// (none: that one has no manifest to compare with).
    pub since: Option<(String, Option<Changed>)>,
    /// How many old backups retention removed.
    pub pruned: usize,
    /// How long the archive took to arrive, and the digest.
    pub took: Duration,
    pub digest_took: Duration,
}

impl Made {
    /// What the command prints.
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![format!(
            "✓ {} ({} files, {} encrypted)",
            self.path.display(),
            self.files,
            sentry_core::fmt::bytes(self.size)
        )];
        match &self.since {
            None => out.push("· the first backup of this router".into()),
            Some((stamp, None)) => out.push(format!(
                "· the backup before ({stamp}) has no manifest to compare with"
            )),
            Some((stamp, Some(c))) if !c.any() => {
                out.push(format!("· nothing changed since the last backup ({stamp})"))
            }
            Some((stamp, Some(c))) => {
                out.push(format!(
                    "· changed since the last backup ({stamp}): {} file(s)",
                    c.files.len()
                ));
                out.extend(
                    capped(&c.options, 20)
                        .into_iter()
                        .map(|o| format!("    {o}")),
                );
                if c.options.is_empty() {
                    out.extend(capped(&c.files, 20).into_iter().map(|f| format!("    {f}")));
                }
            }
        }
        if self.pruned > 0 {
            out.push(format!(
                "· {} old backup(s) removed (backup.keep)",
                self.pruned
            ));
        }
        out
    }
}

/// The first `n` of a list, then how many more.
pub fn capped(list: &[String], n: usize) -> Vec<String> {
    let mut out: Vec<String> = list.iter().take(n).cloned().collect();
    if list.len() > n {
        out.push(format!("… {} more", list.len() - n));
    }
    out
}

/// Make a backup of the network's router now: the archive encrypted to the config's
/// recipients, its sidecars, then retention.
pub fn run(r: &Router) -> Result<Made, Error> {
    let to = recipients(&r.cfg.backup.recipients)?;
    let scope = &r.scope;
    let dir = backups_dir(scope);
    let salt = Salt::load(scope).map_err(failed)?;
    let release = crate::collect::ifaces::collect(r)
        .map(|i| i.board.version)
        .map_err(failed)?;
    // What it holds, taken beside it: the files' tags and the config. No other sysupgrade
    // of sentry's runs on the router until the archive has arrived.
    let turn = turn(scope).map_err(failed)?;
    let t = Instant::now();
    let manifest = digest_in_turn(r, &salt).map_err(failed)?;
    let digest_took = t.elapsed();
    let uci = crate::collect::uci::collect(r).ok();
    let before = status_in(&dir, true, &manifest, uci.as_ref());
    let now = Timestamp::now();
    let t = Instant::now();
    let cmd = r
        .cmd("sysupgrade")
        .args(CREATE.iter().copied())
        .timeout(Some(Duration::from_secs(180)));
    let (path, plain) = create(&dir, &file_name(now, &release), &to, |w| {
        cmd.bytes_to(w).map(|_| ()).map_err(|e| e.to_string())
    })?;
    let took = t.elapsed();
    drop(turn);
    write_sidecars(&dir, &stamp(now), &manifest, uci.as_ref())?;
    let pruned = prune_dir(&dir, r.cfg.backup.keep as usize, now);
    Ok(Made {
        size: std::fs::metadata(&path).map_or(0, |m| m.len()),
        path,
        plain,
        files: manifest.0.len(),
        since: before.newest.map(|k| (k.stamp, before.changed)),
        pruned,
        took,
        digest_took,
    })
}

/// The newest backup is there, is an age file with something in it, and holds what the
/// router has now. What it says when so; why not otherwise.
pub fn verify(r: &Router) -> Result<String, String> {
    let dir = backups_dir(&r.scope);
    let salt = Salt::load(&r.scope).map_err(|e| e.to_string())?;
    let now = digest(r, &salt).map_err(|e| e.to_string())?;
    verify_in(&dir, &now)
}

pub fn verify_in(dir: &Path, now: &Manifest) -> Result<String, String> {
    let kept = list_in(dir);
    let k = kept.first().ok_or("there is no backup")?;
    let mut head = [0u8; AGE_MAGIC.len()];
    let read = std::fs::File::open(&k.path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok();
    if !read || head != AGE_MAGIC {
        return Err(format!("{} isn't an age file", k.path.display()));
    }
    if k.size <= AGE_MAGIC.len() as u64 + 100 {
        return Err(format!("{} is empty", k.path.display()));
    }
    let text = std::fs::read_to_string(sidecar(dir, &k.stamp, "manifest"))
        .map_err(|_| format!("{} has no manifest beside it", k.path.display()))?;
    let diff = Manifest::from_text(&text).changed(now);
    if !diff.is_empty() {
        return Err(format!(
            "the router's config isn't what the backup of {} holds: {}",
            k.stamp,
            capped(&diff, 6).join(", ")
        ));
    }
    Ok(format!(
        "{} · {} · {} files, as on the router now",
        k.path.file_name().unwrap_or_default().to_string_lossy(),
        sentry_core::fmt::bytes(k.size),
        now.0.len()
    ))
}

// ---- the user's side: a key, and reading one back

/// Make an identity file (0600; never over one that's there). Returns its recipient: the
/// line for `backup.recipients`.
pub fn make_key(path: &Path) -> Result<String, Error> {
    use age::secrecy::ExposeSecret;
    let id = age::x25519::Identity::generate();
    let public = id.to_public().to_string();
    if let Some(d) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(d).map_err(failed)?;
    }
    let mut f = private_file(path, true).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            failed(format!(
                "{} is already there: not touching it",
                path.display()
            ))
        } else {
            failed(format!("{}: {e}", path.display()))
        }
    })?;
    let text = format!(
        "# created: {}\n# public key: {public}\n{}\n",
        Timestamp::now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        id.to_string().expose_secret()
    );
    f.write_all(text.as_bytes()).map_err(failed)?;
    Ok(public)
}

/// Decrypt `file` with the identities in `identity`, into `out`. Only ever run by the user.
pub fn decrypt(file: &Path, identity: &Path, out: &mut dyn Write) -> Result<u64, Error> {
    let ids = age::IdentityFile::from_file(identity.display().to_string())
        .map_err(|e| failed(format!("{}: {e}", identity.display())))?
        .into_identities()
        .map_err(|e| failed(format!("{}: {e}", identity.display())))?;
    let f = std::fs::File::open(file).map_err(|e| failed(format!("{}: {e}", file.display())))?;
    let dec = age::Decryptor::new(std::io::BufReader::new(f))
        .map_err(|e| failed(format!("{}: {e}", file.display())))?;
    let mut plain = dec
        .decrypt(ids.iter().map(|i| i.as_ref() as &dyn age::Identity))
        .map_err(|e| failed(format!("{}: {e}", file.display())))?;
    std::io::copy(&mut plain, out).map_err(failed)
}

/// Where `backup decrypt` writes when no `-o` is given: the file's name without `.age`,
/// here.
pub fn decrypted_name(file: &Path) -> PathBuf {
    let name = file.file_name().unwrap_or_default().to_string_lossy();
    PathBuf::from(
        name.strip_suffix(".age")
            .map_or_else(|| format!("{name}.plain"), str::to_string),
    )
}

/// A new file for the decrypted archive (0600; never over one that's there).
pub fn plain_file(path: &Path) -> Result<std::fs::File, Error> {
    private_file(path, true).map_err(|e| failed(format!("{}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::{fixture, uci};
    use std::os::unix::fs::PermissionsExt;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sentry-backup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn salt() -> Salt {
        Salt::fixed([7; 16])
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// A tiny gzip stream stands in for the router's archive (only its magic is looked at).
    fn archive() -> Vec<u8> {
        let mut v = vec![0x1f, 0x8b, 0x08, 0x00];
        v.extend((0..70_000u32).map(|i| (i % 251) as u8));
        v
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn a_backup_round_trips_and_only_ciphertext_is_on_disk() {
        let dir = scratch("round");
        let key = dir.join("keys/id.txt");
        let public = make_key(&key).unwrap();
        assert!(public.starts_with("age1") && public.len() == 62, "{public}");
        assert_eq!(mode(&key), 0o600);
        // Never over a key that's there.
        let again = make_key(&key).unwrap_err();
        assert!(again.to_string().contains("already there"), "{again}");
        let to = recipients(std::slice::from_ref(&public)).unwrap();
        let plain = archive();
        let bdir = dir.join("backups");
        let at: Timestamp = "2026-10-26T11:55:00Z".parse().unwrap();
        let name = file_name(at, "25.12.3");
        assert_eq!(name, "20261026T115500Z-25.12.3.tar.gz.age");
        // The "router": an in-memory stream, in chunks as ssh would hand them over. While
        // it streams, the directory holds only the temporary file.
        let (path, n) = create(&bdir, &name, &to, |w| {
            for chunk in plain.chunks(4096) {
                w.write_all(chunk).map_err(|e| e.to_string())?;
            }
            let there = names(&bdir);
            assert_eq!(there.len(), 1, "{there:?}");
            assert!(there[0].starts_with('.') && there[0].ends_with(".tmp"));
            assert_eq!(mode(&bdir.join(&there[0])), 0o600);
            Ok(())
        })
        .unwrap();
        assert_eq!(n, plain.len() as u64);
        assert_eq!(names(&bdir), std::slice::from_ref(&name));
        assert_eq!((mode(&bdir), mode(&path)), (0o700, 0o600));
        // Encrypted: an age file, with nothing of the archive readable in it.
        let stored = std::fs::read(&path).unwrap();
        assert!(stored.starts_with(AGE_MAGIC));
        assert!(!stored.windows(16).any(|w| w == &plain[100..116]));
        // The secret key reads it back, byte for byte.
        let mut back = Vec::new();
        decrypt(&path, &key, &mut back).unwrap();
        assert_eq!(back, plain);
        // Another key doesn't.
        let other = dir.join("keys/other.txt");
        make_key(&other).unwrap();
        assert!(decrypt(&path, &other, &mut Vec::new()).is_err());
        // A file holding recipients works as one; one holding a secret key is refused.
        let rfile = dir.join("keys/recipients.txt");
        std::fs::write(&rfile, format!("# mine\n{public}\n")).unwrap();
        assert_eq!(recipient(&rfile.display().to_string()).unwrap().len(), 1);
        let e = recipient(&key.display().to_string()).unwrap_err();
        assert!(e.contains("secret key"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failure_leaves_no_temporary_file_and_no_backup() {
        let dir = scratch("fail");
        let id = age::x25519::Identity::generate();
        let to = [id.to_public()];
        // The stream breaks half way.
        let e = create(&dir, "20261026T115500Z-x.tar.gz.age", &to, |w| {
            w.write_all(&archive()[..5000]).unwrap();
            Err("myrouter: connection lost".into())
        })
        .unwrap_err();
        assert_eq!(e, Error::Failed("myrouter: connection lost".into()));
        assert!(names(&dir).is_empty(), "{:?}", names(&dir));
        // Nothing arrived, or it isn't an archive.
        let e = create(&dir, "a.tar.gz.age", &to, |_| Ok(())).unwrap_err();
        assert!(e.to_string().contains("sent nothing"), "{e}");
        let e = create(&dir, "a.tar.gz.age", &to, |w| {
            w.write_all(b"sysupgrade: not found\n")
                .map_err(|e| e.to_string())
        })
        .unwrap_err();
        assert!(e.to_string().contains("isn't a backup archive"), "{e}");
        assert!(names(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn without_a_recipient_it_is_unavailable_and_says_which_key() {
        let e = recipients(&[]).unwrap_err();
        assert!(matches!(&e, Error::Unavailable(m) if m.contains("backup.recipients")));
        let dir = scratch("none");
        let e = create(&dir, "a.tar.gz.age", &[], |_| panic!("never read")).unwrap_err();
        assert!(matches!(e, Error::Unavailable(_)));
        assert!(!dir.exists());
        // What isn't a recipient says what would be.
        for (bad, says) in [
            ("age1short", "isn't a whole age recipient"),
            ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA me@here", "ssh key"),
            ("/nonexistent/recipients.txt", "isn't there"),
            ("hunter2", "isn't an age recipient"),
        ] {
            let e = recipient(bad).unwrap_err();
            assert!(e.contains(says), "{bad}: {e}");
        }
    }

    fn sums(lines: &[(&str, &str)]) -> String {
        lines
            .iter()
            .map(|(p, content)| format!("{:064x}  {p}\n", content.len() * 7919 + 13))
            .collect()
    }

    #[test]
    fn the_manifest_holds_tags_never_the_hashes() {
        let text = fixture("network/digest.txt");
        let m = Manifest::parse(&text, &salt());
        assert_eq!(m.0.len(), 9);
        assert!(m.0.contains_key("/etc/config/wireless") && m.0.contains_key("/etc/shadow"));
        let stored = m.to_text();
        for line in text.lines() {
            let hash = line.split_whitespace().next().unwrap();
            assert!(!stored.contains(hash), "a raw hash is in the manifest");
        }
        assert!(
            stored.lines().all(|l| l.starts_with("redacted:")),
            "{stored}"
        );
        assert_eq!(Manifest::from_text(&stored), m);
        // Another network's salt gives other tags for the same files.
        assert_ne!(Manifest::parse(&text, &Salt::fixed([8; 16])), m);
        // Noise isn't a file.
        assert!(
            Manifest::parse("sha256sum: /etc/x: No such file\n", &salt())
                .0
                .is_empty()
        );
    }

    #[test]
    fn files_changed_added_and_gone() {
        let old = Manifest::parse(
            &sums(&[
                ("/etc/config/dhcp", "a"),
                ("/etc/config/wireless", "bb"),
                ("/etc/old", "c"),
            ]),
            &salt(),
        );
        let same = old.clone();
        assert!(old.changed(&same).is_empty());
        let now = Manifest::parse(
            &sums(&[
                ("/etc/config/dhcp", "a"),
                ("/etc/config/wireless", "bbb"),
                ("/etc/new", "d"),
            ]),
            &salt(),
        );
        assert_eq!(
            old.changed(&now),
            ["/etc/config/wireless", "/etc/new", "/etc/old (gone)"]
        );
    }

    fn the_uci() -> Uci {
        uci::parse(&fixture("network/uci.txt"), &salt())
    }

    fn uci_with(edit: impl Fn(String) -> String) -> Uci {
        uci::parse(&edit(fixture("network/uci.txt")), &salt())
    }

    #[test]
    fn what_changed_by_option() {
        let old = flat(&the_uci());
        // The sidecar's text reads back as it was.
        assert_eq!(uci_from_text(&uci_text(&old)), old);
        assert!(diff(&old, &old).is_empty());
        type Edit = Box<dyn Fn(String) -> String>;
        let table: Vec<(Edit, Vec<&str>)> = vec![
            // A secret: named, its value (old or new) never shown.
            (
                Box::new(|t| {
                    t.replace(
                        "wireless.default_radio0.key='correct horse battery'",
                        "wireless.default_radio0.key='a new passphrase'",
                    )
                }),
                vec!["wireless.default_radio0.key changed"],
            ),
            // A plain option: what it was and is.
            (
                Box::new(|t| {
                    t.replace(
                        "dropbear.main.PasswordAuth='off'",
                        "dropbear.main.PasswordAuth='on'",
                    )
                }),
                vec!["dropbear.main.PasswordAuth: off → on"],
            ),
            // A list.
            (
                Box::new(|t| {
                    t.replace(
                        "firewall.@zone[1].network='wan' 'wan6'",
                        "firewall.@zone[1].network='wan'",
                    )
                }),
                vec!["firewall.@zone[1].network: wan wan6 → wan"],
            ),
            // An option taken out; a secret taken out.
            (
                Box::new(|t| t.replace("firewall.@zone[1].masq='1'\n", "")),
                vec!["firewall.@zone[1].masq removed (was 1)"],
            ),
            (
                Box::new(|t| {
                    t.replace("wireless.default_radio0.key='correct horse battery'\n", "")
                }),
                vec!["wireless.default_radio0.key removed"],
            ),
            // A section added, with a plain option and a secret.
            (
                Box::new(|t| {
                    t.replace(
                        "@@dropbear",
                        "firewall.guest=zone\nfirewall.guest.name='guest'\n\
                         firewall.guest.token='s3cret'\n@@dropbear",
                    )
                }),
                vec![
                    "firewall.guest added (zone)",
                    "firewall.guest.name added: guest",
                    "firewall.guest.token added",
                ],
            ),
        ];
        for (edit, want) in table {
            let new = flat(&uci_with(edit));
            let got = diff(&old, &new);
            assert_eq!(got, want);
            for l in &got {
                assert!(
                    !l.contains("horse") && !l.contains("passphrase") && !l.contains("s3cret"),
                    "{l}"
                );
            }
        }
    }

    fn kept(stamps: &[&str]) -> Vec<Kept> {
        let mut v: Vec<Kept> = stamps
            .iter()
            .map(|s| Kept {
                stamp: s.to_string(),
                at: stamp_time(s).unwrap(),
                release: "25.12.3".into(),
                size: 1,
                path: PathBuf::from(format!("{s}-25.12.3{SUFFIX}")),
            })
            .collect();
        v.sort_by(|a, b| b.stamp.cmp(&a.stamp));
        v
    }

    #[test]
    fn retention_keeps_the_newest_and_each_months_first() {
        let now: Timestamp = "2026-10-26T12:00:00Z".parse().unwrap();
        let all = [
            "20261026T110000Z", // newest
            "20261020T090000Z",
            "20261003T090000Z",
            "20261001T080000Z", // October's first
            "20260915T090000Z",
            "20260902T090000Z", // September's first
            "20260410T090000Z", // April's first (its only one)
            "20251101T090000Z", // within the year: November 2025's first
            "20251005T090000Z", // more than a year old
            "20240101T000000Z", // long ago
        ];
        let gone = |keep: usize| -> Vec<String> {
            prune(&kept(&all), keep, now)
                .iter()
                .map(|k| k.stamp.clone())
                .collect()
        };
        // Two newest, and every month's first of the last year.
        assert_eq!(
            gone(2),
            [
                "20261003T090000Z",
                "20260915T090000Z",
                "20251005T090000Z",
                "20240101T000000Z"
            ]
        );
        // Enough kept: only what's neither among them nor a month's first goes.
        assert_eq!(gone(8), ["20251005T090000Z", "20240101T000000Z"]);
        assert!(gone(10).is_empty() && gone(99).is_empty());
        // keep: 0 still keeps the newest.
        assert!(!gone(0).contains(&"20261026T110000Z".to_string()));
        assert!(prune(&[], 3, now).is_empty());
    }

    #[test]
    fn pruning_takes_the_sidecars_along() {
        let dir = scratch("prune");
        std::fs::create_dir_all(&dir).unwrap();
        let m = Manifest::parse(&fixture("network/digest.txt"), &salt());
        for s in ["20261001T080000Z", "20261003T090000Z", "20261026T110000Z"] {
            std::fs::write(dir.join(format!("{s}-25.12.3{SUFFIX}")), b"x").unwrap();
            write_sidecars(&dir, s, &m, Some(&the_uci())).unwrap();
        }
        std::fs::write(dir.join("notes.txt"), b"mine").unwrap();
        assert_eq!(mode(&dir.join("20261001T080000Z.manifest")), 0o600);
        let now: Timestamp = "2026-10-26T12:00:00Z".parse().unwrap();
        assert_eq!(prune_dir(&dir, 1, now), 1);
        assert_eq!(
            names(&dir),
            [
                "20261001T080000Z-25.12.3.tar.gz.age",
                "20261001T080000Z.manifest",
                "20261001T080000Z.uci",
                "20261026T110000Z-25.12.3.tar.gz.age",
                "20261026T110000Z.manifest",
                "20261026T110000Z.uci",
                "notes.txt"
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn how_things_stand_against_the_newest_backup() {
        let dir = scratch("status");
        let m = Manifest::parse(&fixture("network/digest.txt"), &salt());
        let u = the_uci();
        // No backup at all.
        let s = status_in(&dir, false, &m, Some(&u));
        assert!(s.newest.is_none() && s.changed.is_none() && s.unsaved() && !s.recipients);
        assert!(verify_in(&dir, &m).unwrap_err().contains("no backup"));
        // One, of the router as it is.
        let id = age::x25519::Identity::generate();
        let at: Timestamp = "2026-10-20T09:00:00Z".parse().unwrap();
        create(&dir, &file_name(at, "25.12.3"), &[id.to_public()], |w| {
            w.write_all(&archive()).map_err(|e| e.to_string())
        })
        .unwrap();
        write_sidecars(&dir, &stamp(at), &m, Some(&u)).unwrap();
        let s = status_in(&dir, true, &m, Some(&u));
        assert_eq!(s.count, 1);
        assert_eq!(s.newest.as_ref().unwrap().release, "25.12.3");
        assert_eq!(s.newest.as_ref().unwrap().at, at);
        assert_eq!(s.changed, Some(Changed::default()));
        assert!(!s.unsaved());
        let ok = verify_in(&dir, &m).unwrap();
        assert!(ok.contains("9 files, as on the router now"), "{ok}");
        // The Wi-Fi passphrase and the size of the DHCP pool change: two files, two options named.
        let text = fixture("network/digest.txt");
        let changed_sums: String = text
            .lines()
            .map(|l| {
                if l.ends_with("/etc/config/wireless") || l.ends_with("/etc/config/dhcp") {
                    format!(
                        "{}  {}\n",
                        "f".repeat(64),
                        l.split_whitespace().nth(1).unwrap()
                    )
                } else {
                    format!("{l}\n")
                }
            })
            .collect();
        let m2 = Manifest::parse(&changed_sums, &salt());
        let u2 = uci_with(|t| {
            t.replace(
                "wireless.default_radio0.key='correct horse battery'",
                "wireless.default_radio0.key='another one'",
            )
            .replace("dhcp.lan.limit='150'", "dhcp.lan.limit='200'")
        });
        let s = status_in(&dir, true, &m2, Some(&u2));
        let c = s.changed.clone().unwrap();
        assert_eq!(c.files, ["/etc/config/dhcp", "/etc/config/wireless"]);
        assert_eq!(
            c.options,
            [
                "dhcp.lan.limit: 150 → 200",
                "wireless.default_radio0.key changed"
            ]
        );
        assert!(s.unsaved());
        let e = verify_in(&dir, &m2).unwrap_err();
        assert!(e.contains("/etc/config/wireless"), "{e}");
        // A backup that's no age file doesn't verify.
        std::fs::write(dir.join(format!("20261021T090000Z-x{SUFFIX}")), b"plain").unwrap();
        assert!(
            verify_in(&dir, &m)
                .unwrap_err()
                .contains("isn't an age file")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_sysupgrade_at_a_time() {
        // Two takers, as two threads (or two processes) would be: the second waits for
        // the first to be done.
        let scope = "net:turn-test";
        let first = turn(scope).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let waiting = std::thread::spawn(move || {
            let _second = turn(scope).unwrap();
            tx.send(()).unwrap();
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(150)).is_err(),
            "the second didn't wait"
        );
        drop(first);
        rx.recv_timeout(Duration::from_secs(5)).expect("its turn");
        waiting.join().unwrap();
        let _ = std::fs::remove_dir_all(sentry_core::maint::data_root(scope));
    }

    #[test]
    fn what_a_run_says() {
        let made = |since| Made {
            path: PathBuf::from("/b/20261026T115500Z-25.12.3.tar.gz.age"),
            size: 30_000,
            plain: 29_000,
            files: 37,
            since,
            pruned: 0,
            took: Duration::ZERO,
            digest_took: Duration::ZERO,
        };
        let l = made(Some(("20261020T090000Z".into(), Some(Changed::default())))).lines();
        assert_eq!(
            l[1],
            "· nothing changed since the last backup (20261020T090000Z)"
        );
        let l = made(Some((
            "20261020T090000Z".into(),
            Some(Changed {
                files: vec!["/etc/config/wireless".into()],
                options: vec!["wireless.default_radio0.key changed".into()],
            }),
        )))
        .lines();
        assert!(l[1].contains("changed since the last backup") && l[1].contains("1 file(s)"));
        assert_eq!(l[2], "    wireless.default_radio0.key changed");
        assert!(made(None).lines()[1].contains("first backup"));
        assert!(made(Some(("20261020T090000Z".into(), None))).lines()[1].contains("no manifest"));
        assert_eq!(
            capped(&["a".into(), "b".into(), "c".into()], 2),
            ["a", "b", "… 1 more"]
        );
        assert_eq!(
            decrypted_name(Path::new("/x/s-1.tar.gz.age")),
            PathBuf::from("s-1.tar.gz")
        );
        assert_eq!(
            backups_dir("net:home"),
            sentry_core::paths::data_dir().join("networks/home/backups")
        );
    }
}
