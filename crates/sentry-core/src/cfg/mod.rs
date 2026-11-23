//! The one writer of sentry's config files: `config.toml` (this machine and the window),
//! `server_config.yaml`, `network_config.yaml`. Config is what you said, one file each:
//! sentry writes it only from its typed value ([`render`]), keeps the file it replaces
//! ([`save`]: `<file>.bak-<UTC time>`, the newest [`BACKUPS`]), and changes it by path
//! ([`Change`], [`diff`], [`apply`]), so a change made against an older file is re-made on
//! the newer one or shown as a conflict, never written over it ([`Doc::rebase`]).
//!
//! Each file's type says what it is through [`ConfigFile`] (implemented beside the type: core
//! for `config.toml`, sentry-server and sentry-network for theirs), so whatever holds the
//! three (the window) needs no target crate: a `Doc<T>` per file.

pub mod change;
pub mod fields;
pub mod value;

use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;
use serde::de::DeserializeOwned;

pub use change::{By, Change, apply, diff};
pub use fields::{Field, Kind};
pub use value::{Seg, Value, parse_path, path_string};

use crate::paths;

/// The three files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileId {
    /// `config.toml`: this machine, the window, the targets shown.
    App,
    /// `server_config.yaml`.
    Servers,
    /// `network_config.yaml`.
    Networks,
}

pub const FILES: [FileId; 3] = [FileId::App, FileId::Servers, FileId::Networks];

impl FileId {
    pub fn name(self) -> &'static str {
        match self {
            FileId::App => "config.toml",
            FileId::Servers => "server_config.yaml",
            FileId::Networks => "network_config.yaml",
        }
    }

    /// Where it is: the config dir.
    pub fn path(self) -> PathBuf {
        paths::config_dir().join(self.name())
    }

    /// The word `sentry config show` takes for it.
    pub fn word(self) -> &'static str {
        match self {
            FileId::App => "app",
            FileId::Servers => "servers",
            FileId::Networks => "networks",
        }
    }

    pub fn from_word(w: &str) -> Option<Self> {
        FILES.into_iter().find(|f| f.word() == w || f.name() == w)
    }

    /// The file a setting's path is in: `servers.…`, `networks.…`, else `config.toml`.
    pub fn of_path(path: &str) -> Self {
        match path.split(['.', '[']).next() {
            Some("servers") => FileId::Servers,
            Some("networks") => FileId::Networks,
            _ => FileId::App,
        }
    }

    fn toml(self) -> bool {
        self == FileId::App
    }

    /// The comment at the top of every file sentry writes.
    pub fn header(self) -> String {
        let what = match self {
            FileId::App => "this machine and the window",
            FileId::Servers => "the servers sentry watches over ssh",
            FileId::Networks => "the networks sentry watches through their routers",
        };
        format!(
            "# sentry's configuration: {what}.\n\
             # Written by sentry: change it in the Config tab or with `sentry config`. Editing it\n\
             # in $EDITOR is fine, but comments are not kept: the next save writes it again\n\
             # from what it says, keeping the file before beside it ({}.bak-<time>).\n\n",
            self.name()
        )
    }
}

/// A config file's type: which file it is, how its text is read, what its settings are.
pub trait ConfigFile: Serialize + DeserializeOwned + Default + PartialEq + Clone {
    const FILE: FileId;
    /// Every setting, for `explain`, the forms and the checks of a proposed change.
    const FIELDS: &'static [Field];
    /// The file's text as the type; unknown keys are warnings, not errors.
    fn parse(text: &str) -> Result<(Self, Vec<String>), String>;
}

/// The text of a config file for its value: the only way sentry makes one. A fixed header,
/// then the value as YAML or TOML, leaving out every setting the file means the same without
/// (a default), so a file holds what was said.
pub fn render<T: ConfigFile>(v: &T) -> Result<String, String> {
    let tree = prune(v)?;
    let body = if T::FILE.toml() {
        toml::to_string_pretty(&tree.without_nulls()).map_err(|e| e.to_string())?
    } else {
        let opts = serde_saphyr::ser_options! {
            compact_list_indent: false,
            prefer_block_scalars: false,
        };
        serde_saphyr::to_string_with_options(&tree, opts).map_err(|e| e.to_string())?
    };
    let text = format!("{}{body}", T::FILE.header());
    // Never a file that reads back as something else.
    match T::parse(&text) {
        Ok((back, _)) if back == *v => Ok(text),
        Ok(_) => Err(format!(
            "{}: what would be written reads back differently",
            T::FILE.name()
        )),
        Err(e) => Err(format!(
            "{}: what would be written doesn't read back: {e}",
            T::FILE.name()
        )),
    }
}

/// `v`'s tree without what it doesn't need: an entry goes when the value reads the same
/// without it (the type's own default for it, whatever that is), else what's in it is looked
/// at the same way. Generic, so no type has to say its defaults twice.
fn prune<T: ConfigFile>(v: &T) -> Result<Value, String> {
    let mut tree = Value::of(v)?;
    let same = |t: &Value| t.to::<T>().is_ok_and(|x| x == *v);
    if !same(&tree) {
        return Err(format!(
            "{}: the value doesn't read back as itself",
            T::FILE.name()
        ));
    }
    fn walk(tree: &mut Value, at: &mut Vec<Seg>, same: &dyn Fn(&Value) -> bool) {
        let keys: Vec<String> = match tree.at(at) {
            Some(Value::Map(m)) => m.iter().map(|(k, _)| k.clone()).collect(),
            Some(Value::List(l)) => {
                for i in 0..l.len() {
                    at.push(Seg::Index(i));
                    walk(tree, at, same);
                    at.pop();
                }
                return;
            }
            _ => return,
        };
        for k in keys {
            let Some(Value::Map(m)) = tree.at_mut(at) else {
                return;
            };
            let Some(i) = m.iter().position(|(x, _)| *x == k) else {
                continue;
            };
            let entry = m.remove(i);
            if same(tree) {
                continue;
            }
            if let Some(Value::Map(m)) = tree.at_mut(at) {
                m.insert(i, entry);
            }
            at.push(Seg::Key(k));
            walk(tree, at, same);
            at.pop();
        }
    }
    walk(&mut tree, &mut Vec::new(), &same);
    Ok(tree)
}

/// The file's text isn't what sentry would write for what it says: someone wrote it, or
/// edited it, by hand. Saving loses its comments and layout (the save says so).
pub fn handwritten<T: ConfigFile>(text: &str, v: &T) -> bool {
    render(v).map_or(true, |r| r != text)
}

/// Backups kept beside each file.
pub const BACKUPS: usize = 5;

/// Write a config file: when it is there, first a copy beside it (`<file>.bak-<UTC time>`,
/// the newest [`BACKUPS`] kept), then the new text by rename, so the file is never half
/// written. The copy's path, when one was made. When anything fails, the file is as it was.
pub fn save(path: &Path, text: &str) -> io::Result<Option<PathBuf>> {
    let backup = if path.exists() {
        let b = backup_path(path);
        std::fs::copy(path, &b)?;
        Some(b)
    } else {
        None
    };
    paths::write_atomic(path, text.as_bytes())?;
    if backup.is_some() {
        prune_backups(path);
    }
    Ok(backup)
}

fn backup_prefix(path: &Path) -> String {
    format!(
        "{}.bak-",
        path.file_name().unwrap_or_default().to_string_lossy()
    )
}

/// `<file>.bak-20261123T181000Z`, then `-2`, `-3`… within that second (after the highest
/// there, so a pruned name isn't taken again out of order): names sort by time.
fn backup_path(path: &Path) -> PathBuf {
    let stamp = jiff::Timestamp::now()
        .strftime("%Y%m%dT%H%M%SZ")
        .to_string();
    let base = format!("{}{stamp}", backup_prefix(path));
    let last = backups(path)
        .iter()
        .filter_map(|b| {
            let name = b.file_name()?.to_string_lossy().into_owned();
            match name.strip_prefix(&base)? {
                "" => Some(1),
                rest => rest.strip_prefix('-')?.parse::<u32>().ok(),
            }
        })
        .max();
    match last {
        None => path.with_file_name(&base),
        Some(n) => path.with_file_name(format!("{base}-{}", n + 1)),
    }
}

/// The backups of `path`, oldest first.
pub fn backups(path: &Path) -> Vec<PathBuf> {
    let prefix = backup_prefix(path);
    let Some(dir) = path.parent() else {
        return Vec::new();
    };
    let mut found: Vec<(String, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.starts_with(&prefix).then(|| (name, e.path()))
        })
        .collect();
    // The same second's later copies (`-2`, `-10`) after its first, in order.
    found.sort_by_key(|(n, _)| {
        let rest = &n[prefix.len()..];
        let (stamp, k) = rest.split_once('-').unwrap_or((rest, "1"));
        (stamp.to_string(), k.parse::<u32>().unwrap_or(0))
    });
    found.into_iter().map(|(_, p)| p).collect()
}

fn prune_backups(path: &Path) {
    let all = backups(path);
    for old in &all[..all.len().saturating_sub(BACKUPS)] {
        let _ = std::fs::remove_file(old);
    }
}

/// What a file was when it was read: changed since when either differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    pub len: u64,
    pub modified: Option<SystemTime>,
}

impl Stamp {
    /// None: there is no file.
    pub fn of(path: &Path) -> Option<Self> {
        let m = std::fs::metadata(path).ok()?;
        Some(Self {
            len: m.len(),
            modified: m.modified().ok(),
        })
    }
}

/// What [`Doc::rebase`] made of the pending changes: those made again on the newer file, and
/// those whose `from` isn't there any more, each with why (conflicts, left out).
pub type Rebased = (Vec<Change>, Vec<(Change, String)>);

/// One config file as read (`on_disk`, `stamp`) and as it is to be (`now`: what was read
/// with the pending changes made).
#[derive(Debug, Clone)]
pub struct Doc<T> {
    pub path: PathBuf,
    pub on_disk: String,
    /// None: the file isn't there (`now` starts as the defaults).
    pub stamp: Option<Stamp>,
    pub now: T,
}

impl<T: ConfigFile> Doc<T> {
    /// The file where it lives. A file that isn't there is the defaults; one that doesn't
    /// parse is an error. The parse's warnings (unknown keys) come back beside it.
    pub fn load() -> Result<(Self, Vec<String>), String> {
        Self::load_from(&T::FILE.path())
    }

    pub fn load_from(path: &Path) -> Result<(Self, Vec<String>), String> {
        let (on_disk, stamp) = read(path)?;
        let (now, warnings) = if stamp.is_some() {
            T::parse(&on_disk).map_err(|e| format!("{}: {e}", path.display()))?
        } else {
            (T::default(), Vec::new())
        };
        Ok((
            Self {
                path: path.to_path_buf(),
                on_disk,
                stamp,
                now,
            },
            warnings,
        ))
    }

    /// The file is not what was read (written, removed or made since).
    pub fn changed_on_disk(&self) -> bool {
        Stamp::of(&self.path) != self.stamp
    }

    /// What the file says, as read.
    pub fn base(&self) -> Result<T, String> {
        if self.stamp.is_none() {
            return Ok(T::default());
        }
        T::parse(&self.on_disk).map(|(t, _)| t)
    }

    /// The changes `now` has over the file as read.
    pub fn pending(&self) -> Result<Vec<Change>, String> {
        diff(&self.base()?, &self.now)
    }

    /// The file as read was written by hand (saving it loses its comments and layout).
    pub fn handwritten(&self) -> bool {
        self.stamp.is_some() && self.base().map_or(true, |b| handwritten(&self.on_disk, &b))
    }

    /// The file changed underneath: read it again and make `changes` on it. The ones made,
    /// and the ones whose `from` isn't there any more (each with why), left out. A file that
    /// no longer parses changes nothing here.
    pub fn rebase(&mut self, changes: &[Change]) -> Result<Rebased, String> {
        let (fresh, _) = Self::load_from(&self.path)?;
        *self = fresh;
        let (mut made, mut conflicts) = (Vec::new(), Vec::new());
        for c in changes {
            match apply(&mut self.now, c) {
                Ok(()) => made.push(c.clone()),
                Err(e) => conflicts.push((c.clone(), e)),
            }
        }
        Ok((made, conflicts))
    }

    /// Write `now`: refused when the file changed since it was read ([`Doc::rebase`]
    /// first). The backup's path, when the file was there.
    pub fn save(&mut self) -> io::Result<Option<PathBuf>> {
        if self.changed_on_disk() {
            return Err(io::Error::other(format!(
                "{} changed since it was read",
                self.path.display()
            )));
        }
        let text = render(&self.now).map_err(io::Error::other)?;
        let backup = save(&self.path, &text)?;
        self.on_disk = text;
        self.stamp = Stamp::of(&self.path);
        Ok(backup)
    }
}

/// What a write through [`update`] did, for the lines that say so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    /// The copy of the file before (None: there was no file).
    pub backup: Option<PathBuf>,
    /// The file before was written by hand: its comments and layout are only in the copy.
    pub handwritten: bool,
    /// What the file before said that sentry doesn't know (unknown keys): only in the copy.
    pub dropped: Vec<String>,
}

impl Saved {
    /// One line each for what was kept aside, for a terminal.
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(b) = &self.backup {
            out.push(format!("kept a copy of the file before: {}", b.display()));
        }
        if self.handwritten {
            out.push(
                "the file was written by hand: its comments and layout were not kept (the copy has them)"
                    .into(),
            );
        }
        for d in &self.dropped {
            out.push(format!("not kept (the copy has it): {d}"));
        }
        out
    }
}

/// Read the file at `path` (none: the defaults), change it with `change`, write it through
/// [`render`] and [`save`]. A file that doesn't parse, or a change that fails, writes nothing.
pub fn update<T: ConfigFile>(
    path: &Path,
    change: impl FnOnce(&mut T) -> Result<(), String>,
) -> Result<Saved, String> {
    let (mut doc, dropped) = Doc::<T>::load_from(path)?;
    let handwritten = doc.handwritten();
    change(&mut doc.now)?;
    let backup = doc.save().map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Saved {
        backup,
        handwritten,
        dropped,
    })
}

fn read(path: &Path) -> Result<(String, Option<Stamp>), String> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok((t, Stamp::of(path))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok((String::new(), None)),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// What `init` (and the setup flow) proposes for one entry: the typed entry, and what it
/// wants said about it (what a draft's comments used to say), each at the path it is about.
#[derive(Debug, Clone, PartialEq)]
pub struct Draft<T> {
    pub entry: T,
    pub notes: Vec<Note>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// The setting it is about (`servers.myserver.timers`); None: the entry as a whole.
    pub path: Option<String>,
    pub text: String,
}

impl Note {
    pub fn on(path: &str, text: impl Into<String>) -> Self {
        Self {
            path: Some(path.to_string()),
            text: text.into(),
        }
    }

    pub fn whole(text: impl Into<String>) -> Self {
        Self {
            path: None,
            text: text.into(),
        }
    }
}

impl<T> Draft<T> {
    /// The notes as plain lines (`· timers: …`), for a terminal.
    pub fn note_lines(&self) -> Vec<String> {
        self.notes
            .iter()
            .map(|n| match &n.path {
                Some(p) => format!("· {p}: {}", n.text),
                None => format!("· {}", n.text),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
