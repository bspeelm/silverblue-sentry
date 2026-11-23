//! Adding a system: the hosts sentry could look at (read from THIS machine only: the `Host`
//! entries of your ssh config, the default gateway, a name you type), ticked; one box that
//! says what a look reads; then each ticked host is looked at on a worker (the binary's
//! prober: reads only, `BatchMode` ssh), and what it drafts is staged as a new entry with
//! the draft's notes kept beside it for the review. Nothing is read anywhere before the
//! list opens, and no host before the box's Enter.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratatui::text::Line;
use sentry_core::cfg::{self, By, FileId, Seg, Value, parse_path};
use sentry_core::exec::Cmd;
use sentry_core::tui::form::{self, Form};
use sentry_core::tui::lineedit::LineEdit;
use sentry_core::tui::theme::Theme;
use sentry_core::tui::ticklist::{self, Row, TickList, Tone};
use sentry_core::tui::widgets;

use super::kind::{self, Drafted, Probe, Refused};
use super::systems::entry_path;
use super::{Ask, ConfigArea, Page, Prompt, Then, Yes};
use crate::app::{Event, Win};

/// Looks at one host and drafts its entry: the binary's (it alone knows every kind).
pub type Prober = Arc<dyn Fn(&str) -> Probe + Send + Sync>;

/// Where a host to look at came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    SshConfig,
    Gateway,
    Typed,
}

/// A host sentry could look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// What `ssh` would connect to.
    pub ssh: String,
    pub source: Source,
}

/// What a worker of the add flow sends back.
pub enum Msg {
    /// What was found on this machine.
    Candidates(Vec<Candidate>),
    /// What looking at a host came to.
    Probed(String, Probe),
}

/// Where a host stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Idle,
    Reading,
    Drafted { kind: &'static str, name: String },
    Failed(Refused),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cand {
    pub ssh: String,
    pub source: Source,
    pub state: State,
    pub ticked: bool,
}

/// The add flow's first page: the hosts, ticked or not, and where each stands.
pub struct Add {
    pub list: TickList,
    pub cands: Vec<Cand>,
    /// This machine is still being asked what it knows.
    pub looking: bool,
}

/// A system drafted here and staged to be added: what the review needs beside the staged
/// entry itself.
#[derive(Debug, Clone, PartialEq)]
pub struct DraftInfo {
    pub file: FileId,
    pub name: String,
    pub kind: &'static str,
    pub ssh: String,
    /// What the host is, in a few words.
    pub what: String,
    /// The draft's notes; a note's path is within the entry.
    pub notes: Vec<cfg::Note>,
    /// The entry as drafted, everything proposed in it.
    pub full: Value,
    /// What was unticked in the review: `<setting>#<index>`.
    pub off: BTreeSet<String>,
    pub reviewed: bool,
}

/// The review of one drafted system: what it proposes to watch, ticked; then its name.
pub struct Review {
    /// Which draft.
    pub at: usize,
    pub naming: bool,
    pub list: TickList,
    pub form: Form,
}

/// The file `ssh` reads its hosts from: `SENTRY_SSH_CONFIG` when set (tests, and whoever
/// points sentry at another), else `~/.ssh/config`.
pub fn ssh_config_path() -> PathBuf {
    match std::env::var("SENTRY_SSH_CONFIG") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => sentry_core::paths::home().join(".ssh/config"),
    }
}

/// The `Host` entries of an ssh config that name one host: no pattern (`*`, `?`), nothing
/// negated. A plain `Include` (no pattern) is followed, relative to the file's folder.
pub fn ssh_hosts(path: &Path) -> Vec<String> {
    fn read(path: &Path, depth: u8, out: &mut Vec<String>) {
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        for line in text.lines() {
            let line = line.trim();
            let (word, rest) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
                Some((w, r)) => (w, r.trim().trim_start_matches('=').trim()),
                None => continue,
            };
            if word.eq_ignore_ascii_case("host") {
                for h in rest.split_whitespace() {
                    let h = h.trim_matches('"');
                    if !h.is_empty() && !h.contains(['*', '?', '!']) && !out.iter().any(|x| x == h)
                    {
                        out.push(h.to_string());
                    }
                }
            } else if word.eq_ignore_ascii_case("include") && depth < 4 {
                for inc in rest.split_whitespace() {
                    let inc = inc.trim_matches('"');
                    if inc.contains(['*', '?']) {
                        continue;
                    }
                    let p = match inc.strip_prefix("~/") {
                        Some(r) => sentry_core::paths::home().join(r),
                        None if Path::new(inc).is_absolute() => PathBuf::from(inc),
                        None => path.parent().unwrap_or(Path::new(".")).join(inc),
                    };
                    read(&p, depth + 1, out);
                }
            }
        }
    }
    let mut out = Vec::new();
    read(path, 0, &mut out);
    out
}

/// The default gateway in `ip route show default`'s answer.
pub fn gateway(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let mut words = l.split_whitespace();
        (words.next() == Some("default")).then_some(())?;
        let mut words = words.skip_while(|w| *w != "via");
        words.next()?;
        words.next().map(str::to_string)
    })
}

/// What this machine knows of hosts to look at: its ssh config's hosts and its default
/// gateway. Reads of this machine only; no login anywhere.
pub fn candidates() -> Vec<Candidate> {
    let mut out: Vec<Candidate> = ssh_hosts(&ssh_config_path())
        .into_iter()
        .map(|ssh| Candidate {
            ssh,
            source: Source::SshConfig,
        })
        .collect();
    let route = Cmd::host("ip")
        .args(["route", "show", "default"])
        .output()
        .unwrap_or_default();
    if let Some(gw) = gateway(&route) {
        // A router's login is root.
        out.push(Candidate {
            ssh: format!("root@{gw}"),
            source: Source::Gateway,
        });
    }
    out
}

/// Why a host couldn't be looked at, in plain words, from what ssh said, and what to do.
/// sentry only ever logs in with a key, without asking (`BatchMode`).
pub fn refusal(ssh: &str, err: &str) -> Refused {
    let low = err.to_lowercase();
    let (why, todo): (&str, String) = if low.contains("permission denied") {
        (
            "it refused this machine's key",
            format!(
                "It wants a password, or a key this machine doesn't have. sentry logs in \
                 with your ssh key only and never asks for a password. Put your key on it (`ssh-copy-id {ssh}`), check that `ssh {ssh}` gets in \
                 without a prompt, then try again."
            ),
        )
    } else if low.contains("could not resolve hostname") || low.contains("name or service") {
        (
            "no host of that name",
            "Check the name: an alias in your ssh config, or user@host.".to_string(),
        )
    } else if low.contains("host key verification failed") {
        (
            "its host key isn't known here",
            format!(
                "Run `ssh {ssh}` once in a terminal and accept its key (after checking \
                 it), then try again."
            ),
        )
    } else if low.contains("timed out") || low.contains("timeout") {
        (
            "it didn't answer in time",
            "Is it on, and reachable from this machine? sentry waits 5 seconds.".to_string(),
        )
    } else if low.contains("connection refused") {
        (
            "it refused the connection",
            "Is ssh running there, on the port your ssh config names?".to_string(),
        )
    } else if low.contains("no route to host") || low.contains("unreachable") {
        (
            "it can't be reached from here",
            "Is it on this network, and switched on?".to_string(),
        )
    } else {
        (
            "ssh failed",
            format!(
                "ssh said: {}",
                err.lines()
                    .map(str::trim)
                    .rfind(|l| !l.is_empty())
                    .unwrap_or("nothing")
            ),
        )
    };
    Refused {
        ssh: ssh.to_string(),
        why: why.to_string(),
        todo,
    }
}

/// A name for a system from its ssh target: the host, as one word.
pub fn name_from(ssh: &str) -> String {
    let host = host_of(ssh);
    let name: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let name = name.trim_matches('-').to_string();
    if name.is_empty() {
        "system".to_string()
    } else {
        name
    }
}

/// The host part of an ssh target (`user@host` → `host`).
fn host_of(ssh: &str) -> &str {
    ssh.rsplit_once('@').map_or(ssh, |(_, h)| h)
}

impl Add {
    fn rows(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        let groups = [
            (Source::SshConfig, "From your ssh config", ""),
            (
                Source::Gateway,
                "This machine's default gateway",
                "likely your router",
            ),
            (Source::Typed, "Added by name", ""),
        ];
        for (source, head, note) in groups {
            let of: Vec<&Cand> = self.cands.iter().filter(|c| c.source == source).collect();
            if of.is_empty() {
                continue;
            }
            rows.push(Row::head(head).note(note));
            for c in of {
                let mut r = Row::tick(&c.ssh, &c.ssh, c.ticked);
                r = match &c.state {
                    State::Idle => r.detail(match c.source {
                        Source::SshConfig => {
                            "A host of your ssh config. Tick it to have sentry look at it."
                        }
                        Source::Gateway => {
                            "Where this machine sends what isn't local: usually your router. \
                             sentry can watch an OpenWrt router, logging in as root with a key."
                        }
                        Source::Typed => "A host you named.",
                    }),
                    State::Reading => r
                        .state("reading…", Tone::Busy)
                        .detail("sentry is logged in and reading. Nothing is changed there."),
                    State::Drafted { kind, name } => r
                        .state(
                            &format!(
                                "drafted as a {kind}{}",
                                if name == host_of(&c.ssh) || *name == c.ssh {
                                    String::new()
                                } else {
                                    format!(" · {name}")
                                }
                            ),
                            Tone::Good,
                        )
                        .detail(&format!(
                            "Drafted as the {kind} `{name}` and staged to be added: nothing is \
                             written before the save box. Enter goes on to review what it \
                             proposes to watch."
                        )),
                    State::Failed(f) => {
                        r.state(&format!("couldn't: {}", f.why), Tone::Bad)
                            .detail(&format!(
                                "sentry couldn't look at it: {}.\n{}\nTick it again (Space) and \
                             press Enter to try once more.",
                                f.why, f.todo
                            ))
                    }
                };
                rows.push(r);
            }
        }
        rows.push(Row::head("Another"));
        rows.push(
            Row::info("@name", "n  add one by name (an ssh alias, or user@host)").detail(
                "Any host ssh can reach with a key: an alias from your ssh config, or \
                 user@host. A router's login is root.",
            ),
        );
        rows
    }

    fn sync(&mut self) {
        let rows = self.rows();
        self.list.set_rows(rows);
    }

    /// The hosts a look would go to now: ticked, and not drafted or being read.
    fn to_read(&self) -> Vec<String> {
        self.cands
            .iter()
            .filter(|c| c.ticked && matches!(c.state, State::Idle | State::Failed(_)))
            .map(|c| c.ssh.clone())
            .collect()
    }

    fn reading(&self) -> usize {
        self.cands
            .iter()
            .filter(|c| c.state == State::Reading)
            .count()
    }
}

/// What a look reads, as its box says it.
pub const READS: &str = "its system and release; which services and timers run; its disks and \
    mounts; what listens; its compose projects; whether sudo asks. On a router: its \
    interfaces, its firewall's zones and forwards, its DHCP leases.";

impl ConfigArea {
    /// Every configured system's ssh destination: those aren't offered again.
    fn configured_ssh(&self) -> Vec<String> {
        self.systems()
            .into_iter()
            .filter_map(|(_, e)| e.ssh)
            .collect()
    }

    /// "+ add a system…": the list opens, and this machine is asked what it knows (on a
    /// worker; never offline: a test hands the hosts in).
    pub(crate) fn open_add(&mut self, w: &mut Win) {
        if self.add.is_none() {
            let mut add = Add {
                list: TickList::new("Hosts sentry could look at", Vec::new()),
                cands: Vec::new(),
                looking: !w.offline,
            };
            add.sync();
            self.add = Some(add);
            if !w.offline {
                let tx = self.tx.clone();
                std::thread::spawn(move || {
                    let _ = tx.send(Event::Config(Box::new(Msg::Candidates(candidates()))));
                });
            }
        }
        self.page = Page::Add;
        w.dirty = true;
    }

    /// What this machine knows came in: the hosts not configured yet, each once.
    pub(crate) fn on_candidates(&mut self, found: Vec<Candidate>) {
        let taken = self.configured_ssh();
        let Some(add) = self.add.as_mut() else {
            return;
        };
        add.looking = false;
        for c in found {
            let known = taken
                .iter()
                .any(|t| *t == c.ssh || host_of(t) == host_of(&c.ssh));
            if known || add.cands.iter().any(|x| x.ssh == c.ssh) {
                continue;
            }
            add.cands.push(Cand {
                ssh: c.ssh,
                source: c.source,
                state: State::Idle,
                ticked: false,
            });
        }
        add.sync();
        // The cursor on the first host (not on the line that says how to add one).
        if add
            .list
            .selected()
            .is_none_or(|r| r.kind != ticklist::Kind::Tick)
            && let Some(i) = add
                .list
                .rows
                .iter()
                .position(|r| r.kind == ticklist::Kind::Tick)
        {
            add.list.cur = i;
        }
    }

    /// A host typed by name joins the list, ticked.
    pub(crate) fn add_by_name(&mut self, w: &mut Win, ssh: &str) {
        let ssh = ssh.trim();
        if ssh.is_empty() {
            return;
        }
        if ssh.contains(char::is_whitespace) || ssh.starts_with('-') {
            return w.toast("an ssh target is one word: an alias, or user@host");
        }
        if self.configured_ssh().iter().any(|t| t == ssh) {
            return w.toast(&format!("{ssh} is configured already"));
        }
        let Some(add) = self.add.as_mut() else {
            return;
        };
        match add.cands.iter_mut().find(|c| c.ssh == ssh) {
            Some(c) => c.ticked = true,
            None => add.cands.push(Cand {
                ssh: ssh.to_string(),
                source: Source::Typed,
                state: State::Idle,
                ticked: true,
            }),
        }
        add.sync();
        if let Some(i) = add.list.rows.iter().position(|r| r.key == ssh) {
            add.list.cur = i;
        }
    }

    /// A key on the hosts' list. True: the flow is done with this page (go on).
    pub(crate) fn add_key(
        &mut self,
        w: &mut Win,
        k: &ratatui::crossterm::event::KeyEvent,
    ) -> AddFx {
        use ratatui::crossterm::event::KeyCode;
        let Some(add) = self.add.as_mut() else {
            return AddFx::Leave;
        };
        if !add.list.typing() && k.code == KeyCode::Char('n') {
            self.prompt = Some(Prompt {
                title: "Add a host by name".into(),
                label: "ssh".into(),
                help: "An alias from your ssh config, or user@host (a router's login is root). \
                       Key-based login is needed: sentry never asks for an ssh password."
                    .into(),
                line: LineEdit::default(),
                then: Then::AddHost,
            });
            return AddFx::Stay;
        }
        match add.list.key(k) {
            ticklist::Fx::Toggled(keys) => {
                for c in add.cands.iter_mut().filter(|c| keys.contains(&c.ssh)) {
                    c.ticked = !c.ticked;
                    // (One drafted or being read isn't looked at again by a tick.)
                    if matches!(c.state, State::Reading | State::Drafted { .. }) {
                        c.ticked = false;
                    }
                }
                add.sync();
                AddFx::Stay
            }
            ticklist::Fx::Enter => {
                let hosts = add.to_read();
                if add.reading() > 0 {
                    w.toast(&format!(
                        "still reading {}",
                        match add.reading() {
                            1 => "1 host".to_string(),
                            n => format!("{n} hosts"),
                        }
                    ));
                    AddFx::Stay
                } else if hosts.is_empty() {
                    AddFx::Done
                } else {
                    self.ask = Some(probe_box(&hosts));
                    AddFx::Stay
                }
            }
            ticklist::Fx::Leave => AddFx::Leave,
            ticklist::Fx::None => AddFx::Stay,
        }
    }

    /// Enter in the box: each host is looked at on a worker of its own (never offline: a
    /// test hands the answers in).
    pub(crate) fn start_probes(&mut self, w: &mut Win, hosts: &[String]) {
        for h in hosts {
            if !self.asked.contains(h) {
                self.asked.push(h.clone());
            }
        }
        if let Some(add) = self.add.as_mut() {
            for c in add.cands.iter_mut().filter(|c| hosts.contains(&c.ssh)) {
                c.state = State::Reading;
                c.ticked = false;
            }
            add.sync();
        }
        if w.offline {
            return;
        }
        let Some(prober) = self.prober.clone() else {
            return w.toast("this window can't look at hosts");
        };
        for h in hosts {
            let (tx, prober, h) = (self.tx.clone(), prober.clone(), h.clone());
            std::thread::spawn(move || {
                let p = prober(&h);
                let _ = tx.send(Event::Config(Box::new(Msg::Probed(h, p))));
            });
        }
    }

    /// A name no entry of `file` has: the one asked for, else with a number after it.
    fn free_name(&self, file: FileId, want: &str) -> String {
        let taken: Vec<String> = self
            .kind_doc(file)
            .map(|(k, d)| k.entries(d).into_iter().map(|e| e.name).collect())
            .unwrap_or_default();
        let base: String = want
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let base = base.trim_start_matches(['.', '-']).to_string();
        let base = if base.is_empty() {
            "system".to_string()
        } else {
            base
        };
        if !taken.contains(&base) {
            return base;
        }
        (2..)
            .map(|n| format!("{base}-{n}"))
            .find(|n| !taken.contains(n))
            .unwrap_or(base)
    }

    /// What looking at a host came to: a draft is staged as a new entry (yours: you ticked
    /// the host), its notes kept for the review; a refusal is said on its row.
    pub(crate) fn on_probed(&mut self, w: &mut Win, ssh: &str, probe: Probe) {
        let state = match probe {
            Probe::Failed(f) => State::Failed(f),
            Probe::Drafted(d) => match self.stage_draft(&d) {
                Ok(name) => State::Drafted { kind: d.kind, name },
                Err(why) => State::Failed(Refused {
                    ssh: ssh.to_string(),
                    why,
                    todo: "The draft doesn't fit the file as it is: e opens the file.".into(),
                }),
            },
        };
        if let Some(add) = self.add.as_mut() {
            if let Some(c) = add.cands.iter_mut().find(|c| c.ssh == ssh) {
                c.state = state;
                c.ticked = false;
            }
            add.sync();
        }
        self.lint(w);
        w.dirty = true;
    }

    fn stage_draft(&mut self, d: &Drafted) -> Result<String, String> {
        let name = self.free_name(d.file, &d.name);
        let path = entry_path(d.file, &name).ok_or("not a file that holds systems")?;
        self.stage(&path, Some(d.entry.clone()), By::You)?;
        self.drafts.push(DraftInfo {
            file: d.file,
            name: name.clone(),
            kind: d.kind,
            ssh: d.ssh.clone(),
            what: d.what.clone(),
            notes: d.notes.clone(),
            full: d.entry.clone(),
            off: BTreeSet::new(),
            reviewed: false,
        });
        Ok(name)
    }

    /// The drafts still staged to be added (one undone since is gone).
    pub(crate) fn live_drafts(&mut self) {
        let staged: Vec<bool> = self
            .drafts
            .iter()
            .map(|d| self.staged_add(d.file, &d.name).is_some())
            .collect();
        let mut it = staged.into_iter();
        self.drafts.retain(|_| it.next().unwrap_or(false));
    }

    /// The settings of a draft that are lists of things to watch: (path within the entry,
    /// label, the elements as rows' texts).
    fn proposals(&self, d: &DraftInfo) -> Vec<(String, &'static str, Vec<String>)> {
        let Some(kind) = self.kind(d.file) else {
            return Vec::new();
        };
        let Some(top) = super::systems::top(d.file) else {
            return Vec::new();
        };
        let prefix = format!("{top}.*.");
        let mut out = Vec::new();
        for f in kind.fields().iter().filter(|f| f.common) {
            let Some(rest) = f.path.strip_prefix(&prefix) else {
                continue;
            };
            if rest.contains(['[', '*']) {
                continue;
            }
            let Ok(segs) = parse_path(rest) else {
                continue;
            };
            let rows: Vec<String> = match (f.kind, d.full.at(&segs)) {
                (cfg::Kind::List, Some(Value::List(l))) => {
                    l.iter().map(|v| kind::plain(Some(v))).collect()
                }
                (cfg::Kind::Records, Some(Value::List(l))) => l
                    .iter()
                    .map(|r| match r {
                        Value::Map(m) => m
                            .iter()
                            .filter(|(_, v)| {
                                !matches!(v, Value::Null | Value::Bool(false))
                                    && *v != Value::Str(String::new())
                            })
                            .map(|(k, v)| match v {
                                Value::Bool(true) => k.clone(),
                                v => kind::plain(Some(v)),
                            })
                            .collect::<Vec<_>>()
                            .join(" · "),
                        v => kind::plain(Some(v)),
                    })
                    .collect(),
                (cfg::Kind::Map, Some(Value::Map(m))) => m
                    .iter()
                    .map(|(k, v)| match v {
                        Value::List(l) => format!(
                            "{k}: {}",
                            l.iter()
                                .map(|x| kind::plain(Some(x)))
                                .collect::<Vec<_>>()
                                .join(" ")
                        ),
                        v => format!("{k}: {}", kind::plain(Some(v))),
                    })
                    .collect(),
                _ => continue,
            };
            if !rows.is_empty() {
                out.push((rest.to_string(), f.label, rows));
            }
        }
        out
    }

    fn review_rows(&self, d: &DraftInfo) -> Vec<Row> {
        let whole: Vec<&str> = d
            .notes
            .iter()
            .filter(|n| n.path.is_none())
            .map(|n| n.text.as_str())
            .collect();
        let mut rows =
            vec![Row::head(&format!("{} · a {} over ssh {}", d.name, d.kind, d.ssh)).note(&d.what)];
        let props = self.proposals(d);
        if props.is_empty() {
            rows.push(
                Row::info(
                    "@none",
                    "nothing was found to propose: it is watched as it is",
                )
                .detail(&whole.join("\n")),
            );
        }
        for (rest, label, elems) in props {
            let note = kind::note_on(&d.notes, &rest).unwrap_or("");
            rows.push(Row::head(label).note(note));
            for (i, text) in elems.iter().enumerate() {
                let key = format!("{rest}#{i}");
                rows.push(
                    Row::tick(&key, text, !d.off.contains(&key)).detail(&format!(
                        "{}{}\nUnticked, it is left out of what sentry watches on {}.",
                        if note.is_empty() {
                            String::new()
                        } else {
                            format!("{label}: {note}\n")
                        },
                        whole.join(" "),
                        d.name
                    )),
                );
            }
        }
        rows
    }

    /// The entry as drafted without what was unticked.
    fn draft_entry(d: &DraftInfo) -> Value {
        let mut entry = d.full.clone();
        // Highest index first, so the ones before it keep their places.
        let mut off: Vec<(String, usize)> = d
            .off
            .iter()
            .filter_map(|k| {
                let (rest, i) = k.rsplit_once('#')?;
                Some((rest.to_string(), i.parse().ok()?))
            })
            .collect();
        off.sort_by_key(|a| std::cmp::Reverse(a.1));
        for (rest, i) in off {
            let Ok(segs) = parse_path(&rest) else {
                continue;
            };
            match entry.at_mut(&segs) {
                Some(Value::List(l)) if i < l.len() => {
                    l.remove(i);
                }
                Some(Value::Map(m)) if i < m.len() => {
                    m.remove(i);
                }
                _ => {}
            }
        }
        entry
    }

    /// The setting of an entry that is its ssh destination, within the entry.
    fn ssh_setting(&self, file: FileId) -> Option<String> {
        let top = super::systems::top(file)?;
        let prefix = format!("{top}.*.");
        self.kind(file)?
            .fields()
            .iter()
            .find(|f| f.path.ends_with(".ssh") && f.path.starts_with(&prefix))
            .map(|f| f.path[prefix.len()..].to_string())
    }

    fn name_form(&self, d: &DraftInfo) -> Form {
        Form::new(
            &format!("{} · its name and how it is reached", d.name),
            vec![
                form::Field::new("@name", "Name", form::Value::Text(d.name.clone())).help(
                    "What it is called in the window and in `[targets] show`, and the folder \
                     its records are kept in. One word.",
                ),
                form::Field::new("@ssh", "ssh", form::Value::Text(d.ssh.clone())).help(
                    "What `ssh` connects to: an alias from your ssh config, or user@host. \
                     Key-based login is required.",
                ),
            ],
        )
    }

    /// The review opens on the first drafted system not reviewed yet. False: there is none.
    pub(crate) fn open_review(&mut self, w: &mut Win) -> bool {
        self.live_drafts();
        let Some(at) = self.drafts.iter().position(|d| !d.reviewed) else {
            self.review = None;
            return false;
        };
        let d = &self.drafts[at];
        self.review = Some(Review {
            at,
            naming: false,
            list: TickList::new(
                &format!("{} · what sentry would watch", d.name),
                self.review_rows(d),
            ),
            form: self.name_form(d),
        });
        self.page = Page::Review;
        w.dirty = true;
        true
    }

    /// A key in the review. What became of the page.
    pub(crate) fn review_key(
        &mut self,
        w: &mut Win,
        k: &ratatui::crossterm::event::KeyEvent,
    ) -> AddFx {
        use ratatui::crossterm::event::{KeyCode, KeyEvent};
        let Some(r) = self.review.as_mut() else {
            return AddFx::Done;
        };
        let at = r.at;
        if !r.naming {
            return match r.list.key(k) {
                ticklist::Fx::Toggled(keys) => {
                    let Some(d) = self.drafts.get_mut(at) else {
                        return AddFx::Stay;
                    };
                    for key in keys {
                        if !d.off.remove(&key) {
                            d.off.insert(key);
                        }
                    }
                    let (file, name, entry) = (d.file, d.name.clone(), Self::draft_entry(d));
                    if let Some(path) = entry_path(file, &name)
                        && let Err(why) = self.stage(&path, Some(entry), By::You)
                    {
                        w.toast(&format!("not staged: {why}"));
                    }
                    self.lint(w);
                    AddFx::Stay
                }
                ticklist::Fx::Enter => {
                    r.naming = true;
                    AddFx::Stay
                }
                ticklist::Fx::Leave => AddFx::Leave,
                ticklist::Fx::None => AddFx::Stay,
            };
        }
        // Its name and ssh: Enter goes on; Space (or e) edits the field under the cursor.
        if !r.form.captures() {
            match k.code {
                KeyCode::Enter => {
                    if let Some(d) = self.drafts.get_mut(at) {
                        d.reviewed = true;
                    }
                    return match self.open_review(w) {
                        true => AddFx::Stay,
                        false => AddFx::Done,
                    };
                }
                KeyCode::Backspace | KeyCode::Char('b') => {
                    r.naming = false;
                    return AddFx::Stay;
                }
                KeyCode::Char(' ' | 'e') => {
                    r.form.key(&KeyEvent::from(KeyCode::Enter));
                    return AddFx::Stay;
                }
                _ => {}
            }
        }
        match r.form.key(k) {
            form::Fx::Leave => r.naming = false,
            form::Fx::Set(key, v) => {
                let text = match &v {
                    form::Value::Text(s) => s.trim().to_string(),
                    _ => String::new(),
                };
                let Some(d) = self.drafts.get(at).cloned() else {
                    return AddFx::Stay;
                };
                let done = match key.as_str() {
                    "@name" => self.rename(d.file, &d.name, &text),
                    _ => self.draft_ssh(at, &text),
                };
                self.lint(w);
                let fresh = self.drafts.get(at).map(|d| self.name_form(d));
                if let (Some(r), Some(fresh)) = (self.review.as_mut(), fresh) {
                    r.form = fresh.at(&r.form);
                    if let Err(why) = done {
                        r.form.refuse(&key, &why);
                    } else if let Some(d) = self.drafts.get(at) {
                        r.list.title = format!("{} · what sentry would watch", d.name);
                    }
                }
            }
            _ => {}
        }
        AddFx::Stay
    }

    /// A drafted system's ssh destination was typed.
    fn draft_ssh(&mut self, at: usize, ssh: &str) -> Result<(), String> {
        if ssh.is_empty() || ssh.contains(char::is_whitespace) || ssh.starts_with('-') {
            return Err("an ssh target is one word: an alias, or user@host".into());
        }
        let Some(d) = self.drafts.get(at) else {
            return Ok(());
        };
        let (file, name) = (d.file, d.name.clone());
        let rest = self.ssh_setting(file).ok_or("it has no ssh setting")?;
        let mut segs = parse_path(&rest)?;
        let mut full = d.full.clone();
        // (A section that isn't in the entry yet is made on the way.)
        let last = segs.pop().ok_or("it has no ssh setting")?;
        for i in 0..segs.len() {
            if full.at(&segs[..=i]).is_none() {
                full.set(&segs[..=i], Some(Value::Map(Vec::new())))?;
            }
        }
        segs.push(last);
        full.set(&segs, Some(Value::Str(ssh.to_string())))?;
        let d = &mut self.drafts[at];
        d.full = full;
        d.ssh = ssh.to_string();
        let entry = Self::draft_entry(d);
        let path = entry_path(file, &name).ok_or("not a file that holds systems")?;
        self.stage(&path, Some(entry), By::You)
    }

    /// The hosts looked at in this window, as they were ticked and confirmed: the only
    /// ones anything here may be asked to look at again.
    pub fn hosts_asked(&self) -> &[String] {
        &self.asked
    }

    /// What the add page says beside its list.
    pub(crate) fn add_lines(&self, t: &Theme, offline: bool) -> Vec<Line<'static>> {
        let Some(add) = &self.add else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if add.looking {
            out.push(Line::styled(
                "looking at this machine's ssh config and routes…",
                t.dim(),
            ));
        } else if add.cands.is_empty() {
            out.push(Line::styled(
                if offline {
                    "this machine wasn't asked what it knows"
                } else {
                    "nothing found here that isn't configured already"
                },
                t.dim(),
            ));
        }
        let (ticked, reading) = (add.to_read().len(), add.reading());
        let drafted = add
            .cands
            .iter()
            .filter(|c| matches!(c.state, State::Drafted { .. }))
            .count();
        out.push(Line::styled(
            match (reading, ticked, drafted) {
                (n, _, _) if n > 0 => format!("Reading {n}: nothing is changed on them."),
                (_, 0, 0) => "Tick the hosts sentry should look at; Enter with none ticked \
                              goes on with just what there is."
                    .to_string(),
                (_, 0, n) => format!("{n} drafted and staged. Enter reviews what they propose."),
                (_, n, _) => format!(
                    "Enter: one box says what sentry reads on {}, then it looks.",
                    match n {
                        1 => "it".to_string(),
                        n => format!("the {n}"),
                    }
                ),
            },
            t.fg(),
        ));
        out.push(Line::styled(
            "Nothing was read anywhere to make this list: it is this machine's own.",
            t.dim(),
        ));
        out
    }
}

/// What a key on one of the add flow's pages came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddFx {
    Stay,
    /// The page is done with: on to the next.
    Done,
    /// Esc: the page is left.
    Leave,
}

/// The one box before any host is looked at.
fn probe_box(hosts: &[String]) -> Ask {
    let n = hosts.len();
    let mut lines = vec![
        format!(
            "sentry logs in to {} with your ssh key and reads:",
            match n {
                1 => "1 host".to_string(),
                n => format!("{n} hosts"),
            }
        ),
        format!("  {}", widgets::trunc(&hosts.join("  "), 200)),
        String::new(),
        READS.split_whitespace().collect::<Vec<_>>().join(" "),
        String::new(),
        "Nothing is changed on them. No password is asked for: a host that wants one is said \
         to, and stays in the list."
            .to_string(),
        "What each says becomes a draft, staged here: nothing is written before the save box."
            .to_string(),
    ];
    lines.retain(|l| !l.starts_with("  ") || !l.trim().is_empty());
    Ask {
        title: "Look at these hosts".into(),
        lines,
        enter: "look",
        yes: Yes::Probe(hosts.to_vec()),
    }
}

/// A path as it is typed, `~` being home.
pub(crate) fn expand(path: &str) -> PathBuf {
    match path.trim().strip_prefix("~/") {
        Some(r) => sentry_core::paths::home().join(r),
        None => PathBuf::from(path.trim()),
    }
}

/// Whether a segment list is an entry's own path (`servers.<name>`).
pub(crate) fn is_entry(segs: &[Seg]) -> bool {
    matches!(segs, [Seg::Key(t), Seg::Key(_)] if t == "servers" || t == "networks")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ssh_configs_hosts_are_the_ones_that_name_one_host() {
        let dir = std::env::temp_dir().join(format!("sentry-sshcfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("more")).unwrap();
        std::fs::write(
            dir.join("config"),
            "# mine\nInclude more/extra\nInclude conf.d/*\nHost myserver other\n  HostName 192.0.2.10\n\
             host=myrouter\nHost *\n  User me\nHost *.example !skip web?\nHost \"quoted\"\nHost myserver\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("more/extra"),
            "Host included\n  User x\nInclude ../config\n",
        )
        .unwrap();
        assert_eq!(
            ssh_hosts(&dir.join("config")),
            ["included", "myserver", "other", "myrouter", "quoted"]
        );
        assert!(ssh_hosts(&dir.join("nope")).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_gateway_is_the_default_routes() {
        assert_eq!(
            gateway("default via 192.0.2.1 dev eth0 proto dhcp src 192.0.2.50 metric 100\n")
                .as_deref(),
            Some("192.0.2.1")
        );
        assert_eq!(gateway("default dev wg0 scope link\n"), None);
        assert_eq!(gateway(""), None);
        assert_eq!(host_of("root@192.0.2.1"), "192.0.2.1");
    }

    #[test]
    fn a_refusal_says_why_in_plain_words_and_what_to_do() {
        let r = refusal(
            "myserver",
            "ssh: connect to host 192.0.2.10 port 22: Connection timed out",
        );
        assert_eq!(r.why, "it didn't answer in time");
        let r = refusal(
            "admin@myserver",
            "admin@192.0.2.10: Permission denied (publickey,password).",
        );
        assert_eq!(r.why, "it refused this machine's key");
        assert!(r.todo.contains("ssh-copy-id admin@myserver"), "{}", r.todo);
        assert_eq!(
            refusal(
                "nope",
                "ssh: Could not resolve hostname nope: Name or service not known"
            )
            .why,
            "no host of that name"
        );
        assert_eq!(
            refusal("x", "Host key verification failed.").why,
            "its host key isn't known here"
        );
        let r = refusal("x", "something else\nbroke here\n");
        assert_eq!(
            (r.why.as_str(), r.todo.as_str()),
            ("ssh failed", "ssh said: broke here")
        );
        assert_eq!(name_from("admin@192.0.2.10"), "192-0-2-10");
        assert_eq!(name_from("myserver"), "myserver");
    }
}
