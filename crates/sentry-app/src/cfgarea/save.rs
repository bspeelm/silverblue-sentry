//! The save box: what a save will write, said before anything is written, and the save
//! itself. Per file to be rewritten a line of scope (what changes, by entry), what follows
//! in the window, the copy that is kept, and that a hand-written file loses its comments.

use sentry_core::cfg::{self, FileId, Value};

use sentry_core::tui::widgets;

use super::kind::what_changed;
use super::systems::entry_path;
use super::{ConfigArea, Fx, Pending, SaveBox, Step, count};
use crate::app::Win;

/// What a staged change does to a system as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Whole {
    Added,
    Removed,
}

/// The longest a file's scope line gets before it is summed up.
const SCOPE_MAX: usize = 70;

impl ConfigArea {
    /// The files a save writes, each with its ticked changes in the order they were staged.
    fn to_save(&self) -> Vec<(FileId, Vec<&Pending>)> {
        cfg::FILES
            .into_iter()
            .map(|f| {
                (
                    f,
                    self.pending
                        .iter()
                        .filter(|p| p.change.file == f && p.change.on)
                        .collect::<Vec<_>>(),
                )
            })
            // (The setup's last step writes `config.toml` whatever is staged for it.)
            .filter(|(f, c)| {
                !c.is_empty()
                    || (*f == FileId::App
                        && self.write_app
                        && !self.doc(FileId::App).is_some_and(|d| d.there()))
            })
            .collect()
    }

    /// The system a change adds or removes as a whole, and its target.
    pub(crate) fn whole(&self, p: &Pending) -> Option<(Whole, String, String)> {
        let c = &p.change;
        let k = self.kind(c.file)?;
        let name = k.entry_of(&c.path);
        if entry_path(c.file, &name)? != c.path {
            return None;
        }
        let what = match (&c.from, &c.to) {
            (None, Some(_)) => Whole::Added,
            (Some(_), None) => Whole::Removed,
            _ => return None,
        };
        let target = match c.file {
            FileId::Servers => format!("srv:{name}"),
            FileId::Networks => format!("net:{name}"),
            FileId::App => return None,
        };
        Some((what, name, target))
    }

    /// The systems a save would remove that are at work now: each with what is running
    /// there. A save that would close one is refused before anything is written.
    pub(crate) fn busy_removals(&self) -> Vec<(String, Vec<String>)> {
        self.pending
            .iter()
            .filter(|p| p.change.on)
            .filter_map(|p| self.whole(p))
            .filter(|(what, _, _)| *what == Whole::Removed)
            .filter_map(|(_, name, target)| {
                let t = self.targets.iter().find(|t| t.id == target)?;
                (!t.going.is_empty()).then(|| (name, t.going.clone()))
            })
            .collect()
    }

    /// The entry a change belongs to and its setting's label.
    pub(crate) fn named(&self, p: &Pending) -> (String, String) {
        self.named_at(p.change.file, &p.change.path)
    }

    /// The entry a setting belongs to and its label.
    pub(crate) fn named_at(&self, file: FileId, path: &str) -> (String, String) {
        match self.kind(file) {
            Some(k) => (
                k.entry_of(path),
                cfg::fields::find(k.fields(), path)
                    .map_or_else(|| path.to_string(), |f| f.label.to_string()),
            ),
            None => (file.word().to_string(), path.to_string()),
        }
    }

    /// One line for what a file's changes are, by entry: `agent: Command · window: Keys`;
    /// too long, each entry's count; still too long, the counts alone.
    fn scope(&self, changes: &[&Pending]) -> String {
        let mut by_entry: Vec<(String, Vec<String>)> = Vec::new();
        for p in changes {
            let (entry, mut label) = self.named(p);
            match self.whole(p) {
                Some((Whole::Added, _, _)) => label = "added".to_string(),
                Some((Whole::Removed, _, _)) => label = "removed".to_string(),
                None => {}
            }
            match by_entry.iter_mut().find(|(e, _)| *e == entry) {
                Some((_, labels)) => labels.push(label),
                None => by_entry.push((entry, vec![label])),
            }
        }
        if changes.is_empty() {
            return "every setting at its default".to_string();
        }
        let full = by_entry
            .iter()
            .map(|(e, l)| format!("{e}: {}", l.join(", ")))
            .collect::<Vec<_>>()
            .join(" · ");
        if full.chars().count() <= SCOPE_MAX {
            return full;
        }
        let counted = by_entry
            .iter()
            .map(|(e, l)| format!("{e}: {}", count(l.len(), "setting")))
            .collect::<Vec<_>>()
            .join(" · ");
        if counted.chars().count() <= SCOPE_MAX {
            return counted;
        }
        format!(
            "{} in {}",
            count(changes.len(), "change"),
            match by_entry.len() {
                1 => "1 entry".to_string(),
                n => format!("{n} entries"),
            }
        )
    }

    /// What the window does once these are saved, each said once.
    fn follows(&self, changes: &[&Pending]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut say = |s: String| {
            if !out.contains(&s) {
                out.push(s);
            }
        };
        for p in changes {
            let c = &p.change;
            let top = c.path.split(['.', '[']).next().unwrap_or("");
            match (c.file, top) {
                (FileId::App, "keys") => say("keys are rebound now, in every target".into()),
                (FileId::App, "review") => {
                    say("reviews at start and after a run follow it from now".into())
                }
                (FileId::App, "retention") => {
                    say("records are pruned by the new limits now".into())
                }
                (FileId::App, "maintenance") => {
                    say("Claude reads these notes from the next plan or review".into())
                }
                (FileId::App, "ui") if c.path == "ui.terminal" => {
                    say("containers are entered in that terminal from now".into())
                }
                (FileId::App, "agent") => {
                    say("the agent's command is used from the next turn".into())
                }
                (FileId::App, "targets") => {
                    let shown: Option<Vec<String>> = match &c.to {
                        Some(Value::List(l)) => Some(
                            l.iter()
                                .filter_map(|v| match v {
                                    Value::Str(s) => Some(s.clone()),
                                    _ => None,
                                })
                                .collect(),
                        ),
                        _ => None,
                    };
                    // (A list that names none of them shows them all.)
                    let shown = shown.filter(|s| self.targets.iter().any(|t| s.contains(&t.id)));
                    let mut any = false;
                    for t in &self.targets {
                        let stays = shown.as_ref().is_none_or(|s| s.contains(&t.id));
                        if !stays && !t.hidden {
                            any = true;
                            say(match t.working {
                                true => format!(
                                    "{} leaves the strip (what it is doing goes on, out of view)",
                                    t.title
                                ),
                                false => format!("{} leaves the strip", t.title),
                            });
                        } else if stays && t.hidden {
                            any = true;
                            say(format!("{} is back in the strip", t.title));
                        }
                    }
                    if !any {
                        say("the strip is put in that order now".into());
                    }
                }
                (FileId::App, _) => say("the rest of config.toml is read at the next start".into()),
                (_, _) => {
                    let (entry, _) = self.named(p);
                    match self.whole(p) {
                        Some((Whole::Added, name, _)) => say(format!(
                            "{name} gets a tab (it starts when it first has the window)"
                        )),
                        Some((Whole::Removed, name, target)) => {
                            match self.targets.iter().any(|t| t.id == target) {
                                true => say(format!("{name}'s tab closes")),
                                false => say(format!("{name} is no longer configured")),
                            }
                        }
                        None if self.targets.iter().any(|t| {
                            Self::file_of(&t.id) == c.file
                                && t.id.split_once(':').is_some_and(|(_, n)| n == entry)
                        }) =>
                        {
                            say(format!("{entry} reads its settings again"))
                        }
                        None => {}
                    }
                }
            }
        }
        out
    }

    /// The save box's text, in order.
    pub fn save_lines(&self) -> Vec<String> {
        let files = self.to_save();
        let mut out = Vec::new();
        let mut kept = Vec::new();
        let mut warn = Vec::new();
        let all: Vec<&Pending> = files.iter().flat_map(|(_, c)| c.iter().copied()).collect();
        for (id, changes) in &files {
            let f = self.file(*id);
            let there = f.and_then(|f| f.doc.as_ref()).is_some_and(|d| d.there());
            out.push(format!(
                "  {:<21} {}{}",
                id.name(),
                self.scope(changes),
                if there { "" } else { "  (a new file)" }
            ));
            if there {
                kept.push(format!("{}.bak-<UTC time>", id.name()));
                if f.and_then(|f| f.doc.as_ref())
                    .is_some_and(|d| d.handwritten())
                {
                    warn.push(format!(
                        "! {} was written by hand: its comments and layout are not kept.",
                        id.name()
                    ));
                }
            }
            for w in f.map(|f| f.warnings.as_slice()).unwrap_or_default() {
                let w = super::Problem::of(*id, None, w).text;
                warn.push(format!("! {}: not kept either: {w}", id.name()));
            }
        }
        out.push(String::new());
        let line = |p: &Pending| {
            let (entry, label) = self.named(p);
            format!(
                "  {entry} · {}",
                match self.whole(p) {
                    Some((Whole::Added, _, _)) => "added, as drafted and reviewed".to_string(),
                    Some((Whole::Removed, _, _)) => "removed from the file".to_string(),
                    None => format!(
                        "{label}: {}",
                        match self.said_of(&p.change.path) {
                            Some(said) => said.to_string(),
                            None => what_changed(p.change.from.as_ref(), p.change.to.as_ref()),
                        }
                    ),
                }
            )
        };
        // Yours first; what the agent proposed apart, under its own heading.
        let (yours, agents): (Vec<&Pending>, Vec<&Pending>) =
            all.iter().partition(|p| p.change.by == cfg::By::You);
        out.extend(yours.iter().map(|p| line(p)));
        if !agents.is_empty() {
            if !yours.is_empty() {
                out.push(String::new());
            }
            out.push(format!(
                "Proposed by Claude, not by you ({}; Esc, then Space on one in the Overview \
                 unticks it):",
                count(agents.len(), "change")
            ));
            for p in &agents {
                out.push(format!("{}  (Claude)", line(p)));
                if let Some(why) = self.why_of(&p.change.path) {
                    out.push(format!("      its reason: {why}"));
                }
            }
        }
        out.push(String::new());
        let follows = self.follows(&all);
        out.push(match follows.is_empty() {
            true => "What follows: nothing in the window changes.".to_string(),
            false => format!("What follows: {}", follows.join(" · ")),
        });
        // A removed system's records are nobody's to touch here.
        for (what, name, target) in all.iter().filter_map(|p| self.whole(p)) {
            if what != Whole::Removed {
                continue;
            }
            let dirs: Vec<String> = Self::records_of(&target)
                .iter()
                .map(|d| widgets::short_home(d))
                .collect();
            out.push(format!(
                "{name}'s records (its log, plans, baseline, runs) stay on disk, untouched: {}",
                dirs.join(" and ")
            ));
        }
        out.push(match kept.len() {
            0 => "Kept before saving: nothing (there was no file).".to_string(),
            _ => format!(
                "Kept before saving: {} (beside it, the newest {})",
                kept.join(", "),
                cfg::BACKUPS
            ),
        });
        out.extend(warn);
        let unticked = self
            .pending
            .iter()
            .filter(|p| !p.change.on && p.conflict.is_none())
            .count();
        let conflicts = self.pending.iter().filter(|p| p.conflict.is_some()).count();
        if unticked + conflicts > 0 {
            let mut parts = Vec::new();
            if unticked > 0 {
                parts.push(format!("{unticked} unticked"));
            }
            if conflicts > 0 {
                parts.push(format!("{conflicts} that no longer fit the file"));
            }
            out.push(format!("Left out, still staged: {}.", parts.join(", ")));
        }
        out
    }

    /// `s`: the files are looked at once more, then the box says what Enter will write.
    pub(crate) fn open_save(&mut self, w: &mut Win) -> Option<Fx> {
        let changed = self.look(w);
        // A system that is at work isn't closed under what it is doing: said before
        // anything is written.
        let busy = self.busy_removals();
        if !busy.is_empty() {
            let mut lines = Vec::new();
            for (name, going) in &busy {
                lines.push(format!("! {name} is to be removed, and it is at work now:"));
                lines.extend(going.iter().map(|g| format!("  {g}")));
            }
            lines.push(String::new());
            lines.push(
                "Nothing is saved. Let it finish (or stop it) on its tab first, or take the \
                 removal back (u on it, in the Overview)."
                    .to_string(),
            );
            self.save = Some(SaveBox {
                lines,
                scroll: 0,
                refused: true,
            });
            return (!changed.is_empty()).then_some(Fx::Changed(changed));
        }
        if self.to_save().is_empty() {
            w.toast(if self.pending.is_empty() {
                "nothing to save"
            } else {
                "nothing ticked to save"
            });
        } else {
            self.save = Some(SaveBox {
                lines: self.save_lines(),
                scroll: 0,
                refused: false,
            });
        }
        (!changed.is_empty()).then_some(Fx::Changed(changed))
    }

    /// Enter in the save box: each file is written through `cfg` (the copy first), then
    /// read again; what was saved is no longer staged.
    pub(crate) fn do_save(&mut self, w: &mut Win) -> Option<Fx> {
        // What it was refused for may still hold: the box says so again.
        if self.save.as_ref().is_some_and(|b| b.refused) || !self.busy_removals().is_empty() {
            w.toast("nothing saved: a system to be removed is at work");
            return self.open_save(w);
        }
        // A file that changed while the box was open is not written over: the box says
        // what the save is now.
        if !self.look(w).is_empty() {
            w.toast("a file changed on disk meanwhile: this is what would be saved now");
            match self.to_save().is_empty() {
                true => self.save = None,
                false => {
                    self.save = Some(SaveBox {
                        lines: self.save_lines(),
                        scroll: 0,
                        refused: false,
                    })
                }
            }
            return None;
        }
        let files: Vec<FileId> = self.to_save().into_iter().map(|(f, _)| f).collect();
        let (mut saved, mut said) = (Vec::new(), Vec::new());
        let mut failed = None;
        // The systems this save adds, as the window will name them.
        let adds: Vec<(FileId, String)> = self
            .pending
            .iter()
            .filter(|p| p.change.on)
            .filter_map(|p| match self.whole(p) {
                Some((Whole::Added, _, target)) => Some((p.change.file, target)),
                _ => None,
            })
            .collect();
        for id in files {
            let Some(d) = self.doc_mut(id) else {
                continue;
            };
            match d.save() {
                Ok(backup) => {
                    said.push(match backup.as_ref().and_then(|b| b.file_name()) {
                        Some(b) => format!("{} (before: {})", id.name(), b.to_string_lossy()),
                        None => format!("{} (new)", id.name()),
                    });
                    saved.push(id);
                    self.pending
                        .retain(|p| !(p.change.file == id && p.change.on));
                }
                Err(e) => {
                    failed = Some(format!("{} not saved: {e}", id.name()));
                    break;
                }
            }
        }
        // What was written is read again; what is still staged is made on it.
        for id in &saved {
            if let Some(i) = self.at(*id) {
                let fresh = self.read(self.kinds[i].as_ref());
                self.files[i] = fresh;
            }
        }
        self.restage();
        self.lint(w);
        let old = self.form.take();
        self.form = self.build_form().map(|f| match &old {
            Some(o) => f.at(o),
            None => f,
        });
        self.cur = 0;
        match failed {
            Some(why) => {
                w.toast(&why);
                self.save = (!self.to_save().is_empty()).then(|| SaveBox {
                    lines: self.save_lines(),
                    scroll: 0,
                    refused: false,
                });
            }
            None => {
                self.save = None;
                w.toast(&format!("saved {}", said.join(", ")));
            }
        }
        self.added = adds
            .into_iter()
            .filter(|(f, _)| saved.contains(f))
            .map(|(_, t)| t)
            .collect();
        // What was drafted and is saved now is a system like any other.
        self.live_drafts();
        if self.save.is_none() && self.guide == Some(Step::Save) {
            self.guide_done();
        }
        (!saved.is_empty()).then_some(Fx::Changed(saved))
    }

    pub(crate) fn save_scroll(&mut self, down: bool) {
        if let Some(b) = self.save.as_mut() {
            b.scroll = match down {
                true => (b.scroll + 1).min(b.lines.len().saturating_sub(1)),
                false => b.scroll.saturating_sub(1),
            };
        }
    }

    pub(crate) fn save_at(&self) -> usize {
        self.save.as_ref().map_or(0, |b| b.scroll)
    }
}
