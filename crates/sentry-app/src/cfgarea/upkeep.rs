//! Upkeep, per system: the workflows it has (the set its kind of device shares, or its own
//! set, which replaces the shared one whole), and how often each is due. "How often" is a
//! setting of the system's own entry (a server's `maintenance.cadence`, a network's, this
//! machine's `[jobs]`) and is staged like any other. A workflow's steps are edited in
//! `$EDITOR`, never here. "Its own copy" writes workflow files, which are not config files:
//! it is not part of the save box, asks in a box of its own that says what is copied where,
//! and copies the whole shared set (a system's folder replaces the shared set, so copying
//! one file would take the others away from it).

use std::path::{Path, PathBuf};

use sentry_core::cfg::{By, FileId};
use sentry_core::tui::form;
use sentry_core::tui::widgets;

use super::kind::{DocAny, Kind, Upkeep, WfRow};
use super::systems::UPKEEP;
use super::{Ask, ConfigArea, Yes};
use crate::app::Win;

/// Copy every workflow file of the shared set into a system's own folder (made when it
/// isn't there). Nothing that is there already is written over; nothing else is touched.
/// The names copied.
pub fn copy_set(shared: &Path, own: &Path) -> std::io::Result<Vec<String>> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(shared)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    std::fs::create_dir_all(own)?;
    let mut copied = Vec::new();
    for p in files {
        let Some(name) = p.file_name() else {
            continue;
        };
        let to = own.join(name);
        if to.exists() {
            continue;
        }
        std::fs::copy(&p, &to)?;
        copied.push(name.to_string_lossy().into_owned());
    }
    Ok(copied)
}

/// How a workflow's cadence reads in its field.
fn every_shown(r: &WfRow) -> String {
    r.every.clone()
}

/// A workflow in words: what it is for, where it comes from, what is wrong with it.
fn row_help(r: &WfRow, up: &Upkeep, settable: bool) -> String {
    let mut parts = Vec::new();
    if !r.title.is_empty() {
        parts.push(match r.title.ends_with('.') {
            true => r.title.clone(),
            false => format!("{}.", r.title),
        });
    }
    parts.push(match (r.what, r.own, &up.own) {
        ("job", _, _) => "A job of this machine's.".to_string(),
        (_, true, _) => "This system's own copy: it no longer follows the shared set.".to_string(),
        (_, false, Some(_)) => "From the set every system of its kind shares.".to_string(),
        (_, false, None) => "This machine's workflow.".to_string(),
    });
    if r.draft {
        parts.push("A draft: it won't start until `draft = true` is taken out of its file.".into());
    }
    for p in &r.problems {
        parts.push(format!("! {p}"));
    }
    parts.push(
        match (settable, r.default.as_str()) {
            (false, _) => "It runs when there is something for it to do: no cadence to set.",
            (true, "") => {
                "How often it is due: a duration (7d, 30d), `off`, or empty for not on a \
                 cadence."
            }
            (true, _) => {
                "How often it is due: a duration (7d, 30d), `off`, or empty for its own default."
            }
        }
        .to_string(),
    );
    if r.path.is_some() {
        parts.push("Its steps are edited in $EDITOR (e).".to_string());
    }
    parts.join(" ")
}

impl ConfigArea {
    /// A system's upkeep as the last group of its form: a field per workflow, its value
    /// how often it is due.
    pub(crate) fn upkeep_fields(
        &self,
        kind: &dyn Kind,
        doc: &dyn DocAny,
        entry: &str,
    ) -> Vec<form::Field> {
        let up = kind.upkeep(doc, entry, self.disk);
        let mut head = Some(match (&up.own, up.has_own) {
            (Some(_), true) => "Upkeep · its own workflows",
            (Some(_), false) => "Upkeep · the shared workflows",
            (None, _) => "Upkeep",
        });
        let staged = |name: &str| {
            kind.cadence(doc, entry, name, None)
                .is_some_and(|(path, _)| self.pending.iter().any(|p| p.change.path == path))
        };
        up.rows
            .iter()
            .map(|r| {
                let mut f = form::Field::new(
                    &format!("{UPKEEP}{}", r.name),
                    &r.name,
                    form::Value::Text(every_shown(r)),
                )
                .help(&row_help(
                    r,
                    &up,
                    kind.cadence(doc, entry, &r.name, None).is_some(),
                ))
                .empty(match r.default.as_str() {
                    "" => "not on a cadence",
                    d => d,
                });
                f.head = head.take().unwrap_or_default().to_string();
                f.problem = r.problems.first().cloned();
                // (One setting holds every cadence of the system: any of them staged marks
                // the row that differs from the file.)
                f.changed = staged(&r.name) && self.cadence_changed(kind, entry, r);
                f
            })
            .collect()
    }

    /// A workflow's cadence differs from what its file says.
    fn cadence_changed(&self, kind: &dyn Kind, entry: &str, r: &WfRow) -> bool {
        let Some(disk) = self.doc(kind.id()).map(|d| d.on_disk()) else {
            return false;
        };
        kind.upkeep(disk.as_ref(), entry, self.disk)
            .rows
            .iter()
            .find(|x| x.name == r.name)
            .is_none_or(|x| x.every != r.every)
    }

    /// "How often" was set for a workflow: staged in the system's own entry.
    pub(crate) fn set_cadence(
        &mut self,
        w: &mut Win,
        file: FileId,
        entry: &str,
        wf: &str,
        text: &str,
    ) -> Result<(), String> {
        let text = text.trim();
        let every = match text {
            "" => None,
            "off" => Some("off"),
            d => {
                d.parse::<sentry_core::config::Dur>()
                    .map_err(|e| format!("not a duration ({e}): 7d, 30d, `off`, or empty"))?;
                Some(d)
            }
        };
        let (path, to) = self
            .kind_doc(file)
            .and_then(|(k, d)| k.cadence(d, entry, wf, every))
            .ok_or_else(|| format!("`{wf}` has no cadence to set here"))?;
        self.stage(&path, to, By::You)?;
        self.lint(w);
        Ok(())
    }

    /// The workflow under the cursor of the system form in view.
    pub(crate) fn upkeep_here(&self) -> Option<(FileId, String, WfRow, Upkeep)> {
        let key = self.field_path()?;
        let wf = key.strip_prefix(UPKEEP)?;
        let (file, e) = match self.open_system() {
            Some(x) => x,
            None => self.system_here()?,
        };
        let (k, d) = self.kind_doc(file)?;
        let up = k.upkeep(d, &e.name, self.disk);
        let row = up.rows.iter().find(|r| r.name == wf)?.clone();
        Some((file, e.name, row, up))
    }

    /// `o` on a workflow: this system gets its own copy of the set, then the workflow opens
    /// in the editor. Asked first, in a box of its own; a system that has its own set (and
    /// this machine, which has no set per system) opens the file at once.
    pub(crate) fn own_copy(&mut self, w: &mut Win) {
        let Some((_, entry, row, up)) = self.upkeep_here() else {
            return w.toast("o is for a workflow under Upkeep");
        };
        let Some(path) = row.path.clone() else {
            return w.toast(&format!("{} is a job: it has no file of steps", row.name));
        };
        let Some(own) = up.own.clone().filter(|_| !up.has_own) else {
            self.edit = Some(path);
            return;
        };
        let names: Vec<String> = up
            .rows
            .iter()
            .filter_map(|r| r.path.as_ref()?.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .collect();
        let file = path.file_name().map(|n| n.to_string_lossy().into_owned());
        let lines = vec![
            format!(
                "Give {entry} its own copy of the workflows? {} copied:",
                match names.len() {
                    1 => "1 file is".to_string(),
                    n => format!("{n} files are"),
                }
            ),
            format!("  {}", names.join("  ")),
            format!("  from  {}", widgets::short_home(&up.shared)),
            format!("  to    {}", widgets::short_home(&own)),
            String::new(),
            format!(
                "From then on {entry} uses only its own copies: a change to the shared set \
                 (yours, or a newer sentry's) no longer reaches it. That is why all of them \
                 are copied: its folder replaces the shared set whole."
            ),
            "This writes workflow files, not config: it happens on Enter, not in the save box."
                .to_string(),
            format!(
                "Then {} opens in $EDITOR.",
                file.clone().unwrap_or_else(|| row.name.clone())
            ),
        ];
        self.ask = Some(Ask {
            title: "Its own copy of the workflows".into(),
            lines,
            enter: "copy and open",
            yes: Yes::OwnCopy {
                shared: up.shared.clone(),
                own: own.clone(),
                open: file.map(|f| own.join(f)),
            },
        });
    }

    /// Enter in that box.
    pub(crate) fn do_own_copy(
        &mut self,
        w: &mut Win,
        shared: &Path,
        own: &Path,
        open: Option<PathBuf>,
    ) {
        if w.offline {
            return w.toast("offline: nothing is copied");
        }
        match copy_set(shared, own) {
            Ok(copied) => {
                w.toast(&format!(
                    "copied {} to {}",
                    match copied.len() {
                        1 => "1 workflow".to_string(),
                        n => format!("{n} workflows"),
                    },
                    widgets::short_home(own)
                ));
                self.edit = open;
                self.refresh_forms(w);
            }
            Err(e) => w.toast(&format!("not copied: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn its_own_copy_is_the_whole_set_and_nothing_else() {
        let root = std::env::temp_dir().join(format!("sentry-ownset-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (shared, own) = (
            root.join("server-workflows"),
            root.join("servers/a/workflows"),
        );
        std::fs::create_dir_all(&shared).unwrap();
        for (name, text) in [
            ("apt-maintenance.toml", "name = \"a\"\n"),
            ("compose-update.toml", "name = \"b\"\n"),
            (".seeded.json", "{}"),
            ("notes.md", "not a workflow"),
        ] {
            std::fs::write(shared.join(name), text).unwrap();
        }
        let copied = copy_set(&shared, &own).unwrap();
        assert_eq!(copied, ["apt-maintenance.toml", "compose-update.toml"]);
        let mut there: Vec<String> = std::fs::read_dir(&own)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        there.sort();
        assert_eq!(there, ["apt-maintenance.toml", "compose-update.toml"]);
        assert_eq!(
            std::fs::read_to_string(own.join("compose-update.toml")).unwrap(),
            "name = \"b\"\n"
        );
        // The shared set is as it was, and nothing else was made beside the system's folder.
        assert_eq!(std::fs::read_dir(&shared).unwrap().count(), 4);
        let beside: Vec<String> = std::fs::read_dir(root.join("servers/a"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(beside, ["workflows"]);
        // Again: what is there is never written over.
        std::fs::write(own.join("compose-update.toml"), "edited").unwrap();
        assert!(copy_set(&shared, &own).unwrap().is_empty());
        assert_eq!(
            std::fs::read_to_string(own.join("compose-update.toml")).unwrap(),
            "edited"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
