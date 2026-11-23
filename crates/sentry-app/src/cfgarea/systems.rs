//! A server's and a network's settings in forms, as this machine's are: the entry's sections,
//! its lists of records (a row opens as a form of its own; `n` adds one, `x` takes one away),
//! its name, its upkeep, and its connection checks. Every edit is staged as a `cfg::Change`;
//! a list of records is staged whole at its own path, like every other list.
//!
//! Renaming: a system that is in its file keeps its name here. Its records (log, plans,
//! baseline, runs, metrics) live under that name, and nothing in this window moves or
//! deletes records; the file in `$EDITOR` is where a rename is done, by whoever also moves
//! them. A system only staged (added here, not saved yet) has no records and takes a new
//! name freely.

use sentry_core::cfg::{self, By, FileId, Seg, Value, parse_path, path_string};
use sentry_core::tui::form::{self, Form};

use super::kind::{self, CheckLine, DocAny, Kind};
use super::{ConfigArea, Entry, Pending, Screen};
use crate::app::{Event, Win};

/// A record's own form, in front of its system's.
pub struct RowEdit {
    pub file: FileId,
    /// The list it is in (`servers.myserver.timers`).
    pub list: String,
    pub at: usize,
    pub form: Form,
}

/// The connection checks of one system: running, or what they said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub file: FileId,
    pub entry: String,
    pub running: bool,
    pub lines: Vec<CheckLine>,
}

/// What a worker that ran a system's checks sends back.
pub struct ChecksDone {
    pub file: FileId,
    pub entry: String,
    pub lines: Vec<CheckLine>,
}

/// A form field that is the system's name, not a setting of it.
const NAME: &str = "@name";
/// A form field that is one of the system's workflows: how often it is due.
pub(crate) const UPKEEP: &str = "@upkeep:";

/// The top-level key a file's entries are under.
pub(crate) fn top(file: FileId) -> Option<&'static str> {
    match file {
        FileId::Servers => Some("servers"),
        FileId::Networks => Some("networks"),
        FileId::App => None,
    }
}

/// An entry's path in its file: `servers.myserver`.
pub(crate) fn entry_path(file: FileId, name: &str) -> Option<String> {
    Some(path_string(&[
        Seg::Key(top(file)?.to_string()),
        Seg::Key(name.to_string()),
    ]))
}

/// A name a system can have: one word (it names a folder and a target).
pub fn name_problem(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        Some("a name is needed")
    } else if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        || name.starts_with(['.', '-'])
    {
        Some("a name is one word: letters, digits, - _ . (it names a folder and a tab)")
    } else {
        None
    }
}

impl ConfigArea {
    /// The system whose form is open on a list screen: its file and its entry.
    pub(crate) fn open_system(&self) -> Option<(FileId, Entry)> {
        let l = self.list_of(self.screen)?;
        let file = self.screen.file()?;
        let e = self.entries_of(self.screen).into_iter().nth(self.list[l])?;
        self.open.then_some((file, e))
    }

    /// The system the cursor is on: the Overview's row, a list's, this machine on its
    /// screen.
    pub(crate) fn system_here(&self) -> Option<(FileId, Entry)> {
        match self.screen {
            Screen::Overview => self.systems().into_iter().nth(self.cur),
            Screen::Servers | Screen::Networks => {
                let l = self.list_of(self.screen)?;
                let file = self.screen.file()?;
                self.entries_of(self.screen)
                    .into_iter()
                    .nth(self.list[l])
                    .map(|e| (file, e))
            }
            Screen::Machine => self.systems().into_iter().find(|(f, _)| *f == FileId::App),
            _ => None,
        }
    }

    /// The staged change that adds this entry, if it is only staged.
    pub(crate) fn staged_add(&self, file: FileId, name: &str) -> Option<usize> {
        let path = entry_path(file, name)?;
        self.pending
            .iter()
            .position(|p| p.change.path == path && p.change.from.is_none() && p.change.on)
    }

    /// A system's form: its name, its sections, its upkeep.
    pub(crate) fn system_form(&self, file: FileId, e: &Entry) -> Option<Form> {
        let kind = self.kind(file)?;
        let doc = self.doc(file)?;
        let mut fields = vec![
            form::Field::new(NAME, "Name", form::Value::Text(e.name.clone()))
                .head("Who it is")
                .help(
                    "Its name in the window, in `[targets] show`, and of the folder its \
                     records are kept in. A system that is saved keeps its name here: its \
                     log, plans and baseline are under it.",
                ),
        ];
        let mut rest = self.form_fields(kind, doc, &kind.sections(doc, &e.name));
        // (The name's group goes on with the first section's fields.)
        if let Some(first) = rest.first_mut().filter(|f| f.head == "Who it is") {
            first.head.clear();
        }
        fields.append(&mut rest);
        fields.extend(self.upkeep_fields(kind, doc, &e.name));
        Some(Form::new(&format!("{} · {}", e.name, e.kind), fields))
    }

    /// The columns a list of records shows and its rows' form has: the record's settings
    /// the table marks essential, in the table's order.
    pub(crate) fn record_fields(&self, kind: &dyn Kind, list: &str) -> Vec<&'static cfg::Field> {
        let Some(spec) = cfg::fields::find(kind.fields(), list) else {
            return Vec::new();
        };
        let prefix = format!("{}[].", spec.path);
        kind.fields()
            .iter()
            .filter(|f| {
                f.essential
                    && f.kind != cfg::Kind::Section
                    && f.path
                        .strip_prefix(&prefix)
                        .is_some_and(|leaf| !leaf.contains(['.', '[']))
            })
            .collect()
    }

    /// A list of records as rows: the essential columns only.
    pub(crate) fn rows_of(&self, kind: &dyn Kind, list: &str, v: Option<&Value>) -> form::Value {
        let cols: Vec<&cfg::Field> = self.record_fields(kind, list);
        let leaf = |f: &cfg::Field| f.path.rsplit('.').next().unwrap_or("").to_string();
        let rows = match v {
            Some(Value::List(l)) => l
                .iter()
                .map(|r| {
                    cols.iter()
                        .map(|c| match r.get(&leaf(c)) {
                            None | Some(Value::Null) => "–".to_string(),
                            Some(Value::Str(s)) if s.is_empty() => "–".to_string(),
                            Some(Value::Str(s)) => s.clone(),
                            Some(Value::Bool(true)) => "yes".to_string(),
                            Some(Value::Bool(false)) => "no".to_string(),
                            Some(v) => v.to_string(),
                        })
                        .collect()
                })
                .collect(),
            _ => Vec::new(),
        };
        form::Value::Rows(cols.iter().map(|c| c.label.to_lowercase()).collect(), rows)
    }

    /// The form of one record: its essential settings, each at its own path.
    fn row_form(&self, file: FileId, list: &str, at: usize) -> Option<Form> {
        let kind = self.kind(file)?;
        let doc = self.doc(file)?;
        let tree = doc.tree();
        let spec = cfg::fields::find(kind.fields(), list)?;
        let mut fields = Vec::new();
        for f in self.record_fields(kind, list) {
            let leaf = f.path.rsplit('.').next().unwrap_or("");
            let path = format!("{list}[{at}].{leaf}");
            let segs = parse_path(&path).ok()?;
            let now = tree.at(&segs);
            let value = match kind.choices(doc, &path, self.disk) {
                // One of what there is; the first row is "none of them".
                Some(words) => {
                    let mut all = vec![NONE.to_string()];
                    all.extend(words);
                    let cur = match now {
                        Some(Value::Str(s)) => s.clone(),
                        _ => NONE.to_string(),
                    };
                    let at = match all.iter().position(|w| *w == cur) {
                        Some(i) => i,
                        None => {
                            all.push(cur);
                            all.len() - 1
                        }
                    };
                    form::Value::Pick(all, at)
                }
                None => match kind::to_form(f.kind, now) {
                    Some(v) => v,
                    // (A choice the record doesn't say: its first word.)
                    None => match f.kind {
                        cfg::Kind::Choice(words) => {
                            form::Value::Pick(words.iter().map(|w| w.to_string()).collect(), 0)
                        }
                        cfg::Kind::Bool => form::Value::Bool(false),
                        cfg::Kind::Number => form::Value::Int(0),
                        _ => form::Value::Text(String::new()),
                    },
                },
            };
            let mut x = form::Field::new(&path, f.label, value).help(f.help);
            if f.kind == cfg::Kind::Number {
                x.range = Some((0, i64::MAX));
            }
            fields.push(x);
        }
        let entry = kind.entry_of(list);
        Some(Form::new(
            &format!("{entry} · {} · {}", spec.label.to_lowercase(), at + 1),
            fields,
        ))
    }

    /// Enter on a record's row: its form.
    pub(crate) fn open_row(&mut self, file: FileId, list: &str, at: usize) {
        if let Some(form) = self.row_form(file, list, at) {
            self.row = Some(RowEdit {
                file,
                list: list.to_string(),
                at,
                form,
            });
        }
    }

    /// The list at `list` as it is to be.
    fn list_now(&self, file: FileId, list: &str) -> Vec<Value> {
        let segs = parse_path(list).unwrap_or_default();
        match self
            .doc(file)
            .map(|d| d.tree())
            .and_then(|t| t.at(&segs).cloned())
        {
            Some(Value::List(l)) => l,
            _ => Vec::new(),
        }
    }

    /// `n` in a list of records: one more, as its kind starts one, and its form.
    pub(crate) fn add_row(&mut self, w: &mut Win, file: FileId, list: &str) {
        let Some(blank) = self.kind(file).and_then(|k| k.blank(list)) else {
            return w.toast("nothing to add here: e opens the file");
        };
        let mut l = self.list_now(file, list);
        l.push(blank);
        let at = l.len() - 1;
        match self.stage(list, Some(Value::List(l)), By::You) {
            Ok(()) => {
                self.refresh_forms(w);
                self.open_row(file, list, at);
            }
            Err(why) => w.toast(&format!("not added: {why}")),
        }
    }

    /// `x` on a record's row: staged without it.
    pub(crate) fn remove_row(&mut self, w: &mut Win, file: FileId, list: &str, at: usize) {
        let mut l = self.list_now(file, list);
        if at >= l.len() {
            return;
        }
        l.remove(at);
        match self.stage(list, Some(Value::List(l)), By::You) {
            Ok(()) => self.refresh_forms(w),
            Err(why) => w.toast(&format!("not removed: {why}")),
        }
    }

    /// A record's field was set in its form: the list it is in is staged with it.
    pub(crate) fn row_set(&mut self, w: &mut Win, path: &str, v: &form::Value) {
        let Some(row) = self.row.as_ref() else {
            return;
        };
        let (file, list, at) = (row.file, row.list.clone(), row.at);
        let leaf = path.rsplit('.').next().unwrap_or("").to_string();
        let mut l = self.list_now(file, &list);
        let Some(rec) = l.get_mut(at) else {
            return;
        };
        // What an empty answer means: unset where the record may leave it out.
        let nullable = self
            .kind(file)
            .and_then(|k| k.blank(&list))
            .is_none_or(|b| matches!(b.get(&leaf), None | Some(Value::Null)));
        let to = match v {
            form::Value::Pick(words, i) if words.get(*i).is_some_and(|x| x == NONE) => Value::Null,
            v => kind::from_form(v, nullable),
        };
        // (What reads the same is no change: a port typed as it was.)
        let same = |a: &Value, b: &Value| a == b || kind::plain(Some(a)) == kind::plain(Some(b));
        let staged = if rec.get(&leaf).is_some_and(|now| same(now, &to)) {
            Ok(())
        } else {
            rec.set(&[Seg::Key(leaf)], Some(to))
                .and_then(|()| self.stage(&list, Some(Value::List(l)), By::You))
        };
        self.refresh_forms(w);
        if let (Err(why), Some(r)) = (staged, self.row.as_mut()) {
            r.form.refuse(path, &why);
        }
    }

    /// The forms in view made again from the files as they are to be, each where it was.
    pub(crate) fn refresh_forms(&mut self, w: &mut Win) {
        self.lint(w);
        let fresh = self.build_form();
        self.form = match (fresh, self.form.take()) {
            (Some(f), Some(old)) => Some(f.at(&old)),
            (f, _) => f,
        };
        if let Some(r) = self.row.take() {
            self.row = self.row_form(r.file, &r.list, r.at).map(|form| RowEdit {
                form: form.at(&r.form),
                ..r
            });
        }
    }

    /// The name field was set. A staged system is staged under its new name; a saved one
    /// keeps its name (its records are under it).
    pub(crate) fn rename(&mut self, file: FileId, old: &str, new: &str) -> Result<(), String> {
        let new = new.trim();
        if new == old {
            return Ok(());
        }
        if let Some(why) = name_problem(new) {
            return Err(why.to_string());
        }
        let taken = self
            .kind(file)
            .zip(self.doc(file))
            .is_some_and(|(k, d)| k.entries(d).iter().any(|e| e.name == new));
        if taken {
            return Err(format!("there is a `{new}` already"));
        }
        let Some(i) = self.staged_add(file, old) else {
            return Err(format!(
                "`{old}` is saved under that name, and its records (log, plans, baseline) \
                 are kept under it: sentry doesn't move them. To rename it, edit the file \
                 (e) and move its folders yourself"
            ));
        };
        let (Some(to), Some(path)) = (self.pending[i].change.to.clone(), entry_path(file, new))
        else {
            return Ok(());
        };
        let by = self.pending[i].change.by;
        self.pending.remove(i);
        self.restage();
        self.stage(&path, Some(to), by)?;
        for d in &mut self.drafts {
            if d.file == file && d.name == old {
                d.name = new.to_string();
            }
        }
        for c in &mut self.checks {
            if c.file == file && c.entry == old {
                c.entry = new.to_string();
            }
        }
        Ok(())
    }

    /// `x` on a system: its removal is staged (one only staged is no longer staged). Its
    /// records on disk are nobody's to touch here: the save box says where they are.
    pub(crate) fn remove_system(&mut self, w: &mut Win, file: FileId, name: &str) {
        let Some(path) = entry_path(file, name) else {
            return w
                .toast("this machine is always here: it can be left out of the strip (Window)");
        };
        // What was staged inside it is moot.
        let inside = |p: &Pending| {
            p.change.file == file
                && p.change.path != path
                && p.change.path.starts_with(&path)
                && p.change.path[path.len()..].starts_with(['.', '['])
        };
        self.pending.retain(|p| !inside(p));
        if let Some(i) = self.staged_add(file, name) {
            self.pending.remove(i);
            self.drafts.retain(|d| !(d.file == file && d.name == name));
            self.restage();
            w.toast(&format!("{name}: no longer staged to be added"));
        } else {
            self.restage();
            match self.stage(&path, None, By::You) {
                Ok(()) => w.toast(&format!(
                    "{name}: its removal is staged (its records stay on disk) · u takes it back"
                )),
                Err(why) => w.toast(&format!("not staged: {why}")),
            }
        }
        self.open = false;
        self.refresh_forms(w);
        self.cur = self.cur.min(self.overview_rows().saturating_sub(1));
    }

    /// Where a system's records are, as the save box says them: its folders under the
    /// config and the data directories.
    pub(crate) fn records_of(target: &str) -> Vec<std::path::PathBuf> {
        let scope = match target.split_once(':') {
            Some(("srv", name)) => name.to_string(),
            Some(("net", _)) => target.to_string(),
            _ => return Vec::new(),
        };
        vec![
            sentry_core::maint::root(&scope),
            sentry_core::maint::data_root(&scope),
        ]
    }

    /// `c` on a system: its connection checks run on a worker (never offline: a test hands
    /// the lines in). True: this system has checks.
    pub(crate) fn check_system(&mut self, w: &mut Win, file: FileId, entry: &str) -> bool {
        let Some(run) = self
            .kind(file)
            .zip(self.doc(file))
            .and_then(|(k, d)| k.check(d, entry))
        else {
            return false;
        };
        self.checks
            .retain(|c| !(c.file == file && c.entry == entry));
        self.checks.push(Checked {
            file,
            entry: entry.to_string(),
            running: true,
            lines: Vec::new(),
        });
        if !w.offline {
            let tx = self.tx.clone();
            let entry = entry.to_string();
            std::thread::spawn(move || {
                let lines = run();
                let _ = tx.send(Event::Config(Box::new(ChecksDone { file, entry, lines })));
            });
        }
        true
    }

    pub(crate) fn checks_done(&mut self, done: ChecksDone) {
        self.checks
            .retain(|c| !(c.file == done.file && c.entry == done.entry));
        self.checks.push(Checked {
            file: done.file,
            entry: done.entry,
            running: false,
            lines: done.lines,
        });
    }

    pub(crate) fn checks_of(&self, file: FileId, entry: &str) -> Option<&Checked> {
        self.checks
            .iter()
            .find(|c| c.file == file && c.entry == entry)
    }

    /// A form's change that isn't a plain setting: the name, a workflow's cadence. None: it
    /// is a plain setting.
    pub(crate) fn special_set(
        &mut self,
        w: &mut Win,
        key: &str,
        v: &form::Value,
    ) -> Option<Result<(), String>> {
        let text = match v {
            form::Value::Text(s) => s.trim().to_string(),
            _ => String::new(),
        };
        if key == NAME {
            let (file, e) = self.open_system()?;
            let r = self.rename(file, &e.name, &text);
            if r.is_ok() {
                // The cursor follows the system to where its new name sorts.
                if let Some(l) = self.list_of(self.screen)
                    && let Some(at) = self
                        .entries_of(self.screen)
                        .iter()
                        .position(|x| x.name == text)
                {
                    self.list[l] = at;
                }
            }
            return Some(r);
        }
        let wf = key.strip_prefix(UPKEEP)?;
        let (file, e) = match self.open_system() {
            Some(x) => x,
            None => self.system_here()?,
        };
        Some(self.set_cadence(w, file, &e.name, wf, &text))
    }

    /// What `doc` is for a kind: the pair, where both are there.
    pub(crate) fn kind_doc(&self, file: FileId) -> Option<(&dyn Kind, &dyn DocAny)> {
        self.kind(file).zip(self.doc(file))
    }
}

/// A pick's first word where nothing may be picked.
pub(crate) const NONE: &str = "(none)";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_one_word() {
        assert_eq!(name_problem("my-server_2.lan"), None);
        assert!(name_problem("").is_some());
        assert!(name_problem("my server").is_some());
        assert!(name_problem("a/b").is_some());
        assert!(name_problem(".hidden").is_some());
        assert!(name_problem("-x").is_some());
    }

    #[test]
    fn a_systems_records_are_under_its_scope() {
        assert!(ConfigArea::records_of("local").is_empty());
        let srv = ConfigArea::records_of("srv:myserver");
        assert!(srv[0].ends_with("servers/myserver"), "{srv:?}");
        let net = ConfigArea::records_of("net:home");
        assert!(net[0].ends_with("networks/home"), "{net:?}");
    }
}
