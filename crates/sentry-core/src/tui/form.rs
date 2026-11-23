//! A form: named fields with typed values, one cursor, edited in place. Target-agnostic: the
//! Config area builds one per section from a config file's field table, and whatever asks
//! for a few values can use it. The form holds what is shown; every change comes back as
//! [`Fx::Set`] for its owner to take (stage, validate further) or refuse ([`Form::refuse`]).
//!
//! Keys: `j`/`k` move; Enter edits a value in a line editor ([`LineEdit`]), toggles a yes/no,
//! takes the next of a choice, or goes into a list; Space toggles and cycles; in a list `n`
//! adds, `x` removes, Enter edits the element, `J`/`K` move it (a record's row is its owner's
//! to open, add and remove: [`Fx::Open`], [`Fx::Add`], [`Fx::Remove`]); Esc leaves the
//! editor, then the list, then the form ([`Fx::Leave`]).
//!
//! Groups that fold: a field whose value is a [`Value::Fold`] is a group's header row (its
//! name, what is set in it, a line about it), and the fields that name it in
//! [`Field::fold`] are in it: hidden while it is closed, the cursor going past them. Enter
//! or Space on the header opens and closes it; a group opens by itself when something in it
//! has a problem or was changed ([`Form::new`], [`Form::at`]). A form without such a field
//! is as it always was.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::frame::Hints;
use super::lineedit::{Edited, LineEdit};
use super::theme::Theme;
use super::widgets;
use crate::config::Dur;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Text(String),
    Bool(bool),
    /// One of these words: (the words, which one).
    Pick(Vec<String>, usize),
    Int(i64),
    Float(f64),
    Dur(Dur),
    /// A list of words, in order.
    List(Vec<String>),
    /// Named entries, `name = value`.
    Pairs(Vec<(String, String)>),
    /// A list of records as rows: (the columns, each record's cells). Enter on a row is
    /// its owner's to open ([`Fx::Open`]).
    Rows(Vec<String>, Vec<Vec<String>>),
    /// A date, `YYYY-MM-DD`; empty: not set.
    Date(String),
    /// A group's header row: (what is set in it, in a few words; whether it is open).
    Fold(String, bool),
}

impl Value {
    /// What kind of value it is, in a word.
    pub fn word(&self) -> &'static str {
        match self {
            Value::Text(_) => "text",
            Value::Bool(_) => "yes/no",
            Value::Pick(..) => "one of",
            Value::Int(_) | Value::Float(_) => "number",
            Value::Dur(_) => "duration (10s, 5m, 24h, 30d)",
            Value::List(_) => "list",
            Value::Pairs(_) => "named entries (name = value)",
            Value::Rows(..) => "list of records",
            Value::Date(_) => "date (YYYY-MM-DD), or empty: not set",
            Value::Fold(..) => "a group of settings",
        }
    }

    /// How many elements a list has (0 for anything else).
    fn len(&self) -> usize {
        match self {
            Value::List(l) => l.len(),
            Value::Pairs(p) => p.len(),
            Value::Rows(_, r) => r.len(),
            _ => 0,
        }
    }

    fn is_list(&self) -> bool {
        matches!(self, Value::List(_) | Value::Pairs(_) | Value::Rows(..))
    }

    /// The element at `i` as it is typed.
    fn elem(&self, i: usize) -> String {
        match self {
            Value::List(l) => l.get(i).cloned().unwrap_or_default(),
            Value::Pairs(p) => p
                .get(i)
                .map(|(k, v)| format!("{k} = {v}"))
                .unwrap_or_default(),
            Value::Rows(_, r) => r.get(i).map(|c| c.join("  ")).unwrap_or_default(),
            _ => String::new(),
        }
    }

    /// The value on one line.
    pub fn shown(&self) -> String {
        match self {
            Value::Text(s) => s.clone(),
            Value::Bool(true) => "[x] yes".into(),
            Value::Bool(false) => "[ ] no".into(),
            Value::Pick(words, at) => words.get(*at).cloned().unwrap_or_default(),
            Value::Int(n) => n.to_string(),
            Value::Float(x) => x.to_string(),
            Value::Dur(d) => d.to_string(),
            Value::List(l) => l.join(", "),
            Value::Pairs(_) => (0..self.len())
                .map(|i| self.elem(i))
                .collect::<Vec<_>>()
                .join(", "),
            Value::Rows(_, r) => match r.len() {
                0 => String::new(),
                1 => "1 entry".into(),
                n => format!("{n} entries"),
            },
            Value::Date(s) => s.clone(),
            Value::Fold(summary, _) => summary.clone(),
        }
    }
}

/// `text` as a date, as it is written back (`2027-03-31`); why it isn't one.
pub fn date(text: &str) -> Result<String, String> {
    let b = text.as_bytes();
    let shaped = b.len() == 10
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        });
    shaped
        .then(|| text.parse::<jiff::civil::Date>().ok())
        .flatten()
        .map(|d| d.to_string())
        .ok_or_else(|| format!("`{text}` isn't a date: YYYY-MM-DD (2027-03-31), or empty for none"))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    /// What it is to its owner: a setting's path.
    pub key: String,
    pub label: String,
    pub help: String,
    pub value: Value,
    /// What is wrong with it, drawn under it.
    pub problem: Option<String>,
    /// It differs from what is saved: marked `*`.
    pub changed: bool,
    /// What an empty value means, shown in its place (`all, this machine first`).
    pub empty: String,
    /// A number's bounds, both included.
    pub range: Option<(i64, i64)>,
    /// What an empty list starts as when it is opened (so there is something to reorder).
    pub seed: Vec<String>,
    /// A heading over it: it is the first of a group.
    pub head: String,
    /// The group it is in: the key of that group's header (a [`Value::Fold`] field). It is
    /// shown only while the group is open.
    pub fold: String,
    /// The value is the setting's default: said quietly beside it.
    pub is_default: bool,
    /// The default, as it reads (empty: it has none worth saying).
    pub default: String,
    /// It may be left unset: an empty text means that.
    pub optional: bool,
}

impl Field {
    pub fn new(key: &str, label: &str, value: Value) -> Self {
        Self {
            key: key.to_string(),
            label: label.to_string(),
            help: String::new(),
            value,
            problem: None,
            changed: false,
            empty: String::new(),
            range: None,
            seed: Vec::new(),
            head: String::new(),
            fold: String::new(),
            is_default: false,
            default: String::new(),
            optional: false,
        }
    }

    /// A group's header row: its name, a line about it, what is set in it.
    pub fn group(key: &str, name: &str, about: &str, summary: &str) -> Self {
        Self::new(key, name, Value::Fold(summary.to_string(), false)).help(about)
    }

    /// It is in the group whose header has this key.
    pub fn within(mut self, group: &str) -> Self {
        self.fold = group.to_string();
        self
    }

    pub fn head(mut self, head: &str) -> Self {
        self.head = head.to_string();
        self
    }

    pub fn help(mut self, help: &str) -> Self {
        self.help = help.to_string();
        self
    }

    pub fn empty(mut self, what: &str) -> Self {
        self.empty = what.to_string();
        self
    }

    pub fn range(mut self, min: i64, max: i64) -> Self {
        self.range = Some((min, max));
        self
    }
}

/// Said beside a value nobody set.
const DEFAULT: &str = "  (default)";

/// Which element the line editor holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Elem {
    /// The field's own value (not a list).
    Whole,
    /// The list's element here.
    At(usize),
    /// A new element, to go in here.
    New(usize),
}

#[derive(Debug, Clone, PartialEq)]
enum State {
    Browse,
    /// In the selected field's list, on this element.
    In(usize),
    Edit {
        line: LineEdit,
        elem: Elem,
        /// Why the last answer was refused.
        note: Option<String>,
    },
}

/// What a key came to.
#[derive(Debug, Clone, PartialEq)]
pub enum Fx {
    None,
    /// Esc with nothing open: the form is left.
    Leave,
    /// The field with this key is now this (the form already shows it).
    Set(String, Value),
    /// Enter on a record's row: (the field's key, which row).
    Open(String, usize),
    /// `n` in a list of records: its owner adds one (the field's key).
    Add(String),
    /// `x` on a record's row: its owner takes it away (the field's key, which row).
    Remove(String, usize),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Form {
    pub title: String,
    pub fields: Vec<Field>,
    pub cur: usize,
    state: State,
    /// Why its owner refused the last change: (the field, why), until the next key.
    refused: Option<(usize, String)>,
}

impl Form {
    /// A group that holds a problem or a change starts open; the others closed.
    pub fn new(title: &str, fields: Vec<Field>) -> Self {
        let mut f = Self {
            title: title.to_string(),
            fields,
            cur: 0,
            state: State::Browse,
            refused: None,
        };
        for i in 0..f.fields.len() {
            let key = f.fields[i].key.clone();
            if let Value::Fold(_, open) = &mut f.fields[i].value {
                *open = false;
            } else {
                continue;
            }
            if f.wants_open(&key) {
                f.set_open(&key, true);
            }
        }
        f
    }

    /// Something in the group has a problem or was changed: it is to be seen.
    fn wants_open(&self, group: &str) -> bool {
        self.fields
            .iter()
            .any(|f| f.fold == group && (f.problem.is_some() || f.changed))
    }

    /// The group with this header key is open (a key that is no group's: yes).
    pub fn is_open(&self, group: &str) -> bool {
        !self
            .fields
            .iter()
            .any(|f| f.key == group && matches!(f.value, Value::Fold(_, false)))
    }

    /// Open or close a group; closing one the cursor is in puts the cursor on its header.
    pub fn set_open(&mut self, group: &str, to: bool) {
        let Some(i) = self.fields.iter().position(|f| f.key == group) else {
            return;
        };
        if let Value::Fold(_, open) = &mut self.fields[i].value {
            *open = to;
        }
        if !to && self.fields.get(self.cur).is_some_and(|f| f.fold == group) {
            self.cur = i;
            self.state = State::Browse;
        }
    }

    /// The field is shown: it is in no group, or its group is open.
    fn visible(&self, i: usize) -> bool {
        self.fields
            .get(i)
            .is_some_and(|f| f.fold.is_empty() || self.is_open(&f.fold))
    }

    /// The next field shown after `from` (or before it), else `from`.
    fn step(&self, from: usize, down: bool) -> usize {
        let mut i = from;
        loop {
            i = match down {
                true if i + 1 < self.fields.len() => i + 1,
                false if i > 0 => i - 1,
                _ => return from,
            };
            if self.visible(i) {
                return i;
            }
        }
    }

    /// The cursor on the field with this key, if the form has it.
    pub fn go(&mut self, key: &str) -> bool {
        match self.fields.iter().position(|f| f.key == key) {
            Some(i) => {
                let group = self.fields[i].fold.clone();
                self.set_open(&group, true);
                self.cur = i;
                true
            }
            None => false,
        }
    }

    /// Which element of the selected field's list the cursor is on, while the list is open.
    pub fn element(&self) -> Option<usize> {
        match self.state {
            State::In(i) => Some(i),
            _ => None,
        }
    }

    /// The same place in a form made again from newer values (after a change was taken).
    pub fn at(mut self, old: &Form) -> Self {
        // A group stays as it was left, and opens when something in it newly needs seeing.
        let groups: Vec<String> = self
            .fields
            .iter()
            .filter(|f| matches!(f.value, Value::Fold(..)))
            .map(|f| f.key.clone())
            .collect();
        for g in groups {
            if !old.fields.iter().any(|f| f.key == g) {
                continue;
            }
            let open = old.is_open(&g) || (self.wants_open(&g) && !old.wants_open(&g));
            self.set_open(&g, open);
        }
        self.cur = old
            .field()
            .and_then(|f| self.fields.iter().position(|x| x.key == f.key))
            .unwrap_or(old.cur)
            .min(self.fields.len().saturating_sub(1));
        if let State::In(i) = old.state {
            let n = self.fields.get(self.cur).map_or(0, |f| f.value.len());
            self.state = State::In(i.min(n.saturating_sub(1)));
        }
        // (The field the cursor was on is in a group that is closed now: its header.)
        if !self.fields.is_empty() && !self.visible(self.cur) {
            let group = self.fields[self.cur].fold.clone();
            self.set_open(&group, false);
        }
        self
    }

    pub fn field(&self) -> Option<&Field> {
        self.fields.get(self.cur)
    }

    /// A line is being typed: every character is text.
    pub fn editing(&self) -> bool {
        matches!(self.state, State::Edit { .. })
    }

    /// The form has something open (a list, the editor): every key is its own.
    pub fn captures(&self) -> bool {
        self.state != State::Browse
    }

    /// The owner didn't take the last change: said under the field until the next key.
    pub fn refuse(&mut self, key: &str, why: &str) {
        if let Some(i) = self.fields.iter().position(|f| f.key == key) {
            self.refused = Some((i, why.to_string()));
        }
    }

    pub fn paste(&mut self, text: &str) {
        if let State::Edit { line, note, .. } = &mut self.state {
            line.paste(text);
            *note = None;
        }
    }

    pub fn key(&mut self, k: &KeyEvent) -> Fx {
        self.refused = None;
        if self.fields.is_empty() {
            return match k.code {
                KeyCode::Esc => Fx::Leave,
                _ => Fx::None,
            };
        }
        self.cur = self.cur.min(self.fields.len() - 1);
        if !self.visible(self.cur) {
            let group = self.fields[self.cur].fold.clone();
            self.set_open(&group, false);
        }
        match std::mem::replace(&mut self.state, State::Browse) {
            State::Browse => self.browse_key(k),
            State::In(at) => self.list_key(k, at),
            State::Edit { line, elem, .. } => self.edit_key(k, line, elem),
        }
    }

    fn set(&mut self, v: Value) -> Fx {
        let f = &mut self.fields[self.cur];
        f.value = v.clone();
        Fx::Set(f.key.clone(), v)
    }

    fn browse_key(&mut self, k: &KeyEvent) -> Fx {
        let last = self.fields.len() - 1;
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match k.code {
            KeyCode::Down | KeyCode::Char('j') if !ctrl => self.cur = self.step(self.cur, true),
            KeyCode::Up | KeyCode::Char('k') if !ctrl => self.cur = self.step(self.cur, false),
            KeyCode::Home => {
                self.cur = match self.visible(0) {
                    true => 0,
                    false => self.step(0, true),
                }
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.cur = match self.visible(last) {
                    true => last,
                    false => self.step(last, false),
                }
            }
            KeyCode::Esc => return Fx::Leave,
            // A group's header: open it, close it. Nothing is set by that.
            KeyCode::Char(' ') | KeyCode::Enter
                if matches!(self.fields[self.cur].value, Value::Fold(..)) =>
            {
                let key = self.fields[self.cur].key.clone();
                let open = self.is_open(&key);
                self.set_open(&key, !open);
            }
            KeyCode::Char(' ') => {
                return match self.fields[self.cur].value.clone() {
                    Value::Bool(b) => self.set(Value::Bool(!b)),
                    Value::Pick(words, at) if words.len() > 1 => {
                        let next = (at + 1) % words.len();
                        self.set(Value::Pick(words, next))
                    }
                    _ => Fx::None,
                };
            }
            KeyCode::Enter => {
                let f = &self.fields[self.cur];
                match f.value.clone() {
                    Value::Bool(b) => return self.set(Value::Bool(!b)),
                    Value::Pick(words, at) if words.len() > 1 => {
                        let next = (at + 1) % words.len();
                        return self.set(Value::Pick(words, next));
                    }
                    Value::Pick(..) => {
                        self.refused = Some((self.cur, "there is only this one so far".into()));
                    }
                    // An empty list starts as what there is to choose from, when its owner
                    // says what that is; else with its first element being typed.
                    Value::List(l) if l.is_empty() && !f.seed.is_empty() => {
                        let seed = f.seed.clone();
                        self.state = State::In(0);
                        return self.set(Value::List(seed));
                    }
                    v @ (Value::List(_) | Value::Pairs(_)) if v.len() == 0 => {
                        self.state = State::Edit {
                            line: LineEdit::default(),
                            elem: Elem::New(0),
                            note: None,
                        };
                    }
                    // Records: the list opens even when it is empty (`n` adds the first).
                    v if v.is_list() => self.state = State::In(0),
                    v => {
                        self.state = State::Edit {
                            line: LineEdit::new(&v.shown()),
                            elem: Elem::Whole,
                            note: None,
                        };
                    }
                }
            }
            _ => {}
        }
        Fx::None
    }

    fn list_key(&mut self, k: &KeyEvent, at: usize) -> Fx {
        let key = self.fields[self.cur].key.clone();
        let n = self.fields[self.cur].value.len();
        let at = at.min(n.saturating_sub(1));
        let rows = matches!(self.fields[self.cur].value, Value::Rows(..));
        self.state = State::In(at);
        match k.code {
            KeyCode::Esc => self.state = State::Browse,
            KeyCode::Down | KeyCode::Char('j') => {
                self.state = State::In((at + 1).min(n.saturating_sub(1)))
            }
            KeyCode::Up | KeyCode::Char('k') => self.state = State::In(at.saturating_sub(1)),
            KeyCode::Enter if rows && n > 0 => return Fx::Open(key, at),
            KeyCode::Char('n') if rows => return Fx::Add(key),
            KeyCode::Char('x') if rows && n > 0 => return Fx::Remove(key, at),
            KeyCode::Enter if n > 0 => {
                self.state = State::Edit {
                    line: LineEdit::new(&self.fields[self.cur].value.elem(at)),
                    elem: Elem::At(at),
                    note: None,
                };
            }
            KeyCode::Char('n') if !rows => {
                self.state = State::Edit {
                    line: LineEdit::default(),
                    elem: Elem::New(if n == 0 { 0 } else { at + 1 }),
                    note: None,
                };
            }
            KeyCode::Char('x') if !rows && n > 0 => {
                let v = match self.fields[self.cur].value.clone() {
                    Value::List(mut l) => {
                        l.remove(at);
                        Value::List(l)
                    }
                    Value::Pairs(mut p) => {
                        p.remove(at);
                        Value::Pairs(p)
                    }
                    v => v,
                };
                self.state = State::In(at.min(v.len().saturating_sub(1)));
                return self.set(v);
            }
            // Move the element down or up: a list's order is part of what it says.
            KeyCode::Char(c @ ('J' | 'K')) if !rows && n > 1 => {
                let to = match c {
                    'J' if at + 1 < n => at + 1,
                    'K' if at > 0 => at - 1,
                    _ => return Fx::None,
                };
                let v = match self.fields[self.cur].value.clone() {
                    Value::List(mut l) => {
                        l.swap(at, to);
                        Value::List(l)
                    }
                    Value::Pairs(mut p) => {
                        p.swap(at, to);
                        Value::Pairs(p)
                    }
                    v => v,
                };
                self.state = State::In(to);
                return self.set(v);
            }
            _ => {}
        }
        Fx::None
    }

    fn edit_key(&mut self, k: &KeyEvent, mut line: LineEdit, elem: Elem) -> Fx {
        let back = match elem {
            Elem::Whole => State::Browse,
            Elem::At(i) => State::In(i),
            Elem::New(i) => State::In(i.saturating_sub(1)),
        };
        match line.key(k) {
            Edited::Cancel => {
                self.state = back;
                Fx::None
            }
            Edited::Submit => match self.parsed(&line.text(), elem) {
                Ok(None) => {
                    self.state = back;
                    Fx::None
                }
                Ok(Some(v)) => {
                    self.state = match elem {
                        Elem::Whole => State::Browse,
                        Elem::At(i) | Elem::New(i) => State::In(i),
                    };
                    self.set(v)
                }
                Err(why) => {
                    self.state = State::Edit {
                        line,
                        elem,
                        note: Some(why),
                    };
                    Fx::None
                }
            },
            _ => {
                self.state = State::Edit {
                    line,
                    elem,
                    note: None,
                };
                Fx::None
            }
        }
    }

    /// What the line typed makes of the field: its new value, nothing to change (an empty
    /// new element), or why it isn't one.
    fn parsed(&self, text: &str, elem: Elem) -> Result<Option<Value>, String> {
        let f = &self.fields[self.cur];
        let text = text.trim();
        let element = |text: &str| -> Result<Option<String>, String> {
            match (text.is_empty(), elem) {
                (true, Elem::New(_)) => Ok(None),
                (true, _) => Err("empty: Esc leaves it as it was, x removes it".into()),
                (false, _) => Ok(Some(text.to_string())),
            }
        };
        Ok(Some(match &f.value {
            Value::Text(_) => Value::Text(text.to_string()),
            Value::Int(_) => {
                let n: i64 = text
                    .parse()
                    .map_err(|_| format!("`{text}` isn't a whole number"))?;
                if let Some((min, max)) = f.range.filter(|(min, max)| n < *min || n > *max) {
                    return Err(format!("{n} is out of range: {min} to {max}"));
                }
                Value::Int(n)
            }
            Value::Float(_) => {
                let x: f64 = text
                    .parse()
                    .ok()
                    .filter(|x: &f64| x.is_finite())
                    .ok_or_else(|| format!("`{text}` isn't a number"))?;
                if let Some((min, max)) = f
                    .range
                    .filter(|(min, max)| x < *min as f64 || x > *max as f64)
                {
                    return Err(format!("{x} is out of range: {min} to {max}"));
                }
                Value::Float(x)
            }
            Value::Dur(_) => Value::Dur(
                text.parse()
                    .map_err(|e| format!("not a duration ({e}): 10s, 5m, 24h, 30d"))?,
            ),
            Value::Date(_) if text.is_empty() => Value::Date(String::new()),
            Value::Date(_) => Value::Date(date(text)?),
            Value::List(l) => {
                let Some(text) = element(text)? else {
                    return Ok(None);
                };
                let mut l = l.clone();
                match elem {
                    Elem::At(i) if i < l.len() => l[i] = text,
                    Elem::New(i) => l.insert(i.min(l.len()), text),
                    _ => {}
                }
                Value::List(l)
            }
            Value::Pairs(p) => {
                let Some(text) = element(text)? else {
                    return Ok(None);
                };
                let pair = text
                    .split_once('=')
                    .map(|(k, v)| (k.trim().to_string(), v.trim().trim_matches('"').to_string()))
                    .filter(|(k, v)| !k.is_empty() && !v.is_empty())
                    .ok_or("write it as `name = value`")?;
                let mut p = p.clone();
                let other = |i: usize| p.iter().position(|(k, _)| *k == pair.0).filter(|j| *j != i);
                match elem {
                    Elem::At(i) if i < p.len() => {
                        if other(i).is_some() {
                            return Err(format!("`{}` is already there", pair.0));
                        }
                        p[i] = pair;
                    }
                    Elem::New(i) => {
                        if other(usize::MAX).is_some() {
                            return Err(format!("`{}` is already there", pair.0));
                        }
                        p.insert(i.min(p.len()), pair);
                    }
                    _ => {}
                }
                Value::Pairs(p)
            }
            // (Never edited as a line.)
            v @ (Value::Bool(_) | Value::Pick(..) | Value::Rows(..) | Value::Fold(..)) => v.clone(),
        }))
    }

    /// The keys that act now.
    pub fn hints(&self) -> Hints<'static> {
        let Some(f) = self.field() else {
            return vec![("Esc", "back")];
        };
        match &self.state {
            State::Edit { .. } => vec![("Enter", "set"), ("Esc", "leave it"), ("←→", "move")],
            State::In(_) if matches!(f.value, Value::Rows(..)) => vec![
                ("Enter", "open"),
                ("n", "add"),
                ("x", "remove"),
                ("j/k", "move"),
                ("Esc", "back"),
            ],
            State::In(_) => vec![
                ("Enter", "edit"),
                ("n", "add"),
                ("x", "remove"),
                ("J/K", "move it"),
                ("Esc", "back"),
            ],
            State::Browse => {
                let enter = match &f.value {
                    Value::Bool(_) => "toggle",
                    Value::Pick(..) => "next",
                    Value::Fold(_, true) => "close the group",
                    Value::Fold(_, false) => "open the group",
                    v if v.is_list() => "open the list",
                    _ => "edit",
                };
                vec![("Enter", enter), ("j/k", "move"), ("Esc", "back")]
            }
        }
    }

    /// The fields as lines, and which line the cursor is on.
    fn lines(&self, t: &Theme, width: usize) -> (Vec<Line<'static>>, usize) {
        let is_group = |f: &Field| matches!(f.value, Value::Fold(..));
        // (A field in a group is set in by two.)
        let indent = |f: &Field| if f.fold.is_empty() { 0 } else { 2 };
        // The labels' column: the fields outside the groups share one, each group's fields
        // their own (so opening a group moves nothing above it).
        let column = |group: &str| {
            self.fields
                .iter()
                .filter(|f| !is_group(f) && f.fold == group)
                .map(|f| f.label.chars().count() + indent(f))
                .max()
                .unwrap_or(0)
                .min(width / 2)
        };
        let widest = |of: &dyn Fn(&Field) -> usize| {
            self.fields
                .iter()
                .filter(|f| is_group(f))
                .map(of)
                .max()
                .unwrap_or(0)
        };
        let gw = widest(&|f| f.label.chars().count()).min(width / 2);
        let sw = widest(&|f| f.value.shown().chars().count());
        let sel = Style::new().bg(t.sel_bg);
        let mut out: Vec<Line<'static>> = Vec::new();
        let mut cursor = 0;
        for (i, f) in self.fields.iter().enumerate() {
            if !self.visible(i) {
                continue;
            }
            let lw = column(&f.fold);
            let room = width.saturating_sub(lw + 5);
            let on = i == self.cur;
            let state = if on { &self.state } else { &State::Browse };
            if !f.head.is_empty() {
                if !out.is_empty() {
                    out.push(Line::raw(""));
                }
                out.push(Line::styled(
                    format!(" {}", widgets::trunc(&f.head, width.saturating_sub(2))),
                    t.s(t.mag),
                ));
            }
            // A group's header: whether it is open, its name, what is set in it, a line
            // about it.
            if let Value::Fold(summary, open) = &f.value {
                let about = width.saturating_sub(gw + sw + 8);
                let mut line = Line::from(vec![
                    Span::styled(if *open { " ▾ " } else { " ▸ " }, t.s(t.mag)),
                    Span::styled(
                        format!("{:<gw$}  ", widgets::trunc(&f.label, gw)),
                        t.fg().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{summary:<sw$}  "),
                        if summary.contains("default") {
                            t.dim()
                        } else {
                            t.fg()
                        },
                    ),
                    Span::styled(widgets::trunc(&f.help, about), t.dim()),
                ]);
                if on {
                    line = line.style(sel);
                    cursor = out.len();
                }
                out.push(line);
                continue;
            }
            let label = format!("{}{}", " ".repeat(indent(f)), f.label);
            let mut spans = vec![
                Span::styled(
                    if f.changed { " * " } else { "   " },
                    t.s(t.yellow).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<lw$}  ", widgets::trunc(&label, lw)),
                    if on { t.fg() } else { t.dim() },
                ),
            ];
            match state {
                State::Edit {
                    line,
                    elem: Elem::Whole,
                    ..
                } => spans.extend(line.spans(t)),
                _ => {
                    let shown = f.value.shown();
                    if shown.is_empty() {
                        spans.push(Span::styled(
                            widgets::trunc(
                                &match (&f.value, f.empty.is_empty()) {
                                    (_, false) => format!("({})", f.empty),
                                    (Value::Date(_), _) => "(not set)".to_string(),
                                    (Value::Text(_), _) if f.optional => "(not set)".to_string(),
                                    _ => "(none)".to_string(),
                                },
                                room,
                            ),
                            t.dim(),
                        ));
                    } else if f.is_default {
                        // What nobody set: the value, and quietly that it is the default.
                        spans.push(Span::styled(
                            widgets::trunc(&shown, room.saturating_sub(DEFAULT.len())),
                            t.fg(),
                        ));
                        if room > DEFAULT.len() {
                            spans.push(Span::styled(DEFAULT, t.dim()));
                        }
                    } else {
                        spans.push(Span::styled(widgets::trunc(&shown, room), t.fg()));
                    }
                }
            }
            let mut line = Line::from(spans);
            if on && *state == State::Browse {
                line = line.style(sel);
                cursor = out.len();
            } else if on {
                cursor = out.len();
            }
            out.push(line);
            // The list, open: an element a line.
            if let State::In(at)
            | State::Edit {
                elem: Elem::At(at) | Elem::New(at),
                ..
            } = state
            {
                let editing = match state {
                    State::Edit { line, elem, .. } => Some((line, *elem)),
                    _ => None,
                };
                let n = f.value.len();
                let pad = " ".repeat(lw + 5);
                if let Value::Rows(cols, _) = &f.value {
                    out.push(Line::styled(
                        format!("{pad}    {}", widgets::trunc(&cols.join("  "), room)),
                        t.dim(),
                    ));
                }
                // Each element's text, and whether the cursor (or the editor) is on it.
                let mut rows: Vec<(Vec<Span<'static>>, bool)> = Vec::new();
                let plain = |j: usize| {
                    vec![Span::styled(
                        widgets::trunc(&f.value.elem(j), room.saturating_sub(4)),
                        t.fg(),
                    )]
                };
                for j in 0..n {
                    match editing {
                        Some((line, Elem::New(e))) if e == j => {
                            rows.push((line.spans(t), true));
                            rows.push((plain(j), false));
                        }
                        Some((line, Elem::At(e))) if e == j => rows.push((line.spans(t), true)),
                        Some(_) => rows.push((plain(j), false)),
                        None => rows.push((plain(j), j == *at)),
                    }
                }
                if let Some((line, Elem::New(e))) = editing
                    && e >= n
                {
                    rows.push((line.spans(t), true));
                }
                for (j, (text, here)) in rows.into_iter().enumerate() {
                    let mut spans = vec![
                        Span::raw(pad.clone()),
                        Span::styled(format!("{:>2}  ", j + 1), t.dim()),
                    ];
                    spans.extend(text);
                    let mut l = Line::from(spans);
                    if here {
                        l = l.style(sel);
                        cursor = out.len();
                    }
                    out.push(l);
                }
                if n == 0 && editing.is_none() {
                    out.push(Line::styled(format!("{pad}(none) · n adds one"), t.dim()));
                }
            }
            // What is wrong: why the last answer was refused, else the field's problem.
            let note = match state {
                State::Edit { note: Some(n), .. } => Some(n.clone()),
                _ => self
                    .refused
                    .as_ref()
                    .filter(|(j, _)| *j == i)
                    .map(|(_, why)| why.clone())
                    .or_else(|| f.problem.clone()),
            };
            if let Some(note) = note {
                for l in widgets::wrap(&note, width.saturating_sub(7).max(10)) {
                    out.push(Line::styled(format!("     ! {l}"), t.s(t.red)));
                }
            }
        }
        (out, cursor)
    }

    /// The fields in `area`, scrolled so the cursor's line is in it.
    pub fn draw(&self, f: &mut Frame, area: Rect, t: &Theme) {
        if self.fields.is_empty() {
            return widgets::placeholder(f, area, t, &[("nothing to set here", t.dim())]);
        }
        let (lines, cursor) = self.lines(t, area.width as usize);
        let h = area.height as usize;
        let off = cursor
            .saturating_sub(h / 2)
            .min(lines.len().saturating_sub(h));
        let shown: Vec<Line> = lines.into_iter().skip(off).take(h).collect();
        f.render_widget(Paragraph::new(shown), area);
    }

    /// The selected field in words: what it is, its help, what is wrong with it.
    pub fn detail(&self, t: &Theme, width: usize) -> Vec<Line<'static>> {
        let Some(f) = self.field() else {
            return Vec::new();
        };
        let mut out = vec![
            Line::from(vec![
                Span::styled(f.label.clone(), t.fg().add_modifier(Modifier::BOLD)),
                Span::styled(format!("  {}", f.key), t.dim()),
            ]),
            Line::styled(
                match &f.value {
                    Value::Pick(words, _) => format!("one of: {}", words.join(", ")),
                    Value::Fold(_, true) => "a group of settings · Enter closes it".to_string(),
                    Value::Fold(_, false) => "a group of settings · Enter opens it".to_string(),
                    Value::Text(_) if f.optional => "text, or empty: not set".to_string(),
                    v => match f.range {
                        Some((min, max)) if max == i64::MAX => {
                            format!("{}, {min} or more", v.word())
                        }
                        Some((min, max)) => format!("{}, {min} to {max}", v.word()),
                        None => v.word().to_string(),
                    },
                },
                t.dim(),
            ),
            Line::raw(""),
        ];
        out.extend(
            widgets::wrap(&f.help, width.max(10))
                .into_iter()
                .map(|l| Line::styled(l, t.fg())),
        );
        // A group: what is in it, so it needn't be opened to know.
        if matches!(f.value, Value::Fold(..)) {
            let inside: Vec<&str> = self
                .fields
                .iter()
                .filter(|x| x.fold == f.key)
                .map(|x| x.label.as_str())
                .collect();
            out.push(Line::raw(""));
            out.extend(
                widgets::wrap(&format!("In it: {}.", inside.join(", ")), width.max(10))
                    .into_iter()
                    .map(|l| Line::styled(l, t.dim())),
            );
        }
        // What it is when nobody sets it: the file holds only what differs.
        let none = matches!(&f.value, Value::Text(s) | Value::Date(s) if s.is_empty());
        let said = match (f.is_default, f.default.is_empty()) {
            (true, false) => Some(format!(
                "This is the default ({}): the file doesn't say it.",
                f.default
            )),
            (true, true) if none && f.optional => {
                Some("Not set, which is the default: the file doesn't say it.".to_string())
            }
            (false, false) => Some(format!("The default is {}.", f.default)),
            (false, true) if f.optional && !none => {
                Some("Emptied, it is not set again (the default).".to_string())
            }
            _ => None,
        };
        if let Some(said) = said {
            out.push(Line::raw(""));
            out.extend(
                widgets::wrap(&said, width.max(10))
                    .into_iter()
                    .map(|l| Line::styled(l, t.dim())),
            );
        }
        if f.changed {
            out.push(Line::raw(""));
            out.push(Line::styled("* changed here, not saved yet", t.s(t.yellow)));
        }
        if let Some(p) = &f.problem {
            out.push(Line::raw(""));
            out.extend(
                widgets::wrap(&format!("! {p}"), width.max(10))
                    .into_iter()
                    .map(|l| Line::styled(l, t.s(t.red))),
            );
        }
        out
    }
}

/// A form in two panels: the fields, and the selected one in words with `extra` under it.
/// Side by side where there is room (100 columns), else the words under the fields.
pub fn draw_panels(f: &mut Frame, area: Rect, t: &Theme, form: &Form, extra: &[Line<'static>]) {
    let (left, right) = if area.width >= 100 {
        let [l, r] =
            Layout::horizontal([Constraint::Percentage(55), Constraint::Fill(1)]).areas(area);
        (l, r)
    } else {
        let below = (area.height / 3).clamp(6, 12);
        let [l, r] = Layout::vertical([Constraint::Fill(1), Constraint::Length(below)]).areas(area);
        (l, r)
    };
    let changed = form.fields.iter().filter(|f| f.changed).count();
    let block = widgets::panel(
        t,
        &form.title,
        match changed {
            0 => String::new(),
            1 => "1 changed".into(),
            n => format!("{n} changed"),
        },
    );
    let inner = widgets::inner(&block, left);
    f.render_widget(block, left);
    form.draw(f, inner, t);
    let name = form.field().map_or("", |x| x.label.as_str());
    let block = widgets::panel(t, name, "");
    let inner = widgets::inner(&block, right);
    f.render_widget(block, right);
    let mut lines = form.detail(t, inner.width as usize);
    // The first line is the name again: the panel's title says it.
    if !lines.is_empty() {
        lines.remove(0);
    }
    if !extra.is_empty() {
        lines.push(Line::raw(""));
        lines.extend(extra.iter().cloned());
    }
    f.render_widget(Paragraph::new(lines), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::frame::render_to_string;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn typed(f: &mut Form, s: &str) {
        for c in s.chars() {
            assert_eq!(f.key(&key(KeyCode::Char(c))), Fx::None);
        }
    }

    fn form() -> Form {
        Form::new(
            "Window",
            vec![
                Field::new("agent.command", "Command", Value::Text("claude".into()))
                    .head("Agent")
                    .help("The program that starts it: a name on PATH or a path."),
                Field::new("review.at_start", "Review at start", Value::Bool(true))
                    .help("At each start of the window: which tasks are due again."),
                Field::new(
                    "agent.kind",
                    "Kind",
                    Value::Pick(vec!["claude-code".into()], 0),
                ),
                Field::new("retention.log_months", "Log (months)", Value::Int(12))
                    .head("Records")
                    .range(0, 1200)
                    .help("Log entries older than this go."),
                Field::new("recorder.interval", "Interval", Value::Dur(Dur::secs(10))),
                Field::new("targets.show", "Shown, in order", Value::List(vec![]))
                    .empty("all, this machine first")
                    .help("The targets shown, in the strip's order."),
                Field::new(
                    "keys",
                    "Keys",
                    Value::Pairs(vec![("quit".into(), "Q".into())]),
                ),
                Field::new(
                    "servers.myserver.timers",
                    "Timers",
                    Value::Rows(
                        vec!["unit".into(), "max age".into()],
                        vec![
                            vec!["backup.timer".into(), "26h".into()],
                            vec!["certs.timer".into(), "8d".into()],
                        ],
                    ),
                ),
            ],
        )
    }

    fn drawn(f: &Form, w: u16, h: u16) -> String {
        let t = Theme::truecolor();
        render_to_string(w, h, |fr| draw_panels(fr, fr.area(), &t, f, &[]))
    }

    #[test]
    fn enter_edits_a_text_in_place_and_esc_leaves_it() {
        let mut f = form();
        assert!(!f.captures());
        assert_eq!(f.key(&key(KeyCode::Enter)), Fx::None);
        assert!(f.editing() && f.captures());
        // A real editor: the cursor moves, text goes in where it is.
        f.key(&key(KeyCode::Home));
        typed(&mut f, "/opt/");
        f.paste("bin/\n");
        assert_eq!(
            f.key(&key(KeyCode::Enter)),
            Fx::Set(
                "agent.command".into(),
                Value::Text("/opt/bin/claude".into())
            )
        );
        assert!(!f.editing());
        assert_eq!(f.fields[0].value, Value::Text("/opt/bin/claude".into()));
        // Esc in the editor changes nothing; Esc again leaves the form.
        f.key(&key(KeyCode::Enter));
        typed(&mut f, "x");
        assert_eq!(f.key(&key(KeyCode::Esc)), Fx::None);
        assert_eq!(f.fields[0].value, Value::Text("/opt/bin/claude".into()));
        assert_eq!(f.key(&key(KeyCode::Esc)), Fx::Leave);
    }

    #[test]
    fn space_toggles_and_a_choice_of_one_says_so() {
        let mut f = form();
        f.key(&key(KeyCode::Char('j')));
        assert_eq!(
            f.key(&key(KeyCode::Char(' '))),
            Fx::Set("review.at_start".into(), Value::Bool(false))
        );
        assert_eq!(
            f.key(&key(KeyCode::Enter)),
            Fx::Set("review.at_start".into(), Value::Bool(true))
        );
        f.key(&key(KeyCode::Down));
        assert_eq!(f.key(&key(KeyCode::Char(' '))), Fx::None);
        assert_eq!(f.key(&key(KeyCode::Enter)), Fx::None);
        assert!(drawn(&f, 100, 16).contains("! there is only this one so far"));
        // Several: Space goes round.
        f.fields[2].value = Value::Pick(vec!["a".into(), "b".into()], 1);
        assert_eq!(
            f.key(&key(KeyCode::Char(' '))),
            Fx::Set(
                "agent.kind".into(),
                Value::Pick(vec!["a".into(), "b".into()], 0)
            )
        );
    }

    #[test]
    fn a_number_or_duration_that_isnt_one_is_refused_in_place() {
        let mut f = form();
        f.cur = 3;
        f.key(&key(KeyCode::Enter));
        f.key(&key(KeyCode::Char('x')));
        assert_eq!(f.key(&key(KeyCode::Enter)), Fx::None);
        assert!(f.editing(), "still being typed");
        assert!(drawn(&f, 100, 16).contains("! `12x` isn't a whole number"));
        f.key(&key(KeyCode::Backspace));
        typed(&mut f, "000");
        assert_eq!(f.key(&key(KeyCode::Enter)), Fx::None);
        assert!(drawn(&f, 100, 16).contains("! 12000 is out of range: 0 to 1200"));
        assert_eq!(f.fields[3].value, Value::Int(12), "nothing was set");
        for _ in 0..3 {
            f.key(&key(KeyCode::Backspace));
        }
        assert_eq!(
            f.key(&key(KeyCode::Enter)),
            Fx::Set("retention.log_months".into(), Value::Int(12))
        );
        // A duration.
        f.key(&key(KeyCode::Char('j')));
        f.key(&key(KeyCode::Enter));
        typed(&mut f, "0");
        assert_eq!(f.key(&key(KeyCode::Enter)), Fx::None);
        assert!(drawn(&f, 100, 16).contains("! not a duration"));
        f.key(&key(KeyCode::Backspace));
        f.key(&key(KeyCode::Backspace));
        typed(&mut f, "m");
        assert_eq!(
            f.key(&key(KeyCode::Enter)),
            Fx::Set("recorder.interval".into(), Value::Dur(Dur::secs(600)))
        );
        // What its owner refuses is said under the field until the next key.
        f.refuse("recorder.interval", "at least 10s");
        assert!(drawn(&f, 100, 16).contains("! at least 10s"));
        f.key(&key(KeyCode::Char('k')));
        assert!(!drawn(&f, 100, 16).contains("at least 10s"));
    }

    #[test]
    fn a_list_takes_n_x_enter_and_moves_its_elements() {
        let mut f = form();
        f.cur = 5;
        let set = |l: &[&str]| {
            Fx::Set(
                "targets.show".into(),
                Value::List(l.iter().map(|s| s.to_string()).collect()),
            )
        };
        // Empty: Enter types the first.
        f.key(&key(KeyCode::Enter));
        assert!(f.editing());
        typed(&mut f, "local");
        assert_eq!(f.key(&key(KeyCode::Enter)), set(&["local"]));
        assert!(f.captures() && !f.editing(), "in the list");
        f.key(&key(KeyCode::Char('n')));
        typed(&mut f, "srv:myserver");
        assert_eq!(f.key(&key(KeyCode::Enter)), set(&["local", "srv:myserver"]));
        // The new one is where the cursor is: K moves it up, J back down.
        assert_eq!(
            f.key(&key(KeyCode::Char('K'))),
            set(&["srv:myserver", "local"])
        );
        assert_eq!(f.key(&key(KeyCode::Char('K'))), Fx::None);
        assert_eq!(
            f.key(&key(KeyCode::Char('J'))),
            set(&["local", "srv:myserver"])
        );
        // Enter edits it; empty is refused; an empty new one is just not added.
        f.key(&key(KeyCode::Enter));
        for _ in 0..12 {
            f.key(&key(KeyCode::Backspace));
        }
        assert_eq!(f.key(&key(KeyCode::Enter)), Fx::None);
        assert!(f.editing());
        typed(&mut f, "net:home");
        assert_eq!(f.key(&key(KeyCode::Enter)), set(&["local", "net:home"]));
        f.key(&key(KeyCode::Char('n')));
        assert_eq!(f.key(&key(KeyCode::Enter)), Fx::None);
        assert!(!f.editing());
        assert_eq!(f.key(&key(KeyCode::Char('x'))), set(&["local"]));
        assert_eq!(f.key(&key(KeyCode::Char('x'))), set(&[]));
        // Esc: out of the list, then out of the form.
        assert_eq!(f.key(&key(KeyCode::Esc)), Fx::None);
        assert_eq!(f.key(&key(KeyCode::Esc)), Fx::Leave);
        // A list whose owner says what there is starts as that.
        f.fields[5].seed = vec!["local".into(), "srv:myserver".into()];
        assert_eq!(f.key(&key(KeyCode::Enter)), set(&["local", "srv:myserver"]));
        assert!(f.captures());
    }

    #[test]
    fn named_entries_are_typed_as_name_equals_value_and_rows_open() {
        let mut f = form();
        f.cur = 6;
        f.key(&key(KeyCode::Enter));
        f.key(&key(KeyCode::Char('n')));
        typed(&mut f, "nonsense");
        assert_eq!(f.key(&key(KeyCode::Enter)), Fx::None);
        assert!(drawn(&f, 100, 20).contains("! write it as `name = value`"));
        for _ in 0..8 {
            f.key(&key(KeyCode::Backspace));
        }
        typed(&mut f, "quit = X");
        assert_eq!(f.key(&key(KeyCode::Enter)), Fx::None);
        assert!(drawn(&f, 100, 20).contains("! `quit` is already there"));
        f.key(&key(KeyCode::Home));
        for _ in 0..4 {
            f.key(&key(KeyCode::Delete));
        }
        typed(&mut f, "target.next");
        assert_eq!(
            f.key(&key(KeyCode::Enter)),
            Fx::Set(
                "keys".into(),
                Value::Pairs(vec![
                    ("quit".into(), "Q".into()),
                    ("target.next".into(), "X".into())
                ])
            )
        );
        f.key(&key(KeyCode::Esc));
        // A record list: Enter on a row is its owner's.
        f.key(&key(KeyCode::Char('j')));
        f.key(&key(KeyCode::Enter));
        f.key(&key(KeyCode::Char('j')));
        assert_eq!(
            f.key(&key(KeyCode::Enter)),
            Fx::Open("servers.myserver.timers".into(), 1)
        );
        // So are adding one and taking one away: the form doesn't know what a record is.
        assert_eq!(
            f.key(&key(KeyCode::Char('n'))),
            Fx::Add("servers.myserver.timers".into())
        );
        assert_eq!(
            f.key(&key(KeyCode::Char('x'))),
            Fx::Remove("servers.myserver.timers".into(), 1)
        );
        // An empty list of records opens too: `n` adds its first.
        let mut f = Form::new(
            "x",
            vec![Field::new(
                "servers.myserver.disks",
                "Disks",
                Value::Rows(vec!["mount".into()], vec![]),
            )],
        );
        f.key(&key(KeyCode::Enter));
        assert!(f.captures());
        assert_eq!(f.key(&key(KeyCode::Enter)), Fx::None);
        assert_eq!(f.key(&key(KeyCode::Char('x'))), Fx::None);
        assert_eq!(
            f.key(&key(KeyCode::Char('n'))),
            Fx::Add("servers.myserver.disks".into())
        );
        // The cursor goes to a field by its key, and a form made again keeps it there.
        let mut f = form();
        assert!(f.go("targets.show") && !f.go("nope"));
        assert_eq!(f.field().unwrap().key, "targets.show");
        let mut newer = form();
        newer.fields.remove(0);
        assert_eq!(newer.at(&f).field().unwrap().key, "targets.show");
    }

    /// Two fields in the open, then two groups: thresholds (two numbers) and an item's
    /// dates and words.
    fn grouped() -> Form {
        let mut mem = Field::new("thresholds.mem", "Memory", Value::Float(90.0))
            .help("Memory used, in percent, from which it counts as high (90).")
            .within("@group:Thresholds");
        mem.is_default = true;
        mem.default = "90".into();
        let mut hold =
            Field::new("item.hold", "Why held", Value::Text(String::new())).within("@group:Item");
        hold.optional = true;
        hold.is_default = true;
        let mut ssh =
            Field::new("ssh", "ssh", Value::Text("admin@192.0.2.10".into())).head("Who it is");
        ssh.optional = true;
        Form::new(
            "myserver · server",
            vec![
                ssh,
                Field::new(
                    "services",
                    "Services",
                    Value::List(vec!["app.service".into()]),
                ),
                Field::group(
                    "@group:Thresholds",
                    "Thresholds",
                    "When memory, load or temperature is high.",
                    "1 set",
                )
                .head("More settings · Enter opens a group"),
                mem,
                Field::new("thresholds.load", "Load per core", Value::Float(1.5))
                    .within("@group:Thresholds"),
                Field::group(
                    "@group:Item",
                    "Tracked item",
                    "What is kept at a deliberate version.",
                    "all defaults",
                ),
                Field::new("item.review_by", "Review by", Value::Date(String::new()))
                    .within("@group:Item"),
                hold,
            ],
        )
    }

    fn cur(f: &Form) -> &str {
        f.field().map_or("", |x| x.key.as_str())
    }

    #[test]
    fn a_group_folds_its_fields_and_the_cursor_goes_past_them() {
        let mut f = grouped();
        assert!(!f.is_open("@group:Thresholds") && !f.is_open("@group:Item"));
        // Closed: only the header rows are there, and j/k go from one to the next.
        let s = drawn(&f, 158, 16);
        assert!(s.contains("▸ Thresholds") && s.contains("1 set"), "{s}");
        assert!(
            s.contains("▸ Tracked item") && s.contains("all defaults"),
            "{s}"
        );
        assert!(
            !s.contains("Load per core") && !s.contains("Review by"),
            "{s}"
        );
        f.key(&key(KeyCode::Char('j')));
        f.key(&key(KeyCode::Char('j')));
        assert_eq!(cur(&f), "@group:Thresholds");
        f.key(&key(KeyCode::Char('j')));
        assert_eq!(cur(&f), "@group:Item");
        f.key(&key(KeyCode::Char('j')));
        assert_eq!(cur(&f), "@group:Item", "nothing shown is below it");
        f.key(&key(KeyCode::End));
        assert_eq!(cur(&f), "@group:Item");
        f.key(&key(KeyCode::Char('k')));
        assert_eq!(cur(&f), "@group:Thresholds");
        // Enter opens it (nothing is set by that), and its fields are below its header.
        assert_eq!(f.hints()[0], ("Enter", "open the group"));
        assert_eq!(f.key(&key(KeyCode::Enter)), Fx::None);
        assert!(f.is_open("@group:Thresholds") && !f.captures());
        assert_eq!(f.hints()[0], ("Enter", "close the group"));
        let s = drawn(&f, 158, 16);
        assert!(
            s.contains("▾ Thresholds") && s.contains("Load per core"),
            "{s}"
        );
        assert!(!s.contains("Review by"), "{s}");
        f.key(&key(KeyCode::Char('j')));
        assert_eq!(cur(&f), "thresholds.mem");
        f.key(&key(KeyCode::Char('j')));
        f.key(&key(KeyCode::Char('j')));
        assert_eq!(cur(&f), "@group:Item");
        // Space closes and opens too.
        f.key(&key(KeyCode::Char('k')));
        f.key(&key(KeyCode::Char('k')));
        f.key(&key(KeyCode::Char('k')));
        assert_eq!(f.key(&key(KeyCode::Char(' '))), Fx::None);
        assert!(!f.is_open("@group:Thresholds"));
        f.key(&key(KeyCode::Char('j')));
        assert_eq!(cur(&f), "@group:Item");
        f.key(&key(KeyCode::Char(' ')));
        f.key(&key(KeyCode::End));
        assert_eq!(cur(&f), "item.hold");
        f.key(&key(KeyCode::Home));
        assert_eq!(cur(&f), "ssh");
        // Going to a field by its key opens the group it is in.
        assert!(f.go("thresholds.load"));
        assert!(f.is_open("@group:Thresholds"));
        assert_eq!(cur(&f), "thresholds.load");
        // Closing the group the cursor is in leaves the cursor on its header.
        f.set_open("@group:Thresholds", false);
        assert_eq!(cur(&f), "@group:Thresholds");
        // The header in words: what the group is for and what is in it.
        let words: Vec<String> = f
            .detail(&Theme::truecolor(), 60)
            .iter()
            .map(|l| l.to_string())
            .collect();
        assert!(words.contains(&"a group of settings · Enter opens it".to_string()));
        assert!(
            words.contains(&"In it: Memory, Load per core.".to_string()),
            "{words:?}"
        );
        // A form without groups is as it was.
        let mut plain = form();
        plain.key(&key(KeyCode::End));
        assert_eq!(plain.cur, 7);
        plain.key(&key(KeyCode::Home));
        assert_eq!(plain.cur, 0);
    }

    #[test]
    fn a_group_opens_by_itself_on_a_problem_or_a_change_and_stays_as_it_was_left() {
        // A problem in it when the form is made: open.
        let mut fields = grouped().fields;
        fields[4].problem = Some("load: must be more than 0".into());
        let f = Form::new("x", fields.clone());
        assert!(f.is_open("@group:Thresholds") && !f.is_open("@group:Item"));
        // (Whatever its owner said of the header: the form decides.)
        fields[4].problem = None;
        fields[5].value = Value::Fold("all defaults".into(), true);
        assert!(!Form::new("x", fields).is_open("@group:Item"));
        // Made again after a change in a group that was closed: it opens.
        let old = grouped();
        let mut fields = grouped().fields;
        fields[7].changed = true;
        let f = Form::new("x", fields.clone()).at(&old);
        assert!(f.is_open("@group:Item") && !f.is_open("@group:Thresholds"));
        // Closed by hand with the change still in it: it stays closed (nothing new in it),
        // and one opened by hand stays open though nothing in it needs seeing.
        let mut left = f.clone();
        left.set_open("@group:Item", false);
        left.set_open("@group:Thresholds", true);
        let again = Form::new("x", fields).at(&left);
        assert!(!again.is_open("@group:Item") && again.is_open("@group:Thresholds"));
        // The cursor's field went into hiding: the cursor is on its group's header.
        let mut old = grouped();
        old.go("item.hold");
        let mut closed = grouped();
        closed.cur = 7;
        closed.set_open("@group:Item", false);
        assert_eq!(cur(&closed), "@group:Item");
        assert_eq!(cur(&grouped().at(&old)), "item.hold");
    }

    #[test]
    fn a_date_and_a_fraction_are_checked_in_place_and_empty_is_unset() {
        let mut f = grouped();
        f.go("item.review_by");
        for (text, why) in [
            ("tomorrow", "`tomorrow` isn't a date: YYYY-MM-DD"),
            ("2027-02-30", "`2027-02-30` isn't a date"),
            ("27-3-1", "`27-3-1` isn't a date"),
        ] {
            f.key(&key(KeyCode::Enter));
            f.paste(text);
            assert_eq!(f.key(&key(KeyCode::Enter)), Fx::None, "{text}");
            assert!(f.editing(), "still being typed");
            assert!(drawn(&f, 158, 20).contains(why), "{text}");
            f.key(&key(KeyCode::Esc));
            assert_eq!(f.fields[6].value, Value::Date(String::new()));
        }
        f.key(&key(KeyCode::Enter));
        f.paste("2027-03-31");
        assert_eq!(
            f.key(&key(KeyCode::Enter)),
            Fx::Set("item.review_by".into(), Value::Date("2027-03-31".into()))
        );
        // Emptied: no date again.
        f.key(&key(KeyCode::Enter));
        for _ in 0..10 {
            f.key(&key(KeyCode::Backspace));
        }
        assert_eq!(
            f.key(&key(KeyCode::Enter)),
            Fx::Set("item.review_by".into(), Value::Date(String::new()))
        );
        assert!(drawn(&f, 158, 20).contains("Review by  (not set)"));
        assert_eq!(date("2028-02-29"), Ok("2028-02-29".to_string()));
        // A number with a fraction.
        f.go("thresholds.load");
        f.key(&key(KeyCode::Enter));
        f.paste("x");
        assert_eq!(f.key(&key(KeyCode::Enter)), Fx::None);
        assert!(drawn(&f, 158, 20).contains("! `1.5x` isn't a number"));
        f.key(&key(KeyCode::Backspace));
        f.key(&key(KeyCode::Backspace));
        f.paste("25");
        assert_eq!(
            f.key(&key(KeyCode::Enter)),
            Fx::Set("thresholds.load".into(), Value::Float(1.25))
        );
        // What nobody set says so beside it, and in words; what was set says its default.
        let s = drawn(&f, 158, 20);
        assert!(s.contains("Memory         90  (default)"), "{s}");
        assert!(!s.contains("1.25  (default)"), "{s}");
        f.go("thresholds.mem");
        let s = drawn(&f, 158, 20);
        assert!(
            s.contains("This is the default (90): the file doesn't say it."),
            "{s}"
        );
        f.fields[3].is_default = false;
        assert!(drawn(&f, 158, 20).contains("The default is 90."));
        // An optional text: empty is not set, and the panel says what emptying means.
        f.go("item.hold");
        let s = drawn(&f, 158, 20);
        assert!(s.contains("Why held   (not set)"), "{s}");
        assert!(s.contains("text, or empty: not set"), "{s}");
        assert!(s.contains("Not set, which is the default"), "{s}");
        f.go("ssh");
        assert!(drawn(&f, 158, 20).contains("Emptied, it is not set again (the default)."));
    }

    #[test]
    fn the_form_with_groups_at_158_columns() {
        let mut f = grouped();
        f.fields[4].changed = true;
        f.go("thresholds.load");
        insta::assert_snapshot!(drawn(&f, 158, 20));
    }

    #[test]
    fn the_form_with_groups_at_80_columns() {
        let mut f = grouped();
        f.go("item.review_by");
        insta::assert_snapshot!(drawn(&f, 80, 24));
    }

    #[test]
    fn the_form_at_158_columns() {
        let mut f = form();
        f.fields[0].changed = true;
        f.fields[3].problem = Some("retention: log_months must be at least 1".into());
        f.cur = 5;
        f.fields[5].value = Value::List(vec!["local".into(), "srv:myserver".into()]);
        f.key(&key(KeyCode::Enter));
        f.key(&key(KeyCode::Char('n')));
        typed(&mut f, "net:hoe");
        f.key(&key(KeyCode::Left));
        typed(&mut f, "m");
        insta::assert_snapshot!(drawn(&f, 158, 20));
    }

    #[test]
    fn the_form_at_80_columns() {
        let mut f = form();
        f.fields[0].changed = true;
        f.fields[3].problem = Some("retention: log_months must be at least 1".into());
        f.key(&key(KeyCode::Enter));
        f.key(&key(KeyCode::Home));
        typed(&mut f, "/usr/local/bin/");
        insta::assert_snapshot!(drawn(&f, 80, 24));
        // A short area scrolls to the cursor.
        let mut f = form();
        f.cur = 7;
        let s = drawn(&f, 80, 9);
        assert!(s.contains("Timers") && !s.contains("Command"), "{s}");
    }
}
