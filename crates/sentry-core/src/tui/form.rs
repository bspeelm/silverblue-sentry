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
        }
    }
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
        }
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
    pub fn new(title: &str, fields: Vec<Field>) -> Self {
        Self {
            title: title.to_string(),
            fields,
            cur: 0,
            state: State::Browse,
            refused: None,
        }
    }

    /// The cursor on the field with this key, if the form has it.
    pub fn go(&mut self, key: &str) -> bool {
        match self.fields.iter().position(|f| f.key == key) {
            Some(i) => {
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
        self.cur = old
            .field()
            .and_then(|f| self.fields.iter().position(|x| x.key == f.key))
            .unwrap_or(old.cur)
            .min(self.fields.len().saturating_sub(1));
        if let State::In(i) = old.state {
            let n = self.fields.get(self.cur).map_or(0, |f| f.value.len());
            self.state = State::In(i.min(n.saturating_sub(1)));
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
            KeyCode::Down | KeyCode::Char('j') if !ctrl => self.cur = (self.cur + 1).min(last),
            KeyCode::Up | KeyCode::Char('k') if !ctrl => self.cur = self.cur.saturating_sub(1),
            KeyCode::Home => self.cur = 0,
            KeyCode::End | KeyCode::Char('G') => self.cur = last,
            KeyCode::Esc => return Fx::Leave,
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
            v @ (Value::Bool(_) | Value::Pick(..) | Value::Rows(..)) => v.clone(),
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
                    v if v.is_list() => "open the list",
                    _ => "edit",
                };
                vec![("Enter", enter), ("j/k", "move"), ("Esc", "back")]
            }
        }
    }

    /// The fields as lines, and which line the cursor is on.
    fn lines(&self, t: &Theme, width: usize) -> (Vec<Line<'static>>, usize) {
        let lw = self
            .fields
            .iter()
            .map(|f| f.label.chars().count())
            .max()
            .unwrap_or(0)
            .min(width / 2);
        let room = width.saturating_sub(lw + 5);
        let sel = Style::new().bg(t.sel_bg);
        let mut out: Vec<Line<'static>> = Vec::new();
        let mut cursor = 0;
        for (i, f) in self.fields.iter().enumerate() {
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
            let mut spans = vec![
                Span::styled(
                    if f.changed { " * " } else { "   " },
                    t.s(t.yellow).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<lw$}  ", widgets::trunc(&f.label, lw)),
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
                    spans.push(if shown.is_empty() {
                        Span::styled(
                            widgets::trunc(
                                &if f.empty.is_empty() {
                                    "(none)".to_string()
                                } else {
                                    format!("({})", f.empty)
                                },
                                room,
                            ),
                            t.dim(),
                        )
                    } else {
                        Span::styled(widgets::trunc(&shown, room), t.fg())
                    });
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
