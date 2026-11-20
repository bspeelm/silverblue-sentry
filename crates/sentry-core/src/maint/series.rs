//! A series: the rows ticked on Maintenance, taken care of one after another. Each opens by
//! itself when the one before ended well; one that didn't waits for the user. Pure: the
//! program opens what each row needs and says how it ended.

/// How a row of the series ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Done,
    /// Not done, and nothing to decide (it left the list, Claude says it can wait): why.
    Skipped(String),
    /// It didn't end well: why.
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The row's key (`Rec::key`): rows move while the series runs.
    pub key: String,
    pub title: String,
    pub end: Option<Outcome>,
}

/// What the series waits for: how the row being done was started.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Wait {
    #[default]
    Nothing,
    /// An apply session.
    Session,
    /// A run of this workflow.
    Workflow(String),
    /// Claude writing this item's plan (sentry-server); its session follows.
    Plan(String),
    /// An audit.
    Audit,
}

#[derive(Debug, Default)]
pub struct Series {
    pub items: Vec<Entry>,
    /// The row being done.
    pub at: usize,
    pub wait: Wait,
}

impl Series {
    /// From the ticked rows (key, title), in the list's order; rows sharing a key (an
    /// item's, on a server) are one.
    pub fn new(rows: Vec<(String, String)>) -> Self {
        let mut items: Vec<Entry> = Vec::new();
        for (key, title) in rows {
            if !items.iter().any(|e| e.key == key) {
                items.push(Entry {
                    key,
                    title,
                    end: None,
                });
            }
        }
        Self {
            items,
            ..Default::default()
        }
    }

    pub fn current(&self) -> Option<&Entry> {
        self.items.get(self.at)
    }

    /// The row being done ended; on to the next. False: that was the last.
    pub fn ended(&mut self, o: Outcome) -> bool {
        if let Some(e) = self.items.get_mut(self.at) {
            e.end = Some(o);
        }
        self.at += 1;
        self.at < self.items.len()
    }

    /// Where it is: (2, 5).
    pub fn pos(&self) -> (usize, usize) {
        ((self.at + 1).min(self.items.len()), self.items.len())
    }

    /// The rows still to do (failed or not reached): they stay ticked.
    pub fn left(&self) -> Vec<String> {
        self.items
            .iter()
            .filter(|e| matches!(e.end, None | Some(Outcome::Failed(_))))
            .map(|e| e.key.clone())
            .collect()
    }

    /// For the banner row.
    pub fn line(&self) -> String {
        let (i, n) = self.pos();
        match self.current() {
            Some(e) => format!("series {i} of {n} · {}", e.title),
            None => format!("series of {n}"),
        }
    }

    /// When it stops before its end.
    pub fn stopped(&self) -> String {
        let (i, n) = self.pos();
        let left = self.left().len();
        format!("series stopped at {i} of {n} · {left} still ticked · Enter goes on")
    }

    /// When it's through: what was done, and what wasn't and why.
    pub fn summary(&self) -> String {
        let done = self
            .items
            .iter()
            .filter(|e| e.end == Some(Outcome::Done))
            .count();
        let mut s = format!("series: {done} of {} done", self.items.len());
        // The reasons only, each once: the toast is short, and the rows are still listed.
        let mut why: Vec<&str> = Vec::new();
        let mut not = 0;
        for e in &self.items {
            if let Some(Outcome::Skipped(w) | Outcome::Failed(w)) = &e.end {
                not += 1;
                if !why.contains(&w.as_str()) {
                    why.push(w);
                }
            }
        }
        if not > 0 {
            s.push_str(&format!(" · {not} not: {}", why.join(", ")));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(keys: &[&str]) -> Vec<(String, String)> {
        keys.iter()
            .map(|k| (k.to_string(), format!("Do {k}")))
            .collect()
    }

    #[test]
    fn rows_are_done_in_order_and_what_is_left_stays_ticked() {
        // Two rows about one item are one.
        let mut s = Series::new(rows(&["web", "finding:a", "web", "task:t"]));
        assert_eq!(s.items.len(), 3);
        assert_eq!(s.line(), "series 1 of 3 · Do web");
        assert!(s.ended(Outcome::Done));
        assert_eq!(s.current().unwrap().key, "finding:a");
        assert!(s.ended(Outcome::Failed("exit 1".into())));
        assert_eq!(s.pos(), (3, 3));
        // Stopped here: the failed one and the one not reached are still ticked.
        assert_eq!(s.left(), ["finding:a", "task:t"]);
        assert_eq!(
            s.stopped(),
            "series stopped at 3 of 3 · 2 still ticked · Enter goes on"
        );
        assert!(!s.ended(Outcome::Skipped("no longer needed".into())));
        assert!(s.current().is_none());
        assert_eq!(
            s.summary(),
            "series: 1 of 3 done · 2 not: exit 1, no longer needed"
        );
    }
}
