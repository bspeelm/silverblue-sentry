//! Upgrade workflows (spec §9): TOML files in `~/.config/sentry/workflows/`, linted, rendered
//! with `{{ }}` templates and run as a resumable state machine (`runner.rs`, `state.rs`).

pub mod cli;
pub mod runner;
pub mod state;
pub mod template;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::config::Dur;
use crate::paths;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workflow {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Refuses to start until the user removes it (addendum A3).
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub vars: BTreeMap<String, VarSpec>,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VarSpec {
    pub prompt: String,
    #[serde(default)]
    pub default: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Run,
    Reboot,
    Shell,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Gate {
    Auto,
    #[default]
    Confirm,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnFail {
    #[default]
    Stop,
    Manual,
    Continue,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub run: Option<String>,
    #[serde(default)]
    pub kind: Kind,
    #[serde(default)]
    pub gate: Gate,
    #[serde(default)]
    pub on_fail: OnFail,
    /// Condition name, optionally negated with a leading `!` (addendum A3).
    #[serde(default)]
    pub when: Option<String>,
    #[serde(default)]
    pub timeout: Option<Dur>,
    #[serde(default)]
    pub optional: bool,
    /// Only offered from "abandon"; skipped in the normal sequence.
    #[serde(default)]
    pub rollback: bool,
    /// Instructions for manual steps and `on_fail = "manual"` cards.
    #[serde(default)]
    pub manual: Option<String>,
    /// `false` suppresses the automatic rpm-ostree dry-run sibling.
    #[serde(default)]
    pub dry_run: Option<bool>,
}

impl Step {
    /// Reboot steps are always confirmed (spec §9.2).
    pub fn gate(&self) -> Gate {
        match self.kind {
            Kind::Reboot => Gate::Confirm,
            _ => self.gate,
        }
    }

    /// `(negated, name)` of the `when` condition.
    pub fn cond(&self) -> Option<(bool, &str)> {
        let w = self.when.as_deref()?.trim();
        Some(match w.strip_prefix('!') {
            Some(n) => (true, n.trim()),
            None => (false, w),
        })
    }

    pub fn tag(&self) -> &'static str {
        match (self.kind, self.optional, self.gate()) {
            (Kind::Reboot, _, _) => "reboot",
            (Kind::Shell, _, _) => "shell",
            (Kind::Manual, _, _) | (_, _, Gate::Manual) => "manual",
            (_, true, _) => "optional",
            (_, _, Gate::Auto) => "auto",
            (_, _, Gate::Confirm) => "confirm",
        }
    }
}

/// Built-in template variables (spec §9.2 + addendum A3).
pub const BUILTINS: &[&str] = &[
    "current_version",
    "booted_kernel",
    "pending_kernel",
    "old_kmod",
    "home",
];

/// The automatic dry-run sibling for an rpm-ostree command, if it has one (addendum A10).
pub fn dry_run_of(cmd: &str) -> Option<String> {
    let rest = cmd.trim().strip_prefix("rpm-ostree ")?;
    if cmd.contains("&&") || cmd.contains(';') || cmd.contains('|') {
        return None;
    }
    let (sub, args) = rest.split_once(' ').unwrap_or((rest, ""));
    match sub {
        "install" | "uninstall" if !args.contains("--dry-run") && !args.contains(" -n") => Some(
            format!("rpm-ostree {sub} --dry-run {args}")
                .trim_end()
                .to_string(),
        ),
        // Only a bare upgrade previews cleanly; with --uninstall/--install the preview step
        // in the workflow is the dry run.
        "upgrade" if args.trim().is_empty() => Some("rpm-ostree upgrade --preview".into()),
        _ => None,
    }
}

pub fn dir() -> PathBuf {
    paths::config_dir().join("workflows")
}

pub const SEEDS: &[(&str, &str)] = &[
    (
        "quick-update",
        include_str!("../../assets/workflows/quick-update.toml"),
    ),
    (
        "release-rebase",
        include_str!("../../assets/workflows/release-rebase.toml"),
    ),
];

/// Write the shipped workflows where they're missing; never touches existing files.
pub fn seed() -> std::io::Result<()> {
    let d = dir();
    for (name, body) in SEEDS {
        let p = d.join(format!("{name}.toml"));
        if !p.exists() {
            paths::write_atomic(&p, body.as_bytes())?;
        }
    }
    Ok(())
}

pub fn parse(text: &str) -> Result<Workflow, String> {
    toml::from_str(text).map_err(|e| e.to_string().trim().to_string())
}

/// A workflow file as found on disk, with its lint result.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub path: PathBuf,
    pub wf: Result<Workflow, String>,
    pub issues: Vec<Issue>,
}

impl Entry {
    pub fn errors(&self) -> impl Iterator<Item = &Issue> {
        self.issues.iter().filter(|i| i.error)
    }

    /// Why this workflow can't start, if it can't.
    pub fn blocked(&self) -> Option<String> {
        match &self.wf {
            Err(e) => Some(format!("parse error: {e}")),
            Ok(_) if self.errors().next().is_some() => Some(format!(
                "lint: {}",
                self.errors()
                    .map(|i| i.msg.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            )),
            Ok(w) if w.draft => {
                Some("draft: review the steps, then delete `draft = true` from the file".into())
            }
            Ok(_) => None,
        }
    }
}

pub fn load_path(path: &Path) -> Entry {
    let name = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let wf = std::fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .and_then(|t| parse(&t));
    let issues = match &wf {
        Ok(w) => lint(w),
        Err(_) => Vec::new(),
    };
    Entry {
        name,
        path: path.to_path_buf(),
        wf,
        issues,
    }
}

/// Every `*.toml` in the workflows directory (seeded first), sorted by name.
pub fn list() -> Vec<Entry> {
    let _ = seed();
    let mut v: Vec<Entry> = std::fs::read_dir(dir())
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .map(|p| load_path(&p))
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

pub fn find(name: &str) -> Option<Entry> {
    let _ = seed();
    let p = dir().join(format!("{name}.toml"));
    p.exists().then(|| load_path(&p))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Issue {
    pub error: bool,
    pub msg: String,
}

/// Spec §9.6 lint: ids, templates, `when` names, `sentry check` names, kind/field combinations.
pub fn lint(w: &Workflow) -> Vec<Issue> {
    let mut out = Vec::new();
    let mut err = |m: String| {
        out.push(Issue {
            error: true,
            msg: m,
        })
    };
    if w.steps.is_empty() {
        err("no steps".into());
    }
    let mut seen = std::collections::HashSet::new();
    let known = |id: &str| w.vars.contains_key(id) || BUILTINS.contains(&id);
    for s in &w.steps {
        let at = format!("step {:?}", s.id);
        if s.id.trim().is_empty() {
            err("a step has an empty id".into());
        }
        if !seen.insert(s.id.as_str()) {
            err(format!("duplicate step id {:?}", s.id));
        }
        match (s.kind, &s.run) {
            (Kind::Run, None) => err(format!("{at}: kind = \"run\" needs `run`")),
            (Kind::Reboot | Kind::Shell | Kind::Manual, Some(_)) => {
                err(format!("{at}: `run` is not used by kind = {:?}", s.kind))
            }
            _ => {}
        }
        if (s.kind == Kind::Manual || s.gate == Gate::Manual) && s.manual.is_none() {
            err(format!("{at}: manual steps need `manual` instructions"));
        }
        if s.on_fail == OnFail::Manual && s.manual.is_none() {
            err(format!(
                "{at}: on_fail = \"manual\" needs `manual` instructions"
            ));
        }
        for text in [Some(&s.title), s.run.as_ref(), s.manual.as_ref()]
            .into_iter()
            .flatten()
        {
            match template::idents(text) {
                Ok(ids) => {
                    for id in ids.iter().filter(|i| !known(i)) {
                        err(format!("{at}: undefined variable `{id}`"));
                    }
                }
                Err(e) => err(format!("{at}: {e}")),
            }
        }
        if let Some((_, c)) = s.cond()
            && crate::checks::cond_check(c).is_none()
        {
            err(format!("{at}: unknown `when` condition {c:?}"));
        }
        if let Some(run) = &s.run {
            for name in check_names(run) {
                if !crate::checks::NAMES.contains(&name) {
                    err(format!("{at}: unknown check `sentry check {name}`"));
                }
            }
        }
    }
    for (k, v) in &w.vars {
        if BUILTINS.contains(&k.as_str()) {
            out.push(Issue {
                error: true,
                msg: format!("var {k:?} shadows a built-in"),
            });
        }
        if let Some(d) = &v.default {
            match template::idents(d) {
                Ok(ids) => {
                    for id in ids.iter().filter(|i| !BUILTINS.contains(&i.as_str())) {
                        out.push(Issue {
                            error: true,
                            msg: format!("var {k:?}: default uses `{id}` (only built-ins allowed)"),
                        });
                    }
                }
                Err(e) => out.push(Issue {
                    error: true,
                    msg: format!("var {k:?}: {e}"),
                }),
            }
        }
    }
    if w.steps.iter().all(|s| s.rollback) && !w.steps.is_empty() {
        out.push(Issue {
            error: true,
            msg: "every step is a rollback step".into(),
        });
    }
    if w.draft {
        out.push(Issue {
            error: false,
            msg: "draft = true: won't start until removed".into(),
        });
    }
    for s in w
        .steps
        .iter()
        .filter(|s| s.kind == Kind::Reboot && s.gate == Gate::Auto)
    {
        out.push(Issue {
            error: false,
            msg: format!(
                "step {:?}: reboot steps always confirm; gate = \"auto\" ignored",
                s.id
            ),
        });
    }
    out
}

/// Names following `sentry check` in a shell command.
fn check_names(run: &str) -> Vec<&str> {
    let mut v = Vec::new();
    let mut rest = run;
    while let Some(i) = rest.find("sentry check ") {
        rest = &rest[i + "sentry check ".len()..];
        if let Some(name) = rest.split_whitespace().next() {
            v.push(name.trim_end_matches([';', '&', '|', ')']));
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_parse_and_lint_clean() {
        for (name, body) in SEEDS {
            let w = parse(body).unwrap_or_else(|e| panic!("{name}: {e}"));
            let errs: Vec<_> = lint(&w).into_iter().filter(|i| i.error).collect();
            assert!(errs.is_empty(), "{name}: {errs:?}");
        }
        let rr = parse(SEEDS[1].1).unwrap();
        assert!(rr.draft);
    }

    #[test]
    fn lint_catches_mistakes() {
        let w = parse(
            r#"
name = "x"
[[steps]]
id = "a"
title = "uses {{ nope }}"
run = "sentry check bogus && echo {{ target }}"
when = "!not_a_condition"
[[steps]]
id = "a"
title = "dup"
kind = "reboot"
run = "systemctl reboot"
[[steps]]
id = "m"
title = "manual without text"
kind = "manual"
"#,
        )
        .unwrap();
        let msgs: Vec<String> = lint(&w).into_iter().map(|i| i.msg).collect();
        let has = |s: &str| msgs.iter().any(|m| m.contains(s));
        assert!(has("undefined variable `nope`"), "{msgs:#?}");
        assert!(has("undefined variable `target`"));
        assert!(has("unknown check `sentry check bogus`"));
        assert!(has("unknown `when` condition \"not_a_condition\""));
        assert!(has("duplicate step id \"a\""));
        assert!(has("`run` is not used by kind = Reboot"));
        assert!(has("manual steps need `manual`"));
        assert!(
            parse("name = \"x\"\nbogus = 1\nsteps = []")
                .unwrap_err()
                .contains("bogus")
        );
    }

    #[test]
    fn dry_run_siblings() {
        assert_eq!(
            dry_run_of("rpm-ostree install /var/cache/akmods/nvidia/kmod-nvidia-x.rpm").as_deref(),
            Some("rpm-ostree install --dry-run /var/cache/akmods/nvidia/kmod-nvidia-x.rpm")
        );
        assert_eq!(
            dry_run_of("rpm-ostree upgrade").as_deref(),
            Some("rpm-ostree upgrade --preview")
        );
        assert_eq!(dry_run_of("rpm-ostree upgrade --uninstall kmod-x"), None);
        assert_eq!(
            dry_run_of("rpm-ostree rebase fedora:fedora/45/x86_64/silverblue"),
            None
        );
        assert_eq!(dry_run_of("flatpak update -y"), None);
    }
}
