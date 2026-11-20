//! A network's workflows: the same TOML format and run as a server's
//! (`sentry_app::remote::workflow`). Definitions live in
//! `~/.config/sentry/networks/<name>/workflows/` when that has any (a network's own,
//! replacing the generic ones), otherwise `~/.config/sentry/network-workflows/` (seeded);
//! runs in `~/.local/share/sentry/networks/<name>/workflows/`.
//!
//! A step that starts with `sentry-network ` runs on this machine, by this program, with
//! the network's name put after its first word (`sentry-network backup` is
//! `sentry-network backup <name>`); anything else is the router's shell over ssh, as root.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::remote::Router;
pub use sentry_app::remote::workflow::{Session, Words, own_dir, pick_dir, root, tomls};
use sentry_core::paths;
use sentry_core::workflows::runner::Env;
use sentry_core::workflows::{self, Entry, LintRules};

/// The program a step's `sentry-network …` line is run by, here.
pub const PROG: &str = "sentry-network";

/// What a run calls its host.
pub const WORDS: Words = Words {
    host: "the router",
    hosts: "routers",
};

pub const BUILTINS: &[&str] = &["network"];

/// No conditions yet: nothing a network's workflow does depends on one.
pub const RULES: LintRules = LintRules {
    builtins: BUILTINS,
    cond: |_| false,
    check: |_| false,
};

pub const SEEDS: &[(&str, &str)] = &[(
    "config-backup",
    include_str!("../../../assets/network-workflows/config-backup.toml"),
)];

/// The generic workflows, seeded.
pub fn dir() -> PathBuf {
    paths::config_dir().join("network-workflows")
}

/// Where a network's workflows come from: its own directory if it has any, else the
/// generic one.
pub fn dir_for(scope: &str) -> PathBuf {
    pick_dir(own_dir(scope), dir())
}

/// A network's workflows, with their lint results (the generic ones seeded first).
pub fn list_for(scope: &str) -> Vec<Entry> {
    let d = dir_for(scope);
    if d == dir() {
        let _ = std::fs::create_dir_all(&d);
        let _ = workflows::seed_with(&d, SEEDS, &[]);
    }
    let mut v: Vec<Entry> = tomls(&d)
        .into_iter()
        .map(|p| workflows::load_path_with(&p, &RULES))
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

/// The seeded workflows as they parse, without touching the disk (tests, and a window
/// that's offline).
pub fn seeded() -> Vec<Entry> {
    SEEDS
        .iter()
        .map(|(name, text)| Entry {
            name: name.to_string(),
            path: dir().join(format!("{name}.toml")),
            wf: workflows::parse(text),
            issues: Vec::new(),
        })
        .collect()
}

pub struct RouterEnv {
    pub r: Router,
    /// The workflow has a reboot step: only then is the router's boot id read (one ssh
    /// exec before each step otherwise, for nothing).
    pub reboots: bool,
}

impl Env for RouterEnv {
    fn cond(&self, name: &str) -> Result<bool, String> {
        Err(format!("unknown condition `{name}`"))
    }

    fn builtin(&self, name: &str) -> Result<String, String> {
        match name {
            "network" => Ok(self.r.name.clone()),
            n => Err(format!("unknown built-in {n}")),
        }
    }

    fn boot_id(&self) -> String {
        if !self.reboots {
            return String::new();
        }
        self.r
            .output(&self.r.cmd("cat").arg("/proc/sys/kernel/random/boot_id"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }

    fn builtins(&self) -> &'static [&'static str] {
        BUILTINS
    }

    fn live(&self) -> &'static [&'static str] {
        &[]
    }
}

fn env(r: &Router, wf: Option<&workflows::Workflow>) -> Box<dyn Env> {
    Box::new(RouterEnv {
        r: r.clone(),
        reboots: wf.is_none_or(|w| w.steps.iter().any(|s| s.kind == workflows::Kind::Reboot)),
    })
}

/// The run still in progress for this network, if any.
pub fn resume(r: &Router) -> Option<Session> {
    Session::resume(r, PROG, env(r, None)).map(|s| s.on(WORDS))
}

/// Start a run. `vars`: the workflow's `[vars]`, asked for before it starts.
pub fn begin(entry: &Entry, r: &Router, vars: BTreeMap<String, String>) -> anyhow::Result<Session> {
    let e = env(r, entry.wf.as_ref().ok());
    Session::begin(entry, r, vars, PROG, e).map(|s| s.on(WORDS))
}

/// Tests that seed or read the generic directory take turns: it is one for the process.
#[cfg(test)]
pub(crate) fn seeding() -> std::sync::MutexGuard<'static, ()> {
    static SEEDING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SEEDING.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seeded_workflows_parse_and_lint_clean() {
        for e in seeded() {
            let w =
                e.wf.as_ref()
                    .unwrap_or_else(|err| panic!("{}: {err}", e.name));
            assert_eq!(w.name, e.name);
            let issues = workflows::lint_with(w, &RULES);
            assert!(issues.is_empty(), "{}: {issues:?}", e.name);
            assert!(e.blocked().is_none());
        }
        let backup = &seeded()[0];
        let w = backup.wf.as_ref().unwrap();
        // Both steps run here, by this program, and neither asks.
        let runs: Vec<&str> = w.steps.iter().filter_map(|s| s.run.as_deref()).collect();
        assert_eq!(
            runs,
            ["sentry-network backup", "sentry-network backup --verify"]
        );
        assert!(runs.iter().all(|r| r.starts_with(PROG)));
    }

    #[test]
    fn a_networks_own_workflows_replace_the_seeded_ones() {
        let _turn = seeding();
        let scope = "net:wf-dirs-test";
        assert_eq!(dir_for(scope), dir());
        assert!(
            own_dir(scope).ends_with("networks/wf-dirs-test/workflows"),
            "{}",
            own_dir(scope).display()
        );
        // Seeded where there are none of its own.
        let names: Vec<String> = list_for(scope).into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["config-backup"]);
        assert!(dir().join("config-backup.toml").is_file());
        // One of its own: only that.
        let own = own_dir(scope);
        std::fs::create_dir_all(&own).unwrap();
        std::fs::write(
            own.join("mine.toml"),
            "name = \"mine\"\ndescription = \"d\"\n[[steps]]\nid = \"a\"\ntitle = \"t\"\nrun = \"echo {{ network }}\"\ngate = \"auto\"\n",
        )
        .unwrap();
        assert_eq!(dir_for(scope), own);
        let l = list_for(scope);
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].name, "mine");
        assert!(l[0].issues.is_empty(), "{:?}", l[0].issues);
        let _ = std::fs::remove_dir_all(sentry_core::maint::root(scope));
    }
}
