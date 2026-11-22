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
    reboot: &["reboot"],
};

pub const BUILTINS: &[&str] = &["network"];

/// `guard_waiting`: a guarded change is applied and still armed (it asks to be kept).
/// `packages_leaf`: upgrading the run's `packages` would touch only packages on the short
/// list auto mode may upgrade by itself (the whole transaction, as apk simulates it).
/// `firmware_missing`: after a firmware upgrade, packages installed by name before it
/// aren't installed now (the run's record says which).
pub const CONDS: &[&str] = &["guard_waiting", "packages_leaf", "firmware_missing"];

pub const RULES: LintRules = LintRules {
    builtins: BUILTINS,
    cond: |c| CONDS.contains(&c),
    check: |_| false,
};

pub const SEEDS: &[(&str, &str)] = &[
    (
        "config-backup",
        include_str!("../../../assets/network-workflows/config-backup.toml"),
    ),
    (
        "firmware-upgrade",
        include_str!("../../../assets/network-workflows/firmware-upgrade.toml"),
    ),
    (
        "guarded-change",
        include_str!("../../../assets/network-workflows/guarded-change.toml"),
    ),
    (
        "package-update",
        include_str!("../../../assets/network-workflows/package-update.toml"),
    ),
    (
        "security-action",
        include_str!("../../../assets/network-workflows/security-action.toml"),
    ),
];

pub use crate::packages::{base_package, package_name};

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

/// The same, with their lint results.
pub fn seeded_all() -> Vec<Entry> {
    seeded()
        .into_iter()
        .map(|mut e| {
            if let Ok(w) = &e.wf {
                e.issues = workflows::lint_with(w, &RULES);
            }
            e
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
        match name {
            "guard_waiting" => Ok(crate::guard::pending(&self.r.scope).is_some()),
            "firmware_missing" => Ok(crate::firmware::missing_now(&self.r.scope)),
            // The run in progress is this one: its `packages` value, simulated on the
            // router now. Anything that keeps it from being worked out isn't a yes.
            "packages_leaf" => {
                let names = sentry_core::workflows::state::in_progress_in(&root(&self.r.scope))
                    .and_then(|run| run.state.vars.get("packages").cloned())
                    .unwrap_or_default();
                let names: Vec<&str> = names.split_whitespace().collect();
                Ok(crate::packages::simulate(&self.r, &names)
                    .is_ok_and(|tx| crate::packages::all_leaves(&tx)))
            }
            _ => Err(format!("unknown condition `{name}`")),
        }
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
    begin_hiding(entry, r, vars, &[])
}

/// `begin`, with the secrets the window's sessions hold (`given`: a key captured on
/// another target, a value the user was asked for): a value of the run that holds one is
/// kept out of what is written down too, whatever option it is set in.
pub fn begin_hiding(
    entry: &Entry,
    r: &Router,
    vars: BTreeMap<String, String>,
    given: &[String],
) -> anyhow::Result<Session> {
    let e = env(r, entry.wf.as_ref().ok());
    // A secret among its values (a guarded change's new passphrase) is never written
    // down: the run's state, its log and its card get the tag, the steps the value.
    let salt = crate::redact::Salt::load(&r.scope).ok();
    let mut held = BTreeMap::new();
    let mut shown = vars.clone();
    for (k, v) in &vars {
        let kept = crate::guard::kept(v, salt.as_ref());
        let swept = crate::guard::swept(kept.as_deref().unwrap_or(v), given, salt.as_ref());
        if kept.is_some() || swept != *v {
            held.insert(k.clone(), v.clone());
            shown.insert(k.clone(), swept);
        }
    }
    Session::begin(entry, r, shown, PROG, e).map(|s| s.on(WORDS).holding(held))
}

/// The one way a draft starts: the user read what has and hasn't been proven and said go
/// (the firmware row's box, `NetworkTarget::begin_run` with its acknowledgment). Only the
/// draft is let through: a workflow that doesn't parse or lint still doesn't start, nor
/// one beside a run in progress.
pub fn begin_acknowledged(
    entry: &Entry,
    r: &Router,
    vars: BTreeMap<String, String>,
    given: &[String],
) -> anyhow::Result<Session> {
    let mut e = entry.clone();
    if let Ok(w) = e.wf.as_mut() {
        w.draft = false;
    }
    begin_hiding(&e, r, vars, given)
}

/// What the flash's box says while the workflow is a draft (`undraft` takes it out).
pub const DRAFT_LINE: &str = "sentry has never flashed a router before this run.";

/// Takes `draft = true` out of a workflow's file (after it ran end to end once, when the
/// user says so). Only that line: the rest of the file is left as it is.
pub fn undraft(path: &std::path::Path) -> std::io::Result<()> {
    let text = std::fs::read_to_string(path)?;
    let mut kept: Vec<&str> = Vec::new();
    let mut skip_blank = false;
    for l in text.lines() {
        if l.replace(' ', "") == "draft=true" {
            continue;
        }
        // The flash box's line that is true only of a draft goes too, with its blank line.
        if l.trim() == DRAFT_LINE {
            skip_blank = true;
            continue;
        }
        if std::mem::take(&mut skip_blank) && l.trim().is_empty() {
            continue;
        }
        kept.push(l);
    }
    let mut out = kept.join("\n");
    out.push('\n');
    sentry_core::paths::write_atomic(path, out.as_bytes())
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
        for e in seeded_all() {
            if e.name == "firmware-upgrade" {
                let w = e.wf.as_ref().unwrap();
                let issues = workflows::lint_with(w, &RULES);
                assert!(w.draft && issues.iter().all(|i| !i.error), "{issues:?}");
                assert!(e.blocked().unwrap().starts_with("draft"));
                continue;
            }
            let w =
                e.wf.as_ref()
                    .unwrap_or_else(|err| panic!("{}: {err}", e.name));
            assert_eq!(w.name, e.name);
            let issues = workflows::lint_with(w, &RULES);
            assert!(issues.is_empty(), "{}: {issues:?}", e.name);
            assert!(e.blocked().is_none());
        }
        // The firmware upgrade is the one draft.
        let drafts: Vec<&str> = seeded_all()
            .iter()
            .filter(|e| e.blocked().is_some())
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>()
            .into_iter()
            .map(|n| SEEDS.iter().find(|(s, _)| *s == n).unwrap().0)
            .collect();
        assert_eq!(drafts, ["firmware-upgrade"]);
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
        assert_eq!(
            names,
            [
                "config-backup",
                "firmware-upgrade",
                "guarded-change",
                "package-update",
                "security-action"
            ]
        );
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

#[cfg(test)]
mod secret_tests {
    use super::*;
    use sentry_app::remote::SudoMode;
    use sentry_app::run::{Exec, How};

    const CANARY: &str = "c4nary-Resume-Passphrase";

    fn step_cmd(e: Option<Exec>) -> String {
        match e {
            Some(Exec::Stream {
                how: How::Plain(c), ..
            }) => c.display(),
            _ => panic!("no step to run"),
        }
    }

    /// A guarded change that sets a secret: the step runs with the value, the run's
    /// state and logs have its tag, and the run picked up after a restart stops rather
    /// than apply the tag as the passphrase.
    #[test]
    fn a_run_holds_a_secret_in_memory_and_a_resumed_one_asks_for_it_again() {
        let _turn = seeding();
        let name = "held-secret-test";
        let scope = crate::remote::scope(name);
        let _ = std::fs::remove_dir_all(sentry_core::maint::root(&scope));
        let _ = std::fs::remove_dir_all(sentry_core::maint::data_root(&scope));
        let r = Router::new(name, &crate::audit::tests::cfg());
        let entry = list_for(&scope)
            .into_iter()
            .find(|e| e.name == "guarded-change")
            .unwrap();
        let lines = format!(
            "uci set wireless.default_radio0.key='{CANARY}'; uci set wireless.radio0.channel='36'"
        );
        let vars: BTreeMap<String, String> = [
            ("configs", "wireless"),
            ("lines", lines.as_str()),
            ("services", "wifi"),
            ("alters_wan", "no"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .into();
        let root_login = Some(SudoMode::Root);
        let mut s = begin(&entry, &r, vars).unwrap();
        let tag = crate::redact::Salt::load(&scope).unwrap().tag(CANARY);
        // What runs: the value. What the window and the step's log show: the tag.
        let cmd = step_cmd(s.auto(root_login));
        assert!(cmd.contains(CANARY) && !cmd.contains(&tag), "{cmd}");
        let shown: Vec<&str> = s.log.iter().map(|(l, _)| l.as_str()).collect();
        assert!(
            shown
                .iter()
                .any(|l| l.starts_with("$ sentry-network guard preview")
                    && l.contains(&format!("wireless.default_radio0.key={tag}"))
                    && l.contains("wireless.radio0.channel=36")),
            "{shown:?}"
        );
        assert_eq!(s.run.state.vars["lines"].matches(&tag).count(), 1);
        // The preview ends well; the apply step waits for its Enter. The window closes.
        s.on_exit(0, 0);
        assert!(matches!(
            s.next,
            sentry_core::workflows::runner::Next::Confirm(1)
        ));
        let dir = s.run.dir.clone();
        drop(s);
        let on_disk = |what: &str| {
            let mut all = String::new();
            let mut dirs = vec![
                sentry_core::maint::root(&scope),
                sentry_core::maint::data_root(&scope),
            ];
            while let Some(d) = dirs.pop() {
                for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        dirs.push(p);
                    } else {
                        let text =
                            String::from_utf8_lossy(&std::fs::read(&p).unwrap()).into_owned();
                        assert!(!text.contains(CANARY), "{what}: {} has it", p.display());
                        all.push_str(&text);
                    }
                }
            }
            all
        };
        let all = on_disk("after the first step");
        assert!(
            dir.join("state.json").is_file() && all.contains(&tag),
            "{all}"
        );

        // The window closed and opened again: the run is there, the value is not.
        let mut s = resume(&r).expect("the run in progress");
        let cmd = step_cmd(s.go(root_login).unwrap());
        assert!(
            cmd.contains("guard held-secret-test apply") && cmd.contains(&tag),
            "{cmd}"
        );
        assert!(!cmd.contains(CANARY), "{cmd}");
        // What that step does with it (`sentry-network guard preview|apply`, here):
        // stops before anything is read or changed, and says what to do.
        let err =
            crate::guard::Change::parse("wireless", &s.run.state.vars["lines"], "wifi", false)
                .unwrap_err();
        assert!(
            err.contains("isn't here any more") && err.contains("give the value"),
            "{err}"
        );
        on_disk("after the resume");
        s.abandon();
        let _ = std::fs::remove_dir_all(sentry_core::maint::root(&scope));
        let _ = std::fs::remove_dir_all(sentry_core::maint::data_root(&scope));
    }
}

#[cfg(test)]
mod change_tests {
    use super::*;
    use sentry_core::workflows::{Gate, Kind};

    fn wf(name: &str) -> workflows::Workflow {
        seeded()
            .into_iter()
            .find(|e| e.name == name)
            .and_then(|e| e.wf.ok())
            .unwrap_or_else(|| panic!("{name}"))
    }

    #[test]
    fn what_changes_a_router_waits_for_a_key_and_auto_never_answers_the_hard_ones() {
        use sentry_core::auto::{Asked, answers};
        let auto = |w: &workflows::Workflow, id: &str| {
            let step = w
                .steps
                .iter()
                .find(|s| s.id == id)
                .unwrap_or_else(|| panic!("{id}"));
            let cmd = step.run.clone().unwrap_or_default();
            answers(true, &Asked::Step { step, cmd: &cmd })
        };
        let g = wf("guarded-change");
        let gates: Vec<(&str, Gate)> = g.steps.iter().map(|s| (s.id.as_str(), s.gate())).collect();
        assert_eq!(
            gates,
            [
                ("show", Gate::Auto),
                ("guard", Gate::Confirm),
                ("keep", Gate::Confirm)
            ]
        );
        // Every step runs here, through the guard: none hands the router a line of its own.
        assert!(g.steps.iter().all(|s| {
            s.run
                .as_deref()
                .unwrap()
                .starts_with("sentry-network guard ")
        }));
        assert!(
            !auto(&g, "guard"),
            "applying a guarded change is the user's Enter"
        );
        assert!(!auto(&g, "keep"), "Wi-Fi's keep is the user's");
        // Even with the workflow's `risky` taken out, auto doesn't answer a keep.
        let mut keep = g.steps[2].clone();
        keep.risky = false;
        assert!(!answers(
            true,
            &Asked::Step {
                step: &keep,
                cmd: "sentry-network guard keep"
            }
        ));
        assert!(!answers(
            true,
            &Asked::Step {
                step: &keep,
                cmd: "sentry-network guard home keep"
            }
        ));
        // Its values: the change itself has no default, so auto asks for it.
        assert!(g.vars["configs"].default.is_none() && g.vars["lines"].default.is_none());

        let p = wf("package-update");
        assert!(p.vars["packages"].default.is_none(), "never every package");
        assert!(auto(&p, "upgrade") && !auto(&p, "upgrade-base"));
        let step = |id: &str| p.steps.iter().find(|s| s.id == id).unwrap();
        assert_eq!(step("upgrade").cond(), Some((false, "packages_leaf")));
        assert_eq!(step("upgrade-base").cond(), Some((true, "packages_leaf")));
        assert!(step("upgrade-base").risky && !step("upgrade").risky);
        // The whole transaction is shown before either is asked.
        let ids: Vec<&str> = p.steps.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "preview",
                "backup",
                "plan",
                "upgrade",
                "upgrade-base",
                "check"
            ]
        );
        // Whatever a workflow file says, auto never confirms an upgrade that may hold
        // more than leaves.
        let mut loose = step("upgrade-base").clone();
        loose.risky = false;
        assert!(!answers(
            true,
            &Asked::Step {
                step: &loose,
                cmd: "sentry-network packages upgrade base -- busybox"
            }
        ));
        assert!(!answers(
            true,
            &Asked::Step {
                step: &loose,
                cmd: "sentry network packages home upgrade base -- busybox"
            }
        ));
        // No step is a bare upgrade.
        for w in [&g, &p, &wf("firmware-upgrade")] {
            for s in &w.steps {
                let run = s.run.as_deref().unwrap_or("");
                assert!(
                    !run.contains("apk upgrade") && !run.contains("sysupgrade"),
                    "{run}"
                );
                assert_ne!(
                    s.kind,
                    Kind::Reboot,
                    "{}: the flash step waits for the restart itself",
                    s.id
                );
            }
        }
        let f = wf("firmware-upgrade");
        assert!(f.draft);
        assert!(!auto(&f, "flash"), "auto never flashes");
        let mut flash = f.steps.iter().find(|s| s.id == "flash").unwrap().clone();
        flash.risky = false;
        assert!(!answers(
            true,
            &Asked::Step {
                step: &flash,
                cmd: "sentry-network firmware flash"
            }
        ));
        assert!(!auto(&f, "download"), "owut download is a firmware command");
        assert!(
            !auto(&f, "add-missing"),
            "what comes back after a flash is asked"
        );
        // Even with `risky` taken out of the file, and however the program is called.
        for cmd in [
            "sentry-network firmware download",
            "sentry network firmware home download",
            "sentry-network firmware add-missing",
        ] {
            let mut step = f.steps.iter().find(|s| s.id == "download").unwrap().clone();
            step.risky = false;
            assert!(!answers(true, &Asked::Step { step: &step, cmd }), "{cmd}");
        }
        // The flash says what happens before it runs; the reads in between need no key.
        let flash = f.steps.iter().find(|s| s.id == "flash").unwrap();
        let ask = flash.ask.as_deref().unwrap();
        for said in [
            "no internet",
            "What is kept",
            "recovery procedure",
            "15 minutes",
        ] {
            assert!(ask.contains(said), "{said}");
        }
        let gates: Vec<(&str, Gate)> = f.steps.iter().map(|s| (s.id.as_str(), s.gate())).collect();
        assert_eq!(
            gates,
            [
                ("check", Gate::Auto),
                ("backup", Gate::Auto),
                ("plan", Gate::Auto),
                ("download", Gate::Confirm),
                ("flash", Gate::Confirm),
                ("wait", Gate::Auto),
                ("after", Gate::Auto),
                ("add-missing", Gate::Confirm),
                ("forget", Gate::Auto)
            ]
        );
        assert!(f.steps.iter().find(|s| s.id == "forget").unwrap().rollback);
    }
}
