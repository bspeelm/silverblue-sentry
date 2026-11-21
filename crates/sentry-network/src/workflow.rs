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
/// `packages_base`: the run's `packages` names a base-system package.
pub const CONDS: &[&str] = &["guard_waiting", "packages_base"];

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
];

/// Packages a router doesn't boot or answer without: upgrading one of these alone, against
/// the firmware it was built with, is the risky kind.
pub fn base_package(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "base-files",
        "busybox",
        "libc",
        "musl",
        "kernel",
        "netifd",
        "procd",
        "firewall4",
        "dropbear",
        "ubus",
        "ubusd",
        "uci",
        "fstools",
        "mtd",
        "apk-mbedtls",
        "apk-openssl",
        "odhcpd",
        "odhcp6c",
        "nftables",
        "logd",
        "rpcd",
        "urngd",
    ];
    const STARTS: &[&str] = &[
        "kmod-",
        "hostapd",
        "wpad",
        "dnsmasq",
        "libubox",
        "libubus",
        "libuci",
        "procd-",
        "libnftnl",
        "nftables-",
        "odhcpd-",
        "libgcc",
        "libpthread",
        "librt",
        "wpa-supplicant",
    ];
    EXACT.contains(&name) || STARTS.iter().any(|s| name.starts_with(s))
}

/// A package's name as apk takes it, and nothing a shell would read as anything else.
pub fn package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 80
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+._-".contains(c))
}

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
            // The run in progress is this one: its `packages` value.
            "packages_base" => Ok(sentry_core::workflows::state::in_progress_in(&root(
                &self.r.scope,
            ))
            .and_then(|run| run.state.vars.get("packages").cloned())
            .is_some_and(|p| p.split_whitespace().any(base_package))),
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
                "package-update"
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
        assert_eq!(p.steps[2].cond(), Some((true, "packages_base")));
        assert_eq!(p.steps[3].cond(), Some((false, "packages_base")));
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
    }

    #[test]
    fn base_packages_and_names() {
        for b in [
            "base-files",
            "busybox",
            "libc",
            "netifd",
            "procd",
            "firewall4",
            "dnsmasq",
            "dnsmasq-full",
            "dropbear",
            "hostapd-common",
            "wpad-basic-mbedtls",
            "kmod-mt7915e",
            "kernel",
            "libubox20240329",
            "uci",
        ] {
            assert!(base_package(b), "{b}");
        }
        for o in [
            "tcpdump",
            "luci-app-firewall",
            "nano",
            "adblock-fast",
            "owut",
            "curl",
        ] {
            assert!(!base_package(o), "{o}");
        }
        for ok in [
            "tcpdump",
            "luci-app-firewall",
            "libstdcpp6",
            "kmod-mt7915e",
            "a.b+c_d",
        ] {
            assert!(package_name(ok), "{ok}");
        }
        for bad in [
            "",
            "-x",
            "a;reboot",
            "a b",
            "$(reboot)",
            "a|b",
            "--force",
            "a'b",
            "a/b",
            "*",
        ] {
            assert!(!package_name(bad), "{bad}");
        }
    }
}
