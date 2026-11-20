//! Server workflows: the same TOML format and state machine as the local ones
//! (`workflows::runner`), with server built-ins and conditions read over ssh. Definitions live in
//! `~/.config/sentry/servers/<name>/workflows/` when that has any (a server's own, replacing
//! the generic ones), otherwise `~/.config/sentry/server-workflows/` (seeded); runs in
//! `~/.local/share/sentry/servers/<name>/workflows/`.
//!
//! Steps run on the server (`sh -c` over ssh); a step that starts with `sentry-server cond` runs
//! here and checks the server, so verification needs nothing installed there.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::collect::{apt, docker, units};
use super::remote::{Remote, SrvError};
pub use sentry_app::remote::workflow::{
    Exec, Live, LogKind, SUDO_REFUSED, Session, no_prompt, own_dir, pick_dir, root, tee_to, tomls,
};
use sentry_core::paths;
use sentry_core::workflows::runner::Env;
use sentry_core::workflows::{self, Entry, LintRules, Workflow};

pub const BUILTINS: &[&str] = &[
    "running_kernel",
    "newest_kernel",
    "server",
    "compose_project",
    "compose_file",
];
/// Read fresh every time (a reboot changes them; freezing them would be wrong).
const LIVE: &[&str] = &["running_kernel", "newest_kernel"];

pub const CONDS: &[&str] = &[
    "reboot_required",
    "kernel_pending",
    "updates_pending",
    "services_ok",
    "containers_healthy",
];

pub const RULES: LintRules = LintRules {
    builtins: BUILTINS,
    cond: |c| CONDS.contains(&c),
    check: |_| false,
};

pub const SEEDS: &[(&str, &str)] = &[
    (
        "apt-maintenance",
        include_str!("../../../assets/server-workflows/apt-maintenance.toml"),
    ),
    (
        "compose-update",
        include_str!("../../../assets/server-workflows/compose-update.toml"),
    ),
];

pub fn dir() -> PathBuf {
    paths::config_dir().join("server-workflows")
}

/// A server's own workflows: these replace the generic ones when there are any.
pub fn server_dir(server: &str) -> PathBuf {
    own_dir(server)
}

/// Where a server's workflows come from: its own directory if it has any, else the generic one.
pub fn dir_for(server: &str) -> PathBuf {
    pick_dir(server_dir(server), dir())
}

/// A server's workflows, with their lint results: its own if it has any, else the generic ones
/// (seeded first).
pub fn list_for(server: &str) -> Vec<Entry> {
    let d = dir_for(server);
    if d == dir() {
        let _ = std::fs::create_dir_all(&d);
        let _ = workflows::seed_with(&d, SEEDS, &[]);
    }
    load_dir(&d)
}

fn load_dir(d: &std::path::Path) -> Vec<Entry> {
    let mut v: Vec<Entry> = tomls(d)
        .into_iter()
        .map(|p| {
            let mut e = workflows::load_path_with(&p, &RULES);
            if let Ok(w) = &e.wf {
                e.issues.extend(lint_conds(w));
            }
            e
        })
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

/// `sentry-server cond <name>` steps must name a real condition.
fn lint_conds(w: &Workflow) -> Vec<workflows::Issue> {
    w.steps
        .iter()
        .filter_map(|s| {
            let run = s.run.as_deref()?;
            let name = run
                .strip_prefix("sentry-server cond ")?
                .split_whitespace()
                .next()?;
            (!CONDS.contains(&name)).then(|| workflows::Issue {
                error: true,
                msg: format!("step {:?}: unknown condition `{name}`", s.id),
            })
        })
        .collect()
}

/// A condition, with a line saying why.
pub fn cond(r: &Remote, name: &str) -> Result<(bool, String), SrvError> {
    match name {
        "reboot_required" => {
            let o = r.output(&r.sh("[ -f /var/run/reboot-required ] && echo yes || echo no"))?;
            let yes = o.trim() == "yes";
            Ok((
                yes,
                if yes {
                    "a reboot is required".into()
                } else {
                    "no reboot required".into()
                },
            ))
        }
        "kernel_pending" => {
            let a = apt::collect(r)?;
            Ok((
                a.kernel_pending(),
                format!(
                    "running {}, newest installed {}",
                    a.running_kernel,
                    a.newest_kernel.as_deref().unwrap_or("?")
                ),
            ))
        }
        "updates_pending" => {
            let a = apt::collect(r)?;
            Ok((
                !a.upgrades.is_empty(),
                format!("{} update(s) waiting", a.upgrades.len()),
            ))
        }
        "services_ok" => {
            if r.cfg.services.is_empty() {
                return Ok((true, "no services: listed in server_config.yaml".into()));
            }
            let u = units::collect(r)?;
            let down: Vec<&str> = r
                .cfg
                .services
                .iter()
                .filter(|s| u.get(s).is_none_or(|st| st.active != "active"))
                .map(String::as_str)
                .collect();
            Ok(if down.is_empty() {
                (true, format!("{} service(s) running", r.cfg.services.len()))
            } else {
                (false, format!("not running: {}", down.join(", ")))
            })
        }
        "containers_healthy" => {
            let d = docker::collect(r)?;
            let ignored = |c: &docker::Container| {
                r.cfg
                    .containers
                    .ignore
                    .iter()
                    .any(|g| sentry_core::baseline::glob(g, &c.name))
            };
            let bad: Vec<String> = d
                .containers
                .iter()
                .filter(|c| !ignored(c) && !c.finished())
                .filter(|c| {
                    c.status != "running"
                        || matches!(c.health.as_deref(), Some("unhealthy" | "starting"))
                })
                .map(|c| {
                    format!(
                        "{} ({})",
                        c.name,
                        c.health.clone().unwrap_or_else(|| c.status.clone())
                    )
                })
                .collect();
            let n = d
                .containers
                .iter()
                .filter(|c| c.status == "running")
                .count();
            Ok(if bad.is_empty() {
                (true, format!("{n} container(s) running, none unhealthy"))
            } else {
                (false, format!("not ready: {}", bad.join(", ")))
            })
        }
        n => Err(SrvError::Failed(format!(
            "unknown condition `{n}` (one of: {})",
            CONDS.join(", ")
        ))),
    }
}

pub struct RemoteEnv {
    pub r: Remote,
}

/// The program a step's `sentry-server cond …` line is run by, here.
pub const PROG: &str = "sentry-server";

/// The run still in progress on this server, if any.
pub fn resume(r: &Remote) -> Option<Session> {
    Session::resume(r, PROG, Box::new(RemoteEnv { r: r.clone() }))
}

/// Start a run. `vars`: the workflow's `[vars]`, asked for before it starts.
pub fn begin(entry: &Entry, r: &Remote, vars: BTreeMap<String, String>) -> anyhow::Result<Session> {
    Session::begin(entry, r, vars, PROG, Box::new(RemoteEnv { r: r.clone() }))
}

impl Env for RemoteEnv {
    fn cond(&self, name: &str) -> Result<bool, String> {
        cond(&self.r, name)
            .map(|(b, _)| b)
            .map_err(|e| e.to_string())
    }

    fn builtin(&self, name: &str) -> Result<String, String> {
        let r = &self.r;
        let first = || {
            r.cfg
                .compose
                .first()
                .ok_or_else(|| "no compose: projects in server_config.yaml".to_string())
        };
        match name {
            "server" => Ok(r.name.clone()),
            "running_kernel" => r
                .output(&r.cmd("uname").arg("-r"))
                .map(|s| s.trim().to_string())
                .map_err(|e| e.to_string()),
            "newest_kernel" => apt::collect(r)
                .map_err(|e| e.to_string())?
                .newest_kernel
                .ok_or_else(|| "no kernel found in /boot".into()),
            "compose_project" => first().map(|c| c.name.clone()),
            "compose_file" => first().map(|c| c.file.clone()),
            n => Err(format!("unknown built-in {n}")),
        }
    }

    fn boot_id(&self) -> String {
        self.r
            .output(&self.r.cmd("cat").arg("/proc/sys/kernel/random/boot_id"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }

    fn builtins(&self) -> &'static [&'static str] {
        BUILTINS
    }

    fn live(&self) -> &'static [&'static str] {
        LIVE
    }
}

/// `sentry-server cond <server> <name> [--wait SECS]`: exit 0 when true. With --wait it keeps
/// checking every 5 s until it's true or the time is up.
pub fn cond_cli(r: &Remote, name: &str, wait: Option<u64>) -> u8 {
    let until = Instant::now() + Duration::from_secs(wait.unwrap_or(0));
    loop {
        match cond(r, name) {
            Ok((true, why)) => {
                println!("✓ {why}");
                return 0;
            }
            Ok((false, why)) if Instant::now() >= until => {
                println!("✗ {why}");
                return 1;
            }
            Ok((false, why)) => println!("… {why}"),
            // Waiting won't fix these.
            Err(
                e @ (SrvError::NeedsSudo(_) | SrvError::SudoPassword(_) | SrvError::NotFound(_)),
            ) => {
                println!("✗ {e}");
                return 2;
            }
            Err(e) if Instant::now() >= until => {
                println!("✗ {e}");
                return 2;
            }
            Err(e) => println!("… {e}"),
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_lint_clean() {
        for (name, text) in SEEDS {
            let w = workflows::parse(text).unwrap_or_else(|e| panic!("{name}: {e}"));
            let mut issues = workflows::lint_with(&w, &RULES);
            issues.extend(lint_conds(&w));
            let errors: Vec<_> = issues.iter().filter(|i| i.error).collect();
            assert!(errors.is_empty(), "{name}: {errors:?}");
        }
        // sentry's built-ins would reject them: these are the server's.
        let w = workflows::parse(SEEDS[0].1).unwrap();
        let local = workflows::LintRules {
            builtins: workflows::BUILTINS,
            cond: |_| true,
            check: |_| true,
        };
        assert!(
            workflows::lint_with(&w, &local)
                .iter()
                .any(|i| i.msg.contains("newest_kernel"))
        );
    }

    #[test]
    fn a_servers_own_workflows_replace_the_generic_ones() {
        let base = std::env::temp_dir().join(format!("sentry-wfdir-{}", std::process::id()));
        let (own, generic) = (base.join("own"), base.join("generic"));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&generic).unwrap();
        // No directory, or one without workflows: the generic ones.
        assert_eq!(pick_dir(own.clone(), generic.clone()), generic);
        std::fs::create_dir_all(&own).unwrap();
        std::fs::write(own.join("notes.txt"), "x").unwrap();
        assert_eq!(pick_dir(own.clone(), generic.clone()), generic);
        std::fs::write(own.join("bump.toml"), SEEDS[1].1).unwrap();
        assert_eq!(pick_dir(own.clone(), generic.clone()), own);
        let names: Vec<String> = load_dir(&own).into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["bump"]);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn cond_steps_are_linted() {
        let w = workflows::parse(
            "name = \"x\"\ndescription = \"x\"\n[[steps]]\nid = \"a\"\ntitle = \"a\"\nrun = \"sentry-server cond nope\"\ngate = \"auto\"\n",
        )
        .unwrap();
        assert_eq!(
            lint_conds(&w)[0].msg,
            "step \"a\": unknown condition `nope`"
        );
    }
}
