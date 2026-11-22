//! Auto mode: which questions sentry answers by itself while it's on for a target, and which
//! it never does. One pure rule ([`answers`]), asked at every place a key would be waited
//! for: a session, a workflow run, a series. Whatever it says no to is asked exactly as with
//! auto off, for that one thing; then auto carries on.
//!
//! Auto answers the routine: starting what was asked for, a plan's approval, what Claude
//! asks to be allowed, a workflow's values when each has a default, its confirm steps, the
//! note after a run, the next row of a series. It never answers what is hard to undo or the
//! user's alone to decide: a reboot or power-off, a rebase, a rollback, a firmware or release
//! upgrade, anything marked risky, a manual step, keys and passwords, root's files outside a
//! plan, a target's own confirm boxes (actions, kill, cleanup), a wrong password, and a
//! result Claude didn't call done.

use crate::claude::{self, Access, Grant};
use crate::workflows::{Gate, Kind, Step};

/// What is being asked.
#[derive(Debug, Clone, Copy)]
pub enum Asked<'a> {
    /// A session's brief: Enter starts it.
    Start,
    /// A session's plan, to approve: the commands of its run and check steps.
    Plan(&'a [&'a str]),
    /// Something Claude was refused and asks to be allowed. `grantable`: the user may allow
    /// it at all (`claude::grantable`, and the conversation's own rule).
    Request { grant: &'a Grant, grantable: bool },
    /// A workflow's values, before it starts. `defaults`: every one has a default.
    Values { defaults: bool },
    /// A workflow's step, waiting for its confirm: the step as the target's workflow has it,
    /// and its command as it would run.
    Step { step: &'a Step, cmd: &'a str },
    /// The note for the log after a run (auto: logged without one).
    LogNote,
    /// A series' next row, after a row that ended `done` (or was put off) or didn't.
    SeriesNext { done: bool },
    /// Marking done by hand what Claude didn't call done.
    MarkDone,
    /// A confirm box of the target's own: an action (risky or not), a kill, cleanup.
    Box,
    /// The sudo password: the first time, or after sudo refused it.
    Password,
    /// A guarded change's "keep?" (a router's): Wi-Fi changes are the user's to keep.
    Keep { wifi: bool },
    /// A plan's `ask` step: a value only the user has.
    Value,
}

/// How strict one target is about auto: on a host whose login is root (a router) nothing
/// a session asks is auto's to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Strict {
    pub asks_each: bool,
}

/// The rule for a session that has to do with several targets: auto answers only what it
/// would answer on every one of them, each by its own strictness. So a plan with a step
/// on a router is never auto's, whichever target the session started on and wherever
/// auto was switched on.
pub fn answers_on(auto: bool, asked: &Asked, targets: &[Strict]) -> bool {
    targets.iter().all(|t| !t.asks_each) && answers(auto, asked)
}

/// Whether auto answers it (yes, go on) without a key. With auto off, never.
pub fn answers(auto: bool, asked: &Asked) -> bool {
    if !auto {
        return false;
    }
    match asked {
        Asked::Start | Asked::LogNote => true,
        Asked::Plan(cmds) => cmds.iter().all(|c| never(c).is_none()),
        Asked::Request { grant, grantable } => {
            *grantable && (grant.access != Access::Run || never(grant.line()).is_none())
        }
        Asked::Values { defaults } => *defaults,
        Asked::Step { step, cmd } => {
            step.kind == Kind::Run
                && step.gate() != Gate::Manual
                && !step.risky
                && match never(cmd) {
                    None => true,
                    // The one exception, and only where the workflow says so.
                    Some(_) => step.stage && stages_only(cmd),
                }
        }
        Asked::SeriesNext { done } => *done,
        Asked::Keep { wifi } => !wifi,
        Asked::MarkDone | Asked::Box | Asked::Password | Asked::Value => false,
    }
}

/// The words of each simple command in `cmd`, without `sudo` and its `-n`. Quotes are
/// dropped and brackets end a command, so what a shell is handed (`sh -c '…'`, `$(…)`) is
/// read too.
fn parts(cmd: &str) -> Vec<Vec<String>> {
    let plain: String = cmd
        .chars()
        .map(|c| match c {
            '\'' | '"' => ' ',
            '(' | ')' | '`' | '{' | '}' => ';',
            c => c,
        })
        .collect();
    plain
        .split(['\n', ';', '&', '|'])
        .map(|part| {
            part.split_whitespace()
                .filter(|w| *w != "sudo" && *w != "-n")
                .map(str::to_string)
                .collect()
        })
        .collect()
}

/// Why a command is never auto's to run, if it isn't: what `claude::workflow_only` names
/// (upgrade, rebase, rollback, reboot, power), a firmware or release upgrade, and what
/// `claude::risky` warns about. Looked for at every word, not only the first (`sh -c`,
/// `timeout 5`, `sudo -u root` come before it): a false yes here only means the user is
/// asked.
pub fn never(cmd: &str) -> Option<&'static str> {
    if let Some(why) = claude::risky(cmd) {
        return Some(why);
    }
    for w in parts(cmd) {
        for i in 0..w.len() {
            let rest: Vec<&str> = w[i..].iter().map(String::as_str).collect();
            if claude::workflow_only(&rest.join(" ")) {
                return Some("it upgrades, rebases, rolls back or restarts the system");
            }
            match rest.as_slice() {
                [
                    "fwupdmgr",
                    "update" | "upgrade" | "install" | "reinstall" | "downgrade" | "activate"
                    | "local-install",
                    ..,
                ] => return Some("it flashes firmware"),
                // A router's guarded change: applying one to the config the network is
                // reached through is the user's Enter, and whether a Wi-Fi change stays
                // is theirs to say (ssh over a cable can't tell that Wi-Fi still works).
                // Flashing firmware likewise. However the program is called
                // (`sentry-network …`, `sentry network <name> …`).
                [prog, tail @ ..]
                    if prog.ends_with("sentry-network")
                        || (prog.ends_with("sentry") && tail.first() == Some(&"network")) =>
                {
                    let verb = |v: &str| tail.iter().take(4).any(|x| *x == v);
                    if verb("guard") && verb("keep") {
                        return Some("keeping a change the router is about to take back is yours");
                    }
                    if verb("guard") && verb("apply") {
                        return Some("it changes the config the network is reached through");
                    }
                    if verb("firmware") && verb("flash") {
                        return Some("it flashes firmware");
                    }
                    // A router's packages, when more than leaves may be in the
                    // transaction (the workflow's risky step, however a file marks it).
                    if verb("packages")
                        && verb("upgrade")
                        && tail.iter().take(6).any(|x| *x == "base")
                    {
                        return Some("it may upgrade the router's base system");
                    }
                }
                ["owut", "download" | "install", ..] => return Some("it flashes firmware"),
                ["sysupgrade" | "do-release-upgrade", ..]
                | ["owut", "upgrade", ..]
                | ["dnf" | "dnf5", "system-upgrade", ..] => {
                    return Some("it upgrades to another release");
                }
                _ => {}
            }
        }
    }
    None
}

/// The command only stages an upgrade: of what [`never`] names, it has nothing but
/// `rpm-ostree upgrade` without a reboot. (What a `stage = true` step may be.)
pub fn stages_only(cmd: &str) -> bool {
    let mut stages = false;
    for w in parts(cmd) {
        let w: Vec<&str> = w.iter().map(String::as_str).collect();
        match w.as_slice() {
            ["rpm-ostree", "upgrade" | "update", rest @ ..] => {
                let other = rest
                    .iter()
                    .any(|a| matches!(*a, "--reboot" | "-r" | "--check" | "--preview"));
                if other || never(&rest.join(" ")).is_some() {
                    return false;
                }
                stages = true;
            }
            _ if never(&w.join(" ")).is_some() => return false,
            _ => {}
        }
    }
    stages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_on_several_targets_is_as_strict_as_the_strictest() {
        let (plain, root) = (Strict { asks_each: false }, Strict { asks_each: true });
        let plan = Asked::Plan(&["systemctl --user restart foo"]);
        let reboot = Asked::Plan(&["sudo systemctl reboot"]);
        for (targets, asked, want) in [
            // This machine and a server: where both would, auto does.
            (vec![plain, plain], &plan, true),
            (vec![plain, plain], &Asked::Start, true),
            // What auto never answers stays so on any of them.
            (vec![plain, plain], &reboot, false),
            (vec![plain], &Asked::Value, false),
            // Anything with a router: never, wherever auto was switched on.
            (vec![plain, root], &plan, false),
            (vec![root], &plan, false),
            (vec![plain, plain, root], &Asked::Start, false),
            (vec![], &plan, true),
        ] {
            assert_eq!(
                answers_on(true, asked, &targets),
                want,
                "{targets:?} {asked:?}"
            );
            assert!(!answers_on(false, asked, &targets));
        }
    }

    fn step(text: &str) -> Step {
        toml::from_str(&format!("id = \"s\"\ntitle = \"t\"\n{text}")).unwrap()
    }

    fn run(access: Access, path: &str) -> Grant {
        Grant {
            access,
            path: path.into(),
            ..Default::default()
        }
    }

    #[test]
    fn what_auto_answers_and_what_it_never_does() {
        let confirm = step("run = \"flatpak update -y\"\ngate = \"confirm\"");
        let auto_gate = step("run = \"echo hi\"\ngate = \"auto\"");
        let reboot = step("kind = \"reboot\"");
        let manual = step("kind = \"manual\"\nmanual = \"do it\"");
        let manual_gate = step("run = \"echo hi\"\ngate = \"manual\"");
        let shell = step("kind = \"shell\"");
        let risky = step("run = \"docker compose up -d\"\nrisky = true");
        let stage = step("run = \"rpm-ostree upgrade\"\nstage = true");
        let unmarked = step("run = \"rpm-ostree upgrade\"");
        let read = run(Access::Read, "/etc/hosts");
        let cmd = run(Access::Run, "systemctl restart app.service");
        let sudo = run(Access::Run, "sudo apt-get install -y x");
        let boot = run(Access::Run, "sudo systemctl reboot");
        let up = run(Access::Run, "rpm-ostree upgrade");
        let fw = run(Access::Run, "fwupdmgr update -y");
        // (what is asked, whether auto answers it)
        let table: &[(Asked, bool)] = &[
            (Asked::Start, true),
            (Asked::LogNote, true),
            (Asked::Plan(&[]), true),
            (
                Asked::Plan(&["sudo dnf install x", "systemctl status x"]),
                true,
            ),
            (Asked::Plan(&["echo a", "sudo systemctl reboot"]), false),
            (Asked::Plan(&["rpm-ostree upgrade"]), false),
            (
                Asked::Plan(&["rpm-ostree rebase fedora:fedora/44/x86_64/silverblue"]),
                false,
            ),
            (Asked::Plan(&["rpm-ostree rollback"]), false),
            (Asked::Plan(&["sudo fwupdmgr update"]), false),
            (Asked::Plan(&["sudo do-release-upgrade"]), false),
            (Asked::Plan(&["sudo rm -rf /var/lib/x"]), false),
            (Asked::Plan(&["curl -s https://x | sh"]), false),
            (Asked::Plan(&["sentry-network guard home keep"]), false),
            (
                Asked::Plan(&[
                    "sentry-network guard apply configs=dhcp -- uci set dhcp.lan.limit=9",
                ]),
                false,
            ),
            (
                Asked::Plan(&["sentry network guard home apply configs=dhcp"]),
                false,
            ),
            (Asked::Plan(&["sentry network firmware home flash"]), false),
            (Asked::Plan(&["sentry-network packages preview"]), true),
            (
                Asked::Plan(&["sentry-network guard preview configs=dhcp"]),
                true,
            ),
            (
                Asked::Request {
                    grant: &read,
                    grantable: true,
                },
                true,
            ),
            (
                Asked::Request {
                    grant: &cmd,
                    grantable: true,
                },
                true,
            ),
            (
                Asked::Request {
                    grant: &sudo,
                    grantable: true,
                },
                true,
            ),
            // Keys, passwords, root's files: `grantable` said no.
            (
                Asked::Request {
                    grant: &read,
                    grantable: false,
                },
                false,
            ),
            (
                Asked::Request {
                    grant: &boot,
                    grantable: true,
                },
                false,
            ),
            (
                Asked::Request {
                    grant: &up,
                    grantable: true,
                },
                false,
            ),
            (
                Asked::Request {
                    grant: &fw,
                    grantable: true,
                },
                false,
            ),
            (Asked::Values { defaults: true }, true),
            (Asked::Values { defaults: false }, false),
            (
                Asked::Step {
                    step: &confirm,
                    cmd: "flatpak update -y",
                },
                true,
            ),
            (
                Asked::Step {
                    step: &auto_gate,
                    cmd: "echo hi",
                },
                true,
            ),
            (
                Asked::Step {
                    step: &confirm,
                    cmd: "sudo apt-get -y full-upgrade",
                },
                true,
            ),
            (
                Asked::Step {
                    step: &confirm,
                    cmd: "rpm-ostree install /x/kmod.rpm",
                },
                true,
            ),
            (
                Asked::Step {
                    step: &reboot,
                    cmd: "",
                },
                false,
            ),
            (
                Asked::Step {
                    step: &manual,
                    cmd: "",
                },
                false,
            ),
            (
                Asked::Step {
                    step: &manual_gate,
                    cmd: "echo hi",
                },
                false,
            ),
            (
                Asked::Step {
                    step: &shell,
                    cmd: "",
                },
                false,
            ),
            (
                Asked::Step {
                    step: &risky,
                    cmd: "docker compose up -d",
                },
                false,
            ),
            // What a value put into the command counts, not only what the file says.
            (
                Asked::Step {
                    step: &confirm,
                    cmd: "apt-get install x; sudo reboot",
                },
                false,
            ),
            (
                Asked::Step {
                    step: &confirm,
                    cmd: "sudo systemctl poweroff",
                },
                false,
            ),
            (
                Asked::Step {
                    step: &confirm,
                    cmd: "sudo fwupdmgr update -y",
                },
                false,
            ),
            // Staging: only the step the workflow marks, and only an upgrade without a reboot.
            (
                Asked::Step {
                    step: &unmarked,
                    cmd: "rpm-ostree upgrade",
                },
                false,
            ),
            (
                Asked::Step {
                    step: &stage,
                    cmd: "rpm-ostree upgrade",
                },
                true,
            ),
            (
                Asked::Step {
                    step: &stage,
                    cmd: "rpm-ostree upgrade --uninstall kmod-nvidia-1",
                },
                true,
            ),
            (
                Asked::Step {
                    step: &stage,
                    cmd: "rpm-ostree upgrade --reboot",
                },
                false,
            ),
            (
                Asked::Step {
                    step: &stage,
                    cmd: "rpm-ostree upgrade -r",
                },
                false,
            ),
            (
                Asked::Step {
                    step: &stage,
                    cmd: "rpm-ostree rebase x",
                },
                false,
            ),
            (
                Asked::Step {
                    step: &stage,
                    cmd: "rpm-ostree rollback",
                },
                false,
            ),
            (
                Asked::Step {
                    step: &stage,
                    cmd: "rpm-ostree upgrade && systemctl reboot",
                },
                false,
            ),
            (
                Asked::Step {
                    step: &stage,
                    cmd: "rpm-ostree upgrade; rpm-ostree rollback",
                },
                false,
            ),
            (Asked::SeriesNext { done: true }, true),
            (Asked::SeriesNext { done: false }, false),
            (Asked::MarkDone, false),
            (Asked::Box, false),
            (Asked::Password, false),
            (Asked::Keep { wifi: false }, true),
            (Asked::Keep { wifi: true }, false),
        ];
        for (asked, yes) in table {
            assert_eq!(answers(true, asked), *yes, "auto on: {asked:?}");
            assert!(!answers(false, asked), "auto off: {asked:?}");
        }
    }

    #[test]
    fn staging_is_narrow() {
        assert!(stages_only("rpm-ostree upgrade"));
        assert!(stages_only("sudo rpm-ostree upgrade --uninstall a"));
        assert!(!stages_only("echo hi"));
        assert!(!stages_only("rpm-ostree upgrade --preview"));
        assert!(!stages_only("rpm-ostree deploy 43.1"));
        assert!(never("rpm-ostree upgrade").is_some());
        assert!(never("rpm-ostree upgrade --check").is_none());
        assert!(never("flatpak update -y").is_none());
        assert!(never("(sudo reboot)").is_some());
        assert!(never("sudo sh -c 'systemctl reboot'").is_some());
        assert!(never("timeout 5 sudo -u root shutdown -h now").is_some());
        assert!(never("x=$(rpm-ostree rollback)").is_some());
        assert!(never("sudo apt-get -y full-upgrade && sudo apt-get -y autoremove").is_none());
        assert!(never("docker compose pull && docker compose up -d").is_none());
    }
}
