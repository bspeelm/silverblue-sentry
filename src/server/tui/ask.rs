//! Ask Claude about the selected thing on a server. Claude reaches the server only through
//! `sentry-server exec <server>` (read-only allowlist); whatever it proposes, you run through
//! sentry-server after a confirm box.

use super::Tab;
use super::tabs::View;
use crate::claude::{Ask, Profile, fix_question};
use crate::server::remote::Remote;
use crate::server::workflow::Session;
use crate::workflows::runner::Next;

pub fn profile(r: &Remote, os: &str, kernel: &str) -> Profile {
    let name = &r.name;
    Profile {
        system: format!(
            "You are answering inside sentry-server, a monitoring and maintenance TUI on the \
user's laptop, about their server `{name}` ({os}, kernel {kernel}), which it reaches over ssh. \
Run commands on the server ONLY as `sentry-server exec {name} -- <command> <args>`, one command \
per call, no pipes or shell syntax (filter the output yourself). Allowed: {}. Anything else is \
refused. You cannot change anything, so never say you did. When something should be changed, \
give the exact commands for the user: they run them on the server through sentry-server after \
confirming (plain commands as they'd type them on the server, not wrapped in sentry-server or \
ssh). Keep it under about 200 words unless asked for more. If a command was refused or needs \
root, say so and give the command for the user.",
            crate::server::gateway::summary()
        ),
        tools: vec!["Bash".into()],
        allowed: vec![format!("Bash(sentry-server exec {name}:*)")],
        denied: Profile::denied_for_servers(),
    }
}

fn header(v: &View, r: &Remote) -> String {
    let (os, kernel) = v.s.host.value.clone().unwrap_or_default();
    let up = v.s.probe.value.as_ref().map_or(String::new(), |p| {
        format!(", up {}", crate::fmt::uptime(p.uptime_s))
    });
    format!("Server `{}`: {os}, kernel {kernel}{up}.\n", r.name)
}

const ON_SERVER: &str =
    "\nThe commands run on the server, through sentry-server, after I confirm each one.";

/// What `A` asks on each tab, from what's selected there.
pub fn ask_for(tab: Tab, v: &View, r: &Remote, wf: Option<&Session>) -> Option<Ask> {
    let h = header(v, r);
    match tab {
        Tab::Overview => {
            let rows = super::tabs::status_text(v).join("\n");
            Some(Ask::new(
                format!("{} · overview", r.name),
                format!("{h}What sentry-server shows right now:\n{rows}"),
                "How is this server doing? What needs attention, and what should I do first?",
            ))
        }
        Tab::Audit => {
            let f = super::tabs::selected_finding(v)?;
            Some(Ask::new(
                format!("{} · {}", r.name, f.message),
                format!(
                    "{h}Audit finding ({}, {}): {}\nid: {}\nwhat: {}\nwhy: {}\nsuggested: {}\nevidence: {}",
                    f.severity.as_str(),
                    f.category,
                    f.message,
                    f.id,
                    f.what,
                    f.why,
                    f.fix,
                    f.evidence
                ),
                fix_question(ON_SERVER),
            ))
        }
        Tab::Services => {
            let u = super::tabs::selected_unit(v)?;
            Some(Ask::new(
                format!("{} · {u}", r.name),
                format!("{h}{}", super::tabs::unit_text(v, &u)),
                fix_question(&format!(
                    "{ON_SERVER} If {u} is fine, say so and stop there."
                )),
            ))
        }
        Tab::Containers => {
            let c = v.s.docker.value.as_ref()?.containers.get(v.cur)?;
            Some(Ask::new(
                format!("{} · container {}", r.name, c.name),
                format!(
                    "{h}Container {}: image {}, {} (exit {}{}), health {}, {} restarts, compose \
                     project {}, ports {:?}{}",
                    c.name,
                    c.image,
                    c.status,
                    c.exit_code,
                    if c.oom { ", out of memory" } else { "" },
                    c.health.as_deref().unwrap_or("none"),
                    c.restarts,
                    c.compose.as_deref().unwrap_or("none"),
                    c.ports,
                    if c.docker_sock {
                        "; mounts docker.sock"
                    } else {
                        ""
                    }
                ),
                fix_question(&format!(
                    "{ON_SERVER} If the container is fine, say so and stop there."
                )),
            ))
        }
        Tab::Updates => {
            let a = v.s.apt.value.as_ref()?;
            let pkgs: Vec<String> = a
                .upgrades
                .iter()
                .map(|p| {
                    format!(
                        "{} {} → {} ({})",
                        p.name,
                        p.old.as_deref().unwrap_or("new"),
                        p.new,
                        p.origin
                    )
                })
                .collect();
            Some(Ask::new(
                format!("{} · updates", r.name),
                format!(
                    "{h}Updates (simulated): {}\nheld back: {}\nreboot required: {}; running {}, newest installed {}",
                    if pkgs.is_empty() {
                        "none".into()
                    } else {
                        pkgs.join("; ")
                    },
                    a.kept_back.join(" "),
                    a.reboot_since.map_or("no".into(), |s| format!(
                        "for {}",
                        crate::fmt::age(a.now - s)
                    )),
                    a.running_kernel,
                    a.newest_kernel.as_deref().unwrap_or("?")
                ),
                "Is it safe to upgrade and reboot now? Anything to watch out for with these \
                 packages on this server (services, containers, the GPU driver)?",
            ))
        }
        Tab::Workflows => {
            let s = wf?;
            let i = s.next.idx()?;
            if !matches!(s.next, Next::Stopped(_) | Next::Manual { failed: true, .. }) {
                return None;
            }
            let step = &s.wf.steps[i];
            let log = s.step_log().map(|(_, t)| t).unwrap_or_default();
            let tail: Vec<&str> = log.lines().rev().take(60).collect();
            let tail: Vec<&str> = tail.into_iter().rev().collect();
            let later: Vec<String> = (i + 1..s.wf.steps.len()).map(|j| s.title(j)).collect();
            Some(Ask::new(
                format!("{} · {} · {}", r.name, s.wf.name, step.id),
                format!(
                    "{h}Workflow {} step {}/{}: {} ({})\ncommand: {}\nexit: {}\nthe workflow's advice: {}\nlater steps: {}\nlast lines of its log:\n{}",
                    s.wf.name,
                    i + 1,
                    s.wf.steps.len(),
                    s.title(i),
                    step.id,
                    step.run.as_deref().unwrap_or("-"),
                    s.run.state.steps[i]
                        .code
                        .map_or("?".into(), |c| c.to_string()),
                    step.manual.as_deref().unwrap_or("none"),
                    later.join(" · "),
                    tail.join("\n")
                ),
                fix_question(&format!(
                    "{ON_SERVER} End the Recommendation with one of: retry (r), done by hand (d), \
                     skip (s), abandon (a). Never do a later step of the workflow yourself."
                )),
            ))
        }
    }
}
