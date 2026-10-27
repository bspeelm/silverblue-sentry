//! Ask Claude about the selected thing on a server. Claude reaches the server only through
//! `sentry-server exec <server>` (read-only allowlist); whatever it proposes, you run through
//! sentry-server after a confirm box.

use super::Tab;
use super::tabs::View;
use crate::claude::{Ask, Profile, fix_question};
use crate::server::remote::{Remote, SudoMode};
use crate::server::workflow::Session;
use crate::workflows::Entry;
use crate::workflows::runner::{Next, preview};
use crate::workflows::state::StepStatus;

/// The assessment profile (`A` on Maintenance): the gateway, plus the web for release notes
/// and reading the configured notes files.
pub fn assess_profile(r: &Remote, os: &str, kernel: &str, sudo: Option<SudoMode>) -> Profile {
    let mut p = profile(r, os, kernel, sudo);
    p.system.push_str(
        " For this question you may also read the web with the WebFetch and WebSearch tools \
         (release notes: fetch the GitHub release pages given; never curl), and the notes files \
         named in it with the Read tool (not grep or cat). Cite what you read.",
    );
    p.tools
        .extend(["WebFetch", "WebSearch", "Read"].map(String::from));
    p.allowed
        .extend(["WebFetch", "WebSearch"].map(String::from));
    // Denied for every other ask; this one is about reading upstream's notes.
    p.denied.retain(|d| d != "WebFetch" && d != "WebSearch");
    let notes = super::maint::resolve_notes(&r.cfg.maintenance.notes);
    p.allowed.extend(super::maint::read_rules(&notes));
    let mut dirs: Vec<String> = notes
        .iter()
        .filter_map(|n| std::path::Path::new(n).parent())
        .map(|d| d.display().to_string())
        .collect();
    dirs.sort();
    dirs.dedup();
    p.dirs = dirs;
    p
}

pub fn profile(r: &Remote, os: &str, kernel: &str, sudo: Option<SudoMode>) -> Profile {
    let name = &r.name;
    let sudo = match sudo {
        Some(SudoMode::Password) => {
            " sudo on this server asks for a password: commands of yours that need root fail; \
             the user runs root commands with their password."
        }
        Some(SudoMode::Absent) => " This login has no sudo on the server.",
        _ => "",
    };
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
root, say so and give the command for the user.{sudo}",
            crate::server::gateway::summary()
        ),
        tools: vec!["Bash".into()],
        allowed: vec![format!("Bash(sentry-server exec {name}:*)")],
        denied: Profile::denied_for_servers(),
        dirs: Vec::new(),
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

/// Why `A` had nothing to ask about, when it doesn't.
pub fn nothing_here(tab: Tab, v: &View) -> &'static str {
    match tab {
        Tab::Updates if v.s.apt.value.is_none() => "the updates are still loading",
        Tab::Audit if v.s.report.value.is_none() => "the audit report is still loading",
        Tab::Containers if v.s.docker.value.is_none() => "the containers are still loading",
        Tab::Services if v.s.units.value.is_none() => "the services are still loading",
        Tab::Maint if v.s.maint.value.is_none() => "the maintenance items are still loading",
        _ => "nothing selected to ask about here",
    }
}

/// What `A` asks on each tab, from what's selected there. `entry`: the workflow selected on
/// the Workflows tab when none is running.
pub fn ask_for(
    tab: Tab,
    v: &View,
    r: &Remote,
    wf: Option<&Session>,
    entry: Option<&Entry>,
) -> Option<Ask> {
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
            let c = super::tabs::selected_container(v)?;
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
            let selected = super::tabs::selected_upgrade(v).map_or(String::new(), |p| {
                format!(
                    "\nSelected: {} {} → {} ({})",
                    p.name,
                    p.old.as_deref().unwrap_or("new"),
                    p.new,
                    p.origin
                )
            });
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
                    "{h}Updates (simulated): {}\nheld back: {}\nreboot required: {}; running {}, newest installed {}{selected}",
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
                if selected.is_empty() {
                    "Is it safe to upgrade and reboot now? Anything to watch out for with these \
                     packages on this server (services, containers, the GPU driver)?"
                        .to_string()
                } else {
                    "What does the selected update change, and is it safe to install on this \
                     server now? Then: anything to watch out for with the rest (services, \
                     containers, the GPU driver), and is a reboot needed?"
                        .to_string()
                },
            ))
        }
        Tab::Maint => super::maint::ask(v, r),
        Tab::Workflows => match wf {
            Some(s) => Some(ask_step(&h, r, s)),
            None => entry.map(|e| ask_workflow(&h, v, r, e)),
        },
    }
}

/// A workflow before it starts: its steps and what the server looks like now.
fn ask_workflow(h: &str, v: &View, r: &Remote, e: &Entry) -> Ask {
    let steps = match &e.wf {
        Ok(w) => w
            .steps
            .iter()
            .enumerate()
            .map(|(i, st)| {
                format!(
                    "{}. {} [{}{}]{}",
                    i + 1,
                    st.title,
                    st.tag(),
                    st.when
                        .as_deref()
                        .map_or(String::new(), |c| format!(", only when {c}")),
                    st.run
                        .as_deref()
                        .map_or(String::new(), |c| format!("\n   $ {c}"))
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Err(err) => format!("(doesn't parse: {err})"),
    };
    let state = super::tabs::status_text(v).join("\n");
    Ask::new(
        format!("{} · workflow {}", r.name, e.name),
        format!(
            "{h}Workflow {} ({}), not started.\nSteps:\n{steps}\nThe server right now:\n{state}",
            e.name,
            e.path.display()
        ),
        "Is now a good time to run this workflow on this server? What will each step do here, \
         what could go wrong, and what should I check first? Don't run any of its steps.",
    )
}

/// The workflow in progress: its current step, whatever state it's in.
fn ask_step(h: &str, r: &Remote, s: &Session) -> Ask {
    let done: Vec<String> =
        s.wf.steps
            .iter()
            .zip(&s.run.state.steps)
            .filter(|(_, st)| st.status != StepStatus::Pending)
            .map(|(step, st)| {
                format!(
                    "{}: {:?}{}",
                    step.id,
                    st.status,
                    st.code.map_or(String::new(), |c| format!(" (exit {c})"))
                )
            })
            .collect();
    let Some(i) = s.next.idx() else {
        return Ask::new(
            format!("{} · {}", r.name, s.wf.name),
            format!(
                "{h}Workflow {} is {}.\nSteps: {}",
                s.wf.name,
                s.state_word(),
                done.join(" · ")
            ),
            "Summarise what this run did on the server and whether anything needs a follow-up.",
        );
    };
    let step = &s.wf.steps[i];
    let log = s.step_log().map(|(_, t)| t).unwrap_or_default();
    let tail: Vec<&str> = log.lines().rev().take(60).collect();
    let tail: Vec<&str> = tail.into_iter().rev().collect();
    let later: Vec<String> = (i + 1..s.wf.steps.len()).map(|j| s.title(j)).collect();
    let failed = matches!(s.next, Next::Stopped(_) | Next::Manual { failed: true, .. });
    let ctx = format!(
        "{h}Workflow {} step {}/{}: {} ({}) · {}\ncommand: {}\nexit: {}\nthe workflow's advice: {}\nsteps so far: {}\nlater steps: {}\nlast lines of its log:\n{}",
        s.wf.name,
        i + 1,
        s.wf.steps.len(),
        s.title(i),
        step.id,
        s.state_word(),
        step.run
            .as_deref()
            .map_or("-".into(), |c| preview(&s.run.state, c)),
        s.run.state.steps[i]
            .code
            .map_or("?".into(), |c| c.to_string()),
        step.manual.as_deref().unwrap_or("none"),
        done.join(" · "),
        later.join(" · "),
        if tail.is_empty() {
            "(nothing yet)".into()
        } else {
            tail.join("\n")
        }
    );
    let question = if failed {
        fix_question(&format!(
            "{ON_SERVER} End the Recommendation with one of: retry (r), done by hand (d), \
             skip (s), abandon (a). Never do a later step of the workflow yourself."
        ))
    } else {
        "This step hasn't run yet. What will it do on this server, is it safe to run now, and \
         what should I check first? Don't run it yourself."
            .to_string()
    };
    Ask::new(
        format!("{} · {} · {}", r.name, s.wf.name, step.id),
        ctx,
        question,
    )
}
