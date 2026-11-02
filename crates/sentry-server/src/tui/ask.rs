//! Ask Claude about the selected thing on a server. Claude reaches the server only through
//! `sentry-server exec <server>` (read-only allowlist); whatever it proposes, you run through
//! sentry-server after a confirm box.

use super::Tab;
use super::tabs::View;
use crate::remote::{Remote, SudoMode};
use crate::workflow::Session;
use sentry_core::claude::{Ask, Profile, fix_question};
use sentry_core::workflows::runner::{Next, preview};
use sentry_core::workflows::state::StepStatus;

/// The plans and reviews profile (`p`, `R` on Maintenance): the gateway, plus the web for release notes
/// and reading the configured notes files.
pub fn writer_profile(r: &Remote, os: &str, kernel: &str, sudo: Option<SudoMode>) -> Profile {
    let mut p = profile(r, os, kernel, sudo).with_notes(&r.cfg.maintenance.notes);
    p.system.push_str(
        " For this question you may also read the web with the WebFetch and WebSearch tools \
         (release notes: fetch the GitHub release pages given; never curl), and the notes files \
         named in it with the Read tool (not grep or cat). Cite what you read.",
    );
    p.tools.extend(["WebFetch", "WebSearch"].map(String::from));
    p.allowed
        .extend(["WebFetch", "WebSearch"].map(String::from));
    // Denied for every other ask; this one is about reading upstream's notes.
    p.denied.retain(|d| d != "WebFetch" && d != "WebSearch");
    // The maintenance log: the ledger and every entry in it.
    let ledger = super::maint::ledger_path(&r.name);
    let log_dir = std::path::Path::new(&ledger)
        .parent()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    p.allowed.push(format!("Read(/{log_dir}/**)"));
    // Claude Code can only add a directory that exists (the log appears with the first run).
    if std::path::Path::new(&log_dir).is_dir() {
        p.dirs.push(log_dir);
    }
    p.dirs.sort();
    p.dirs.dedup();
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
root, say so and give the command for the user.{sudo} Files on the laptop (the user's notes): {}",
            crate::gateway::summary(),
            sentry_core::claude::GRANTS
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
        format!(", up {}", sentry_core::fmt::uptime(p.uptime_s))
    });
    format!("Server `{}`: {os}, kernel {kernel}{up}.\n", r.name)
}

const ON_SERVER: &str =
    "\nThe commands run on the server, through sentry-server, after I confirm each one.";

/// Why `A` had nothing to ask about, when it doesn't.
pub fn nothing_here(tab: Tab, v: &View) -> &'static str {
    match tab {
        Tab::Containers if v.s.docker.value.is_none() => "the containers are still loading",
        Tab::Services if v.s.units.value.is_none() => "the services are still loading",
        Tab::Maint => "the maintenance is still loading",
        _ => "nothing selected to ask about here",
    }
}

/// The ranked recommendations, about one of them (`A` on Maintenance, any other row). A move
/// itself is planned with `p`, which researches it; this is a question.
fn ask_maintenance(v: &View, r: &Remote, about: &str) -> Ask {
    let lines: Vec<String> = super::maint::recs(v)
        .iter()
        .map(|x| format!("- [{}] {}: {}", x.level.word(), x.title, x.why))
        .collect();
    Ask::new(
        format!("{} · maintenance", r.name),
        format!(
            "{}What sentry-server recommends maintaining, ranked:\n{}",
            header(v, r),
            if lines.is_empty() {
                "(nothing)".into()
            } else {
                lines.join("\n")
            }
        ),
        format!("About \"{about}\": what should I know, and is it safe to put off?"),
    )
}

/// The packages waiting: is it safe to upgrade now? (`A` on the updates recommendation.)
pub fn ask_updates(v: &View, r: &Remote) -> Option<Ask> {
    let h = header(v, r);
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
                sentry_core::fmt::age(a.now - s)
            )),
            a.running_kernel,
            a.newest_kernel.as_deref().unwrap_or("?")
        ),
        "Is it safe to upgrade and reboot now? Anything to watch out for with these \
         packages on this server (services, containers, the GPU driver)?"
            .to_string(),
    ))
}

/// An audit finding: how to fix it (Enter on its recommendation, or `A`).
pub fn ask_finding(v: &View, r: &Remote, f: &sentry_core::finding::Finding) -> Ask {
    let h = header(v, r);
    Ask::new(
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
    )
}

/// What `A` asks on each tab, from what's selected there.
pub fn ask_for(tab: Tab, v: &View, r: &Remote) -> Option<Ask> {
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
        // A finding: fix it; updates or the reboot: safe now? Anything else: what to do first.
        Tab::Maint => match super::maint::pick(v)? {
            super::maint::Sel::Rec(x) => match &x.action {
                crate::maint::recommend::Action::Fix(id) => {
                    Some(ask_finding(v, r, super::maint::finding(v, id)?))
                }
                _ if x.key.starts_with("wf:apt-maintenance") || x.key == "reboot" => {
                    ask_updates(v, r)
                }
                _ => Some(ask_maintenance(v, r, &x.title)),
            },
            super::maint::Sel::Item(s, _) => Some(ask_maintenance(v, r, &s.id)),
        },
    }
}

/// `A` in the Run view: the workflow's current step, whatever state it's in.
pub fn ask_run(v: &View, r: &Remote, s: &Session) -> Ask {
    ask_step(&header(v, r), r, s)
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

/// `A` → "help me apply it" on a Maintenance row: what Claude is told, and what the chat can
/// do (start the workflow, mark it done). None: the row is only asked about (a finding has its
/// own fix flow; tracking, untracking and the audit are one key each). `steps` describes a
/// workflow (the app has the files).
pub fn apply_ask(v: &View, r: &Remote, steps: &dyn Fn(&str) -> String) -> Option<Ask> {
    use super::maint::{self as m, Sel};
    use crate::maint::recommend::Action;
    use sentry_core::claude::Apply;
    let item = |id: &str, key: String| apply_item(v, r, id, key, steps);
    match m::pick(v)? {
        Sel::Item(s, _) => item(&s.id, s.id.clone()),
        Sel::Rec(x) => match &x.action {
            Action::Plan(id) | Action::OpenPlan(id) => item(id, x.key.clone()),
            Action::Look(id) if !id.is_empty() => item(id, x.key.clone()),
            Action::Run(wf) => {
                let mut ctx = format!(
                    "{}A maintenance recommendation: [{}] {}\nWhy: {}",
                    header(v, r),
                    x.level.word(),
                    x.title,
                    x.why
                );
                if let Some(u) = ask_updates(v, r) {
                    ctx.push_str(&format!("\n\n{}", u.context));
                }
                ctx.push_str(&format!("\n\n{}", steps(wf)));
                Some(Ask::apply(
                    x.title.clone(),
                    ctx,
                    Apply {
                        key: x.key.clone(),
                        workflow: Some(wf.clone()),
                        item: x.item.clone(),
                        ..Default::default()
                    },
                ))
            }
            Action::Task(id) => {
                use sentry_core::maint::tasks::Do;
                let t = m::all_tasks(v).into_iter().find(|t| &t.id == id)?;
                let (wf, it) = match t.action() {
                    Do::Run(wf) => (Some(wf), t.item.clone()),
                    Do::Plan(it) => return item(&it, x.key.clone()),
                    Do::ByHand => (None, t.item.clone()),
                    Do::Audit | Do::Job(_) => return None,
                };
                let mut ctx = format!(
                    "{}A task ({}): {}\nWhy: {}\n{}",
                    header(v, r),
                    t.when(),
                    t.title,
                    t.why,
                    if t.steps.trim().is_empty() {
                        "(no steps written)".to_string()
                    } else {
                        format!("Its steps:\n{}", t.steps.trim())
                    }
                );
                if let Some(wf) = &wf {
                    ctx.push_str(&format!("\n\n{}", steps(wf)));
                }
                Some(Ask::apply(
                    t.title.clone(),
                    ctx,
                    Apply {
                        key: x.key.clone(),
                        workflow: wf,
                        item: it,
                        task: Some(t.id.clone()),
                        ..Default::default()
                    },
                ))
            }
            Action::Fix(_) | Action::Track(_) | Action::Remove(_) | Action::Audit => None,
            Action::Look(_) => None,
        },
    }
}

/// Applying a maintenance item (its plan if it has one ready), with Claude: also `A` in the
/// Plan view.
pub fn apply_item(
    v: &View,
    r: &Remote,
    id: &str,
    key: String,
    steps: &dyn Fn(&str) -> String,
) -> Option<Ask> {
    use super::maint as m;
    use sentry_core::claude::Apply;
    use sentry_core::maint::plan::PlanStatus;
    let (s, it) = (m::status_of(v, id)?, m::item_of(v, id)?);
    let plan = v
        .plans
        .get(id)
        .filter(|p| p.head.status == PlanStatus::Ready);
    let wf = plan
        .map(|p| p.head.workflow.clone())
        .filter(|w| !w.is_empty())
        .or_else(|| m::workflow_of(it).map(str::to_string));
    let mut ctx = format!("{}{}", header(v, r), m::context(v, r, s, it));
    if let Some(wf) = &wf {
        ctx.push_str(&format!("\n\n{}", steps(wf)));
    }
    if let Some(p) = plan {
        ctx.push_str(&format!(
            "\n\nClaude's plan for it, written earlier (target {}):\n{}",
            p.head.to.as_deref().unwrap_or("retire"),
            p.body
        ));
    }
    Some(Ask::apply(
        id,
        ctx,
        Apply {
            key,
            workflow: wf,
            item: Some(id.to_string()),
            plan: plan.map(|_| id.to_string()),
            ..Default::default()
        },
    ))
}
