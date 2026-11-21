//! Claude for a network. It reaches the router only through `sentry-network exec <name>`
//! (reads; chats and reviews) and, in an apply session, `sentry-network run <name>` (the
//! same reads as a shell line; a change becomes a request, config and service changes a
//! guard step, upgrades and reboots a workflow step: `policy`). Everything of the router's
//! that goes into a prompt passes `redact::Scrub` first, here: no prompt is built until
//! what must be hidden is known.

use super::screens::{View, maint};
use crate::policy;
use crate::redact::{Facts, Salt, Scrub};
use crate::remote::Router;
use crate::workflow::Session;
use sentry_core::claude::{Apply, Ask, Profile, Refuses, StepRef};
use sentry_core::tui::ScreenId;
use sentry_core::workflows::runner::{Next, preview};
use sentry_core::workflows::state::StepStatus;

/// What is said while what must be hidden isn't known yet.
pub const NOT_YET: &str = "still reading what must be hidden from Claude (the uplink's \
     address, the SSIDs, the devices' names): try again in a moment";

/// The scrubbing for what this window has read. Err: something it needs isn't read yet.
pub fn scrub(v: &View) -> Result<Scrub, String> {
    let (Some(ifaces), Some(uci), Some(raw)) = (
        v.s.ifaces.value.as_ref(),
        v.s.uci.value.as_ref(),
        v.s.raw_clients.value.as_ref(),
    ) else {
        return Err(NOT_YET.into());
    };
    let salt = Salt::load(&crate::remote::scope(v.name)).map_err(|e| format!("the salt: {e}"))?;
    Ok(Scrub::new(
        v.cfg,
        salt,
        &Facts::of(ifaces, uci, &crate::redact::leases_of(raw)),
    ))
}

/// The same, from the store alone.
pub fn scrub_of(s: &super::data::Store, r: &Router) -> Result<Scrub, String> {
    let (Some(ifaces), Some(uci), Some(raw)) = (
        s.ifaces.value.as_ref(),
        s.uci.value.as_ref(),
        s.raw_clients.value.as_ref(),
    ) else {
        return Err(NOT_YET.into());
    };
    let salt = Salt::load(&r.scope).map_err(|e| format!("the salt: {e}"))?;
    Ok(Scrub::new(
        &r.cfg,
        salt,
        &Facts::of(ifaces, uci, &crate::redact::leases_of(raw)),
    ))
}

/// `Scrub::text`, and one thing more. It reads a MAC as a word of its own, and a finding's
/// id carries one glued to its colons (`net:client:<mac>`), as a log line may (`sta:<mac>`):
/// there the MAC stayed whole. Whatever the scrubbing left of such a word is looked through
/// for MACs, and each is hidden as it would be standing alone.
pub fn scrubbed(s: &Scrub, text: &str) -> String {
    let text = s.text(text);
    let part = |c: char| c.is_ascii_hexdigit() || c == ':' || c == '-';
    let mut out = String::with_capacity(text.len());
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        if word.len() > MAC_LEN {
            out.push_str(&glued_macs(s, word));
        } else {
            out.push_str(word);
        }
        word.clear();
    };
    for c in text.chars() {
        if part(c) {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}

/// `hh:hh:hh:hh:hh:hh`.
const MAC_LEN: usize = 17;

/// A run of hex digits, colons and dashes (ASCII) with each MAC in it scrubbed: six pairs
/// that no further hex digit touches.
fn glued_macs(s: &Scrub, word: &str) -> String {
    let b = word.as_bytes();
    let mut out = String::with_capacity(word.len());
    let mut i = 0;
    while i < b.len() {
        let end = i + MAC_LEN;
        let alone = (i == 0 || !b[i - 1].is_ascii_hexdigit())
            && (end == b.len() || (end < b.len() && !b[end].is_ascii_hexdigit()));
        if end <= b.len() && alone && crate::config::mac(&word[i..end]).is_some() {
            out.push_str(&s.text(&word[i..end]));
            i = end;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

/// Nothing of an `Ask` leaves unscrubbed: its subject and question too (a finding's
/// message names devices).
fn hidden(mut a: Ask, s: &Scrub) -> Ask {
    a.subject = scrubbed(s, &a.subject);
    a.context = scrubbed(s, &a.context);
    a.question = scrubbed(s, &a.question);
    a
}

/// Why a session never runs a line: the router's guarded, workflow-only and never
/// classes, and on this machine anything that names sentry's own files about a network
/// (its config, salt, backups and reports hold what is scrubbed everywhere else).
pub fn refuses(line: &str, remote: bool) -> Option<String> {
    if remote {
        return policy::refuses(line);
    }
    let l = line.to_lowercase();
    ["/sentry/", "network_config", ".ssh", "sentry-guard"]
        .iter()
        .any(|k| l.contains(k))
        .then(|| {
            "sentry's own files about this network (its config, salt, backups, reports) and \
             ssh's are never read or changed through a command"
                .to_string()
        })
}

/// How a session's Claude is told to work on a router (in place of a server's words).
const HOW: &str = "Checks you simply run on the router, through the `run` gateway: any \
    line that only reads. There is no sudo: the login is root, so sentry reads every line \
    before it runs. A line that changes something that can't cut the network off (a package \
    added, a file under /tmp, a service that isn't the network's, `uci set` and `uci commit` \
    on a config that isn't guarded) is refused at first, I am shown that exact line, and once \
    I allow it sentry runs it and tells you what it printed; end your turn there, saying in \
    one line what you asked for and why. Changes to the network, firewall, wireless, dhcp, \
    dropbear or uhttpd config, and reloads of their services, are never commands and never \
    `run` steps: they are ONE step at the end of the plan, `workflow = \"guarded-change\"` \
    with `vars = { configs = \"dhcp,firewall\", lines = \"uci set …; uci add_list …\", \
    services = \"firewall,dnsmasq\" }` (every uci line of the change in `lines`, values in \
    single quotes, no `uci commit`: the guard commits; `alters_wan = \"yes\"` only when the \
    change is meant to alter the uplink). sentry snapshots those configs, arms the router to \
    take the change back by itself, applies, reconnects and keeps it only if the router, its \
    uplink and its firewall still answer as before; a Wi-Fi change is kept only when I say \
    so. Package upgrades are `workflow = \"package-update\"` with `vars = { packages = \
    \"name name\" }` (named packages, never all); firmware is `firmware-upgrade`; a reboot \
    is never yours to ask for. For everything else,";

fn apply(key: String) -> Apply {
    Apply {
        key,
        remote: true,
        refuses: Refuses(Some(refuses)),
        how: Some(HOW),
        asks_each: true,
        ..Default::default()
    }
}

/// What every prompt is told about the router and its rules.
pub fn system(r: &Router) -> String {
    let name = &r.name;
    let alone: Vec<&str> = r
        .cfg
        .devices
        .iter()
        .filter(|d| d.leave_alone)
        .map(|d| d.label())
        .collect();
    let alone = if alone.is_empty() {
        String::new()
    } else {
        format!(
            " The user has marked these devices leave-alone: {}. Never probe, scan, ping, \
             block, rename, re-address or reconfigure anything for them, and never propose a \
             change whose point is one of them.",
            alone.join(", ")
        )
    };
    format!(
        "You are answering inside sentry-network, a monitoring and maintenance TUI on the \
user's laptop, about their home network `{name}`, seen through its router: OpenWrt, reached over \
ssh as root (busybox ash; there is no sudo). Run commands on the router ONLY as \
`sentry-network exec {name} -- <command> <args>`, one command per call, no pipes or shell syntax \
(filter the output yourself). What reads freely: {}. Anything else is refused. Never read a \
config file raw (`/etc/config/*` holds secrets): `uci show <config>` is the way, one config per \
call. What you are shown is scrubbed on the way out of the router: a secret option's value is a \
tag (`redacted:…`, the same value gives the same tag), the uplink's address is ‹wan› or ‹wan6›, \
a device the user named appears as ‹name›, any other MAC keeps only its vendor half, SSIDs are \
‹ssid-N›, unnamed hostnames ‹host-…›. Those placeholders are all you know; never try to get \
round them. The router's busybox lacks nohup, timeout, ss, bridge, jq, curl, wget, base64 and \
openssl; `ps` takes no -o or -e (use `ps w`); `netstat -lntup` cuts program names at 14 \
characters; services are read with `ubus call service list`; the package index is only as new \
as the last `apk update`, so pass `--no-network` to apk reads. Changes aren't made in a \
conversation, so never say you made one: in a chat, say what should change (the user hands it \
to an apply session with `a`); in an apply session, send them as a plan. Changes to the \
network, firewall, wireless, dhcp, dropbear or uhttpd config are written as one guard step \
(the `guarded-change` workflow); upgrades and reboots are workflow steps.{alone} Keep it under \
about 200 words unless asked for more. Files on the laptop (the user's notes): {}",
        crate::gateway::summary(),
        sentry_core::claude::GRANTS
    )
}

/// What no profile may read or write on this machine, whoever grants what: the encrypted
/// backups, the salt behind the tags, ssh's keys, and the files that hold in plain what is
/// scrubbed everywhere else (the network's config, its reports, who was seen and what is
/// expected).
pub fn private(r: &Router) -> Vec<String> {
    let scope = &r.scope;
    let root = sentry_core::maint::root(scope);
    let data = sentry_core::maint::data_root(scope);
    let mut paths = vec![
        (crate::backup::backups_dir(scope), true),
        (crate::audit::reports_dir(scope), true),
        (data.join("guard"), true),
        (crate::redact::path(scope), false),
        (crate::clients::Seen::path(scope), false),
        (root.join("baseline.toml"), false),
        (crate::config::path(), false),
        (sentry_core::paths::home().join(".ssh"), true),
    ];
    // A workflow's file is commands sentry runs on the router as root: Claude may read
    // them, never write them.
    let workflows = [
        root.join("workflows"),
        sentry_core::paths::config_dir().join("network-workflows"),
    ];
    // As Claude Code resolves them, too.
    for (p, d) in paths.clone() {
        let real = std::path::PathBuf::from(sentry_core::maint::real_path(&p));
        if real != p {
            paths.push((real, d));
        }
    }
    let mut out = Vec::new();
    for (p, is_dir) in paths {
        let p = p.display().to_string();
        let abs = p.trim_start_matches('/');
        for tool in ["Read", "Edit", "Write"] {
            out.push(if is_dir {
                format!("{tool}(//{abs}/**)")
            } else {
                format!("{tool}(//{abs})")
            });
        }
    }
    for p in workflows {
        for p in [
            p.clone(),
            std::path::PathBuf::from(sentry_core::maint::real_path(&p)),
        ] {
            let abs = p.display().to_string();
            let abs = abs.trim_start_matches('/');
            for tool in ["Edit", "Write"] {
                let rule = format!("{tool}(//{abs}/**)");
                if !out.contains(&rule) {
                    out.push(rule);
                }
            }
        }
    }
    out
}

/// A chat: the read gateway, and (through `with_notes`/`with_log`) the notes and the log.
pub fn profile(r: &Router) -> Profile {
    let name = &r.name;
    let mut denied = Profile::denied_for_servers();
    denied.extend(private(r));
    Profile {
        system: system(r),
        tools: ["Bash", "Read", "Edit", "Write"].map(String::from).to_vec(),
        allowed: vec![format!("Bash(sentry-network exec {name}:*)")],
        denied,
        dirs: Vec::new(),
    }
    .with_notes(&r.cfg.notes)
    .with_log(&sentry_core::maint::log::dir(&r.scope))
}

/// The web for release notes and advisories (reviews, sessions).
fn with_web(mut p: Profile) -> Profile {
    p.tools.extend(["WebFetch", "WebSearch"].map(String::from));
    p.allowed
        .extend(["WebFetch", "WebSearch"].map(String::from));
    p.denied.retain(|d| d != "WebFetch" && d != "WebSearch");
    p
}

/// A review: the chat's reads and the web, and no edits at all.
pub fn review_profile(r: &Router) -> Profile {
    let mut p = with_web(profile(r).without_edits());
    p.system.push_str(
        " For this question you may also read the web with the WebFetch and WebSearch tools \
         (OpenWrt's release notes and advisories), and the notes files named in it with the \
         Read tool. Cite what you read.",
    );
    p
}

/// An apply session: the chat's, plus the gateway that takes a shell line.
pub fn session_profile(r: &Router) -> Profile {
    let name = &r.name;
    let mut p = with_web(profile(r));
    p.system.push_str(&format!(
        " In this apply session you also have `sentry-network run {name} -- '<shell command \
         line>'` (the whole line in single quotes; several commands with `;` are fine, and \
         a pipe into grep, head, tail, sort, uniq or wc). A \
         line that only reads runs at once, as root, its output scrubbed. A line that would \
         change something is NOT run: it comes back refused, and the refusal says which of \
         three things it is: a request the user is shown and may allow (then sentry runs it \
         and sends you the output), a change that belongs in the plan's guard step, or an \
         upgrade or reboot that belongs in a workflow step. Name files by their full path \
         (no `cd`, no patterns or variables where a file is read). You may read the web for \
         release notes."
    ));
    p.allowed.push(format!("Bash(sentry-network run {name}:*)"));
    p
}

pub fn header(v: &View) -> String {
    let board = v.s.ifaces.value.as_ref().map_or(String::new(), |i| {
        format!(
            ": {} {} on {}",
            i.board.distribution, i.board.version, i.board.model
        )
    });
    let up = v.s.probe.value.as_ref().map_or(String::new(), |p| {
        format!(", up {}", sentry_core::fmt::uptime(p.host.uptime_s))
    });
    format!("Network `{}`, its router{board}{up}.\n", v.name)
}

/// The Maintenance list as text.
fn rows(v: &View) -> String {
    let lines: Vec<String> = maint::recs(v)
        .iter()
        .map(|x| format!("- [{}] {}: {}", x.level.word(), x.title, x.why))
        .collect();
    if lines.is_empty() {
        "(nothing)".into()
    } else {
        lines.join("\n")
    }
}

fn ask_finding(v: &View, f: &sentry_core::finding::Finding) -> Ask {
    Ask::apply(
        format!("{} · {}", v.name, f.message),
        format!(
            "{}Audit finding ({}, {}): {}\nid: {}\nwhat: {}\nwhy: {}\nsuggested: {}\nevidence: {}",
            header(v),
            f.severity.as_str(),
            f.category,
            f.message,
            f.id,
            f.what,
            f.why,
            f.fix,
            f.evidence
        ),
        Apply {
            finding: Some(f.id.clone()),
            // The audit says whether it's gone: run again after the plan.
            reaudits: true,
            ..apply(format!("finding:{}", f.id))
        },
    )
}

/// The workflow in progress: its current step, whatever state it's in.
fn ask_run(v: &View, s: &Session) -> Ask {
    let h = header(v);
    let done: Vec<String> =
        s.wf.steps
            .iter()
            .zip(&s.run.state.steps)
            .filter(|(_, st)| st.status != StepStatus::Pending)
            .map(|(step, st)| format!("{}: {:?}", step.id, st.status))
            .collect();
    let Some(i) = s.next.idx() else {
        return Ask::new(
            format!("{} · {}", v.name, s.wf.name),
            format!(
                "{h}Workflow {} is {}.\nSteps: {}",
                s.wf.name,
                s.state_word(),
                done.join(" · ")
            ),
            "Summarise what this run did on the router and whether anything needs a follow-up.",
        );
    };
    let step = &s.wf.steps[i];
    let log = s.step_log().map(|(_, t)| t).unwrap_or_default();
    let tail: Vec<&str> = log.lines().rev().take(60).collect();
    let tail: Vec<&str> = tail.into_iter().rev().collect();
    let failed = matches!(s.next, Next::Stopped(_) | Next::Manual { failed: true, .. });
    let ctx = format!(
        "{h}Workflow {} step {}/{}: {} ({}) · {}\ncommand: {}\nthe workflow's advice: {}\nsteps so far: {}\nlast lines of its log:\n{}",
        s.wf.name,
        i + 1,
        s.wf.steps.len(),
        s.title(i),
        step.id,
        s.state_word(),
        step.run
            .as_deref()
            .map_or("-".into(), |c| preview(&s.run.state, c)),
        step.manual.as_deref().unwrap_or("none"),
        done.join(" · "),
        if tail.is_empty() {
            "(nothing yet)".into()
        } else {
            tail.join("\n")
        }
    );
    let subject = format!("{} · {} · {}", v.name, s.wf.name, step.id);
    if failed {
        return Ask::apply(
            subject,
            ctx,
            Apply {
                step: Some(StepRef {
                    workflow: s.wf.name.clone(),
                    idx: i,
                    id: step.id.clone(),
                }),
                ..apply(format!("step:{}:{}", s.wf.name, step.id))
            },
        );
    }
    Ask::new(
        subject,
        ctx,
        "This step hasn't run yet. What will it do on this router, is it safe to run now, and \
         what should I check first? Don't run it yourself.",
    )
}

/// What `A` asks on the screen in view. Err: why there's nothing to ask (or it can't be
/// asked yet).
pub fn ask_for(screen: ScreenId, v: &View) -> Result<Ask, String> {
    let s = scrub(v)?;
    let h = header(v);
    let nothing = || "nothing selected to ask about here".to_string();
    let a = match screen {
        ScreenId::Upgrade => ask_run(v, v.wf.ok_or_else(nothing)?),
        ScreenId::Maint => match maint::pick(v) {
            Some(x) => match &x.action {
                maint::Action::Finding(id) => {
                    ask_finding(v, maint::finding(v, id).ok_or_else(nothing)?)
                }
                _ => Ask::new(
                    format!("{} · maintenance", v.name),
                    format!(
                        "{h}What sentry-network recommends maintaining, ranked:\n{}",
                        rows(v)
                    ),
                    format!(
                        "About \"{}\": what should I know, and is it safe to put off?",
                        x.title
                    ),
                ),
            },
            None => Ask::new(
                format!("{} · maintenance", v.name),
                format!(
                    "{h}What sentry-network recommends maintaining, ranked:\n{}",
                    rows(v)
                ),
                "How is this router's upkeep? What should I do first?",
            ),
        },
        ScreenId::Clients => {
            let list: Vec<String> =
                v.s.clients
                    .iter()
                    .flatten()
                    .map(|c| {
                        format!(
                            "- {} · {:?} · {:?} · {}{}",
                            c.label(),
                            c.link,
                            c.state,
                            c.addrs.first().map_or("no address", String::as_str),
                            if c.flagged { " · NEW" } else { "" }
                        )
                    })
                    .collect();
            Ask::new(
                format!("{} · clients", v.name),
                format!("{h}Who is on the network:\n{}", list.join("\n")),
                "Is anything here unexpected? What would you look at first?",
            )
        }
        _ => {
            let findings: Vec<String> = maint::latest(v)
                .map_or(&[][..], |r| &r.findings[..])
                .iter()
                .filter(|f| !f.expected)
                .map(|f| format!("- {} ({})", f.message, f.id))
                .collect();
            Ask::new(
                format!("{} · overview", v.name),
                format!(
                    "{h}The last audit's open findings:\n{}\n\nMaintenance, ranked:\n{}",
                    if findings.is_empty() {
                        "(none)".into()
                    } else {
                        findings.join("\n")
                    },
                    rows(v)
                ),
                "How is this network doing? What needs attention, and what should I do first?",
            )
        }
    };
    Ok(hidden(a, &s))
}

/// Applying a Maintenance row with Claude (None: it isn't something to apply, or it can't
/// be sent yet). `steps` describes a workflow.
pub fn apply_rec(v: &View, x: &maint::Rec, steps: &dyn Fn(&str) -> String) -> Option<Ask> {
    use crate::config::ItemKind;
    use sentry_core::maint::tasks::Do;
    let s = scrub(v).ok()?;
    let h = header(v);
    let with_wf = |wf: &str, title: &str, why: &str, extra: String| {
        Ask::apply(
            title.to_string(),
            format!(
                "{h}A maintenance recommendation: [{}] {title}\nWhy: {why}{extra}\n\n{}",
                x.level.word(),
                steps(wf)
            ),
            Apply {
                workflow: Some(wf.to_string()),
                ..apply(x.key.clone())
            },
        )
    };
    let a = match &x.action {
        maint::Action::Finding(id) => ask_finding(v, maint::finding(v, id)?),
        maint::Action::Run(wf) => with_wf(wf, &x.title, &x.why, String::new()),
        maint::Action::About(ItemKind::Packages) => {
            let list: Vec<String> =
                v.s.updates
                    .value
                    .iter()
                    .flat_map(|u| &u.packages)
                    .map(|p| format!("{} {} → {}", p.name, p.from, p.to))
                    .collect();
            with_wf(
                "package-update",
                &x.title,
                &x.why,
                format!(
                    "\nUpgradable (from the index the router has): {}",
                    list.join("; ")
                ),
            )
        }
        maint::Action::About(ItemKind::Firmware) => {
            with_wf("firmware-upgrade", &x.title, &x.why, String::new())
        }
        maint::Action::About(ItemKind::Backup) => {
            with_wf("config-backup", &x.title, &x.why, String::new())
        }
        maint::Action::Task(id) => {
            let t = maint::all_tasks(v).into_iter().find(|t| &t.id == id)?;
            let wf = match t.action() {
                Do::Run(wf) => Some(wf),
                Do::ByHand => None,
                Do::Audit | Do::Job(_) | Do::Plan(_) => return None,
            };
            let mut ctx = format!(
                "{h}A task ({}): {}\nWhy: {}\n{}",
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
            Ask::apply(
                t.title.clone(),
                ctx,
                Apply {
                    workflow: wf,
                    task: Some(t.id.clone()),
                    ..apply(x.key.clone())
                },
            )
        }
        maint::Action::Audit => return None,
    };
    Some(hidden(a, &s))
}

/// What a review is sent.
pub fn review_request(v: &View, auto: Option<&str>, changes: &str) -> String {
    let Ok(s) = scrub(v) else {
        return String::new();
    };
    let items: Vec<String> = maint::items(v)
        .iter()
        .map(|i| format!("- {}: {}", i.id, i.state))
        .collect();
    let context = format!(
        "{}Maintenance, ranked:\n{}\n\nItems:\n{}\n\nThe maintenance ledger (start here, with the Read tool): {}",
        header(v),
        rows(v),
        items.join("\n"),
        sentry_core::maint::log::dir(&crate::remote::scope(v.name))
            .join("LOG.md")
            .display()
    );
    let context = scrubbed(&s, &context);
    match auto {
        Some(ask) => format!("{ask}\n\n{context}\n\n{changes}"),
        None => format!(
            "{context}\n\nReview the upkeep of this network's router. Sections:\n\
             ## Summary: two or three lines on where things stand.\n\
             ## Now: what to do first, one bullet each, and why it can't wait.\n\
             ## Soon: the same, for the next weeks.\n\
             ## Routine: regular maintenance due, and what can simply wait (say why).\n\
             ## Watch: the release's end of life, upstream changes, anything to look at again.\n\n\
             {changes}"
        ),
    }
}
