//! "Ask Claude": hands the selected thing to the user's local Claude Code (`claude -p`), which
//! uses their existing login, so no API key. Claude may investigate with a fixed allowlist of
//! read-only commands; anything else is refused by Claude Code itself in `-p` mode.

use serde_json::Value;

use crate::exec::Cmd;

/// What a screen wants to ask about the selected thing.
#[derive(Debug, Clone, PartialEq)]
pub struct Ask {
    /// Short label for the pane title ("Audit · Unknown service on tcp/27500").
    pub subject: String,
    /// The facts sentry sends, shown verbatim in the consent modal.
    pub context: String,
    pub question: String,
    /// sentry's own fixes for the thing asked about (matched against Claude's proposals).
    pub known: Vec<crate::audit::fix::Fix>,
    /// What the chat is about, for what happens after a proposed command runs.
    pub target: Option<Target>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    /// An audit finding id: audited again after a command changes something.
    Finding(String),
    /// A failed workflow step: retried from the chat (`t`).
    Step {
        workflow: String,
        idx: usize,
        id: String,
    },
}

/// What sentry knows about a failed workflow step (built by the Upgrade screen).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StepFacts {
    pub workflow: String,
    pub idx: usize,
    pub total: usize,
    pub id: String,
    pub title: String,
    pub prev: Option<String>,
    pub next: Option<String>,
    /// The steps still to come, `id: title · command`: Claude mustn't do them itself.
    pub later: Vec<String>,
    /// Rendered command.
    pub cmd: String,
    pub code: Option<i32>,
    pub vars: Vec<String>,
    pub log_tail: String,
    /// The workflow author's advice for this failure (`manual`).
    pub manual: Option<String>,
    /// The sentry actions possible now: ("retry", "run the step again …"), …
    pub actions: Vec<(&'static str, &'static str)>,
}

impl Ask {
    pub fn new(
        subject: impl Into<String>,
        context: impl Into<String>,
        question: impl Into<String>,
    ) -> Self {
        Self {
            subject: subject.into(),
            context: context.into(),
            question: question.into(),
            known: Vec::new(),
            target: None,
        }
    }

    /// `f` on an audit finding: diagnose, recommend, and propose commands for the user to run.
    pub fn fix(f: &crate::audit::Finding) -> Self {
        use crate::audit::fix::{Act, fixes};
        let known = fixes(f);
        let list: Vec<String> = known
            .iter()
            .enumerate()
            .filter_map(|(i, x)| match &x.act {
                Act::Shell { cmd, .. } => Some(format!(
                    "  {}. {}: {cmd}{}",
                    i + 1,
                    x.label,
                    x.undo
                        .as_ref()
                        .map_or(String::new(), |u| format!("  (undo: {u})"))
                )),
                _ => None,
            })
            .collect();
        let context = format!(
            "A finding from sentry's audit of my machine:\n{} [{}] {}\nsentry's notes:\n  what: {}\n  why: {}\n  to do: {}\nevidence:\n{}\n\nsentry's known fixes for this:\n{}",
            f.severity.as_str(),
            f.category,
            f.message,
            f.what,
            f.why,
            f.fix,
            f.evidence,
            if list.is_empty() {
                "  (none)".to_string()
            } else {
                list.join("\n")
            }
        );
        Self {
            subject: format!("fix · {}", f.message),
            context,
            question: fix_question(""),
            known,
            target: Some(Target::Finding(f.id.clone())),
        }
    }

    /// `f` on a failed workflow step: the same diagnose → recommend → propose shape, plus the
    /// workflow actions Claude may recommend afterwards.
    pub fn step_fix(s: &StepFacts) -> Self {
        let actions: Vec<String> = s
            .actions
            .iter()
            .map(|(k, d)| format!("  {k}: {d}"))
            .collect();
        let context = format!(
            "A step of the sentry upgrade workflow {} failed on my machine.\n\
             step {}/{}: {} ({})\n\
             before it: {}\nafter it: {}\n\
             command: {}\nexit code: {}\nvalues: {}\n\
             the workflow's own advice for this failure:\n{}\n\
             last lines of steps/{}.log:\n{}\n\n\
             steps the workflow still runs after this one:\n{}\n\n\
             What I can do in sentry now:\n{}",
            s.workflow,
            s.idx + 1,
            s.total,
            s.title,
            s.id,
            s.prev.as_deref().unwrap_or("(first step)"),
            s.next.as_deref().unwrap_or("(last step)"),
            s.cmd,
            s.code.map_or("?".into(), |c| c.to_string()),
            if s.vars.is_empty() {
                "(none)".into()
            } else {
                s.vars.join(" ")
            },
            s.manual.as_deref().map_or("  (none)".into(), |m| m
                .lines()
                .map(|l| format!("  {l}"))
                .collect::<Vec<_>>()
                .join("\n")),
            s.id,
            if s.log_tail.trim().is_empty() {
                "(empty)"
            } else {
                &s.log_tail
            },
            if s.later.is_empty() {
                "  (none)".into()
            } else {
                s.later
                    .iter()
                    .map(|l| format!("  {l}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            },
            actions.join("\n"),
        );
        Self {
            subject: format!("fix · {} · {}", s.workflow, s.id),
            context,
            question: fix_question(
                "\nThe Recommendation must end by naming one of the sentry actions listed above \
                 (usually: fix the cause with the commands, then retry). If the system already \
                 is the way this step checks for, say so and recommend done by hand. Never \
                 propose `rpm-ostree upgrade/rebase/rollback/cleanup/install/uninstall/override`, \
                 `ostree admin`, `akmods` or a reboot, and never do a later step yourself: the \
                 workflow runs those, and doing them outside it leaves it out of step with the \
                 system.",
            ),
            known: Vec::new(),
            target: Some(Target::Step {
                workflow: s.workflow.clone(),
                idx: s.idx,
                id: s.id.clone(),
            }),
        }
    }

    pub fn finding(&self) -> Option<&str> {
        match &self.target {
            Some(Target::Finding(id)) => Some(id),
            _ => None,
        }
    }

    pub fn step(&self) -> Option<usize> {
        match &self.target {
            Some(Target::Step { idx, .. }) => Some(*idx),
            _ => None,
        }
    }

    /// The first turn's prompt: context, then the question.
    pub fn prompt(&self) -> String {
        format!("{}\n\nQuestion: {}", self.context.trim_end(), self.question)
    }
}

/// The three-part fix question; `extra` adds target-specific rules.
pub fn fix_question(extra: &str) -> String {
    format!(
        "Help me fix this. Investigate with your read-only commands first. You cannot change \
         anything: I will run whatever you recommend myself, through sentry. Answer in exactly \
         three parts:\n\
         **What's going on**: what the evidence and logs mean on this machine, in plain words.\n\
         **Recommendation**: what to do and why, and why not the alternatives. \"Leave it and \
         mark it expected\" is a fine answer when that's right.\n\
         **Commands**: each command I should run in its own ```bash fenced block, whose first \
         line is a `# why: ...` comment. Use sentry's known fix when one fits. Use sudo only \
         where it's needed. If nothing should be run, say so and give no blocks.{extra}"
    )
}

/// Commands that change deployments or reboot: they can confuse a workflow in progress.
pub fn touches_deployment(cmd: &str) -> bool {
    cmd.split(['\n', ';', '&', '|']).any(|part| {
        let w: Vec<&str> = part.split_whitespace().filter(|w| *w != "sudo").collect();
        match w.as_slice() {
            ["rpm-ostree", "status", ..] | ["rpm-ostree", "db", ..] => false,
            ["rpm-ostree", ..] | ["ostree", "admin", ..] | ["akmods", ..] => true,
            ["systemctl", "reboot", ..] | ["reboot", ..] => true,
            _ => false,
        }
    })
}

/// A command Claude proposed for the user to run (parsed from its answer).
#[derive(Debug, Clone, PartialEq)]
pub struct Proposed {
    pub cmd: String,
    pub why: String,
    /// The undo, when this matches one of sentry's known fixes.
    pub undo: Option<String>,
    pub known: bool,
}

/// Fenced code blocks in an answer → commands, each with the `# why:` line inside the block (or
/// the last sentence before it). Comment lines are dropped from the command itself.
pub fn parse_commands(text: &str, known: &[crate::audit::fix::Fix]) -> Vec<Proposed> {
    let mut out = Vec::new();
    let mut prev_text = String::new();
    let mut lines = text.lines();
    while let Some(l) = lines.next() {
        let t = l.trim_start();
        if !t.starts_with("```") {
            if !t.is_empty() {
                prev_text = t.trim_end_matches(':').to_string();
            }
            continue;
        }
        let mut why = String::new();
        let mut body = Vec::new();
        for b in lines.by_ref() {
            if b.trim_start().starts_with("```") {
                break;
            }
            let bt = b.trim();
            if let Some(w) = bt
                .strip_prefix("# why:")
                .or_else(|| bt.strip_prefix("#why:"))
            {
                why = w.trim().to_string();
            } else if bt.starts_with('#') || bt.is_empty() {
                continue;
            } else {
                body.push(b.trim_end().to_string());
            }
        }
        if body.is_empty() {
            continue;
        }
        let cmd = body.join("\n");
        let matched = known.iter().find(|f| {
            matches!(&f.act, crate::audit::fix::Act::Shell { cmd: k, .. } if k.trim() == cmd.trim())
        });
        out.push(Proposed {
            why: if why.is_empty() {
                prev_text.clone()
            } else {
                why
            },
            undo: matched.and_then(|f| f.undo.clone()),
            known: matched.is_some(),
            cmd,
        });
    }
    out
}

/// Patterns worth a red warning before running (never silently blocked).
pub fn risky(cmd: &str) -> Option<&'static str> {
    let c = cmd.replace(char::is_whitespace, " ");
    if c.contains("rm -rf /") || c.contains("rm -rf ~") || c.contains("rm -fr /") {
        Some("deletes recursively from a top-level path")
    } else if (c.contains("curl") || c.contains("wget"))
        && (c.contains("| sh") || c.contains("| bash"))
    {
        Some("downloads and runs a script")
    } else if c.contains("mkfs") || c.contains("dd if=") || c.contains("wipefs") {
        Some("writes to a disk directly")
    } else if c.contains("rpm-ostree rebase") || c.contains("rpm-ostree reset") {
        Some("replaces or resets the whole system image")
    } else {
        None
    }
}

/// Every line is one of the allowlisted read-only commands (no re-audit needed after it).
pub fn read_only(cmd: &str) -> bool {
    cmd.lines().filter(|l| !l.trim().is_empty()).all(|l| {
        l.split(['|', ';', '&'])
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .all(|part| {
                ALLOWED.iter().any(|a| {
                    a.strip_prefix("Bash(")
                        .and_then(|x| x.strip_suffix(":*)"))
                        .is_some_and(|prefix| part.starts_with(prefix))
                }) || part.starts_with("grep")
                    || part.starts_with("head")
                    || part.starts_with("tail")
            })
    })
}

/// A full interactive Claude Code session continuing `session`, same restrictions: read-only
/// commands pre-allowed, sudo and file edits denied, anything else asks you first.
pub fn interactive_cmd(session: &str) -> Cmd {
    let dir = cwd();
    let _ = std::fs::create_dir_all(&dir);
    Cmd::host("claude")
        .args(["--resume", session, "--strict-mcp-config"])
        .arg("--append-system-prompt")
        .arg(format!(
            "{} The user runs anything that changes the system themselves (including every sudo \
             command); propose such commands, never run them.",
            system_prompt()
        ))
        .arg("--allowedTools")
        .args(ALLOWED.iter().copied())
        .arg("--disallowedTools")
        .args(DENIED.iter().copied())
        .dir(dir)
        .timeout(None)
}

/// Read-only commands and paths Claude may use. Review this list before widening it.
pub const ALLOWED: &[&str] = &[
    "Bash(ss:*)",
    "Bash(ip addr:*)",
    "Bash(ip route:*)",
    "Bash(systemctl status:*)",
    "Bash(systemctl --user status:*)",
    "Bash(systemctl list-units:*)",
    "Bash(systemctl --failed:*)",
    "Bash(systemctl --user --failed:*)",
    "Bash(systemctl --user list-units:*)",
    "Bash(systemctl list-unit-files:*)",
    "Bash(systemctl cat:*)",
    "Bash(systemctl list-sockets:*)",
    "Bash(systemctl list-timers:*)",
    "Bash(systemctl is-enabled:*)",
    "Bash(systemctl is-active:*)",
    "Bash(systemctl show:*)",
    "Bash(firewall-cmd --list-all:*)",
    "Bash(firewall-cmd --get-active-zones:*)",
    "Bash(firewall-cmd --get-default-zone:*)",
    "Bash(journalctl:*)",
    "Bash(rpm -q:*)",
    "Bash(rpm-ostree status:*)",
    "Bash(rpm-ostree db diff:*)",
    "Bash(flatpak info:*)",
    "Bash(flatpak list:*)",
    "Bash(flatpak remotes:*)",
    "Bash(podman ps:*)",
    "Bash(podman inspect:*)",
    "Bash(podman images:*)",
    "Bash(ps:*)",
    "Bash(lsblk:*)",
    "Bash(df:*)",
    "Bash(findmnt:*)",
    "Bash(nvidia-smi:*)",
    "Bash(modinfo:*)",
    "Bash(mokutil --sb-state:*)",
    "Bash(mokutil --list-enrolled:*)",
    "Bash(uname:*)",
    "Bash(cat /proc/:*)",
    "Read(//etc/**)",
    "Read(//proc/**)",
    "Read(//usr/lib/systemd/**)",
    "Read(//usr/share/doc/**)",
    "Grep(//etc/**)",
    "Glob(//etc/**)",
];

const DENIED: &[&str] = &[
    "Write",
    "Edit",
    "NotebookEdit",
    "WebFetch",
    "WebSearch",
    "Bash(sudo:*)",
    "Bash(rm:*)",
];

/// One line for the consent modal.
pub fn allowlist_summary() -> String {
    "Claude may also run read-only commands (ss, ip, systemctl status/list-units/cat/show, \
     firewall-cmd --list-all, journalctl, \
     rpm -q, rpm-ostree status/db diff, flatpak info/list, podman ps/inspect, ps, df, nvidia-smi, \
     modinfo, mokutil, uname) and read files under /etc, /proc, /usr/lib/systemd. Nothing that \
     changes the system is allowed."
        .into()
}

pub fn system_prompt() -> String {
    let os = crate::paths::os_version();
    let kernel = crate::collectors::ostree::booted_kernel();
    format!(
        "You are answering inside sentry, a maintenance TUI for Fedora Silverblue, about the user's \
own machine. Facts: Silverblue {os}, kernel {kernel}; the NVIDIA driver kmod is built by akmods \
and layered as a local rpm-ostree package (Secure Boot, MOK-signed); toolboxes are podman \
containers sharing $HOME. You can only run the read-only commands you're allowed; you cannot \
change anything, so never say you did. Answer in three short parts: what it is, whether it \
matters on this machine, and what to do (exact commands the user can run, clearly marked as \
theirs to run). Keep it under about 200 words unless asked for more. If you could not verify \
something because a command was denied or needs root, say so and give the command for the user."
    )
}

pub fn cwd() -> std::path::PathBuf {
    crate::paths::cache_dir().join("claude")
}

pub fn available() -> bool {
    #[cfg(test)]
    return TEST_AVAILABLE.with(std::cell::Cell::get);
    #[cfg(not(test))]
    Cmd::host("claude").available()
}

#[cfg(test)]
thread_local! {
    /// Render tests don't depend on whether this machine has Claude Code.
    pub static TEST_AVAILABLE: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// What a chat may do: its system prompt, tools and permissions. The local machine's is
/// [`Profile::local`]; sentry-server builds one per server.
pub struct Profile {
    pub system: String,
    pub tools: Vec<String>,
    pub allowed: Vec<String>,
    pub denied: Vec<String>,
    /// Directories Claude may work in besides its own (`--add-dir`).
    pub dirs: Vec<String>,
}

impl Profile {
    pub fn local() -> Self {
        Self {
            system: system_prompt(),
            tools: ["Bash", "Read", "Grep", "Glob"].map(String::from).to_vec(),
            allowed: ALLOWED.iter().map(|s| s.to_string()).collect(),
            denied: DENIED.iter().map(|s| s.to_string()).collect(),
            dirs: Vec::new(),
        }
    }

    /// The local denials plus every way around a server gateway.
    pub fn denied_for_servers() -> Vec<String> {
        DENIED
            .iter()
            .map(|s| s.to_string())
            .chain(
                [
                    "Bash(ssh:*)",
                    "Bash(scp:*)",
                    "Bash(sftp:*)",
                    "Bash(rsync:*)",
                ]
                .map(String::from),
            )
            .collect()
    }
}

/// One turn: the first (`resume = None`) or a follow-up in the same session.
pub fn turn_cmd(prompt: &str, resume: Option<&str>) -> Cmd {
    turn_cmd_with(prompt, resume, &Profile::local())
}

pub fn turn_cmd_with(prompt: &str, resume: Option<&str>, p: &Profile) -> Cmd {
    let mut c = Cmd::host("claude")
        .args(["-p", prompt])
        .args([
            "--output-format",
            "stream-json",
            "--verbose",
            "--include-partial-messages",
            "--strict-mcp-config",
        ])
        .arg("--append-system-prompt")
        .arg(&p.system)
        .arg("--tools")
        .args(&p.tools)
        .arg("--allowedTools")
        .args(&p.allowed)
        .arg("--disallowedTools")
        .args(&p.denied);
    for d in &p.dirs {
        c = c.args(["--add-dir", d]);
    }
    if let Some(id) = resume {
        c = c.args(["--resume", id]);
    }
    let dir = cwd();
    let _ = std::fs::create_dir_all(&dir);
    c.dir(dir).timeout(None)
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Init {
        session_id: String,
    },
    Text(String),
    ToolUse {
        name: String,
        input: String,
    },
    ToolResult {
        summary: String,
        is_error: bool,
    },
    Done {
        is_error: bool,
        result: String,
        cost: Option<f64>,
    },
}

/// Parse one stream-json line into the events sentry shows. Unknown lines yield nothing.
/// Assistant text arrives twice (as deltas, then the whole block); only the deltas are used.
pub fn parse_line(line: &str) -> Vec<Event> {
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return Vec::new();
    };
    let s = |x: &Value| x.as_str().unwrap_or("").to_string();
    match v["type"].as_str() {
        Some("system") if v["subtype"] == "init" => vec![Event::Init {
            session_id: s(&v["session_id"]),
        }],
        Some("stream_event") => {
            let d = &v["event"]["delta"];
            if v["event"]["type"] == "content_block_delta" && d["type"] == "text_delta" {
                vec![Event::Text(s(&d["text"]))]
            } else {
                Vec::new()
            }
        }
        Some("assistant") => v["message"]["content"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["type"] == "tool_use")
            .map(|c| {
                let input = &c["input"];
                let shown = input["command"]
                    .as_str()
                    .or_else(|| input["file_path"].as_str())
                    .or_else(|| input["pattern"].as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| input.to_string());
                Event::ToolUse {
                    name: s(&c["name"]),
                    input: shown,
                }
            })
            .collect(),
        Some("user") => v["message"]["content"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["type"] == "tool_result")
            .map(|c| {
                let text = match &c["content"] {
                    Value::String(t) => t.clone(),
                    Value::Array(parts) => parts
                        .iter()
                        .filter_map(|p| p["text"].as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                    _ => String::new(),
                };
                let is_error = c["is_error"].as_bool().unwrap_or(false);
                let n = text.lines().count();
                let summary = if is_error {
                    format!("denied: {}", text.lines().next().unwrap_or(""))
                } else {
                    match n {
                        0 => "(no output)".into(),
                        1 => text.trim().to_string(),
                        _ => format!("{} lines", n),
                    }
                };
                Event::ToolResult { summary, is_error }
            })
            .collect(),
        Some("result") => {
            let result = s(&v["result"]);
            let is_error = v["is_error"].as_bool().unwrap_or(false);
            let login = is_error
                && (result.contains("login")
                    || result.contains("API key")
                    || result.contains("authenticat"));
            vec![Event::Done {
                is_error,
                result: if login {
                    "Claude Code isn't logged in: run `claude` once in a terminal, then try again."
                        .into()
                } else {
                    result
                },
                cost: v["total_cost_usd"].as_f64(),
            }]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stream_fixture() {
        let evs: Vec<Event> = crate::collectors::fixture("claude/stream.jsonl")
            .lines()
            .flat_map(parse_line)
            .collect();
        assert_eq!(
            evs,
            vec![
                Event::Init {
                    session_id: "11111111-2222-3333-4444-555555555555".into()
                },
                Event::ToolUse {
                    name: "Bash".into(),
                    input: "ss -tlnp 'sport = :27500'".into()
                },
                Event::ToolResult {
                    summary: "2 lines".into(),
                    is_error: false
                },
                Event::ToolUse {
                    name: "Bash".into(),
                    input: "sudo ss -tlnp".into()
                },
                Event::ToolResult {
                    summary: "denied: Claude requested permissions to use Bash, but you haven't granted it yet.".into(),
                    is_error: true
                },
                Event::Text("Port 27500 is ".into()),
                Event::Text("owned by root.".into()),
                Event::Done {
                    is_error: false,
                    result: "Port 27500 is owned by root.".into(),
                    cost: Some(0.0312)
                },
            ]
        );
    }

    #[test]
    fn proposed_commands() {
        let known = crate::audit::fix::fixes(&crate::audit::Finding {
            id: "unit-failed:system:systemd-remount-fs.service".into(),
            ..Default::default()
        });
        let answer = "**Commands**\nClear it:\n```bash\n# why: the root is a read-only composefs overlay, remount can't succeed\nsudo systemctl reset-failed systemd-remount-fs.service\n```\nThen check:\n```\nsystemctl status systemd-remount-fs.service\n```\n";
        let p = parse_commands(answer, &known);
        assert_eq!(p.len(), 2);
        assert_eq!(
            p[0].cmd,
            "sudo systemctl reset-failed systemd-remount-fs.service"
        );
        assert!(p[0].why.starts_with("the root is a read-only"));
        assert!(p[0].known && p[0].undo.is_some());
        assert_eq!(
            p[1].why, "Then check",
            "falls back to the sentence before the block"
        );
        assert!(!p[1].known);
        assert!(parse_commands("no blocks here", &known).is_empty());
        assert!(read_only(
            "systemctl status x; journalctl -b -u x | tail -5"
        ));
        assert!(!read_only("sudo systemctl reset-failed x"));
        assert_eq!(
            risky("curl -s https://x | sh"),
            Some("downloads and runs a script")
        );
        assert_eq!(risky("sudo systemctl mask --now passim"), None);
        let a = Ask::fix(&crate::audit::Finding {
            id: "listener:svc:passim (fwupd firmware cache)".into(),
            message: "passim · open to all networks".into(),
            ..Default::default()
        });
        assert!(
            a.context.contains("1. Stop passim sharing firmware")
                && a.context.contains("(undo: sudo systemctl unmask")
        );
        assert!(a.finding().is_some() && a.prompt().contains("# why:"));
    }

    #[test]
    fn step_fix_prompt() {
        let facts = StepFacts {
            workflow: "quick-update".into(),
            idx: 2,
            total: 17,
            id: "layer-kmod".into(),
            title: "Layer the new kmod".into(),
            cmd: "rpm-ostree install akmod-nvidia".into(),
            code: Some(1),
            log_tail: "error: Packages not found".into(),
            manual: Some("Check `rpm-ostree status`.".into()),
            actions: vec![("retry", "run the step again"), ("abandon", "stop it")],
            ..Default::default()
        };
        let a = Ask::step_fix(&facts);
        let p = a.prompt();
        assert!(p.contains("step 3/17: Layer the new kmod (layer-kmod)"));
        assert!(
            p.contains("error: Packages not found") && p.contains("  Check `rpm-ostree status`.")
        );
        assert!(p.contains("  retry: run the step again") && !p.contains("  done by hand:"));
        assert!(p.contains("still runs after this one:\n  (none)"));
        assert!(p.contains("**Commands**") && p.contains("Never propose"));
        assert_eq!(a.step(), Some(2));
        assert!(a.finding().is_none());
        assert!(touches_deployment("sudo rpm-ostree upgrade"));
        assert!(touches_deployment("echo x; systemctl reboot"));
        assert!(!touches_deployment("rpm-ostree status -v"));
        assert!(!touches_deployment("touch /tmp/flag"));
    }

    #[test]
    fn login_errors_are_explained() {
        let e = parse_line(
            r#"{"type":"result","is_error":true,"result":"Invalid API key · Please run /login"}"#,
        );
        assert!(
            matches!(&e[0], Event::Done { is_error: true, result, .. } if result.contains("run `claude` once"))
        );
    }

    #[test]
    fn command_is_read_only_and_resumable() {
        let c = turn_cmd("hi", Some("abc")).display();
        assert!(
            c.starts_with("claude -p hi --output-format stream-json"),
            "{c}"
        );
        assert!(c.contains("--allowedTools") && c.contains("'Bash(journalctl:*)'"));
        assert!(c.contains("--disallowedTools Write Edit"));
        assert!(c.contains("'Bash(sudo:*)'"));
        assert!(c.ends_with("--resume abc"), "{c}");
        assert!(
            !ALLOWED
                .iter()
                .any(|a| a.contains("rm") || a.contains("sudo") || a.contains("install"))
        );
    }
}
