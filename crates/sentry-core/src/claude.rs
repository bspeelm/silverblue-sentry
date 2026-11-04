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
    /// What the chat is about, for what happens after a proposed command runs.
    pub target: Option<Target>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    /// Applying something with Claude: a Maintenance row, a plan, a finding, a failed step.
    Apply(Apply),
}

/// A failed workflow step being fixed: the session ends by retrying it.
#[derive(Debug, Clone, PartialEq)]
pub struct StepRef {
    pub workflow: String,
    pub idx: usize,
    pub id: String,
}

/// What's being applied: what the chat's own keys do around the commands you run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Apply {
    /// The Maintenance row's key (the log tags what you run `apply:<key>`).
    pub key: String,
    /// The workflow that makes the change: `w` in the chat starts it.
    pub workflow: Option<String>,
    /// The sentry-server item it's about.
    pub item: Option<String>,
    /// A task: `d` in the chat marks it done.
    pub task: Option<String>,
    /// There's a plan for it (by item, or by workflow on this machine).
    pub plan: Option<String>,
    /// It's on a server (sentry-server): its files change through `run` steps there; only
    /// files on this machine (the notes) are `edit` steps.
    pub remote: bool,
    /// An audit finding (its id): audited again after the plan, before Claude verifies.
    pub finding: Option<String>,
    /// A failed workflow step: once it's fixed, the step is retried.
    pub step: Option<StepRef>,
}

impl Apply {
    /// `d` marks it done: a task, or a plan with no workflow (done by hand).
    pub fn can_mark_done(&self) -> bool {
        self.task.is_some() || (self.plan.is_some() && self.workflow.is_none())
    }
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
            target: None,
        }
    }

    /// Fixing an audit finding (`list`: sentry's own fixes for it, one line each, for Claude).
    pub fn for_finding(f: &crate::finding::Finding, list: &[String]) -> Self {
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
        Self::apply(
            f.message.clone(),
            context,
            Apply {
                key: format!("finding:{}", f.id),
                finding: Some(f.id.clone()),
                ..Default::default()
            },
        )
    }

    /// `f` on a failed workflow step: fix what made it fail; the session then retries it.
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
        Self::apply(
            format!("{} · {}", s.workflow, s.id),
            context,
            Apply {
                key: format!("step:{}:{}", s.workflow, s.id),
                step: Some(StepRef {
                    workflow: s.workflow.clone(),
                    idx: s.idx,
                    id: s.id.clone(),
                }),
                ..Default::default()
            },
        )
    }

    /// Help applying a recommendation or a plan (`context`: what sentry knows about it).
    pub fn apply(subject: impl Into<String>, context: impl Into<String>, a: Apply) -> Self {
        Self {
            subject: format!("apply · {}", subject.into()),
            context: context.into(),
            question: apply_question(&a),
            target: Some(Target::Apply(a)),
        }
    }

    /// What's being applied, when that's what the chat is about.
    pub fn applying(&self) -> Option<&Apply> {
        match &self.target {
            Some(Target::Apply(a)) => Some(a),
            None => None,
        }
    }

    pub fn finding(&self) -> Option<&str> {
        self.applying().and_then(|a| a.finding.as_deref())
    }

    pub fn step(&self) -> Option<usize> {
        self.applying().and_then(|a| a.step.as_ref().map(|s| s.idx))
    }

    /// The first turn's prompt: context, then the question.
    pub fn prompt(&self) -> String {
        format!("{}\n\nQuestion: {}", self.context.trim_end(), self.question)
    }
}

/// Help me apply it: Claude investigates, then answers with one plan for sentry to carry out.
pub fn apply_question(a: &Apply) -> String {
    let files = files_rule(a);
    let planned = if a.plan.is_some() {
        " The brief has the plan written earlier for this, with its research: carry it out. \
         Its Before checks become `check` steps, its Change the workflow step with the plan's \
         values (or, when no workflow applies it, `run` and `edit` steps), its Verify `check` \
         steps. Check first that it still fits (versions, what's running), and say if it doesn't."
    } else {
        ""
    };
    let what = match (&a.finding, &a.step) {
        (Some(_), _) => {
            " If the finding is fine as it is, say so and send no plan: I'll mark it \
             expected. Use sentry's known fix when it fits. After the plan, sentry audits again \
             and tells you whether the finding is gone."
        }
        (_, Some(_)) => {
            " Fix what made the step fail, so it can run again: sentry retries the \
             step when your fix is done. Leave the workflow's later steps to it (they have their \
             own confirms and log). If the system already is the way the step checks for, say \
             so and send no plan."
        }
        _ => "",
    };
    let wf = match &a.workflow {
        Some(wf) => format!(
            " sentry's workflow `{wf}` makes this change, with its own confirm steps and log: put \
             it in the plan as a `workflow = \"{wf}\"` step (its values as \
             `vars = {{ name = \"value\" }}`) and never its commands (upgrades, rebases, pin or \
             image edits, `compose up`, reboots)."
        ),
        None => String::new(),
    };
    let how = if a.remote {
        "Changes on the server go in a plan, so for any change"
    } else {
        "One command, a check or a change, you simply call (sudo where needed): sentry shows me \
         the exact call when it's refused, and once I allow it sentry carries it out and tells \
         you what happened; end your turn there, saying in one line what you asked for and why. \
         For a change of several dependent steps, or one that needs a way back,"
    };
    format!(
        "Do this for me. If nothing needs changing, say so and send no plan. Run every check \
         yourself first (read files with the Read tool); never ask me to run or paste anything. \
         {how} answer with a short \
         assessment (what you found, anything in the task that no longer fits) and ONE plan, \
         as a single ```sentry-apply fenced TOML block, and no other code blocks:\n\
         ```sentry-apply\n\
         summary = \"what the plan does, in one line\"\n\
         rollback = \"how to undo it, in words\"\n\n\
         [[step]]\n\
         title = \"what this step does\"\n\
         edit = \"/absolute/path/of/the/file\"\n\
         old = \"\"\"exact text in the file as it is now, unique in it\"\"\"\n\
         new = \"\"\"its replacement\"\"\"\n\n\
         [[step]]\n\
         title = \"check it worked\"\n\
         check = \"a command that exits 0 when it did\"\n\
         ```\n\
         Each step has exactly one of: `edit` (with `old` and `new`), `run` (a command that \
         changes something; sudo where needed), `check` (a command that must exit 0, or the \
         plan stops) or `workflow` (one of sentry's workflows, with `vars` for its values). \
         {files} Order the steps as they must happen and end with \
         the checks that show it worked. sentry shows me the plan; once I approve it, sentry \
         backs up every file it edits, asks me for my sudo password if a step needs it, and \
         runs the steps in order. So don't back anything up yourself. If a step fails, sentry sends you what happened and you send a plan for \
         the rest. When the plan has run, sentry sends you the results to verify.{wf}{planned}{what}"
    )
}

/// Where a plan's file changes go: `edit` steps on this machine, `run` steps on a server.
fn files_rule(a: &Apply) -> &'static str {
    if a.remote {
        "The commands run on the server. Change the server's files with `run` steps there \
         (sudo where needed); `edit` steps are only for my files on this machine (the notes)."
    } else {
        "Change files with `edit` steps, never with sed or tee: my own files anywhere, and \
         root's configuration under /etc (sentry writes those with my sudo)."
    }
}

/// sentry couldn't use the plan (`why`: each step and what's wrong, or the block didn't
/// parse), or a step failed (`why`: the run's report): a corrected plan, please.
pub fn apply_fix(why: &str) -> String {
    format!(
        "{why}\n\nSend the plan again, corrected, as one ```sentry-apply block (all the steps \
         still to do, the ones that were fine included), with a line on what you changed. \
         Investigate first if you need to."
    )
}

/// Commands the user allowed ran (`report`: each one's result): carry on, or say it's done.
pub fn apply_ran(report: &str) -> String {
    format!(
        "I allowed it, and sentry ran it for you:\n{report}\n\nCarry on where you stopped. If \
         the job needs more, call the next command or send a plan. {}",
        verify_tail("If that finished it, verify the result and")
    )
}

/// The plan ran: verify it (`report`: every step's result).
pub fn apply_verify(report: &str) -> String {
    format!(
        "{report}\n\n{}",
        verify_tail("Verify the result with your read-only commands. Then")
    )
}

/// `lead`, then how to end with a verdict.
fn verify_tail(lead: &str) -> String {
    format!(
        "{lead} answer in a few \
         lines and end with one ```sentry-verdict fenced TOML block, and no other code blocks:\n\
         ```sentry-verdict\n\
         status = \"done\"     # done: it worked · more: something's left · failed: it didn't\n\
         summary = \"what changed, in one line\"\n\
         next = \"what I should do later, if anything (e.g. reboot to confirm), in words\"\n\
         ```\n\
         With `more`, also send one ```sentry-apply block for what's left. Never give me \
         commands to run: you call them, and `next` is words. When something can only be \
         confirmed later (after the next update, a reboot, a few days), add to the verdict \
         block a check for later, which sentry puts on my Maintenance list when it's due:\n\
         ```\n\
         [follow_up]\n\
         title = \"what to confirm, in a few words\"\n\
         steps = \"how to confirm it, read-only\"\n\
         after = \"quick-update\"   # a sentry workflow whose next good run makes it due, or a wait like \"7d\"\n\
         ```"
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
            "{} sudo commands can't run here: the user runs those in sentry, as a plan.",
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
    "Bash(rpm -qa:*)",
    "Bash(rpm -qf:*)",
    "Bash(rpm -qi:*)",
    "Bash(rpm -ql:*)",
    "Bash(rpm -V:*)",
    "Bash(rpm-ostree status:*)",
    "Bash(rpm-ostree db diff:*)",
    // Refreshes the update metadata and deploys nothing (sentry's own `c` runs --preview).
    "Bash(rpm-ostree upgrade --check:*)",
    "Bash(rpm-ostree upgrade --preview:*)",
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
    // Desktop settings, read only (dconf: `get` and the listings, never `set`/`reset`).
    "Bash(gsettings get:*)",
    "Bash(gsettings list-keys:*)",
    "Bash(gsettings list-recursively:*)",
    "Bash(gsettings range:*)",
    "Bash(gsettings describe:*)",
    "Bash(cat /proc/:*)",
    "Read(//etc/**)",
    "Read(//proc/**)",
    // /usr is the read-only OS image: nothing private, and where the distro's repos live.
    "Read(//usr/**)",
    "Grep(//etc/**)",
    "Glob(//etc/**)",
    "Grep(//proc/**)",
    "Glob(//proc/**)",
    "Grep(//usr/**)",
    "Glob(//usr/**)",
];

const DENIED: &[&str] = &[
    "Write",
    "Edit",
    "NotebookEdit",
    "WebFetch",
    "WebSearch",
    // Claude Code can't type a password: refused, so it comes to the user and sentry runs it.
    "Bash(sudo:*)",
];

/// One line for the consent modal.
pub fn allowlist_summary() -> String {
    "Claude may run read-only commands (ss, ip, systemctl status/list-units/cat/show, \
     firewall-cmd --list-all, journalctl, \
     rpm -q/-V, rpm-ostree status/db diff/upgrade --check, flatpak info/list, podman ps/inspect, \
     ps, df, nvidia-smi, modinfo, mokutil, uname, gsettings get/list) and read files under /etc, \
     /proc, /usr. Anything else, and every change, asks you first."
        .into()
}

/// How Claude gets what it isn't allowed yet (every chat's system prompt).
pub const GRANTS: &str = "Do the work yourself: never ask the user to run, paste or type a command \
or its output. If you need a file, or a command, that you aren't allowed yet, call Read, Edit or \
Bash on it anyway: sentry shows the user the exact call and tells you once they allow it.";

pub fn system_prompt() -> String {
    let os = crate::paths::os_version();
    let kernel = crate::paths::kernel();
    format!(
        "You are answering inside sentry, a maintenance TUI for Fedora Silverblue, about the user's \
own machine, and you do its maintenance for them. Facts: Silverblue {os}, kernel {kernel}; the NVIDIA driver kmod is built by akmods \
and layered as a local rpm-ostree package (Secure Boot, MOK-signed); toolboxes are podman \
containers sharing $HOME. Answer in three short parts: what it is, whether it \
matters on this machine, and what you'd do about it. Upgrades, rebases and reboots go through \
sentry's workflows, which have their own confirms and log. Never say you did something you didn't. \
Keep it under about 200 words unless asked for more. In a chat you explain; when the user wants \
something changed, they press `a` and you do it in an apply session. {GRANTS}"
    )
}

pub fn cwd() -> std::path::PathBuf {
    crate::paths::cache_dir().join("claude")
}

pub fn available() -> bool {
    #[cfg(any(test, feature = "testing"))]
    return TEST_AVAILABLE.with(std::cell::Cell::get);
    #[cfg(not(any(test, feature = "testing")))]
    Cmd::host("claude").available()
}

#[cfg(any(test, feature = "testing"))]
thread_local! {
    /// Render tests don't depend on whether this machine has Claude Code.
    pub static TEST_AVAILABLE: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// What a grant lets Claude do with one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    /// Run one exact command (not on the read-only allowlist).
    Run,
}

/// One file Claude may use for the rest of a conversation, because the user said so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub access: Access,
    /// The real path (symlinks resolved), as Claude Code checks it.
    /// For `Run`: the exact command.
    pub path: String,
}

impl Grant {
    pub fn word(&self) -> &'static str {
        match self.access {
            Access::Read => "read",
            Access::Write => "edit",
            Access::Run => "run",
        }
    }

    /// It changes something: a write, or a command not known to only read. Only a label and
    /// a route (sentry runs these itself, and logs them); the user allows them all the same.
    pub fn changes(&self) -> bool {
        match self.access {
            Access::Read => false,
            Access::Write => true,
            Access::Run => !only_reads(&self.path),
        }
    }
}

/// Every command in `cmd` only reads. Unknown means no: a false "no" costs a log line, a
/// false "yes" would hide a change.
pub fn only_reads(cmd: &str) -> bool {
    let mut cleaned = cmd.to_string();
    for safe in [
        "2>&1",
        ">&2",
        "2>/dev/null",
        "2> /dev/null",
        ">/dev/null",
        "> /dev/null",
    ] {
        cleaned = cleaned.replace(safe, " ");
    }
    let mut parts = vec![String::new()];
    let mut quote = None;
    for c in cleaned.chars() {
        match (quote, c) {
            (Some(q), _) if q == c => quote = None,
            // Substitutions run a command of their own, and `>` writes a file.
            (None | Some('"'), '$' | '`') | (None, '>' | '\n') => return false,
            (None, '\'' | '"') => quote = Some(c),
            (None, '|' | ';' | '&') => {
                parts.push(String::new());
                continue;
            }
            _ => {}
        }
        if let Some(last) = parts.last_mut() {
            last.push(c);
        }
    }
    parts
        .iter()
        .filter(|p| !p.trim().is_empty())
        .all(|p| reads(p))
}

/// One simple command only reads.
fn reads(cmd: &str) -> bool {
    let w: Vec<&str> = cmd.split_whitespace().collect();
    let has = |flags: &[&str]| w.iter().any(|x| flags.contains(x));
    // The first word after the program that isn't a flag: its subcommand.
    let sub = w.iter().skip(1).find(|x| !x.starts_with('-')).copied();
    let Some(prog) = w.first().copied() else {
        return true;
    };
    match prog {
        "cat" | "ls" | "grep" | "egrep" | "fgrep" | "head" | "tail" | "wc" | "stat" | "file"
        | "which" | "id" | "whoami" | "hostname" | "date" | "uname" | "echo" | "printf"
        | "sort" | "uniq" | "cut" | "tr" | "du" | "df" | "free" | "lsblk" | "lspci" | "lsusb"
        | "lsmod" | "lsof" | "findmnt" | "ss" | "ps" | "pgrep" | "uptime" | "readlink"
        | "realpath" | "basename" | "dirname" | "test" | "true" | "false" | "diff" | "cmp"
        | "printenv" | "modinfo" | "nvidia-smi" | "getenforce" | "sestatus" | "getent" => true,
        "sed" => !w
            .iter()
            .any(|x| x.starts_with("-i") || x.starts_with("--in-place")),
        "find" => !w.iter().any(|x| {
            x.starts_with("-exec")
                || x.starts_with("-ok")
                || x.starts_with("-fprint")
                || *x == "-delete"
        }),
        "journalctl" => !w.iter().any(|x| {
            x.starts_with("--vacuum") || x.starts_with("--rotate") || x.starts_with("--flush")
        }),
        "rpm" => w.get(1).is_some_and(|f| {
            f.starts_with("-q") || f.starts_with("-V") || *f == "--query" || *f == "--verify"
        }),
        "rpm-ostree" => match sub {
            None | Some("status" | "db") => true,
            Some("kargs") => w.len() == 2,
            Some("upgrade" | "update") => has(&["--check", "--preview"]),
            _ => false,
        },
        "ostree" => match (sub, w.get(2).copied()) {
            (Some("admin"), Some("status")) => true,
            (Some("log" | "show" | "ls" | "rev-parse"), _) => true,
            (Some("refs"), _) => !has(&["--delete"]),
            _ => false,
        },
        "flatpak" => matches!(
            sub,
            Some("info" | "list" | "remotes" | "remote-ls" | "remote-info" | "history" | "search")
        ),
        "systemctl" => match sub {
            None => true,
            Some(s) => {
                s.starts_with("list-")
                    || s.starts_with("is-")
                    || matches!(s, "status" | "show" | "cat" | "get-default")
            }
        },
        "podman" => match sub {
            Some("volume" | "network" | "system") => {
                w.iter().any(|x| matches!(*x, "ls" | "df" | "inspect"))
            }
            Some(s) => matches!(s, "ps" | "inspect" | "images" | "logs" | "version" | "info"),
            None => false,
        },
        "toolbox" => sub == Some("list"),
        "ip" => !w.iter().any(|x| {
            matches!(
                *x,
                "add" | "del" | "delete" | "change" | "replace" | "set" | "flush"
            )
        }),
        "firewall-cmd" => w[1..].iter().all(|x| {
            x.starts_with("--list")
                || x.starts_with("--get")
                || x.starts_with("--query")
                || *x == "--state"
                || x.starts_with("--zone")
        }),
        "mokutil" => w[1..].iter().all(|x| {
            matches!(
                *x,
                "--sb-state" | "--list-enrolled" | "--list-new" | "--list-delete"
            )
        }),
        "gsettings" => sub.is_some_and(|s| {
            s == "get" || s == "range" || s == "describe" || s.starts_with("list-")
        }),
        "dnf" => matches!(
            sub,
            Some("list" | "info" | "search" | "repoquery" | "check-update")
        ),
        _ => false,
    }
}

/// A refused tool call → what it asked for: the tool and its input (Read, Edit, Write,
/// MultiEdit, NotebookEdit carry a file path), else the path in the refusal itself.
pub fn requested(name: &str, input: &str, refusal: &str) -> Option<Grant> {
    // A command: the part Claude Code wants approved, else the whole command.
    if name == "Bash" && !refusal.contains("permissions to read") && !refusal.contains("to write") {
        let cmd = refusal
            .split_once("requires approval: ")
            .map_or(input, |(_, part)| part)
            .trim();
        return (!cmd.is_empty()).then(|| Grant {
            access: Access::Run,
            path: cmd.to_string(),
        });
    }
    let access = match name {
        "Read" => Some(Access::Read),
        "Edit" | "Write" | "MultiEdit" | "NotebookEdit" => Some(Access::Write),
        _ => None,
    };
    let from_text = || {
        [
            ("to read from ", Access::Read),
            ("to write to ", Access::Write),
            ("to edit ", Access::Write),
        ]
        .into_iter()
        .find_map(|(k, a)| {
            let rest = &refusal[refusal.find(k)? + k.len()..];
            let path = rest.split([',', ' ']).next()?.trim_end_matches('.');
            path.starts_with('/').then(|| (a, path.to_string()))
        })
    };
    let (access, path) = match access {
        Some(a) if input.starts_with('/') || input.starts_with("~/") => (a, input.to_string()),
        _ => from_text()?,
    };
    let path = match path.strip_prefix("~/") {
        Some(rest) => crate::paths::home().join(rest),
        None => std::path::PathBuf::from(&path),
    };
    Some(Grant {
        access,
        path: crate::maint::real_path(&path),
    })
}

/// A tool result says Claude Code turned the call down (not that it ran and failed).
pub fn refused(summary: &str) -> bool {
    [
        "requested permissions",
        "requires approval",
        "has been denied",
        "isn't allowed",
    ]
    .iter()
    .any(|k| summary.contains(k))
}

/// Never granted, read or write: where keys and passwords live.
const NEVER: &[&str] = &[".ssh", ".gnupg", ".local/share/keyrings", ".password-store"];

/// Whether the user may allow it, and why not: everything can be asked for, except what
/// would send keys and passwords to Anthropic, and root's files (those are `edit` plan steps).
pub fn grantable(g: &Grant) -> Result<(), &'static str> {
    if g.access == Access::Run {
        return if NEVER.iter().any(|n| g.path.contains(n)) {
            Err("keys and passwords live there")
        } else {
            Ok(())
        };
    }
    let p = std::path::Path::new(&g.path);
    let home = crate::paths::home();
    if NEVER.iter().any(|n| p.starts_with(home.join(n))) {
        return Err("keys and passwords live there");
    }
    match g.access {
        Access::Run => Ok(()),
        Access::Read if !p.exists() => Err("it doesn't exist"),
        Access::Read => Ok(()),
        Access::Write if p.exists() && !p.is_file() => Err("not a file"),
        Access::Write if !p.parent().is_some_and(|d| d.is_dir()) => Err("its folder doesn't exist"),
        Access::Write if !yours(p, &home) => {
            Err("it's root's: Claude sends it as a plan's edit step")
        }
        Access::Write => Ok(()),
    }
}

/// The file (or, for a new one, its folder) belongs to whoever owns the home folder: the
/// user's own files anywhere (a work tree under /var/mnt too), never root's or another user's.
fn yours(p: &std::path::Path, home: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(me) = std::fs::metadata(home).map(|m| m.uid()) else {
        return false;
    };
    let of = if p.exists() { Some(p) } else { p.parent() };
    of.and_then(|q| std::fs::metadata(q).ok())
        .is_some_and(|m| m.uid() == me)
}

/// A copy of `path` before Claude may write it: `cache_dir/claude/backups/<when>-<name>`.
pub fn backup(path: &str) -> std::io::Result<std::path::PathBuf> {
    let d = cwd().join("backups");
    std::fs::create_dir_all(&d)?;
    let name = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let to = d.join(format!(
        "{}-{name}",
        jiff::Zoned::now().strftime("%Y%m%d-%H%M%S")
    ));
    if std::path::Path::new(path).exists() {
        std::fs::copy(path, &to)?;
    } else {
        // A new file: the backup says it didn't exist.
        std::fs::write(&to, "")?;
    }
    Ok(to)
}

/// A chat's denials: the interactive ones without Edit/Write (which stay refused unless a
/// file is granted, and can be asked for).
fn chat_denied(d: &[&str]) -> Vec<String> {
    d.iter()
        .filter(|x| **x != "Edit" && **x != "Write")
        .map(|s| s.to_string())
        .collect()
}

/// `Read(//abs)` for an absolute path, as Claude Code's rules want it.
fn rule(tool: &str, path: &str) -> String {
    match path.strip_prefix('/') {
        Some(abs) => format!("{tool}(//{abs})"),
        None => format!("{tool}({path})"),
    }
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
    /// A chat on this machine: read-only commands, and Edit/Write there to be asked for
    /// (refused unless granted: `-p` turns every call without an allow rule down).
    pub fn local() -> Self {
        Self {
            system: system_prompt(),
            tools: ["Bash", "Read", "Grep", "Glob", "Edit", "Write"]
                .map(String::from)
                .to_vec(),
            allowed: ALLOWED.iter().map(|s| s.to_string()).collect(),
            denied: chat_denied(DENIED),
            dirs: Vec::new(),
        }
    }

    /// No edits at all (plans and reviews: nobody is there to grant one).
    pub fn without_edits(mut self) -> Self {
        self.tools.retain(|t| t != "Edit" && t != "Write");
        for d in ["Edit", "Write"] {
            if !self.denied.iter().any(|x| x == d) {
                self.denied.push(d.into());
            }
        }
        self
    }

    /// Claude may read sentry's own maintenance log (`dir`: the ledger `LOG.md` and its
    /// entries), as plans and reviews do: it's what was done before.
    pub fn with_log(mut self, dir: &std::path::Path) -> Self {
        let d = crate::maint::real_path(dir);
        if !self.tools.iter().any(|t| t == "Read") {
            self.tools.push("Read".into());
        }
        let rule = format!("Read(/{d}/**)");
        if !self.allowed.contains(&rule) {
            self.allowed.push(rule);
        }
        // Claude Code can only add a directory that exists (the log appears with the first run).
        if dir.is_dir() && !self.dirs.contains(&d) {
            self.dirs.push(d);
        }
        self
    }

    /// Chats may read the configured notes files (as plans and reviews do).
    pub fn with_notes(mut self, notes: &[String]) -> Self {
        let notes = crate::maint::resolve_notes(notes);
        if notes.is_empty() {
            return self;
        }
        if !self.tools.iter().any(|t| t == "Read") {
            self.tools.push("Read".into());
        }
        self.allowed.extend(crate::maint::read_rules(&notes));
        self.dirs.extend(
            notes
                .iter()
                .filter_map(|n| std::path::Path::new(n).parent())
                .map(|d| d.display().to_string()),
        );
        self.dirs.sort();
        self.dirs.dedup();
        self
    }

    /// The conversation's grants on top: each file read (and, granted, written) by path only.
    /// A bare `Edit`/`Write` deny beats any allow, so it goes when a write is granted; the
    /// path-scoped allows keep every other file out.
    pub fn with_grants(mut self, grants: &[Grant]) -> Self {
        for g in grants {
            if g.access == Access::Run {
                self.allowed.push(format!("Bash({})", g.path));
                continue;
            }
            let mut tools = vec!["Read"];
            let dir = std::path::Path::new(&g.path).is_dir();
            if dir {
                self.allowed.push(rule("Read", &format!("{}/**", g.path)));
                self.dirs.push(g.path.clone());
                continue;
            }
            self.allowed.push(rule("Read", &g.path));
            if g.access == Access::Write {
                tools.extend(["Edit", "Write"]);
                self.allowed.push(rule("Edit", &g.path));
                self.allowed.push(rule("Write", &g.path));
                self.denied.retain(|d| d != "Edit" && d != "Write");
            }
            for t in tools {
                if !self.tools.iter().any(|x| x == t) {
                    self.tools.push(t.into());
                }
            }
            if let Some(d) = std::path::Path::new(&g.path).parent() {
                self.dirs.push(d.display().to_string());
            }
        }
        self.dirs.sort();
        self.dirs.dedup();
        self
    }

    /// The local denials plus every way around a server gateway.
    pub fn denied_for_servers() -> Vec<String> {
        chat_denied(DENIED)
            .into_iter()
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

/// A failed tool call in a few words: a command's exit code and why, or a refusal.
fn error_summary(text: &str) -> String {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let first = lines.next().unwrap_or("");
    match first.strip_prefix("Exit code ") {
        // Not a refusal: the command ran and exited non-zero (`systemctl is-failed` says 1 for
        // "not failed").
        Some(code) => match lines.next_back() {
            Some(why) => format!("exit {code}: {why}"),
            None => format!("exit {code}"),
        },
        None => format!("denied: {first}"),
    }
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
                    error_summary(&text)
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
        // An apply session: one plan, the step's rules, then sentry retries it.
        assert!(p.contains("```sentry-apply") && p.contains("later steps to it"));
        assert!(p.contains("sentry retries the step"));
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
        // Edit/Write are there to be asked for, with no allow rule (refused unless granted).
        assert!(c.contains("--tools Bash Read Grep Glob Edit Write"), "{c}");
        assert!(
            !c.contains("Edit(") && !c.contains("--disallowedTools Write Edit"),
            "{c}"
        );
        assert!(c.contains("--disallowedTools NotebookEdit"), "{c}");
        assert!(c.contains("'Bash(sudo:*)'"));
        assert!(c.ends_with("--resume abc"), "{c}");
        assert!(
            !ALLOWED
                .iter()
                .any(|a| a.contains("rm") || a.contains("sudo") || a.contains("install"))
        );
        // gsettings reads only: `set` and `reset` aren't allowed, nor read-only to sentry.
        assert!(read_only(
            "gsettings get org.gnome.software download-updates"
        ));
        assert!(!read_only(
            "gsettings set org.gnome.software download-updates false"
        ));
        assert!(
            !ALLOWED
                .iter()
                .any(|a| a.contains("gsettings set") || a.contains("gsettings reset"))
        );
    }

    #[test]
    fn failed_commands_are_labelled_by_exit_code_not_denied() {
        assert_eq!(
            error_summary("Exit code 1\nactive"),
            "exit 1: active",
            "systemctl is-failed says 1 for a unit that's fine"
        );
        assert_eq!(error_summary("Exit code 3"), "exit 3");
        assert_eq!(
            error_summary(
                "Claude requested permissions to read from /x, but you haven't granted it yet."
            ),
            "denied: Claude requested permissions to read from /x, but you haven't granted it yet."
        );
    }

    #[test]
    fn a_refused_file_is_a_request_from_the_tool_or_the_refusal() {
        let r = "denied: Claude requested permissions to read from /nowhere/notes.md, but you \
                 haven't granted it yet.";
        let g = requested("Read", "/nowhere/notes.md", r).unwrap();
        assert_eq!(
            (g.access, g.path.as_str()),
            (Access::Read, "/nowhere/notes.md")
        );
        let g = requested("Edit", "/nowhere/notes.md", "denied: …").unwrap();
        assert_eq!(g.access, Access::Write);
        // Not a file tool: the path in the refusal.
        let g = requested("Bash", "cat x", r).unwrap();
        assert_eq!(g.path, "/nowhere/notes.md");
        let w = "denied: Claude requested permissions to write to /nowhere/a.md, but …";
        assert_eq!(requested("Bash", "x", w).unwrap().access, Access::Write);
        // A command: the part Claude Code wants approved, else the whole command.
        let part = "denied: This Bash command contains multiple operations. The following part \
                    requires approval: ostree admin status 2>&1";
        let g = requested(
            "Bash",
            "rpm-ostree status; ostree admin status 2>&1 | head",
            part,
        )
        .unwrap();
        assert_eq!(
            (g.access, g.path.as_str()),
            (Access::Run, "ostree admin status 2>&1")
        );
        assert!(grantable(&g).is_ok());
        let g = requested(
            "Bash",
            "sudo ostree admin pin 1",
            "denied: Bash isn't allowed",
        )
        .unwrap();
        assert!(
            grantable(&g).is_ok() && g.changes(),
            "sudo: allowed, marked"
        );
        let out = Grant {
            access: Access::Run,
            path: "rpm -qa > /tmp/x".into(),
        };
        assert!(grantable(&out).is_ok() && out.changes(), "writes a file");
        let p = Profile::local().with_grants(&[Grant {
            access: Access::Run,
            path: "ostree admin status".into(),
        }]);
        assert!(p.allowed.iter().any(|a| a == "Bash(ostree admin status)"));
    }

    #[test]
    fn the_maintenance_log_is_readable() {
        let d = std::env::temp_dir().join(format!("sentry-log-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = Profile::local().with_log(&d);
        let real = crate::maint::real_path(&d);
        assert!(
            p.allowed.contains(&format!("Read(/{real}/**)")),
            "{:?}",
            p.allowed
        );
        assert!(p.dirs.contains(&real));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn what_can_be_granted() {
        let home = crate::paths::home();
        let g = |access, p: std::path::PathBuf| Grant {
            access,
            path: p.display().to_string(),
        };
        assert!(grantable(&g(Access::Read, home.join(".ssh/id_ed25519"))).is_err());
        assert!(grantable(&g(Access::Write, "/etc/hosts".into())).is_err());
        assert!(grantable(&g(Access::Write, home.join("sentry-grant-test-new.md"))).is_ok());
        // Yours outside home too (this crate's own source tree, wherever it's checked out).
        let mine = format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"));
        assert!(grantable(&g(Access::Write, mine.into())).is_ok());
        assert!(grantable(&g(Access::Write, "/".into())).is_err());
        assert!(grantable(&g(Access::Read, home.join("sentry-grant-test-new.md"))).is_err());
        let here = format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"));
        assert!(grantable(&g(Access::Read, here.into())).is_ok());
        // A folder can be read; keys can't, even through a command.
        assert!(grantable(&g(Access::Read, env!("CARGO_MANIFEST_DIR").into())).is_ok());
        let run = |c: &str| Grant {
            access: Access::Run,
            path: c.into(),
        };
        assert!(grantable(&run("cat ~/.ssh/id_ed25519")).is_err());
        assert!(grantable(&run("rm -rf /tmp/x")).is_ok());
    }

    #[test]
    fn what_a_refusal_looks_like() {
        // The strings from a real session.
        assert!(refused("denied: This command requires approval"));
        assert!(refused(
            "denied: This Bash command contains multiple operations. The following part \
             requires approval: rpm -ql a b"
        ));
        assert!(refused(
            "denied: Claude requested permissions to read from /x, but you haven't granted it yet."
        ));
        assert!(refused(
            "denied: Permission to use Bash with command sudo x has been denied."
        ));
        // It ran and failed, or Claude rephrases it itself.
        assert!(!refused("exit 1: cat: /root/x: Permission denied"));
        assert!(!refused(
            "denied: A variable in this command can't be checked before it runs"
        ));
    }

    #[test]
    fn commands_that_only_read() {
        for c in [
            "rpm-ostree upgrade --check --preview",
            "rpm -V rpmfusion-free-release",
            "rpm -ql a b | grep repo",
            "grep -E 'a|b>c' /etc/hosts 2>/dev/null",
            "systemctl --user status x; journalctl -b -n 5",
            "ostree admin status 2>&1",
            "firewall-cmd --zone=public --list-all",
        ] {
            assert!(only_reads(c), "{c}");
        }
        for c in [
            "sudo ss -tlnp",
            "rpm-ostree upgrade",
            "rpm-ostree install x",
            "rm -f x",
            "echo hi > /tmp/x",
            "cat a | tee b",
            "sed -i s/a/b/ f",
            "find / -name x -delete",
            "ls $(rm x)",
            "systemctl restart x",
            "flatpak uninstall x",
            "gsettings set a b c",
            "some-unknown-tool",
        ] {
            assert!(!only_reads(c), "{c}");
        }
    }

    #[test]
    fn the_prompts_never_hand_the_work_back() {
        let a = Apply::default();
        for text in [system_prompt(), apply_question(&a), GRANTS.to_string()] {
            assert!(!text.contains("theirs to run"), "{text}");
            assert!(!text.contains("cannot change"), "{text}");
        }
        assert!(GRANTS.contains("never ask the user to run"));
        assert!(ALLOWED.contains(&"Bash(rpm-ostree upgrade --check:*)"));
    }

    #[test]
    fn a_write_grant_opens_exactly_that_file() {
        let plain = Profile::local();
        let same = Profile::local().with_grants(&[]);
        assert_eq!(
            (&same.allowed, &same.denied, &same.tools, &same.dirs),
            (&plain.allowed, &plain.denied, &plain.tools, &plain.dirs)
        );
        let p = Profile::local().with_grants(&[Grant {
            access: Access::Write,
            path: "/home/u/notes/up.md".into(),
        }]);
        for r in [
            "Read(//home/u/notes/up.md)",
            "Edit(//home/u/notes/up.md)",
            "Write(//home/u/notes/up.md)",
        ] {
            assert!(p.allowed.iter().any(|a| a == r), "{r}");
        }
        assert!(
            !p.denied.iter().any(|d| d == "Edit" || d == "Write"),
            "{:?}",
            p.denied
        );
        assert!(p.tools.iter().any(|t| t == "Edit") && p.dirs == ["/home/u/notes"]);
        // A read grant allows no edit; plans and reviews can't edit at all.
        let r = Profile::local().with_grants(&[Grant {
            access: Access::Read,
            path: "/home/u/a.md".into(),
        }]);
        assert!(!r.allowed.iter().any(|a| a.starts_with("Edit(")));
        let w = Profile::local().without_edits();
        assert!(w.denied.iter().any(|d| d == "Edit") && !w.tools.iter().any(|t| t == "Edit"));
        // Notes are readable in chats, as for plans.
        let n = Profile::local().with_notes(&["/nowhere/notes/up.md".into()]);
        assert!(n.allowed.iter().any(|a| a == "Read(//nowhere/notes/up.md)"));
        assert_eq!(n.dirs, ["/nowhere/notes"]);
    }
}
