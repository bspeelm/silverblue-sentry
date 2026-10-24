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
        }
    }

    /// The first turn's prompt: context, then the question.
    pub fn prompt(&self) -> String {
        format!("{}\n\nQuestion: {}", self.context.trim_end(), self.question)
    }
}

/// Read-only commands and paths Claude may use. Review this list before widening it.
pub const ALLOWED: &[&str] = &[
    "Bash(ss:*)",
    "Bash(ip addr:*)",
    "Bash(ip route:*)",
    "Bash(systemctl status:*)",
    "Bash(systemctl --user status:*)",
    "Bash(systemctl list-units:*)",
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
    Cmd::host("claude").available()
}

/// One turn: the first (`resume = None`) or a follow-up in the same session.
pub fn turn_cmd(prompt: &str, resume: Option<&str>) -> Cmd {
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
        .arg(system_prompt())
        .args(["--tools", "Bash", "Read", "Grep", "Glob"])
        .arg("--allowedTools")
        .args(ALLOWED.iter().copied())
        .arg("--disallowedTools")
        .args(DENIED.iter().copied());
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
