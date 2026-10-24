//! Concrete fixes for audit findings, derived from the finding itself (so they work on older
//! reports too). Only fixes that are safe and reversible are offered; everything else says why
//! not and points to "To do" or Ask Claude.

use super::Finding;

#[derive(Debug, Clone, PartialEq)]
pub enum Act {
    /// A shell command; `sudo` ones need a terminal for the password prompt.
    Shell { cmd: String, sudo: bool },
    /// Open a file in $EDITOR at a line.
    Edit { path: String, line: usize },
    /// Go to the tab that already handles this (`cleanup`, `flatpaks`, `containers`).
    Open(&'static str),
    /// Cleanup tab focused on one job.
    Cleanup(crate::jobs::JobId),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Fix {
    pub label: String,
    pub act: Act,
    /// How to undo it, shown before confirming.
    pub undo: Option<String>,
    /// Destructive or hard to undo: shown in red.
    pub risky: bool,
    /// Only looks (no change): no re-audit afterwards.
    pub inspect: bool,
}

fn shell(label: &str, cmd: impl Into<String>, sudo: bool, undo: Option<&str>) -> Fix {
    Fix {
        label: label.into(),
        act: Act::Shell {
            cmd: cmd.into(),
            sudo,
        },
        undo: undo.map(str::to_string),
        risky: false,
        inspect: label.contains("read-only"),
    }
}

/// Why `f` has nothing to offer for this finding.
pub fn no_fix_reason(f: &Finding) -> &'static str {
    let id = f.id.as_str();
    if id.starts_with("listener:port:") {
        "unknown service: identify it first (the fix is offered once it's named), or press A"
    } else if id.starts_with("repos:vendor:") {
        "these repos provide packages you rely on; removing them is a decision, see To do"
    } else if id.starts_with("flatpak-origin:") || id.starts_with("ostree-sig:") {
        "no safe automatic fix; follow To do, or press A to ask Claude"
    } else {
        "no automatic fix for this one; see To do, or press A to ask Claude"
    }
}

pub fn fixes(f: &Finding) -> Vec<Fix> {
    let id = f.id.as_str();
    let (kind, rest) = id.split_once(':').unwrap_or((id, ""));
    match kind {
        "listener" => match rest.strip_prefix("svc:") {
            Some(name) => listener_fixes(name),
            None => {
                // Unknown service: the only safe step is identifying it.
                let port = rest.rsplit(':').next().unwrap_or("");
                vec![shell(
                    "Identify the process (read-only)",
                    format!("sudo ss -tulpn 'sport = :{port}'"),
                    true,
                    None,
                )]
            }
        },
        "repo" => {
            let file = rest;
            if file == "updates-master.repo" {
                vec![Fix {
                    risky: true,
                    ..shell(
                        "Remove the temporary master-mirror repo",
                        "sudo rm /etc/yum.repos.d/updates-master.repo",
                        true,
                        Some("recreate it from the quick-update manual card (upgrade-ritual step)"),
                    )
                }]
            } else {
                vec![shell(
                    "Disable this COPR repo (packages stay installed)",
                    format!("sudo sed -i 's/^enabled=1/enabled=0/' /etc/yum.repos.d/{file}"),
                    true,
                    Some(&format!(
                        "sudo sed -i 's/^enabled=0/enabled=1/' /etc/yum.repos.d/{file}"
                    )),
                )]
            }
        }
        "unit-failed" => {
            let (scope, unit) = rest.split_once(':').unwrap_or(("system", rest));
            let user = scope == "user";
            let u = if user { " --user" } else { "" };
            vec![
                shell(
                    "Show why it failed (read-only)",
                    format!(
                        "systemctl{u} status --no-pager {unit}; journalctl{u} -b -u {unit} --no-pager -n 40"
                    ),
                    false,
                    None,
                ),
                shell(
                    "Restart it",
                    format!(
                        "{}systemctl{u} restart {unit}",
                        if user { "" } else { "sudo " }
                    ),
                    !user,
                    None,
                ),
                shell(
                    "Clear the failed state (if it's harmless)",
                    format!(
                        "{}systemctl{u} reset-failed {unit}",
                        if user { "" } else { "sudo " }
                    ),
                    !user,
                    Some("it reappears if the unit fails again"),
                ),
            ]
        }
        "container-stale-home" => vec![Fix {
            risky: true,
            ..shell(
                "Remove the container (its installed packages go with it; $HOME stays)",
                format!("podman rm {rest}"),
                false,
                Some("not undoable: recreate it from its image"),
            )
        }],
        "flatpak-perm" => {
            let (app, flag) = rest.split_once(':').unwrap_or((rest, ""));
            let (no, yes) = match flag.strip_prefix("talk:") {
                Some(name) => (
                    format!("--no-talk-name={name}"),
                    format!("--talk-name={name}"),
                ),
                None => (
                    format!("--nofilesystem={flag}"),
                    format!("--filesystem={flag}"),
                ),
            };
            vec![shell(
                "Take the permission away (a user override)",
                format!("flatpak override --user {no} {app}"),
                false,
                Some(&format!("flatpak override --user {yes} {app}")),
            )]
        }
        "flatpak-fs-access" => vec![Fix {
            label: "Review per app on the Flatpaks tab (o opens Flatseal)".into(),
            act: Act::Open("flatpaks"),
            undo: None,
            risky: false,
            inspect: true,
        }],
        "flatpak-gl-stale" | "flatpak-unused" => vec![Fix {
            label: "Remove it from Cleanup (preview first)".into(),
            act: Act::Cleanup(crate::jobs::JobId::CleanupFlatpak),
            undo: None,
            risky: false,
            inspect: true,
        }],
        "cache-size" => vec![Fix {
            label: "See the biggest folders in Cleanup".into(),
            act: Act::Cleanup(crate::jobs::JobId::CleanupCache),
            undo: None,
            risky: false,
            inspect: true,
        }],
        "shell" => {
            let file = rest.split(':').next().unwrap_or(".bashrc");
            // "~/.bashrc line 12 runs curl"
            let line = f
                .message
                .split_whitespace()
                .skip_while(|w| *w != "line")
                .nth(1)
                .and_then(|n| n.parse().ok())
                .unwrap_or(1);
            vec![Fix {
                label: format!("Open ~/{file} at line {line}"),
                act: Act::Edit {
                    path: format!("~/{file}"),
                    line,
                },
                undo: None,
                risky: false,
                inspect: false,
            }]
        }
        "failed-logins" => vec![shell(
            "Show the failed attempts (read-only)",
            "journalctl SYSLOG_FACILITY=10 --since -24h --no-pager | grep -i 'authentication failure'",
            false,
            None,
        )],
        _ => Vec::new(),
    }
}

fn listener_fixes(service: &str) -> Vec<Fix> {
    let disable = |label: &str, units: &str, undo: &str| {
        vec![shell(
            label,
            format!("sudo systemctl disable --now {units}"),
            true,
            Some(&format!("sudo systemctl enable --now {undo}")),
        )]
    };
    match service {
        "mDNS (Avahi)" => disable(
            "Turn off Avahi (printer/Chromecast discovery stops)",
            "avahi-daemon.socket avahi-daemon.service",
            "avahi-daemon.socket avahi-daemon.service",
        ),
        "WS-Discovery (wsdd)" => disable(
            "Turn off wsdd (hidden from Windows' Network view)",
            "wsdd",
            "wsdd",
        ),
        "SSH server" => disable("Turn off the SSH server", "sshd", "sshd"),
        "Samba file sharing" => disable("Turn off Samba sharing", "smb nmb", "smb nmb"),
        "rpcbind (NFS)" => disable(
            "Turn off rpcbind",
            "rpcbind.socket rpcbind",
            "rpcbind.socket rpcbind",
        ),
        "passim (fwupd firmware cache)" => vec![shell(
            "Stop passim sharing firmware on the LAN (fwupd keeps working)",
            "sudo systemctl mask --now passim.service",
            true,
            Some("sudo systemctl unmask passim.service"),
        )],
        "LLMNR (systemd-resolved)" => vec![shell(
            "Turn off LLMNR in systemd-resolved",
            "sudo mkdir -p /etc/systemd/resolved.conf.d && printf '[Resolve]\\nLLMNR=no\\n' | sudo tee /etc/systemd/resolved.conf.d/no-llmnr.conf >/dev/null && sudo systemctl restart systemd-resolved",
            true,
            Some(
                "sudo rm /etc/systemd/resolved.conf.d/no-llmnr.conf && sudo systemctl restart systemd-resolved",
            ),
        )],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(id: &str, message: &str) -> Finding {
        Finding {
            id: id.into(),
            message: message.into(),
            ..Default::default()
        }
    }

    #[test]
    fn fixes_per_finding_kind() {
        let p = fixes(&f("listener:svc:passim (fwupd firmware cache)", ""));
        assert!(
            matches!(&p[0].act, Act::Shell { cmd, sudo: true } if cmd == "sudo systemctl mask --now passim.service")
        );
        assert_eq!(
            p[0].undo.as_deref(),
            Some("sudo systemctl unmask passim.service")
        );
        assert!(fixes(&f("listener:svc:DHCPv6 client (NetworkManager)", "")).is_empty());
        let unknown = fixes(&f("listener:port:tcp:27999", ""));
        assert!(
            matches!(&unknown[0].act, Act::Shell { cmd, .. } if cmd.contains("sport = :27999"))
        );
        let units = fixes(&f("unit-failed:user:foo.service", ""));
        assert_eq!(units.len(), 3);
        assert!(
            matches!(&units[1].act, Act::Shell { cmd, sudo: false } if cmd == "systemctl --user restart foo.service")
        );
        let sys = fixes(&f("unit-failed:system:bar.service", ""));
        assert!(
            matches!(&sys[2].act, Act::Shell { cmd, sudo: true } if cmd == "sudo systemctl reset-failed bar.service")
        );
        let perm = fixes(&f("flatpak-perm:com.example.App:home", ""));
        assert!(
            matches!(&perm[0].act, Act::Shell { cmd, .. } if cmd == "flatpak override --user --nofilesystem=home com.example.App")
        );
        let sh = fixes(&f("shell:.bashrc:curl:abcd", "~/.bashrc line 12 runs curl"));
        assert_eq!(
            sh[0].act,
            Act::Edit {
                path: "~/.bashrc".into(),
                line: 12
            }
        );
        assert!(fixes(&f("repos:vendor:RPM Fusion", "")).is_empty());
        assert!(no_fix_reason(&f("repos:vendor:RPM Fusion", "")).contains("rely on"));
        assert!(fixes(&f("repo:updates-master.repo", ""))[0].risky);
    }
}
