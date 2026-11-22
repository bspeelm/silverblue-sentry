//! What a server says to the security audit (`sentry audit security`, core `secaudit`):
//! the audit's own snapshot plus one read without root (its addresses, the ssh server's
//! settings, apt's automatic updates) and how sudo answers. Read-only; where root is
//! needed and not at hand (`sshd -T` outside the sudo list, containers without an
//! inventory) the section stays empty and the audit says it couldn't check.

use sentry_core::secaudit::{
    Backup, Ctr, Eol, Kind, Listen, Os, Software, Ssh, TargetFacts, Watch, backup_signal, sshd,
};

use crate::collect::apt::Kind as AptKind;
use crate::collect::crowdsec::Agent;
use crate::collect::{self, Snapshot};
use crate::config::Server;
use crate::maint::eval::Flag;
use crate::remote::{Remote, SrvError, SudoMode};

/// The target's id in the audit.
pub fn id(name: &str) -> String {
    format!("srv:{name}")
}

/// The one read without root. Sections at lines starting `@@`.
pub fn script() -> String {
    format!(
        "echo @@addrs; hostname -I 2>/dev/null; \
         echo @@sshd-on; systemctl is-active ssh.service sshd.service ssh.socket 2>/dev/null; \
         echo @@auto; apt-config dump 2>/dev/null | grep -i '^APT::Periodic::'; \
         echo @@sshd; {}",
        sshd::files_script("")
    )
}

/// What [`script`] printed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Read {
    pub addrs: Vec<String>,
    /// The ssh server runs (none: systemd didn't say).
    pub ssh_on: Option<bool>,
    /// apt installs security updates by itself (none: apt said nothing about it).
    pub auto: Option<bool>,
    /// From the config files (none: not readable).
    pub ssh: Option<Ssh>,
}

pub fn parse(text: &str) -> Read {
    let mut r = Read::default();
    let mut name = "";
    let mut sshd_text = String::new();
    let mut states = Vec::new();
    let mut periodic = Vec::new();
    for l in text.lines() {
        if let Some(n) = l.strip_prefix("@@") {
            name = n.trim();
            continue;
        }
        match name {
            "addrs" => r.addrs.extend(l.split_whitespace().map(str::to_string)),
            "sshd-on" => states.push(l.trim()),
            "auto" => periodic.push(l.trim()),
            "sshd" => {
                sshd_text.push_str(l);
                sshd_text.push('\n');
            }
            _ => {}
        }
    }
    if !states.is_empty() {
        r.ssh_on = Some(states.contains(&"active"));
    }
    if !periodic.is_empty() {
        // `APT::Periodic::Unattended-Upgrade "1";`
        r.auto = Some(periodic.iter().any(|l| {
            l.to_ascii_lowercase()
                .starts_with("apt::periodic::unattended-upgrade ")
                && !l.contains("\"0\"")
                && !l.contains("\"\"")
        }));
    }
    r.ssh = sshd::parse_files(&sshd_text);
    r
}

/// Pure: the facts of one snapshot and one read.
pub fn facts(
    name: &str,
    cfg: &Server,
    s: &Snapshot,
    read: Option<&Read>,
    effective: Option<Ssh>,
    sudo: Option<SudoMode>,
    today: jiff::civil::Date,
) -> TargetFacts {
    let mut t = TargetFacts::new(&id(name), Kind::Server, name);
    // (Disks, sensors and the journal are the server's own audit's, not this one's.)
    t.errors = s
        .errors
        .iter()
        .filter(|(sec, _)| {
            [
                "docker",
                "listeners",
                "apt",
                "units",
                "crowdsec",
                "fail2ban",
            ]
            .iter()
            .any(|k| sec.starts_with(k))
        })
        .cloned()
        .collect();
    t.addrs = read.map(|r| r.addrs.clone()).unwrap_or_default();

    t.os = s.apt.as_ref().map(|a| Os {
        name: s.os.clone(),
        updates: Some(a.upgrades.len() as u32),
        security: Some(
            a.upgrades
                .iter()
                .filter(|p| p.kind == AptKind::Security)
                .count() as u32,
        ),
        reboot_pending: a.reboot_since.is_some() || a.kernel_pending(),
        updated_days: a.stamp("upgrade").map(|t| (a.now - t).max(0) / 86_400),
        auto_updates: read.and_then(|r| r.auto),
        eol: Eol::Unknown,
    });
    t.listeners = s.listeners.as_ref().map(|ls| {
        ls.iter()
            .filter_map(|l| {
                Some(Listen {
                    proto: l.proto.clone(),
                    port: l.port.parse().ok()?,
                    wide: !sentry_core::secaudit::loopback(&l.addr),
                    process: l.process.clone(),
                })
            })
            .collect()
    });
    // `sshd -T` where the sudo list allows it, else the config files.
    let mut ssh = effective.or_else(|| read.and_then(|r| r.ssh.clone()));
    if let Some(on) = read.and_then(|r| r.ssh_on) {
        ssh.get_or_insert_with(Ssh::default).on = Some(on);
    }
    t.ssh = ssh;
    t.sudo_nopasswd = match sudo {
        Some(SudoMode::NoPasswd) => Some(true),
        Some(SudoMode::Password) => Some(false),
        _ => None,
    };
    t.containers = s.docker.as_ref().map(|d| {
        d.containers
            .iter()
            .filter(|c| c.status == "running")
            .map(|c| {
                let mut ports: Vec<u16> = c
                    .ports
                    .iter()
                    .filter(|(ip, _, _)| !sentry_core::secaudit::loopback(ip))
                    .filter_map(|(_, p, _)| p.parse().ok())
                    .collect();
                ports.sort_unstable();
                ports.dedup();
                Ctr {
                    name: c.name.clone(),
                    image: c.image.clone(),
                    privileged: c.privileged,
                    host_network: c.host_network,
                    docker_sock: c.docker_sock,
                    ports,
                }
            })
            .collect()
    });
    let container_of = |item: &str| -> Option<String> {
        let image = cfg
            .maintenance
            .items
            .iter()
            .find(|i| i.id == item)?
            .image
            .as_ref()?;
        let cs = &s.docker.as_ref()?.containers;
        cs.iter()
            .find(|c| {
                image.container.as_deref() == Some(c.name.as_str())
                    || (image.service.is_some()
                        && image.service == c.service
                        && (image.compose.is_none() || image.compose == c.compose))
            })
            .map(|c| c.name.clone())
    };
    if !cfg.maintenance.items.is_empty() {
        t.software = Some(
            s.maint
                .iter()
                .filter(|m| !m.has(Flag::Retired))
                .map(|m| Software {
                    id: m.id.clone(),
                    running: m.running.clone(),
                    latest: m.latest.clone(),
                    behind: m.has(Flag::Behind) || m.has(Flag::Security),
                    security: m.has(Flag::Security),
                    eol: if m.has(Flag::Eol) {
                        let days = m
                            .eol
                            .as_ref()
                            .and_then(|e| e.eol)
                            .map_or(0, |d| (today - d).get_days() as i64);
                        Eol::Past(days.max(0))
                    } else if m.has(Flag::EolSoon) {
                        let days = m
                            .eol
                            .as_ref()
                            .and_then(|e| e.eol)
                            .map_or(0, |d| (d - today).get_days() as i64);
                        Eol::Soon(days.max(0))
                    } else if m.eol.is_some() {
                        Eol::Supported
                    } else {
                        Eol::Unknown
                    },
                    container: container_of(&m.id),
                })
                .collect(),
        );
    }
    if s.crowdsec.is_some() || s.jails.is_some() {
        let cs = s.crowdsec.as_ref();
        let quiet: Vec<&str> = cs
            .map(|c| c.quiet_bouncers().iter().map(|b| b.name.as_str()).collect())
            .unwrap_or_default();
        t.watch = Some(Watch {
            crowdsec: cs.and_then(|c| match c.agent {
                Agent::Running => Some(true),
                Agent::Down(_) => Some(false),
                Agent::NoUnit => None,
            }),
            bouncers: cs.and_then(|c| c.bouncers.as_ref()).map(|bs| {
                bs.iter()
                    .filter(|b| !b.revoked && !quiet.contains(&b.name.as_str()))
                    .map(|b| b.kind.clone())
                    .collect()
            }),
            jails: s.jails.as_ref().map(Vec::len),
            enforces: None,
        });
        if cs.is_none() {
            t.watch.as_mut().unwrap().bouncers = Some(Vec::new());
        }
    } else if !s
        .errors
        .iter()
        .any(|(sec, _)| sec.starts_with("crowdsec") || sec == "fail2ban")
    {
        // Neither is there: that is known, not unread.
        t.watch = Some(Watch {
            bouncers: Some(Vec::new()),
            ..Default::default()
        });
    }
    if s.units.is_some() || s.docker.is_some() {
        let mut signals: Vec<String> = s
            .units
            .iter()
            .flat_map(|u| &u.all)
            .filter(|u| backup_signal(&u.unit) && u.load != "not-found")
            .map(|u| u.unit.clone())
            .chain(
                s.docker
                    .iter()
                    .flat_map(|d| &d.containers)
                    .filter(|c| backup_signal(&c.name) || backup_signal(&c.image))
                    .map(|c| format!("container {}", c.name)),
            )
            .collect();
        signals.sort();
        signals.dedup();
        signals.truncate(6);
        t.backup = Some(Backup {
            signals,
            ..Default::default()
        });
    }
    t
}

/// Read the server and say what it knows. Never fails: a server that doesn't answer is a
/// target that couldn't be checked. Root reads come from the sudo list or the last
/// inventory, never from a password.
pub fn collect(r: &Remote) -> TargetFacts {
    let r = r.clone().with_inventory();
    let snap = match collect::snapshot(&r) {
        Ok(s) => s,
        Err(e) => {
            return TargetFacts::unreachable(&id(&r.name), Kind::Server, &r.name, &e.to_string());
        }
    };
    let mut errors = Vec::new();
    let read = r
        .output(&r.sh(&script()))
        .map(|t| parse(&t))
        .map_err(|e| errors.push(("ssh and updates settings".to_string(), e.to_string())))
        .ok();
    let effective = match r.privileged(&["sshd", "-T"]).and_then(|c| r.output(&c)) {
        Ok(text) => Some(sshd::parse_effective(&text)),
        Err(SrvError::NeedsSudo(_)) => None,
        Err(e) => {
            errors.push(("sshd -T".to_string(), e.to_string()));
            None
        }
    };
    let sudo = r.sudo_mode().ok();
    let today = jiff::Zoned::now().date();
    let mut t = facts(
        &r.name,
        &r.cfg,
        &snap,
        read.as_ref(),
        effective,
        sudo,
        today,
    );
    t.errors.extend(errors);
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::{apt, docker, fixture, units};
    use sentry_core::collectors::net;

    const READ: &str = "@@addrs\n192.0.2.93 172.17.0.1 2001:db8::93 \n\
                        @@sshd-on\nactive\ninactive\ninactive\n\
                        @@auto\nAPT::Periodic::Update-Package-Lists \"1\";\n\
                        APT::Periodic::Unattended-Upgrade \"1\";\n\
                        @@sshd\n#@file /etc/ssh/sshd_config\n\
                        Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n\n\
                        #@file /etc/ssh/sshd_config.d/10-keys.conf\nPasswordAuthentication no\n\n";

    #[test]
    fn the_read_is_parsed_by_section() {
        let r = parse(READ);
        assert_eq!(r.addrs, ["192.0.2.93", "172.17.0.1", "2001:db8::93"]);
        assert_eq!(r.ssh_on, Some(true));
        assert_eq!(r.auto, Some(true));
        let ssh = r.ssh.unwrap();
        assert_eq!(ssh.password, Some(false));
        assert_eq!(ssh.root.as_deref(), Some("no"));
        // Off, said so; nothing said, not known; an unreadable ssh config, not known.
        let r = parse(
            "@@addrs\n@@sshd-on\ninactive\n@@auto\nAPT::Periodic::Unattended-Upgrade \"0\";\n@@sshd\n",
        );
        assert_eq!((r.ssh_on, r.auto, r.ssh), (Some(false), Some(false), None));
        assert_eq!(parse("@@addrs\n@@sshd-on\n@@auto\n@@sshd\n").auto, None);
        assert!(script().contains("hostname -I") && !script().contains("sudo"));
    }

    fn snap() -> Snapshot {
        Snapshot {
            server: "myserver".into(),
            os: "Debian GNU/Linux 12 (bookworm)".into(),
            units: Some(units::Units {
                all: units::parse_list(&fixture("list-units.json")).unwrap(),
                watched: vec![],
            }),
            docker: Some(docker::Docker {
                containers: docker::parse_inspect(&fixture("docker-inspect.json")).unwrap(),
                projects: vec![],
            }),
            apt: Some(apt::parse(&fixture("apt.txt"))),
            listeners: Some(net::parse_listen(&fixture("ss-tulpn.txt"))),
            ..Default::default()
        }
    }

    #[test]
    fn a_snapshot_and_a_read_become_facts() {
        let s = snap();
        let today = jiff::civil::date(2026, 10, 26);
        let t = facts(
            "myserver",
            &Server::default(),
            &s,
            Some(&parse(READ)),
            None,
            Some(SudoMode::Password),
            today,
        );
        assert_eq!((t.id.as_str(), t.kind), ("srv:myserver", Kind::Server));
        assert!(t.addrs.contains(&"192.0.2.93".to_string()));
        // Its addresses are for matching a router's forward only.
        assert!(!serde_json::to_string(&t).unwrap().contains("192.0.2.93"));
        let os = t.os.as_ref().unwrap();
        let apt = s.apt.as_ref().unwrap();
        assert_eq!(os.updates, Some(apt.upgrades.len() as u32));
        assert_eq!(os.auto_updates, Some(true));
        assert_eq!(t.sudo_nopasswd, Some(false));
        let ssh = t.ssh.as_ref().unwrap();
        assert_eq!((ssh.on, ssh.password), (Some(true), Some(false)));
        assert_eq!(ssh.source, "its config files");
        let ls = t.listeners.as_ref().unwrap();
        assert!(ls.iter().any(|l| l.wide) && ls.iter().any(|l| !l.wide));
        let running = s
            .docker
            .as_ref()
            .unwrap()
            .containers
            .iter()
            .filter(|c| c.status == "running")
            .count();
        assert_eq!(t.containers.as_ref().unwrap().len(), running);
        // No maintenance items: nothing is said about software, rather than "all current".
        assert!(t.software.is_none());
        // Nothing there watches, and that's known.
        assert_eq!(
            t.watch,
            Some(Watch {
                bouncers: Some(vec![]),
                ..Default::default()
            })
        );
        assert!(t.backup.is_some());

        // `sshd -T` wins over the files; no read at all leaves ssh unknown.
        let eff = sshd::parse_effective("passwordauthentication yes\npermitrootlogin yes\n");
        let t = facts(
            "myserver",
            &Server::default(),
            &s,
            Some(&parse(READ)),
            Some(eff),
            None,
            today,
        );
        let ssh = t.ssh.unwrap();
        assert_eq!((ssh.password, ssh.source.as_str()), (Some(true), "sshd -T"));
        assert_eq!(t.sudo_nopasswd, None);
        let t = facts("myserver", &Server::default(), &s, None, None, None, today);
        assert!(t.ssh.is_none() && t.addrs.is_empty());
    }

    #[test]
    fn a_container_says_how_much_of_the_host_it_holds() {
        let json = r#"[{"Name":"/tool","Config":{"Image":"example/tool:1"},
            "State":{"Status":"running"},"RestartCount":0,
            "Mounts":[{"Source":"/var/run/docker.sock"}],
            "HostConfig":{"Privileged":true,"NetworkMode":"host"},
            "NetworkSettings":{"Ports":{"8443/tcp":[{"HostIp":"0.0.0.0","HostPort":"8443"},
            {"HostIp":"::","HostPort":"8443"}],"9000/tcp":[{"HostIp":"127.0.0.1","HostPort":"9000"}]}}}]"#;
        let mut s = snap();
        s.docker = Some(docker::Docker {
            containers: docker::parse_inspect(json).unwrap(),
            projects: vec![],
        });
        let t = facts(
            "myserver",
            &Server::default(),
            &s,
            None,
            None,
            None,
            jiff::civil::date(2026, 10, 26),
        );
        let c = &t.containers.unwrap()[0];
        assert!(c.privileged && c.host_network && c.docker_sock);
        assert_eq!(
            c.ports,
            [8443],
            "only what's published beyond the server itself"
        );
    }
}
