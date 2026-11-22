//! What this machine says to the security audit (`sentry audit security`, core
//! `secaudit`): the deployment's age and what's waiting (rpm-ostree's own status), and one
//! read of the host without root: whether an ssh server runs and what its config allows
//! (where that is readable), the firewall, what listens, what looks like a backup. And
//! how the private ssh keys' files are kept (their modes; no key is read).

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use sentry_core::secaudit::{
    Backup, HostFw, Keys, Kind, LOCAL, Listen, Os, Ssh, TargetFacts, backup_signal, loopback, sshd,
};

use crate::collectors::{net, ostree};
use crate::exec::Cmd;

/// The one read of the host. Sections at lines starting `@@`.
pub fn script() -> String {
    format!(
        "echo @@addrs; hostname -I 2>/dev/null; \
         echo @@sshd-on; systemctl is-active sshd.service sshd.socket 2>/dev/null; \
         echo @@fw; systemctl is-active firewalld.service 2>/dev/null; \
         firewall-cmd --get-default-zone 2>/dev/null; \
         echo @@listen; ss -tulnH 2>/dev/null; \
         echo @@units; systemctl list-unit-files --type=timer,service --no-legend 2>/dev/null \
         | awk '{{print $1}}'; \
         systemctl --user list-unit-files --type=timer,service --no-legend 2>/dev/null \
         | awk '{{print $1}}'; \
         flatpak list --app --columns=application 2>/dev/null; \
         echo @@sshd; {}",
        sshd::files_script("")
    )
}

/// What [`script`] printed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Read {
    pub addrs: Vec<String>,
    pub ssh_on: Option<bool>,
    pub firewall: Option<HostFw>,
    pub listeners: Vec<Listen>,
    /// Units and apps that look like a backup.
    pub backups: Vec<String>,
    pub ssh: Option<Ssh>,
}

pub fn parse(text: &str) -> Read {
    let mut r = Read::default();
    let mut name = "";
    let (mut sshd_text, mut listen) = (String::new(), String::new());
    let (mut states, mut fw) = (Vec::new(), Vec::new());
    for l in text.lines() {
        if let Some(n) = l.strip_prefix("@@") {
            name = n.trim();
            continue;
        }
        match name {
            "addrs" => r.addrs.extend(l.split_whitespace().map(str::to_string)),
            "sshd-on" => states.push(l.trim()),
            "fw" => fw.push(l.trim()),
            "listen" => {
                listen.push_str(l);
                listen.push('\n');
            }
            "units" if backup_signal(l) => r.backups.push(l.trim().to_string()),
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
    if let Some(state) = fw.first() {
        r.firewall = Some(HostFw {
            active: *state == "active",
            zone: fw.get(1).filter(|z| !z.is_empty()).map(|z| z.to_string()),
        });
    }
    r.listeners = net::parse_listen(&listen)
        .into_iter()
        .filter_map(|l| {
            Some(Listen {
                proto: l.proto,
                port: l.port.parse().ok()?,
                wide: !loopback(&l.addr),
                process: l.process,
            })
        })
        .collect();
    r.backups.sort();
    r.backups.dedup();
    r.backups.truncate(6);
    r.ssh = sshd::parse_files(&sshd_text);
    r
}

/// The private keys in an `.ssh` directory, by their names (a file with a `.pub` beside
/// it, or called `id_…`), and how many of them others can read. None: no such directory.
pub fn keys(dir: &Path) -> Option<Keys> {
    let names: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    let mut k = Keys::default();
    for n in &names {
        let private =
            !n.ends_with(".pub") && (names.contains(&format!("{n}.pub")) || n.starts_with("id_"));
        if !private {
            continue;
        }
        let Ok(m) = std::fs::metadata(dir.join(n)) else {
            continue;
        };
        if !m.is_file() {
            continue;
        }
        k.total += 1;
        if m.permissions().mode() & 0o077 != 0 {
            k.loose += 1;
        }
    }
    Some(k)
}

fn os_name(os_release: &str) -> String {
    os_release
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_else(|| "this machine's system".into())
}

/// Pure: the facts of what was read. `now`: epoch seconds.
pub fn facts(
    os_release: &str,
    tree: Option<&ostree::Ostree>,
    read: Option<&Read>,
    keys: Option<Keys>,
    now: i64,
) -> TargetFacts {
    let mut t = TargetFacts::new(LOCAL, Kind::Local, "this machine");
    t.os = tree.map(|o| {
        // A deployment staged for the next boot is an update already fetched.
        let staged = o.deployments.iter().any(|d| d.staged);
        Os {
            name: os_name(os_release),
            updates: o.update.as_ref().map(|_| 1),
            security: o.update.as_ref().map(|u| u.advisories as u32),
            reboot_pending: staged,
            updated_days: o
                .booted()
                .filter(|d| d.timestamp > 0)
                .map(|d| (now - d.timestamp).max(0) / 86_400),
            auto_updates: None,
            eol: Default::default(),
        }
    });
    if let Some(r) = read {
        t.addrs = r.addrs.clone();
        t.listeners = Some(r.listeners.clone());
        t.firewall = r.firewall.clone();
        let mut ssh = r.ssh.clone();
        if let Some(on) = r.ssh_on {
            ssh.get_or_insert_with(Ssh::default).on = Some(on);
        }
        t.ssh = ssh;
        t.backup = Some(Backup {
            signals: r.backups.clone(),
            ..Default::default()
        });
    }
    t.keys = keys;
    t
}

/// Read this machine and say what it knows.
pub fn collect() -> TargetFacts {
    let mut errors = Vec::new();
    let tree = ostree::collect()
        .map_err(|e| errors.push(("deployments".to_string(), e.to_string())))
        .ok();
    let read = Cmd::host("sh")
        .args(["-c", &script()])
        .output()
        .map(|t| parse(&t))
        .map_err(|e| errors.push(("ssh, firewall and listeners".to_string(), e.to_string())))
        .ok();
    let os_release =
        std::fs::read_to_string(crate::paths::host("/etc/os-release")).unwrap_or_default();
    let mut t = facts(
        &os_release,
        tree.as_ref(),
        read.as_ref(),
        keys(&crate::paths::home().join(".ssh")),
        jiff::Timestamp::now().as_second(),
    );
    t.errors = errors;
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry_core::secaudit::{Answers, State, evaluate};

    const READ: &str = "@@addrs\n192.0.2.20 \n\
        @@sshd-on\ninactive\ninactive\n\
        @@fw\nactive\nFedoraWorkstation\n\
        @@listen\n\
        udp   UNCONN 0      0         127.0.0.54:53        0.0.0.0:*\n\
        tcp   LISTEN 0      4096         0.0.0.0:27500     0.0.0.0:*\n\
        tcp   LISTEN 0      128        127.0.0.1:631       0.0.0.0:*\n\
        @@units\nsshd.service\nfstrim.timer\nrestic-home.timer\norg.gnome.World.PikaBackup\n\
        org.mozilla.firefox\n\
        @@sshd\n";

    #[test]
    fn the_read_is_parsed_by_section() {
        let r = parse(READ);
        assert_eq!(r.addrs, ["192.0.2.20"]);
        assert_eq!(r.ssh_on, Some(false));
        assert_eq!(
            r.firewall,
            Some(HostFw {
                active: true,
                zone: Some("FedoraWorkstation".into())
            })
        );
        assert_eq!(r.listeners.len(), 3);
        let wide: Vec<u16> = r
            .listeners
            .iter()
            .filter(|l| l.wide)
            .map(|l| l.port)
            .collect();
        assert_eq!(wide, [27500]);
        assert_eq!(
            r.backups,
            ["org.gnome.World.PikaBackup", "restic-home.timer"]
        );
        // Fedora's sshd_config is root's to read: nothing can be said of it.
        assert_eq!(r.ssh, None);
        // No firewalld at all.
        let r = parse("@@fw\ninactive\n@@sshd-on\n");
        assert_eq!(
            r.firewall,
            Some(HostFw {
                active: false,
                zone: None
            })
        );
        assert_eq!(r.ssh_on, None);
        assert!(!script().contains("sudo"));
    }

    #[test]
    fn keys_are_counted_by_name_and_mode_and_never_read() {
        let d = std::env::temp_dir().join(format!("sentry-secfacts-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(keys(&d), None);
        std::fs::create_dir_all(&d).unwrap();
        let put = |name: &str, mode: u32| {
            let p = d.join(name);
            std::fs::write(&p, "x").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        put("id_ed25519", 0o600);
        put("id_ed25519.pub", 0o644);
        put("work", 0o644);
        put("work.pub", 0o644);
        put("known_hosts", 0o644);
        put("config", 0o644);
        assert_eq!(keys(&d), Some(Keys { total: 2, loose: 1 }));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn what_was_read_becomes_facts_the_rules_take() {
        let tree = ostree::parse(&crate::collectors::fixture("ostree/status.json")).unwrap();
        let booted = tree.booted().unwrap().timestamp;
        let t = facts(
            "NAME=Fedora\nPRETTY_NAME=\"Fedora Linux 44 (Silverblue)\"\n",
            Some(&tree),
            Some(&parse(READ)),
            Some(Keys { total: 1, loose: 0 }),
            booted + 3 * 86_400,
        );
        assert_eq!((t.id.as_str(), t.kind), (LOCAL, Kind::Local));
        let os = t.os.as_ref().unwrap();
        assert_eq!(os.name, "Fedora Linux 44 (Silverblue)");
        assert_eq!(os.updated_days, Some(3));
        assert!(!serde_json::to_string(&t).unwrap().contains("192.0.2.20"));
        let items = evaluate(&[t], &Answers::default(), jiff::civil::date(2026, 11, 21));
        let state = |id: &str| items.iter().find(|i| i.id == id).map(|i| i.state);
        assert_eq!(state("sec:firewall:local"), Some(State::Fine));
        assert_eq!(state("sec:ssh-password:local"), Some(State::Fine));
        assert_eq!(state("sec:keys:local"), Some(State::Fine));
        assert_eq!(state("sec:backup:local"), Some(State::Fine));
        assert_eq!(state("sec:restore:local"), Some(State::Ask));
        // Nothing read: nothing claimed.
        let t = facts("", None, None, None, 0);
        let items = evaluate(&[t], &Answers::default(), jiff::civil::date(2026, 11, 21));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].state, State::CouldNotCheck);
    }
}
