//! `sentry-server init <ssh-host>`: look around a server (read-only) and draft its entry for
//! server_config.yaml. Discovery and drafting are separate so the draft is testable.

use serde::Deserialize;

use std::path::Path;

use super::config::{Compose, DiskRule, Server, ServerFile, TimerRule};
use super::remote::{Remote, SrvError, SudoMode};
use sentry_core::cfg::{Draft, Note, Saved, Seg, path_string};
use sentry_core::collectors::{disk, net};
use sentry_core::config::Dur;
use sentry_core::exec::sh_quote;

/// Vendor services worth watching when they run (admin-written units are always proposed).
const NOTABLE: &[&str] = &[
    "docker",
    "containerd",
    "podman",
    "ssh",
    "sshd",
    "smbd",
    "nmbd",
    "winbind",
    "fail2ban",
    "crowdsec",
    "nginx",
    "caddy",
    "apache2",
    "httpd",
    "haproxy",
    "postgresql",
    "mariadb",
    "mysql",
    "redis-server",
    "nfs-server",
    "cron",
    "crond",
    "smartmontools",
    "smartd",
    "zfs-zed",
    "tailscaled",
    "wg-quick",
    "unattended-upgrades",
];

/// Admin tools (smartctl) live in sbin, which isn't on an ordinary login's PATH everywhere.
pub const SBIN: &str = "PATH=\"$PATH:/usr/local/sbin:/usr/sbin:/sbin\"; ";

const TOOLS: &[&str] = &[
    "docker",
    "smartctl",
    "sensors",
    "nvidia-smi",
    "fail2ban-client",
    "cscli",
];

#[derive(Debug, Default, Clone)]
pub struct Facts {
    pub os: String,
    /// Unit files written by the admin (`/etc/systemd/system/*.{service,timer}`).
    pub admin_units: Vec<String>,
    pub running: Vec<String>,
    pub timers: Vec<TimerFact>,
    pub sudo: Option<SudoMode>,
    pub tools: Vec<String>,
    /// (project, compose file)
    pub compose: Vec<(String, String)>,
    /// (mount point, fstype)
    pub mounts: Vec<(String, String)>,
    /// Whole disks, `/dev/sda`.
    pub disks: Vec<String>,
    pub listeners: Vec<net::Listener>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TimerFact {
    pub unit: String,
    /// Time between the last and next run, when both are known.
    pub period_s: Option<u64>,
}

#[derive(Deserialize)]
struct TimerJson {
    unit: String,
    #[serde(default)]
    next: Option<u64>,
    #[serde(default)]
    last: Option<u64>,
}

#[derive(Deserialize)]
struct UnitJson {
    unit: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ComposeJson {
    name: String,
    config_files: String,
}

#[derive(Deserialize)]
struct Lsblk {
    blockdevices: Vec<BlockDev>,
}

#[derive(Deserialize)]
struct BlockDev {
    name: String,
    #[serde(rename = "type")]
    kind: String,
}

pub fn parse_timers(json: &str) -> Result<Vec<TimerFact>, String> {
    let v: Vec<TimerJson> = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(v.into_iter()
        .map(|t| TimerFact {
            period_s: match (t.last, t.next) {
                (Some(l), Some(n)) if l > 0 && n > l => Some((n - l) / 1_000_000),
                _ => None,
            },
            unit: t.unit,
        })
        .collect())
}

pub fn parse_units(json: &str) -> Result<Vec<String>, String> {
    let v: Vec<UnitJson> = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(v.into_iter().map(|u| u.unit).collect())
}

pub fn parse_compose_ls(json: &str) -> Result<Vec<(String, String)>, String> {
    let v: Vec<ComposeJson> = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(v.into_iter()
        .map(|c| {
            let first = c.config_files.split(',').next().unwrap_or("").to_string();
            (c.name, first)
        })
        .collect())
}

pub fn parse_lsblk(json: &str) -> Result<Vec<String>, String> {
    let v: Lsblk = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(v.blockdevices
        .into_iter()
        .filter(|d| d.kind == "disk" && !d.name.starts_with("zram") && !d.name.starts_with("loop"))
        .map(|d| format!("/dev/{}", d.name))
        .collect())
}

/// Look around, read-only. Parts that fail are left out of the draft rather than failing it.
pub fn discover(r: &Remote) -> Result<Facts, SrvError> {
    let mut f = Facts {
        os: r
            .output(&r.sh(". /etc/os-release && echo \"$PRETTY_NAME\""))?
            .trim()
            .to_string(),
        ..Default::default()
    };
    let units = r.output(&r.sh(
        "find /etc/systemd/system -maxdepth 1 -type f \\( -name '*.service' -o -name '*.timer' \\) -printf '%f\\n'",
    ))?;
    f.admin_units = units.lines().map(str::to_string).collect();
    f.admin_units.sort();
    if let Ok(j) = r.output(&r.cmd("systemctl").args([
        "list-units",
        "--type=service",
        "--state=running",
        "--output=json",
        "--no-pager",
    ])) {
        f.running = parse_units(&j).unwrap_or_default();
    }
    if let Ok(j) =
        r.output(
            &r.cmd("systemctl")
                .args(["list-timers", "--all", "--output=json", "--no-pager"]),
        )
    {
        f.timers = parse_timers(&j).unwrap_or_default();
    }
    f.sudo = r.sudo_mode().ok();
    let probe = TOOLS
        .iter()
        .map(|t| {
            format!(
                "command -v {} >/dev/null && echo {}",
                sh_quote(t),
                sh_quote(t)
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    f.tools = r
        .sh(&format!("{SBIN}{probe}; true"))
        .output()
        .map(|o| o.lines().map(str::to_string).collect())
        .unwrap_or_default();
    if f.sudo == Some(SudoMode::NoPasswd) && f.tools.iter().any(|t| t == "docker") {
        let c = r
            .cmd("sudo")
            .args(["-n", "docker", "compose", "ls", "--all", "--format", "json"]);
        if let Ok(j) = r.output(&c) {
            f.compose = parse_compose_ls(&j).unwrap_or_default();
        }
    }
    if let Ok(j) = r.output(&r.cmd("findmnt").args([
        "-J",
        "-b",
        "--real",
        "-o",
        "TARGET,SOURCE,FSTYPE,SIZE,USED",
    ])) {
        f.mounts = disk::parse(&j)
            .map(|m| m.into_iter().map(|m| (m.target, m.fstype)).collect())
            .unwrap_or_default();
    }
    if let Ok(j) = r.output(&r.cmd("lsblk").args(["-J", "-d", "-o", "NAME,TYPE"])) {
        f.disks = parse_lsblk(&j).unwrap_or_default();
    }
    if let Ok(t) = r.output(&r.cmd("ss").arg("-tulnH")) {
        f.listeners = net::parse_listen(&t);
    }
    Ok(f)
}

/// `max_age` for a timer that runs every `period_s`: one period plus a tenth (at least 10
/// minutes), rounded up to whole hours from an hour on, to whole minutes below.
pub fn max_age(period_s: u64) -> String {
    let s = period_s + (period_s / 10).max(600);
    if s >= 3600 {
        format!("{}h", s.div_ceil(3600))
    } else {
        format!("{}m", s.div_ceil(60))
    }
}

/// The path of one of the entry's settings: `servers.<name>.<field>`.
fn at(name: &str, field: &str) -> String {
    format!(
        "{}.{field}",
        path_string(&[Seg::Key("servers".into()), Seg::Key(name.into())])
    )
}

/// The entry for one server, and notes saying where each part came from (what the drafted
/// text's comments used to say), each at the setting it is about.
pub fn draft(name: &str, ssh: &str, f: &Facts) -> Draft<Server> {
    let mut s = Server::default();
    let mut notes = vec![
        Note::whole(format!(
            "Drafted by `sentry-server init` from {ssh} ({}).",
            f.os
        )),
        Note::whole("Review every part: it's a starting point, not a verdict."),
    ];
    let has = |t: &str| f.tools.iter().any(|x| x == t);
    if ssh != name {
        s.ssh = Some(ssh.to_string());
    }

    let mut sudo: Vec<&str> = Vec::new();
    if has("docker") {
        sudo.extend([
            "docker ps",
            "docker inspect",
            "docker logs",
            "docker compose ls",
            "docker stats",
        ]);
    }
    if has("smartctl") {
        sudo.push("smartctl");
    }
    if has("fail2ban-client") {
        sudo.push("fail2ban-client status");
    }
    // CrowdSec is here: its read-only lists (sentry never changes it).
    if has("cscli") {
        sudo.extend([
            "cscli decisions list",
            "cscli alerts list",
            "cscli hub list",
            "cscli bouncers list",
            "cscli metrics",
        ]);
    }
    sudo.extend(["journalctl", "ss -tulpn"]);
    match f.sudo {
        Some(SudoMode::NoPasswd) => {
            s.sudo = sudo.iter().map(|x| x.to_string()).collect();
            notes.push(Note::on(
                &at(name, "sudo"),
                "read-only commands run as `sudo -n` (sudo works without a password here).",
            ));
        }
        _ => notes.push(Note::on(
            &at(name, "sudo"),
            "sudo asks for a password here: the allowlist is empty, so nothing runs as root \
             while monitoring. Root-only panels (docker, SMART, system journal) say what's \
             missing; `I` reads them once with your password.",
        )),
    }

    s.disks = f
        .mounts
        .iter()
        .filter(|(t, fs)| {
            ["ext4", "ext3", "xfs", "btrfs", "zfs", "f2fs"].contains(&fs.as_str())
                && !t.starts_with("/boot")
        })
        .map(|(t, _)| DiskRule {
            mount: t.clone(),
            warn: Server::default_warn(),
            crit: Server::default_crit(),
        })
        .collect();
    if has("smartctl") {
        s.smart = f.disks.clone();
    }

    let timer_bases: Vec<&str> = f
        .admin_units
        .iter()
        .filter_map(|u| u.strip_suffix(".timer"))
        .collect();
    let mut services: Vec<String> = f
        .admin_units
        .iter()
        .filter(|u| u.ends_with(".service"))
        .filter(|u| !timer_bases.contains(&u.trim_end_matches(".service")))
        .filter(|u| f.running.contains(u))
        .cloned()
        .collect();
    let notable: Vec<String> = f
        .running
        .iter()
        .filter(|u| NOTABLE.contains(&u.trim_end_matches(".service")))
        .filter(|u| !services.contains(u))
        .cloned()
        .collect();
    services.extend(notable);
    services.sort();
    if !services.is_empty() {
        notes.push(Note::on(
            &at(name, "services"),
            "the running services installed by hand, plus well-known daemons.",
        ));
    }
    s.services = services;

    let timers: Vec<&TimerFact> = f
        .timers
        .iter()
        .filter(|t| f.admin_units.contains(&t.unit))
        .collect();
    if !timers.is_empty() {
        notes.push(Note::on(
            &at(name, "timers"),
            "timers installed by hand; max_age is one period plus slack.",
        ));
    }
    for t in timers {
        match t.period_s.and_then(|p| max_age(p).parse::<Dur>().ok()) {
            Some(max_age) => s.timers.push(TimerRule {
                unit: t.unit.clone(),
                max_age,
            }),
            None => notes.push(Note::on(
                &at(name, "timers"),
                format!(
                    "not taken: {} (no last/next run to measure its max_age by)",
                    t.unit
                ),
            )),
        }
    }

    s.compose = f
        .compose
        .iter()
        .map(|(n, file)| Compose {
            name: n.clone(),
            file: file.clone(),
        })
        .collect();
    if s.compose.is_empty() && has("docker") && f.sudo != Some(SudoMode::NoPasswd) {
        notes.push(Note::on(
            &at(name, "compose"),
            "couldn't list the compose projects without sudo: add them as {name, file}.",
        ));
    }

    let mut ports: Vec<(u32, String)> = Vec::new();
    let mut loopback = Vec::new();
    for l in &f.listeners {
        if l.addr.starts_with("127.") {
            loopback.push("127.0.0.1:*/*");
        } else if l.addr == "[::1]" {
            loopback.push("[::1]:*/*");
        } else if l.proto == "udp" && (l.port == "68" || l.port == "546") {
            // DHCP clients (v4, v6) listen too, but they aren't services.
        } else if let Ok(p) = l.port.parse::<u32>() {
            let e = format!("*:{p}/*");
            if !ports.iter().any(|(_, x)| *x == e) {
                ports.push((p, e));
            }
        }
    }
    ports.sort();
    loopback.sort();
    loopback.dedup();
    s.listeners = ports
        .into_iter()
        .map(|(_, e)| e)
        .chain(loopback.into_iter().map(str::to_string))
        .collect();
    if !s.listeners.is_empty() {
        notes.push(Note::on(
            &at(name, "listeners"),
            "everything listening now. Remove what you didn't expect: it becomes a finding.",
        ));
    }
    Draft { entry: s, notes }
}

/// Add `entry` as `name` to the file at `path` (made when it isn't there), through `cfg`: the
/// whole file is written again from what it says, a copy of it before kept. A name the file
/// has, or a file that doesn't parse, writes nothing.
pub fn write(path: &Path, name: &str, entry: &Server) -> Result<Saved, String> {
    sentry_core::cfg::update::<ServerFile>(path, |f| {
        if f.servers.contains_key(name) {
            return Err(format!(
                "{} already has `{name}`; not touching it. Use --name to add it under another name.",
                path.display()
            ));
        }
        f.servers.insert(name.to_string(), entry.clone());
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/../../tests/fixtures/server/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn parses_discovery_output() {
        let t = parse_timers(&fx("list-timers.json")).unwrap();
        assert_eq!(
            t[0],
            TimerFact {
                unit: "backup.timer".into(),
                period_s: Some(86_400)
            }
        );
        assert!(
            t.iter()
                .any(|t| t.unit == "app-sync.timer" && t.period_s == Some(300))
        );
        let c = parse_compose_ls(&fx("compose-ls.json")).unwrap();
        assert_eq!(
            c,
            [(
                "stack".to_string(),
                "/home/admin/stack/compose.yaml".to_string()
            )]
        );
        let d = parse_lsblk(&fx("lsblk.json")).unwrap();
        assert_eq!(d, ["/dev/sda", "/dev/sdb"]);
        assert!(
            parse_units(&fx("units-running.json"))
                .unwrap()
                .contains(&"app.service".to_string())
        );
    }

    #[test]
    fn max_age_has_slack() {
        assert_eq!(max_age(86_400), "27h");
        assert_eq!(max_age(300), "15m");
        assert_eq!(max_age(3600), "2h");
    }

    /// The fixture's server, with sudo as given.
    fn facts(sudo: Option<SudoMode>) -> Facts {
        Facts {
            os: "Debian GNU/Linux 12 (bookworm)".into(),
            admin_units: vec![
                "app.service".into(),
                "backup.service".into(),
                "backup.timer".into(),
                "app-sync.timer".into(),
            ],
            running: vec![
                "app.service".into(),
                "docker.service".into(),
                "dbus.service".into(),
            ],
            timers: parse_timers(&fx("list-timers.json")).unwrap(),
            sudo,
            tools: vec!["docker".into(), "smartctl".into()],
            compose: if sudo == Some(SudoMode::NoPasswd) {
                parse_compose_ls(&fx("compose-ls.json")).unwrap()
            } else {
                vec![]
            },
            mounts: vec![
                ("/".into(), "ext4".into()),
                ("/boot/efi".into(), "vfat".into()),
                ("/srv/data".into(), "xfs".into()),
            ],
            disks: vec!["/dev/sda".into()],
            listeners: net::parse_listen(&fx("ss-tuln.txt")),
        }
    }

    fn written(name: &str, d: &Draft<Server>) -> String {
        let file = super::super::config::ServerFile {
            servers: [(name.to_string(), d.entry.clone())].into(),
        };
        sentry_core::cfg::render(&file).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn draft_is_valid_config() {
        let d = draft(
            "myserver",
            "admin@myserver.example",
            &facts(Some(SudoMode::NoPasswd)),
        );
        let text = written("myserver", &d);
        let (file, warnings) = super::super::config::parse(&text).expect(&text);
        assert!(warnings.is_empty(), "{warnings:?}");
        let s = &file.servers["myserver"];
        assert_eq!(s, &d.entry);
        assert_eq!(s.ssh.as_deref(), Some("admin@myserver.example"));
        assert_eq!(s.services, ["app.service", "docker.service"], "{text}");
        assert_eq!(s.timers.len(), 2, "only admin timers: {text}");
        assert_eq!(s.timers[0].max_age.to_string(), "27h");
        assert_eq!(
            s.disks.iter().map(|d| d.mount.as_str()).collect::<Vec<_>>(),
            ["/", "/srv/data"]
        );
        assert_eq!(s.compose[0].name, "stack");
        assert!(s.sudo.contains(&"docker ps".to_string()));
        assert!(s.listeners.contains(&"*:443/*".to_string()));
        assert!(!s.listeners.contains(&"*:68/*".to_string()), "DHCP client");
        assert!(s.listeners.contains(&"127.0.0.1:*/*".to_string()));
        assert!(super::super::config::lint("myserver", s).is_empty());
        insta::assert_snapshot!(format!("{text}\n{}", d.note_lines().join("\n")));
    }

    #[test]
    fn without_sudo_the_notes_say_what_couldnt_be_drafted() {
        let mut f = facts(None);
        f.timers.retain(|t| t.unit != "app-sync.timer");
        f.timers.push(TimerFact {
            unit: "app-sync.timer".into(),
            period_s: None,
        });
        let d = draft("my.server", "my.server", &f);
        assert!(d.entry.sudo.is_empty() && d.entry.ssh.is_none() && d.entry.compose.is_empty());
        let notes = d.note_lines();
        let has = |s: &str| notes.iter().any(|n| n.contains(s));
        assert!(
            has(
                "· servers.\"my.server\".sudo: sudo asks for a password here: the allowlist is empty"
            ),
            "{notes:#?}"
        );
        assert!(
            has("servers.\"my.server\".timers: not taken: app-sync.timer"),
            "{notes:#?}"
        );
        assert!(
            has("servers.\"my.server\".compose: couldn't list the compose projects"),
            "{notes:#?}"
        );
        let text = written("my.server", &d);
        let (file, _) = super::super::config::parse(&text).unwrap();
        assert_eq!(file.servers["my.server"], d.entry);
    }

    /// What the text draft (before the typed one) wrote for the same facts, word for word.
    const OLD_NOPASSWD: &str = r#"servers:
  # Drafted by `sentry-server init` from admin@myserver.example (Debian GNU/Linux 12 (bookworm)).
  # Review every part: it's a starting point, not a verdict.
  myserver:
    ssh: admin@myserver.example
    # Read-only commands run as `sudo -n` (sudo works without a password here).
    sudo:
      - docker ps
      - docker inspect
      - docker logs
      - docker compose ls
      - docker stats
      - smartctl
      - journalctl
      - ss -tulpn
    disks:
      - mount: /
      - mount: /srv/data
    smart: [/dev/sda]
    # Running services: the ones installed by hand, plus well-known daemons.
    services: [app.service, docker.service]
    # Timers installed by hand; max_age is one period plus slack.
    timers:
      - {unit: backup.timer, max_age: 27h}
      - {unit: app-sync.timer, max_age: 15m}
    compose:
      - {name: stack, file: /home/admin/stack/compose.yaml}
    # Everything listening now. Remove what you didn't expect: it becomes a finding.
    listeners:
      - "*:22/*"
      - "*:443/*"
      - "127.0.0.1:*/*"
"#;

    const OLD_PASSWORD: &str = r#"servers:
  # Drafted by `sentry-server init` from my.server (Debian GNU/Linux 12 (bookworm)).
  # Review every part: it's a starting point, not a verdict.
  my.server:
    # sudo needs a password here, so nothing runs as root while monitoring.
    # Root-only panels (docker, SMART, system journal) say what's missing.
    sudo: []
    disks:
      - mount: /
      - mount: /srv/data
    smart: [/dev/sda]
    # Running services: the ones installed by hand, plus well-known daemons.
    services: [app.service, docker.service]
    # Timers installed by hand; max_age is one period plus slack.
    timers:
      - {unit: backup.timer, max_age: 27h}
      # - {unit: app-sync.timer, max_age: ?}  (no last/next run to measure)
    # compose: [{name: …, file: …}]  (couldn't list projects without sudo)
    # Everything listening now. Remove what you didn't expect: it becomes a finding.
    listeners:
      - "*:22/*"
      - "*:443/*"
      - "127.0.0.1:*/*"
"#;

    /// The typed draft proposes exactly what the text draft did: the same services, timers,
    /// disks, compose projects, sudo entries and listeners.
    #[test]
    fn the_typed_draft_is_what_the_text_draft_was() {
        let ok = draft(
            "myserver",
            "admin@myserver.example",
            &facts(Some(SudoMode::NoPasswd)),
        );
        let (old, _) = super::super::config::parse(OLD_NOPASSWD).unwrap();
        assert_eq!(old.servers["myserver"], ok.entry);
        let mut f = facts(None);
        f.timers.retain(|t| t.unit != "app-sync.timer");
        f.timers.push(TimerFact {
            unit: "app-sync.timer".into(),
            period_s: None,
        });
        let pw = draft("my.server", "my.server", &f);
        let (old, _) = super::super::config::parse(OLD_PASSWORD).unwrap();
        assert_eq!(old.servers["my.server"], pw.entry);
    }

    #[test]
    fn written_into_a_file_by_hand_it_keeps_a_copy_and_says_so() {
        let dir = sentry_core::paths::config_dir().join("init-write");
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("server_config.yaml");
        let d = draft(
            "myserver",
            "admin@myserver.example",
            &facts(Some(SudoMode::NoPasswd)),
        );
        // No file yet: made, nothing kept.
        let saved = write(&p, "myserver", &d.entry).unwrap();
        assert_eq!((saved.backup, saved.handwritten), (None, false));
        let (f, _) = super::super::config::parse(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(f.servers["myserver"], d.entry);
        assert!(super::super::config::lint("myserver", &f.servers["myserver"]).is_empty());
        // The same name again: refused, the file as it was.
        let before = std::fs::read_to_string(&p).unwrap();
        assert!(
            write(&p, "myserver", &d.entry)
                .unwrap_err()
                .contains("already has `myserver`")
        );
        assert_eq!(std::fs::read_to_string(&p).unwrap(), before);
        // A file written by hand: the entry is added to what it says, the copy keeps the rest.
        let hand = "# mine\nservers:\n  other:\n    ssh: o   # a note\n    sudoo: [x]\n";
        std::fs::write(&p, hand).unwrap();
        let saved = write(&p, "myserver", &d.entry).unwrap();
        assert!(saved.handwritten);
        assert_eq!(saved.dropped.len(), 1, "{:?}", saved.dropped);
        let b = saved.backup.clone().expect("a copy");
        assert_eq!(std::fs::read_to_string(&b).unwrap(), hand);
        let lines = saved.lines();
        assert!(
            lines[0].starts_with("kept a copy of the file before: "),
            "{lines:?}"
        );
        assert!(
            lines[1].contains("comments and layout were not kept"),
            "{lines:?}"
        );
        assert!(lines[2].contains("servers.other.sudoo"), "{lines:?}");
        let (f, w) = super::super::config::parse(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert!(w.is_empty());
        assert_eq!(f.servers.len(), 2);
        assert_eq!(f.servers["other"].ssh.as_deref(), Some("o"));
        // A file that doesn't parse: nothing written.
        std::fs::write(&p, "servers: [\n").unwrap();
        assert!(write(&p, "x", &d.entry).is_err());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "servers: [\n");
    }
}
