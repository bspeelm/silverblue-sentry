//! `sentry-server init <ssh-host>`: look around a server (read-only) and draft its entry for
//! server_config.yaml. Discovery and drafting are separate so the draft is testable.

use std::fmt::Write as _;

use serde::Deserialize;

use super::remote::{Remote, SrvError, SudoMode};
use crate::collectors::{disk, net};
use crate::exec::sh_quote;

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

/// The YAML entry for one server, with comments saying where each part came from.
pub fn draft(name: &str, ssh: &str, f: &Facts) -> String {
    let mut y = String::new();
    let has = |t: &str| f.tools.iter().any(|x| x == t);
    let _ = writeln!(
        y,
        "  # Drafted by `sentry-server init` from {} ({}).",
        ssh, f.os
    );
    let _ = writeln!(
        y,
        "  # Review every part: it's a starting point, not a verdict."
    );
    let _ = writeln!(y, "  {name}:");
    if ssh != name {
        let _ = writeln!(y, "    ssh: {ssh}");
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
    sudo.extend(["journalctl", "ss -tulpn"]);
    match f.sudo {
        Some(SudoMode::NoPasswd) => {
            let _ = writeln!(
                y,
                "    # Read-only commands run as `sudo -n` (sudo works without a password here)."
            );
            let _ = writeln!(y, "    sudo:");
            for s in &sudo {
                let _ = writeln!(y, "      - {s}");
            }
        }
        _ => {
            let _ = writeln!(
                y,
                "    # sudo needs a password here, so nothing runs as root while monitoring.\n    \
                 # Root-only panels (docker, SMART, system journal) say what's missing."
            );
            let _ = writeln!(y, "    sudo: []");
        }
    }

    let real: Vec<&(String, String)> = f
        .mounts
        .iter()
        .filter(|(t, fs)| {
            ["ext4", "ext3", "xfs", "btrfs", "zfs", "f2fs"].contains(&fs.as_str())
                && !t.starts_with("/boot")
        })
        .collect();
    if !real.is_empty() {
        let _ = writeln!(y, "    disks:");
        for (t, _) in real {
            let _ = writeln!(y, "      - mount: {t}");
        }
    }
    if has("smartctl") && !f.disks.is_empty() {
        let _ = writeln!(y, "    smart: [{}]", f.disks.join(", "));
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
        let _ = writeln!(
            y,
            "    # Running services: the ones installed by hand, plus well-known daemons."
        );
        let _ = writeln!(y, "    services: [{}]", services.join(", "));
    }

    let timers: Vec<&TimerFact> = f
        .timers
        .iter()
        .filter(|t| f.admin_units.contains(&t.unit))
        .collect();
    if !timers.is_empty() {
        let _ = writeln!(
            y,
            "    # Timers installed by hand; max_age is one period plus slack."
        );
        let _ = writeln!(y, "    timers:");
        for t in timers {
            match t.period_s {
                Some(p) => {
                    let _ = writeln!(y, "      - {{unit: {}, max_age: {}}}", t.unit, max_age(p));
                }
                None => {
                    let _ = writeln!(
                        y,
                        "      # - {{unit: {}, max_age: ?}}  (no last/next run to measure)",
                        t.unit
                    );
                }
            }
        }
    }

    if !f.compose.is_empty() {
        let _ = writeln!(y, "    compose:");
        for (n, file) in &f.compose {
            let _ = writeln!(y, "      - {{name: {n}, file: {file}}}");
        }
    } else if has("docker") && f.sudo != Some(SudoMode::NoPasswd) {
        let _ = writeln!(
            y,
            "    # compose: [{{name: …, file: …}}]  (couldn't list projects without sudo)"
        );
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
    if !ports.is_empty() || !loopback.is_empty() {
        let _ = writeln!(
            y,
            "    # Everything listening now. Remove what you didn't expect: it becomes a finding."
        );
        let _ = writeln!(y, "    listeners:");
        for e in ports.iter().map(|(_, e)| e.as_str()).chain(loopback) {
            let _ = writeln!(y, "      - \"{e}\"");
        }
    }
    y
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/server/{name}",
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

    #[test]
    fn draft_is_valid_config() {
        let f = Facts {
            os: "Debian GNU/Linux 12 (bookworm)".into(),
            admin_units: vec![
                "app.service".into(),
                "backup.service".into(),
                "backup.timer".into(),
            ],
            running: vec![
                "app.service".into(),
                "docker.service".into(),
                "dbus.service".into(),
            ],
            timers: parse_timers(&fx("list-timers.json")).unwrap(),
            sudo: Some(SudoMode::NoPasswd),
            tools: vec!["docker".into(), "smartctl".into()],
            compose: parse_compose_ls(&fx("compose-ls.json")).unwrap(),
            mounts: vec![
                ("/".into(), "ext4".into()),
                ("/boot/efi".into(), "vfat".into()),
                ("/srv/data".into(), "xfs".into()),
            ],
            disks: vec!["/dev/sda".into()],
            listeners: net::parse_listen(&fx("ss-tuln.txt")),
        };
        let d = draft("myserver", "admin@myserver.example", &f);
        let (file, warnings) = super::super::config::parse(&format!("servers:\n{d}")).expect(&d);
        assert!(warnings.is_empty(), "{warnings:?}");
        let s = &file.servers["myserver"];
        assert_eq!(s.ssh.as_deref(), Some("admin@myserver.example"));
        assert_eq!(s.services, ["app.service", "docker.service"], "{d}");
        assert_eq!(s.timers.len(), 1, "only admin timers: {d}");
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
    }
}
