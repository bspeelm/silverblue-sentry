//! Findings from a report: what's worth a look on this machine, each with plain-language
//! what / why / fix text. Pure: no I/O, so every rule is unit-tested.
//!
//! Severity: `High` = check this (unknown or newly changed exposure), `Medium` = review it,
//! `Low` = information about choices the user has probably made deliberately.

use std::collections::{BTreeMap, BTreeSet};

use super::known;
use super::{Finding, Report, Sev};
use crate::baseline::Baseline;
use crate::collectors::flatpak::gl_version_for_driver;
use crate::config::Config;
use crate::fmt;

/// Whether the (current) baseline suppresses `f`. Listener findings are baselined through
/// `listeners` (so the Network screen agrees): a service group counts as expected when every
/// one of its addresses is. Everything else goes through `findings` (globs allowed).
pub fn is_expected(f: &Finding, b: &Baseline) -> bool {
    if !f.listeners.is_empty() {
        return f.listeners.iter().all(|k| b.has_listener(k));
    }
    match f.id.strip_prefix("listener:") {
        // Reports written before listener groups existed.
        Some(key) => b.has_listener(key),
        None => b.findings.iter().any(|x| crate::baseline::glob(x, &f.id)),
    }
}

/// Short stable hash for ids built from free text (rc lines).
fn hash(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:08x}", h as u32)
}

/// Builder for one finding.
struct F {
    id: String,
    severity: Sev,
    category: &'static str,
    message: String,
    what: String,
    why: String,
    fix: String,
    evidence: String,
    listeners: Vec<String>,
}

impl F {
    fn new(
        id: impl Into<String>,
        severity: Sev,
        category: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            severity,
            category,
            message: message.into(),
            what: String::new(),
            why: String::new(),
            fix: String::new(),
            evidence: String::new(),
            listeners: Vec::new(),
        }
    }
    fn what(mut self, s: impl Into<String>) -> Self {
        self.what = s.into();
        self
    }
    fn why(mut self, s: impl Into<String>) -> Self {
        self.why = s.into();
        self
    }
    fn fix(mut self, s: impl Into<String>) -> Self {
        self.fix = s.into();
        self
    }
    fn evidence(mut self, s: impl Into<String>) -> Self {
        self.evidence = s.into();
        self
    }
    fn done(self) -> Finding {
        Finding {
            id: self.id,
            severity: self.severity,
            category: self.category.into(),
            message: self.message,
            evidence: self.evidence,
            expected: false,
            what: self.what,
            why: self.why,
            fix: self.fix,
            listeners: self.listeners,
        }
    }
}

/// Short reach label for a message: "all networks", "LAN", "VPN", "link-local", "private net".
fn reach(addr: &str) -> &'static str {
    let s = known::scope(addr);
    if s.starts_with("every network") {
        "all networks"
    } else if s.starts_with("the VPN") {
        "VPN"
    } else if s.starts_with("the local link") {
        "link-local"
    } else if s.starts_with("your LAN") {
        "LAN"
    } else {
        "private net"
    }
}

fn listeners(r: &Report, out: &mut Vec<Finding>) {
    // Group reachable listeners by service (or by proto/port when unknown).
    struct Group<'a> {
        svc: Option<&'static known::Service>,
        proto: String,
        port: u16,
        procs: BTreeSet<&'a str>,
        keys: Vec<(&'a str, &'a str)>,
    }
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    for l in r.sections.listeners.iter().flatten().filter(|l| !l.local) {
        let (_, port, proc_) = known::split_key(&l.key);
        let svc = known::service(&l.proto, port);
        let gid = match svc {
            Some(s) => format!("svc:{}", s.name),
            None => format!("port:{}:{port}", l.proto),
        };
        let g = groups.entry(gid).or_insert_with(|| Group {
            svc,
            proto: l.proto.clone(),
            port,
            procs: BTreeSet::new(),
            keys: Vec::new(),
        });
        g.procs.insert(proc_);
        g.keys.push((&l.proto, &l.key));
    }
    for (gid, g) in groups {
        let mut reaches: Vec<&str> = g
            .keys
            .iter()
            .map(|(_, k)| reach(known::split_key(k).0))
            .collect();
        reaches.sort_unstable();
        reaches.dedup();
        let open_to = if reaches.contains(&"all networks") {
            "all networks".to_string()
        } else if reaches.len() > 2 {
            "several networks".to_string()
        } else {
            reaches.join(" + ")
        };
        let scopes: Vec<String> = {
            let mut v: Vec<String> = g
                .keys
                .iter()
                .map(|(_, k)| known::scope(known::split_key(k).0))
                .collect();
            v.sort();
            v.dedup();
            v
        };
        let root_owned = g.procs.contains("?");
        let named: Vec<&str> = g.procs.iter().copied().filter(|p| *p != "?").collect();
        let evidence = g
            .keys
            .iter()
            .map(|(p, k)| format!("{p:<4} {k}"))
            .collect::<Vec<_>>()
            .join("\n");
        let f = match g.svc {
            Some(svc) => {
                let sev = if !svc.normal && svc.remote_access && open_to == "all networks" {
                    Sev::Medium
                } else if svc.normal || !svc.remote_access {
                    Sev::Low
                } else {
                    Sev::Medium
                };
                F::new(format!("listener:{gid}"), sev, "listener", format!("{} · open to {open_to}", svc.name))
                    .what(svc.what)
                    .why(format!(
                        "Reachable from {}. {}",
                        scopes.join("; "),
                        if svc.normal {
                            "It's a standard Fedora desktop service, listed once so you can confirm you expect it."
                        } else {
                            "Anything other machines can connect to is worth confirming."
                        }
                    ))
                    .fix(format!("{} If it's expected, press b.", svc.advice))
            }
            None => {
                let who = if named.is_empty() {
                    "Its process belongs to root, and sentry runs without root, so it can't see the name.".to_string()
                } else {
                    format!("Process: {}.", named.join(", "))
                };
                let sev = if root_owned { Sev::High } else { Sev::Medium };
                let label = if named.is_empty() {
                    format!("Unknown service on {}/{}", g.proto, g.port)
                } else {
                    format!("{} on {}/{}", named.join(", "), g.proto, g.port)
                };
                F::new(format!("listener:{gid}"), sev, "listener", format!("{label} · open to {open_to}"))
                    .what(format!("Something is accepting {} connections on port {}. {who}", g.proto, g.port))
                    .why(format!(
                        "Reachable from {}, and sentry doesn't recognise the port.",
                        scopes.join("; ")
                    ))
                    .fix(format!(
                        "Find out what it is: `sudo ss -tulpn 'sport = :{}'`. If it's yours and expected, press b; if not, stop the service that owns it.",
                        g.port
                    ))
            }
        };
        let mut f = f.evidence(evidence);
        f.listeners = g.keys.iter().map(|(_, k)| k.to_string()).collect();
        f.listeners.dedup(); // tcp + udp on one address share a baseline key
        out.push(f.done());
    }
}

fn flatpaks(r: &Report, prev: Option<&Report>, out: &mut Vec<Finding>) {
    let Some(fp) = &r.sections.flatpak else {
        return;
    };
    let prev_apps: BTreeMap<&str, &super::FpApp> = prev
        .and_then(|p| p.sections.flatpak.as_ref())
        .map(|f| f.apps.iter().map(|a| (a.id.as_str(), a)).collect())
        .unwrap_or_default();
    let since = prev.map(|p| fmt::date(p.taken_at)).unwrap_or_default();
    let mut access: Vec<String> = Vec::new();
    for a in &fp.apps {
        let before = prev_apps.get(a.id.as_str());
        for flag in a.flags.iter().filter(|f| *f != "devices=all") {
            let gained = prev.is_some() && !before.is_some_and(|p| p.flags.contains(flag));
            let talk = flag.starts_with("talk:");
            let perm = if talk {
                flag.replacen("talk:", "talk-name=", 1)
            } else {
                format!("filesystem={flag}")
            };
            let reach = match flag.as_str() {
                "host" => "every file you can read, outside its sandbox",
                "host-os" => "the system's files (/usr, /etc)",
                "home" => "your whole home folder",
                _ => "the Flatpak service itself, so it can start commands outside its sandbox",
            };
            if gained {
                out.push(
                    F::new(format!("flatpak-perm:{}:{flag}", a.id), Sev::High, "flatpak", format!("{} gained {perm}", a.id))
                        .what(format!("{} can now access {reach}.", a.id))
                        .why(format!("This permission is new since the audit on {since}: an app update or an override added it."))
                        .fix(format!(
                            "Check `flatpak info --show-permissions {id}`. To take it back: Flatseal (Flatpaks tab, o) or `flatpak override --user --no{arg} {id}`. If you expect it, press b.",
                            id = a.id,
                            arg = if talk { format!("-talk-name={}", flag.trim_start_matches("talk:")) } else { format!("filesystem={flag}") }
                        ))
                        .evidence(format!("[Context] filesystems={};", a.filesystems.join(";")))
                        .done(),
                );
            } else if talk {
                out.push(
                    F::new(format!("flatpak-perm:{}:{flag}", a.id), Sev::Medium, "flatpak", format!("{} can run commands outside its sandbox", a.id))
                        .what(format!("{} may talk to the Flatpak service ({perm}), which lets it start commands on the host.", a.id))
                        .why("That's effectively no sandbox. Some apps (IDEs, Flatseal-like tools) need it; most don't.")
                        .fix(format!("If you don't know why it needs this, remove it in Flatseal or `flatpak override --user --no-talk-name=org.freedesktop.Flatpak {}`. Otherwise press b.", a.id))
                        .done(),
                );
            } else {
                access.push(format!("{:<40} {perm}  ({})", a.id, a.origin));
            }
        }
        if a.unverified {
            let url = fp
                .remotes
                .iter()
                .find(|(n, _)| *n == a.origin)
                .map_or("?", |(_, u)| u.as_str());
            out.push(
                F::new(format!("flatpak-origin:{}", a.id), Sev::Medium, "flatpak", format!("{} comes from {}", a.id, a.origin))
                    .what(format!("{} was installed from the remote \"{}\" ({url}).", a.id, a.origin))
                    .why("That remote isn't Flathub or Fedora, so nobody besides its owner reviews what it ships.")
                    .fix("Fine if you trust that source; add it to [flatpak] trusted_origins in config.toml, or press b. Otherwise reinstall the app from Flathub.")
                    .done(),
            );
        }
    }
    if !access.is_empty() {
        out.push(
            F::new("flatpak-fs-access", Sev::Low, "flatpak", format!("{} apps can read your files", access.len()))
                .what("These apps' sandboxes include your home folder or the whole filesystem.")
                .why("Normal for file managers, editors, viewers and disk tools (GNOME's own apps do this), but the sandbox doesn't protect those files from them.")
                .fix("Look down the list; tighten any app that shouldn't need it in Flatseal (Flatpaks tab, o). Press b to accept the set; an app gaining access later is reported on its own.")
                .evidence(access.join("\n"))
                .done(),
        );
    }
    if let Some(unused) = fp.unused.as_ref().filter(|u| !u.is_empty()) {
        out.push(
            F::new(
                "flatpak-unused",
                Sev::Low,
                "flatpak",
                format!("{} unused Flatpak runtime(s)", unused.len()),
            )
            .what("Runtimes no installed app uses any more.")
            .why("They only take disk space.")
            .fix("Cleanup (C on Maintenance) removes them (`flatpak uninstall --unused`).")
            .evidence(unused.join("\n"))
            .done(),
        );
    }
    if let Some(driver) = &r.host.driver {
        let want = gl_version_for_driver(driver);
        for (kind, ver) in fp.gl_nvidia.iter().filter(|(_, v)| *v != want) {
            let ext = format!("org.freedesktop.Platform.{kind}.nvidia-{ver}");
            out.push(
                F::new(format!("flatpak-gl-stale:{ext}"), Sev::Low, "flatpak", format!("Old {kind}.nvidia-{ver} driver extension"))
                    .what(format!("Flatpak's copy of an older NVIDIA driver ({ver}); the host runs {driver}."))
                    .why("Left behind after a driver update; `flatpak uninstall --unused` doesn't remove these. Several hundred MB each.")
                    .fix("Cleanup (C on Maintenance) offers to remove it.")
                    .evidence(ext)
                    .done(),
            );
        }
    }
}

/// Vendor name for a third-party repo file (`rpmfusion-free-updates.repo` → RPM Fusion).
fn vendor(file: &str) -> (String, &'static str) {
    let stem = file.trim_end_matches(".repo");
    if stem.starts_with("rpmfusion") {
        return (
            "RPM Fusion".into(),
            "the NVIDIA driver, codecs and Steam packages",
        );
    }
    match stem {
        "brave-browser" => ("Brave".into(), "the Brave browser"),
        "vscode" => ("VS Code".into(), "Visual Studio Code"),
        s if s.starts_with("google-chrome") => ("Google Chrome".into(), "Chrome"),
        s => (s.to_string(), "packages you installed from it"),
    }
}

fn repos(r: &Report, prev: Option<&Report>, out: &mut Vec<Finding>) {
    let Some(repos) = &r.sections.repos else {
        return;
    };
    let prev_files: Option<BTreeSet<&str>> =
        prev.and_then(|p| p.sections.repos.as_ref()).map(|rs| {
            rs.iter()
                .filter(|r| r.enabled)
                .map(|r| r.file.as_str())
                .collect()
        });
    let mut vendors: BTreeMap<String, (&'static str, Vec<String>)> = BTreeMap::new();
    let mut files: BTreeMap<&str, Vec<&super::RepoSec>> = BTreeMap::new();
    for r in repos.iter().filter(|r| r.enabled && r.third_party) {
        files.entry(&r.file).or_default().push(r);
    }
    for (file, rs) in files {
        let sections = rs
            .iter()
            .map(|r| format!("{file} [{}] {}", r.section, r.url))
            .collect::<Vec<_>>()
            .join("\n");
        if file == "updates-master.repo" {
            out.push(
                F::new("repo:updates-master.repo", Sev::Medium, "repos", "Temporary master-mirror repo still enabled")
                    .what("updates-master.repo points rpm-ostree at Fedora's master mirror. It's the workaround for a lagging mirror during an upgrade.")
                    .why("It's meant to be removed once the upgrade is done; left in place, every transaction also pulls from the master mirror.")
                    .fix("Once nvidia-smi works after the upgrade: `sudo rm /etc/yum.repos.d/updates-master.repo` (quick-update's last step offers this).")
                    .evidence(sections)
                    .done(),
            );
            continue;
        }
        if rs.iter().any(|r| r.copr) {
            let new = prev_files.as_ref().is_some_and(|p| !p.contains(file));
            out.push(
                F::new(format!("repo:{file}"), if new { Sev::High } else { Sev::Medium }, "repos",
                    format!("{}COPR repo: {}", if new { "New " } else { "" }, file.trim_start_matches("_copr_").trim_start_matches("_copr:").trim_end_matches(".repo")))
                    .what("A COPR is a personal package repository built by one Fedora user.")
                    .why(if new { "It was enabled since the last audit. COPR packages aren't reviewed by Fedora." } else { "COPR packages aren't reviewed by Fedora, so you're trusting that one maintainer." })
                    .fix("Fine if you added it on purpose (press b). Otherwise remove the file in /etc/yum.repos.d and the packages you layered from it.")
                    .evidence(sections)
                    .done(),
            );
            continue;
        }
        let (name, provides) = vendor(file);
        let e = vendors.entry(name).or_insert((provides, Vec::new()));
        e.1.push(sections);
    }
    for (name, (provides, secs)) in vendors {
        let n = secs.len();
        out.push(
            F::new(format!("repos:vendor:{name}"), Sev::Low, "repos",
                if n > 1 { format!("{name} repos enabled ({n} files)") } else { format!("{name} repo enabled") })
                .what(format!("Third-party package repositories from {name}, which provide {provides}."))
                .why("You added these; listed once so you can confirm them. Packages from here can change your system on every upgrade.")
                .fix("If you still use them, press b. Otherwise remove the .repo files and the packages layered from them.")
                .evidence(secs.join("\n"))
                .done(),
        );
    }
}

pub fn derive(r: &Report, prev: Option<&Report>, b: &Baseline, cfg: &Config) -> Vec<Finding> {
    let mut out = Vec::new();
    let s = &r.sections;
    listeners(r, &mut out);
    flatpaks(r, prev, &mut out);
    repos(r, prev, &mut out);

    for c in s
        .containers
        .iter()
        .flatten()
        .filter(|c| c.stale && c.home_mount)
    {
        out.push(
            F::new(format!("container-stale-home:{}", c.name), Sev::Medium, "container", format!("{} unused for {}d, shares your home folder", c.name, c.idle_days))
                .what(format!("The {} container {} has been stopped for {} days and has your home folder mounted read-write.", c.kind, c.name, c.idle_days))
                .why("Anything inside it can read and change your files when it runs, and old containers miss updates.")
                .fix("Remove it if you're done with it (Containers tab, d). Its installed packages go with it; your home folder doesn't.")
                .evidence(format!("image {} · {}", c.image, c.state))
                .done(),
        );
    }

    if let Some(u) = &s.units {
        for f in &u.failed {
            let (scope, unit) = f.split_once(':').unwrap_or(("system", f));
            let user = if scope == "user" { " --user" } else { "" };
            out.push(
                F::new(format!("unit-failed:{f}"), Sev::Medium, "units", format!("{unit} failed"))
                    .what(format!("The {scope} service {unit} failed this boot."))
                    .why("A failed service can mean something isn't working; some failures are harmless.")
                    .fix(format!("`systemctl{user} status {unit}` and `journalctl{user} -u {unit} -b` show why. If it's harmless, press b."))
                    .done(),
            );
        }
    }

    for h in &s.shell {
        out.push(
            F::new(format!("shell:{}:{}:{}", h.file, h.pattern, hash(h.text.trim())), Sev::High, "shell", format!("~/{} line {} runs {}", h.file, h.line, h.pattern))
                .what(format!("Your shell startup file uses {} on line {}.", h.pattern, h.line))
                .why("Downloading or decoding and running code at every login is a classic persistence trick; usually it's just a tool's installer.")
                .fix("Read the line. If you recognise it, press b; if not, remove it.")
                .evidence(format!("~/{}:{}\n{}", h.file, h.line, h.text.trim()))
                .done(),
        );
    }

    if let Some(o) = &s.ostree {
        for v in &o.bad_signatures {
            out.push(
                F::new(format!("ostree-sig:{v}"), Sev::High, "ostree", format!("Deployment {v} has an invalid signature"))
                    .what(format!("The system image {v} doesn't verify against Fedora's signing key."))
                    .why("An image that fails verification may have been tampered with or corrupted.")
                    .fix("Don't boot it. Remove it (`rpm-ostree cleanup -r` if it's the rollback) and upgrade again.")
                    .done(),
            );
        }
    }

    if let Some(c) = &s.cache
        && c.bytes > cfg.audit.cache_warn_mb << 20
    {
        let top: Vec<String> = c
            .top
            .iter()
            .take(8)
            .map(|(n, b)| format!("~/.cache/{n:<20} {}", fmt::bytes(*b)))
            .collect();
        out.push(
            F::new("cache-size", Sev::Low, "cache", format!("~/.cache is {}", fmt::bytes(c.bytes)))
                .what(format!("Your cache folder is over the {} MB threshold.", cfg.audit.cache_warn_mb))
                .why("Caches are safe to delete but grow without limit.")
                .fix("Cleanup (C on Maintenance) lists the biggest folders; add names to [cleanup.cache] delete_dirs in config.toml to let it clear them.")
                .evidence(top.join("\n"))
                .done(),
        );
    }

    if let Some(j) = &s.journal
        && j.failed_logins > 0
    {
        out.push(
            F::new(
                "failed-logins",
                Sev::Low,
                "auth",
                format!("{} failed login(s) in the last 24 h", j.failed_logins),
            )
            .what("Password attempts that failed (login, sudo, polkit).")
            .why("Usually a mistyped password; many in a row can mean someone guessing.")
            .fix("`journalctl SYSLOG_FACILITY=10 --since -24h` shows them.")
            .done(),
        );
    }

    for f in &mut out {
        f.expected = is_expected(f, b);
    }
    // Open findings first, by severity; expected ones sink to the bottom.
    out.sort_by(|a, b| {
        a.expected
            .cmp(&b.expected)
            .then(b.severity.cmp(&a.severity))
            .then(a.category.cmp(&b.category))
            .then(a.id.cmp(&b.id))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use crate::audit::test_report as report;

    fn app(id: &str, flags: &[&str]) -> FpApp {
        FpApp {
            id: id.into(),
            origin: "flathub".into(),
            installation: "system".into(),
            flags: flags.iter().map(|s| s.to_string()).collect(),
            filesystems: flags.iter().map(|s| s.to_string()).collect(),
            unverified: false,
        }
    }

    fn base(listeners: &[&str], findings: &[&str]) -> Baseline {
        Baseline {
            listeners: listeners.iter().map(|s| s.to_string()).collect(),
            findings: findings.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn ids(fs: &[Finding]) -> Vec<(&str, Sev, bool)> {
        fs.iter()
            .map(|f| (f.id.as_str(), f.severity, f.expected))
            .collect()
    }

    fn listen(proto: &str, key: &str) -> ListenSec {
        ListenSec {
            proto: proto.into(),
            key: key.into(),
            local: crate::collectors::net::is_local(key.rsplit_once(':').unwrap().0),
        }
    }

    /// The reachable listeners of a real Silverblue desktop (addresses scrubbed).
    fn desktop_listeners() -> Vec<ListenSec> {
        [
            ("tcp", "0.0.0.0:27999/?"),
            ("udp", "0.0.0.0:5353/?"),
            ("tcp", "0.0.0.0:5355/?"),
            ("udp", "0.0.0.0:5355/?"),
            ("udp", "10.64.0.2:3702/wsdd"),
            ("udp", "192.168.1.180:3702/wsdd"),
            ("udp", "[::]:5353/?"),
            ("tcp", "[::]:5355/?"),
            ("udp", "[::]:5355/?"),
            ("udp", "[fe80::aaaa:bbbb:cccc:dddd]%enp4s0:3702/wsdd"),
            ("udp", "[fe80::aaaa:bbbb:cccc:dddd]%enp4s0:546/?"),
            ("udp", "[fe80::1111:2222:3333:4444]%wg-vpn-server:3702/wsdd"),
            ("tcp", "127.0.0.1:631/?"),
        ]
        .iter()
        .map(|(p, k)| listen(p, k))
        .collect()
    }

    #[test]
    fn listeners_grouped_by_service_with_explanations() {
        let r = report(Sections {
            listeners: Some(desktop_listeners()),
            ..Default::default()
        });
        let f = derive(&r, None, &base(&[], &[]), &Config::default());
        let msgs: Vec<(&str, Sev)> = f.iter().map(|f| (f.message.as_str(), f.severity)).collect();
        assert_eq!(
            msgs,
            vec![
                (
                    "Unknown service on tcp/27999 · open to all networks",
                    Sev::High
                ),
                (
                    "DHCPv6 client (NetworkManager) · open to link-local",
                    Sev::Low
                ),
                ("LLMNR (systemd-resolved) · open to all networks", Sev::Low),
                ("WS-Discovery (wsdd) · open to several networks", Sev::Low),
                ("mDNS (Avahi) · open to all networks", Sev::Low),
            ],
            "13 sockets (one loopback) become 5 findings"
        );
        let unknown = &f[0];
        assert!(unknown.what.contains("belongs to root"), "{}", unknown.what);
        assert!(unknown.fix.contains("sudo ss -tulpn 'sport = :27999'"));
        let wsdd = f
            .iter()
            .find(|x| x.message.starts_with("WS-Discovery"))
            .unwrap();
        assert_eq!(wsdd.listeners.len(), 4);
        assert!(wsdd.why.contains("the VPN (wg-vpn-server)") && wsdd.why.contains("your LAN"));
        // A group is expected only once every address is baselined.
        let partly = base(&["192.168.1.180:3702/wsdd"], &[]);
        assert!(!is_expected(wsdd, &partly));
        let all = Baseline {
            listeners: wsdd.listeners.clone(),
            findings: vec![],
        };
        assert!(is_expected(wsdd, &all));
    }

    #[test]
    fn remote_access_open_to_all_is_review() {
        let r = report(Sections {
            listeners: Some(vec![
                listen("tcp", "0.0.0.0:22/?"),
                listen("tcp", "0.0.0.0:22000/syncthing"),
            ]),
            ..Default::default()
        });
        let f = derive(&r, None, &base(&[], &[]), &Config::default());
        assert_eq!(
            ids(&f),
            vec![
                ("listener:svc:SSH server", Sev::Medium, false),
                ("listener:svc:Syncthing", Sev::Low, false),
            ]
        );
    }

    #[test]
    fn flatpak_gained_vs_summarised() {
        let prev = report(Sections {
            flatpak: Some(FlatpakSec {
                apps: vec![app("com.valvesoftware.Steam", &["home"])],
                ..Default::default()
            }),
            ..Default::default()
        });
        let cur = report(Sections {
            flatpak: Some(FlatpakSec {
                apps: vec![
                    app("com.valvesoftware.Steam", &["home"]),
                    app("com.visualstudio.code", &["host"]),
                    app("org.gnome.Loupe", &["host"]),
                ],
                gl_nvidia: vec![
                    ("GL".into(), "615-71-09".into()),
                    ("GL".into(), "610-57-04".into()),
                ],
                ..Default::default()
            }),
            ..Default::default()
        });
        // Loupe is new in `cur` but `prev` had flatpak data, so its access counts as gained.
        let f = derive(&cur, Some(&prev), &base(&[], &[]), &Config::default());
        let ids: Vec<&str> = f.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "flatpak-perm:com.visualstudio.code:host",
                "flatpak-perm:org.gnome.Loupe:host",
                "flatpak-fs-access",
                "flatpak-gl-stale:org.freedesktop.Platform.GL.nvidia-610-57-04"
            ]
        );
        assert_eq!(f[0].message, "com.visualstudio.code gained filesystem=host");
        assert!(f[2].evidence.contains("com.valvesoftware.Steam"));
        // First audit: nothing gained, everything summarised in one row.
        let first = derive(&cur, None, &base(&[], &[]), &Config::default());
        let fs = first.iter().find(|f| f.id == "flatpak-fs-access").unwrap();
        assert_eq!(fs.message, "3 apps can read your files");
        assert_eq!(fs.severity, Sev::Low);
        assert!(!first.iter().any(|f| f.severity == Sev::High));
    }

    #[test]
    fn repos_grouped_by_vendor() {
        let repo = |file: &str, copr: bool| RepoSec {
            file: file.into(),
            section: "main".into(),
            enabled: true,
            url: "https://example".into(),
            copr,
            third_party: true,
        };
        let cur = report(Sections {
            repos: Some(vec![
                repo("_copr_scottames-ghostty.repo", true),
                repo("rpmfusion-free.repo", false),
                repo("rpmfusion-free-updates.repo", false),
                repo("rpmfusion-nonfree-nvidia-driver.repo", false),
                repo("updates-master.repo", false),
                repo("brave-browser.repo", false),
            ]),
            ..Default::default()
        });
        let f = derive(&cur, None, &base(&[], &[]), &Config::default());
        let msgs: Vec<(&str, Sev)> = f.iter().map(|f| (f.message.as_str(), f.severity)).collect();
        assert_eq!(
            msgs,
            vec![
                ("COPR repo: scottames-ghostty", Sev::Medium),
                ("Temporary master-mirror repo still enabled", Sev::Medium),
                ("Brave repo enabled", Sev::Low),
                ("RPM Fusion repos enabled (3 files)", Sev::Low),
            ]
        );
        assert!(
            f[1].fix
                .contains("sudo rm /etc/yum.repos.d/updates-master.repo")
        );
        // A COPR that appears after an audit is new.
        let empty = report(Sections {
            repos: Some(vec![]),
            ..Default::default()
        });
        let again = derive(&cur, Some(&empty), &base(&[], &[]), &Config::default());
        assert_eq!(again[0].severity, Sev::High);
        assert!(again[0].message.starts_with("New COPR"));
    }

    #[test]
    fn every_finding_explains_itself() {
        let cur = report(Sections {
            listeners: Some(desktop_listeners()),
            units: Some(UnitsSec {
                failed: vec!["system:systemd-remount-fs.service".into()],
                ..Default::default()
            }),
            containers: Some(vec![CtrSec {
                name: "arch".into(),
                kind: "distrobox".into(),
                state: "exited".into(),
                home_mount: true,
                stale: true,
                idle_days: 64,
                ..Default::default()
            }]),
            cache: Some(CacheSec {
                bytes: 9 << 30,
                top: vec![("pip".into(), 1 << 30)],
            }),
            shell: vec![crate::collectors::shell::Hit {
                file: ".bashrc".into(),
                line: 3,
                pattern: "curl".into(),
                text: "curl -s x | sh".into(),
            }],
            ..Default::default()
        });
        let f = derive(
            &cur,
            None,
            &base(&[], &["unit-failed:system:*"]),
            &Config::default(),
        );
        for x in &f {
            assert!(
                !x.what.is_empty() && !x.why.is_empty() && !x.fix.is_empty(),
                "{x:?}"
            );
        }
        let unit = f.iter().find(|x| x.category == "units").unwrap();
        assert!(unit.expected, "globs in the baseline still work");
        assert_eq!(
            f.last().unwrap().id,
            unit.id,
            "expected findings sink to the bottom"
        );
    }

    #[test]
    fn shell_ids_are_stable() {
        let h = |line| crate::collectors::shell::Hit {
            file: ".bashrc".into(),
            line,
            pattern: "curl".into(),
            text: "  curl -s x | sh".into(),
        };
        let one = |hit| {
            derive(
                &report(Sections {
                    shell: vec![hit],
                    ..Default::default()
                }),
                None,
                &base(&[], &[]),
                &Config::default(),
            )
        };
        assert_eq!(
            one(h(3))[0].id,
            one(h(9))[0].id,
            "moving a line doesn't change its id"
        );
    }
}
