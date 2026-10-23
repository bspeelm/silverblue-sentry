//! `sentry check <name> [args]` (spec §9.4 + addendum A3): built-in checks used by workflows.
//! Each returns pass/fail plus one line of reason; the CLI exits 0/1 (2 = usage error).
//! The same checks back workflow `when` conditions (`kernel_changed` → `kernel-changed`).

use std::path::Path;

use crate::collectors::flatpak::{gl_pair_status, parse_gl_nvidia};
use crate::collectors::{gpu, ostree};
use crate::exec::Cmd;
use crate::paths;

pub struct Outcome {
    pub ok: bool,
    pub reason: String,
}

fn pass(reason: impl Into<String>) -> Result<Outcome, String> {
    Ok(Outcome {
        ok: true,
        reason: reason.into(),
    })
}

fn fail(reason: impl Into<String>) -> Result<Outcome, String> {
    Ok(Outcome {
        ok: false,
        reason: reason.into(),
    })
}

pub const NAMES: &[&str] = &[
    "preflight",
    "booted-version",
    "booted-kernel",
    "kernel-changed",
    "nvidia-module",
    "nvidia-loaded",
    "rpmfusion-version",
    "rpmfusion-pinned",
    "kargs",
    "secureboot-mok",
    "kmod-local",
    "akmods-built",
    "flatpak-gl-nvidia",
    "flatpak-idle",
    "master-repo-present",
];

/// `when` condition names (`kernel_changed`) map onto check names (`kernel-changed`).
pub fn cond_check(cond: &str) -> Option<&'static str> {
    let name = cond.replace('_', "-");
    NAMES.iter().copied().find(|n| *n == name)
}

/// `--flag value` lookup in a check's args.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

pub fn version_id() -> String {
    let text = std::fs::read_to_string(paths::host("/etc/os-release")).unwrap_or_default();
    text.lines()
        .find_map(|l| l.strip_prefix("VERSION_ID="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default()
}

/// Boot id of the running kernel; changes on every boot (spec §9.3).
pub fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Free bytes on the filesystem holding `path` (host view).
fn free_bytes(path: &str) -> Option<u64> {
    let st = rustix::fs::statvfs(paths::host(path)).ok()?;
    Some(st.f_bavail * st.f_frsize)
}

pub fn run(name: &str, args: &[String]) -> Result<Outcome, String> {
    match name {
        "preflight" => preflight(args),
        "booted-version" => {
            let want = flag(args, "--expect").ok_or("usage: booted-version --expect N")?;
            let have = version_id();
            if have == want {
                pass(format!("booted Fedora {have}"))
            } else {
                fail(format!("booted Fedora {have}, expected {want}"))
            }
        }
        "booted-kernel" => {
            let want = flag(args, "--expect").ok_or("usage: booted-kernel --expect KVER")?;
            let have = ostree::booted_kernel();
            if want.is_empty() {
                return Err("booted-kernel: empty --expect".into());
            }
            if have == want {
                pass(format!("booted kernel {have}"))
            } else {
                fail(format!("booted kernel {have}, expected {want}"))
            }
        }
        "kernel-changed" => {
            let o = ostree::collect().map_err(|e| e.to_string())?;
            match o.update.as_ref() {
                Some(u) if u.kernel_changed => pass(format!(
                    "pending update changes the kernel: {} → {}",
                    o.booted_kernel,
                    u.new_kernel.as_deref().unwrap_or("?")
                )),
                Some(_) => fail("pending update keeps the kernel"),
                None => fail("no pending update (cached-update is empty; run the preview)"),
            }
        }
        "nvidia-module" => {
            let k = ostree::booted_kernel();
            match Cmd::host("modinfo")
                .args(["-k", &k, "-n", "nvidia"])
                .output()
            {
                Ok(p) if !p.trim().is_empty() => pass(p.trim().to_string()),
                Ok(_) | Err(_) => fail(format!("no nvidia module for {k}")),
            }
        }
        "nvidia-loaded" => {
            let mods = std::fs::read_to_string("/proc/modules").unwrap_or_default();
            if !mods.lines().any(|l| l.starts_with("nvidia ")) {
                return fail("nvidia module not loaded");
            }
            match gpu::collect().ok().flatten() {
                Some(g) => pass(format!("nvidia loaded · {} · {}", g.driver, g.name)),
                None => fail("nvidia module loaded but nvidia-smi failed"),
            }
        }
        "rpmfusion-version" => {
            let want = flag(args, "--target").ok_or("usage: rpmfusion-version --target N")?;
            let pkgs = rpmfusion_pkgs()?;
            let bad: Vec<&String> = pkgs
                .iter()
                .filter(|p| !p.contains(&format!("-release-{want}")))
                .collect();
            if pkgs.is_empty() {
                fail("no rpmfusion release packages layered")
            } else if bad.is_empty() {
                pass(format!("rpmfusion release packages at {want}"))
            } else {
                fail(format!("not at {want}: {}", join(&bad)))
            }
        }
        "rpmfusion-pinned" => {
            let o = ostree::collect().map_err(|e| e.to_string())?;
            let local: Vec<&String> = o
                .booted()
                .map(|d| {
                    d.local
                        .iter()
                        .filter(|p| p.starts_with("rpmfusion-"))
                        .collect()
                })
                .unwrap_or_default();
            if local.is_empty() {
                fail("rpmfusion release packages are not version-pinned local packages")
            } else {
                pass(format!("pinned: {}", join(&local)))
            }
        }
        "kargs" => {
            let o = ostree::collect().map_err(|e| e.to_string())?;
            let k = o.kargs.unwrap_or_default();
            let want = [
                "rd.driver.blacklist=nouveau",
                "modprobe.blacklist=nouveau",
                "nvidia-drm.modeset=1",
            ];
            let missing: Vec<&str> = want
                .iter()
                .copied()
                .filter(|w| !k.split_whitespace().any(|a| a == *w))
                .collect();
            if missing.is_empty() {
                pass("kargs present")
            } else {
                fail(format!("missing kargs: {}", missing.join(" ")))
            }
        }
        "secureboot-mok" => {
            let sb = Cmd::host("mokutil")
                .arg("--sb-state")
                .run()
                .map_err(|e| e.to_string())?;
            if !sb.stdout.contains("SecureBoot enabled") {
                return pass("Secure Boot disabled: no MOK needed");
            }
            let list = Cmd::host("mokutil")
                .arg("--list-enrolled")
                .output()
                .map_err(|e| e.to_string())?;
            if list.contains("akmods") {
                pass("Secure Boot enabled · akmods MOK key enrolled")
            } else {
                fail("Secure Boot enabled but no akmods key is enrolled (kmods won't load)")
            }
        }
        "kmod-local" => {
            let o = ostree::collect().map_err(|e| e.to_string())?;
            let k = o.kmods();
            match (k.as_slice(), has(args, "--exactly-one")) {
                ([one], _) => pass(one.to_string()),
                ([], false) => pass("no layered kmod-nvidia"),
                (many, _) => fail(format!(
                    "{} layered kmod-nvidia packages (need exactly one): {}",
                    many.len(),
                    many.join(" ")
                )),
            }
        }
        "akmods-built" => {
            let k = ostree::booted_kernel();
            let dir = paths::host("/var/cache/akmods/nvidia");
            let rpms = built_kmods(&dir, &k);
            match (rpms.as_slice(), has(args, "--exactly-one")) {
                ([one], _) => pass(format!("/var/cache/akmods/nvidia/{one}")),
                ([], _) => fail(format!("no kmod-nvidia RPM built for {k} (run akmods)")),
                (many, true) => fail(format!(
                    "{} kmod RPMs for {k}; stop and pick one: {}",
                    many.len(),
                    many.join(" ")
                )),
                (many, false) => pass(format!("{} RPM(s) for {k}", many.len())),
            }
        }
        "flatpak-gl-nvidia" => {
            let Some(g) = gpu::collect().ok().flatten() else {
                return fail("nvidia-smi failed: driver not loaded?");
            };
            let rt = Cmd::host("flatpak")
                .args(["list", "--runtime", "--columns=application,version,branch"])
                .output()
                .map_err(|e| e.to_string())?;
            let gl = parse_gl_nvidia(&rt);
            match gl_pair_status(&gl, &g.driver) {
                (true, true) => pass(format!("GL + GL32 match driver {}", g.driver)),
                (gl_ok, gl32_ok) => fail(format!(
                    "driver {}: GL {} · GL32 {} (flatpak update, then restart Steam)",
                    g.driver,
                    if gl_ok { "ok" } else { "missing" },
                    if gl32_ok { "ok" } else { "missing" }
                )),
            }
        }
        "flatpak-idle" => {
            let app = flag(args, "--app");
            let running = crate::jobs::plan::flatpak_running();
            let hit: Vec<&String> = running
                .iter()
                .filter(|r| app.is_none_or(|a| r.as_str() == a))
                .collect();
            if hit.is_empty() {
                pass(match app {
                    Some(a) => format!("{a} is not running"),
                    None => "no sandboxes running".into(),
                })
            } else {
                fail(format!("running: {} (quit fully first)", join(&hit)))
            }
        }
        "master-repo-present" => {
            if paths::host("/etc/yum.repos.d/updates-master.repo").exists() {
                pass("/etc/yum.repos.d/updates-master.repo is present")
            } else {
                fail("no updates-master.repo")
            }
        }
        other => Err(format!(
            "unknown check {other:?}; one of: {}",
            NAMES.join(", ")
        )),
    }
}

fn join(v: &[&String]) -> String {
    v.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ")
}

fn rpmfusion_pkgs() -> Result<Vec<String>, String> {
    let o = ostree::collect().map_err(|e| e.to_string())?;
    Ok(o.booted()
        .map(|d| {
            d.local
                .iter()
                .chain(d.layered.iter())
                .filter(|p| p.starts_with("rpmfusion-") && p.contains("-release"))
                .cloned()
                .collect()
        })
        .unwrap_or_default())
}

/// `kmod-nvidia-<kver>-*.rpm` in the akmods cache.
pub fn built_kmods(dir: &Path, kver: &str) -> Vec<String> {
    let prefix = format!("kmod-nvidia-{kver}-");
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(&prefix) && n.ends_with(".rpm"))
        .collect();
    v.sort();
    v
}

fn preflight(args: &[String]) -> Result<Outcome, String> {
    let mut lines = Vec::new();
    let mut ok = true;
    let mut note = |good: bool, s: String| {
        ok &= good;
        lines.push(format!("{} {s}", if good { "✓" } else { "✗" }));
    };
    let cur = version_id();
    if let Some(t) = flag(args, "--target") {
        let newer = t.parse::<u32>().ok() > cur.parse::<u32>().ok();
        note(newer, format!("target {t} vs booted {cur}"));
    }
    for (path, min_gib) in [("/sysroot", 10u64), ("/var", 5)] {
        match free_bytes(path) {
            Some(b) => note(
                b >= min_gib << 30,
                format!("{path} free {} (need {min_gib} GiB)", crate::fmt::bytes(b)),
            ),
            None => note(false, format!("{path}: can't stat")),
        }
    }
    match ostree::collect() {
        Ok(o) => note(
            !o.deployments.iter().any(|d| d.staged),
            if o.deployments.iter().any(|d| d.staged) {
                "a deployment is already staged (reboot or `rpm-ostree cleanup -p` first)".into()
            } else {
                "no pending deployment".into()
            },
        ),
        Err(e) => note(false, format!("rpm-ostree: {e}")),
    }
    note(power_ok(), "AC power or battery > 50%".into());
    note(network_ok(), "network (dl.fedoraproject.org:443)".into());
    let own = std::env::var("SENTRY_WORKFLOW_RUN").ok();
    let other = crate::resume::in_progress()
        .filter(|r| own.as_deref() != Some(r.run_dir.to_string_lossy().as_ref()));
    note(
        other.is_none(),
        match &other {
            Some(r) => format!("another workflow in progress: {}", r.summary()),
            None => "no other workflow in progress".into(),
        },
    );
    let reason = format!(
        "preflight {}\n{}",
        if ok { "passed" } else { "failed" },
        lines.join("\n")
    );
    if ok { pass(reason) } else { fail(reason) }
}

fn power_ok() -> bool {
    let root = Path::new("/sys/class/power_supply");
    let mut on_ac = false;
    let mut batt: Option<u32> = None;
    for e in std::fs::read_dir(root).into_iter().flatten().flatten() {
        let p = e.path();
        let read = |f: &str| std::fs::read_to_string(p.join(f)).unwrap_or_default();
        match read("type").trim() {
            "Mains" => on_ac |= read("online").trim() == "1",
            "Battery" => batt = read("capacity").trim().parse().ok(),
            _ => {}
        }
    }
    // Desktops have no battery at all.
    on_ac || batt.is_none_or(|c| c > 50)
}

fn network_ok() -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    let Ok(mut addrs) = ("dl.fedoraproject.org", 443).to_socket_addrs() else {
        return false;
    };
    addrs.any(|a| TcpStream::connect_timeout(&a, std::time::Duration::from_secs(3)).is_ok())
}

/// `sentry check` entry point: prints the reason, returns the exit code.
pub fn run_cli(name: &str, args: &[String]) -> u8 {
    match run(name, args) {
        Ok(o) => {
            println!("{} {}", if o.ok { "✓" } else { "✗" }, o.reason);
            if o.ok { 0 } else { 1 }
        }
        Err(e) => {
            eprintln!("sentry check {name}: {e}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditions_map_to_checks() {
        assert_eq!(cond_check("kernel_changed"), Some("kernel-changed"));
        assert_eq!(
            cond_check("master_repo_present"),
            Some("master-repo-present")
        );
        assert_eq!(cond_check("nope"), None);
    }

    #[test]
    fn built_kmod_glob() {
        let d = std::env::temp_dir().join(format!("sentry-akmods-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        for f in [
            "kmod-nvidia-7.2.11-200.fc44.x86_64-615.71.09-3.fc44.x86_64.rpm",
            "kmod-nvidia-7.2.8-200.fc44.x86_64-615.71.09-3.fc44.x86_64.rpm",
            "615.71.09-3-for-7.2.11-200.fc44.x86_64.failed.log",
        ] {
            std::fs::write(d.join(f), b"").unwrap();
        }
        let v = built_kmods(&d, "7.2.11-200.fc44.x86_64");
        std::fs::remove_dir_all(&d).unwrap();
        assert_eq!(
            v,
            vec!["kmod-nvidia-7.2.11-200.fc44.x86_64-615.71.09-3.fc44.x86_64.rpm"]
        );
    }

    #[test]
    fn usage_errors() {
        assert!(run("booted-version", &[]).is_err());
        assert!(run("bogus", &[]).is_err());
    }
}
