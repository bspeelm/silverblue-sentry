//! Debian/Ubuntu updates, read without root: a simulated `apt-get dist-upgrade` (it reads the
//! package lists apt already has; refreshing them is a maintenance action), the periodic
//! stamps, `/var/run/reboot-required` and the installed vs running kernel.

use serde::{Deserialize, Serialize};

use super::super::remote::{Remote, SrvError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Security,
    Updates,
    /// A repository outside the distribution (vendor repos).
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pkg {
    pub name: String,
    pub old: Option<String>,
    pub new: String,
    /// `12-updates/oldstable-updates`, `repo.example.com`, …
    pub origin: String,
    pub kind: Kind,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Apt {
    pub upgrades: Vec<Pkg>,
    /// Held back (phased rollouts, or upgrades that would remove packages).
    pub kept_back: Vec<String>,
    pub removals: Vec<String>,
    /// Unix seconds of `/var/lib/apt/periodic/<name>-stamp` (update, upgrade, …).
    pub stamps: Vec<(String, i64)>,
    /// Since when a reboot has been required, and which packages asked for it.
    pub reboot_since: Option<i64>,
    pub reboot_pkgs: Vec<String>,
    pub running_kernel: String,
    pub newest_kernel: Option<String>,
    /// The server's clock when this was read (ages are computed against it).
    pub now: i64,
}

impl Apt {
    pub fn stamp(&self, name: &str) -> Option<i64> {
        self.stamps.iter().find(|(n, _)| n == name).map(|(_, t)| *t)
    }

    pub fn kernel_pending(&self) -> bool {
        self.newest_kernel
            .as_deref()
            .is_some_and(|n| n != self.running_kernel)
    }
}

const SCRIPT: &str = "apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>&1; \
     echo @@stamps; stat -c '%Y %n' /var/lib/apt/periodic/*-stamp /var/run/reboot-required 2>/dev/null; \
     echo @@pkgs; cat /var/run/reboot-required.pkgs 2>/dev/null; \
     echo @@uname; uname -r; \
     echo @@boot; ls /boot/vmlinuz-* 2>/dev/null; \
     echo @@now; date +%s";

pub fn collect(r: &Remote) -> Result<Apt, SrvError> {
    let c = r
        .sh(SCRIPT)
        .timeout(Some(std::time::Duration::from_secs(60)));
    let o = c.run()?;
    // apt-get may fail (no apt on this server); the rest still says something.
    if !o.stdout.contains("@@now") {
        return Err(SrvError::Failed(o.stderr.trim().to_string()));
    }
    if o.stdout.contains("apt-get: not found") || o.stdout.contains("apt-get: command not found") {
        return Err(SrvError::NotFound("apt-get".into()));
    }
    Ok(parse(&o.stdout))
}

pub fn parse(text: &str) -> Apt {
    let mut a = Apt::default();
    let (sim, rest) = text.split_once("@@stamps").unwrap_or((text, ""));
    let mut section = "";
    let mut kept = false;
    for l in sim.lines() {
        if l.starts_with("The following packages have been kept back") {
            kept = true;
            continue;
        }
        if kept {
            if l.starts_with("  ") {
                a.kept_back.extend(l.split_whitespace().map(str::to_string));
                continue;
            }
            kept = false;
        }
        if let Some(rest) = l.strip_prefix("Inst ") {
            if let Some(p) = parse_inst(rest) {
                a.upgrades.push(p);
            }
        } else if let Some(rest) = l.strip_prefix("Remv ") {
            a.removals
                .push(rest.split_whitespace().next().unwrap_or("").to_string());
        }
    }
    for l in rest.lines() {
        if let Some(s) = l.strip_prefix("@@") {
            section = s.trim();
            continue;
        }
        match section {
            "" => {
                // still the stamps (they follow the `@@stamps` marker we split on)
                if let Some((t, path)) = l.split_once(' ') {
                    let t: i64 = t.parse().unwrap_or(0);
                    if path.ends_with("reboot-required") {
                        a.reboot_since = Some(t);
                    } else if let Some(name) = path
                        .rsplit('/')
                        .next()
                        .and_then(|f| f.strip_suffix("-stamp"))
                    {
                        a.stamps.push((name.to_string(), t));
                    }
                }
            }
            "pkgs" if !l.trim().is_empty() => a.reboot_pkgs.push(l.trim().to_string()),
            "uname" if !l.trim().is_empty() => a.running_kernel = l.trim().to_string(),
            "boot" => {
                if let Some(v) = l.trim().strip_prefix("/boot/vmlinuz-")
                    && a.newest_kernel.as_deref().is_none_or(|n| version_lt(n, v))
                {
                    a.newest_kernel = Some(v.to_string());
                }
            }
            "now" => a.now = l.trim().parse().unwrap_or(0),
            _ => {}
        }
    }
    a
}

/// `tzdata [2024a-0+deb12u1] (2025b-0+deb12u1 Debian:12-updates/oldstable-updates [all])`
fn parse_inst(rest: &str) -> Option<Pkg> {
    let (name, rest) = rest.split_once(' ').unwrap_or((rest, ""));
    let (old, rest) = match rest.strip_prefix('[') {
        Some(r) => {
            let (o, r) = r.split_once("] ")?;
            (Some(o.to_string()), r)
        }
        None => (None, rest),
    };
    let inner = rest.strip_prefix('(')?;
    let inner = inner.split(" [").next()?.trim_end_matches(')');
    let (new, origin) = inner.split_once(' ').unwrap_or((inner, ""));
    // `Debian:12-updates/oldstable-updates`, `Debian-Security:12/oldstable-security`,
    // `Vendor Name <mail>:repo.example.com`: the part after the last colon names the repo.
    let label = origin
        .rsplit(':')
        .next()
        .unwrap_or(origin)
        .trim()
        .to_string();
    let kind = if origin.contains("Security") || label.contains("security") {
        Kind::Security
    } else if origin.starts_with("Debian") || origin.starts_with("Ubuntu") {
        Kind::Updates
    } else {
        Kind::Other
    };
    Some(Pkg {
        name: name.to_string(),
        old,
        new: new.to_string(),
        origin: label,
        kind,
    })
}

/// Compare kernel versions numerically (`6.1.0-9` < `6.1.0-21`).
pub fn version_lt(a: &str, b: &str) -> bool {
    let nums = |s: &str| -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .filter_map(|p| p.parse().ok())
            .collect()
    };
    nums(a) < nums(b)
}

#[cfg(test)]
mod tests {
    use super::super::fixture;
    use super::*;

    #[test]
    fn simulation_and_state() {
        let a = parse(&fixture("apt.txt"));
        let names: Vec<(&str, Kind)> = a
            .upgrades
            .iter()
            .map(|p| (p.name.as_str(), p.kind))
            .collect();
        assert_eq!(
            names,
            [
                ("libssl3t64", Kind::Security),
                ("tzdata", Kind::Updates),
                ("vendor-tool", Kind::Other),
                ("newpkg", Kind::Updates),
            ]
        );
        assert_eq!(a.upgrades[0].old.as_deref(), Some("3.0.14-1~deb12u1"));
        assert_eq!(a.upgrades[0].origin, "12/oldstable-security");
        assert_eq!(a.upgrades[2].origin, "repo.example.com");
        assert_eq!(a.upgrades[3].old, None, "newly installed");
        assert_eq!(a.kept_back, ["libfoo1", "libfoo-dev", "foo-tools"]);
        assert_eq!(a.removals, ["oldpkg"]);
        assert_eq!(a.stamp("update"), Some(1793185600));
        assert_eq!(a.reboot_since, Some(1792508800));
        assert_eq!(a.reboot_pkgs, ["linux-image-6.1.0-25-amd64"]);
        assert_eq!(a.running_kernel, "6.1.0-9-amd64");
        assert_eq!(a.newest_kernel.as_deref(), Some("6.1.0-25-amd64"));
        assert!(a.kernel_pending());
        assert_eq!(a.now, 1793200000);
    }

    #[test]
    fn kernel_versions_compare_as_numbers() {
        assert!(version_lt("6.1.0-9-amd64", "6.1.0-21-amd64"));
        assert!(!version_lt("6.1.0-25-amd64", "6.1.0-21-amd64"));
    }
}
