//! Mounted filesystems via `findmnt -J`, one row per underlying filesystem.

use serde::{Deserialize, Serialize};

use super::CResult;
use crate::exec::Cmd;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Mount {
    pub target: String,
    pub source: String,
    pub fstype: String,
    pub size: u64,
    pub used: u64,
    pub removable: bool,
}

impl Mount {
    pub fn pct(&self) -> f64 {
        if self.size == 0 {
            0.0
        } else {
            self.used as f64 / self.size as f64 * 100.0
        }
    }
}

#[derive(Deserialize)]
struct Root {
    filesystems: Vec<Fs>,
}

#[derive(Deserialize)]
struct Fs {
    target: String,
    source: String,
    fstype: String,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    used: Option<u64>,
    #[serde(default)]
    children: Vec<Fs>,
}

pub fn collect() -> CResult<Vec<Mount>> {
    let out = Cmd::host("findmnt")
        .args(["-J", "-b", "--real", "-o", "TARGET,SOURCE,FSTYPE,SIZE,USED"])
        .output()?;
    Ok(parse(&out)?)
}

fn flatten(fs: Vec<Fs>, out: &mut Vec<Fs>) {
    for mut f in fs {
        let kids = std::mem::take(&mut f.children);
        out.push(f);
        flatten(kids, out);
    }
}

fn rank(target: &str) -> (u8, usize) {
    match target {
        "/" => (0, 0),
        "/sysroot" => (1, 0),
        "/etc" => (3, 0),
        t => (2, t.len()),
    }
}

pub fn parse(json: &str) -> anyhow::Result<Vec<Mount>> {
    let root: Root = serde_json::from_str(json)?;
    let mut all = Vec::new();
    flatten(root.filesystems, &mut all);

    let mut out: Vec<Mount> = Vec::new();
    for f in all {
        let (Some(size), Some(used)) = (f.size, f.used) else {
            continue;
        };
        if size == 0 {
            continue;
        }
        let base = f.source.split('[').next().unwrap_or(&f.source).to_string();
        let removable = f.target.starts_with("/run/media/");
        // Small vfat volumes are ESPs; only /boot/efi is interesting.
        if f.fstype == "vfat" && size < 1 << 30 && f.target != "/boot/efi" {
            continue;
        }
        match out.iter_mut().find(|m| m.source == base) {
            Some(m) if rank(&f.target) < rank(&m.target) => m.target = f.target,
            Some(_) => {}
            None => out.push(Mount {
                target: f.target,
                source: base,
                fstype: f.fstype,
                size,
                used,
                removable,
            }),
        }
    }
    out.sort_by_key(|m| (m.removable, rank(&m.target).0 > 1, m.target.clone()));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupes_btrfs_subvolumes() {
        let m = parse(&crate::collectors::fixture("disk/findmnt.json")).unwrap();
        let targets: Vec<&str> = m.iter().map(|m| m.target.as_str()).collect();
        assert_eq!(
            targets.iter().filter(|t| **t == "/sysroot").count(),
            1,
            "{targets:?}"
        );
        assert!(
            !targets.contains(&"/var/home") && !targets.contains(&"/etc"),
            "{targets:?}"
        );
        assert!(targets.contains(&"/var/mnt/vault"));
        assert!(targets.contains(&"/boot/efi"));
        assert!(
            m.last().unwrap().removable,
            "removable media sorts last: {targets:?}"
        );
    }
}
