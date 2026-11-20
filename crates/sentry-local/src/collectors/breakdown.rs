//! Where /var and ~ space goes: containers, flatpak, ~/.cache, ostree. Slow directory walk;
//! cached and refreshed only on request.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::Ctx;
use crate::paths;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Breakdown {
    pub containers: u64,
    pub flatpak: u64,
    pub cache: u64,
    pub ostree: u64,
    /// Directories that could not be read (counted, not fatal).
    pub unreadable: u64,
}

pub fn collect(ctx: &Ctx) -> Breakdown {
    let h = &ctx.home;
    let mut b = Breakdown::default();
    let mut seen = HashSet::new();
    b.containers = du(
        &[h.join(".local/share/containers")],
        &mut seen,
        &mut b.unreadable,
    );
    b.flatpak = du(
        &[
            paths::host("/var/lib/flatpak"),
            h.join(".local/share/flatpak"),
        ],
        &mut seen,
        &mut b.unreadable,
    );
    b.cache = du(&[h.join(".cache")], &mut seen, &mut b.unreadable);
    // ostree objects are hardlinked into every deployment; dedup by inode counts them once.
    b.ostree = du(
        &[paths::host("/sysroot/ostree/repo")],
        &mut seen,
        &mut b.unreadable,
    );
    b
}

/// `~/.cache` total plus its children larger than `min`, biggest first.
pub fn cache_top(home: &std::path::Path, min: u64) -> (u64, Vec<(String, u64)>) {
    let root = home.join(".cache");
    let mut seen = HashSet::new();
    let mut bad = 0;
    let mut total = 0;
    let mut top = Vec::new();
    for e in std::fs::read_dir(&root).into_iter().flatten().flatten() {
        let Ok(md) = e.metadata() else { continue };
        let n = if md.is_dir() {
            du(&[e.path()], &mut seen, &mut bad) + md.blocks() * 512
        } else {
            md.blocks() * 512
        };
        total += n;
        if n >= min {
            top.push((e.file_name().to_string_lossy().into_owned(), n));
        }
    }
    top.sort_by_key(|e| std::cmp::Reverse(e.1));
    (total, top)
}

/// Allocated bytes under `roots`, counting each (dev, inode) once and never crossing into
/// directories we can't read.
pub fn du(roots: &[PathBuf], seen: &mut HashSet<(u64, u64)>, unreadable: &mut u64) -> u64 {
    let mut total = 0;
    let mut stack: Vec<PathBuf> = roots.iter().filter(|p| p.exists()).cloned().collect();
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            *unreadable += 1;
            continue;
        };
        for e in rd.flatten() {
            let Ok(md) = e.metadata() else { continue };
            if !seen.insert((md.dev(), md.ino())) {
                continue;
            }
            total += md.blocks() * 512;
            if md.is_dir() {
                stack.push(e.path());
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardlinks_count_once() {
        let d = std::env::temp_dir().join(format!("sentry-du-{}", std::process::id()));
        std::fs::create_dir_all(d.join("a")).unwrap();
        std::fs::write(d.join("a/f"), vec![1u8; 64 * 1024]).unwrap();
        std::fs::hard_link(d.join("a/f"), d.join("g")).unwrap();
        let (mut seen, mut bad) = (HashSet::new(), 0);
        let total = du(std::slice::from_ref(&d), &mut seen, &mut bad);
        std::fs::remove_dir_all(&d).unwrap();
        assert!((64 * 1024..2 * 64 * 1024).contains(&total), "{total}");
    }
}
