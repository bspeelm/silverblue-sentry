//! XDG locations and host-root resolution.

use std::path::{Path, PathBuf};

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn xdg(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home().join(fallback))
        .join("sentry")
}

pub fn config_dir() -> PathBuf {
    xdg("XDG_CONFIG_HOME", ".config")
}

pub fn data_dir() -> PathBuf {
    xdg("XDG_DATA_HOME", ".local/share")
}

pub fn cache_dir() -> PathBuf {
    xdg("XDG_CACHE_HOME", ".cache")
}

/// Root of the host filesystem: `/run/host` inside a toolbox, `/` otherwise.
pub fn host_root() -> PathBuf {
    if crate::exec::spawn_mode() && Path::new("/run/host/etc").is_dir() {
        PathBuf::from("/run/host")
    } else {
        PathBuf::from("/")
    }
}

/// `host_root()` joined with an absolute host path.
pub fn host(path: &str) -> PathBuf {
    host_root().join(path.trim_start_matches('/'))
}

/// Write via temp file + rename so readers never see a partial file.
pub fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(tmp, path)
}

/// `44.20261002.0` from host os-release `VERSION="44.20261002.0 (Silverblue)"`.
pub fn os_version() -> String {
    let text = std::fs::read_to_string(host("/etc/os-release")).unwrap_or_default();
    parse_os_version(&text)
}

pub fn parse_os_version(text: &str) -> String {
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k))
            .map(|v| v.trim_matches('"').to_string())
    };
    get("VERSION=")
        .map(|v| v.split(' ').next().unwrap_or(&v).to_string())
        .or_else(|| get("VERSION_ID="))
        .unwrap_or_default()
}

