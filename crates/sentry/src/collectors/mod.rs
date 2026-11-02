//! Read-only collectors. Each module exposes a pure `parse*` (fixture-tested) and a `collect`
//! (exec + parse) returning a serde struct.

pub use sentry_core::collectors::{
    CResult, CollectError, Ctx, disk, fields, gpu, journal, net, procfs,
};

pub mod breakdown;
pub mod flatpak;
pub mod ostree;
pub mod podman;
pub mod processes;
pub mod repos;
pub mod shell;
pub mod system;
pub mod toolbox;
pub mod units;

pub const NAMES: &[&str] = &[
    "system",
    "processes",
    "gpu",
    "disk",
    "disk-breakdown",
    "net",
    "ostree",
    "flatpak",
    "flatpak-updates",
    "toolbox-updates",
    "podman",
    "units",
    "repos",
    "shell",
    "journal",
];

fn json<T: serde::Serialize>(v: CResult<T>) -> CResult<serde_json::Value> {
    Ok(serde_json::to_value(v?)?)
}

/// Run a collector by CLI name and return its JSON.
pub fn collect_json(name: &str, ctx: &Ctx) -> CResult<serde_json::Value> {
    match name {
        "system" => json(Ok(system::Sampler::new().sample_settled())),
        "processes" => json(Ok(processes::ProcSampler::new().sample_settled())),
        "gpu" => json(gpu::collect()),
        "disk" => json(disk::collect()),
        "disk-breakdown" => json(Ok(breakdown::collect(ctx))),
        "net" => json(net::collect(ctx)),
        "ostree" => json(ostree::collect()),
        "flatpak" => json(flatpak::collect(ctx)),
        "flatpak-updates" => json(flatpak::collect_updates()),
        "toolbox-updates" => json(toolbox::collect(ctx)),
        "podman" => json(podman::collect(ctx)),
        "units" => json(units::collect(ctx)),
        "repos" => json(repos::collect()),
        "shell" => json(Ok(shell::collect(ctx))),
        "journal" => json(journal::collect()),
        other => Err(CollectError::Other(anyhow::anyhow!(
            "unknown collector {other:?}; one of: {}",
            NAMES.join(", ")
        ))),
    }
}

#[cfg(test)]
pub(crate) fn fixture(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("fixture {}: {e}", p.display()))
}
