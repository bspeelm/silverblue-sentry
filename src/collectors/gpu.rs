//! NVIDIA GPU via `nvidia-smi`. Optional: panel hides when this returns `None`.

use serde::{Deserialize, Serialize};

use super::CResult;
use crate::exec::Cmd;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Gpu {
    pub name: String,
    pub util: f32,
    pub vram_used_mib: u64,
    pub vram_total_mib: u64,
    pub temp: f32,
    pub driver: String,
}

pub const QUERY: &str =
    "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,driver_version";

pub fn collect() -> CResult<Option<Gpu>> {
    let cmd = Cmd::host("nvidia-smi")
        .arg(QUERY)
        .arg("--format=csv,noheader,nounits");
    match cmd.output() {
        Ok(out) => Ok(parse(&out)),
        Err(crate::exec::ExecError::NotFound(_)) => Ok(None),
        // Driver not loaded etc.: same as "no GPU" for display purposes.
        Err(_) => Ok(None),
    }
}

/// First GPU line of the CSV.
pub fn parse(csv: &str) -> Option<Gpu> {
    let line = csv.lines().next()?;
    let f: Vec<&str> = line.split(',').map(str::trim).collect();
    if f.len() < 6 {
        return None;
    }
    let num = |s: &str| s.parse::<f32>().unwrap_or(0.0);
    Some(Gpu {
        name: f[0]
            .trim_start_matches("NVIDIA ")
            .trim_start_matches("GeForce ")
            .to_string(),
        util: num(f[1]),
        vram_used_mib: num(f[2]) as u64,
        vram_total_mib: num(f[3]) as u64,
        temp: num(f[4]),
        driver: f[5].to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixture() {
        let g = parse(&crate::collectors::fixture("gpu/nvidia-smi.csv")).unwrap();
        assert!(g.name.contains("4090"), "{g:?}");
        assert!(g.vram_total_mib > 20000);
        assert!(g.driver.starts_with("615."));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("NVIDIA-SMI has failed").is_none());
        assert!(parse("").is_none());
    }
}
