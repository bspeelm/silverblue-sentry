//! Docker on the server: containers from `docker inspect` (state, health, restarts, published
//! ports, whether the docker socket is mounted), compose projects, and on request `docker stats`.
//! Everything goes through the `sudo:` allowlist, since the docker socket is root's.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::super::remote::{Remote, SrvError};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Container {
    pub name: String,
    pub image: String,
    /// `running`, `exited`, `restarting`, `paused`, `created`, `dead`
    pub status: String,
    /// `healthy`, `unhealthy`, `starting`; None without a health check.
    pub health: Option<String>,
    pub restarts: u32,
    pub started_at: Option<Timestamp>,
    pub exit_code: i32,
    pub oom: bool,
    pub compose: Option<String>,
    /// The compose service it runs (`com.docker.compose.service`).
    #[serde(default)]
    pub service: Option<String>,
    /// Mounts `/var/run/docker.sock`: control of the docker daemon, i.e. root on the host.
    pub docker_sock: bool,
    /// Published ports: (host ip, host port, container port/proto).
    pub ports: Vec<(String, String, String)>,
    /// `no`, `always`, `unless-stopped`, `on-failure` (empty when unset).
    #[serde(default)]
    pub restart_policy: String,
}

impl Container {
    /// A one-off that ran and exited cleanly (CI jobs, `docker run` tasks): not a failure.
    pub fn finished(&self) -> bool {
        self.status == "exited"
            && self.exit_code == 0
            && matches!(self.restart_policy.as_str(), "" | "no")
            && self.compose.is_none()
    }

    /// Should be running and isn't.
    pub fn down(&self) -> bool {
        self.status != "running" && !self.finished()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Project {
    pub name: String,
    pub status: String,
    pub files: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Docker {
    pub containers: Vec<Container>,
    pub projects: Vec<Project>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Stat {
    pub name: String,
    pub cpu_pct: f32,
    pub mem_pct: f32,
    pub mem: String,
    pub pids: u32,
}

// --- the slices of `docker inspect` that matter ---

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Inspect {
    name: String,
    #[serde(default)]
    restart_count: u32,
    state: State,
    config: Config,
    #[serde(default)]
    mounts: Vec<Mount>,
    #[serde(default)]
    network_settings: Option<NetworkSettings>,
    #[serde(default)]
    host_config: Option<HostConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HostConfig {
    #[serde(default)]
    restart_policy: Option<RestartPolicy>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RestartPolicy {
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct State {
    status: String,
    #[serde(default)]
    started_at: Option<String>,
    #[serde(default, rename = "OOMKilled")]
    oom_killed: bool,
    #[serde(default)]
    exit_code: i32,
    #[serde(default)]
    health: Option<Health>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Health {
    status: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Config {
    image: String,
    #[serde(default)]
    labels: Option<std::collections::HashMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Mount {
    #[serde(default)]
    source: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NetworkSettings {
    #[serde(default)]
    ports: Option<std::collections::BTreeMap<String, Option<Vec<Binding>>>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Binding {
    #[serde(default)]
    host_ip: String,
    #[serde(default)]
    host_port: String,
}

pub fn parse_inspect(json: &str) -> Result<Vec<Container>, String> {
    let v: Vec<Inspect> = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let mut out: Vec<Container> = v
        .into_iter()
        .map(|i| {
            let ports = i
                .network_settings
                .and_then(|n| n.ports)
                .unwrap_or_default()
                .into_iter()
                .flat_map(|(inner, binds)| {
                    binds
                        .unwrap_or_default()
                        .into_iter()
                        .map(move |b| (b.host_ip, b.host_port, inner.clone()))
                })
                .collect();
            Container {
                name: i.name.trim_start_matches('/').to_string(),
                image: i.config.image,
                status: i.state.status,
                health: i.state.health.map(|h| h.status),
                restarts: i.restart_count,
                started_at: i
                    .state
                    .started_at
                    .and_then(|s| s.parse().ok())
                    // Never-started containers report year 1.
                    .filter(|t: &Timestamp| t.as_second() > 0),
                exit_code: i.state.exit_code,
                oom: i.state.oom_killed,
                compose: i
                    .config
                    .labels
                    .as_ref()
                    .and_then(|l| l.get("com.docker.compose.project").cloned()),
                service: i
                    .config
                    .labels
                    .as_ref()
                    .and_then(|l| l.get("com.docker.compose.service").cloned()),
                docker_sock: i.mounts.iter().any(|m| m.source.ends_with("/docker.sock")),
                ports,
                restart_policy: i
                    .host_config
                    .and_then(|h| h.restart_policy)
                    .map(|p| p.name)
                    .unwrap_or_default(),
            }
        })
        .collect();
    out.sort_by(|a, b| (&a.compose, &a.name).cmp(&(&b.compose, &b.name)));
    Ok(out)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ProjectJson {
    name: String,
    status: String,
    config_files: String,
}

pub fn parse_projects(json: &str) -> Result<Vec<Project>, String> {
    let v: Vec<ProjectJson> = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(v.into_iter()
        .map(|p| Project {
            name: p.name,
            status: p.status,
            files: p.config_files,
        })
        .collect())
}

/// `docker stats --format '{{json .}}'`: one object per line, numbers as `"0.40%"`.
pub fn parse_stats(text: &str) -> Vec<Stat> {
    let pct = |v: &serde_json::Value| {
        v.as_str()
            .and_then(|s| s.trim_end_matches('%').parse().ok())
            .unwrap_or(0.0)
    };
    text.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .map(|v| Stat {
            name: v["Name"].as_str().unwrap_or("?").to_string(),
            cpu_pct: pct(&v["CPUPerc"]),
            mem_pct: pct(&v["MemPerc"]),
            mem: v["MemUsage"].as_str().unwrap_or("").to_string(),
            pids: v["PIDs"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0),
        })
        .collect()
}

pub const PS_ARGV: &[&str] = &["docker", "ps", "-aq"];
pub const COMPOSE_LS_ARGV: &[&str] = &["docker", "compose", "ls", "--all", "--format", "json"];

pub fn collect(r: &Remote) -> Result<Docker, SrvError> {
    let ids = r.output(&r.privileged(PS_ARGV)?)?;
    let ids: Vec<&str> = ids.split_whitespace().collect();
    let containers = if ids.is_empty() {
        Vec::new()
    } else {
        let mut argv = vec!["docker", "inspect"];
        argv.extend(ids.iter().copied());
        parse_inspect(&r.output(&r.privileged(&argv)?)?).map_err(SrvError::Parse)?
    };
    // Projects are optional: without that sudo entry, containers still show.
    let projects = r
        .privileged(COMPOSE_LS_ARGV)
        .and_then(|c| r.output(&c))
        .map(|j| parse_projects(&j).unwrap_or_default())
        .unwrap_or_default();
    Ok(Docker {
        containers,
        projects,
    })
}

/// About two seconds: docker samples before it answers. Only on request.
pub fn stats(r: &Remote) -> Result<Vec<Stat>, SrvError> {
    let c = r
        .privileged(&["docker", "stats", "--no-stream", "--format", "{{json .}}"])?
        .timeout(Some(std::time::Duration::from_secs(20)));
    Ok(parse_stats(&r.output(&c)?))
}

#[cfg(test)]
mod tests {
    use super::super::fixture;
    use super::*;

    #[test]
    fn inspect() {
        let c = parse_inspect(&fixture("docker-inspect.json")).unwrap();
        let names: Vec<&str> = c.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            ["runner", "db", "web"],
            "loose containers first, then by project"
        );
        let runner = &c[0];
        assert!(runner.docker_sock && runner.compose.is_none() && runner.health.is_none());
        assert!(!runner.finished() && !runner.down());
        let db = &c[1];
        assert!(db.down(), "exited 137 in a project");
        let mut job = db.clone();
        (job.exit_code, job.compose, job.restart_policy) = (0, None, "no".into());
        assert!(job.finished() && !job.down(), "a CI job that exited 0");
        assert_eq!(
            (db.status.as_str(), db.exit_code, db.oom),
            ("exited", 137, true)
        );
        assert_eq!(db.health.as_deref(), Some("unhealthy"));
        assert_eq!(
            db.started_at, None,
            "never-started containers report year 1"
        );
        let web = &c[2];
        assert_eq!(web.restarts, 3);
        assert_eq!(
            web.ports,
            [
                ("0.0.0.0".into(), "443".into(), "443/tcp".into()),
                ("::".into(), "443".into(), "443/tcp".into()),
                ("127.0.0.1".into(), "8080".into(), "80/tcp".into())
            ]
        );
        assert_eq!(
            web.started_at.unwrap().to_string(),
            "2026-10-26T01:47:12.912345678Z"
        );
    }

    #[test]
    fn projects_and_stats() {
        let p = parse_projects(&fixture("compose-ls.json")).unwrap();
        assert_eq!(
            (p[0].name.as_str(), p[0].status.as_str()),
            ("stack", "running(3)")
        );
        let s = parse_stats(&fixture("docker-stats.jsonl"));
        assert_eq!(s.len(), 2);
        assert_eq!(
            (s[1].name.as_str(), s[1].cpu_pct, s[1].mem_pct, s[1].pids),
            ("web", 7.25, 18.4, 23)
        );
    }
}
