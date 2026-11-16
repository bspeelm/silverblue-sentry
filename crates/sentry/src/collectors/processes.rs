//! Process table (sysinfo). Refreshed only while the Processes screen is visible.

use std::time::Duration;

pub use sentry_core::collectors::procs::{Proc, SortBy, sort};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

pub struct ProcSampler {
    sys: System,
    users: Users,
}

impl Default for ProcSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcSampler {
    pub fn new() -> Self {
        Self {
            sys: System::new(),
            users: Users::new_with_refreshed_list(),
        }
    }

    pub fn sample_settled(&mut self) -> Vec<Proc> {
        self.sample();
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL.max(Duration::from_millis(250)));
        self.sample()
    }

    pub fn sample(&mut self) -> Vec<Proc> {
        self.sys.refresh_memory();
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_user(UpdateKind::OnlyIfNotSet)
                .with_cmd(UpdateKind::OnlyIfNotSet),
        );
        let total = self.sys.total_memory().max(1) as f32;
        self.sys
            .processes()
            .values()
            .filter(|p| p.thread_kind().is_none())
            .map(|p| {
                let uid = p.user_id().map(|u| **u);
                let user = p
                    .user_id()
                    .and_then(|u| self.users.get_user_by_id(u))
                    .map(|u| u.name().to_string())
                    .or_else(|| uid.map(|u| u.to_string()))
                    .unwrap_or_else(|| "?".into());
                let cmd = p
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ");
                Proc {
                    pid: p.pid().as_u32(),
                    user,
                    uid,
                    cpu: p.cpu_usage(),
                    mem_pct: p.memory() as f32 / total * 100.0,
                    run_time_s: p.run_time(),
                    cmd: if cmd.trim().is_empty() {
                        p.name().to_string_lossy().into_owned()
                    } else {
                        cmd
                    },
                }
            })
            .collect()
    }
}
