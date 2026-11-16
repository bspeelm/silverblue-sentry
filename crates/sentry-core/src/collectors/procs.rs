//! A process as both programs list it, and how the list is sorted. This machine samples
//! them with sysinfo; a server's come from `ps` and /proc over ssh.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proc {
    pub pid: u32,
    pub user: String,
    pub uid: Option<u32>,
    /// Per-core percentage, like top.
    pub cpu: f32,
    pub mem_pct: f32,
    pub run_time_s: u64,
    pub cmd: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortBy {
    #[default]
    Cpu,
    Mem,
}

pub fn sort(procs: &mut [Proc], by: SortBy) {
    match by {
        SortBy::Cpu => procs.sort_by(|a, b| {
            b.cpu
                .total_cmp(&a.cpu)
                .then(b.mem_pct.total_cmp(&a.mem_pct))
        }),
        SortBy::Mem => procs.sort_by(|a, b| {
            b.mem_pct
                .total_cmp(&a.mem_pct)
                .then(b.cpu.total_cmp(&a.cpu))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorted_by_cpu_or_memory() {
        let p = |pid: u32, cpu: f32, mem_pct: f32| Proc {
            pid,
            user: "u".into(),
            uid: Some(1000),
            cpu,
            mem_pct,
            run_time_s: 0,
            cmd: String::new(),
        };
        let mut v = vec![p(1, 1.0, 9.0), p(2, 50.0, 1.0), p(3, 1.0, 20.0)];
        sort(&mut v, SortBy::Cpu);
        assert_eq!(v.iter().map(|p| p.pid).collect::<Vec<_>>(), [2, 3, 1]);
        sort(&mut v, SortBy::Mem);
        assert_eq!(v.iter().map(|p| p.pid).collect::<Vec<_>>(), [3, 1, 2]);
    }
}
