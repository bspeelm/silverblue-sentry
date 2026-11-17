//! The Processes screen's sample: the probe, then `ps` and each process's CPU ticks from
//! /proc, in one exec. `ps`'s own %CPU is an average over the process's whole life, so the
//! share of a core is worked out here, from the ticks between two samples against the
//! aggregate `cpu` line the probe already reads. No sudo.

use std::collections::HashMap;

use super::probe;
use crate::remote::{Remote, SrvError};
use sentry_core::collectors::procs::Proc;

/// A kernel thread (`PF_KTHREAD` in /proc/<pid>/stat's flags): left out, as sentry does.
const PF_KTHREAD: u64 = 0x0020_0000;

#[derive(Debug, Clone, PartialEq)]
pub struct PsRow {
    pub pid: u32,
    pub uid: u32,
    pub user: String,
    pub rss_kib: u64,
    /// Seconds since it started.
    pub etimes: u64,
    pub args: String,
}

/// One process's line of /proc/<pid>/stat, as far as it's needed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tick {
    pub flags: u64,
    /// utime + stime, in clock ticks.
    pub ticks: u64,
    /// When it started, in clock ticks since boot: tells a reused pid apart.
    pub start: u64,
    /// Its parent (0 when this `awk` line didn't say).
    pub ppid: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Raw {
    pub probe: probe::Probe,
    /// The uid sentry-server logs in as.
    pub login_uid: Option<u32>,
    /// The shell that took this sample: its ancestors are the ssh session sentry-server
    /// talks through.
    pub self_pid: Option<u32>,
    pub rows: Vec<PsRow>,
    pub ticks: HashMap<u32, Tick>,
}

/// The probe's files, then who we are (uid, and this shell's pid), `ps` (with the user name
/// whole where this `ps` can; the uid is exact either way) and pid, flags, ticks, start time
/// and parent per process. The `sub`
/// drops everything up to the last `) `, so a command name with spaces or brackets can't
/// shift the fields; awk fails when a process goes away mid-glob, hence the `true`.
pub fn script() -> String {
    format!(
        "command -v ps >/dev/null || echo '@@missing ps'; {}; echo @@uid; id -u; echo @@self; \
         echo $$; echo @@ps; \
         ps -ww -eo pid=,uid=,user:32=,rss=,etimes=,args= 2>/dev/null \
         || ps -ww -eo pid=,uid=,user=,rss=,etimes=,args=; echo @@ticks; \
         awk '{{p=$1; sub(/^.*\\) /,\"\"); print p, $7, $12+$13, $20, $2}}' /proc/[0-9]*/stat \
         2>/dev/null; true",
        probe::script()
    )
}

/// `Err("ps")`: it isn't installed. The sections are cut at the lines that are exactly
/// `@@ps` and `@@ticks`: a `ps` line starts with a pid, so no process can forge one.
pub fn parse(text: &str) -> Result<Raw, String> {
    if text.lines().any(|l| l.trim() == "@@missing ps") {
        return Err("ps".into());
    }
    let lines: Vec<&str> = text.lines().collect();
    let ps_at = lines
        .iter()
        .position(|l| *l == "@@ps")
        .ok_or("no @@ps section")?;
    let ticks_at = lines[ps_at..]
        .iter()
        .position(|l| *l == "@@ticks")
        .map_or(lines.len(), |i| ps_at + i);
    let head = lines[..ps_at].join("\n");
    let probe = probe::parse(&head)?;
    let after = |mark: &str| {
        lines[..ps_at]
            .iter()
            .position(|l| *l == mark)
            .and_then(|i| lines.get(i + 1))
            .and_then(|l| l.trim().parse::<u32>().ok())
    };
    let (login_uid, self_pid) = (after("@@uid"), after("@@self"));
    let rows = lines[ps_at + 1..ticks_at]
        .iter()
        .filter_map(|l| ps_row(l))
        .collect();
    let ticks = lines
        .get(ticks_at + 1..)
        .unwrap_or_default()
        .iter()
        .filter_map(|l| {
            let v: Vec<u64> = l
                .split_whitespace()
                .map(|x| x.parse().ok())
                .collect::<Option<_>>()?;
            // Four numbers, or five with the parent.
            let (pid, flags, ticks, start, ppid) = match v[..] {
                [a, b, c, d] => (a, b, c, d, 0),
                [a, b, c, d, e] => (a, b, c, d, e),
                _ => return None,
            };
            Some((
                u32::try_from(pid).ok()?,
                Tick {
                    flags,
                    ticks,
                    start,
                    ppid: u32::try_from(ppid).ok()?,
                },
            ))
        })
        .collect();
    Ok(Raw {
        probe,
        login_uid,
        self_pid,
        rows,
        ticks,
    })
}

/// `pid uid user rss etimes args…`: five fields, then the rest of the line.
fn ps_row(l: &str) -> Option<PsRow> {
    let mut rest = l.trim_start();
    let mut field = || {
        let (f, r) = rest.split_once(char::is_whitespace)?;
        rest = r.trim_start();
        Some(f)
    };
    let pid = field()?.parse().ok()?;
    let uid = field()?.parse().ok()?;
    let user = field()?.to_string();
    let rss_kib = field()?.parse().ok()?;
    let etimes = field()?.parse().ok()?;
    Some(PsRow {
        pid,
        uid,
        user,
        rss_kib,
        etimes,
        args: rest.trim_end().to_string(),
    })
}

pub fn collect(r: &Remote) -> Result<Raw, SrvError> {
    parse(&r.output(&r.sh(&script()))?).map_err(|e| {
        if e == "ps" {
            SrvError::NotFound(e)
        } else {
            SrvError::Parse(e)
        }
    })
}

/// Each pid's (ticks, start).
type Seen = HashMap<u32, (u64, u64)>;

/// `pid` and its ancestors, nearest first, as far as the parents are known (init left out).
pub fn lineage(ticks: &HashMap<u32, Tick>, pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut at = pid;
    while at > 1 && !out.contains(&at) {
        out.push(at);
        at = ticks.get(&at).map_or(0, |t| t.ppid);
    }
    out
}

/// The command that ends a process, for the server's shell: nothing is signalled unless the
/// pid still belongs to the process that was listed (its start time in /proc is the one
/// sampled). `kill` is how: `kill`, `sudo -n kill` or `sudo kill`.
pub fn kill_script(pid: u32, start: u64, kill: &str) -> String {
    format!(
        "[ \"$(awk '{{sub(/^.*\\) /,\"\"); print $20}}' /proc/{pid}/stat 2>/dev/null)\" = \"{start}\" ] \
         || {{ echo \"process {pid} is gone\"; exit 1; }}; {kill} -TERM {pid}"
    )
}

/// CPU% between consecutive samples.
#[derive(Debug, Default)]
pub struct Rates {
    /// The aggregate cpu total and what each process had, last time.
    prev: Option<(u64, Seen)>,
}

impl Rates {
    /// The processes as the screen lists them. CPU is a share of one core, like top:
    /// `100 · cores · Δticks / Δtotal`, so neither the tick rate nor how long the sample
    /// took to arrive matters. No figure yet (NaN) on the first sample, or when the total
    /// went backwards (a reboot); 0 for a process that is new or whose pid was reused.
    pub fn procs(&mut self, raw: &Raw) -> Vec<Proc> {
        let total = raw.probe.cpu.total;
        let now: Seen = raw
            .ticks
            .iter()
            .map(|(pid, t)| (*pid, (t.ticks, t.start)))
            .collect();
        let prev = self.prev.replace((total, now));
        let dt = prev
            .as_ref()
            .and_then(|(t, _)| total.checked_sub(*t))
            .filter(|d| *d > 0);
        raw.rows
            .iter()
            .filter(|r| {
                raw.ticks
                    .get(&r.pid)
                    .is_none_or(|t| t.flags & PF_KTHREAD == 0)
            })
            .map(|r| {
                let cpu = match (dt, &prev, raw.ticks.get(&r.pid)) {
                    (Some(dt), Some((_, was)), Some(t)) => match was.get(&r.pid) {
                        Some((ticks, start)) if *start == t.start => {
                            100.0 * raw.probe.cores as f32 * t.ticks.saturating_sub(*ticks) as f32
                                / dt as f32
                        }
                        _ => 0.0,
                    },
                    // Listed by ps but gone before /proc was read.
                    (Some(_), _, None) => 0.0,
                    _ => f32::NAN,
                };
                Proc {
                    pid: r.pid,
                    user: r.user.clone(),
                    uid: Some(r.uid),
                    cpu,
                    mem_pct: if raw.probe.mem_total_kib == 0 {
                        0.0
                    } else {
                        100.0 * r.rss_kib as f32 / raw.probe.mem_total_kib as f32
                    },
                    run_time_s: r.etimes,
                    cmd: r.args.clone(),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::fixture;

    fn one(v: &[Proc], pid: u32) -> &Proc {
        v.iter().find(|p| p.pid == pid).unwrap()
    }

    #[test]
    fn parses_ps_and_ticks() {
        let r = parse(&fixture("procs-1.txt")).unwrap();
        assert_eq!(r.login_uid, Some(1000));
        assert_eq!(r.probe.cores, 4, "the probe is in the same sample");
        assert_eq!(r.self_pid, Some(52800));
        assert_eq!(r.rows.len(), 14);
        assert_eq!(r.ticks.len(), 14);
        let app = r.rows.iter().find(|p| p.pid == 901).unwrap();
        assert_eq!(
            (app.uid, app.user.as_str(), app.rss_kib, app.etimes),
            (999, "app", 412_000, 864_000)
        );
        assert_eq!(app.args, "/opt/app/bin/app --config /etc/app/app.toml");
        assert_eq!(
            r.ticks[&901],
            Tick {
                flags: 4_194_304,
                ticks: 9_000_000,
                start: 34_573_100,
                ppid: 1
            }
        );
        assert_eq!(parse("@@missing ps\n@@stat\n"), Err("ps".to_string()));
        // The script is one line for the remote shell.
        assert!(!script().contains('\n') && script().contains("echo @@ticks; awk"));
    }

    #[test]
    fn kernel_threads_are_left_out() {
        let r = parse(&fixture("procs-1.txt")).unwrap();
        let v = Rates::default().procs(&r);
        assert_eq!(v.len(), 12);
        assert!(v.iter().all(|p| !p.cmd.starts_with("[k")));
        // Memory is its share of the server's.
        assert!((one(&v, 901).mem_pct - 1.2875).abs() < 0.001);
        assert_eq!(one(&v, 901).run_time_s, 864_000);
    }

    #[test]
    fn the_first_sample_has_no_cpu() {
        let r = parse(&fixture("procs-1.txt")).unwrap();
        let v = Rates::default().procs(&r);
        assert!(v.iter().all(|p| p.cpu.is_nan()));
    }

    #[test]
    fn cpu_is_a_share_of_one_core_between_samples() {
        let mut rates = Rates::default();
        rates.procs(&parse(&fixture("procs-1.txt")).unwrap());
        let v = rates.procs(&parse(&fixture("procs-2.txt")).unwrap());
        // The total moved 800 on 4 cores: 150 ticks are 75% of one core, 10 are 5%.
        assert_eq!(one(&v, 901).cpu, 75.0);
        assert_eq!(one(&v, 1440).cpu, 5.0);
        assert_eq!(one(&v, 1).cpu, 0.0);
        // A process that wasn't there last time starts at zero.
        assert_eq!(one(&v, 52803).cpu, 0.0);
        // The total going backwards (a reboot): no figure rather than nonsense.
        let v = rates.procs(&parse(&fixture("procs-1.txt")).unwrap());
        assert!(one(&v, 901).cpu.is_nan());
    }

    #[test]
    fn a_reused_pid_starts_at_zero() {
        let mut rates = Rates::default();
        rates.procs(&parse(&fixture("procs-1.txt")).unwrap());
        // The same pid, started later, with more ticks than the old one had.
        let two = fixture("procs-2.txt").replace(
            "901 4194304 9000150 34573100 1",
            "901 4194304 9999999 120973000 1",
        );
        let v = rates.procs(&parse(&two).unwrap());
        assert_eq!(one(&v, 901).cpu, 0.0);
        assert_eq!(one(&v, 1440).cpu, 5.0);
    }

    #[test]
    fn a_command_with_brackets_and_spaces_parses() {
        let r = parse(&fixture("procs-1.txt")).unwrap();
        let sshd = r.rows.iter().find(|p| p.pid == 612).unwrap();
        assert_eq!(
            sshd.args,
            "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"
        );
        // Not a kernel thread, for all its brackets.
        assert!(Rates::default().procs(&r).iter().any(|p| p.pid == 612));
        assert_eq!(
            ps_row("  7 0 a-very-long-user-name-here 12 3 a  b ")
                .unwrap()
                .args,
            "a  b"
        );
        assert_eq!(ps_row("garbage"), None);
    }

    #[test]
    fn a_forged_section_line_is_ignored() {
        // A process calling itself a section, and junk among the ticks.
        let text = fixture("procs-1.txt")
            .replace(
                "@@ticks\n",
                "   9999  1000 admin 100 5 @@ticks\n@@ticks\n@@ps\n1 2 three 4\n7 7 7\n",
            )
            .replace("nginx: worker process", "@@ps @@ticks @@stat");
        let r = parse(&text).unwrap();
        assert_eq!(r.rows.len(), 15);
        assert_eq!(r.rows.last().unwrap().args, "@@ticks");
        // Junk among the ticks is skipped; a line without the parent still counts.
        assert_eq!(r.ticks.len(), 14);
        let old = parse(&text.replace(
            "901 4194304 9000000 34573100 1\n",
            "901 4194304 9000000 34573100\n",
        ))
        .unwrap();
        assert_eq!(old.ticks[&901].ppid, 0);
        // The sample's own shell quotes the marker for a missing ps: that isn't the marker.
        assert!(text.contains("echo '@@missing ps'"));
        assert_eq!(r.probe.cores, 4);
    }

    #[test]
    fn the_session_s_processes_are_known_and_a_kill_checks_the_start_time() {
        let r = parse(&fixture("procs-1.txt")).unwrap();
        // The shell that sampled, the session's sshd, the ssh server; not init.
        assert_eq!(lineage(&r.ticks, r.self_pid.unwrap()), [52800, 52790, 612]);
        assert_eq!(lineage(&r.ticks, 1502), [1502, 1440]);
        assert!(lineage(&r.ticks, 1).is_empty());
        // A loop in what was read ends.
        let mut t = r.ticks.clone();
        t.get_mut(&612).unwrap().ppid = 52800;
        assert_eq!(lineage(&t, 52800).len(), 3);
        let s = kill_script(901, 34_573_100, "sudo -n kill");
        assert_eq!(
            s,
            "[ \"$(awk '{sub(/^.*\\) /,\"\"); print $20}' /proc/901/stat 2>/dev/null)\" = \
             \"34573100\" ] || { echo \"process 901 is gone\"; exit 1; }; sudo -n kill -TERM 901"
        );
        // The script itself: its awk takes the parent too.
        assert!(
            script().contains("print p, $7, $12+$13, $20, $2}'") && script().contains("echo $$")
        );
    }
}
