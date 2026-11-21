//! The guard: the one way sentry changes the configs a network is reached through
//! (network, firewall, wireless, dhcp, dropbear, uhttpd). A change is a list of `uci`
//! staging lines on those configs and the services to reload. Before anything is touched
//! the router is armed to take the change back by itself: a detached shell that sleeps
//! `window` seconds and then, unless it was disarmed, copies the configs' snapshot back,
//! reloads the same services and says so in the log. sentry then applies, reconnects on a
//! new connection, and disarms only when the router still answers and its uplink, default
//! route and firewall are as they should be. A Wi-Fi change is never kept that way: ssh
//! over a cable can't tell that Wi-Fi still works, so it stays armed until the user says
//! keep. Whatever goes wrong after arming (the link gone, sentry gone, a check failing),
//! sentry does nothing more: the router restores itself at the deadline.
//!
//! The scripts are built here, pure (`*_script`, snapshot-tested); `run` and `keep` carry
//! them out over ssh. The dead-man is the only thing sentry ever leaves running on a
//! router, for at most the window.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::policy::GUARDED;
use crate::remote::Router;
use sentry_core::exec::sh_quote;

/// What may be reloaded, in the order it is: the network first, the door (ssh) last.
pub const SERVICES: &[&str] = &[
    "network", "wifi", "firewall", "dnsmasq", "odhcpd", "uhttpd", "dropbear",
];

/// The verbs a staging line may use.
const VERBS: &[&str] = &[
    "set", "add", "add_list", "del_list", "delete", "rename", "reorder",
];

/// The default window, in seconds.
pub const WINDOW: u64 = 300;

/// One guarded change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    /// The configs it touches (snapshotted, committed, restored).
    pub configs: Vec<String>,
    /// Each staging line: what follows `uci`.
    pub lines: Vec<Vec<String>>,
    /// What is reloaded afterwards, in `SERVICES`' order.
    pub services: Vec<String>,
    /// It is meant to change the uplink or the default route: sentry can't check those
    /// against before, so it asks.
    pub alters_wan: bool,
}

fn list(s: &str) -> Vec<String> {
    s.split([',', ' '])
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

impl Change {
    /// From a workflow's values: `configs` and `services` comma-separated, `lines` the uci
    /// commands with `;` or newlines between them. Err: why it isn't a guarded change.
    pub fn parse(
        configs: &str,
        lines: &str,
        services: &str,
        alters_wan: bool,
    ) -> Result<Self, String> {
        let mut configs = list(configs);
        configs.dedup();
        if configs.is_empty() {
            return Err(
                "no config named (configs: network, firewall, wireless, dhcp, dropbear, uhttpd)"
                    .into(),
            );
        }
        if let Some(c) = configs.iter().find(|c| !GUARDED.contains(&c.as_str())) {
            return Err(format!(
                "`{c}` isn't one of the guarded configs ({}): change it with a plain `uci` request",
                GUARDED.join(", ")
            ));
        }
        let asked = list(services);
        let mut services: Vec<String> = Vec::new();
        for s in asked {
            if !SERVICES.contains(&s.as_str()) {
                return Err(format!(
                    "`{s}` isn't a service the guard reloads ({})",
                    SERVICES.join(", ")
                ));
            }
            if !services.contains(&s) {
                services.push(s);
            }
        }
        services.sort_by_key(|s| SERVICES.iter().position(|x| x == s));
        let mut out = Vec::new();
        for (i, words) in crate::policy::plain_commands(lines)?
            .into_iter()
            .enumerate()
        {
            let n = i + 1;
            let shown = words.join(" ");
            let [uci, verb, args @ ..] = words.as_slice() else {
                return Err(format!("line {n} (`{shown}`) isn't a uci command"));
            };
            if uci != "uci" && uci != "/sbin/uci" {
                return Err(format!(
                    "line {n} (`{shown}`): only `uci` lines are staged in a guard step"
                ));
            }
            let cfg = args
                .first()
                .map_or("", |a| a.split(['.', '=']).next().unwrap_or(""));
            // The guard commits: a commit of one of its configs says nothing new.
            if verb == "commit" && configs.iter().any(|c| c == cfg) && args.len() == 1 {
                continue;
            }
            if !VERBS.contains(&verb.as_str()) {
                return Err(format!(
                    "line {n} (`{shown}`): `uci {verb}` isn't staged in a guard step (only {})",
                    VERBS.join(", ")
                ));
            }
            let want = if verb == "add" { 2 } else { 1 };
            if args.len() != want || args.iter().any(|a| a.starts_with('-')) {
                return Err(format!(
                    "line {n} (`{shown}`): `uci {verb}` takes {want} argument{} (quote a value with spaces)",
                    if want == 1 { "" } else { "s" }
                ));
            }
            if !configs.iter().any(|c| c == cfg) {
                return Err(format!(
                    "line {n} (`{shown}`) is about `{cfg}`, which isn't in this change's configs ({})",
                    configs.join(", ")
                ));
            }
            if args.iter().any(|a| a.contains('\n')) {
                return Err(format!("line {n}: a value can't span lines"));
            }
            out.push(words[1..].to_vec());
        }
        if out.is_empty() {
            return Err("no uci line to stage".into());
        }
        Ok(Self {
            configs,
            lines: out,
            services,
            alters_wan,
        })
    }

    /// It touches Wi-Fi.
    pub fn wifi(&self) -> bool {
        self.configs.iter().any(|c| c == "wireless") || self.services.iter().any(|s| s == "wifi")
    }

    /// Whether it stays is asked, not decided by the checks alone.
    pub fn asks(&self) -> bool {
        self.wifi() || self.alters_wan
    }

    /// The configs whose staged lines would ride along: the ones touched, and the ones the
    /// reloaded services read (a reload sees staged lines, committed or not).
    pub fn relevant(&self) -> Vec<String> {
        let mut out = self.configs.clone();
        for s in &self.services {
            let reads: &[&str] = match s.as_str() {
                "network" => &["network", "wireless"],
                "wifi" => &["wireless", "network"],
                "firewall" => &["firewall", "network"],
                "dnsmasq" | "odhcpd" => &["dhcp", "network"],
                "dropbear" => &["dropbear"],
                "uhttpd" => &["uhttpd"],
                _ => &[],
            };
            for c in reads {
                if !out.iter().any(|x| x == c) {
                    out.push(c.to_string());
                }
            }
        }
        out
    }

    /// The staging lines as the router's shell runs them.
    fn uci_lines(&self) -> Vec<String> {
        self.lines
            .iter()
            .map(|l| {
                format!(
                    "uci {}",
                    l.iter().map(|w| sh_quote(w)).collect::<Vec<_>>().join(" ")
                )
            })
            .collect()
    }
}

/// How a service is reloaded.
fn reload_cmd(service: &str) -> String {
    match service {
        "wifi" => "wifi reload".into(),
        s => format!("/etc/init.d/{s} reload"),
    }
}

/// A new guard's name: 16 hex digits nobody can guess.
pub fn token() -> std::io::Result<String> {
    use std::io::Read;
    let mut b = [0u8; 8];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn dir(token: &str) -> String {
    format!("/tmp/sentry-guard-{token}")
}

/// Where the router says a guard took its change back.
const LAST: &str = "/tmp/sentry-guard.last";

// ---- the scripts (pure)

/// (a) What the router is like now: reads only. Used before (preflight) and after (confirm).
pub fn state_script(c: &Change, token: Option<&str>) -> String {
    let mut s = String::from("echo @@board; ubus call system board >/dev/null 2>&1 && echo ok\n");
    s.push_str("echo @@guards; ls -d /tmp/sentry-guard-*/ 2>/dev/null\n");
    s.push_str(&format!(
        "echo @@staged; for c in {}; do uci -q changes $c; done\n",
        c.relevant().join(" ")
    ));
    s.push_str("echo @@wan; ubus call network.interface dump 2>/dev/null\n");
    s.push_str(
        "echo @@route; ip route show default 2>/dev/null; ip -6 route show default 2>/dev/null\n",
    );
    s.push_str("echo @@firewall; uci -q show firewall\n");
    s.push_str(
        "echo @@stations; for h in $(ubus list 'hostapd.*' 2>/dev/null); do \
         echo \"$h $(ubus call $h get_clients 2>/dev/null | grep -c '\"auth\"')\"; done\n",
    );
    if let Some(t) = token {
        let d = dir(t);
        s.push_str(&format!(
            "echo @@reloaded; cat {d}/reloaded 2>/dev/null\necho @@armed; [ -e {d}/armed ] && echo yes\necho @@log; tail -n 8 {d}/reload.log 2>/dev/null\n"
        ));
    }
    s.push_str("echo @@end\n");
    s
}

/// (b) and (c): snapshot the configs and arm the dead-man. Nothing is changed.
pub fn arm_script(c: &Change, token: &str, window: u64) -> String {
    let d = dir(token);
    let configs = c.configs.join(" ");
    let services = c.services.join(" ");
    let reloads: String = c
        .services
        .iter()
        .map(|s| format!("{} >/dev/null 2>&1\n", reload_cmd(s)))
        .collect();
    format!(
        "set -e\n\
         umask 077\n\
         D={d}\n\
         mkdir \"$D\" \"$D/config\"\n\
         for c in {configs}; do\n\
         \x20 if [ -e /etc/config/$c ]; then cp -p /etc/config/$c \"$D/config/$c\"; else : > \"$D/config/$c.absent\"; fi\n\
         done\n\
         cat > \"$D/restore.sh\" <<'SENTRY_EOF'\n\
         #!/bin/sh\n\
         # sentry's guard {token}: the configs as they were before its change.\n\
         D={d}\n\
         for c in {configs}; do\n\
         \x20 uci -q revert $c\n\
         \x20 if [ -e \"$D/config/$c\" ]; then cp -p \"$D/config/$c\" /etc/config/$c\n\
         \x20 elif [ -e \"$D/config/$c.absent\" ]; then rm -f /etc/config/$c; fi\n\
         done\n\
         SENTRY_EOF\n\
         cat > \"$D/deadman.sh\" <<'SENTRY_EOF'\n\
         #!/bin/sh\n\
         # sentry's guard {token}: unless disarmed within {window} s, take the change back.\n\
         D={d}\n\
         echo $$ > \"$D/pid\"\n\
         sleep {window} &\n\
         echo $! > \"$D/sleep.pid\"\n\
         wait $!\n\
         [ -e \"$D/armed\" ] || exit 0\n\
         rm -f \"$D/armed\"\n\
         logger -t sentry-guard \"{token}: not confirmed within {window}s: restoring {configs}\"\n\
         sh \"$D/restore.sh\"\n\
         {reloads}\
         echo \"{token} reverted $(date +%s)\" > {LAST}\n\
         logger -t sentry-guard \"{token}: restored {configs}; reloaded {services}\"\n\
         rm -rf \"$D\"\n\
         SENTRY_EOF\n\
         : > \"$D/armed\"\n\
         setsid sh \"$D/deadman.sh\" </dev/null >/dev/null 2>&1 &\n\
         echo @@snapshot\n"
    )
}

/// (c) Is the dead-man really there: its marker, its shell and its sleep, all alive.
pub fn armed_script(token: &str) -> String {
    let d = dir(token);
    format!(
        "D={d}\n\
         [ -e \"$D/armed\" ] && [ -s \"$D/pid\" ] && [ -s \"$D/sleep.pid\" ] \\\n\
         \x20 && kill -0 \"$(cat \"$D/pid\")\" 2>/dev/null && kill -0 \"$(cat \"$D/sleep.pid\")\" 2>/dev/null \\\n\
         \x20 && echo \"armed $(cat \"$D/pid\")\"\n"
    )
}

/// (d) Stage, show what is staged, commit, and start the reloads detached (they outlive
/// this connection; their output is under the guard's directory). Exit 3: a line or the
/// commit failed and nothing was reloaded.
pub fn apply_script(c: &Change, token: &str) -> String {
    let d = dir(token);
    let mut s = format!(
        "D={d}\n\
         [ -e \"$D/armed\" ] || {{ echo 'sentry-guard: not armed'; exit 9; }}\n\
         fail() {{ echo \"sentry-guard: $1\"; exit 3; }}\n"
    );
    for (i, l) in c.uci_lines().iter().enumerate() {
        s.push_str(&format!("{l} || fail 'line {} failed'\n", i + 1));
    }
    let configs = c.configs.join(" ");
    s.push_str(&format!(
        "echo @@changes\nfor c in {configs}; do uci -q changes $c; done\necho @@commit\n\
         for c in {configs}; do uci commit $c || fail \"commit $c failed\"; done\n"
    ));
    s.push_str("cat > \"$D/reload.sh\" <<'SENTRY_EOF'\n#!/bin/sh\n");
    s.push_str(&format!("D={d}\nrc=0\n: > \"$D/reload.log\"\n"));
    for svc in &c.services {
        s.push_str(&format!(
            "{} >> \"$D/reload.log\" 2>&1 || rc=1\n",
            reload_cmd(svc)
        ));
    }
    s.push_str("echo $rc > \"$D/reloaded\"\nSENTRY_EOF\n");
    s.push_str("setsid sh \"$D/reload.sh\" </dev/null >/dev/null 2>&1 &\necho @@launched\n");
    s
}

/// Disarm: the marker first (so the sleeper does nothing even if it wakes now), then the
/// sleeper, then the directory. Says `gone` when nothing is left, `reverted` if the
/// dead-man had already taken the change back.
pub fn disarm_script(token: &str) -> String {
    let d = dir(token);
    format!(
        "D={d}\n\
         rm -f \"$D/armed\"\n\
         [ -s \"$D/sleep.pid\" ] && kill \"$(cat \"$D/sleep.pid\")\" 2>/dev/null\n\
         [ -s \"$D/pid\" ] && kill \"$(cat \"$D/pid\")\" 2>/dev/null\n\
         rm -rf \"$D\"\n\
         [ -e \"$D\" ] && echo left || echo gone\n\
         grep -q '^{token} reverted' {LAST} 2>/dev/null && echo reverted\n\
         true\n"
    )
}

/// A line or the commit failed, before anything was reloaded: the snapshot back, the
/// staged lines dropped, then disarmed.
pub fn abort_script(token: &str) -> String {
    format!("sh {}/restore.sh\n{}", dir(token), disarm_script(token))
}

/// (g) After the deadline: did the router take it back?
pub fn settled_script(token: &str) -> String {
    let d = dir(token);
    format!(
        "[ -d {d} ] && echo @@still\n\
         grep '^{token} ' {LAST} 2>/dev/null\n\
         logread -e sentry-guard 2>/dev/null | grep '{token}' | tail -n 2\n\
         true\n"
    )
}

// ---- what the router said

/// The router as a guard sees it, before and after.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct State {
    pub board: bool,
    /// Other guards' directories.
    pub guards: Vec<String>,
    /// Staged lines of the configs that matter.
    pub staged: Vec<String>,
    /// Each uplink interface and whether it is up; None: the router didn't say.
    pub wan: Option<Vec<(String, bool)>>,
    /// The default routes: `via <gateway> dev <device>`, sorted.
    pub routes: Vec<String>,
    /// The zones whose input is REJECT or DROP, and every enabled port forward
    /// (`proto port → address`); None: the firewall config didn't read.
    pub firewall: Option<(Vec<String>, Vec<String>)>,
    /// Stations per radio.
    pub stations: Vec<(String, u32)>,
    /// The reloads' worst exit code, once they're done.
    pub reloaded: Option<i32>,
    pub armed: bool,
    pub reload_log: String,
    /// The whole answer arrived.
    pub complete: bool,
}

pub fn parse_state(text: &str) -> State {
    let mut s = State::default();
    for (name, body) in crate::collect::sections(text) {
        let lines = || body.lines().map(str::trim).filter(|l| !l.is_empty());
        match name {
            "board" => s.board = body.trim() == "ok",
            "guards" => {
                s.guards = lines()
                    .map(|l| l.trim_end_matches('/').to_string())
                    .collect()
            }
            "staged" => s.staged = lines().map(str::to_string).collect(),
            "wan" => {
                s.wan = serde_json::from_str::<serde_json::Value>(body)
                    .ok()
                    .and_then(|v| {
                        let list = v.get("interface")?.as_array()?;
                        Some(
                            list.iter()
                                .filter_map(|i| {
                                    let name = i.get("interface")?.as_str()?;
                                    let default = i
                                        .get("route")
                                        .and_then(|r| r.as_array())
                                        .is_some_and(|r| {
                                            r.iter().any(|x| {
                                                x.get("mask").and_then(|m| m.as_u64()) == Some(0)
                                            })
                                        });
                                    (name.starts_with("wan") || default).then(|| {
                                        (
                                            name.to_string(),
                                            i.get("up").and_then(|u| u.as_bool()).unwrap_or(false),
                                        )
                                    })
                                })
                                .collect(),
                        )
                    });
            }
            "route" => {
                s.routes = lines()
                    .map(|l| {
                        let w: Vec<&str> = l.split_whitespace().collect();
                        let after = |k: &str| {
                            w.iter()
                                .position(|x| *x == k)
                                .and_then(|i| w.get(i + 1))
                                .copied()
                                .unwrap_or("-")
                        };
                        format!("via {} dev {}", after("via"), after("dev"))
                    })
                    .collect();
                s.routes.sort();
                s.routes.dedup();
            }
            "firewall" => {
                if !body.trim().is_empty() {
                    let u = crate::collect::uci::parse(
                        &format!("@@firewall\n{body}"),
                        &crate::redact::Salt::fixed([0; 16]),
                    );
                    let closed: Vec<String> = u
                        .zones()
                        .into_iter()
                        .filter(|z| matches!(z.input.as_str(), "REJECT" | "DROP"))
                        .map(|z| z.name)
                        .collect();
                    let mut forwards: Vec<String> = u
                        .forwards()
                        .into_iter()
                        .filter(|f| f.enabled)
                        .flat_map(|f| {
                            f.protos
                                .iter()
                                .map(|p| format!("{p} {} → {}", f.port, f.dest_ip))
                                .collect::<Vec<_>>()
                        })
                        .collect();
                    forwards.sort();
                    if !u.zones().is_empty() {
                        s.firewall = Some((closed, forwards));
                    }
                }
            }
            "stations" => {
                s.stations = lines()
                    .filter_map(|l| {
                        let (h, n) = l.rsplit_once(' ')?;
                        Some((h.to_string(), n.parse().ok()?))
                    })
                    .collect();
            }
            "reloaded" => s.reloaded = body.trim().parse().ok(),
            "armed" => s.armed = body.trim() == "yes",
            "log" => s.reload_log = body.trim_end().to_string(),
            "end" => s.complete = true,
            _ => {}
        }
    }
    s
}

/// (a) Why the change can't start, if it can't: nothing has been touched.
pub fn preflight(c: &Change, s: &State) -> Result<(), String> {
    if !s.complete || !s.board {
        return Err("the router didn't answer (ubus call system board)".into());
    }
    if let Some(g) = s.guards.first() {
        return Err(format!(
            "another guarded change is armed on the router ({g}): it settles by itself within its window"
        ));
    }
    if !s.staged.is_empty() {
        return Err(format!(
            "someone else's changes are staged in the configs this would commit or reload \
             (LuCI's \"unsaved changes\", a `uci set` by hand, or a package that keeps its own \
             lines staged): {}. Save or revert them on the router first; the guard commits \
             only what it staged",
            s.staged.join("; ")
        ));
    }
    if s.wan.is_none() {
        return Err("the router didn't say how its uplink is (ubus call network.interface dump): without it there's nothing to check the change against".into());
    }
    if c.configs.iter().any(|x| x == "firewall") && s.firewall.is_none() {
        return Err(
            "the firewall config didn't read: there's nothing to check the change against".into(),
        );
    }
    Ok(())
}

/// (f) Why the change isn't confirmed, if it isn't. `expected`: the port forwards the
/// config says must exist (`proto port → address`).
pub fn confirm(
    c: &Change,
    before: &State,
    after: &State,
    expected: &[String],
) -> Result<(), String> {
    if !after.complete || !after.board {
        return Err("the router didn't answer after the change".into());
    }
    match after.reloaded {
        None => return Err("the reloads hadn't finished".into()),
        Some(0) => {}
        Some(_) => {
            return Err(format!(
                "a reload failed: {}",
                after
                    .reload_log
                    .lines()
                    .last()
                    .unwrap_or("(nothing in its log)")
            ));
        }
    }
    if !c.alters_wan {
        if after.wan != before.wan {
            return Err(format!(
                "the uplink isn't as it was (before {:?}, now {:?})",
                before.wan, after.wan
            ));
        }
        if after.routes != before.routes {
            return Err("the default route isn't as it was".into());
        }
    }
    if c.relevant().iter().any(|x| x == "firewall") {
        let Some((closed, forwards)) = &after.firewall else {
            return Err("the firewall config no longer reads".into());
        };
        let (was_closed, was) = before.firewall.clone().unwrap_or_default();
        if let Some(z) = was_closed.iter().find(|z| !closed.contains(z)) {
            return Err(format!(
                "zone {z} no longer rejects what is sent to the router itself (its input was REJECT or DROP)"
            ));
        }
        if let Some(f) = expected
            .iter()
            .find(|f| was.contains(f) && !forwards.contains(f))
        {
            return Err(format!(
                "the port forward {f} is gone, and network_config.yaml expects it"
            ));
        }
    }
    Ok(())
}

/// The port forwards the config expects, as `State.firewall` words them.
pub fn expected_forwards(cfg: &crate::config::Network) -> Vec<String> {
    cfg.expect
        .forwards
        .iter()
        .flat_map(|f| {
            let port = if f.port.from == f.port.to {
                f.port.from.to_string()
            } else {
                format!("{}-{}", f.port.from, f.port.to)
            };
            let protos: Vec<&str> = match f.proto.as_str() {
                "" | "any" | "tcpudp" | "all" => vec!["tcp", "udp"],
                p => p.split_whitespace().collect(),
            };
            protos
                .into_iter()
                .map(|p| format!("{p} {port} → {}", f.to))
                .collect::<Vec<_>>()
        })
        .collect()
}

// ---- carrying it out

/// How a guarded change ended.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Confirmed and disarmed: it stays.
    Kept,
    /// Applied and still armed: the user is asked (`keep`), and the router takes it back
    /// at the deadline otherwise.
    Waiting,
    /// Not started: nothing was changed, and why.
    Stopped(String),
    /// A line or the commit failed before anything was reloaded: put back, and why.
    Failed(String),
    /// Not confirmed: the router took it back by itself, and why it wasn't confirmed.
    Reverted(String),
    /// Not confirmed, and the router can't be reached to see that it took it back.
    Unknown(String),
}

impl Outcome {
    pub fn word(&self) -> &'static str {
        match self {
            Outcome::Kept => "kept",
            Outcome::Waiting => "waiting",
            Outcome::Stopped(_) => "stopped",
            Outcome::Failed(_) => "failed",
            Outcome::Reverted(_) => "reverted",
            Outcome::Unknown(_) => "unknown",
        }
    }

    /// The process's exit code: 0 only when the change is in place.
    pub fn code(&self) -> u8 {
        match self {
            Outcome::Kept | Outcome::Waiting => 0,
            Outcome::Stopped(_) => 3,
            Outcome::Reverted(_) => 4,
            Outcome::Failed(_) => 5,
            Outcome::Unknown(_) => 6,
        }
    }
}

/// A change applied and still armed, waiting for the user's "keep".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    pub token: String,
    /// When the router takes it back (epoch seconds, this machine's clock; never later
    /// than the router's own deadline).
    pub deadline: i64,
    pub change: Change,
}

fn guard_dir(scope: &str) -> std::path::PathBuf {
    sentry_core::maint::data_root(scope).join("guard")
}

pub fn pending_path(scope: &str) -> std::path::PathBuf {
    guard_dir(scope).join("pending.json")
}

pub fn pending(scope: &str) -> Option<Pending> {
    serde_json::from_str(&std::fs::read_to_string(pending_path(scope)).ok()?).ok()
}

/// The guard's own journal on this machine: one JSON line per change and how it ended.
pub fn journal_path(scope: &str) -> std::path::PathBuf {
    guard_dir(scope).join("log.jsonl")
}

fn journal(scope: &str, token: &str, c: &Change, o: &Outcome) {
    use std::io::Write;
    let why = match o {
        Outcome::Stopped(w) | Outcome::Failed(w) | Outcome::Reverted(w) | Outcome::Unknown(w) => {
            w.as_str()
        }
        _ => "",
    };
    let line = serde_json::json!({
        "at": jiff::Timestamp::now().to_string(),
        "token": token,
        "configs": c.configs,
        "services": c.services,
        "lines": c.lines.len(),
        "outcome": o.word(),
        "why": why,
    });
    let _ = std::fs::create_dir_all(guard_dir(scope));
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(journal_path(scope))
    {
        let _ = writeln!(f, "{line}");
    }
}

/// How long before the deadline sentry stops trying to confirm: a disarm must never race
/// the sleeper.
pub fn margin(window: u64) -> u64 {
    (window / 5).clamp(2, 15)
}

/// A read on a connection of its own (the shared one may be dead after a reload).
fn fresh(r: &Router, script: &str) -> Result<String, String> {
    r.sh(script)
        .own_connection()
        .timeout(Some(Duration::from_secs(20)))
        .output()
        .map_err(|e| e.to_string())
}

fn shared(r: &Router, script: &str) -> Result<sentry_core::exec::Output, String> {
    r.sh(script)
        .timeout(Some(Duration::from_secs(30)))
        .run()
        .map_err(|e| e.to_string())
}

/// What is staged, as it may be shown: scrubbed, or (when what to hide isn't known) the
/// option names alone.
fn shown_changes(body: &str, scrub: Option<&crate::redact::Scrub>) -> Vec<String> {
    body.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| match scrub {
            Some(s) => s.text(l),
            None => format!("{}=…", l.split('=').next().unwrap_or(l)),
        })
        .collect()
}

/// (a) alone: what the change would do and whether it could start. Reads only.
pub fn preview(r: &Router, c: &Change, say: &mut dyn FnMut(String)) -> Result<State, String> {
    say(format!(
        "guarded change · configs: {} · reload: {}{}",
        c.configs.join(", "),
        if c.services.is_empty() {
            "nothing".to_string()
        } else {
            c.services.join(", ")
        },
        if c.asks() {
            " · asks before it's kept"
        } else {
            ""
        }
    ));
    let scrub = crate::redact::Scrub::read(r).ok();
    for l in c.uci_lines() {
        say(format!(
            "  {}",
            scrub.as_ref().map_or_else(|| l.clone(), |s| s.text(&l))
        ));
    }
    let out = shared(r, &state_script(c, None))?;
    let s = parse_state(&out.stdout);
    if let Err(why) = preflight(c, &s) {
        // The staged lines are the router's: shown scrubbed.
        return Err(scrub.as_ref().map_or(why.clone(), |sc| sc.text(&why)));
    }
    say(format!(
        "preflight: the router answers · nothing else is staged · uplink {} · {} default route(s){}",
        s.wan
            .as_ref()
            .map(|w| {
                w.iter()
                    .map(|(n, up)| format!("{n} {}", if *up { "up" } else { "down" }))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
        s.routes.len(),
        if c.wifi() {
            format!(" · stations {}", stations(&s))
        } else {
            String::new()
        }
    ));
    Ok(s)
}

fn stations(s: &State) -> String {
    if s.stations.is_empty() {
        return "none (no radio answers)".into();
    }
    s.stations
        .iter()
        .map(|(h, n)| format!("{} {n}", h.trim_start_matches("hostapd.")))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The whole sequence. `say` gets each line for the window; the outcome is journalled.
pub fn run(r: &Router, c: &Change, window: u64, say: &mut dyn FnMut(String)) -> Outcome {
    let token = match token() {
        Ok(t) => t,
        Err(e) => return Outcome::Stopped(format!("no random token: {e}")),
    };
    let o = run_with(r, c, window, &token, say);
    journal(&r.scope, &token, c, &o);
    o
}

fn run_with(
    r: &Router,
    c: &Change,
    window: u64,
    token: &str,
    say: &mut dyn FnMut(String),
) -> Outcome {
    if pending(&r.scope).is_some() {
        return Outcome::Stopped(
            "an earlier guarded change still waits for its answer (keep it, or let its window pass)".into(),
        );
    }
    // (a) Preflight.
    let before = match preview(r, c, say) {
        Ok(s) => s,
        Err(why) => return Outcome::Stopped(why),
    };
    let scrub = crate::redact::Scrub::read(r).ok();
    // (b) + (c) Snapshot and arm. The clock starts before the router's does.
    let armed_at = Instant::now();
    let wall = jiff::Timestamp::now().as_second();
    let limit = Duration::from_secs(window.saturating_sub(margin(window)));
    let arm = shared(r, &arm_script(c, token, window));
    let mut verified = false;
    if matches!(&arm, Ok(o) if o.code == 0 && o.stdout.contains("@@snapshot")) {
        for _ in 0..4 {
            if fresh(r, &armed_script(token)).is_ok_and(|o| o.trim().starts_with("armed ")) {
                verified = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    if !verified {
        // Nothing has changed yet: whatever was made of the guard is removed.
        let _ = shared(r, &disarm_script(token));
        let why = match arm {
            Ok(o) if o.code != 0 => o.stderr.lines().last().unwrap_or("").trim().to_string(),
            Err(e) => e,
            _ => "its sleeper isn't running".into(),
        };
        return Outcome::Stopped(format!(
            "the revert couldn't be armed on the router ({why}): nothing was changed"
        ));
    }
    say(format!(
        "armed: the router takes the change back by itself in {window} s unless it's confirmed"
    ));
    // (d) Stage, commit, reload.
    match shared(r, &apply_script(c, token)) {
        Ok(o) if o.code == 3 => {
            let why = o
                .stdout
                .lines()
                .chain(o.stderr.lines())
                .rfind(|l| !l.starts_with("@@"))
                .unwrap_or("")
                .to_string();
            let why = scrub.as_ref().map_or(why.clone(), |s| s.text(&why));
            return match shared(r, &abort_script(token)) {
                Ok(a) if a.stdout.contains("gone") => Outcome::Failed(format!(
                    "{why}: nothing was reloaded, and the configs are as they were"
                )),
                _ => wait_revert(r, token, window, armed_at, say, why),
            };
        }
        Ok(o) if o.stdout.contains("@@launched") => {
            let staged = crate::collect::sections(&o.stdout)
                .into_iter()
                .find(|(n, _)| *n == "changes")
                .map_or("", |(_, b)| b);
            say("staged (uci changes):".into());
            for l in shown_changes(staged, scrub.as_ref()) {
                say(format!("  {l}"));
            }
            say(format!(
                "committed {} · reloading {}",
                c.configs.join(", "),
                if c.services.is_empty() {
                    "nothing".into()
                } else {
                    c.services.join(", ")
                }
            ));
        }
        // The connection went mid-way, or the answer isn't what it should be: the state
        // isn't known, so nothing more is done.
        Ok(o) => {
            let why = format!("applying it ended unexpectedly (exit {})", o.code);
            return wait_revert(r, token, window, armed_at, say, why);
        }
        Err(e) => {
            return wait_revert(r, token, window, armed_at, say, format!("applying it: {e}"));
        }
    }
    // (e) Reconnect on a new connection, and (f) confirm.
    let mut why = "the router didn't answer on a new connection".to_string();
    let mut after = None;
    while armed_at.elapsed() < limit {
        std::thread::sleep(Duration::from_millis(700));
        match fresh(r, &state_script(c, Some(token))) {
            Ok(text) => {
                let s = parse_state(&text);
                match confirm(c, &before, &s, &expected_forwards(&r.cfg)) {
                    Ok(()) if s.armed => {
                        after = Some(s);
                        break;
                    }
                    Ok(()) => why = "the guard was no longer armed".into(),
                    Err(e) => why = e,
                }
            }
            Err(_) => why = "the router didn't answer on a new connection".into(),
        }
    }
    let Some(after) = after else {
        say(format!("not confirmed: {why}"));
        return wait_revert(r, token, window, armed_at, say, why);
    };
    say(format!(
        "confirmed on a new connection: the router answers · reloads done · uplink and default route {}{}",
        if c.alters_wan {
            "changed as meant"
        } else {
            "as before"
        },
        if c.relevant().iter().any(|x| x == "firewall") {
            " · firewall zones and forwards in place"
        } else {
            ""
        }
    ));
    if c.asks() {
        let p = Pending {
            token: token.to_string(),
            deadline: wall + window as i64,
            change: c.clone(),
        };
        let saved = std::fs::create_dir_all(guard_dir(&r.scope)).and_then(|_| {
            sentry_core::paths::write_atomic(
                &pending_path(&r.scope),
                serde_json::to_string(&p).unwrap_or_default().as_bytes(),
            )
        });
        if let Err(e) = saved {
            let why = format!("couldn't keep track of the armed change here ({e})");
            return wait_revert(r, token, window, armed_at, say, why);
        }
        if c.wifi() {
            say(format!(
                "stations before: {} · now: {}",
                stations(&before),
                stations(&after)
            ));
            say(
                "ssh over a cable can't tell that Wi-Fi still works: check a device on Wi-Fi."
                    .into(),
            );
        }
        let left = window.saturating_sub(armed_at.elapsed().as_secs());
        say(format!(
            "KEEP? Still armed: the router takes this back by itself in about {left} s unless you keep it."
        ));
        return Outcome::Waiting;
    }
    disarm(r, token, armed_at, limit, say)
}

/// Disarm, and see that it held.
fn disarm(
    r: &Router,
    token: &str,
    armed_at: Instant,
    limit: Duration,
    say: &mut dyn FnMut(String),
) -> Outcome {
    if armed_at.elapsed() >= limit {
        let why = "too close to the deadline to disarm safely".to_string();
        return Outcome::Reverted(format!("{why}: the router takes it back by itself"));
    }
    match fresh(r, &disarm_script(token)) {
        Ok(out) if out.contains("gone") && !out.contains("reverted") => {
            say("disarmed: the change is kept (no sleeper, no snapshot left on the router)".into());
            Outcome::Kept
        }
        Ok(out) if out.contains("reverted") => {
            Outcome::Reverted("the router had already taken it back".into())
        }
        Ok(_) => Outcome::Unknown("the guard's directory couldn't be removed".into()),
        Err(e) => Outcome::Unknown(format!(
            "disarming failed ({e}): the router may take the change back at the deadline"
        )),
    }
}

/// (g) Not confirmed: nothing is done; once the deadline has passed, ask the router
/// whether it took the change back.
fn wait_revert(
    r: &Router,
    token: &str,
    window: u64,
    armed_at: Instant,
    say: &mut dyn FnMut(String),
    why: String,
) -> Outcome {
    let deadline = Duration::from_secs(window);
    let left = deadline.saturating_sub(armed_at.elapsed());
    say(format!(
        "sentry does nothing more: the router restores itself in about {} s",
        left.as_secs()
    ));
    std::thread::sleep(left + Duration::from_secs(2));
    // The reloads of the revert take a moment; then it answers again.
    let until = Instant::now() + Duration::from_secs(45);
    let mut last = String::new();
    while Instant::now() < until {
        match fresh(r, &settled_script(token)) {
            Ok(out) if out.contains(&format!("{token} reverted")) || out.contains("restored") => {
                say("the router took the change back by itself at the deadline (it says so in its log)".into());
                return Outcome::Reverted(why);
            }
            Ok(out) if !out.contains("@@still") => {
                last = "the guard is gone from the router, but it left no word of a revert".into();
            }
            Ok(_) => last = "the guard is still on the router".into(),
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Outcome::Unknown(format!(
        "{why}; and whether the router took it back couldn't be seen ({last})"
    ))
}

/// The user's "keep": disarm a change that waits, if its window is still open.
pub fn keep(r: &Router, window: u64, say: &mut dyn FnMut(String)) -> Outcome {
    let Some(p) = pending(&r.scope) else {
        return Outcome::Stopped("no guarded change is waiting to be kept".into());
    };
    let left = p.deadline - jiff::Timestamp::now().as_second();
    let o = if left <= margin(window) as i64 {
        // Too late to disarm without racing the sleeper: see what the router did.
        let said = fresh(r, &settled_script(&p.token)).unwrap_or_default();
        if said.contains("reverted") || said.contains("restored") {
            say("the window passed: the router took the change back by itself".into());
            Outcome::Reverted("not kept within the window".into())
        } else if left > 0 {
            Outcome::Reverted(
                "too close to the deadline to disarm safely: the router takes it back by itself"
                    .into(),
            )
        } else {
            Outcome::Unknown("the window passed, and the router left no word of a revert".into())
        }
    } else {
        let limit = Duration::from_secs(left as u64 - margin(window));
        disarm(r, &p.token, Instant::now(), limit, say)
    };
    let _ = std::fs::remove_file(pending_path(&r.scope));
    journal(&r.scope, &p.token, &p.change, &o);
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change() -> Change {
        Change::parse(
            "dhcp,firewall",
            "uci set dhcp.lan.leasetime='6h'; uci add firewall rule\nuci set firewall.@rule[-1].name='it''s new'; uci commit dhcp",
            "firewall, dnsmasq",
            false,
        )
        .unwrap()
    }

    #[test]
    fn a_change_is_only_uci_lines_on_its_own_guarded_configs() {
        let c = change();
        assert_eq!(c.configs, ["dhcp", "firewall"]);
        // In the order they're reloaded, whatever order they were given in.
        assert_eq!(c.services, ["firewall", "dnsmasq"]);
        assert_eq!(
            c.lines.len(),
            3,
            "the commit is the guard's own: {:?}",
            c.lines
        );
        assert_eq!(
            c.uci_lines(),
            [
                "uci set dhcp.lan.leasetime=6h",
                "uci add firewall rule",
                "uci set 'firewall.@rule[-1].name=its new'",
            ]
        );
        assert!(!c.wifi() && !c.asks());
        assert_eq!(c.relevant(), ["dhcp", "firewall", "network"]);
        let wifi = Change::parse(
            "wireless",
            "uci set wireless.radio0.channel=6",
            "wifi",
            false,
        )
        .unwrap();
        assert!(wifi.wifi() && wifi.asks());
        assert!(
            Change::parse("dhcp", "uci set dhcp.lan.limit=9", "", true)
                .unwrap()
                .asks()
        );
        let bad = |configs: &str, lines: &str, services: &str| {
            Change::parse(configs, lines, services, false).unwrap_err()
        };
        for (configs, lines, services, says) in [
            ("", "uci set dhcp.lan.limit=9", "", "no config named"),
            (
                "system",
                "uci set system.x.y=1",
                "",
                "isn't one of the guarded configs",
            ),
            (
                "dhcp",
                "uci set dhcp.lan.limit=9",
                "cron",
                "isn't a service the guard reloads",
            ),
            ("dhcp", "", "", "no uci line"),
            ("dhcp", "reboot", "", "isn't a uci command"),
            ("dhcp", "rm -rf /etc/config", "", "only `uci` lines"),
            (
                "dhcp",
                "uci set network.lan.proto=dhcp",
                "",
                "isn't in this change's configs",
            ),
            (
                "dhcp",
                "uci commit network",
                "",
                "isn't staged in a guard step",
            ),
            (
                "dhcp",
                "uci revert dhcp",
                "",
                "isn't staged in a guard step",
            ),
            (
                "dhcp",
                "uci import dhcp",
                "",
                "isn't staged in a guard step",
            ),
            (
                "dhcp",
                "uci set dhcp.lan.limit=9 | sh",
                "",
                "isn't allowed between the lines",
            ),
            (
                "dhcp",
                "uci set dhcp.lan.limit=9 && reboot",
                "",
                "isn't allowed between the lines",
            ),
            (
                "dhcp",
                "uci set dhcp.lan.limit=$(reboot)",
                "",
                "would be expanded",
            ),
            (
                "dhcp",
                "uci set dhcp.lan.limit=`reboot`",
                "",
                "would be expanded",
            ),
            (
                "dhcp",
                "uci set dhcp.lan.limit=\"$X\"",
                "",
                "would be expanded",
            ),
            (
                "dhcp",
                "uci set dhcp.lan.limit=9 > /etc/x",
                "",
                "redirection",
            ),
            (
                "dhcp",
                "uci -c /tmp set dhcp.lan.limit=9",
                "",
                "isn't staged",
            ),
            (
                "dhcp",
                "uci set dhcp.lan.limit=9 extra",
                "",
                "takes 1 argument",
            ),
            ("dhcp", "uci set -q", "", "takes 1 argument"),
        ] {
            let e = bad(configs, lines, services);
            assert!(e.contains(says), "{lines}: {e}");
        }
        // A value is one shell word on the router, whatever is in it.
        let odd = Change::parse(
            "wireless",
            "uci set wireless.default_radio0.key='pa$$ word; reboot `x` \"q\"'",
            "",
            false,
        )
        .unwrap();
        assert_eq!(
            odd.uci_lines(),
            [
                r#"uci 'wireless.default_radio0.key=pa$$ word; reboot `x` "q"'"#
                    .replace("uci '", "uci set '")
            ]
        );
    }

    #[test]
    fn the_scripts() {
        let c = change();
        let t = "0123456789abcdef";
        insta::assert_snapshot!("guard_state", state_script(&c, Some(t)));
        insta::assert_snapshot!("guard_arm", arm_script(&c, t, 300));
        insta::assert_snapshot!("guard_armed", armed_script(t));
        insta::assert_snapshot!("guard_apply", apply_script(&c, t));
        insta::assert_snapshot!("guard_disarm", disarm_script(t));
        insta::assert_snapshot!("guard_abort", abort_script(t));
        insta::assert_snapshot!("guard_settled", settled_script(t));
        // Nothing is changed before the sleeper is started, and it is started last.
        let arm = arm_script(&c, t, 300);
        assert!(!arm.contains("uci set") && !arm.contains("uci commit"));
        assert!(arm.trim_end().ends_with("echo @@snapshot"));
        assert!(arm.find(": > \"$D/armed\"").unwrap() < arm.find("setsid sh").unwrap());
        // The revert puts the snapshot back before it reloads, and reloads the same services.
        let dead = &arm[arm.find("deadman.sh").unwrap()..];
        assert!(
            dead.find("restore.sh").unwrap() < dead.find("/etc/init.d/firewall reload").unwrap()
        );
        assert!(
            dead.find("/etc/init.d/firewall reload").unwrap()
                < dead.find("/etc/init.d/dnsmasq reload").unwrap()
        );
        // Applying refuses when it isn't armed, and commits only after every line staged.
        let apply = apply_script(&c, t);
        assert!(apply.find("not armed").unwrap() < apply.find("uci set").unwrap());
        assert!(apply.rfind("|| fail 'line").unwrap() < apply.find("uci commit").unwrap());
        assert!(apply.find("uci commit").unwrap() < apply.find("setsid sh").unwrap());
        // Disarming removes the marker before it kills anything.
        let dis = disarm_script(t);
        assert!(dis.find("rm -f \"$D/armed\"").unwrap() < dis.find("kill").unwrap());
    }

    fn state(text: &str) -> State {
        parse_state(text)
    }

    const BEFORE: &str = "@@board\nok\n@@guards\n@@staged\n@@wan\n{\"interface\":[{\"interface\":\"lan\",\"up\":true},{\"interface\":\"wan\",\"up\":true,\"route\":[{\"target\":\"0.0.0.0\",\"mask\":0,\"nexthop\":\"203.0.113.254\"}]},{\"interface\":\"wan6\",\"up\":false}]}\n@@route\ndefault via 203.0.113.254 dev wan proto static src 203.0.113.7\n@@firewall\nfirewall.@zone[0]=zone\nfirewall.@zone[0].name='lan'\nfirewall.@zone[0].input='ACCEPT'\nfirewall.@zone[1]=zone\nfirewall.@zone[1].name='wan'\nfirewall.@zone[1].input='REJECT'\nfirewall.web=redirect\nfirewall.web.target='DNAT'\nfirewall.web.src='wan'\nfirewall.web.proto='tcp'\nfirewall.web.src_dport='443'\nfirewall.web.dest_ip='192.0.2.10'\n@@stations\nhostapd.phy0-ap0 3\nhostapd.phy1-ap0 0\n@@end\n";

    #[test]
    fn preflight_stops_before_anything_is_touched() {
        let c = change();
        let s = state(BEFORE);
        assert_eq!(
            s.wan,
            Some(vec![("wan".into(), true), ("wan6".into(), false)])
        );
        assert_eq!(s.routes, ["via 203.0.113.254 dev wan"]);
        assert_eq!(
            s.firewall,
            Some((vec!["wan".into()], vec!["tcp 443 → 192.0.2.10".into()]))
        );
        assert_eq!(
            s.stations,
            [
                ("hostapd.phy0-ap0".into(), 3),
                ("hostapd.phy1-ap0".into(), 0)
            ]
        );
        assert_eq!(preflight(&c, &s), Ok(()));
        let no = |text: &str| preflight(&c, &state(text)).unwrap_err();
        assert!(no("").contains("didn't answer"));
        assert!(
            no(&BEFORE.replace("@@end\n", "")).contains("didn't answer"),
            "cut short"
        );
        assert!(no(&BEFORE.replace("@@board\nok", "@@board\n")).contains("didn't answer"));
        let foreign = no(&BEFORE.replace(
            "@@staged\n",
            "@@staged\ndhcp.cfg01411c.serversfile='/var/run/x'\nfirewall.cfg10.name='new'\n",
        ));
        assert!(
            foreign.contains("someone else's")
                && foreign.contains("dhcp.cfg01411c.serversfile")
                && foreign.contains("firewall.cfg10.name"),
            "{foreign}"
        );
        assert!(
            no(&BEFORE.replace("@@guards\n", "@@guards\n/tmp/sentry-guard-ffff/\n"))
                .contains("another guarded change")
        );
        assert!(no(&BEFORE.replace("{\"interface\"", "ubus: not found {")).contains("uplink"));
        assert!(no(&BEFORE.replace("=zone", "=nozone")).contains("firewall config didn't read"));
    }

    #[test]
    fn a_change_is_confirmed_only_when_everything_is_as_it_should_be() {
        let c = change();
        let before = state(BEFORE);
        let after_text = BEFORE.replace("@@end\n", "@@reloaded\n0\n@@armed\nyes\n@@log\n@@end\n");
        let expected = vec!["tcp 443 → 192.0.2.10".to_string()];
        let ok = state(&after_text);
        assert!(ok.armed && ok.reloaded == Some(0));
        assert_eq!(confirm(&c, &before, &ok, &expected), Ok(()));
        let no = |text: String| confirm(&c, &before, &state(&text), &expected).unwrap_err();
        assert!(
            no(after_text.replace("@@reloaded\n0\n", "@@reloaded\n")).contains("hadn't finished")
        );
        assert!(
            no(after_text.replace(
                "@@reloaded\n0\n@@armed\nyes\n@@log\n",
                "@@reloaded\n1\n@@armed\nyes\n@@log\nnft: failed\n"
            ))
            .contains("a reload failed: nft: failed")
        );
        assert!(
            no(after_text.replace("\"wan\",\"up\":true", "\"wan\",\"up\":false"))
                .contains("uplink isn't as it was")
        );
        assert!(
            no(after_text.replace(
                "default via 203.0.113.254 dev wan proto static src 203.0.113.7\n",
                ""
            ))
            .contains("default route")
        );
        assert!(
            no(after_text.replace("input='REJECT'", "input='ACCEPT'"))
                .contains("zone wan no longer rejects")
        );
        assert!(
            no(after_text.replace("src_dport='443'", "src_dport='444'"))
                .contains("port forward tcp 443 → 192.0.2.10 is gone")
        );
        assert!(no(after_text.replace("@@board\nok", "@@board\n")).contains("didn't answer"));
        // A forward the config doesn't expect may go.
        assert_eq!(
            confirm(
                &c,
                &before,
                &state(&after_text.replace("src_dport='443'", "src_dport='444'")),
                &[]
            ),
            Ok(())
        );
        // Meant to change the uplink: not compared (and then it asks).
        let wan = Change::parse(
            "network",
            "uci set network.wan.proto=static",
            "network",
            true,
        )
        .unwrap();
        assert!(wan.asks());
        assert_eq!(
            confirm(
                &wan,
                &before,
                &state(&after_text.replace("\"wan\",\"up\":true", "\"wan\",\"up\":false")),
                &expected
            ),
            Ok(())
        );
        assert_eq!(margin(300), 15);
        assert_eq!(margin(5), 2);
        assert_eq!(margin(20), 4);
    }
}
