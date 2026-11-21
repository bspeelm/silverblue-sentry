//! The guard: the one way sentry changes the configs a network is reached through
//! (network, firewall, wireless, dhcp, dropbear, uhttpd). A change is a list of `uci`
//! staging lines on those configs and the services to reload. Before anything is touched
//! the router is armed to take the change back by itself: a detached shell that sleeps
//! `window` seconds and then, unless it was disarmed, copies the configs' snapshot back,
//! reloads the same services and says so in the log. sentry then applies, reconnects on a
//! new connection, and disarms only when the router still answers, has stopped changing,
//! and its uplink, default route and firewall are as they should be. A Wi-Fi change is
//! never kept that way: ssh over a cable can't tell that Wi-Fi still works, so it stays
//! armed until the user says keep. Whatever goes wrong after arming (the link gone, sentry
//! gone, a check failing), sentry does nothing more: the router restores itself at the
//! deadline.
//!
//! One side takes a guard, never both. The marker `armed` is taken by renaming it
//! (`mv armed claim.<who>`), which only one of the sleeper and a disarm can do: whoever
//! gets it acts, the other does nothing. The sleeper ignores signals once it has it, so a
//! restore is never cut short, and sentry says "kept" only when the router said its own
//! claim was the one that held.
//!
//! A restart inside the window is covered too. The snapshot is kept on flash
//! (`/etc/sentry-guard/<token>/`, 0700), with a one-shot boot hook beside it
//! (`/etc/uci-defaults/zz-sentry-guard-<token>`, which OpenWrt's boot runs once and
//! removes): a router that restarts with an unconfirmed change puts its configs back
//! before any service starts. The hook is the restore itself (the sleeper runs the same
//! file), and both are removed when the change is kept or taken back. This is the one
//! thing sentry ever writes to a router's flash besides the change itself: per guarded
//! change, a copy of each config it touches and one small script, deleted again within
//! the window.
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
            // An option that is a script run as root, or a file a daemon reads or serves.
            let strs: Vec<&str> = args.iter().map(String::as_str).collect();
            if let Some(why) = crate::policy::runs_or_reads(verb, &strs) {
                return Err(format!("line {n} (`{shown}`): {why}"));
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

/// What is running of a guard: its marker, its sleeper, its reloads (gone at a restart).
fn dir(token: &str) -> String {
    format!("/tmp/sentry-guard-{token}")
}

/// Its snapshot, on flash: what a restart inside the window restores from.
fn flash(token: &str) -> String {
    format!("{FLASH}/{token}")
}

/// The one-shot boot hook: the restore itself.
fn hook(token: &str) -> String {
    format!("/etc/uci-defaults/zz-sentry-guard-{token}")
}

const FLASH: &str = "/etc/sentry-guard";

/// A guard's sleeper lives: the process its pid file names is running its `deadman.sh`
/// (not merely some process that has the number now).
const ALIVE: &str =
    r#"[ -s "$d/pid" ] && grep -q "$d/deadman.sh" "/proc/$(cat "$d/pid")/cmdline" 2>/dev/null"#;

/// Where the router says how a guard ended: `<token> kept|reverted <when>`.
const LAST: &str = "/tmp/sentry-guard.last";

/// The same, said by the boot hook (the other is gone with the restart).
const LAST_BOOT: &str = "/etc/sentry-guard.last";

// ---- the scripts (pure)

/// (a) What the router is like now: reads only. Used before (preflight) and after (confirm).
pub fn state_script(c: &Change, token: Option<&str>) -> String {
    let mut s = String::from("echo @@board; ubus call system board >/dev/null 2>&1 && echo ok\n");
    // Every guard there is: one whose sleeper lives is armed; any other is a leftover.
    s.push_str(&format!(
        "echo @@guards\n\
         for d in /tmp/sentry-guard-*/; do\n\
         \x20 [ -d \"$d\" ] || continue\n\
         \x20 d=${{d%/}}\n\
         \x20 if {ALIVE}; then echo \"live $d\"; else echo \"dead $d\"; fi\n\
         done\n\
         for f in {FLASH}/*/; do [ -d \"$f\" ] && echo \"flash $f\"; done\n"
    ));
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

/// The restore, as a file of its own: the one-shot boot hook, which the sleeper (and
/// whatever clears a leftover) runs too. It does nothing when the snapshot is gone, so
/// running it twice, or after the change was kept, is harmless.
pub fn hook_script(c: &Change, token: &str) -> String {
    let f = flash(token);
    let configs = c.configs.join(" ");
    format!(
        "# sentry's guard {token}: a change that was never confirmed is taken back\n\
         # (at the next boot by /etc/init.d/boot, which then removes this file; before\n\
         # that, by the guard's own sleeper).\n\
         F={f}\n\
         [ -d \"$F/config\" ] || exit 0\n\
         for c in {configs}; do\n\
         \x20 uci -q revert $c\n\
         \x20 if [ -e \"$F/config/$c\" ]; then cp -p \"$F/config/$c\" /etc/config/$c\n\
         \x20 elif [ -e \"$F/config/$c.absent\" ]; then rm -f /etc/config/$c; fi\n\
         done\n\
         if [ -z \"$SENTRY_GUARD_SLEEPER\" ]; then\n\
         \x20 echo \"{token} reverted $(date +%s) at boot\" > {LAST_BOOT}\n\
         \x20 logger -t sentry-guard \"{token}: not confirmed before a restart: restored {configs}\" 2>/dev/null\n\
         fi\n\
         rm -rf \"$F\"\n\
         rmdir {FLASH} 2>/dev/null\n\
         exit 0\n"
    )
}

/// (b) and (c): snapshot the configs (on flash, with the boot hook) and arm the dead-man.
/// Nothing is changed. `slow`: seconds the sleeper waits after taking the guard and
/// before restoring (the tests' way to stand in the middle of a restore; 0 otherwise).
pub fn arm_script(c: &Change, token: &str, window: u64) -> String {
    arm_script_slow(c, token, window, 0)
}

pub(crate) fn arm_script_slow(c: &Change, token: &str, window: u64, slow: u64) -> String {
    let d = dir(token);
    let f = flash(token);
    let h = hook(token);
    let configs = c.configs.join(" ");
    let services = c.services.join(" ");
    let reloads: String = c
        .services
        .iter()
        .map(|s| format!("{} >/dev/null 2>&1\n", reload_cmd(s)))
        .collect();
    let hook = hook_script(c, token);
    let slow = if slow > 0 {
        format!("sleep {slow}\n")
    } else {
        String::new()
    };
    format!(
        "set -e\n\
         umask 077\n\
         D={d}\n\
         F={f}\n\
         H={h}\n\
         mkdir \"$D\"\n\
         mkdir -p {FLASH}\n\
         chmod 700 {FLASH}\n\
         mkdir \"$F\" \"$F/config\"\n\
         for c in {configs}; do\n\
         \x20 if [ -e /etc/config/$c ]; then cp -p /etc/config/$c \"$F/config/$c\"; else : > \"$F/config/$c.absent\"; fi\n\
         done\n\
         cat > \"$H\" <<'SENTRY_EOF'\n\
         {hook}\
         SENTRY_EOF\n\
         cat > \"$D/reloads.sh\" <<'SENTRY_EOF'\n\
         {reloads}\
         SENTRY_EOF\n\
         cat > \"$D/deadman.sh\" <<'SENTRY_EOF'\n\
         #!/bin/sh\n\
         # sentry's guard {token}: unless disarmed within {window} s, take the change back.\n\
         D={d}\n\
         H={h}\n\
         echo $$ > \"$D/pid\"\n\
         sleep {window} &\n\
         echo $! > \"$D/sleep.pid\"\n\
         wait $!\n\
         # Take the guard: only one of this and a disarm can (a rename happens once).\n\
         mv \"$D/armed\" \"$D/claim.deadman\" 2>/dev/null || exit 0\n\
         # From here on nothing stops it half-way.\n\
         trap '' HUP INT TERM\n\
         logger -t sentry-guard \"{token}: not confirmed within {window}s: restoring {configs}\"\n\
         {slow}\
         SENTRY_GUARD_SLEEPER=1 sh \"$H\"\n\
         sh \"$D/reloads.sh\"\n\
         echo \"{token} reverted $(date +%s)\" > {LAST}\n\
         logger -t sentry-guard \"{token}: restored {configs}; reloaded {services}\"\n\
         rm -f \"$H\"\n\
         rm -rf \"$D\"\n\
         SENTRY_EOF\n\
         : > \"$D/armed\"\n\
         sync\n\
         setsid sh \"$D/deadman.sh\" </dev/null >/dev/null 2>&1 &\n\
         echo @@snapshot\n"
    )
}

/// (c) Is the dead-man really there: its marker, its shell and its sleep, all alive, and
/// what a restart would restore from.
pub fn armed_script(token: &str) -> String {
    let d = dir(token);
    let f = flash(token);
    let h = hook(token);
    format!(
        "D={d}\n\
         [ -e \"$D/armed\" ] && [ -s \"$D/pid\" ] && [ -s \"$D/sleep.pid\" ] && [ -d {f}/config ] && [ -s {h} ] \\\n\
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

/// Take the guard for `who` and, only if that held, do `then` and clear everything away.
/// Says `claimed` when it held and nothing is left, `left` when it held and something
/// couldn't be removed, `lost` when the sleeper had it already (then `restoring` while it
/// is at work, `reverted` once it has said so).
fn claim_script(token: &str, who: &str, then: &str, word: &str) -> String {
    let d = dir(token);
    let f = flash(token);
    let h = hook(token);
    format!(
        "D={d}\n\
         F={f}\n\
         H={h}\n\
         if mv \"$D/armed\" \"$D/claim.{who}\" 2>/dev/null; then\n\
         \x20 [ -s \"$D/sleep.pid\" ] && kill \"$(cat \"$D/sleep.pid\")\" 2>/dev/null\n\
         \x20 [ -s \"$D/pid\" ] && kill \"$(cat \"$D/pid\")\" 2>/dev/null\n\
         {then}\
         \x20 rm -f \"$H\"\n\
         \x20 rm -rf \"$F\"\n\
         \x20 rmdir {FLASH} 2>/dev/null\n\
         \x20 echo \"{token} {word} $(date +%s)\" > {LAST}\n\
         \x20 rm -rf \"$D\"\n\
         \x20 sync\n\
         \x20 if [ -e \"$D\" ] || [ -e \"$F\" ] || [ -e \"$H\" ]; then echo left; else echo claimed; fi\n\
         else\n\
         \x20 echo lost\n\
         \x20 [ -e \"$D/claim.deadman\" ] && echo restoring\n\
         \x20 cat {LAST} {LAST_BOOT} 2>/dev/null | grep -q '^{token} reverted' && echo reverted\n\
         fi\n\
         true\n"
    )
}

/// Disarm: the change stays. Only if the guard is still there to be taken.
pub fn disarm_script(token: &str) -> String {
    claim_script(token, "disarm", "", "kept")
}

/// A line or the commit failed, before anything was reloaded: the snapshot back and the
/// staged lines dropped, by whoever takes the guard (this, or the sleeper if it was
/// first).
pub fn abort_script(token: &str) -> String {
    claim_script(
        token,
        "abort",
        "\x20 SENTRY_GUARD_SLEEPER=1 sh \"$H\"\n",
        "aborted",
    )
}

/// (g) After the deadline: how did it end on the router?
pub fn settled_script(token: &str) -> String {
    let d = dir(token);
    format!(
        "[ -d {d} ] && echo @@still\n\
         [ -e {d}/claim.deadman ] && echo @@restoring\n\
         cat {LAST} {LAST_BOOT} 2>/dev/null | grep '^{token} '\n\
         logread -e sentry-guard 2>/dev/null | grep '{token}' | tail -n 2\n\
         true\n"
    )
}

/// What an earlier guard left behind with nothing alive to settle it (its sleeper never
/// started, or died): taken back if it has a snapshot (it was never confirmed), its
/// services reloaded, and cleared away. A guard whose sleeper lives is left alone. Says
/// `restored <token>` or `cleared <token>` for each.
pub fn clear_script() -> String {
    format!(
        "for d in /tmp/sentry-guard-*/; do\n\
         \x20 [ -d \"$d\" ] || continue\n\
         \x20 d=${{d%/}}; t=${{d##*sentry-guard-}}\n\
         \x20 if {ALIVE}; then continue; fi\n\
         \x20 H=/etc/uci-defaults/zz-sentry-guard-$t\n\
         \x20 mv \"$d/armed\" \"$d/claim.clear\" 2>/dev/null\n\
         \x20 if [ -s \"$H\" ] && [ -d \"{FLASH}/$t/config\" ]; then\n\
         \x20   SENTRY_GUARD_SLEEPER=1 sh \"$H\"\n\
         \x20   [ -s \"$d/reloads.sh\" ] && sh \"$d/reloads.sh\"\n\
         \x20   logger -t sentry-guard \"$t: left unconfirmed with no sleeper: restored\"\n\
         \x20   echo \"restored $t\"\n\
         \x20 else\n\
         \x20   echo \"cleared $t\"\n\
         \x20 fi\n\
         \x20 rm -f \"$H\"; rm -rf \"{FLASH}/$t\" \"$d\"\n\
         done\n\
         for f in {FLASH}/*/; do\n\
         \x20 [ -d \"$f\" ] || continue\n\
         \x20 f=${{f%/}}; t=${{f##*/}}\n\
         \x20 [ -d \"/tmp/sentry-guard-$t\" ] && continue\n\
         \x20 H=/etc/uci-defaults/zz-sentry-guard-$t\n\
         \x20 if [ -s \"$H\" ]; then SENTRY_GUARD_SLEEPER=1 sh \"$H\"; echo \"restored $t\"; else echo \"cleared $t\"; fi\n\
         \x20 rm -f \"$H\"; rm -rf \"$f\"\n\
         done\n\
         rmdir {FLASH} 2>/dev/null\n\
         true\n"
    )
}

// ---- what the router said

/// The router as a guard sees it, before and after.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct State {
    pub board: bool,
    /// Other guards that are armed (their sleepers live): their tokens.
    pub guards: Vec<String>,
    /// What earlier guards left with nothing alive to settle it: their tokens.
    pub leftovers: Vec<String>,
    /// Each interface as netifd has it (`name up|down addresses`), sorted.
    pub ifaces: Vec<String>,
    /// The interfaces netifd is still setting up.
    pub pending: Vec<String>,
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
                let token = |p: &str| {
                    let p = p.trim_end_matches('/');
                    p.rsplit('/')
                        .next()
                        .unwrap_or(p)
                        .trim_start_matches("sentry-guard-")
                        .to_string()
                };
                let mut flash = Vec::new();
                for l in lines() {
                    match l.split_once(' ') {
                        Some(("live", p)) => s.guards.push(token(p)),
                        Some(("dead", p)) => s.leftovers.push(token(p)),
                        Some(("flash", p)) => flash.push(token(p)),
                        _ => {}
                    }
                }
                // A snapshot with nothing running beside it is a leftover too.
                for t in flash {
                    if !s.guards.contains(&t) && !s.leftovers.contains(&t) {
                        s.leftovers.push(t);
                    }
                }
            }
            "staged" => s.staged = lines().map(str::to_string).collect(),
            "wan" => {
                let dump = serde_json::from_str::<serde_json::Value>(body).ok();
                for i in dump
                    .as_ref()
                    .and_then(|v| v.get("interface")?.as_array())
                    .into_iter()
                    .flatten()
                {
                    let Some(name) = i.get("interface").and_then(|n| n.as_str()) else {
                        continue;
                    };
                    let flag = |k: &str| i.get(k).and_then(|u| u.as_bool()).unwrap_or(false);
                    if flag("pending") {
                        s.pending.push(name.to_string());
                    }
                    let addrs: Vec<String> = ["ipv4-address", "ipv6-address"]
                        .iter()
                        .filter_map(|k| i.get(*k)?.as_array())
                        .flatten()
                        .filter_map(|a| {
                            Some(format!(
                                "{}/{}",
                                a.get("address")?.as_str()?,
                                a.get("mask")?.as_u64()?
                            ))
                        })
                        .collect();
                    s.ifaces.push(format!(
                        "{name} {} {}",
                        if flag("up") { "up" } else { "down" },
                        addrs.join(" ")
                    ));
                }
                s.ifaces.sort();
                s.wan = dump.and_then(|v| {
                    let list = v.get("interface")?.as_array()?;
                    Some(
                        list.iter()
                            .filter_map(|i| {
                                let name = i.get("interface")?.as_str()?;
                                let default =
                                    i.get("route").and_then(|r| r.as_array()).is_some_and(|r| {
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
    if let Some(l) = s.leftovers.first() {
        return Err(format!(
            "an earlier guard left its files on the router with nothing running to settle it ({l})"
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
    // (One that was being set up before too, a DHCP uplink with no lease, says nothing.)
    if let Some(i) = after.pending.iter().find(|i| !before.pending.contains(i)) {
        return Err(format!(
            "the router is still setting interface {i} up (its reload returns before netifd has finished)"
        ));
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

/// How long before the deadline sentry stops trying to confirm: what it starts then
/// could not be finished and answered before the sleeper wakes.
pub fn margin(window: u64) -> u64 {
    (window / 5).clamp(2, 15)
}

/// How long the router must stay as it is before it counts as confirmed: a reload
/// returns before netifd has finished, and a check right then sees the old state.
pub fn settle_gap(window: u64) -> Duration {
    Duration::from_secs((window / 8).clamp(1, 3))
}

/// One guarded change at a time from this machine, whatever started it (two windows, a
/// workflow's step and a command by hand): a lock beside the network's data, like the
/// one a `sysupgrade` takes its turn with.
pub struct Turn(#[allow(dead_code)] std::fs::File);

pub fn turn(scope: &str) -> Result<Turn, String> {
    let dir = guard_dir(scope);
    let open = || -> std::io::Result<std::fs::File> {
        std::fs::create_dir_all(&dir)?;
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("lock"))
    };
    let f = open().map_err(|e| format!("the guard's lock here couldn't be opened ({e})"))?;
    match f.try_lock() {
        Ok(()) => Ok(Turn(f)),
        Err(_) => Err(
            "another guarded change is being carried out from this machine: one at a time".into(),
        ),
    }
}

/// A read on a connection of its own (the shared one may be dead after a reload), given
/// up after `within`.
fn fresh_within(r: &Router, script: &str, within: Duration) -> Result<String, String> {
    r.sh(script)
        .own_connection()
        .timeout(Some(within.max(Duration::from_secs(1))))
        .output()
        .map_err(|e| e.to_string())
}

fn fresh(r: &Router, script: &str) -> Result<String, String> {
    fresh_within(r, script, Duration::from_secs(20))
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
    let mut s = parse_state(&out.stdout);
    // What an earlier guard left with nothing alive is cleared when this one is applied
    // (`run`); a preview only says so.
    if !s.leftovers.is_empty() && s.guards.is_empty() {
        say(format!(
            "an earlier guard left its files on the router with nothing running to settle it ({}): applying clears it first, taking back what it never confirmed",
            s.leftovers.join(", ")
        ));
        s.leftovers.clear();
    }
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
    let _turn = match turn(&r.scope) {
        Ok(t) => t,
        Err(why) => return Outcome::Stopped(why),
    };
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
    // What an earlier guard left with nothing alive to settle it: taken back and cleared,
    // so a failed arm with the link lost doesn't block every guard until a restart.
    match shared(r, &clear_script()) {
        Ok(o) => {
            for l in o.stdout.lines().filter(|l| !l.trim().is_empty()) {
                say(match l.split_once(' ') {
                    Some(("restored", t)) => format!(
                        "an earlier guard ({t}) had been left unconfirmed with nothing running: its configs were put back and its files cleared"
                    ),
                    Some((_, t)) => format!("an earlier guard's leftover files ({t}) were cleared"),
                    None => l.to_string(),
                });
            }
        }
        Err(e) => return Outcome::Stopped(format!("the router didn't answer ({e})")),
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
        // Nothing has changed yet: whatever was made of the guard is removed (if this
        // can't reach the router either, the next guard clears it).
        let _ = shared(r, &disarm_script(token));
        let _ = shared(r, &clear_script());
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
        "armed: the router takes the change back by itself in {window} s unless it's confirmed (at a restart too)"
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
                Ok(a) if said(&a.stdout, "claimed") => Outcome::Failed(format!(
                    "{why}: nothing was reloaded, and the configs are as they were"
                )),
                _ => settle(r, token, window, armed_at, say, why),
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
            return settle(r, token, window, armed_at, say, why);
        }
        Err(e) => {
            return settle(r, token, window, armed_at, say, format!("applying it: {e}"));
        }
    }
    // (e) Reconnect on a new connection, and (f) confirm: everything as it should be,
    // and still so a moment later.
    let gap = settle_gap(window);
    let mut why = "the router didn't answer on a new connection".to_string();
    let mut after = None;
    let mut good: Option<(Instant, State)> = None;
    while armed_at.elapsed() < limit {
        std::thread::sleep(Duration::from_millis(700));
        let left = limit.saturating_sub(armed_at.elapsed());
        match fresh_within(
            r,
            &state_script(c, Some(token)),
            left.min(Duration::from_secs(20)),
        ) {
            Ok(text) => {
                let s = parse_state(&text);
                match confirm(c, &before, &s, &expected_forwards(&r.cfg)) {
                    Ok(()) if s.armed => match &good {
                        Some((at, was)) if steady(was, &s) => {
                            if at.elapsed() >= gap {
                                after = Some(s);
                                break;
                            }
                        }
                        _ => {
                            why = "the router was still changing".into();
                            good = Some((Instant::now(), s));
                        }
                    },
                    Ok(()) => {
                        why = "the guard was no longer armed".into();
                        good = None;
                    }
                    Err(e) => {
                        why = e;
                        good = None;
                    }
                }
            }
            Err(_) => {
                why = "the router didn't answer on a new connection".into();
                good = None;
            }
        }
    }
    let Some(after) = after else {
        say(format!("not confirmed: {why}"));
        return settle(r, token, window, armed_at, say, why);
    };
    say(format!(
        "confirmed on a new connection, twice {} s apart: the router answers · reloads done · interfaces settled · uplink and default route {}{}",
        gap.as_secs(),
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
            return settle(r, token, window, armed_at, say, why);
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
    let left = Duration::from_secs(window).saturating_sub(armed_at.elapsed());
    disarm(r, token, window, left, say)
}

/// The router as it stands is the router as it stood: nothing is still moving.
fn steady(a: &State, b: &State) -> bool {
    a.ifaces == b.ifaces && a.wan == b.wan && a.routes == b.routes && a.firewall == b.firewall
}

/// A line of a script's answer, alone on its line.
fn said(out: &str, word: &str) -> bool {
    out.lines().any(|l| l.trim() == word)
}

/// Disarm, and say "kept" only when the router said this claim was the one that held.
/// `left`: how long until the sleeper wakes. Too close to it, nothing is started: the
/// router settles it. A claim the sleeper won, or an answer that never came, is settled
/// by asking the router afterwards.
pub(crate) fn disarm(
    r: &Router,
    token: &str,
    window: u64,
    left: Duration,
    say: &mut dyn FnMut(String),
) -> Outcome {
    let m = Duration::from_secs(margin(window));
    let started = Instant::now();
    if left <= m {
        let why = "too close to the deadline to disarm".to_string();
        return settle_in(r, token, left, say, why);
    }
    // Answered well before the sleeper wakes, or not waited for.
    let within = m.saturating_sub(Duration::from_secs(1));
    let left_after = |started: Instant| left.saturating_sub(started.elapsed());
    match fresh_within(r, &disarm_script(token), within) {
        Ok(out) if said(&out, "claimed") => {
            say("disarmed: the change is kept (no sleeper, no snapshot and no boot hook left on the router)".into());
            Outcome::Kept
        }
        Ok(out) if said(&out, "left") => Outcome::Unknown(
            "the guard was disarmed, but its files couldn't all be removed from the router".into(),
        ),
        Ok(out) if said(&out, "lost") && said(&out, "reverted") => {
            Outcome::Reverted("the router had already taken it back".into())
        }
        Ok(_) => {
            let why = "the router's own revert had the guard first".to_string();
            settle_in(r, token, left_after(started), say, why)
        }
        Err(e) => {
            let why = format!("disarming wasn't answered ({e})");
            settle_in(r, token, left_after(started), say, why)
        }
    }
}

/// (g) Not confirmed: nothing is done; once the deadline has passed, ask the router how
/// it ended.
fn settle(
    r: &Router,
    token: &str,
    window: u64,
    armed_at: Instant,
    say: &mut dyn FnMut(String),
    why: String,
) -> Outcome {
    let left = Duration::from_secs(window).saturating_sub(armed_at.elapsed());
    settle_in(r, token, left, say, why)
}

fn settle_in(
    r: &Router,
    token: &str,
    left: Duration,
    say: &mut dyn FnMut(String),
    why: String,
) -> Outcome {
    say(format!(
        "sentry does nothing more: the router settles it by itself in about {} s",
        left.as_secs()
    ));
    std::thread::sleep(left + Duration::from_secs(2));
    // The reloads of the revert take a moment; then it answers again.
    let until = Instant::now() + Duration::from_secs(45);
    let mut last = String::new();
    while Instant::now() < until {
        match fresh(r, &settled_script(token)) {
            // A disarm whose answer was lost, and which had the guard all the same.
            Ok(out) if out.contains(&format!("{token} kept")) => {
                say("the router says the guard was disarmed: the change is kept".into());
                return Outcome::Kept;
            }
            Ok(out) if out.contains(&format!("{token} aborted")) => {
                return Outcome::Failed(format!(
                    "{why}: nothing was reloaded, and the configs are as they were"
                ));
            }
            Ok(out) if out.contains("@@restoring") => {
                last = "the router is still putting its configs back".into();
            }
            Ok(out) if out.contains(&format!("{token} reverted")) || out.contains("restored") => {
                say("the router took the change back by itself (it says so in its log)".into());
                return Outcome::Reverted(why);
            }
            Ok(out) if !out.contains("@@still") => {
                last =
                    "the guard is gone from the router, but it left no word of how it ended".into();
            }
            Ok(_) => last = "the guard is still on the router".into(),
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Outcome::Unknown(format!(
        "{why}; and how it ended on the router couldn't be seen ({last})"
    ))
}

/// The user's "keep": disarm a change that waits, if its window is still open.
pub fn keep(r: &Router, window: u64, say: &mut dyn FnMut(String)) -> Outcome {
    let _turn = match turn(&r.scope) {
        Ok(t) => t,
        Err(why) => return Outcome::Stopped(why),
    };
    let Some(p) = pending(&r.scope) else {
        return Outcome::Stopped("no guarded change is waiting to be kept".into());
    };
    let left = p.deadline - jiff::Timestamp::now().as_second();
    let o = if left <= 0 {
        // The window has passed: see what the router did.
        let said = fresh(r, &settled_script(&p.token)).unwrap_or_default();
        if said.contains("reverted") || said.contains("restored") {
            say("the window passed: the router took the change back by itself".into());
            Outcome::Reverted("not kept within the window".into())
        } else {
            Outcome::Unknown("the window passed, and the router left no word of a revert".into())
        }
    } else {
        match disarm(r, &p.token, window, Duration::from_secs(left as u64), say) {
            Outcome::Reverted(w) if w.starts_with("too close") => {
                Outcome::Reverted(format!("{w}: not kept within the window"))
            }
            o => o,
        }
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
            // An option that is a script run as root, or a file a daemon reads or serves.
            ("firewall", "uci add firewall include", "", "runs as root"),
            (
                "firewall",
                "uci set firewall.@include[-1].path='/tmp/x.sh'",
                "",
                "runs as root",
            ),
            (
                "dhcp",
                "uci set dhcp.@dnsmasq[0].dhcpscript='/tmp/x.sh'",
                "",
                "runs as root",
            ),
            (
                "uhttpd",
                "uci add_list uhttpd.main.interpreter='.sh=/bin/sh'",
                "",
                "runs as root",
            ),
            (
                "dropbear",
                "uci set dropbear.main.BannerFile='/etc/shadow'",
                "",
                "runs as root",
            ),
            (
                "network",
                "uci set network.wan.pppd_options='plugin x.so'",
                "",
                "runs as root",
            ),
            (
                "wireless",
                "uci set wireless.radio0.hostapd_options='a=b'",
                "",
                "runs as root",
            ),
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
        insta::assert_snapshot!("guard_hook", hook_script(&c, t));
        insta::assert_snapshot!("guard_armed", armed_script(t));
        insta::assert_snapshot!("guard_apply", apply_script(&c, t));
        insta::assert_snapshot!("guard_disarm", disarm_script(t));
        insta::assert_snapshot!("guard_abort", abort_script(t));
        insta::assert_snapshot!("guard_settled", settled_script(t));
        insta::assert_snapshot!("guard_clear", clear_script());
        // Nothing is changed before the sleeper is started, and it is started last, after
        // the snapshot and the boot hook are on flash.
        let arm = arm_script(&c, t, 300);
        assert!(!arm.contains("uci set") && !arm.contains("uci commit"));
        assert!(arm.trim_end().ends_with("echo @@snapshot"));
        let at = |what: &str| arm.find(what).unwrap_or_else(|| panic!("no `{what}`"));
        assert!(at("cp -p /etc/config/$c \"$F/config/$c\"") < at("cat > \"$H\""));
        assert!(at("cat > \"$H\"") < at(": > \"$D/armed\""));
        assert!(at(": > \"$D/armed\"") < at("sync\n"));
        assert!(at("sync\n") < at("setsid sh"));
        // The sleeper takes the guard by a rename before it does anything, then can't be
        // stopped; it restores before it reloads, the same services in the same order,
        // and removes the hook and its own directory last.
        let dead = &arm[at("deadman.sh")..];
        let d = |what: &str| dead.find(what).unwrap_or_else(|| panic!("no `{what}`"));
        assert!(d("wait $!") < d("mv \"$D/armed\" \"$D/claim.deadman\" 2>/dev/null || exit 0"));
        assert!(d("mv \"$D/armed\"") < d("trap '' HUP INT TERM"));
        assert!(d("trap '' HUP INT TERM") < d("SENTRY_GUARD_SLEEPER=1 sh \"$H\""));
        assert!(d("sh \"$H\"") < d("sh \"$D/reloads.sh\""));
        assert!(d("sh \"$D/reloads.sh\"") < d("rm -f \"$H\""));
        assert!(d("rm -f \"$H\"") < d("rm -rf \"$D\""));
        assert!(
            at("/etc/init.d/firewall reload") < at("/etc/init.d/dnsmasq reload")
                && at("/etc/init.d/dnsmasq reload") < at("deadman.sh")
        );
        // Applying refuses when it isn't armed, and commits only after every line staged.
        let apply = apply_script(&c, t);
        assert!(apply.find("not armed").unwrap() < apply.find("uci set").unwrap());
        assert!(apply.rfind("|| fail 'line").unwrap() < apply.find("uci commit").unwrap());
        assert!(apply.find("uci commit").unwrap() < apply.find("setsid sh").unwrap());
        // Disarming and aborting act only inside their own claim: no kill, no removal and
        // no word of "kept" unless the rename held.
        for (script, who) in [(disarm_script(t), "disarm"), (abort_script(t), "abort")] {
            let claim = format!("if mv \"$D/armed\" \"$D/claim.{who}\" 2>/dev/null; then");
            let (start, other) = (
                script.find(&claim).unwrap(),
                script.find("\nelse\n").unwrap(),
            );
            for acts in [
                "kill ",
                "rm -f \"$H\"",
                "rm -rf \"$F\"",
                "rm -rf \"$D\"",
                "echo claimed",
            ] {
                let i = script.find(acts).unwrap_or_else(|| panic!("no `{acts}`"));
                assert!(i > start && i < other, "{who}: `{acts}` outside the claim");
                assert_eq!(
                    script.matches(acts).count(),
                    script[start..other].matches(acts).count()
                );
            }
            assert!(script[other..].contains("echo lost"));
        }
        assert!(disarm_script(t).contains("0123456789abcdef kept"));
        assert!(
            !disarm_script(t).contains("sh \"$H\""),
            "a disarm restores nothing"
        );
        assert!(abort_script(t).contains("SENTRY_GUARD_SLEEPER=1 sh \"$H\""));
        // The hook restores only while the snapshot is there, and removes it: run twice,
        // or after the change was kept, it does nothing.
        let hook = hook_script(&c, t);
        assert!(hook.find("[ -d \"$F/config\" ] || exit 0").unwrap() < hook.find("cp -p").unwrap());
        assert!(hook.find("cp -p").unwrap() < hook.find("rm -rf \"$F\"").unwrap());
        assert!(hook.trim_end().ends_with("exit 0"));
        assert!(
            !hook.contains("reload") && !hook.contains("/tmp/"),
            "at boot nothing runs yet"
        );
        // Where things are: only names the policy refuses to anyone but the guard.
        for path in [dir(t), flash(t), super::hook(t)] {
            assert!(
                crate::policy::secret_path(&path, true).is_some(),
                "{path} can be listed"
            );
        }
        assert_eq!(flash(t), "/etc/sentry-guard/0123456789abcdef");
        assert_eq!(
            super::hook(t),
            "/etc/uci-defaults/zz-sentry-guard-0123456789abcdef"
        );
    }

    #[test]
    fn one_guarded_change_at_a_time_from_here() {
        let scope = "net:guard-lock-test";
        let first = turn(scope).expect("the lock");
        let second = turn(scope).err().expect("held");
        assert!(second.contains("one at a time"), "{second}");
        drop(first);
        assert!(turn(scope).is_ok(), "free again");
        let _ = std::fs::remove_dir_all(sentry_core::maint::data_root(scope));
        assert_eq!(settle_gap(300), Duration::from_secs(3));
        assert_eq!(settle_gap(20), Duration::from_secs(2));
        assert_eq!(settle_gap(6), Duration::from_secs(1));
        // A disarm is answered before the sleeper wakes, or not waited for.
        for w in [5, 6, 20, 300, 3600] {
            assert!(margin(w) >= 2 && margin(w) - 1 < margin(w) && margin(w) <= 15);
        }
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
            no(&BEFORE.replace("@@guards\n", "@@guards\nlive /tmp/sentry-guard-ffff/\n"))
                .contains("another guarded change is armed on the router (ffff)")
        );
        // A leftover with nothing alive: named, not mistaken for an armed guard (applying
        // clears it; see `clear_script`).
        let dead = state(&BEFORE.replace(
            "@@guards\n",
            "@@guards\ndead /tmp/sentry-guard-aaaa/\nflash /etc/sentry-guard/aaaa/\nflash /etc/sentry-guard/bbbb/\n",
        ));
        assert!(dead.guards.is_empty());
        assert_eq!(dead.leftovers, ["aaaa", "bbbb"]);
        assert!(
            preflight(&c, &dead)
                .unwrap_err()
                .contains("nothing running to settle it (aaaa)")
        );
        // An armed guard's own snapshot isn't a leftover.
        let live = state(&BEFORE.replace(
            "@@guards\n",
            "@@guards\nlive /tmp/sentry-guard-cccc/\nflash /etc/sentry-guard/cccc/\n",
        ));
        assert_eq!((live.guards.len(), live.leftovers.len()), (1, 0));
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
        // netifd still at work: the reload returned, the interface isn't set up yet.
        let pending = after_text.replace(
            "{\"interface\":\"lan\",\"up\":true}",
            "{\"interface\":\"lan\",\"up\":false,\"pending\":true,\"ipv4-address\":[{\"address\":\"192.0.2.1\",\"mask\":24}]}",
        );
        assert_eq!(state(&pending).pending, ["lan"]);
        assert!(no(pending.clone()).contains("still setting interface lan up"));
        // And settled is the same answer twice: an address that moved isn't.
        assert_eq!(
            ok.ifaces,
            ["lan up ", "wan up ", "wan6 down "],
            "{:?}",
            ok.ifaces
        );
        let moved = state(&pending.replace("\"up\":false,\"pending\":true", "\"up\":true"));
        assert_eq!(moved.ifaces[0], "lan up 192.0.2.1/24");
        assert!(steady(&ok, &ok) && !steady(&ok, &moved));
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
