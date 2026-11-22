//! `sentry-network` subcommands that don't need the TUI. Each returns the process exit code.
//! Everything they run on the router is a read.

use std::time::Instant;

use super::collect::{self, CollectError, ifaces, probe};
use super::config::{self, Network};
use super::init;
use super::rates;
use super::remote::Router;

fn load(name: Option<&str>) -> Result<(String, Network), String> {
    let (file, warnings) = config::load()?;
    warnings.iter().for_each(|w| eprintln!("{w}"));
    let (n, s) = config::pick(&file, name)?;
    Ok((n.to_string(), s.clone()))
}

/// `record [name]`: sample the router into its metrics ring until Ctrl-C.
pub fn record(name: Option<&str>) -> u8 {
    let (n, cfg) = match load(name) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    match super::recorder::record(&Router::new(&n, &cfg)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("sentry-network record: {e:#}");
            1
        }
    }
}

/// `lint [name]`: the file, checked without contacting any router.
pub fn lint(name: Option<&str>) -> u8 {
    let (file, warnings) = match config::load() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let mut problems: Vec<String> = warnings;
    let names: Vec<String> = match name {
        Some(n) => vec![n.to_string()],
        None => file.networks.keys().cloned().collect(),
    };
    if names.is_empty() {
        problems.push("network_config.yaml has no networks".into());
    }
    for n in &names {
        match file.networks.get(n) {
            Some(net) => problems.extend(config::lint(n, net)),
            None => problems.push(format!("no network `{n}`")),
        }
    }
    if problems.is_empty() {
        println!("{}: ok ({})", config::path().display(), names.join(", "));
        return 0;
    }
    problems.iter().for_each(|p| println!("{p}"));
    1
}

/// `collect [kind] [name]`: one collector's result as JSON, or every collector's.
pub fn collect(kind: Option<&str>, name: Option<&str>) -> u8 {
    let (n, cfg) = match load(name) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let r = Router::new(&n, &cfg);
    let res = match kind {
        Some(k) => collect::collect_json(&r, k),
        None => collect::KINDS
            .iter()
            .map(|k| Ok((k.to_string(), collect::collect_json(&r, k)?)))
            .collect::<Result<serde_json::Map<_, _>, CollectError>>()
            .map(serde_json::Value::Object),
    };
    match res {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            0
        }
        // As `sentry collect` says it: not an error of ours.
        Err(CollectError::Unavailable(bin)) => {
            println!("{}", serde_json::json!({ "unavailable": bin }));
            3
        }
        Err(e) => {
            eprintln!("sentry-network collect: {e}");
            1
        }
    }
}

/// `audit [name]`: what needs attention on the router, written to a report.
pub fn audit(name: Option<&str>) -> u8 {
    let (n, cfg) = match load(name) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    match super::audit::run(&Router::new(&n, &cfg)) {
        Ok((report, path)) => {
            for f in report.open() {
                println!("{:<6} {}  ({})", f.severity.as_str(), f.message, f.id);
            }
            let expected = report.findings.iter().filter(|f| f.expected).count();
            if report.open().next().is_none() {
                println!("✓ nothing needs attention");
            }
            if expected > 0 {
                println!("· {expected} expected finding(s) hidden");
            }
            for (section, e) in &report.snapshot.errors {
                println!("· {section}: {e}");
            }
            println!("report: {}", path.display());
            0
        }
        Err(e) => {
            eprintln!("sentry-network audit: {e}");
            1
        }
    }
}

/// The commands the network target uses, now or soon: which are there is worth knowing
/// before anything depends on them.
const TOOLS: &[&str] = &[
    "ubus",
    "uci",
    "ip",
    "netstat",
    "nft",
    "iw",
    "logread",
    "apk",
    "sysupgrade",
    "hexdump",
    "brctl",
];

/// `check [name]`: is the router reachable, as root, and what was found there.
pub fn check(name: Option<&str>) -> u8 {
    let (n, cfg) = match load(name) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let r = Router::new(&n, &cfg);
    println!("{n} (ssh {})", r.host);
    let mut bad = 0;
    let mut no = |what: String| {
        println!("✗ {what}");
        bad += 1;
    };
    let t = Instant::now();
    let uid = match r.output(&r.sh("id -u")) {
        Ok(u) => u.trim().to_string(),
        Err(e) => {
            println!("✗ not reachable: {e}");
            return 1;
        }
    };
    let first = t.elapsed().as_millis();
    let t = Instant::now();
    let _ = r.output(&r.sh("true"));
    let again = t.elapsed().as_millis();
    if uid == "0" {
        println!("✓ reachable as root ({first} ms, then {again} ms on the shared connection)");
    } else {
        no(format!(
            "the login is uid {uid}, not root: a router's login is root (there is no sudo)"
        ));
    }
    let tools = format!(
        "for b in {}; do command -v $b >/dev/null && echo \"+$b\" || echo \"-$b\"; done",
        TOOLS.join(" ")
    );
    if let Ok(out) = r.output(&r.sh(&tools)) {
        let (have, miss): (Vec<&str>, Vec<&str>) = out.lines().partition(|l| l.starts_with('+'));
        let strip = |v: Vec<&str>| v.iter().map(|l| &l[1..]).collect::<Vec<_>>().join(" ");
        if miss.is_empty() {
            println!("✓ tools: {}", strip(have));
        } else {
            println!("· tools: {} (missing: {})", strip(have), strip(miss));
        }
    }
    let t = Instant::now();
    let ifs = ifaces::collect(&r);
    let took = t.elapsed().as_millis();
    match &ifs {
        Ok(i) => {
            let b = &i.board;
            println!(
                "✓ {} {} ({}) · {} · {} · kernel {} ({took} ms)",
                b.distribution, b.version, b.revision, b.model, b.target, b.kernel
            );
        }
        Err(e) => no(format!("interfaces: {e}")),
    }
    let t = Instant::now();
    match probe::collect(&r) {
        Ok(p) => {
            let h = &p.host;
            println!(
                "✓ probe: {} cores · load {:.2} · memory {:.0}% of {} · up {} ({} ms)",
                h.cores,
                h.load[0],
                h.mem_used_pct(),
                sentry_core::fmt::bytes(h.mem_total_kib * 1024),
                sentry_core::fmt::uptime(h.uptime_s),
                t.elapsed().as_millis()
            );
        }
        Err(e) => no(format!("probe: {e}")),
    }
    if let Ok(i) = &ifs {
        let rows = i.rows();
        let said: Vec<String> = rows
            .iter()
            .map(|d| {
                let net = i
                    .net_of(&d.name)
                    .map_or(String::new(), |n| format!(" ({n})"));
                let link = match (d.carrier, d.speed) {
                    (false, _) => " no link".to_string(),
                    (true, Some(m)) => format!(" {}", rates::speed(m)),
                    (true, None) => String::new(),
                };
                format!("{}{net}{link}", d.name)
            })
            .collect();
        println!(
            "✓ {} ports and radios, {} with link: {}",
            rows.len(),
            rows.iter().filter(|d| d.carrier).count(),
            said.join(" · ")
        );
        match i.wan() {
            Some(w) if w.up => println!(
                "✓ WAN ({} on {}) up{}{}",
                w.proto,
                w.device,
                w.ipv4.first().map_or(String::new(), |a| format!(": {a}")),
                w.lease_time_s
                    .map_or(String::new(), |l| format!(" · lease {l} s")),
            ),
            Some(w) => println!("· WAN ({} on {}) is down", w.proto, w.device),
            None => println!("· no uplink interface found"),
        }
        if let Some(w6) = i.wan6() {
            println!(
                "{} IPv6 ({}){}",
                if w6.up { "✓" } else { "·" },
                w6.name,
                match (w6.up, w6.prefixes.first()) {
                    (false, _) => " is down".to_string(),
                    (true, Some(p)) => format!(": prefix {p}"),
                    (true, None) => " up".to_string(),
                }
            );
        }
    }
    // What the Clients and Network screens and the audit read: each one exec, timed.
    let mut timed = |what: &str, res: Result<String, CollectError>, t: Instant| match res {
        Ok(said) => println!("✓ {what}: {said} ({} ms)", t.elapsed().as_millis()),
        Err(CollectError::Unavailable(bin)) => println!("· {what}: {bin} isn't on the router"),
        Err(e) => no(format!("{what}: {e}")),
    };
    let t = Instant::now();
    timed(
        "clients",
        collect::clients::collect(&r).map(|c| {
            format!(
                "{} IPv4 and {} IPv6 leases · {} neighbours · {} on wired ports · {} on Wi-Fi",
                c.leases.len(),
                c.leases6.len(),
                c.neigh.iter().filter(|n| n.mac.is_some()).count(),
                c.fdb.len().saturating_sub(c.stations.len()),
                c.stations.len()
            )
        }),
        t,
    );
    let t = Instant::now();
    timed(
        "listeners",
        collect::listeners::collect(&r).map(|l| format!("{} sockets", l.len())),
        t,
    );
    let t = Instant::now();
    timed(
        "config",
        collect::uci::collect(&r).map(|u| {
            format!(
                "{} configs · {} zones · {} forwards · {} staged line(s)",
                u.configs.len(),
                u.zones().len(),
                u.forwards().len(),
                u.staged.len()
            )
        }),
        t,
    );
    let t = Instant::now();
    timed(
        "certificate",
        collect::cert::collect(&r).map(|c| match c {
            Some(c) => format!("valid until {}", c.not_after.strftime("%Y-%m-%d")),
            None => "the web interface has none".to_string(),
        }),
        t,
    );
    let t = Instant::now();
    timed(
        "services",
        collect::services::collect(&r).map(|s| {
            format!(
                "{} of {} running",
                s.0.values().filter(|x| x.running > 0).count(),
                s.0.len()
            )
        }),
        t,
    );
    // What Security reads: counts only are printed here.
    let t = Instant::now();
    timed(
        "counters",
        collect::counters::collect(&r).map(|c| {
            format!(
                "{} · {} · {}",
                match &c.rules {
                    Some(r) => format!("{} counted rules", r.len()),
                    None => "no fw4 table".to_string(),
                },
                match c.conntrack {
                    Some((n, max)) => format!("{n} of {max} connections tracked"),
                    None => "no connection tracking".to_string(),
                },
                match c.dns {
                    Some(_) => "dnsmasq counts",
                    None => "no dnsmasq counters",
                }
            )
        }),
        t,
    );
    let t = Instant::now();
    timed(
        "flows",
        collect::flows::collect(&r).map(|f| {
            format!(
                "{} live flows · accounting {}",
                f.flows.len(),
                match f.acct {
                    Some(true) => "on",
                    Some(false) => "off",
                    None => "unknown",
                }
            )
        }),
        t,
    );
    let t = Instant::now();
    timed(
        "log",
        collect::seclog::collect(&r).map(|l| {
            format!(
                "{} lines · {} · {} ssh and Wi-Fi events",
                l.lines,
                match l.window_s() {
                    Some(w) => format!("{}h {}m back", w / 3600, (w % 3600) / 60),
                    None => "no window".to_string(),
                },
                l.events.len()
            )
        }),
        t,
    );
    let t = Instant::now();
    timed(
        "dns filter",
        collect::dnsstate::collect(&r).map(|d| {
            format!(
                "{} · {}",
                match d.blocklist.as_ref().map(|b| b.entries) {
                    Some(Some(n)) => format!("blocklist {n} names"),
                    Some(None) => "blocklist".to_string(),
                    None => "no adblock-fast".to_string(),
                },
                match &d.proxy {
                    Some(p) if p.force_dns => "DNS forced",
                    Some(_) => "https-dns-proxy",
                    None => "no https-dns-proxy",
                }
            )
        }),
        t,
    );
    // What Maintenance reads about its items.
    let t = Instant::now();
    timed(
        "packages",
        collect::updates::collect(&r)
            .map(|u| format!("{} upgradable · {}", u.packages.len(), u.index_said())),
        t,
    );
    let t = Instant::now();
    timed(
        "backups",
        super::backup::status(&r, None).map(|b| match (&b.newest, &b.changed) {
            (None, _) if b.recipients => "none yet".to_string(),
            (None, _) => "none yet · no recipient (backup.recipients)".to_string(),
            (Some(_), Some(c)) if c.any() => {
                format!("{} kept · {} file(s) changed since", b.count, c.files.len())
            }
            (Some(_), Some(_)) => format!("{} kept · nothing changed since", b.count),
            (Some(_), None) => format!("{} kept", b.count),
        }),
        t,
    );
    let problems = config::lint(&n, &cfg);
    problems.iter().for_each(|p| println!("· config: {p}"));
    u8::from(bad > 0)
}

/// `init <ssh-host> [--name N]`: draft network_config.yaml from what the router reports.
/// Never touches a file that's there.
pub fn init(ssh: &str, name: Option<&str>) -> u8 {
    let name = name.unwrap_or("home");
    let probe = Network {
        router: config::RouterCfg {
            ssh: Some(ssh.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    eprintln!("looking around {ssh} (read-only)…");
    let facts = match init::discover(&Router::new(name, &probe)) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("sentry-network init: {e}");
            return 1;
        }
    };
    let today = jiff::Zoned::now().strftime("%Y-%m-%d").to_string();
    let text = init::draft(name, ssh, &facts, &today);
    // Only what parses back is worth keeping.
    if let Err(e) = config::parse(&text) {
        eprintln!("sentry-network init: the draft doesn't parse ({e}); here it is:\n");
        println!("{text}");
        return 1;
    }
    let p = config::path();
    if p.exists() {
        println!("{text}");
        eprintln!(
            "{} is already there: not touching it. That's the draft, above.",
            p.display()
        );
        return 1;
    }
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    match sentry_core::paths::write_atomic(&p, text.as_bytes()) {
        Ok(()) => {
            println!(
                "wrote {} ({} devices holding a lease, to name): check it, then `sentry-network lint`",
                p.display(),
                config::parse(&text).map_or(0, |(f, _)| f.networks[name].devices.len())
            );
            0
        }
        Err(e) => {
            eprintln!("{}: {e}", p.display());
            1
        }
    }
}

/// `backup [name]`: back the router's configuration up now, encrypted to the config's
/// recipients. 3: no recipient is configured.
pub fn backup(name: Option<&str>) -> u8 {
    use super::backup::{self, Error};
    let (n, cfg) = match load(name) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    match backup::run(&Router::new(&n, &cfg)) {
        Ok(made) => {
            made.lines().iter().for_each(|l| println!("{l}"));
            println!(
                "· the archive took {} ms, the files' digest {} ms",
                made.took.as_millis(),
                made.digest_took.as_millis()
            );
            0
        }
        Err(Error::Unavailable(why)) => {
            println!("✗ {why}");
            3
        }
        Err(e) => {
            println!("✗ no backup was made: {e}");
            1
        }
    }
}

/// `backup [name] --verify`: the newest backup is there, encrypted, and holds what the
/// router has now.
pub fn backup_verify(name: Option<&str>) -> u8 {
    let (n, cfg) = match load(name) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    match super::backup::verify(&Router::new(&n, &cfg)) {
        Ok(said) => {
            println!("✓ {said}");
            0
        }
        Err(why) => {
            println!("✗ {why}");
            1
        }
    }
}

/// `backup list [name]`: the backups kept, newest first. Nothing is read from the router.
pub fn backup_list(name: Option<&str>) -> u8 {
    let (n, cfg) = match load(name) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let scope = super::remote::scope(&n);
    let dir = super::backup::backups_dir(&scope);
    let kept = super::backup::list(&scope);
    if kept.is_empty() {
        println!("no backups of {n} yet ({})", dir.display());
        if cfg.backup.recipients.is_empty() {
            println!("· {}", super::backup::NO_RECIPIENTS);
        }
        return 0;
    }
    for k in &kept {
        println!(
            "{}  OpenWrt {:<10} {:>10}  {}",
            k.at.strftime("%Y-%m-%d %H:%M UTC"),
            k.release,
            sentry_core::fmt::bytes(k.size),
            k.path.display()
        );
    }
    println!(
        "{} kept (backup.keep {}, and each month's first for a year)",
        kept.len(),
        cfg.backup.keep
    );
    0
}

/// `backup decrypt <file> -i <identity> [-o out]`: read a backup back with your secret key.
/// What comes out is the plain archive (the Wi-Fi passphrase and the router's keys are in
/// it): `-o -` writes it to stdout instead of a file.
pub fn backup_decrypt(file: &std::path::Path, identity: &std::path::Path, out: Option<&str>) -> u8 {
    use super::backup;
    let res = match out {
        Some("-") => backup::decrypt(file, identity, &mut std::io::stdout().lock()).map(|_| None),
        _ => {
            let path = out.map_or_else(|| backup::decrypted_name(file), std::path::PathBuf::from);
            backup::plain_file(&path).and_then(|mut f| {
                backup::decrypt(file, identity, &mut f)
                    .inspect_err(|_| {
                        let _ = std::fs::remove_file(&path);
                    })
                    .map(|n| Some((path, n)))
            })
        }
    };
    match res {
        Ok(Some((path, n))) => {
            eprintln!(
                "wrote {} ({}): the plain archive, secrets and all. Restore it with OpenWrt's \
                 own restore, then remove it.",
                path.display(),
                sentry_core::fmt::bytes(n)
            );
            0
        }
        Ok(None) => 0,
        Err(e) => {
            eprintln!("sentry-network backup decrypt: {e}");
            1
        }
    }
}

/// `backup key <path>`: make a key to encrypt backups to. The file is the secret half;
/// what's printed is the public half, for the config.
pub fn backup_key(path: &std::path::Path) -> u8 {
    match super::backup::make_key(path) {
        Ok(public) => {
            eprintln!(
                "wrote {} (0600): the secret key. Keep a copy somewhere that isn't this \
                 machine; without it no backup can be read.",
                path.display()
            );
            eprintln!("In network_config.yaml, under the network:");
            println!("    backup: {{ recipients: [ \"{public}\" ] }}");
            0
        }
        Err(e) => {
            eprintln!("sentry-network backup key: {e}");
            1
        }
    }
}

/// `run <name> [--] <line>`: the gateway an apply session's Claude uses. Only a line that
/// reads is run (as root, its output scrubbed); the rest is refused in its class's words.
pub fn run(name: &str, line: &[String]) -> u8 {
    let line = match line.first().map(String::as_str) {
        Some("--") => line[1..].join(" "),
        _ => line.join(" "),
    };
    match load(Some(name)) {
        Ok((n, cfg)) => super::gateway::run_cli(&Router::new(&n, &cfg), &line),
        Err(e) => {
            eprintln!("{e}");
            2
        }
    }
}

/// `exec <name> [--] <argv…>`: the read-only gateway chats and reviews use.
pub fn exec(name: &str, argv: &[String]) -> u8 {
    let argv: Vec<String> = match argv.first().map(String::as_str) {
        Some("--") => argv[1..].to_vec(),
        _ => argv.to_vec(),
    };
    match load(Some(name)) {
        Ok((n, cfg)) => super::gateway::exec_cli(&Router::new(&n, &cfg), &argv),
        Err(e) => {
            eprintln!("{e}");
            2
        }
    }
}

/// `guard <name> preview|apply|keep [configs=a,b] [services=x,y] [wan=yes] [-- <uci lines>]`:
/// a guarded change (what the `guarded-change` workflow's steps run). `preview` only
/// reads. Exit 0: in place (kept, or applied and waiting for `keep`); 3: not started,
/// nothing changed; 4: the router took it back; 5: failed before any reload, put back;
/// 6: not confirmed, and the router couldn't be asked.
pub fn guard(name: &str, action: &str, rest: &[String]) -> u8 {
    use super::guard::{self, Change, Outcome};
    let (n, cfg) = match load(Some(name)) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let r = Router::new(&n, &cfg);
    let window = cfg.guard.window;
    let mut say = |l: String| println!("{l}");
    let ended = |o: Outcome| {
        match &o {
            Outcome::Kept => println!("KEPT: the change is in place."),
            Outcome::Waiting => {}
            Outcome::Stopped(why) => eprintln!("STOPPED, nothing was changed: {why}"),
            Outcome::Failed(why) => eprintln!("FAILED: {why}"),
            Outcome::Reverted(why) => eprintln!(
                "REVERTED: the change was not kept ({why}). The router restored its configs \
                 and reloaded the same services by itself."
            ),
            Outcome::Unknown(why) => eprintln!(
                "NOT CONFIRMED: {why}. The router restores itself at its deadline; look at it \
                 before trying again."
            ),
        }
        o.code()
    };
    if action == "keep" {
        return ended(guard::keep(&r, window, &mut say));
    }
    let split = rest.iter().position(|a| a == "--").unwrap_or(rest.len());
    let val = |key: &str| {
        rest[..split]
            .iter()
            .find_map(|a| a.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or("")
    };
    let lines = rest.get(split + 1..).unwrap_or(&[]).join(" ");
    let wan = matches!(val("wan"), "yes" | "true" | "1");
    let change = match Change::parse(val("configs"), &lines, val("services"), wan) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("STOPPED, nothing was changed: {e}");
            return 3;
        }
    };
    match action {
        "preview" => match guard::preview(&r, &change, &mut say) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("STOPPED, nothing was changed: {e}");
                3
            }
        },
        "apply" => ended(guard::run(&r, &change, window, &mut say)),
        other => {
            eprintln!("guard: `{other}` isn't preview, apply or keep");
            2
        }
    }
}

/// The services that should run, do: what `packages check` and `firmware after` say.
fn services_up(r: &Router) -> bool {
    use collect::services::{self, State};
    let svc = match services::collect(r) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("the services couldn't be read: {e}");
            return false;
        }
    };
    let mut ok = true;
    for name in svc.watched(&r.cfg.expect.services) {
        match svc.state(name) {
            State::Running | State::NotADaemon => println!("✓ {name} runs"),
            State::Down | State::Missing => {
                eprintln!("✗ {name} isn't running");
                ok = false;
            }
        }
    }
    ok
}

/// `packages <name> preview|plan|upgrade|check [base] [-- <names>]`: what the
/// `package-update` workflow's steps run. `plan` and `upgrade` take the names to upgrade
/// (never everything) and ask apk what the whole transaction would be: `upgrade` goes on
/// only when every package in it is a leaf, unless the step says `base` (the workflow's
/// risky step, never auto's).
pub fn packages(name: &str, action: &str, rest: &[String]) -> u8 {
    use super::packages::{self, all_leaves, base_package};
    let (n, cfg) = match load(Some(name)) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let r = Router::new(&n, &cfg);
    // `[base] -- <names>`. (A `--` right after the action is taken by the argument
    // parser: then everything left is names.)
    let split = rest.iter().position(|a| a == "--");
    let base = split.is_some_and(|i| rest[..i].iter().any(|a| a == "base"));
    let names: Vec<&str> = rest[split.map_or(0, |i| i + 1)..]
        .iter()
        .flat_map(|a| a.split_whitespace())
        .collect();
    // The transaction, shown: the names asked for and everything they take along.
    let planned = || -> Result<Vec<packages::Tx>, u8> {
        match packages::simulate(&r, &names) {
            Ok(tx) => {
                println!("$ {}", packages::simulate_line(&names));
                if tx.is_empty() {
                    println!("nothing would change: these are as new as the index knows");
                } else {
                    println!(
                        "upgrading {} would change {} package(s):",
                        names.join(" "),
                        tx.len()
                    );
                    tx.iter().for_each(|t| println!("{}", t.line()));
                }
                Ok(tx)
            }
            Err(e) => {
                eprintln!("{e}");
                Err(3)
            }
        }
    };
    match action {
        "preview" => match collect::updates::refresh(&r) {
            Ok(u) => {
                if u.refresh_failed.is_some() {
                    eprintln!(
                        "apk update failed on the router: the list below is from the index it had"
                    );
                }
                println!("{} package(s) could be upgraded:", u.packages.len());
                for p in &u.packages {
                    println!(
                        "  {} {} → {}{}",
                        p.name,
                        p.from,
                        p.to,
                        if base_package(&p.name) {
                            "  (base system)"
                        } else {
                            ""
                        }
                    );
                }
                0
            }
            Err(e) => {
                eprintln!("sentry-network packages: {e}");
                1
            }
        },
        "plan" => match planned() {
            Ok(tx) => {
                if !tx.is_empty() && !all_leaves(&tx) {
                    println!(
                        "more than leaves: this one asks, whatever auto mode says (the next step is the risky one)"
                    );
                }
                0
            }
            Err(code) => code,
        },
        "upgrade" => {
            let tx = match planned() {
                Ok(tx) => tx,
                Err(code) => return code,
            };
            if tx.is_empty() {
                return 0;
            }
            if !base && !all_leaves(&tx) {
                let first = tx
                    .iter()
                    .find(|t| !packages::leaf_package(&t.name))
                    .map_or("", |t| t.name.as_str());
                eprintln!(
                    "`{first}` would be upgraded too, and isn't on the list of leaves: that is the workflow's risky step, not this one. Nothing was upgraded"
                );
                return 3;
            }
            let line = format!("apk upgrade {}", names.join(" "));
            println!("$ {line}");
            match r
                .sh(&line)
                .timeout(Some(std::time::Duration::from_secs(900)))
                .run()
            {
                Ok(o) => {
                    print!("{}", o.stdout);
                    eprint!("{}", o.stderr);
                    o.code.clamp(0, 255) as u8
                }
                Err(e) => {
                    eprintln!("sentry-network packages: {e}");
                    1
                }
            }
        }
        "check" => {
            let up = services_up(&r);
            let audited = audit(Some(&n));
            if up && audited == 0 { 0 } else { 1 }
        }
        other => {
            eprintln!("packages: `{other}` isn't preview, plan, upgrade or check");
            2
        }
    }
}

/// `firmware <name> check|flash|after`: what the `firmware-upgrade` workflow's own steps
/// run. `flash` is `owut upgrade` on the router, with sentry's sysupgrade lock held, and
/// the wait for it to come back on a new boot. Never run end to end (the workflow is a
/// draft).
pub fn firmware(name: &str, action: &str) -> u8 {
    let (n, cfg) = match load(Some(name)) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let r = Router::new(&n, &cfg);
    let board = || ifaces::collect(&r).map(|i| i.board);
    let boot_id = |fresh: bool| {
        let c = r.cmd("cat").arg("/proc/sys/kernel/random/boot_id");
        let c = if fresh { c.own_connection() } else { c };
        c.output().map(|s| s.trim().to_string())
    };
    match action {
        "check" => match board() {
            Ok(b) => {
                println!(
                    "running {} {} ({}, {})",
                    b.distribution, b.version, b.target, b.board_name
                );
                let Some(series) = super::maint::eval::series(&b.version) else {
                    println!("not a release (a snapshot build): nothing to compare with");
                    return 0;
                };
                let up = super::maint::upstream::get(&n, &series);
                match &up.data.releases {
                    Ok(rs) => println!(
                        "{} release(s) known upstream for {series}: {rs:?}",
                        rs.len()
                    ),
                    Err(e) => println!("the releases couldn't be looked up: {e}"),
                }
                0
            }
            Err(e) => {
                eprintln!("sentry-network firmware: {e}");
                1
            }
        },
        "flash" => {
            // sysupgrade keeps its file list at a fixed path: nothing else of sentry's
            // may run it while owut does.
            let _turn = match super::backup::turn(&r.scope) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("sentry-network firmware: the sysupgrade lock: {e}");
                    return 1;
                }
            };
            let (Ok(before), Ok(boot)) = (board(), boot_id(false)) else {
                eprintln!("the router didn't answer: nothing was flashed");
                return 1;
            };
            println!("running {} · flashing with `owut upgrade`", before.version);
            // The connection drops when the router restarts: that is the upgrade happening.
            match r
                .sh("owut upgrade")
                .timeout(Some(std::time::Duration::from_secs(900)))
                .run()
            {
                Ok(o) => {
                    print!("{}", o.stdout);
                    eprint!("{}", o.stderr);
                }
                Err(e) => println!("(the connection ended: {e})"),
            }
            println!("… waiting for the router to come back (up to 10 minutes)");
            let until = Instant::now() + std::time::Duration::from_secs(600);
            while Instant::now() < until {
                std::thread::sleep(std::time::Duration::from_secs(5));
                if let Ok(now) = boot_id(true)
                    && !now.is_empty()
                    && now != boot
                {
                    return match board() {
                        Ok(b) if b.version != before.version => {
                            println!("✓ back, running {} (was {})", b.version, before.version);
                            0
                        }
                        Ok(b) => {
                            eprintln!(
                                "✗ back on {}: it restarted, but nothing was flashed",
                                b.version
                            );
                            1
                        }
                        Err(e) => {
                            eprintln!("✗ back, but the board didn't read: {e}");
                            1
                        }
                    };
                }
            }
            eprintln!("✗ the router didn't come back on a new boot within 10 minutes");
            1
        }
        "after" => {
            match board() {
                Ok(b) => println!("running {} {}", b.distribution, b.version),
                Err(e) => {
                    eprintln!("the board didn't read: {e}");
                    return 1;
                }
            }
            let up = services_up(&r);
            let clients = collect::clients::collect(&r)
                .map(|c| c.leases.len())
                .unwrap_or(0);
            println!("{clients} device(s) hold a lease");
            let audited = audit(Some(&n));
            if up && audited == 0 { 0 } else { 1 }
        }
        other => {
            eprintln!("firmware: `{other}` isn't check, flash or after");
            2
        }
    }
}

/// `security [name] [--json]`: what needs attention and how the network is covered, from
/// one read of the router (reads only). `security <name> plan|apply <action>`: the two
/// steps of the `security-action` workflow (`plan` only reads).
pub fn security(rest: &[String]) -> u8 {
    use super::security::{actions::Do, gather, run};
    let json = rest.iter().any(|a| a == "--json");
    let words: Vec<&str> = rest
        .iter()
        .map(String::as_str)
        .filter(|a| *a != "--json")
        .collect();
    let (name, step) = match words.as_slice() {
        [] => (None, None),
        [name] => (Some(*name), None),
        [name, step @ ("plan" | "apply"), action] => (Some(*name), Some((*step, *action))),
        _ => {
            eprintln!("security [name] [--json] · security <name> plan|apply <action>");
            return 2;
        }
    };
    let (n, cfg) = match load(name) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let r = Router::new(&n, &cfg);
    if let Some((step, action)) = step {
        let d = match Do::parse(action) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("STOPPED, nothing was changed: {e}");
                return 3;
            }
        };
        let mut say = |l: String| println!("{l}");
        return match step {
            "plan" => match run::show(&r, &d, &mut say) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("STOPPED, nothing was changed: {e}");
                    3
                }
            },
            _ => run::apply(&r, &d, &mut say),
        };
    }
    let g = match gather::gather(&r) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("{n}: {e}");
            return 1;
        }
    };
    let said = gather::said(&r, &g);
    if json {
        let rows: Vec<_> = said
            .rows
            .iter()
            .map(|x| {
                serde_json::json!({
                    "key": x.key,
                    "rank": x.rank.word(),
                    "title": x.title,
                    "why": x.why,
                    "seen": x.seen,
                    "enter": x.act.enter(),
                    "can_wait": x.can_wait,
                })
            })
            .collect();
        let covered: Vec<_> = said
            .posture
            .iter()
            .map(|l| {
                serde_json::json!({
                    "what": l.what,
                    "state": l.state.word(),
                    "text": l.text,
                })
            })
            .collect();
        let v = serde_json::json!({
            "network": n,
            "attention": rows,
            "covered": covered,
            "not_read": g.errors,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return 0;
    }
    for l in security_text(&n, &said, &g.errors) {
        println!("{l}");
    }
    0
}

/// The attention list and the posture as text.
pub fn security_text(
    name: &str,
    said: &super::security::gather::Said,
    not_read: &[(String, String)],
) -> Vec<String> {
    let mut l = vec![format!("{name} · security"), String::new()];
    if said.rows.iter().all(|x| x.can_wait) {
        l.push("Nothing needs you.".into());
    } else {
        l.push("Needs attention".into());
    }
    for x in &said.rows {
        l.push(format!("  {:<8} {}", x.rank.word(), x.title));
        l.push(format!("           {}", x.why));
        l.extend(x.seen.iter().map(|s| format!("           · {s}")));
        l.push(format!(
            "           Enter on Security (4): {}",
            x.act.enter()
        ));
    }
    l.push(String::new());
    l.push("How you're covered".into());
    for c in &said.posture {
        l.push(format!("  {:<5} {}", c.state.word(), c.text));
    }
    for (what, why) in not_read {
        l.push(format!("  (not read: {what}: {why})"));
    }
    l.push(String::new());
    l.push(
        "One read: what takes two (a rate rising) isn't judged here. What a tool like this \
         can't see: what is inside the traffic, and whatever a device does without passing \
         the router."
            .into(),
    );
    l
}
