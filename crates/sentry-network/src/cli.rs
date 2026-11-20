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
