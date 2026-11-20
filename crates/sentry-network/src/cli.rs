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
