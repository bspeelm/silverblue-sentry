//! `sentry-server` subcommands that don't need the TUI. Each returns the process exit code.

use std::time::Instant;

use super::config::{self, Server};
use super::init;
use super::remote::{Remote, SrvError, SudoMode};
use crate::exec::sh_quote;

fn load(name: Option<&str>) -> Result<(String, Server), String> {
    let (file, warnings) = config::load()?;
    warnings.iter().for_each(|w| eprintln!("{w}"));
    let (n, s) = config::pick(&file, name)?;
    Ok((n.to_string(), s.clone()))
}

/// `sentry-server [name]`: the TUI.
pub fn tui(name: Option<&str>) -> u8 {
    let (n, s) = match load(name) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    match super::tui::run(Remote::new(&n, &s)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("sentry-server: {e:#}");
            1
        }
    }
}

/// `init <ssh-host> [--name N] [--write]`
pub fn init(ssh: &str, name: Option<&str>, write: bool) -> u8 {
    let name = name.unwrap_or_else(|| {
        // `admin@myserver.example` → `myserver`
        let h = ssh.rsplit('@').next().unwrap_or(ssh);
        h.split('.').next().unwrap_or(h)
    });
    let probe = Server {
        ssh: Some(ssh.to_string()),
        ..Default::default()
    };
    let r = Remote::new(name, &probe);
    eprintln!("looking around {ssh} (read-only)…");
    let facts = match init::discover(&r) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("sentry-server init: {e}");
            return 1;
        }
    };
    let entry = init::draft(name, ssh, &facts);
    if !write {
        println!("servers:\n{entry}");
        eprintln!(
            "\nThat's a draft. Save it with --write (adds it to {} without touching what's there).",
            config::path().display()
        );
        return 0;
    }
    let p = config::path();
    let current = std::fs::read_to_string(&p).ok();
    let text = match &current {
        None => format!(
            "# sentry-server configuration. See assets/server_config.example.yaml for every key.\n\
             servers:\n{entry}"
        ),
        Some(t) => {
            let (f, _) = match config::parse(t) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!(
                        "{}: {e}\nnot touching it; the draft:\n\n{entry}",
                        p.display()
                    );
                    return 1;
                }
            };
            if f.servers.contains_key(name) {
                eprintln!(
                    "{} already has `{name}`; not touching it. Use --name to add it under another name.",
                    p.display()
                );
                return 1;
            }
            let sep = if t.ends_with('\n') { "" } else { "\n" };
            format!("{t}{sep}{entry}")
        }
    };
    // Only write what parses back with the new server in it.
    match config::parse(&text) {
        Ok((f, _)) if f.servers.contains_key(name) => {}
        _ => {
            eprintln!(
                "couldn't add the entry to {} safely (is `servers:` the last section?). The draft:\n\n{entry}",
                p.display()
            );
            return 1;
        }
    }
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    match crate::paths::write_atomic(&p, text.as_bytes()) {
        Ok(()) => {
            println!("added `{name}` to {}", p.display());
            0
        }
        Err(e) => {
            eprintln!("{}: {e}", p.display());
            1
        }
    }
}

/// `lint [name] [--offline]`: the file, then (unless offline) what it names on the server.
pub fn lint(name: Option<&str>, offline: bool) -> u8 {
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
        None => file.servers.keys().cloned().collect(),
    };
    for n in &names {
        let Some(s) = file.servers.get(n) else {
            problems.push(format!("no server `{n}`"));
            continue;
        };
        problems.extend(config::lint(n, s));
        if !offline {
            match lint_remote(&Remote::new(n, s)) {
                Ok(p) => problems.extend(p),
                Err(e) => problems.push(format!("{n}: {e}")),
            }
        }
    }
    if problems.is_empty() {
        println!("✓ {}", names.join(", "));
        0
    } else {
        problems.iter().for_each(|p| println!("✗ {p}"));
        1
    }
}

/// Units, timers, devices, mounts and compose projects named in the config exist there.
fn lint_remote(r: &Remote) -> Result<Vec<String>, SrvError> {
    let n = &r.name;
    let s = &r.cfg;
    let mut p = Vec::new();
    let units: Vec<&str> = s
        .services
        .iter()
        .map(String::as_str)
        .chain(s.timers.iter().map(|t| t.unit.as_str()))
        .collect();
    if !units.is_empty() {
        let out = r.output(
            &r.cmd("systemctl")
                .args(["show", "-p", "Id,LoadState", "--"])
                .args(units.iter().copied()),
        )?;
        for (unit, block) in units.iter().zip(out.split("\n\n")) {
            if block.contains("LoadState=not-found") {
                p.push(format!("{n}: unit `{unit}` doesn't exist there"));
            }
        }
    }
    if !s.smart.is_empty() {
        let devs = s
            .smart
            .iter()
            .map(|d| sh_quote(d))
            .collect::<Vec<_>>()
            .join(" ");
        let out = r.output(&r.sh(&format!(
            "for d in {devs}; do [ -b \"$d\" ] || echo \"$d\"; done"
        )))?;
        for d in out.lines() {
            p.push(format!("{n}: smart device {d} doesn't exist there"));
        }
    }
    if !s.disks.is_empty() {
        let out = r.output(&r.cmd("findmnt").args(["-rn", "-o", "TARGET"]))?;
        let mounted: Vec<&str> = out.lines().collect();
        for d in &s.disks {
            if !mounted.contains(&d.mount.as_str()) {
                p.push(format!("{n}: {} isn't a mount point there", d.mount));
            }
        }
    }
    if !s.compose.is_empty() {
        match r.privileged(&["docker", "compose", "ls", "--all", "--format", "json"]) {
            Ok(c) => {
                let have = init::parse_compose_ls(&r.output(&c)?).map_err(SrvError::Parse)?;
                for c in &s.compose {
                    if !have.iter().any(|(name, _)| *name == c.name) {
                        p.push(format!(
                            "{n}: compose project `{}` isn't known to docker there",
                            c.name
                        ));
                    }
                }
            }
            Err(e) => p.push(format!("{n}: can't check compose projects: {e}")),
        }
    }
    Ok(p)
}

/// `collect <server> <kind>`: one collector's result as JSON.
pub fn collect(name: &str, kind: &str) -> u8 {
    let (n, s) = match load(Some(name)) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    match super::collect::collect_json(&Remote::new(&n, &s), kind) {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            0
        }
        Err(e @ (SrvError::NeedsSudo(_) | SrvError::SudoPassword(_) | SrvError::NotFound(_))) => {
            println!("{}", serde_json::json!({ "unavailable": e.to_string() }));
            3
        }
        Err(e) => {
            eprintln!("sentry-server collect {kind}: {e}");
            1
        }
    }
}

/// `audit <server>`: snapshot, findings, report on disk.
pub fn audit(name: Option<&str>) -> u8 {
    let (n, s) = match load(name) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    match super::audit::run(&Remote::new(&n, &s)) {
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
            eprintln!("sentry-server audit: {e}");
            1
        }
    }
}

/// `cond <server> <name> [--wait SECS]` (workflow verification steps call this).
pub fn cond(server: &str, name: &str, wait: Option<u64>) -> u8 {
    match load(Some(server)) {
        Ok((n, s)) => super::workflow::cond_cli(&Remote::new(&n, &s), name, wait),
        Err(e) => {
            eprintln!("{e}");
            2
        }
    }
}

/// `workflow list|lint [server]`: a server's workflows and whether they can start.
pub fn workflow(what: &str, server: Option<&str>) -> u8 {
    let name = match load(server) {
        Ok((n, _)) => n,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let entries = super::workflow::list_for(&name);
    let mut bad = 0;
    for e in &entries {
        let steps = e.wf.as_ref().map_or(0, |w| w.steps.len());
        match e.blocked() {
            None => println!("✓ {:<18} {steps:>2} steps", e.name),
            Some(why) => println!("✗ {:<18} {steps:>2} steps  {why}", e.name),
        }
        if what == "lint" {
            for i in &e.issues {
                println!("    {} {}", if i.error { "error" } else { "note " }, i.msg);
                bad += usize::from(i.error);
            }
        }
    }
    println!("({name}: {})", super::workflow::dir_for(&name).display());
    u8::from(bad > 0)
}

/// `maint [server] [--refresh]`: each maintenance item's standing. `--refresh` looks upstream
/// up again first (from this machine).
pub fn maint(server: Option<&str>, refresh: bool) -> u8 {
    use super::maint::{self, eval::Flag};
    let (n, s) = match load(server) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    if s.maintenance.items.is_empty() {
        println!("{n}: no maintenance: items in server_config.yaml");
        return 0;
    }
    let r = Remote::new(&n, &s).with_inventory();
    if refresh {
        eprintln!("looking up upstream versions…");
        maint::upstream::refresh(&n, &s);
    }
    let up_age = maint::upstream::load(&n).map(|c| c.age_secs(jiff::Timestamp::now()));
    let st = super::collect::maint_status(&r);
    println!(
        "{:<16} {:<6} {:<22} {:<22} {:<22} flags",
        "item", "risk", "pinned", "running", "latest"
    );
    let cut = |s: &Option<String>| -> String {
        let s = s.as_deref().unwrap_or("-");
        if s.chars().count() > 21 {
            format!("{}…", s.chars().take(20).collect::<String>())
        } else {
            s.to_string()
        }
    };
    for x in &st {
        let flags: Vec<&str> = x.flags.iter().map(|f| f.word()).collect();
        println!(
            "{:<16} {:<6} {:<22} {:<22} {:<22} {}",
            x.id,
            x.risk.as_str(),
            cut(&x.pinned),
            cut(&x.running),
            cut(&x.latest),
            flags.join(", ")
        );
        if let Some(note) = x
            .note
            .as_ref()
            .filter(|_| x.has(Flag::Unknown) || x.pinned.is_none())
        {
            println!("{:<16} {note}", "");
        }
    }
    match up_age {
        Some(a) => println!("(upstream looked up {})", crate::fmt::ago(a)),
        None => println!("(upstream not looked up yet: --refresh)"),
    }
    0
}

/// `exec <server> [--] <argv…>`: the read-only gateway Claude uses.
pub fn exec(server: &str, argv: &[String]) -> u8 {
    let argv: Vec<String> = match argv.first().map(String::as_str) {
        Some("--") => argv[1..].to_vec(),
        _ => argv.to_vec(),
    };
    match load(Some(server)) {
        Ok((n, s)) => super::gateway::exec_cli(&Remote::new(&n, &s), &argv),
        Err(e) => {
            eprintln!("{e}");
            2
        }
    }
}

/// `check [name]`: connection, sudo, tools, and that sudoers really allows each `sudo:` entry.
pub fn check(name: Option<&str>) -> u8 {
    let (n, s) = match load(name) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let r = Remote::new(&n, &s);
    let mut bad = 0;
    let t = Instant::now();
    match r.output(&r.sh(". /etc/os-release; echo \"$PRETTY_NAME · $(uname -r)\"")) {
        Ok(o) => println!(
            "✓ {n} ({}): {} · {} ms",
            r.host,
            o.trim(),
            t.elapsed().as_millis()
        ),
        Err(e) => {
            println!("✗ {n} ({}): {e}", r.host);
            return 1;
        }
    }
    let t = Instant::now();
    if r.cmd("true").output().is_ok() {
        println!(
            "✓ next command over the shared connection: {} ms",
            t.elapsed().as_millis()
        );
    }
    let mode = r.sudo_mode();
    match &mode {
        Ok(SudoMode::NoPasswd) => println!("✓ sudo -n: no password needed"),
        Ok(SudoMode::Password) => println!(
            "· sudo asks for a password: monitoring runs without root; maintenance hands you the terminal"
        ),
        Ok(SudoMode::Absent) => println!("· no sudo for this user"),
        Err(e) => {
            println!("✗ sudo: {e}");
            bad += 1;
        }
    }
    let tools = [
        "systemctl",
        "journalctl",
        "findmnt",
        "ss",
        "apt-get",
        "docker",
        "smartctl",
        "sensors",
        "nvidia-smi",
        "fail2ban-client",
    ];
    let script = tools
        .iter()
        .map(|t| format!("command -v {t} >/dev/null && echo {t}"))
        .collect::<Vec<_>>()
        .join("; ");
    if let Ok(o) = r.output(&r.sh(&format!("{}{script}; true", init::SBIN))) {
        let found: Vec<&str> = o.lines().collect();
        let missing: Vec<&str> = tools
            .iter()
            .copied()
            .filter(|t| !found.contains(t))
            .collect();
        println!("✓ tools: {}", found.join(" "));
        if !missing.is_empty() {
            println!(
                "· not installed (their panels stay empty): {}",
                missing.join(" ")
            );
        }
    }
    if mode == Ok(SudoMode::NoPasswd) {
        for entry in &s.sudo {
            // `sudo -l <cmd>` asks sudoers whether it may run, without running it.
            let words: Vec<&str> = entry.split_whitespace().collect();
            let ok = r
                .cmd("sudo")
                .args(["-n", "-l"])
                .args(words.iter().copied())
                .run()
                .is_ok_and(|o| o.code == 0);
            if ok {
                println!("✓ sudo: {entry}");
            } else {
                println!("✗ sudo: {entry} (sudoers doesn't allow it, or it isn't installed)");
                bad += 1;
            }
        }
    }
    for p in config::lint(&n, &s) {
        println!("✗ {p}");
        bad += 1;
    }
    u8::from(bad > 0)
}
