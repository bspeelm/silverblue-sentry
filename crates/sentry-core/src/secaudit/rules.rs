//! The audit's rules: pure, over every target's facts at once. A rule fires only on what a
//! target said; a missing section is `CouldNotCheck` with what it would take.

use std::collections::BTreeSet;

use jiff::civil::Date;

use super::rank::{EXPOSED, FLAT, OUTDATED, RECOVERY, WEAK_LOGIN};
use super::{
    Answers, Ctr, Eol, Family, FamilyTrouble, Forward, Group, Issuer, Item, Kind, Life, Router,
    Software, State, TargetFacts, Web,
};
use Group::{GettingIn, KnownHoles, Logins, MovingAround, Recovering};
use State::{Ask, CouldNotCheck, DoFirst, Fine, Worth};

#[derive(Default)]
struct Out {
    items: Vec<Item>,
}

/// One item's words.
struct Says<'a> {
    title: String,
    why: &'a str,
    fix: &'a str,
}

fn says<'a>(title: impl Into<String>, why: &'a str, fix: &'a str) -> Says<'a> {
    Says {
        title: title.into(),
        why,
        fix,
    }
}

/// A title only (what's fine needs no why).
fn fine(title: impl Into<String>) -> Says<'static> {
    says(title, "", "")
}

impl Out {
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        id: String,
        group: Group,
        state: State,
        rank: u8,
        s: Says,
        targets: &[&str],
        evidence: Vec<String>,
    ) -> &mut Item {
        // A title may start with this machine's name; a server's stays as the user wrote it.
        let mut title = s.title;
        if let Some(rest) = title.strip_prefix("this machine") {
            title = format!("This machine{rest}");
        }
        let mut brief = format!("Fix this finding of the security audit: {title}");
        if !s.fix.is_empty() {
            brief.push_str(&format!("\nWhat it takes: {}", s.fix));
        }
        brief.push_str(
            "\nCheck how it stands first, change only what this needs, and say how to undo it.",
        );
        self.items.push(Item {
            id,
            group,
            state,
            rank,
            title,
            why: s.why.to_string(),
            fix: s.fix.to_string(),
            targets: targets.iter().map(|t| t.to_string()).collect(),
            evidence,
            brief,
            question: None,
        });
        self.items.last_mut().expect("just pushed")
    }

    /// An item whose state is the user's answer: unanswered it's an `Ask`.
    #[allow(clippy::too_many_arguments)]
    fn asked(
        &mut self,
        id: String,
        group: Group,
        key: String,
        answers: &Answers,
        // (state, rank, words) for yes, for no, and the question.
        yes: (State, u8, Says),
        no: (State, u8, Says),
        question: Says,
        targets: &[&str],
        mut evidence: Vec<String>,
    ) {
        let said = answers.answers.get(&key);
        if let Some(a) = said {
            evidence.push(format!("you answered {} on {}", a.answer, a.at));
        }
        let (state, rank, s) = match said.map(|a| a.answer == "yes") {
            Some(true) => yes,
            Some(false) => no,
            None => (Ask, 0, question),
        };
        self.add(id, group, state, rank, s, targets, evidence)
            .question = Some(key);
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// What the doors lead to, for the rules after them.
#[derive(Default)]
struct Doors {
    any: bool,
    /// Hosts a door leads to.
    hosts: BTreeSet<String>,
    /// Their ports the internet is meant to reach.
    ports: BTreeSet<(String, u16)>,
    /// (host, container) behind a door.
    ctrs: BTreeSet<(String, String)>,
    /// (host, software id) a door's item already speaks of.
    software: BTreeSet<(String, String)>,
    /// Hosts whose ssh login is a door.
    ssh: BTreeSet<String>,
    /// (network, zone) a door leads into.
    zones: BTreeSet<(String, String)>,
}

/// What finishing a router's bouncer takes, as a session is briefed (one across the server
/// and the router) and as the report says it.
/// CrowdSec's bouncer installed on the router and switched off, in the one sentence the
/// audit, the network's Security page and its finding all say. `server`: a server's
/// CrowdSec bans attackers the router could turn away.
pub fn edge_off(server: bool) -> String {
    format!(
        "CrowdSec is installed on the router but switched off: {} aren't turned away there",
        if server {
            "attackers the server banned"
        } else {
            "known attackers"
        }
    )
}

pub const EDGE_FIX: &str = "Finish connecting the router's CrowdSec bouncer to the server's \
CrowdSec, in one plan across both: on the server, make CrowdSec's local API reachable from the \
router and from nothing else (it listens on loopback only: have it listen on the address the \
router reaches, and let only the router through the server's firewall on that port); create a \
bouncer key there (`cscli bouncers add`, captured as a secret); on the router set the bouncer's \
API address and that key (a guarded change), switch it on and start it; then check on the \
server that the bouncer pulls and on the router that its sets fill.";

/// More devices than this on one home network, with no other to put gadgets on, is worth
/// saying: a few computers and phones alone don't need splitting.
const HANDFUL: usize = 5;

fn version(sw: &Software) -> String {
    match (&sw.running, &sw.latest) {
        (Some(r), Some(l)) if sw.behind => format!("{}: running {r}, latest {l}", sw.id),
        (Some(r), _) => format!("{}: running {r}", sw.id),
        _ => format!("{}: version not known", sw.id),
    }
}

fn ctr_powers(c: &Ctr) -> Vec<&'static str> {
    let mut v = Vec::new();
    if c.privileged {
        v.push("runs privileged (full control of the server)");
    }
    if c.docker_sock {
        v.push("holds the Docker socket (controls every container)");
    }
    if c.host_network {
        v.push("shares the server's network");
    }
    v
}

/// How old what was read as root is, said where it was used.
fn inventory_age(hours: i64) -> String {
    let age = if hours < 1 {
        "less than an hour ago".to_string()
    } else if hours < 48 {
        format!("{} ago", plural(hours as usize, "hour", "hours"))
    } else {
        format!("{} ago", plural((hours / 24) as usize, "day", "days"))
    };
    if hours >= 72 {
        format!(
            "what runs there is from the server's inventory, read {age}: it may be out of \
             date (press I on the server target to read it again)"
        )
    } else {
        format!("what runs there is from the server's inventory, read {age}")
    }
}

/// `29 more days`.
fn more_days(d: i64) -> String {
    format!("{d} more day{}", if d == 1 { "" } else { "s" })
}

/// The certificate a door showed this machine, as an item of its own.
fn cert(n: &TargetFacts, f: &Forward, targets: &[&str], out: &mut Out) {
    let Some(t) = f.probe.as_ref().and_then(|a| a.tls.as_ref()) else {
        return;
    };
    let id = format!("sec:cert:{}:{}:{}", n.id, f.proto, f.port);
    let port = f.port.as_str();
    let mut ev = vec![format!("the certificate is {}", t.issuer.said())];
    if let Some(d) = t.days_left {
        ev.push(if d < 0 {
            format!("it expired {} ago", plural((-d) as usize, "day", "days"))
        } else {
            format!("it is good for {}", more_days(d))
        });
    }
    let fake = "Nobody can then tell your server from someone pretending to be it, and \
                people learn to click the warning away.";
    let (state, rank, s) = match (t.days_left, t.issuer) {
        (Some(d), _) if d < 0 => (
            DoFirst,
            WEAK_LOGIN,
            says(
                format!("The certificate the internet sees on port {port} has expired"),
                "Browsers and apps warn or refuse to connect. People learn to click the \
                 warning away, which is what someone posing as your server needs.",
                "Renew it, and have it renew by itself; a session with Claude can find what \
                 issues it.",
            ),
        ),
        (Some(d), _) if d < 14 => (
            Worth,
            0,
            says(
                format!(
                    "The certificate the internet sees on port {port} expires in {}",
                    plural(d as usize, "day", "days")
                ),
                "When it lapses, browsers and apps warn or refuse to connect.",
                "Make sure it renews by itself before then; a session with Claude can check.",
            ),
        ),
        (_, Issuer::SelfSigned) => (
            Worth,
            0,
            says(
                format!("Port {port} shows the internet a self-signed certificate"),
                fake,
                "Use a certificate from a public authority (Let's Encrypt is free and renews \
                 by itself).",
            ),
        ),
        (_, Issuer::Private) => (
            Worth,
            0,
            says(
                format!(
                    "Port {port} shows the internet a certificate from an authority browsers \
                     don't know"
                ),
                fake,
                "Use a certificate from a public authority (Let's Encrypt is free and renews \
                 by itself).",
            ),
        ),
        (d, i) => (
            Fine,
            0,
            fine(format!(
                "The certificate on port {port} is {}{}",
                i.said(),
                d.map_or(String::new(), |d| format!(" and good for {}", more_days(d)))
            )),
        ),
    };
    out.add(id, GettingIn, state, rank, s, targets, ev);
}

fn door(
    n: &TargetFacts,
    f: &Forward,
    hosts: &[&TargetFacts],
    answers: &Answers,
    doors: &mut Doors,
    out: &mut Out,
) {
    let id = format!("sec:door:{}:{}:{}", n.id, f.proto, f.port);
    let proto = f.proto.as_str();
    let port = f.port.as_str();
    doors.any = true;
    if let Some(z) = &f.zone {
        doors.zones.insert((n.id.clone(), z.clone()));
    }
    let Some(h) = hosts.iter().find(|t| t.addrs.contains(&f.dest)) else {
        out.add(
            id,
            GettingIn,
            CouldNotCheck,
            0,
            says(
                format!(
                    "The internet can reach {proto} port {port} on a device sentry doesn't manage"
                ),
                "sentry can't see what answers there, how old it is, or whether it asks for a \
                 login.",
                "If it is a machine of yours, add it to sentry as a server. If nothing should \
                 answer there, remove the forward on the router.",
            ),
            &[&n.id],
            vec![format!(
                "the router forwards {proto} {port} to an address no machine sentry manages has"
            )],
        );
        return;
    };
    doors.hosts.insert(h.id.clone());
    let mut ev = vec![format!(
        "the router forwards {proto} {port} to {} port {}",
        h.name, f.to_port
    )];
    let targets = [n.id.as_str(), h.id.as_str()];
    let (Some(listeners), Ok(to)) = (&h.listeners, f.to_port.parse::<u16>()) else {
        let (why, fix) = if h.listeners.is_none() {
            (
                "What listens there couldn't be read.",
                "Run the audit again (S) when the server answers.",
            )
        } else {
            (
                "It is a range of ports, which sentry doesn't follow one by one.",
                "Make sure each port of the range is meant to be open; a session with Claude \
                 can go through them.",
            )
        };
        out.add(
            id,
            GettingIn,
            CouldNotCheck,
            0,
            says(
                format!("The internet can reach {proto} port {port} on {}", h.name),
                why,
                fix,
            ),
            &targets,
            ev,
        );
        return;
    };
    doors.ports.insert((h.id.clone(), to));
    let Some(l) = listeners
        .iter()
        .find(|l| l.port == to && l.wide && l.proto == proto)
    else {
        out.add(
            id,
            GettingIn,
            Worth,
            0,
            says(
                format!(
                    "The router lets the internet in on {proto} port {port}, but nothing on {} \
                     answers there",
                    h.name
                ),
                "A door nobody uses is still a door: whatever starts listening there later is \
                 on the internet at once.",
                "Remove the forward on the router, or start what it was for.",
            ),
            &targets,
            ev,
        );
        return;
    };
    let ctr = h
        .containers
        .iter()
        .flatten()
        .find(|c| c.ports.contains(&to));
    let sw = ctr.and_then(|c| {
        h.software
            .iter()
            .flatten()
            .find(|s| s.container.as_deref() == Some(c.name.as_str()))
    });
    if let Some(p) = &l.process {
        ev.push(format!("answered by the program {p}"));
    }
    if let Some(c) = ctr {
        doors.ctrs.insert((h.id.clone(), c.name.clone()));
        ev.push(format!(
            "the container {} runs the image {}",
            c.name, c.image
        ));
        for p in ctr_powers(c) {
            ev.push(format!("that container {p}"));
        }
    }
    match sw {
        Some(s) => {
            doors.software.insert((h.id.clone(), s.id.clone()));
            ev.push(version(s));
            match s.eol {
                Eol::Past(d) => ev.push(format!("its support ended {d} days ago")),
                Eol::Soon(d) => ev.push(format!("its support ends in {d} days")),
                Eol::Supported => ev.push("its version is still supported".into()),
                Eol::Unknown => {}
            }
        }
        None if ctr.is_some() => ev.push(
            "sentry doesn't follow this app's updates: add it to the server's maintenance \
             items to know when it falls behind"
                .into(),
        ),
        None => {}
    }
    let what = sw
        .map(|s| match &s.running {
            Some(v) => format!("{} {v}", s.id),
            None => s.id.clone(),
        })
        .or(ctr.map(|c| c.name.clone()))
        .or(l.process.clone());
    if what.is_none() {
        ev.push(if h.containers.is_none() && h.kind == Kind::Server {
            "what answers there couldn't be named: open the server target and press I (it reads \
             what needs root), then run the audit again (S)"
                .into()
        } else {
            "what answers there couldn't be named".to_string()
        });
    }
    if let Some(hours) = h.inventory_hours.filter(|_| h.containers.is_some()) {
        ev.push(inventory_age(hours));
    }
    // `web 1.4 on myserver`, or the server alone when sentry can't tell what answers.
    let what = match what {
        Some(w) => format!("{w} on {}", h.name),
        None => h.name.clone(),
    };

    // ssh: its own question, and one sentry can read.
    if l.process.as_deref().is_some_and(|p| p.contains("sshd")) || (to == 22 && ctr.is_none()) {
        doors.ssh.insert(h.id.clone());
        let ssh = h.ssh.as_ref();
        if let Some(s) = ssh {
            ev.push(format!("ssh settings read from {}", s.source));
        }
        let (state, rank, s) = match ssh.and_then(|s| s.password) {
            Some(true) => (
                DoFirst,
                WEAK_LOGIN,
                says(
                    format!(
                        "Anyone on the internet can try passwords on {}'s ssh login",
                        h.name
                    ),
                    "Password guessing against ssh never stops, and it's automated. One weak or \
                     reused password is the whole server.",
                    "Log in with a key, then turn password logins off. Or stop forwarding ssh \
                     and reach the server through a VPN.",
                ),
            ),
            Some(false) => (
                Fine,
                0,
                fine(format!(
                    "{}'s ssh login is reachable from the internet, with keys only",
                    h.name
                )),
            ),
            None => (
                CouldNotCheck,
                0,
                says(
                    format!(
                        "{}'s ssh login is reachable from the internet; whether it takes \
                         passwords couldn't be read",
                        h.name
                    ),
                    "If it takes passwords, anyone can keep guessing them.",
                    "Add `sshd -T` to the server's `sudo:` list in server_config.yaml, press I \
                     on the server target, then run the audit again (S).",
                ),
            ),
        };
        out.add(id, GettingIn, state, rank, s, &targets, ev);
        return;
    }

    if let Some(a) = &f.probe {
        ev.push(format!(
            "asked once from this machine, without a login: {}",
            a.web.said()
        ));
    }
    cert(n, f, &targets, out);

    let eol = sw.is_some_and(|s| matches!(s.eol, Eol::Past(_)));
    if eol || sw.is_some_and(|s| s.security) {
        let how = if eol {
            "gets no security fixes any more"
        } else {
            "is missing security fixes that are already out"
        };
        out.add(
            id,
            GettingIn,
            DoFirst,
            EXPOSED,
            says(
                format!("{what} is open to the internet ({proto} port {port}) and {how}"),
                "Published holes in software the internet can reach are found and tried by \
                 automated attacks within days, sometimes hours.",
                "Update it now (its row on the server's Maintenance screen), or close the \
                 door on the router until it is.",
            ),
            &targets,
            ev,
        );
        return;
    }
    let behind = sw.is_some_and(|s| s.behind);
    let key = format!("door-login:{}:{proto}:{port}", n.id);
    // A login seen, and nothing answered otherwise: nothing to ask.
    if f.probe.as_ref().is_some_and(|a| a.web.asks_login()) && !answers.answers.contains_key(&key) {
        let (state, s) = if behind {
            (
                Worth,
                says(
                    format!(
                        "{what} is open to the internet ({proto} port {port}) and asks for a \
                         login, but is behind its latest version"
                    ),
                    "No security fix is known to be missing, but what the internet can reach \
                     is worth keeping current.",
                    "Update it from the server's Maintenance screen.",
                ),
            )
        } else {
            (
                Fine,
                fine(format!(
                    "{what} is open to the internet ({proto} port {port}) and asks for a login \
                     first{}",
                    if sw.is_some() {
                        "; it is up to date"
                    } else {
                        ""
                    }
                )),
            )
        };
        out.add(id, GettingIn, state, 0, s, &targets, ev);
        return;
    }
    let yes = if behind {
        (
            Worth,
            0,
            says(
                format!(
                    "{what} is open to the internet ({proto} port {port}) and behind its latest \
                     version"
                ),
                "No security fix is known to be missing, but what the internet can reach is \
                 worth keeping current.",
                "Update it from the server's Maintenance screen.",
            ),
        )
    } else {
        (
            Fine,
            0,
            fine(format!(
                "{what} is open to the internet on {proto} port {port} on purpose: public, or \
                 behind its own login"
            )),
        )
    };
    let open = f.probe.as_ref().is_some_and(|a| a.web == Web::Open);
    let question = if open {
        says(
            format!(
                "{what} answers the internet on {proto} port {port} without asking for a \
                 login. Is that on purpose: is all of it meant for anyone?"
            ),
            "Its front page is open to everyone. That is right for a public site, and wrong \
             for anything private.",
            "Answer yes if it is public on purpose, no if it isn't (then it needs a login in \
             front of it, or the door closed).",
        )
    } else {
        says(
            format!(
                "{what} is open to the internet on {proto} port {port}. Is everything it \
                 serves meant for anyone, or behind its own login?"
            ),
            "sentry can see the door; whether what is behind it is private, only you know.",
            "Answer yes or no. A second step at login (a code from your phone) is worth \
             having on anything private.",
        )
    };
    out.asked(
        id,
        GettingIn,
        key,
        answers,
        yes,
        (
            DoFirst,
            EXPOSED,
            says(
                format!(
                    "{what} is open to the internet on {proto} port {port}, and something it \
                     serves needs no login"
                ),
                "Anything there that isn't meant for everyone can be read or used by anyone \
                 who finds it, and scanners find every open port.",
                "Put a login in front of it (ideally with a second step), or close the door \
                 and reach it through a VPN.",
            ),
        ),
        question,
        &targets,
        ev,
    );
}

fn outside(n: &TargetFacts, r: &Router, out: &mut Out) {
    let Some(o) = &r.outside else { return };
    let id = format!("sec:outside:{}", n.id);
    if let Some(e) = &o.error {
        out.add(
            id,
            GettingIn,
            CouldNotCheck,
            0,
            says(
                "The check from outside didn't run",
                "Without it, what the internet can reach is read from the router's \
                 configuration only.",
                "Check the command in [audit] outside in config.toml (the README has two \
                 examples).",
            ),
            &[&n.id],
            vec![e.clone()],
        );
        return;
    }
    let forwarded: BTreeSet<u16> = r
        .forwards
        .iter()
        .flatten()
        .filter_map(|f| f.port.parse().ok())
        .collect();
    let ports = |v: &[u16]| v.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
    let mut ev = vec![
        format!("asked: {}", ports(&o.asked)),
        format!(
            "open: {}",
            if o.open.is_empty() {
                "none".into()
            } else {
                ports(&o.open)
            }
        ),
    ];
    let closed: Vec<u16> = forwarded
        .iter()
        .copied()
        .filter(|p| o.asked.contains(p) && !o.open.contains(p))
        .collect();
    if !closed.is_empty() {
        ev.push(format!(
            "forwarded but not answering from outside: {}",
            ports(&closed)
        ));
    }
    let extra: Vec<u16> = o
        .open
        .iter()
        .copied()
        .filter(|p| !forwarded.contains(p))
        .collect();
    for p in &extra {
        out.add(
            format!("{id}:tcp:{p}"),
            GettingIn,
            DoFirst,
            EXPOSED,
            says(
                format!(
                    "Seen from outside, port {p} on your address answers, and nothing in the \
                     router's configuration says it should"
                ),
                "Something is reachable from the internet that sentry can't account for: the \
                 router's own admin or ssh, your provider's equipment, or a rule it doesn't read.",
                "Find what answers there (a session with Claude can) and close it.",
            ),
            &[&n.id],
            ev.clone(),
        );
    }
    if extra.is_empty() {
        out.add(
            id,
            GettingIn,
            Fine,
            0,
            fine("Seen from outside, only the ports you forward answer"),
            &[&n.id],
            ev,
        );
    }
}

/// sentry's family filter: whether it is on and for how many devices; when it has
/// stopped working, one item of its own per way (the Security page's rows say the same).
fn family(f: &Family, id: &dyn Fn(&str) -> String, t: &[&str], out: &mut Out) {
    let devices = plural(f.devices, "device", "devices");
    let posture = if f.devices == 0 {
        fine("No device is in the family filter (a choice: the network's Security page offers it)")
    } else if f.trouble.is_none() {
        fine(format!(
            "The family filter (CleanBrowsing Family) is on for {devices}"
        ))
    } else {
        fine(format!(
            "The family filter is set up for {devices}, but has stopped working (below)"
        ))
    };
    out.add(id("family"), Recovering, Fine, 0, posture, t, vec![]);
    let Some(trouble) = f.trouble else {
        return;
    };
    let (what, s) = match trouble {
        FamilyTrouble::Forced => (
            "family-forced",
            says(
                "The family filter has stopped working: the router's own forced lookups are \
                 back in front of it",
                "The filtered devices' lookups go to the router like everyone's, so nothing \
                 is filtered for them.",
                "Put the filter back in front (the Security page's row does it, its plan first).",
            ),
        ),
        FamilyTrouble::Canaries => (
            "family-canaries",
            says(
                "A browser's own encrypted lookups are no longer switched off on this network",
                "Firefox's own encrypted lookups and iCloud Private Relay can switch on by \
                 themselves and skip the family filter and the router's blocklist.",
                "Put sentry's entries for those names back (the Security page's row does it, \
                 its plan first).",
            ),
        ),
        FamilyTrouble::Unforced => (
            "family-unforced",
            says(
                "Lookups aren't forced through the router for anyone",
                "Any device can ask another service and skip the family filter and the \
                 router's blocklist.",
                "Put sentry's rules for forcing lookups back (the Security page's row does it, \
                 its plan first).",
            ),
        ),
    };
    out.add(
        id(what),
        Recovering,
        DoFirst,
        0,
        s,
        t,
        vec![format!("the filter is set up for {devices}")],
    );
}

fn router(n: &TargetFacts, r: &Router, doors: &Doors, answers: &Answers, out: &mut Out) {
    let t = [n.id.as_str()];
    let name = n.name.as_str();
    let id = |what: &str| format!("sec:{what}:{}", n.id);

    // -- getting in
    if r.wan_input_accept == Some(true) {
        out.add(
            id("wan-input"),
            GettingIn,
            DoFirst,
            EXPOSED,
            says(
                "The router's firewall accepts whatever the internet sends to the router itself",
                "Its admin page, ssh and every other service on it are then on the internet.",
                "Set the router back to refusing what the internet sends it (the internet side's \
                 input: REJECT, its default).",
            ),
            &t,
            vec![],
        );
    }
    match &r.wan_listeners {
        None => {
            out.add(
                id("wan-mgmt"),
                GettingIn,
                CouldNotCheck,
                0,
                says(
                    "Whether the router's own admin page and ssh can be reached from the \
                     internet couldn't be read",
                    "Those two are the keys to the whole network.",
                    "Run the audit again when the router answers.",
                ),
                &t,
                vec![],
            );
        }
        Some(v) if v.is_empty() => {
            if r.wan_input_accept != Some(true) {
                out.add(
                    id("wan-mgmt"),
                    GettingIn,
                    Fine,
                    0,
                    fine("The router's own admin page and ssh can't be reached from the internet"),
                    &t,
                    vec![],
                );
            }
        }
        Some(v) => {
            for l in v {
                let p = l.process.as_deref().unwrap_or("");
                let what = if p.contains("dropbear") || p.contains("sshd") || l.port == 22 {
                    "ssh login".to_string()
                } else if p.contains("uhttpd") || p.contains("nginx") || [80, 443].contains(&l.port)
                {
                    "admin page".to_string()
                } else if p.is_empty() {
                    format!("service on port {}", l.port)
                } else {
                    format!("service {p}")
                };
                out.add(
                    format!("{}:{}:{}", id("wan-mgmt"), l.proto, l.port),
                    GettingIn,
                    DoFirst,
                    EXPOSED,
                    says(
                        format!("The router's own {what} can be reached from the internet"),
                        "Whoever gets into the router sees and can redirect everything at home.",
                        "Stop it answering on the internet side, or remove the firewall rule \
                         that lets it in; reach the router from home, or through a VPN (a private \
                         tunnel into your network).",
                    ),
                    &t,
                    vec![format!("{} port {} answers on the uplink", l.proto, l.port)],
                );
            }
        }
    }
    match &r.v6_inbound {
        Some(v) if !v.is_empty() => {
            out.add(
                id("v6-inbound"),
                GettingIn,
                Worth,
                0,
                says(
                    format!(
                        "{} the internet reach devices at home directly over IPv6",
                        if v.len() == 1 {
                            "1 firewall rule lets".to_string()
                        } else {
                            format!("{} firewall rules let", v.len())
                        }
                    ),
                    "With IPv6 every device has an address the internet could reach; only the \
                     firewall stands in between.",
                    "Keep the rules you use; remove the others on the router.",
                ),
                &t,
                v.clone(),
            );
        }
        Some(_) => {
            out.add(
                id("v6-inbound"),
                GettingIn,
                Fine,
                0,
                fine(
                    "Over IPv6, the firewall lets nothing from the internet reach devices at home",
                ),
                &t,
                vec![],
            );
        }
        None => {}
    }
    outside(n, r, out);

    // -- known holes
    match &r.firmware {
        None => {
            out.add(
                id("firmware"),
                KnownHoles,
                CouldNotCheck,
                0,
                says(
                    "How old the router's firmware is couldn't be read",
                    "The router is the one device every attack from outside meets first.",
                    "Run the audit again when the router answers.",
                ),
                &t,
                vec![],
            );
        }
        Some(f) => {
            let mut ev = vec![format!("installed: {}", f.version)];
            if let Some(l) = &f.latest {
                ev.push(format!("latest of its series: {l}"));
            }
            let (state, rank, s) = match (f.eol, f.newer, f.security) {
                (Eol::Past(d), _, _) => {
                    ev.push(format!("support ended {d} days ago"));
                    (
                        DoFirst,
                        OUTDATED,
                        says(
                            "The router's firmware is no longer supported: it gets no more security fixes",
                            "Holes found from now on stay open, on the device that faces the internet.",
                            "Upgrade to a supported release (back the configuration up first).",
                        ),
                    )
                }
                (_, true, Some(true)) => (
                    DoFirst,
                    OUTDATED,
                    says(
                        "A newer router firmware with security fixes is out",
                        "The router faces the internet; its published holes are tried by \
                         automated attacks.",
                        "Upgrade the firmware (back the configuration up first).",
                    ),
                ),
                (_, true, _) => (
                    Worth,
                    0,
                    says(
                        "A newer router firmware is out",
                        "Its notes don't speak of security fixes (or couldn't be read), but \
                         point releases usually carry some.",
                        "Upgrade the firmware when convenient (back the configuration up first).",
                    ),
                ),
                (Eol::Soon(d), _, _) => {
                    ev.push(format!("support ends in {d} days"));
                    (
                        Worth,
                        0,
                        says(
                            "The router's firmware series stops getting fixes soon",
                            "After that, new holes stay open.",
                            "Plan the upgrade to the next release.",
                        ),
                    )
                }
                (Eol::Unknown, false, _) if f.latest.is_none() => (
                    CouldNotCheck,
                    0,
                    says(
                        "Whether the router's firmware is current couldn't be looked up",
                        "A snapshot build, or the release list couldn't be fetched.",
                        "Press r on the network's Maintenance screen, then run the audit again.",
                    ),
                ),
                _ => (
                    Fine,
                    0,
                    fine(format!("The router's firmware is current ({})", f.version)),
                ),
            };
            out.add(id("firmware"), KnownHoles, state, rank, s, &t, ev);
        }
    }
    if let Some(p) = &r.packages {
        let (state, s, ev) = match p.index_days {
            None => (
                CouldNotCheck,
                says(
                    "The router has no package list, so sentry can't say which of its packages are behind",
                    "The list is kept in memory and is gone after a restart.",
                    "Press r on the network's Maintenance screen, then run the audit again.",
                ),
                vec![],
            ),
            Some(d) if d > 30 => (
                CouldNotCheck,
                says(
                    format!(
                        "The router's package list is {d} days old, too old to say what's behind"
                    ),
                    "Updates published since then aren't in it.",
                    "Press r on the network's Maintenance screen, then run the audit again.",
                ),
                vec![format!("{} behind as of that list", p.behind)],
            ),
            Some(d) if p.behind > 0 => (
                Worth,
                says(
                    format!(
                        "{} on the router {} behind",
                        plural(p.behind, "package", "packages"),
                        if p.behind == 1 { "is" } else { "are" }
                    ),
                    "Package updates between firmware releases are mostly fixes.",
                    "Update them from the network's Maintenance screen.",
                ),
                vec![format!("package list {d} days old")],
            ),
            Some(_) => (Fine, fine("The router's packages are up to date"), vec![]),
        };
        out.add(id("packages"), KnownHoles, state, 0, s, &t, ev);
    }

    // -- logins
    match r.ssh_password {
        Some(true) => {
            out.add(
                id("ssh-password"),
                Logins,
                Worth,
                0,
                says(
                    "The router accepts ssh logins with a password",
                    "Any device at home that gets broken into can keep guessing it; the \
                     router's login is root.",
                    "sentry already logs in with a key: turn password logins off.",
                ),
                &t,
                vec![],
            );
        }
        Some(false) => {
            out.add(
                id("ssh-password"),
                Logins,
                Fine,
                0,
                fine("The router's ssh login takes keys only"),
                &t,
                vec![],
            );
        }
        None => {}
    }
    match r.admin_http {
        Some(true) => {
            out.add(
                id("admin-http"),
                Logins,
                Worth,
                0,
                says(
                    "The router's admin page works over plain HTTP",
                    "Its password crosses the network unencrypted each time you log in; any \
                     device at home could read it.",
                    "Send HTTP to HTTPS (one setting of the router's web server).",
                ),
                &t,
                vec![],
            );
        }
        Some(false) => {
            out.add(
                id("admin-http"),
                Logins,
                Fine,
                0,
                fine("The router's admin page is HTTPS only"),
                &t,
                vec![],
            );
        }
        None => {}
    }
    if let Some(wifi) = &r.wifi {
        let mut weak = 0;
        for w in wifi {
            let enc = w.encryption.to_ascii_lowercase();
            let wid = format!(
                "{}:{}",
                id("wifi"),
                w.label.replace(' ', "-").to_ascii_lowercase()
            );
            let ev = vec![format!("{}: encryption {}", w.label, w.encryption)];
            if enc == "none" || enc.starts_with("wep") {
                weak += 1;
                let open = enc == "none";
                out.add(
                    wid,
                    Logins,
                    if w.guest { Worth } else { DoFirst },
                    WEAK_LOGIN,
                    says(
                        if open {
                            format!("{} has no password: anyone nearby can join", w.label)
                        } else {
                            format!("{} uses WEP, which can be broken in minutes", w.label)
                        },
                        "Whoever joins is inside your network, past the router's firewall.",
                        "Set it to WPA2 or WPA3 with a long passphrase.",
                    ),
                    &t,
                    ev,
                );
            } else if enc.contains("tkip")
                || enc == "psk"
                || enc.starts_with("psk+")
                || enc.starts_with("psk-mixed")
            {
                weak += 1;
                out.add(
                    wid,
                    Logins,
                    Worth,
                    0,
                    says(
                        format!("{} still allows the old WPA protection", w.label),
                        "The first WPA has known weaknesses; WPA2 and WPA3 don't share them.",
                        "Set it to WPA2 (psk2) or WPA2/WPA3 mixed; very old devices may need replacing.",
                    ),
                    &t,
                    ev,
                );
            }
        }
        if weak == 0 && !wifi.is_empty() {
            out.add(
                id("wifi"),
                Logins,
                Fine,
                0,
                fine(format!(
                    "Wi-Fi uses WPA2 or WPA3 on {}",
                    if wifi.len() == 1 {
                        "its one network".to_string()
                    } else if wifi.len() == 2 {
                        "both networks".to_string()
                    } else {
                        format!("all {} networks", wifi.len())
                    }
                )),
                &t,
                wifi.iter()
                    .map(|w| format!("{}: {}", w.label, w.encryption))
                    .collect(),
            );
        }
        let wps: Vec<String> = wifi
            .iter()
            .filter(|w| w.wps)
            .map(|w| w.label.clone())
            .collect();
        if !wps.is_empty() {
            out.add(
                id("wps"),
                Logins,
                Worth,
                0,
                says(
                    "The Wi-Fi's push-button pairing (WPS) is on",
                    "It is a second way in that skips the passphrase, and has had flaws.",
                    "Turn WPS off; join new devices with the passphrase.",
                ),
                &t,
                wps,
            );
        }
    }

    // -- moving around
    if let Some(zones) = &r.zones {
        let inside: Vec<_> = zones.iter().filter(|z| !z.wan).collect();
        let guest = r.wifi.iter().flatten().any(|w| w.guest);
        let devices = r.devices.as_ref().map(|d| d.total);
        // The home side: the zones that aren't a server's (where a door leads). A side
        // kept for a server doesn't split the devices at home from each other.
        let door = |z: &&&super::Zone| doors.zones.contains(&(n.id.clone(), z.name.clone()));
        let mut home: Vec<&&super::Zone> = inside.iter().filter(|z| !door(z)).collect();
        if home.is_empty() {
            home = inside.iter().collect();
        }
        let kept: Vec<&str> = inside
            .iter()
            .filter(|z| door(z) && inside.len() > home.len())
            .map(|z| z.name.as_str())
            .collect();
        // More than a handful on the one home network: which of them are gadgets isn't
        // guessed, only that they all reach each other.
        let crowded = home.len() == 1 && home[0].devices.is_some_and(|d| d > HANDFUL);
        if (inside.len() <= 1 || crowded) && !guest {
            let mut ev: Vec<String> = match (home.first().and_then(|z| z.devices), devices) {
                (Some(d), _) if crowded => vec![format!("{d} devices on {}", home[0].name)],
                (_, Some(n)) => vec![format!("{n} devices seen on it")],
                _ => Vec::new(),
            };
            // What is known of them without guessing what they are.
            if let Some(z) = home.first().filter(|_| crowded) {
                if let (Some(d), Some(named)) = (z.devices, z.named) {
                    ev.push(format!(
                        "{named} of them named in sentry, {} not",
                        d.saturating_sub(named)
                    ));
                }
                if let (Some(c), Some(w)) = (z.wired, z.wifi) {
                    ev.push(format!("{c} on a cable, {w} on Wi-Fi"));
                }
            }
            if !kept.is_empty() {
                ev.push(format!(
                    "only the server's side is separate ({})",
                    kept.join(", ")
                ));
            }
            ev.push("no guest or gadgets network".into());
            let radios = r.wifi.as_ref().is_some_and(|w| !w.is_empty());
            out.add(
                id("flat"),
                MovingAround,
                Worth,
                FLAT,
                says(
                    "Every device at home shares one network, so one broken-into gadget can \
                     reach your computers",
                    "A TV, camera or smart-home gadget that gets broken into can talk to \
                     every computer and phone beside it. sentry can't tell which devices are \
                     gadgets, only that nothing keeps any of them apart.",
                    if radios {
                        "A separate network for gadgets and guests, with its own Wi-Fi name, \
                         that the router keeps apart from your computers; this router has \
                         Wi-Fi, so it can run that network itself. Then move the gadgets onto it."
                    } else {
                        "A separate network for gadgets and guests, that the router keeps \
                         apart from your computers. Then move the gadgets onto it."
                    },
                ),
                &t,
                ev,
            );
        } else {
            out.add(
                id("flat"),
                MovingAround,
                Fine,
                0,
                fine(format!(
                    "The network is split into {} parts ({})",
                    inside.len().max(2),
                    inside
                        .iter()
                        .map(|z| z.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
                &t,
                vec![],
            );
        }
        for z in inside
            .iter()
            .filter(|z| doors.zones.contains(&(n.id.clone(), z.name.clone())))
        {
            let others: Vec<&str> = z
                .reaches
                .iter()
                .filter(|y| inside.iter().any(|i| &i.name == *y))
                .map(String::as_str)
                .collect();
            let zid = format!("{}:{}", id("apart"), z.name);
            if !others.is_empty() {
                out.add(
                    zid,
                    MovingAround,
                    DoFirst,
                    FLAT,
                    says(
                        format!(
                            "What the internet can reach (the {} network) is allowed to open \
                             connections into {}",
                            z.name,
                            others.join(", ")
                        ),
                        "If the server there is broken into, the attacker is one step from \
                         every device on those networks.",
                        "Remove that forwarding on the router; allow only the single ports \
                         it really needs.",
                    ),
                    &t,
                    vec![format!(
                        "firewall forwarding {} → {}",
                        z.name,
                        others.join(", ")
                    )],
                );
            } else if inside.len() == 1 {
                out.add(
                    zid,
                    MovingAround,
                    Worth,
                    FLAT,
                    says(
                        "What the internet can reach sits on the same network as everything else",
                        "If it is broken into, the attacker is on your home network.",
                        "Give it a network of its own (a DMZ) that can't open connections \
                         into the others.",
                    ),
                    &t,
                    vec![],
                );
            } else {
                let mut ev = vec![];
                let mut s = fine(format!(
                    "What the internet can reach (the {} network) is kept apart from the rest \
                     by the firewall",
                    z.name
                ));
                let mut state = Fine;
                if z.input == "ACCEPT" {
                    state = Worth;
                    ev.push(format!("zone {} input: ACCEPT", z.name));
                    s = says(
                        format!(
                            "Devices on the {} network can reach the router's own admin page and ssh",
                            z.name
                        ),
                        "A server the internet can reach shouldn't also be able to try the \
                         router's logins.",
                        "Make the router refuse that network's connections to itself, except \
                         the two it needs (handing out addresses and name lookups: DHCP and DNS).",
                    );
                }
                out.add(zid, MovingAround, state, 0, s, &t, ev);
            }
        }
    }
    match &r.crossings {
        Some(v) if !v.is_empty() => {
            for c in v {
                let from_door = doors.zones.contains(&(n.id.clone(), c.from.clone()));
                out.add(
                    format!("{}:{}:{}", id("crossing"), c.from, c.to),
                    MovingAround,
                    if from_door { DoFirst } else { Worth },
                    FLAT,
                    says(
                        format!(
                            "Right now, {} from the {} network into {}, which the firewall \
                             is meant to keep apart",
                            if c.flows == 1 {
                                "1 connection goes".to_string()
                            } else {
                                format!("{} connections go", c.flows)
                            },
                            c.from,
                            c.to
                        ),
                        "Either a rule lets more through than intended, or something there \
                         is reaching where it shouldn't.",
                        "Look at them on the network's Security screen; a session with \
                         Claude can find the rule.",
                    ),
                    &t,
                    vec![],
                );
            }
        }
        Some(_) => {
            out.add(
                id("crossing"),
                MovingAround,
                Fine,
                0,
                fine(
                    "No connection was crossing between parts of the network kept apart (at \
                     the moment of the audit)",
                ),
                &t,
                vec![],
            );
        }
        None => {}
    }
    if let Some(d) = &r.devices {
        if d.unknown > 0 {
            out.add(
                id("unknown-devices"),
                MovingAround,
                Worth,
                0,
                says(
                    format!(
                        "{} on the network {} no name in sentry's config",
                        plural(d.unknown, "device", "devices"),
                        if d.unknown == 1 { "has" } else { "have" }
                    ),
                    "You can only notice a stranger when you know who belongs.",
                    "Name each one on the network's Clients screen (or find out what it is).",
                ),
                &t,
                vec![format!("{} devices seen in all", d.total)],
            );
        } else {
            out.add(
                id("unknown-devices"),
                MovingAround,
                Fine,
                0,
                fine(format!(
                    "All {} devices on the network are ones you named",
                    d.total
                )),
                &t,
                vec![],
            );
        }
    }

    // -- noticing and recovering
    if let Some(f) = &r.dns_filter {
        let (state, s) = match (f.on, f.age_days) {
            (false, _) => (
                Worth,
                says(
                    "The router's DNS blocklist is installed but off",
                    "It stops devices reaching known malware and tracking names.",
                    "Turn it on.",
                ),
            ),
            (true, Some(d)) if d > 14 => (
                Worth,
                says(
                    format!("The router's DNS blocklist is {d} days old"),
                    "New malicious names appear daily; an old list misses them.",
                    "Refresh it and turn its automatic updates on.",
                ),
            ),
            (true, _) => (
                Fine,
                fine("The router blocks known bad names (DNS blocklist on and fresh)"),
            ),
        };
        out.add(id("dns-filter"), Recovering, state, 0, s, &t, vec![]);
    }
    if let Some(f) = &r.family {
        family(f, &id, &t, out);
    }
    if r.log_kept == Some(false) {
        out.add(
            id("logs"),
            Recovering,
            Worth,
            0,
            says(
                "The router forgets its log when it restarts",
                "After a break-in, the log is how you find out what happened; an attacker \
                 only has to restart the router.",
                "Have it send its log to the server, or keep it on storage that survives a \
                 restart (a USB stick).",
            ),
            &t,
            vec!["the log is kept in memory only".into()],
        );
    }
    if let Some(b) = &n.backup {
        let bid = id("backup");
        let (state, s) = match (b.count, b.unsaved, b.newest_days) {
            (Some(0), _, _) => (
                Worth,
                says(
                    format!("There is no backup of {name}'s router configuration"),
                    "If the router dies or has to be reset after a break-in, everything is \
                     set up again from memory.",
                    "Run config-backup on the network's Upgrade screen (set backup.recipients first).",
                ),
            ),
            (_, Some(true), _) => (
                Worth,
                says(
                    "The router's configuration has changes that are in no backup",
                    "A restore would bring back the old settings.",
                    "Run config-backup on the network's Upgrade screen.",
                ),
            ),
            (_, _, Some(d)) if d > 90 => (
                Worth,
                says(
                    format!("The newest backup of the router's configuration is {d} days old"),
                    "It was compared by its files; still, an old backup is easy to lose track of.",
                    "Run config-backup on the network's Upgrade screen.",
                ),
            ),
            (Some(_), _, _) => (
                Fine,
                fine(
                    "The router's configuration is backed up, encrypted, and matches the newest backup",
                ),
            ),
            (None, _, _) => (
                CouldNotCheck,
                says(
                    "Whether the router's configuration is backed up couldn't be read",
                    "",
                    "Run the audit again when the router answers.",
                ),
            ),
        };
        let has = b.count.is_some_and(|c| c > 0);
        out.add(bid, Recovering, state, RECOVERY, s, &t, vec![]);
        if has {
            restore_ask(n, answers, out);
        }
    }
}

fn restore_ask(t: &TargetFacts, answers: &Answers, out: &mut Out) {
    let name = &if t.kind == Kind::Network {
        "the router's configuration".to_string()
    } else {
        t.name.clone()
    };
    out.asked(
        format!("sec:restore:{}", t.id),
        Recovering,
        format!("restore-tested:{}", t.id),
        answers,
        (
            Fine,
            0,
            fine(format!(
                "You have restored from the backup of {name} at least once"
            )),
        ),
        (
            Worth,
            RECOVERY,
            says(
                format!("The backup of {name} has never been restored to check it works"),
                "A backup that can't be restored is found out on the worst day.",
                "Restore it once somewhere harmless (for the router: decrypt it and look inside).",
            ),
        ),
        says(
            format!("Have you ever restored from the backup of {name} to check it works?"),
            "sentry can see that a backup exists, not that it can be used.",
            "Answer yes or no.",
        ),
        &[&t.id],
        vec![],
    );
}

/// When a machine's operating system release stops getting security fixes. A server the
/// internet reaches weighs most; this machine, which nothing reaches from outside, least.
fn os_life(h: &TargetFacts, life: &Life, exposed: bool, today: Date, out: &mut Out) {
    let t = [h.id.as_str()];
    let name = h.name.as_str();
    let id = format!("sec:os-life:{}", h.id);
    let rel = life.release.as_str();
    if let Some(e) = &life.error {
        out.add(
            id,
            KnownHoles,
            CouldNotCheck,
            0,
            says(
                format!("When {name}'s system stops getting security fixes couldn't be looked up"),
                "",
                "sentry looks it up on endoflife.date from this machine; it tries again at the \
                 next audit (S).",
            ),
            &t,
            vec![e.clone()],
        );
        return;
    }
    let Some(ends) = life.ends else {
        out.add(
            id,
            KnownHoles,
            Fine,
            0,
            fine(format!(
                "{name}'s system ({rel}) has no end of security fixes announced"
            )),
            &t,
            vec![],
        );
        return;
    };
    let days = (ends - today).get_days() as i64;
    let ev = vec![format!(
        "{rel}: security fixes until {ends}, says endoflife.date"
    )];
    let soon = if h.kind == Kind::Local { 60 } else { 182 };
    let (state, rank, s) = if days < 0 {
        (
            if exposed && h.kind == Kind::Server {
                DoFirst
            } else {
                Worth
            },
            OUTDATED,
            says(
                format!("{name}'s system ({rel}) no longer gets security fixes"),
                if exposed {
                    "Every hole found in it since its support ended stays open, on a machine \
                     the internet can reach."
                } else {
                    "Every hole found in it since its support ended stays open."
                },
                "Upgrade to a supported release (with a backup first); a session with Claude \
                 can plan it.",
            ),
        )
    } else if days <= soon {
        (
            Worth,
            0,
            says(
                format!(
                    "{name}'s system ({rel}) stops getting security fixes in {}",
                    plural(days as usize, "day", "days")
                ),
                "After that, holes found in it stay open.",
                "Plan the move to the next release before then.",
            ),
        )
    } else {
        (
            Fine,
            0,
            fine(format!(
                "{name}'s system ({rel}) gets security fixes until {ends}"
            )),
        )
    };
    out.add(id, KnownHoles, state, rank, s, &t, ev);
}

/// How long a server keeps its system log.
fn logs(h: &TargetFacts, out: &mut Out) {
    let t = [h.id.as_str()];
    let name = h.name.as_str();
    let id = format!("sec:logs:{}", h.id);
    let why = "After a break-in, the log is how you find out what happened.";
    let unread = |out: &mut Out| {
        out.add(
            id.clone(),
            Recovering,
            CouldNotCheck,
            0,
            says(
                format!("How long {name} keeps its system log couldn't be read"),
                why,
                if h.needs_inventory {
                    "Open the server target and press I once (it reads what needs root), then \
                     run the audit again (S)."
                } else {
                    "In server_config.yaml, add `journalctl` to the server's `sudo:` list \
                     (sentry's own read-only reads), press I on the server target, then run the \
                     audit again (S)."
                },
            ),
            &t,
            vec![],
        );
    };
    let Some(l) = &h.logs else {
        unread(out);
        return;
    };
    let ev: Vec<String> = l
        .limit
        .iter()
        .map(|x| format!("its log settings say {x}"))
        .collect();
    match (l.kept, l.days) {
        (Some(false), _) => {
            out.add(
                id,
                Recovering,
                Worth,
                0,
                says(
                    format!("{name} forgets its system log when it restarts"),
                    "After a break-in, the log is how you find out what happened; an attacker \
                     only has to restart the server.",
                    "Keep the log on disk (journald's Storage=persistent); a session with \
                     Claude can.",
                ),
                &t,
                ev,
            );
        }
        (_, Some(d)) if d < 14 => {
            out.add(
                id,
                Recovering,
                Worth,
                0,
                says(
                    format!(
                        "{name}'s system log goes back only {}",
                        plural(d as usize, "day", "days")
                    ),
                    "A break-in is often found weeks later, when its traces are gone.",
                    "Keep more of it (journald's size and age limits); a session with Claude \
                     can.",
                ),
                &t,
                ev,
            );
        }
        (_, Some(d)) => {
            out.add(
                id,
                Recovering,
                Fine,
                0,
                fine(format!(
                    "{name} keeps its system log, going back {}",
                    plural(d as usize, "day", "days")
                )),
                &t,
                ev,
            );
        }
        (Some(true), None) => {
            let mut ev = ev;
            ev.push(
                "how far back it goes needs root to read (press I on the server target)".into(),
            );
            out.add(
                id,
                Recovering,
                Fine,
                0,
                fine(format!("{name} keeps its system log across restarts")),
                &t,
                ev,
            );
        }
        (None, None) => unread(out),
    }
}

fn host(h: &TargetFacts, doors: &Doors, answers: &Answers, today: Date, out: &mut Out) {
    let t = [h.id.as_str()];
    let name = h.name.as_str();
    let exposed = doors.hosts.contains(&h.id);
    let id = |what: &str| format!("sec:{what}:{}", h.id);

    // -- known holes
    match &h.os {
        None => {
            out.add(
                id("os"),
                KnownHoles,
                CouldNotCheck,
                0,
                says(
                    format!("Whether {name}'s system is up to date couldn't be read"),
                    "",
                    "Run the audit again when it answers.",
                ),
                &t,
                vec![],
            );
        }
        Some(os) => {
            let mut ev = vec![os.name.clone()];
            ev.extend(os.detail.iter().cloned());
            if let Some(d) = os.updated_days {
                ev.push(format!(
                    "last update run {} ago",
                    plural(d as usize, "day", "days")
                ));
            }
            let sec = os.security.unwrap_or(0);
            let (state, rank, s) = if let Eol::Past(d) = os.eol {
                ev.push(format!("support ended {d} days ago"));
                (
                    DoFirst,
                    OUTDATED,
                    says(
                        format!("{name}'s operating system is no longer supported"),
                        "It gets no more security fixes; every hole found from now on stays open.",
                        "Upgrade to a supported release.",
                    ),
                )
            } else if sec > 0 {
                (
                    if exposed { DoFirst } else { Worth },
                    OUTDATED,
                    says(
                        format!(
                            "{} waiting on {name}",
                            if sec == 1 {
                                "1 security update is".to_string()
                            } else {
                                format!("{sec} security updates are")
                            }
                        ),
                        if exposed {
                            "The internet can reach this machine; published holes are tried \
                             by automated attacks."
                        } else {
                            "Fixes for known holes that aren't installed yet."
                        },
                        "Run its update from the Maintenance screen.",
                    ),
                )
            } else if os.updates.is_some_and(|n| n > 0) {
                (
                    Worth,
                    0,
                    says(
                        format!(
                            "{} waiting on {name}",
                            plural(os.updates.unwrap_or(0) as usize, "update is", "updates are")
                        ),
                        "None is marked as a security fix, but updates are how fixes arrive.",
                        "Run its update from the Maintenance screen.",
                    ),
                )
            } else if os.updates.is_none() && os.updated_days.is_some_and(|d| d > 45) {
                (
                    Worth,
                    0,
                    says(
                        format!(
                            "{name} hasn't been updated in {} days",
                            os.updated_days.unwrap_or(0)
                        ),
                        "Whether updates are waiting isn't known, but that is a long time \
                         between fixes.",
                        "Check for updates on its Maintenance screen.",
                    ),
                )
            } else if os.updates.is_none() && os.updated_days.is_none() {
                (
                    CouldNotCheck,
                    0,
                    says(
                        format!("Whether updates are waiting on {name} couldn't be read"),
                        "",
                        "Check for updates on its Maintenance screen, then run the audit again.",
                    ),
                )
            } else {
                (
                    Fine,
                    0,
                    fine(match (os.updates, os.updated_days) {
                        (None, Some(d)) => format!(
                            "{name}'s system was updated {} ago",
                            plural(d as usize, "day", "days")
                        ),
                        _ => format!("{name}'s system is up to date"),
                    }),
                )
            };
            out.add(id("os"), KnownHoles, state, rank, s, &t, ev);
            if os.reboot_pending {
                out.add(
                    id("reboot"),
                    KnownHoles,
                    Worth,
                    0,
                    says(
                        format!("{name} needs a restart to finish an update"),
                        "Until then the old code, without the fix, is what's running.",
                        "Restart it when convenient.",
                    ),
                    &t,
                    vec![],
                );
            }
            match (os.auto_updates, h.kind) {
                (Some(false), _) => {
                    out.add(
                        id("auto-updates"),
                        KnownHoles,
                        Worth,
                        0,
                        says(
                            format!("{name} doesn't install security updates by itself"),
                            "Fixes wait until you run the update; attacks on new holes don't.",
                            "Turn on automatic security updates (unattended-upgrades).",
                        ),
                        &t,
                        vec![],
                    );
                }
                (Some(true), _) => {
                    out.add(
                        id("auto-updates"),
                        KnownHoles,
                        Fine,
                        0,
                        fine(format!("{name} installs security updates by itself")),
                        &t,
                        vec![],
                    );
                }
                (None, Kind::Server) => {
                    out.add(
                        id("auto-updates"),
                        KnownHoles,
                        CouldNotCheck,
                        0,
                        says(
                            format!(
                                "Whether {name} installs security updates by itself couldn't be read"
                            ),
                            "",
                            "sentry reads apt's settings for this; another system isn't covered yet.",
                        ),
                        &t,
                        vec![],
                    );
                }
                _ => {}
            }
        }
    }
    if let Some(life) = h.os.as_ref().and_then(|o| o.life.as_ref()) {
        os_life(h, life, exposed, today, out);
    }
    if let Some(sw) = &h.software {
        let rest: Vec<&Software> = sw
            .iter()
            .filter(|s| !doors.software.contains(&(h.id.clone(), s.id.clone())))
            .collect();
        let mut behind = Vec::new();
        for s in rest {
            let sid = format!("sec:app:{}:{}", h.id, s.id);
            if let Eol::Past(d) = s.eol {
                out.add(
                    sid,
                    KnownHoles,
                    Worth,
                    OUTDATED,
                    says(
                        format!("{} on {name} is no longer supported", s.id),
                        "It gets no more security fixes. The internet can't reach it directly as far \
                         as sentry sees.",
                        "Move to a supported version (its row on the Maintenance screen).",
                    ),
                    &t,
                    vec![version(s), format!("support ended {d} days ago")],
                );
            } else if s.security {
                out.add(
                    sid,
                    KnownHoles,
                    Worth,
                    OUTDATED,
                    says(
                        format!("{} on {name} is missing security fixes that are out", s.id),
                        "The internet can't reach it directly as far as sentry sees, but \
                         something that gets inside can.",
                        "Update it from the Maintenance screen.",
                    ),
                    &t,
                    vec![version(s)],
                );
            } else if s.behind {
                behind.push(version(s));
            }
        }
        if !behind.is_empty() {
            out.add(
                id("apps-behind"),
                KnownHoles,
                Worth,
                0,
                says(
                    format!(
                        "{} on {name} {} behind the latest version",
                        plural(behind.len(), "tracked app", "tracked apps"),
                        if behind.len() == 1 { "is" } else { "are" }
                    ),
                    "No security fix is known to be missing; staying close makes the next \
                     urgent update a small one.",
                    "Update them from the Maintenance screen.",
                ),
                &t,
                behind,
            );
        } else if !sw.is_empty()
            && !sw
                .iter()
                .any(|s| s.security || matches!(s.eol, Eol::Past(_)))
        {
            // Current only where the newest version was looked up.
            let unknown = sw.iter().filter(|s| s.latest.is_none()).count();
            if unknown == sw.len() {
                out.add(
                    id("apps-behind"),
                    KnownHoles,
                    CouldNotCheck,
                    0,
                    says(
                        format!(
                            "Whether the tracked apps on {name} are current couldn't be looked up"
                        ),
                        "",
                        "Press r on the server's Maintenance screen (it looks up what is newer), \
                         then run the audit again (S).",
                    ),
                    &t,
                    vec![],
                );
            } else {
                out.add(
                    id("apps-behind"),
                    KnownHoles,
                    Fine,
                    0,
                    fine(format!(
                        "The {} on {name} are current",
                        plural(sw.len() - unknown, "tracked app", "tracked apps")
                    )),
                    &t,
                    (unknown > 0)
                        .then(|| format!("{unknown} more couldn't be looked up"))
                        .into_iter()
                        .collect(),
                );
            }
        }
    }

    // -- logins
    if !doors.ssh.contains(&h.id) {
        match &h.ssh {
            Some(s) if s.on == Some(false) => {
                out.add(
                    id("ssh-password"),
                    Logins,
                    Fine,
                    0,
                    fine(format!(
                        "{name} accepts no ssh logins (its ssh server is off)"
                    )),
                    &t,
                    vec![],
                );
            }
            Some(s) => {
                let ev = vec![format!("read from {}", s.source)];
                match s.password {
                    Some(true) => {
                        out.add(
                            id("ssh-password"),
                            Logins,
                            Worth,
                            WEAK_LOGIN,
                            says(
                                format!("{name} accepts ssh logins with a password"),
                                "A password can be guessed, reused or phished; any device on \
                                 its network can keep trying.",
                                "Log in with a key, then set PasswordAuthentication no.",
                            ),
                            &t,
                            ev,
                        );
                    }
                    Some(false) => {
                        out.add(
                            id("ssh-password"),
                            Logins,
                            Fine,
                            0,
                            fine(format!("{name}'s ssh login takes keys only")),
                            &t,
                            ev,
                        );
                    }
                    None => {
                        out.add(
                            id("ssh-password"),
                            Logins,
                            CouldNotCheck,
                            0,
                            says(
                                format!(
                                    "Whether {name}'s ssh login takes passwords couldn't be read"
                                ),
                                "Its ssh server is on and its settings need root to read.",
                                "For a server: add `sshd -T` to its `sudo:` list in \
                                 server_config.yaml, press I on the server target, then run \
                                 the audit again (S). On this machine: ask Claude from \
                                 Maintenance (A) to check it; sentry asks for the sudo \
                                 password there.",
                            ),
                            &t,
                            vec![],
                        );
                    }
                }
            }
            None => {}
        }
    }
    if let Some(s) = &h.ssh
        && s.on != Some(false)
        && s.root.as_deref() == Some("yes")
    {
        out.add(
            id("ssh-root"),
            Logins,
            Worth,
            0,
            says(
                format!("{name} lets root itself log in over ssh with a password"),
                "The one account every attacker tries, with no second step.",
                "Stop root logging in with a password (PermitRootLogin no, or \
                 prohibit-password).",
            ),
            &t,
            vec![],
        );
    }
    match h.sudo_nopasswd {
        Some(true) => {
            out.add(
                id("sudo"),
                Logins,
                Worth,
                0,
                says(
                    format!("On {name}, your login can do anything as root without a password"),
                    "Whoever gets into your account there (a stolen key, a broken app running \
                     as you) owns the whole machine at once.",
                    "Make sudo ask for a password, or limit it to the commands that need none.",
                ),
                &t,
                vec![],
            );
        }
        Some(false) => {
            out.add(
                id("sudo"),
                Logins,
                Fine,
                0,
                fine(format!("On {name}, becoming root takes a password")),
                &t,
                vec![],
            );
        }
        None => {}
    }
    if let Some(k) = &h.keys {
        if k.loose > 0 {
            out.add(
                id("keys"),
                Logins,
                Worth,
                0,
                says(
                    format!(
                        "{} on {name} can be read by other users of the machine",
                        plural(k.loose, "private ssh key", "private ssh keys")
                    ),
                    "A key is a login; whoever copies it is you on every server it opens.",
                    "Make the key files readable by you alone; a session with Claude can.",
                ),
                &t,
                vec![],
            );
        } else if k.total > 0 {
            out.add(
                id("keys"),
                Logins,
                Fine,
                0,
                fine(format!(
                    "The private ssh keys on {name} are readable only by you"
                )),
                &t,
                vec![],
            );
        }
    }

    // -- moving around
    match (&h.containers, h.kind) {
        (Some(cs), _) => {
            let mut any = false;
            for c in cs {
                let p = ctr_powers(c);
                if p.is_empty() {
                    continue;
                }
                any = true;
                let behind_door = doors.ctrs.contains(&(h.id.clone(), c.name.clone()));
                let grave = c.privileged || c.docker_sock;
                out.add(
                    format!("sec:ctr:{}:{}", h.id, c.name),
                    MovingAround,
                    if behind_door && grave { DoFirst } else { Worth },
                    FLAT,
                    says(
                        format!(
                            "The container {} on {name} {}{}",
                            c.name,
                            p[0],
                            if behind_door {
                                ", and the internet can reach it"
                            } else {
                                ""
                            }
                        ),
                        "A container is meant to be a box: with this, breaking into the app \
                         inside is breaking into the server.",
                        "Take that away if the app works without it (many do); for the \
                         Docker socket, give it a read-only stand-in (a socket proxy).",
                    ),
                    &t,
                    p.iter()
                        .map(|s| s.to_string())
                        .chain([format!("image {}", c.image)])
                        .collect(),
                );
            }
            if !any && !cs.is_empty() {
                out.add(
                    id("ctrs"),
                    MovingAround,
                    Fine,
                    0,
                    fine(format!(
                        "None of the {} on {name} has more control of the server than a \
                         container needs",
                        plural(cs.len(), "container", "containers")
                    )),
                    &t,
                    vec![],
                );
            }
        }
        (None, Kind::Server) => {
            out.add(
                id("ctrs"),
                MovingAround,
                CouldNotCheck,
                0,
                says(
                    format!("How {name}'s containers are confined couldn't be read"),
                    "Reading that takes root on the server.",
                    "Open the server target and press I once (it asks for the sudo password \
                     and reads what needs root), then run the audit again (S).",
                ),
                &t,
                vec![],
            );
        }
        _ => {}
    }
    if exposed && let Some(ls) = &h.listeners {
        let meant: BTreeSet<u16> = doors
            .ports
            .iter()
            .filter(|(id, _)| id == &h.id)
            .map(|(_, p)| *p)
            .collect();
        let mut wide: Vec<(u16, String)> = ls
            .iter()
            .filter(|l| l.wide && !meant.contains(&l.port) && l.port != 22 && l.proto == "tcp")
            .map(|l| (l.port, l.process.clone().unwrap_or_default()))
            .collect();
        wide.sort();
        wide.dedup_by_key(|(p, _)| *p);
        if !wide.is_empty() {
            out.add(
                id("listen-wide"),
                MovingAround,
                Worth,
                FLAT,
                says(
                    format!(
                        "{} on {name} {} on every address, though the internet is only meant \
                         to reach {}",
                        plural(wide.len(), "other service", "other services"),
                        if wide.len() == 1 { "listens" } else { "listen" },
                        plural(meant.len(), "port", "ports")
                    ),
                    "Anything else on its network, or anyone who gets one step in, can reach \
                     them too.",
                    "Make what only the server itself uses listen on 127.0.0.1, the address \
                     only the server can reach; a session with Claude can.",
                ),
                &t,
                wide.iter()
                    .take(12)
                    .map(|(p, proc)| {
                        if proc.is_empty() {
                            format!("tcp {p}")
                        } else {
                            format!("tcp {p} ({proc})")
                        }
                    })
                    .chain((wide.len() > 12).then(|| format!("… and {} more", wide.len() - 12)))
                    .collect(),
            );
        }
    }
    if let Some(fw) = &h.firewall {
        if fw.active {
            out.add(
                id("firewall"),
                MovingAround,
                Fine,
                0,
                fine(format!("{name}'s firewall is on")),
                &t,
                fw.zone
                    .iter()
                    .map(|z| format!("default zone: {z}"))
                    .collect(),
            );
        } else {
            out.add(
                id("firewall"),
                MovingAround,
                Worth,
                0,
                says(
                    format!("{name}'s firewall is off"),
                    "Everything listening on it is reachable from every network it joins, a \
                     café's Wi-Fi included.",
                    "Turn firewalld on.",
                ),
                &t,
                vec![],
            );
        }
    }

    // -- noticing and recovering
    if h.kind == Kind::Server {
        logs(h, out);
    }
    if let Some(b) = &h.backup {
        if b.signals.is_empty() {
            out.asked(
                id("backup"),
                Recovering,
                format!("backup-exists:{}", h.id),
                answers,
                (
                    Fine,
                    0,
                    fine(format!(
                        "{name}'s data is backed up somewhere else (you said so)"
                    )),
                ),
                (
                    DoFirst,
                    RECOVERY,
                    says(
                        format!("{name}'s data has no backup"),
                        "Ransomware, a mistake or a dead disk then loses it for good.",
                        "Set up a backup that leaves the machine (another disk or place), \
                         encrypted, on a schedule.",
                    ),
                ),
                says(
                    format!(
                        "No sign of a backup was found on {name}. Is its data backed up somewhere else?"
                    ),
                    "sentry looks for known backup tools and timers; yours may be one it \
                     doesn't know.",
                    "Answer yes or no.",
                ),
                &t,
                vec![],
            );
            if answers.get(&format!("backup-exists:{}", h.id)) == Some(true) {
                restore_ask(h, answers, out);
            }
        } else {
            out.add(
                id("backup"),
                Recovering,
                Fine,
                0,
                fine(format!("A backup seems to run on {name}")),
                &t,
                b.signals.clone(),
            );
            restore_ask(h, answers, out);
        }
    }
}

/// Who watches the doors, and where what they catch is blocked.
fn watch(hosts: &[&TargetFacts], nets: &[&TargetFacts], doors: &Doors, out: &mut Out) {
    if !doors.any {
        return;
    }
    let exposed: Vec<&&TargetFacts> = hosts
        .iter()
        .filter(|h| doors.hosts.contains(&h.id))
        .collect();
    if exposed.is_empty() {
        return;
    }
    let mut targets: Vec<&str> = exposed.iter().map(|h| h.id.as_str()).collect();
    targets.extend(nets.iter().map(|n| n.id.as_str()));
    let names = exposed
        .iter()
        .map(|h| h.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let id = "sec:watch".to_string();
    if exposed.iter().all(|h| h.watch.is_none()) {
        out.add(
            id,
            Recovering,
            CouldNotCheck,
            0,
            says(
                format!(
                    "Whether anything on {names} watches for repeated attacks couldn't be read"
                ),
                "",
                "Run the audit again when it answers.",
            ),
            &targets,
            vec![],
        );
        return;
    }
    let agent = exposed
        .iter()
        .any(|h| h.watch.as_ref().is_some_and(|w| w.crowdsec == Some(true)));
    let local_bouncer = exposed.iter().any(|h| {
        h.watch
            .as_ref()
            .is_some_and(|w| w.bouncers.as_ref().is_some_and(|b| !b.is_empty()))
    });
    // Where bans are enforced isn't known: the server's bouncers or the router weren't read.
    let unread = exposed.iter().any(|h| {
        h.watch
            .as_ref()
            .is_some_and(|w| w.crowdsec == Some(true) && w.bouncers.is_none())
    }) || nets.iter().any(|n| n.watch.is_none());
    let jails: usize = exposed
        .iter()
        .filter_map(|h| h.watch.as_ref().and_then(|w| w.jails))
        .sum();
    let at_router = nets
        .iter()
        .any(|n| n.watch.as_ref().is_some_and(|w| w.enforces == Some(true)));
    // The router has the bouncer and it isn't switched on.
    let router_off = !at_router
        && nets
            .iter()
            .any(|n| n.watch.as_ref().is_some_and(|w| w.installed_off));
    // What needs root on a server waits for its inventory (sudo asks for a password).
    let waits = exposed.iter().any(|h| h.needs_inventory);
    let mut ev = Vec::new();
    for h in &exposed {
        if let Some(w) = &h.watch {
            match w.crowdsec {
                Some(true) => ev.push(format!("{}: CrowdSec runs", h.name)),
                Some(false) => {
                    ev.push(format!("{}: CrowdSec is installed but not running", h.name))
                }
                None => {}
            }
            match &w.bouncers {
                Some(b) if !b.is_empty() => {
                    ev.push(format!("{}: bouncers {}", h.name, b.join(", ")))
                }
                None if w.crowdsec == Some(true) => {
                    ev.push(format!("{}: its bouncers couldn't be read", h.name))
                }
                _ => {}
            }
            if let Some(j) = w.jails.filter(|j| *j > 0) {
                ev.push(format!(
                    "{}: {} on",
                    h.name,
                    plural(j, "fail2ban jail", "fail2ban jails")
                ));
            }
        }
    }
    if at_router {
        ev.push("the router's firewall enforces CrowdSec's bans".into());
    }
    if router_off {
        ev.push("the router: CrowdSec's bouncer is installed, switched off".into());
    }
    let (state, s) = if agent && at_router {
        (
            Fine,
            fine(format!(
                "Attackers that CrowdSec catches on {names} are blocked at the router, for \
                 every door"
            )),
        )
    } else if agent && router_off {
        (
            Worth,
            says(
                edge_off(true),
                "A banned address can still try every other door and device the router lets \
                 it reach.",
                EDGE_FIX,
            ),
        )
    } else if agent && unread {
        (
            CouldNotCheck,
            says(
                format!(
                    "CrowdSec runs on {names}; whether anything blocks the attackers it \
                     catches couldn't be read"
                ),
                "It decides who to ban; a bouncer (on the server or the router) is what \
                 enforces it.",
                if waits {
                    "Open the server target and press I once (it asks for the sudo password \
                     and reads what needs root), then run the audit again (S)."
                } else {
                    "In server_config.yaml, add `cscli bouncers list -o json` to the server's \
                     `sudo:` list (sentry's own read-only reads), press I on the server \
                     target, then run the audit again (S)."
                },
            ),
        )
    } else if agent && local_bouncer {
        (
            Worth,
            says(
                format!(
                    "Attackers that CrowdSec catches on {names} are blocked there, but not at \
                     the router"
                ),
                "A banned address can still try every other door and device the router lets \
                 it reach.",
                "Install CrowdSec's blocker on the router (its firewall bouncer) and connect \
                 it to the server's CrowdSec.",
            ),
        )
    } else if agent {
        (
            Worth,
            says(
                format!("CrowdSec on {names} notices attackers, but nothing blocks them"),
                "It decides who to ban; a bouncer is what enforces it.",
                "Install CrowdSec's blocker (a firewall bouncer): on the router for every \
                 door, or on the server.",
            ),
        )
    } else if jails > 0 {
        (
            Fine,
            fine(format!("fail2ban blocks repeated failed logins on {names}")),
        )
    } else {
        (
            Worth,
            says(
                format!(
                    "Nothing on {names} watches the doors the internet can reach for repeated \
                     attacks"
                ),
                "Automated attacks try thousands of things; without a watcher, none of it \
                 is noticed or slowed.",
                "Install CrowdSec on the server (and its bouncer on the router).",
            ),
        )
    };
    out.add(id, Recovering, state, RECOVERY, s, &targets, ev);
}

/// Every item, most pressing first: what to do first (by [`super::rank`]), what's worth
/// doing, questions, what couldn't be checked, what's fine. `today` dates an operating
/// system's end of support.
pub fn evaluate(facts: &[TargetFacts], answers: &Answers, today: Date) -> Vec<Item> {
    let mut out = Out::default();
    for f in facts {
        if let Some(why) = &f.unreachable {
            out.add(
                format!("sec:reach:{}", f.id),
                GettingIn,
                CouldNotCheck,
                0,
                says(
                    format!(
                        "{} couldn't be reached, so nothing about it was checked",
                        f.name
                    ),
                    "",
                    "Run the audit again when it answers.",
                ),
                &[&f.id],
                vec![why.clone()],
            );
        }
    }
    let live: Vec<&TargetFacts> = facts.iter().filter(|f| f.unreachable.is_none()).collect();
    let hosts: Vec<&TargetFacts> = live
        .iter()
        .copied()
        .filter(|f| f.kind != Kind::Network)
        .collect();
    let nets: Vec<&TargetFacts> = live
        .iter()
        .copied()
        .filter(|f| f.kind == Kind::Network)
        .collect();

    let mut doors = Doors::default();
    for n in &nets {
        let Some(r) = &n.router else { continue };
        match &r.forwards {
            Some(fwds) => {
                for f in fwds {
                    door(n, f, &hosts, answers, &mut doors, &mut out);
                }
                if fwds.is_empty() {
                    out.add(
                        format!("sec:door:{}", n.id),
                        GettingIn,
                        Fine,
                        0,
                        fine("The router forwards nothing from the internet to devices at home"),
                        &[&n.id],
                        vec![],
                    );
                }
            }
            None => {
                out.add(
                    format!("sec:door:{}", n.id),
                    GettingIn,
                    CouldNotCheck,
                    0,
                    says(
                        "What the router forwards from the internet couldn't be read",
                        "Those forwards are the doors into your network.",
                        "Run the audit again when the router answers.",
                    ),
                    &[&n.id],
                    vec![],
                );
            }
        }
    }
    for n in &nets {
        if let Some(r) = &n.router {
            router(n, r, &doors, answers, &mut out);
        }
    }
    for h in &hosts {
        host(h, &doors, answers, today, &mut out);
    }
    watch(&hosts, &nets, &doors, &mut out);

    let order = |s: State| match s {
        DoFirst => 0,
        Worth => 1,
        Ask => 2,
        CouldNotCheck => 3,
        Fine => 4,
    };
    out.items.sort_by(|a, b| {
        (order(a.state), a.rank, a.group, &a.id).cmp(&(order(b.state), b.rank, b.group, &b.id))
    });
    out.items
}
