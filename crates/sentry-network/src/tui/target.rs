//! A network as a target of the app (`sentry_app::Target`): its router's collectors and store,
//! its screens, and how a command line becomes a `Cmd` over ssh. Everything else (the frame,
//! records, sessions, the workflow run) is the app's.
//!
//! Maintenance lists the audit's findings, what the firmware, the packages and the backups
//! ask for, and the tasks due (`Upkeep`); its workflows (`crate::workflow`) run through the
//! shared `remote::workflow::Session`, in a router's words. Claude (`Asks`, `super::ask`)
//! reaches the router only through the gateway, and nothing of the router's goes into a
//! prompt unscrubbed. What a session runs for Claude goes through `Host::command`, which
//! refuses by `policy` whatever the plan says.

use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::text::Line;

use super::SCREENS;
use super::data::{Data, Kind, Store};
use super::screens::{Screens, View, maint};
use crate::remote::Router;
use crate::workflow::{self, Session};
use sentry_app::effect;
use sentry_app::remote::SudoMode;
use sentry_app::run::{Exec, WfRun};
use sentry_app::shared::Shared;
use sentry_app::target::{
    Asks, Changes, Cx, Hints, Host, Ident, Mail, ProfileFor, SeriesStep, Settle, TabInfo, Target,
    Upkeep, Ways, Why,
};
use sentry_core::claude::{Ask, Grant, Profile};
use sentry_core::exec::{Cmd, ExecError};
use sentry_core::maint::changes::{Change, Known};
use sentry_core::maint::tasks::Task;
use sentry_core::tui::ScreenId;
use sentry_core::tui::keys::Action;
use sentry_core::tui::records::{LaterKind, LaterRow};
use sentry_core::workflows::Entry;

pub use sentry_app::effect::{Effect, Modal};

/// The program's name: its chip in the top bar.
const APP: &str = "sentry-network";

/// The probe: every second while the Dashboard has the window.
const PROBE: Duration = Duration::from_secs(1);
/// Board, interfaces and devices: they move slowly.
const IFACES: Duration = Duration::from_secs(30);
/// Who is on the network: while Clients is in view.
const CLIENTS: Duration = Duration::from_secs(10);
/// Which services run: the Dashboard's row.
const SERVICES: Duration = Duration::from_secs(60);
/// What the firewall counted: Security's rates are made from two of these. Inside ssh's
/// `ControlPersist` (15 s), so the shared connection stays up between reads and no read
/// is a new login in the router's log.
const COUNTERS: Duration = Duration::from_secs(10);
/// The connections tracked now.
const FLOWS: Duration = Duration::from_secs(30);
/// The certificate's dates don't move: read again after this long.
const CERT_S: i64 = 86_400;

/// What only a network has, as effects: they travel through the app wrapped (`Effect::Own`)
/// and come back in [`Target::on_own`].
#[derive(Clone, Debug)]
pub enum Own {
    Fetch(Kind),
    /// `b` on a finding or a client (or `B`, a pattern): expected from now on, or not any
    /// more (the network's baseline.toml).
    Expected(String, bool),
    /// `b` on Network: a port's listeners (their baseline keys) and its finding are expected
    /// from now on, or not any more. `what` names the port for the toast.
    ListenExpected {
        keys: Vec<String>,
        id: String,
        what: String,
        on: bool,
    },
    /// The audit report, over Maintenance (`F`, `:audit`), on this finding when one is named.
    OpenReport(Option<String>),
    /// What Security's list asks for (`screens::threats`): an action started, a name or a
    /// new Wi-Fi password answered.
    Security(super::screens::threats::Want),
}

impl Own {
    pub fn fetch(k: Kind) -> Effect {
        Effect::own(Own::Fetch(k))
    }
}

/// A fetch a screen wants while it's in view: when it's entered, then every `every` (None:
/// at entry only).
struct Poll {
    kind: Kind,
    every: Option<Duration>,
}

/// What the screen fetches while it's the one in view.
fn polls(id: ScreenId) -> Vec<Poll> {
    let at = |kind, every: Option<Duration>| Poll { kind, every };
    let mut v = polls_of(id);
    // What must be hidden from Claude (the SSIDs, the devices' names) is known wherever
    // it can be asked: read once when the screen is entered.
    for k in [Kind::Uci, Kind::Clients, Kind::Ifaces] {
        if !v.iter().any(|p| p.kind == k) {
            v.push(at(k, None));
        }
    }
    v
}

fn polls_of(id: ScreenId) -> Vec<Poll> {
    let at = |kind, every: Option<Duration>| Poll { kind, every };
    match id {
        // Read from this machine's disk, when the screen is entered (and on r).
        ScreenId::Hist => vec![at(Kind::History, None)],
        ScreenId::Clients => vec![
            at(Kind::Clients, Some(CLIENTS)),
            at(Kind::Ifaces, Some(IFACES)),
        ],
        // Nothing here moves by itself: entry and `r`.
        ScreenId::Net => vec![
            at(Kind::Listeners, None),
            at(Kind::Uci, None),
            at(Kind::Ifaces, Some(IFACES)),
        ],
        // The last report, from disk; the audit itself runs when that is old (`on_data`).
        // The packages from the index the router has (`--no-network`; fetching it again is
        // `r`, never this), what was last looked up upstream (this machine's cache), and
        // the backups against the router's files now.
        ScreenId::Maint => vec![
            at(Kind::Report, None),
            at(Kind::Ifaces, Some(IFACES)),
            at(Kind::Updates, None),
            at(Kind::Upstream, None),
            at(Kind::Backup, None),
        ],
        // The counters and the flows move; the log and the packages' own status are read
        // when it's entered (and on `r`). The stations come with the clients' read, as on
        // Clients.
        ScreenId::Security => vec![
            at(Kind::Counters, Some(COUNTERS)),
            at(Kind::Flows, Some(FLOWS)),
            at(Kind::Clients, Some(CLIENTS)),
            at(Kind::Ifaces, Some(IFACES)),
            at(Kind::Uci, None),
            at(Kind::SecLog, None),
            at(Kind::DnsState, None),
            // What the list's findings are also made of (the audit's own rule).
            at(Kind::Listeners, None),
            at(Kind::Services, None),
        ],
        // The run's own steps are the app's; the list is read from disk.
        ScreenId::Upgrade => Vec::new(),
        _ => vec![
            at(Kind::Probe, Some(PROBE)),
            at(Kind::Ifaces, Some(IFACES)),
            at(Kind::Services, Some(SERVICES)),
            at(Kind::Report, None),
        ],
    }
}

pub struct NetworkTarget {
    ident: Ident,
    pub router: Router,
    mail: Mail,
    pub store: Store,
    pub screens: Screens,
    /// Maintenance was just entered: once the last report is read, audit if it's old.
    audit_on_entry: bool,
    /// The audit running is the one after a finding's plan (`Why::Reaudit`).
    reaudit: bool,
    /// The samples taken become the router's metrics ring (History).
    recorder: crate::recorder::Recorder,
    /// There's a ring for this network: History is in the strip.
    has_ring: bool,
    /// The ring couldn't be written (said once).
    ring_failed: bool,
    /// When each fetch of the screen in view is next due.
    due: HashMap<Kind, Instant>,
    /// The secrets this window's runs were given (a guarded change's new passphrase):
    /// in memory only, so that nothing written down afterwards says one.
    given: Vec<String>,
    /// Every fetch asked for, in order (tests: nothing is spawned there, this still counts).
    #[cfg(any(test, feature = "testing"))]
    pub asked: Vec<Kind>,
}

impl NetworkTarget {
    /// The target's id for a network's name.
    pub fn id_of(name: &str) -> String {
        crate::remote::scope(name)
    }

    pub fn new(router: Router, mail: Mail) -> Self {
        let name = router.name.clone();
        let scope = router.scope.clone();
        Self {
            ident: Ident {
                id: Self::id_of(&name),
                title: name.clone(),
                scope: scope.clone(),
                place: "the network",
                word: "net",
                app: APP,
                screens: &SCREENS,
                runs: sentry_app::remote::workflow::root(&scope),
                wf_dir: format!("~/.config/sentry/networks/{name}/workflows/"),
                ways: Ways {
                    // A review is about a network, and changes its tasks only (nothing
                    // here is tracked the way a server's items are).
                    writer_place: "network",
                    server_changes: false,
                    // What a run did is read from the log (a cadence is done when its
                    // workflow last ended well): it follows every entry written.
                    // A secret typed among a run's values shows as dots.
                    typed: |p, text| match p {
                        effect::Prompt::WfVar(_) => crate::guard::typed(text),
                        // Security's new Wi-Fi password.
                        effect::Prompt::Own(o) => match o.own.0.downcast_ref::<Own>() {
                            Some(Own::Security(w)) if w.secret() => {
                                Some("•".repeat(text.chars().count()))
                            }
                            _ => None,
                        },
                        _ => None,
                    },
                    ..Default::default()
                },
                quit: format!("Quit sentry? Nothing keeps running on {name}'s router after exit."),
                help_globals: &[
                    ("A", "ask Claude about what's selected"),
                    (
                        "C-a",
                        "auto mode: a workflow's steps, a plan's approval and a series' next row need no key",
                    ),
                ],
                commands: ":q  :<screen>  :audit [now|security]  :wf [name]  :log  :refresh",
                help_footer: format!(
                    "Nothing is installed on {name}'s router. A guarded change leaves one \
                     sleeper there for at most its window."
                ),
                privacy: "Sent to Claude through your Claude Code login (Anthropic): scrubbed \
                          of secrets, the uplink's address, MACs, SSIDs and unnamed hostnames. \
                          It reads the router through sentry-network's read-only gateway."
                    .into(),
                session_privacy: "Sent to Claude through your Claude Code login (Anthropic), \
                                  scrubbed. It reads the router itself; every change is shown \
                                  to you first, and config changes go through the guard."
                    .into(),
            },
            router,
            mail,
            store: Store::default(),
            screens: Screens::default(),
            audit_on_entry: false,
            reaudit: false,
            recorder: Default::default(),
            has_ring: false,
            ring_failed: false,
            due: HashMap::new(),
            given: Vec::new(),
            #[cfg(any(test, feature = "testing"))]
            asked: Vec::new(),
        }
    }

    fn fetch(&mut self, k: Kind, cx: &Cx) {
        #[cfg(any(test, feature = "testing"))]
        self.asked.push(k);
        if cx.offline {
            return;
        }
        self.store.fetch(k, &self.router, &self.mail);
    }

    fn view<'a>(&'a self, sh: &'a Shared, cx: &'a Cx) -> View<'a> {
        view_of(
            &self.store,
            &self.router,
            sh,
            cx,
            (
                self.screens.cur(cx.screen),
                self.screens.security.group.clone(),
            ),
        )
    }

    /// The screens with the view they act on (the view borrows the rest of the target).
    fn with_screens<R>(
        &mut self,
        sh: &Shared,
        cx: &Cx,
        f: impl FnOnce(&mut Screens, &View) -> R,
    ) -> R {
        let at = (
            self.screens.cur(cx.screen),
            self.screens.security.group.clone(),
        );
        let v = view_of(&self.store, &self.router, sh, cx, at);
        f(&mut self.screens, &v)
    }

    fn clamp(&mut self, sh: &Shared, cx: &Cx) {
        let id = cx.screen;
        self.with_screens(sh, cx, |s, v| s.clamp(id, v));
    }

    /// What's expected of the stored findings, by the baseline as it is now (a report on
    /// disk says what was expected when it was written, and is read again on every entry).
    fn remark(&mut self, sh: &Shared) {
        let (cur, prev) = match self.store.shown.as_mut() {
            Some(s) => (s.cur.as_mut(), s.prev.as_mut()),
            None => (None, None),
        };
        let latest = self.store.report.value.as_mut().and_then(|r| r.as_mut());
        let cfg = &self.router.cfg;
        for r in [latest, cur, prev].into_iter().flatten() {
            // What isn't watched any more can't be reported by a new audit: it leaves
            // with the watching, not at the next audit.
            r.findings.retain(|f| !crate::watch::dropped(cfg, &f.id));
            sentry_app::remote::audit::mark_expected(&mut r.findings, &[], &sh.baseline);
        }
    }

    /// network_config.yaml changed on disk: read again; on an error, what was loaded stays.
    fn reload_config(&mut self) -> Vec<Effect> {
        let name = self.router.name.clone();
        let said = match crate::config::load().and_then(|(f, w)| {
            let n = f
                .networks
                .get(&name)
                .cloned()
                .ok_or_else(|| format!("{name} is no longer in network_config.yaml"))?;
            Ok((n, w))
        }) {
            Ok((n, warnings)) => {
                let problems = crate::config::lint(&name, &n);
                self.router = Router::new(&name, &n);
                match warnings.iter().chain(&problems).next() {
                    Some(p) => format!("reloaded · {p}"),
                    None => "network_config.yaml reloaded".into(),
                }
            }
            Err(e) => format!("not reloaded: {e}"),
        };
        vec![Effect::Toast(said)]
    }

    /// `b` on a finding or a client (or `B`, a pattern): into the baseline file, or out of
    /// it. What's in memory is the file as last read; tests write nothing.
    fn expected(&mut self, id: &str, on: bool, sh: &mut Shared, cx: &Cx) -> Vec<Effect> {
        let toast = |s: &str| vec![Effect::Toast(s.to_string())];
        let mut b = sh.baseline.clone();
        let changed = crate::audit::set_expected_in(&mut b, id, on);
        let saved = if changed && !cx.offline {
            b.save(&self.router.scope).map(|_| true)
        } else {
            Ok(changed)
        };
        if saved.is_ok() {
            sh.baseline = b;
        }
        match saved {
            // Still expected by something else: a pattern.
            Ok(false) if !on => toast("expected by a pattern: Records › Later takes it back"),
            Ok(_) => {
                self.remark(sh);
                self.clamp(sh, cx);
                toast(if on {
                    "marked expected (baseline.toml)"
                } else {
                    "no longer expected"
                })
            }
            Err(e) => toast(&format!("couldn't save: {e}")),
        }
    }

    /// `b` on Network: the port's listeners and its finding go into the baseline file, or
    /// come out of it. No box: it's one local file, and `b` again undoes it.
    fn listen_expected(
        &mut self,
        keys: &[String],
        id: &str,
        what: &str,
        on: bool,
        sh: &mut Shared,
        cx: &Cx,
    ) -> Vec<Effect> {
        let toast = |s: String| vec![Effect::Toast(s)];
        let mut b = sh.baseline.clone();
        if on {
            for k in keys {
                if !b.listeners.contains(k) {
                    b.listeners.push(k.clone());
                }
            }
            crate::audit::set_expected_in(&mut b, id, true);
        } else {
            b.drop_listeners(keys);
            crate::audit::set_expected_in(&mut b, id, false);
        }
        if !cx.offline
            && let Err(e) = b.save(&self.router.scope)
        {
            return toast(format!("couldn't save: {e}"));
        }
        let still =
            !on && sh.baseline.listeners == b.listeners && sh.baseline.findings == b.findings;
        sh.baseline = b;
        self.remark(sh);
        self.clamp(sh, cx);
        toast(if on {
            format!("{what}: expected (baseline.toml)")
        } else if still {
            // Nothing of the file's covered it: the config does, which sentry doesn't rewrite.
            "expected by network_config.yaml (expect.listeners): change it there".into()
        } else {
            format!("{what}: no longer expected")
        })
    }

    /// A probe just arrived: it goes towards the router's ring, one record every ten
    /// seconds. Nothing is read for this.
    fn record_sample(&mut self, cx: &Cx) -> Vec<Effect> {
        let Some(s) = self.store.sampled.take() else {
            return Vec::new();
        };
        let Some(p) = &self.store.probe.value else {
            return Vec::new();
        };
        let flash = self
            .store
            .ifaces
            .value
            .as_ref()
            .and_then(|i| i.info.root_pct());
        let Some(rec) = self.recorder.feed(
            jiff::Timestamp::now().as_second(),
            s.cpu,
            s.rx,
            s.tx,
            &p.host,
            s.temp,
            None,
            flash,
        ) else {
            return Vec::new();
        };
        match crate::recorder::write(&self.router.scope, cx.offline, &rec) {
            Ok(wrote) => self.has_ring |= wrote,
            Err(e) if !self.ring_failed => {
                self.ring_failed = true;
                return vec![Effect::Toast(format!("history isn't being recorded: {e}"))];
            }
            Err(_) => {}
        }
        Vec::new()
    }

    /// The screens in the strip: History only once something was recorded (`H` still opens
    /// it), as for this machine and a server.
    fn visible(&self, screen: ScreenId) -> Vec<ScreenId> {
        SCREENS
            .ids
            .iter()
            .copied()
            .filter(|s| *s != ScreenId::Hist || self.has_ring || screen == ScreenId::Hist)
            .collect()
    }
}

/// The view over a store (a free function, so the screens can be borrowed beside it).
fn view_of<'a>(
    store: &'a Store,
    router: &'a Router,
    sh: &'a Shared,
    cx: &'a Cx,
    (cur, group): (usize, Option<String>),
) -> View<'a> {
    View {
        t: cx.theme,
        s: store,
        sh,
        cfg: &router.cfg,
        name: &router.name,
        cur,
        now: cx.now,
        filter: cx
            .filter
            .filter(|f| !f.is_empty() && Screens::filterable(cx.screen)),
        everything: cx.everything,
        wf: cx.run.and_then(|r| r.as_any().downcast_ref::<Session>()),
        auto: cx.auto,
        system: cx.system,
        group,
    }
}

impl Target for NetworkTarget {
    fn ident(&self) -> &Ident {
        &self.ident
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    /// Nothing is read ahead of the screen in view: its own fetches follow (`enter`).
    fn start(&mut self, _sh: &mut Shared, cx: &Cx) -> Vec<Effect> {
        if !cx.offline {
            let scope = &self.router.scope;
            self.has_ring = sentry_core::recorder::ring::path(scope).exists();
            self.store.seen = crate::clients::Seen::load(scope);
            self.store.blocks = crate::security::blocks::Blocks::load(scope);
            sentry_core::maint::retention::cap_reports(
                &crate::audit::reports_dir(scope),
                sentry_core::config::Config::load().0.retention.reports,
            );
        }
        Vec::new()
    }

    fn enter(&mut self, from: ScreenId, now: Instant, _sh: &Shared, cx: &Cx) -> Vec<Effect> {
        // Arriving at Maintenance from elsewhere: its list, not a view left open; and the
        // audit again if the last one is old.
        if cx.screen == ScreenId::Maint && from != ScreenId::Maint {
            self.screens.maint.view = None;
            self.audit_on_entry = true;
        }
        self.due.clear();
        for p in polls(cx.screen) {
            self.fetch(p.kind, cx);
            if let Some(every) = p.every {
                self.due.insert(p.kind, now + every);
            }
        }
        // Security shows what a server's own guard says of the doors forwarded to it: a
        // server that never had the window starts now, so it has read it.
        if cx.screen == ScreenId::Security {
            return cx
                .system
                .iter()
                .filter(|s| s.peer.id.starts_with("srv:"))
                .map(|s| Effect::Wake(s.peer.id.clone()))
                .collect();
        }
        Vec::new()
    }

    fn due(&mut self, now: Instant, cx: &Cx) -> bool {
        // Only what the screen in view polls, and only while the network has the window.
        if !cx.focused {
            return false;
        }
        for p in polls(cx.screen) {
            if let Some(every) = p.every
                && self.due.get(&p.kind).is_none_or(|t| now >= *t)
            {
                self.fetch(p.kind, cx);
                self.due.insert(p.kind, now + every);
            }
        }
        false
    }

    fn next_due(&self, _now: Instant, cx: &Cx) -> Option<Instant> {
        // Out of view nothing of a network sets a time.
        self.due.values().copied().min().filter(|_| cx.focused)
    }

    fn on_data(&mut self, data: Box<dyn Any + Send>, sh: &mut Shared, cx: &Cx) -> Vec<Effect> {
        let Ok(data) = data.downcast::<Data>() else {
            return Vec::new();
        };
        let Data(k, res) = *data;
        let mut fx = Vec::new();
        let ok = res.is_ok();
        match (k, &*res) {
            (Kind::Audit, Ok(_)) => fx.push(Effect::Toast("audit done · report saved".into())),
            (Kind::Audit, Err(e)) => fx.push(Effect::Toast(format!("audit failed: {e}"))),
            _ => {}
        }
        self.store.apply(k, *res);
        if matches!(k, Kind::Audit | Kind::Report | Kind::ReportAt(_)) {
            self.remark(sh);
        }
        match k {
            // One list of clients from the read, once the layout is known.
            Kind::Clients => self.store.raw_pending = ok,
            Kind::Audit => {
                fx.push(Effect::AuditEnded(ok));
                // The audit after a finding's plan: is the finding gone?
                if let Some(id) = cx.finding.filter(|_| std::mem::take(&mut self.reaudit)) {
                    let still = match self.store.report.value.as_ref() {
                        _ if !ok => Some("the audit couldn't run".to_string()),
                        r => r
                            .and_then(|r| r.as_deref())
                            .and_then(|r| r.findings.iter().find(|f| f.id == id && !f.expected))
                            .map(sentry_core::finding::Finding::standing),
                    };
                    fx.push(Effect::Reaudited(still));
                }
            }
            // The refresh was asked for: say how it went.
            Kind::Refresh => fx.push(Effect::Toast(match &self.store.updates {
                u if !ok => format!(
                    "the package index wasn't refreshed: {}",
                    u.err.as_ref().map_or(String::new(), |e| e.to_string())
                ),
                u => match u.value.as_ref() {
                    Some(v) if v.refresh_failed.is_some() => {
                        "apk update failed on the router: the index is as it was".to_string()
                    }
                    Some(v) => format!("package index refreshed · {} upgradable", v.packages.len()),
                    None => String::new(),
                },
            })),
            Kind::History => {
                let recorded = |h: &sentry_core::tui::histview::HistData| h.header.is_some();
                self.has_ring |= self.store.history.value.as_ref().is_some_and(recorded);
            }
            _ => {}
        }
        if matches!(k, Kind::Clients | Kind::Ifaces) {
            let scope = (!cx.offline).then_some(self.router.scope.as_str());
            self.store
                .merge_clients(&self.router.cfg.devices, cx.now.as_second(), scope);
        }
        self.store
            .recognise(cx.system, &super::id_of(&self.router.name));
        if k == Kind::Report && ok {
            let v = self.view(sh, cx);
            let (audited, due) = maint::audit_age(&v);
            // Entering Maintenance with an old report (or none): audit, once.
            let audit = std::mem::take(&mut self.audit_on_entry)
                && due
                && cx.screen == ScreenId::Maint
                && cx.focused;
            // The certificate: what the last audit read is good for a day.
            let cert = self.store.cert.at.is_none()
                && audited.is_none_or(|t| cx.now.as_second() - t.as_second() > CERT_S);
            if audit {
                self.fetch(Kind::Audit, cx);
                fx.push(Effect::Toast("auditing the network…".into()));
            } else if cert {
                self.fetch(Kind::Cert, cx);
            }
        }
        if matches!(
            k,
            Kind::Audit
                | Kind::Report
                | Kind::ReportAt(_)
                | Kind::Clients
                | Kind::Updates
                | Kind::Refresh
                | Kind::Upstream
                | Kind::Lookup
                | Kind::Backup
                | Kind::Flows
                | Kind::Uci
                | Kind::SecLog
                | Kind::DnsState
                | Kind::Counters
        ) {
            self.clamp(sh, cx);
        }
        fx.extend(self.record_sample(cx));
        fx
    }

    fn refresh(&mut self, why: Why, sh: &Shared, cx: &Cx) -> Vec<Effect> {
        match why {
            Why::Audit => {
                self.fetch(Kind::Audit, cx);
                vec![Effect::Toast("auditing the network…".into())]
            }
            // A finding's plan ran: the audit says whether it's gone.
            Why::Reaudit => {
                self.reaudit = true;
                self.fetch(Kind::Audit, cx);
                Vec::new()
            }
            // A run ended: what it may have made (a backup) is read again.
            Why::Run | Why::Changed => {
                self.fetch(Kind::Backup, cx);
                // And what a Security action changed: the config, and who is blocked.
                self.fetch(Kind::Uci, cx);
                if !cx.offline {
                    self.store.blocks = crate::security::blocks::Blocks::load(&self.router.scope);
                }
                Vec::new()
            }
            // The lists are made from the app's records as they're drawn; what's expected
            // of the stored report follows the baseline.
            Why::Lists | Why::Baseline => {
                self.remark(sh);
                self.clamp(sh, cx);
                Vec::new()
            }
            Why::Edited => self.reload_config(),
            _ => Vec::new(),
        }
    }

    fn files(&self) -> Vec<std::path::PathBuf> {
        vec![
            crate::config::path(),
            sentry_core::maint::watch::path(&self.router.scope),
        ]
    }

    fn on_own(&mut self, fx: &effect::Own, sh: &mut Shared, cx: &Cx) -> Vec<Effect> {
        match fx.0.downcast_ref::<Own>() {
            Some(Own::Fetch(k)) => self.fetch(*k, cx),
            // `id` may be a pattern (`B`: `net:client:*`).
            Some(Own::Expected(id, on)) => return self.expected(id, *on, sh, cx),
            Some(Own::ListenExpected { keys, id, what, on }) => {
                return self.listen_expected(keys, id, what, *on, sh, cx);
            }
            Some(Own::OpenReport(id)) => {
                return self.with_screens(sh, cx, |s, v| s.maint.open_report(v, id.as_deref()));
            }
            Some(Own::Security(w)) => {
                let w = w.clone();
                return super::screens::threats::on_own(self, &w, sh, cx);
            }
            None => {}
        }
        Vec::new()
    }

    /// Security's own prompts: a device's name, a new Wi-Fi password.
    fn on_prompt(
        &mut self,
        own: &effect::Own,
        answer: Option<&str>,
        sh: &mut Shared,
        cx: &Cx,
    ) -> Vec<Effect> {
        let Some(Own::Security(w)) = own.0.downcast_ref::<Own>() else {
            return Vec::new();
        };
        let w = w.clone();
        let fx = super::screens::threats::on_prompt(self, &w, answer, cx);
        self.clamp(sh, cx);
        fx
    }

    /// Nothing of a network's has the terminal.
    fn after_suspend(
        &mut self,
        _own: &effect::Own,
        _status: Result<ExitStatus, ExecError>,
        _sh: &mut Shared,
        _cx: &Cx,
    ) -> Vec<Effect> {
        Vec::new()
    }

    fn handle(&mut self, a: Action, sh: &Shared, cx: &Cx) -> Vec<Effect> {
        let id = cx.screen;
        self.with_screens(sh, cx, |s, v| s.handle(id, a, v))
    }

    fn render(&mut self, f: &mut Frame, area: Rect, sh: &Shared, cx: &Cx) {
        let id = cx.screen;
        // A device that is another of the window's targets is shown as that target.
        self.store
            .recognise(cx.system, &super::id_of(&self.router.name));
        self.with_screens(sh, cx, |s, v| s.render(id, f, area, v));
    }

    fn hints(&self, help: bool, sh: &Shared, cx: &Cx) -> Hints {
        let keys = self.screens.hints(cx.screen, &self.view(sh, cx));
        // `?` on Maintenance: every row key, not only the selected row's.
        if help && cx.screen == ScreenId::Maint && self.screens.maint.view.is_none() {
            return maint::help();
        }
        // `?` on Security: what each number is, and what it is not.
        if help && cx.screen == ScreenId::Security {
            return if self.screens.security.panels {
                super::screens::security::help()
            } else {
                super::screens::threats::help()
            };
        }
        keys
    }

    fn tabs(&self, sh: &Shared, cx: &Cx) -> Vec<TabInfo> {
        let v = self.view(sh, cx);
        self.visible(cx.screen)
            .into_iter()
            .map(|id| TabInfo {
                id,
                badge: match id {
                    // A run in progress.
                    ScreenId::Upgrade => cx
                        .run
                        .filter(|s| !s.done())
                        .map(|_| (" ●".to_string(), cx.theme.yellow)),
                    _ => self.screens.badge(id, &v),
                },
                filterable: Screens::filterable(id),
            })
            .collect()
    }

    fn settle(&mut self, why: Settle, sh: &Shared, cx: &Cx) {
        match why {
            Settle::Key => {
                if cx.screen == ScreenId::Maint {
                    // `o` changed the list: the cursor follows its row first.
                    if self.screens.maint.everything != cx.everything {
                        self.screens.maint.everything = cx.everything;
                        self.clamp(sh, cx);
                    }
                    self.screens.maint.sel = maint::row_key(&self.view(sh, cx));
                }
                // Security's list: a key may have changed it (`o`, a row dismissed).
                if cx.screen == ScreenId::Security {
                    self.clamp(sh, cx);
                }
            }
            Settle::Lists => self.clamp(sh, cx),
            Settle::Filter | Settle::FilterCleared => self.screens.reset_cursor(cx.screen),
            Settle::Ticks(left) => self.screens.maint.ticks = left.into_iter().collect(),
            Settle::Workflow(i) => self.screens.upgrade.cur.sel = i,
        }
    }

    /// The top bar: what the router runs and how long it's been up; the connection.
    fn top(&self, cx: &Cx) -> (Vec<String>, (String, Color)) {
        let t = cx.theme;
        let mut facts = Vec::new();
        if let Some(i) = &self.store.ifaces.value {
            facts.push(format!("{} {}", i.board.distribution, i.board.version));
            facts.push(i.board.model.clone());
        }
        if let Some(p) = &self.store.probe.value {
            facts.push(format!("up {}", sentry_core::fmt::uptime(p.host.uptime_s)));
        }
        let s = &self.store;
        let state = match &s.unreachable {
            Some(_) => ("○ unreachable · retrying".to_string(), t.red),
            None if s.rebooted() => ("● rebooted".to_string(), t.mag),
            None if s.probe.value.is_some() || s.ifaces.value.is_some() => {
                ("● connected".to_string(), t.green)
            }
            None => ("○ connecting…".to_string(), t.dim),
        };
        (facts, state)
    }

    fn colon(
        &mut self,
        _line: &str,
        cmd: &str,
        arg: Option<&str>,
        _sh: &Shared,
        _cx: &Cx,
    ) -> Option<Vec<Effect>> {
        match cmd {
            "audit" if arg == Some("now") => Some(vec![Own::fetch(Kind::Audit)]),
            // The audit report, over Maintenance.
            "audit" => Some(vec![
                Effect::Goto(ScreenId::Maint),
                Effect::own(Own::OpenReport(None)),
            ]),
            _ => None,
        }
    }
}

// ---- Maintenance: the audit's findings, the upkeep's rules and the tasks due. Then the
// ---- plain answers about Claude, and how a workflow runs.

/// A review can change a network's tasks; there is nothing else of a network's to change
/// (no tracked items yet).
struct NoChanges;

impl Changes for NoChanges {
    fn apply(&mut self, _c: &Change) -> Option<Result<String, String>> {
        None
    }
    fn save(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn done(self: Box<Self>) -> Vec<Effect> {
        Vec::new()
    }
}

impl Upkeep for NetworkTarget {
    /// The config's `maintenance.cadence`, for the workflows this network has.
    fn derived_tasks(&self, sh: &Shared) -> Vec<Task> {
        crate::maint::cadence_tasks(&self.router.cfg, &sh.workflows)
    }

    fn with_known(&self, sh: &Shared, cx: &Cx, f: &mut dyn FnMut(&Known)) {
        let v = View {
            filter: None,
            everything: true,
            ..self.view(sh, cx)
        };
        let tasks = maint::all_tasks(&v);
        let rows: Vec<(String, String)> = maint::recs(&v)
            .into_iter()
            .map(|r| (r.key, r.title))
            .collect();
        f(&Known {
            workflows: &sh.workflows,
            tasks: &tasks,
            rows: &rows,
            later: Some(&sh.later),
            log: &sh.log,
            now: Some(jiff::Timestamp::now()),
            ..Default::default()
        })
    }

    fn changes(&self, _sh: &Shared, _cx: &Cx) -> Box<dyn Changes> {
        Box::new(NoChanges)
    }

    /// A row a series can do: a workflow's run, or the audit.
    fn series_step(&self, key: &str, sh: &Shared, cx: &Cx) -> Option<SeriesStep> {
        let v = View {
            filter: None,
            everything: true,
            ..self.view(sh, cx)
        };
        let rec = maint::every_rec(&v).into_iter().find(|r| r.key == key)?;
        Some(match maint::series_kind(&v, &rec)? {
            maint::SeriesKind::Workflow(name) => SeriesStep::Workflow(name),
            maint::SeriesKind::Audit => SeriesStep::Audit,
            // A finding, a task done by hand: a session, as on the other targets.
            maint::SeriesKind::Session => {
                SeriesStep::Session(Box::new(super::ask::apply_rec(&v, &rec, &|wf| {
                    sh.workflow_text(APP, wf)
                })?))
            }
        })
    }

    fn task_enter(&self, id: &str, sh: &Shared, cx: &Cx) -> Vec<Effect> {
        maint::task_enter(&self.view(sh, cx), id)
    }

    fn item_kind(&self, item: &str) -> Option<(String, String)> {
        use crate::config::ItemKind;
        let (_, kind) = crate::maint::recommend::kinds(&self.router.cfg)
            .into_iter()
            .find(|(id, _)| id == item)?;
        let (kind, risk) = match kind {
            ItemKind::Firmware => ("firmware", "high"),
            ItemKind::Packages => ("packages", "medium"),
            ItemKind::Backup => ("backup", "low"),
        };
        Some((kind.to_string(), risk.to_string()))
    }

    fn records(&self, sh: &Shared, cx: &Cx) -> (Vec<LaterRow>, Option<jiff::Timestamp>) {
        // What the config lists and sentry no longer watches (`u` watches it again).
        let later = self
            .router
            .watch
            .unwatched
            .iter()
            .map(|u| LaterRow {
                kind: LaterKind::Unwatched {
                    since: u.since.to_string(),
                    why: u.why.clone(),
                },
                key: u.key(),
                file: "watch.toml",
            })
            .collect();
        (later, maint::audit_age(&self.view(sh, cx)).0)
    }

    /// The thing was retired on purpose: the config's own expectation goes (the file is
    /// applied over the YAML, which isn't rewritten), and with it every finding about it.
    fn unwatch(
        &mut self,
        what: &str,
        why: &str,
        sh: &mut Shared,
        cx: &Cx,
    ) -> Result<String, String> {
        let Some((kind, thing)) = sentry_core::maint::watch::split(what) else {
            return Err(format!("{what} isn't `<kind>:<name>`"));
        };
        if !crate::watch::known(self.router.listed(), what) {
            return Err(format!("network_config.yaml expects no {kind} {thing}"));
        }
        let mut w = (*self.router.watch).clone();
        if !w.add(kind, thing, jiff::Zoned::now().date(), why) {
            return Ok(format!("{what} already wasn't watched"));
        }
        if !cx.offline {
            sentry_core::maint::watch::save(&self.router.scope, &w)
                .map_err(|e| format!("watch.toml: {e}"))?;
        }
        self.router = self.router.clone().with_watch(w);
        self.remark(sh);
        Ok(format!(
            "sentry no longer watches {what} (watch.toml; Records › Later takes it back)"
        ))
    }

    fn row_at(&self, sh: &Shared, cx: &Cx) -> Option<String> {
        match maint::sel(&self.view(sh, cx))? {
            maint::Sel::Rec(r) => Some(r.key),
            maint::Sel::Item(i) => Some(format!("item:{}", i.id)),
        }
    }

    fn undo(&mut self, row: &LaterRow, _sh: &mut Shared, cx: &Cx) -> Result<Vec<Effect>, String> {
        match row.kind {
            LaterKind::Expected => Ok(vec![Effect::own(Own::Expected(row.key.clone(), false))]),
            // Watched again: the next audit says how it stands.
            LaterKind::Unwatched { .. } => {
                let mut w = (*self.router.watch).clone();
                if !w.remove(&row.key) {
                    return Err(format!("{} isn't in watch.toml any more", row.key));
                }
                if !cx.offline {
                    sentry_core::maint::watch::save(&self.router.scope, &w)
                        .map_err(|e| format!("watch.toml: {e}"))?;
                }
                self.router = self.router.clone().with_watch(w);
                self.fetch(Kind::Audit, cx);
                Ok(vec![Effect::Toast(format!(
                    "{}: watched again · auditing",
                    row.key
                ))])
            }
            _ => Ok(Vec::new()),
        }
    }
}

/// Claude: asked through the read gateway, told only what has been scrubbed.
impl Asks for NetworkTarget {
    /// The router's rules, for any session's steps on it: its policy classes, auto never,
    /// its output scrubbed, a secret option's value a tag.
    fn peer(&self) -> sentry_core::apply::session::Peer {
        let name = &self.router.name;
        let scope = self.router.scope.clone();
        sentry_core::apply::session::Peer {
            id: self.ident.id.clone(),
            title: self.ident.title.clone(),
            remote: true,
            refuses: sentry_core::claude::Refuses(Some(super::ask::refuses)),
            asks_each: true,
            hides: true,
            calls: [
                "sentry-network exec",
                "sentry-network run",
                "sentry network exec",
                "sentry network run",
            ]
            .iter()
            .map(|c| format!("{c} {name}"))
            .collect(),
            masks: sentry_core::apply::session::Masks(Some(std::sync::Arc::new(move |line| {
                let salt = crate::redact::Salt::load(&scope).ok();
                crate::guard::secret_tags(line, salt.as_ref())
            }))),
        }
    }

    fn describe(&self, _sh: &Shared, _cx: &Cx) -> sentry_app::system::SystemLine {
        super::ask::describe(&self.store, &self.router)
    }

    /// A secret a session holds (captured on any target, or asked for) is swept from
    /// what this target writes down, as a run's own secrets are.
    fn given(&mut self, secrets: &[String]) {
        for v in secrets {
            if !self.given.contains(v) {
                self.given.push(v.clone());
            }
        }
    }

    /// A secret one of this window's runs was given never reaches the log, whoever's
    /// words would have said it (a step's note, Claude's verdict, the user's own note).
    fn kept(&self, text: &str) -> Option<String> {
        if !self.given.iter().any(|v| text.contains(v.as_str())) {
            return None;
        }
        let salt = crate::redact::Salt::load(&self.router.scope).ok();
        Some(crate::guard::swept(text, &self.given, salt.as_ref()))
    }

    /// A plan that is kept has a guard step's secrets as tags: in its block, in its
    /// header's values, and wherever its words say one. Opened again later, that step
    /// stops and says the value must be given again (`guard::Change::parse`).
    fn plan_kept(&self, doc: &mut sentry_core::maint::plan::PlanDoc, _answer: &str) {
        use sentry_core::apply::plan::{self, Kind as StepKind};
        let salt = crate::redact::Salt::load(&self.router.scope).ok();
        let mut secrets = self.given.clone();
        let (words, block) = plan::take(&doc.body);
        let mut block = block.and_then(Result::ok);
        for vars in block
            .iter_mut()
            .flat_map(|p| p.steps.iter_mut())
            .filter_map(|s| match &mut s.kind {
                StepKind::Workflow { vars, .. } => Some(vars),
                _ => None,
            })
            .chain([&mut doc.head.vars])
        {
            for v in vars.values_mut() {
                secrets.extend(crate::guard::secrets_in(v));
                if let Some(k) = crate::guard::kept(v, salt.as_ref()) {
                    *v = k;
                }
            }
        }
        doc.body = match &block {
            Some(p) => format!(
                "{}\n\n{}",
                crate::guard::swept(&words, &secrets, salt.as_ref()),
                crate::guard::swept(&plan::to_block(p), &secrets, salt.as_ref())
            )
            .trim()
            .to_string(),
            None => crate::guard::swept(&doc.body, &secrets, salt.as_ref()),
        };
    }

    fn ask(&self, sh: &Shared, cx: &Cx) -> Result<Ask, String> {
        super::ask::ask_for(cx.screen, &self.view(sh, cx))
    }

    fn apply_ask(&self, sh: &Shared, cx: &Cx) -> Option<Ask> {
        let v = self.view(sh, cx);
        if cx.screen == ScreenId::Security {
            return super::screens::threats::apply_ask(&v);
        }
        super::ask::apply_rec(&v, &maint::pick_apply(&v)?, &|wf| sh.workflow_text(APP, wf))
    }

    /// Nothing on a network has a plan document of its own.
    fn plan_ask(&self, _item: &str, _key: String, _sh: &Shared, _cx: &Cx) -> Option<Ask> {
        None
    }

    fn review_brief(&self, cx: &Cx) -> Vec<Line<'static>> {
        let t = cx.theme;
        let name = &self.router.name;
        let notes = &self.router.cfg.notes;
        [
            (String::new(), t.fg()),
            (
                format!("  Claude reviews the upkeep of {name}'s router: the audit's findings, the firmware"),
                t.fg(),
            ),
            (
                "  against upstream, the packages, the backups, the tasks due and the maintenance log,"
                    .into(),
                t.fg(),
            ),
            ("  then writes what to do now, soon and routinely, and why.".into(), t.fg()),
            (String::new(), t.fg()),
            (
                "  It ends with how the task list should change. You see those as one list, ticked;"
                    .into(),
                t.fg(),
            ),
            ("  Enter applies them together.".into(), t.fg()),
            (String::new(), t.fg()),
            (
                format!(
                    "  It reads the web, your notes ({}), and the router read-only through the gateway.",
                    if notes.is_empty() { "none".to_string() } else { notes.join(", ") }
                ),
                t.dim(),
            ),
            (
                "  What it is sent and what it reads is scrubbed: secrets, the uplink's address, MACs,"
                    .into(),
                t.dim(),
            ),
            ("  SSIDs and unnamed hostnames never leave this machine.".into(), t.dim()),
            (
                "  Sent to Claude through your Claude Code login (Anthropic). Nothing on the router changes."
                    .into(),
                t.s(t.yellow),
            ),
            (String::new(), t.fg()),
            ("  Enter starts the review.".into(), t.s(t.cyan)),
        ]
        .into_iter()
        .map(|(l, st)| Line::styled(l, st))
        .collect()
    }

    fn review_request(&self, auto: Option<&str>, changes: &str, sh: &Shared, cx: &Cx) -> String {
        let v = View {
            filter: None,
            everything: true,
            ..self.view(sh, cx)
        };
        super::ask::review_request(&v, auto, changes)
    }

    fn profile(&self, f: ProfileFor, grants: &[Grant]) -> Profile {
        let r = &self.router;
        match f {
            ProfileFor::Chat => super::ask::profile(r).with_grants(grants),
            ProfileFor::Session => super::ask::session_profile(r).with_grants(grants),
            // From a session that started elsewhere the router is reached as from its
            // own: the same gateways, classes and scrubbing, the same denials.
            ProfileFor::Peer => super::ask::session_profile(r),
            ProfileFor::Review => super::ask::review_profile(r),
        }
    }

    fn sec_ask(&self, item: &sentry_core::secaudit::Item, sh: &Shared, cx: &Cx) -> Ask {
        super::ask::apply_audit(&self.view(sh, cx), item)
    }

    /// What a command sentry ran for Claude printed goes back scrubbed; while what must
    /// be hidden isn't known, nothing of it goes back.
    fn hides(&self, text: &str) -> Option<String> {
        let cx_free = super::ask::scrub_of(&self.store, &self.router);
        Some(match cx_free {
            Ok(s) => super::ask::scrubbed(&s, text),
            Err(_) => "(hidden: what must be scrubbed isn't known yet)".into(),
        })
    }
}

impl Host for NetworkTarget {
    /// A line of a session (a plan's step, what the user allowed), as it is run. A read
    /// goes through the gateway, like one Claude sends itself: rebuilt by sentry, its
    /// filters done here. A line the policy keeps for the guard or a workflow, or never
    /// runs, becomes a command that only says so, here, and nothing is sent to the router.
    /// Anything else is a change the user was shown and allowed: the router's shell runs
    /// it as written, as root (there is no sudo there).
    fn command(&self, line: &str) -> Cmd {
        use crate::policy::Class;
        // (What `sudo::detached` puts in front: nothing here reads stdin.)
        let inner = line.strip_prefix("exec </dev/null\n").unwrap_or(line);
        let v = crate::policy::verdict(inner);
        match v.class {
            Class::Read => {
                let exe = sentry_app::remote::workflow::exe(workflow::PROG);
                Cmd::local(&exe[0])
                    .args(exe[1..].iter().map(String::as_str))
                    .args(["run", self.router.name.as_str(), "--", inner])
            }
            Class::Change => self.router.sh(line),
            _ => Cmd::local("sh").args([
                "-c",
                "printf '%s\\n' \"$1\" >&2; exit 126",
                "sh",
                &format!(
                    "sentry-network: not run: {}",
                    v.refusal().unwrap_or(v.why.clone())
                ),
            ]),
        }
    }

    /// The login is root: nothing asks for a password.
    fn sudo_asks(&mut self, _cx: &Cx) -> Result<bool, String> {
        Ok(false)
    }

    /// Its own workflows if it has any, else the seeded ones.
    fn workflows(&self) -> (Vec<Entry>, std::path::PathBuf) {
        let scope = &self.router.scope;
        (workflow::list_for(scope), workflow::dir_for(scope))
    }

    fn begin_run(
        &mut self,
        entry: &Entry,
        vars: BTreeMap<String, String>,
        _sh: &Shared,
    ) -> Result<Box<dyn WfRun>, String> {
        for v in vars.values().flat_map(|v| crate::guard::secrets_in(v)) {
            if !self.given.contains(&v) {
                self.given.push(v);
            }
        }
        match workflow::begin_hiding(entry, &self.router, vars, &self.given) {
            Ok(s) => Ok(Box::new(s)),
            Err(e) => Err(e.to_string()),
        }
    }

    fn resume_run(&self) -> Option<Box<dyn WfRun>> {
        let s = workflow::resume(&self.router)?;
        Some(Box::new(s))
    }

    /// The login is root: no step waits on sudo.
    fn run_go(
        &mut self,
        run: &mut dyn WfRun,
        auto: bool,
        _cx: &Cx,
    ) -> Result<Option<Exec>, String> {
        let Some(s) = run.as_any_mut().downcast_mut::<Session>() else {
            return Ok(None);
        };
        let root = Some(SudoMode::Root);
        if auto { Ok(s.auto(root)) } else { s.go(root) }
    }

    /// A step ended: what it may have made (a backup) is read again, so the Items row
    /// follows the run.
    fn step_ended(&mut self, _run: &dyn WfRun, cx: &Cx) {
        self.fetch(Kind::Backup, cx);
    }

    /// No workflow reboots a router by a reboot step (the firmware's flash waits for the
    /// restart itself).
    fn reboot(&mut self, _cmd: Cmd, _old_boot: String, _cx: &Cx) -> Vec<Effect> {
        Vec::new()
    }
}
