//! A network as a target of the app (`sentry_app::Target`): its router's collectors and store,
//! its screens, and how a command line becomes a `Cmd` over ssh. Everything else (the frame,
//! records, sessions, the workflow run) is the app's.
//!
//! Maintenance lists the audit's findings and the tasks due (`Upkeep`). What the app asks a
//! target about Claude and workflows still has plain answers here: Claude isn't set up for a
//! network, there are no workflows. Those are the seams for what comes next (`Asks`, and
//! the workflow half of `Host`, at the end of this file); until then the key bar and `?`
//! offer neither (`Asks::offered`).

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
use sentry_app::effect;
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

/// What asking Claude says for now.
const NO_CLAUDE_YET: &str = "Claude isn't set up for a network yet";
/// What starting a workflow says for now.
const NO_WORKFLOWS_YET: &str = "there are no workflows for a network yet";

/// The probe: every second while the Dashboard has the window.
const PROBE: Duration = Duration::from_secs(1);
/// Board, interfaces and devices: they move slowly.
const IFACES: Duration = Duration::from_secs(30);
/// Who is on the network: while Clients is in view.
const CLIENTS: Duration = Duration::from_secs(10);
/// Which services run: the Dashboard's row.
const SERVICES: Duration = Duration::from_secs(60);
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
        ScreenId::Maint => vec![at(Kind::Report, None)],
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
    /// The samples taken become the router's metrics ring (History).
    recorder: crate::recorder::Recorder,
    /// There's a ring for this network: History is in the strip.
    has_ring: bool,
    /// The ring couldn't be written (said once).
    ring_failed: bool,
    /// When each fetch of the screen in view is next due.
    due: HashMap<Kind, Instant>,
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
                    no_claude: NO_CLAUDE_YET,
                    // A review, when there is one, is about a network, and changes its
                    // tasks only (nothing here is tracked the way a server's items are).
                    writer_place: "network",
                    server_changes: false,
                    ..Default::default()
                },
                quit: format!("Quit sentry? Nothing keeps running on {name}'s router after exit."),
                help_globals: &[],
                commands: ":q  :<screen>  :audit [now]  :log  :refresh",
                help_footer: format!(
                    "Nothing is installed on {name}'s router, and nothing keeps running there."
                ),
                privacy: format!("{NO_CLAUDE_YET}: nothing is sent."),
                session_privacy: format!("{NO_CLAUDE_YET}: nothing is sent."),
            },
            router,
            mail,
            store: Store::default(),
            screens: Screens::default(),
            audit_on_entry: false,
            recorder: Default::default(),
            has_ring: false,
            ring_failed: false,
            due: HashMap::new(),
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
            self.screens.cur(cx.screen),
        )
    }

    /// The screens with the view they act on (the view borrows the rest of the target).
    fn with_screens<R>(
        &mut self,
        sh: &Shared,
        cx: &Cx,
        f: impl FnOnce(&mut Screens, &View) -> R,
    ) -> R {
        let cur = self.screens.cur(cx.screen);
        let v = view_of(&self.store, &self.router, sh, cx, cur);
        f(&mut self.screens, &v)
    }

    fn clamp(&mut self, sh: &Shared, cx: &Cx) {
        let id = cx.screen;
        self.with_screens(sh, cx, |s, v| s.clamp(id, v));
    }

    /// Set `expected` on the stored findings an id (or pattern) covers.
    fn mark_findings(&mut self, id: &str, on: bool) {
        let reports = [
            self.store.report.value.as_mut().and_then(|r| r.as_mut()),
            self.store.shown.as_mut().and_then(|s| s.cur.as_mut()),
        ];
        for r in reports.into_iter().flatten() {
            for f in r
                .findings
                .iter_mut()
                .filter(|f| sentry_core::baseline::glob(id, &f.id))
            {
                f.expected = on;
            }
        }
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
                self.mark_findings(id, on);
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
        self.mark_findings(id, on);
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
    cur: usize,
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
        match k {
            // One list of clients from the read, once the layout is known.
            Kind::Clients => self.store.raw_pending = ok,
            Kind::Audit => fx.push(Effect::AuditEnded(ok)),
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
            Kind::Audit | Kind::Report | Kind::ReportAt(_) | Kind::Clients
        ) {
            self.clamp(sh, cx);
        }
        fx.extend(self.record_sample(cx));
        fx
    }

    fn refresh(&mut self, why: Why, cx: &Cx) -> Vec<Effect> {
        match why {
            Why::Audit => {
                self.fetch(Kind::Audit, cx);
                vec![Effect::Toast("auditing the network…".into())]
            }
            // The lists are made from the app's records as they're drawn; nothing of a
            // network's follows a run or a session yet.
            _ => Vec::new(),
        }
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
            None => {}
        }
        Vec::new()
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
        self.with_screens(sh, cx, |s, v| s.render(id, f, area, v));
    }

    fn hints(&self, help: bool, sh: &Shared, cx: &Cx) -> Hints {
        let keys = self.screens.hints(cx.screen, &self.view(sh, cx));
        // `?` on Maintenance: every row key, not only the selected row's.
        if help && cx.screen == ScreenId::Maint && self.screens.maint.view.is_none() {
            return maint::help();
        }
        keys
    }

    fn tabs(&self, sh: &Shared, cx: &Cx) -> Vec<TabInfo> {
        let v = self.view(sh, cx);
        self.visible(cx.screen)
            .into_iter()
            .map(|id| TabInfo {
                id,
                badge: self.screens.badge(id, &v),
                filterable: Screens::filterable(id),
            })
            .collect()
    }

    fn settle(&mut self, why: Settle, sh: &Shared, cx: &Cx) {
        match why {
            Settle::Key => {
                if cx.screen == ScreenId::Maint {
                    self.screens.maint.sel = maint::row_key(&self.view(sh, cx));
                }
            }
            Settle::Lists => self.clamp(sh, cx),
            Settle::Filter | Settle::FilterCleared => self.screens.reset_cursor(cx.screen),
            // No series and no workflows yet.
            Settle::Ticks(_) | Settle::Workflow(_) => {}
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
            // The app's `:wf` goes to screen 0, which a network doesn't have yet.
            "workflow" | "wf" => Some(vec![Effect::Toast(NO_WORKFLOWS_YET.into())]),
            _ => None,
        }
    }
}

// ---- Maintenance: the audit's findings and the tasks due. Then the plain answers: the
// ---- seams for Claude and workflows.

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
    /// The config's `maintenance.cadence` names workflows, and a network has none yet.
    fn derived_tasks(&self, _sh: &Shared) -> Vec<Task> {
        Vec::new()
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

    /// Nothing a network's rows do is carried out by sentry yet: no series.
    fn series_step(&self, _key: &str, _sh: &Shared, _cx: &Cx) -> Option<SeriesStep> {
        None
    }

    fn task_enter(&self, id: &str, sh: &Shared, cx: &Cx) -> Vec<Effect> {
        maint::task_enter(&self.view(sh, cx), id)
    }

    fn item_kind(&self, _item: &str) -> Option<(String, String)> {
        None
    }

    fn records(&self, sh: &Shared, cx: &Cx) -> (Vec<LaterRow>, Option<jiff::Timestamp>) {
        (Vec::new(), maint::audit_age(&self.view(sh, cx)).0)
    }

    fn undo(&mut self, row: &LaterRow, _sh: &mut Shared, _cx: &Cx) -> Result<Vec<Effect>, String> {
        match row.kind {
            LaterKind::Expected => Ok(vec![Effect::own(Own::Expected(row.key.clone(), false))]),
            _ => Ok(Vec::new()),
        }
    }
}

/// Claude: not set up for a network yet. Nothing is asked, so nothing is sent; the profile
/// (never used while `ask` refuses) allows no tool at all.
impl Asks for NetworkTarget {
    fn offered(&self) -> bool {
        false
    }

    fn ask(&self, _sh: &Shared, _cx: &Cx) -> Result<Ask, String> {
        Err(NO_CLAUDE_YET.into())
    }

    fn apply_ask(&self, _sh: &Shared, _cx: &Cx) -> Option<Ask> {
        None
    }

    fn plan_ask(&self, _item: &str, _key: String, _sh: &Shared, _cx: &Cx) -> Option<Ask> {
        None
    }

    fn review_brief(&self, cx: &Cx) -> Vec<Line<'static>> {
        vec![
            Line::raw(""),
            Line::styled(format!("  {NO_CLAUDE_YET}."), cx.theme.dim()),
        ]
    }

    fn review_request(
        &self,
        _auto: Option<&str>,
        _changes: &str,
        _sh: &Shared,
        _cx: &Cx,
    ) -> String {
        String::new()
    }

    fn profile(&self, _f: ProfileFor, _grants: &[Grant]) -> Profile {
        Profile {
            system: format!("{NO_CLAUDE_YET}. Say so, and do nothing else."),
            tools: Vec::new(),
            allowed: Vec::new(),
            denied: ["Bash", "Read", "Grep", "Glob", "Edit", "Write"]
                .map(String::from)
                .to_vec(),
            dirs: Vec::new(),
        }
    }
}

impl Host for NetworkTarget {
    /// The line as the router's shell runs it, as root (there is no sudo there).
    fn command(&self, line: &str) -> Cmd {
        self.router.sh(line)
    }

    /// The login is root: nothing asks for a password.
    fn sudo_asks(&mut self, _cx: &Cx) -> Result<bool, String> {
        Ok(false)
    }

    /// Workflows: none yet. A network's own will live under `networks/<name>/workflows/`.
    fn workflows(&self) -> (Vec<Entry>, std::path::PathBuf) {
        (
            Vec::new(),
            sentry_app::remote::workflow::own_dir(&self.router.scope),
        )
    }

    fn begin_run(
        &mut self,
        _entry: &Entry,
        _vars: BTreeMap<String, String>,
        _sh: &Shared,
    ) -> Result<Box<dyn WfRun>, String> {
        Err(NO_WORKFLOWS_YET.into())
    }

    fn resume_run(&self) -> Option<Box<dyn WfRun>> {
        None
    }

    fn run_go(
        &mut self,
        _run: &mut dyn WfRun,
        _auto: bool,
        _cx: &Cx,
    ) -> Result<Option<Exec>, String> {
        Ok(None)
    }

    /// No workflow reboots a router yet.
    fn reboot(&mut self, _cmd: Cmd, _old_boot: String, _cx: &Cx) -> Vec<Effect> {
        Vec::new()
    }
}
