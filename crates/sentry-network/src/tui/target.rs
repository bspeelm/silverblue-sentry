//! A network as a target of the app (`sentry_app::Target`): its router's collectors and store,
//! its screens, and how a command line becomes a `Cmd` over ssh. Everything else (the frame,
//! records, sessions, the workflow run) is the app's.
//!
//! What the app asks a target about maintenance, Claude and workflows has plain answers here
//! until those parts of the network target exist: nothing to recommend, Claude isn't set up
//! for a network, there are no workflows. They are the seams for what comes next (`Upkeep`,
//! `Asks`, and the workflow half of `Host`, at the end of this file).

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
use super::screens::{View, dashboard, history};
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
use sentry_core::tui::records::LaterRow;
use sentry_core::workflows::Entry;

pub use sentry_app::effect::Effect;

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

/// What only a network has, as effects: they travel through the app wrapped (`Effect::Own`)
/// and come back in [`Target::on_own`].
#[derive(Clone, Debug)]
pub enum Own {
    Fetch(Kind),
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
    match id {
        ScreenId::Hist => vec![Poll {
            kind: Kind::History,
            every: None,
        }],
        _ => vec![
            Poll {
                kind: Kind::Probe,
                every: Some(PROBE),
            },
            Poll {
                kind: Kind::Ifaces,
                every: Some(IFACES),
            },
        ],
    }
}

pub struct NetworkTarget {
    ident: Ident,
    pub router: Router,
    mail: Mail,
    pub store: Store,
    hist: history::History,
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
                commands: ":q  :<screen>  :log  :refresh",
                help_footer: format!(
                    "Nothing is installed on {name}'s router, and nothing keeps running there."
                ),
                privacy: format!("{NO_CLAUDE_YET}: nothing is sent."),
                session_privacy: format!("{NO_CLAUDE_YET}: nothing is sent."),
            },
            router,
            mail,
            store: Store::default(),
            hist: Default::default(),
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

    fn view<'a>(&'a self, cx: &'a Cx) -> View<'a> {
        View {
            t: cx.theme,
            s: &self.store,
            cfg: &self.router.cfg,
            name: &self.router.name,
        }
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
            self.has_ring = sentry_core::recorder::ring::path(&self.router.scope).exists();
        }
        Vec::new()
    }

    fn enter(&mut self, _from: ScreenId, now: Instant, _sh: &Shared, cx: &Cx) -> Vec<Effect> {
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

    fn on_data(&mut self, data: Box<dyn Any + Send>, _sh: &mut Shared, cx: &Cx) -> Vec<Effect> {
        let Ok(data) = data.downcast::<Data>() else {
            return Vec::new();
        };
        let Data(k, res) = *data;
        self.store.apply(k, *res);
        let fx = self.record_sample(cx);
        if k == Kind::History {
            let recorded = |h: &sentry_core::tui::histview::HistData| h.header.is_some();
            self.has_ring |= self.store.history.value.as_ref().is_some_and(recorded);
        }
        fx
    }

    /// Nothing of a network's follows the lists, a run or an edit yet.
    fn refresh(&mut self, _why: Why, _cx: &Cx) -> Vec<Effect> {
        Vec::new()
    }

    fn on_own(&mut self, fx: &effect::Own, _sh: &mut Shared, cx: &Cx) -> Vec<Effect> {
        match fx.0.downcast_ref::<Own>() {
            Some(Own::Fetch(k)) => self.fetch(*k, cx),
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

    fn handle(&mut self, a: Action, _sh: &Shared, cx: &Cx) -> Vec<Effect> {
        match cx.screen {
            ScreenId::Hist => {
                let v = View {
                    t: cx.theme,
                    s: &self.store,
                    cfg: &self.router.cfg,
                    name: &self.router.name,
                };
                self.hist.handle(a, &v)
            }
            _ => dashboard::handle(a),
        }
    }

    fn render(&mut self, f: &mut Frame, area: Rect, _sh: &Shared, cx: &Cx) {
        let v = View {
            t: cx.theme,
            s: &self.store,
            cfg: &self.router.cfg,
            name: &self.router.name,
        };
        match cx.screen {
            ScreenId::Hist => self.hist.render(f, area, &v),
            _ => dashboard::render(f, area, &v),
        }
    }

    fn hints(&self, _help: bool, _sh: &Shared, cx: &Cx) -> Hints {
        match cx.screen {
            ScreenId::Hist => history::hints(),
            _ => dashboard::hints(),
        }
    }

    fn tabs(&self, _sh: &Shared, cx: &Cx) -> Vec<TabInfo> {
        self.visible(cx.screen)
            .into_iter()
            .map(|id| TabInfo {
                id,
                badge: None,
                filterable: false,
            })
            .collect()
    }

    /// No cursor or selection to put right yet.
    fn settle(&mut self, _why: Settle, _sh: &Shared, _cx: &Cx) {}

    /// The top bar: what the router runs and how long it's been up; the connection.
    fn top(&self, cx: &Cx) -> (Vec<String>, (String, Color)) {
        let t = cx.theme;
        let v = self.view(cx);
        let mut facts = Vec::new();
        if let Some(i) = &v.s.ifaces.value {
            facts.push(format!("{} {}", i.board.distribution, i.board.version));
            facts.push(i.board.model.clone());
        }
        if let Some(p) = &v.s.probe.value {
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
        _arg: Option<&str>,
        _sh: &Shared,
        _cx: &Cx,
    ) -> Option<Vec<Effect>> {
        match cmd {
            // The app's `:wf` goes to screen 0, which a network doesn't have yet.
            "workflow" | "wf" => Some(vec![Effect::Toast(NO_WORKFLOWS_YET.into())]),
            _ => None,
        }
    }
}

// ---- What follows are the plain answers: the seams for Maintenance, Claude and workflows.

/// A review can change a network's tasks; there is nothing else of a network's to change.
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

/// Maintenance: there is no Maintenance screen for a network yet, so there are no rows, no
/// derived tasks and nothing put off that is the network's own.
impl Upkeep for NetworkTarget {
    fn derived_tasks(&self, _sh: &Shared) -> Vec<Task> {
        Vec::new()
    }

    fn with_known(&self, sh: &Shared, _cx: &Cx, f: &mut dyn FnMut(&Known)) {
        f(&Known {
            workflows: &sh.workflows,
            tasks: &sh.tasks,
            later: Some(&sh.later),
            log: &sh.log,
            now: Some(jiff::Timestamp::now()),
            ..Default::default()
        })
    }

    fn changes(&self, _sh: &Shared, _cx: &Cx) -> Box<dyn Changes> {
        Box::new(NoChanges)
    }

    fn series_step(&self, _key: &str, _sh: &Shared, _cx: &Cx) -> Option<SeriesStep> {
        None
    }

    fn task_enter(&self, _id: &str, _sh: &Shared, _cx: &Cx) -> Vec<Effect> {
        Vec::new()
    }

    fn item_kind(&self, _item: &str) -> Option<(String, String)> {
        None
    }

    fn records(&self, _sh: &Shared, _cx: &Cx) -> (Vec<LaterRow>, Option<jiff::Timestamp>) {
        (Vec::new(), None)
    }

    fn undo(&mut self, _row: &LaterRow, _sh: &mut Shared, _cx: &Cx) -> Result<Vec<Effect>, String> {
        Ok(Vec::new())
    }
}

/// Claude: not set up for a network yet. Nothing is asked, so nothing is sent; the profile
/// (never used while `ask` refuses) allows no tool at all.
impl Asks for NetworkTarget {
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
