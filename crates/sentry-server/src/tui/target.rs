//! A server as a target of the app (`sentry_app::Target`): what only this kind of host has.
//! Its collectors' kinds and store, its screens, the inventory read with sudo, the queue of
//! reads Claude asks for, tracking and ignoring what discovery finds, the sudo checks, its
//! prompts and profiles, and how a command line becomes a `Cmd` over ssh. Everything else
//! (sessions, series, reviews, plans, records, the workflow run, the frame) is the app's.
//! `upkeep` holds what its maintenance lists hold and what Claude is asked and allowed.

use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::text::Line;

mod upkeep;

use super::SCREENS;
use super::data::{Data, Kind, Store};
use super::planview;
use super::screens::{Screens, View};
use crate::maint::tracked::{self, Tracked};
use crate::remote::{Remote, SudoMode};
use crate::workflow::{self, Session};
use sentry_app::effect::{self, ReadsFor};
use sentry_app::run::{Exec, LogKind, WfRun};
use sentry_app::shared::Shared;
use sentry_app::target::{
    Asks, Changes, Cx, Hints, Host, Ident, Mail, ProfileFor, SeriesStep, Settle, TabInfo, Target,
    Upkeep, Why,
};
use sentry_core::claude::{self, Ask, Grant, Profile};
use sentry_core::exec::{Cmd, ExecError, StreamMsg};
use sentry_core::maint::changes::{Change, Known};
use sentry_core::maint::tasks::Task;
use sentry_core::tui::ScreenId;
use sentry_core::tui::keys::Action;
use sentry_core::tui::records::{LaterKind, LaterRow};
use sentry_core::workflows::Entry;

pub use sentry_app::effect::{Choice, Effect, Modal, WfCmd};

/// The program's name: its chip, and whose workflows Claude is told about.
const APP: &str = "sentry-server";

/// Streamed in the pane (after a confirm).
#[derive(Clone, Debug)]
pub struct RunSpec {
    pub title: String,
    pub cmd: Cmd,
    /// What to re-read when it exits.
    pub then: Vec<Kind>,
    /// It reboots the server: wait for it to come back.
    pub reboot: bool,
    /// It needs root: this line (with sudo in it) is what runs, with the server's password
    /// when sudo wants one.
    pub root: Option<String>,
}

/// What only a server has, as effects: they travel through the app wrapped
/// (`Effect::Own`) and come back in [`Target::on_own`] or [`Target::after_suspend`].
#[derive(Clone, Debug)]
pub enum Own {
    Fetch(Kind),
    Expected(String, bool),
    /// `b` on Network: a port's listeners (their baseline keys) and its finding are expected
    /// from now on, or not any more. `what` names the port for the toast.
    ListenExpected {
        keys: Vec<String>,
        id: String,
        what: String,
        on: bool,
    },
    /// Read what needs root (`I`), with the server's password when sudo wants one.
    Inventory,
    /// The user skipped the reads a review waits for: Claude writes it without them.
    ReadsSkipped,
    /// Track what discovery found (written to servers/<name>/items.toml).
    Track(Box<crate::config::MaintItem>),
    /// Don't suggest it again: (discovery key, its id).
    Ignore(String, String),
    /// Stop tracking an item (one of sentry-server's own; a YAML one is edited there).
    Untrack(String),
    /// Ask Claude how to fix an audit finding (the consent box first).
    FixFinding(String),
    /// Select the first Maintenance recommendation whose key starts with this.
    MaintFind(String),
    /// Select an item's row on Maintenance.
    MaintJump(String),
    /// The audit report, over Maintenance (`:audit`).
    OpenReport,
    /// A review changed what's tracked: take it in.
    ItemsChanged(Tracked),
    /// A streamed reboot command exited: wait for the server to come back.
    RebootWait,
    /// The inventory was read: its output comes back with this.
    AfterInventory,
    /// Claude's reads ran: their output comes back with this.
    AfterReads(Vec<Vec<String>>, ReadsFor),
}

impl From<Own> for Effect {
    fn from(o: Own) -> Self {
        Effect::own(o)
    }
}

/// The screens' effects of the server's own, made the way the shared ones are written.
impl Own {
    pub fn fetch(k: Kind) -> Effect {
        Own::Fetch(k).into()
    }
    pub fn expected(id: String, on: bool) -> Effect {
        Own::Expected(id, on).into()
    }
    pub fn track(item: crate::config::MaintItem) -> Effect {
        Own::Track(Box::new(item)).into()
    }
    pub fn ignore(key: String, id: String) -> Effect {
        Own::Ignore(key, id).into()
    }
    pub fn untrack(id: String) -> Effect {
        Own::Untrack(id).into()
    }
    pub fn fix_finding(id: String) -> Effect {
        Own::FixFinding(id).into()
    }
    pub fn maint_find(prefix: String) -> Effect {
        Own::MaintFind(prefix).into()
    }
    pub fn maint_jump(id: String) -> Effect {
        Own::MaintJump(id).into()
    }
    /// Stream a command's output into the pane.
    pub fn run(spec: RunSpec) -> Effect {
        // ssh drops as the server goes down: the wait starts when the command exits.
        let then = if spec.reboot {
            vec![Own::RebootWait.into()]
        } else {
            spec.then.into_iter().map(Own::fetch).collect()
        };
        Effect::Run(effect::RunSpec {
            title: spec.title,
            cmd: spec.cmd,
            then,
            reboot: spec.reboot,
            queue: Vec::new(),
            end: None,
            root: spec.root,
        })
    }
    /// The server's own effect inside one that came back.
    pub fn of(e: &Effect) -> Option<&Own> {
        match e {
            Effect::Own(o) => o.0.downcast_ref(),
            _ => None,
        }
    }
}

pub struct ServerTarget {
    ident: Ident,
    pub remote: Remote,
    /// What ssh resolves its alias to (looked up once, for `describe`).
    pub(crate) resolved: std::cell::OnceCell<Vec<String>>,
    mail: Mail,
    pub store: Store,
    pub screens: Screens,
    /// The samples taken become the server's metrics ring (History).
    recorder: crate::recorder::Recorder,
    /// There's a ring for this server: History is in the strip.
    has_ring: bool,
    /// The ring couldn't be written (said once).
    ring_failed: bool,
    /// When each fetch of the screen in view is next due.
    due: HashMap<Kind, Instant>,
    /// While waiting for a reboot: when the boot id is read next.
    reboot_probe: Option<Instant>,
    /// Rebooting: since when, and the boot id it had.
    reboot_wait: Option<(Instant, String)>,
    /// The stream id of a workflow's reboot command.
    wf_reboot_id: Option<u64>,
    /// When the last inventory was read.
    pub(super) inventory_at: Option<jiff::Timestamp>,
    /// After the log note: offer to read the server again (the run changed what was read).
    offer_reread: bool,
}

impl ServerTarget {
    /// The target's id for a server's name.
    pub fn id_of(name: &str) -> String {
        format!("srv:{name}")
    }

    pub fn new(remote: Remote, mail: Mail) -> Self {
        let name = remote.name.clone();
        Self {
            resolved: Default::default(),
            ident: Ident {
                id: Self::id_of(&name),
                title: name.clone(),
                scope: name.clone(),
                place: "the server",
                word: "server",
                app: APP,
                screens: &SCREENS,
                runs: workflow::root(&name),
                // Until the workflows are read: where the seeded ones are.
                wf_dir: "~/.config/sentry/server-workflows/".into(),
                ways: Default::default(),
                quit: format!("Quit sentry-server? Nothing keeps running on {name} after exit."),
                help_globals: &[("I", "read what needs root (your sudo password, asked once)")],
                commands: ":q  :<screen>  :workflow <name>  :audit [now]  :log  :refresh",
                help_footer: format!("Nothing keeps running on {name} after sentry-server exits."),
                privacy: format!(
                    "Claude may run read-only commands on {name} through `sentry-server exec` (nothing \
                     that changes it); it can't use ssh."
                ),
                session_privacy: format!(
                    "Claude may run any command on {name} that needs no root (through `sentry-server \
                     run`, as your login). sudo, and every step of a plan, asks you first; it can't \
                     use ssh, turn the server off or read files that may hold secrets."
                ),
            },
            remote: remote.with_inventory(),
            mail,
            store: Store::default(),
            screens: Screens::default(),
            recorder: Default::default(),
            has_ring: false,
            ring_failed: false,
            due: HashMap::new(),
            reboot_probe: None,
            reboot_wait: None,
            wf_reboot_id: None,
            inventory_at: None,
            offer_reread: false,
        }
    }

    fn fetch(&mut self, k: Kind, cx: &Cx) {
        if cx.offline {
            return;
        }
        self.store.fetch(k, &self.remote, &self.mail);
    }

    fn view<'a>(&'a self, sh: &'a Shared, cx: &'a Cx) -> View<'a> {
        self.view_at(sh, cx, self.screens.cur(cx.screen))
    }

    /// The view with `cur` as the row selected on the screen in view.
    fn view_at<'a>(&'a self, sh: &'a Shared, cx: &'a Cx, cur: usize) -> View<'a> {
        view_of(&self.store, &self.remote, self.inventory_at, sh, cx, cur)
    }

    /// The view with no `/` filter: a review is about everything on the list.
    fn view_all<'a>(&'a self, sh: &'a Shared, cx: &'a Cx) -> View<'a> {
        View {
            filter: None,
            everything: true,
            ..self.view(sh, cx)
        }
    }

    /// The screens with the view they act on (the view borrows the rest of the target).
    fn with_screens<R>(
        &mut self,
        sh: &Shared,
        cx: &Cx,
        f: impl FnOnce(&mut Screens, &View, &Remote) -> R,
    ) -> R {
        let cur = self.screens.cur(cx.screen);
        let v = view_of(&self.store, &self.remote, self.inventory_at, sh, cx, cur);
        f(&mut self.screens, &v, &self.remote)
    }

    /// The lists changed: Maintenance stays on the row it was on, and the cursor in view
    /// stays inside its list.
    fn clamp(&mut self, sh: &Shared, cx: &Cx) {
        let id = cx.screen;
        self.with_screens(sh, cx, |s, v, _| s.clamp(id, v));
    }

    /// A sample just arrived (the Dashboard's probe, or Processes'): it goes towards the
    /// server's ring, one record every ten seconds. Nothing is read for this.
    fn record_sample(&mut self, cx: &Cx) -> Vec<Effect> {
        use crate::recorder::{fresh, root_pct, write};
        let Some(s) = self.store.sampled.take() else {
            return Vec::new();
        };
        let st = &self.store;
        let Some(p) = &st.probe.value else {
            return Vec::new();
        };
        let now = Instant::now();
        let temp = fresh(
            st.temp.value.as_ref().and_then(|t| t.as_ref()),
            st.temp.at,
            now,
        );
        let gpu = fresh(
            st.gpu.value.as_ref().and_then(|g| g.as_ref()),
            st.gpu.at,
            now,
        );
        let Some(rec) = self.recorder.feed(
            jiff::Timestamp::now().as_second(),
            s.cpu,
            s.rx,
            s.tx,
            p,
            temp.map(|t| t.c),
            gpu.map(|g| (g.util, g.temp)),
            st.disks.value.as_deref().and_then(root_pct),
        ) else {
            return Vec::new();
        };
        match write(&self.remote.name, cx.offline, &rec) {
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
    /// it), as in sentry.
    fn visible(&self, screen: ScreenId) -> Vec<ScreenId> {
        SCREENS
            .ids
            .iter()
            .copied()
            .filter(|s| *s != ScreenId::Hist || self.has_ring || screen == ScreenId::Hist)
            .collect()
    }

    /// While rebooting: a probe with a new boot id means it's back.
    fn check_back(&mut self, cx: &Cx) -> Vec<Effect> {
        let Some((since, old)) = &self.reboot_wait else {
            return Vec::new();
        };
        let Some(p) = &self.store.probe.value else {
            return Vec::new();
        };
        if p.boot_id != *old && !old.is_empty() {
            let secs = since.elapsed().as_secs();
            self.reboot_wait = None;
            self.store.reset_boot();
            for k in [Kind::Host, Kind::Apt, Kind::Units, Kind::Docker] {
                self.fetch(k, cx);
            }
            return vec![Effect::Rebooted(format!(
                "✓ {} is back after {secs} s",
                self.remote.name
            ))];
        }
        Vec::new()
    }

    /// The boot id the last probe saw.
    fn boot_id(&self) -> String {
        self.store
            .probe
            .value
            .as_ref()
            .map(|p| p.boot_id.clone())
            .unwrap_or_default()
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

    /// `b` on a finding (or `B`, a pattern): into the baseline file, or out of it.
    fn expected(&mut self, id: &str, on: bool, sh: &mut Shared, cx: &Cx) -> Vec<Effect> {
        let toast = |s: &str| vec![Effect::Toast(s.to_string())];
        // What's in memory is the file as last read; tests write nothing.
        let mut b = sh.baseline.clone();
        let changed = crate::audit::set_expected_in(&mut b, id, on);
        let saved = if changed && !cx.offline {
            b.save(&self.remote.name).map(|_| true)
        } else {
            Ok(changed)
        };
        if saved.is_ok() {
            sh.baseline = b;
        }
        match saved {
            // Still expected by something else: a pattern, or the config.
            Ok(false) if !on => {
                toast("expected by a pattern or server_config.yaml: change it there")
            }
            Ok(_) => {
                self.mark_findings(id, on);
                self.clamp(sh, cx);
                toast(if on {
                    "marked expected"
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
            && let Err(e) = b.save(&self.remote.name)
        {
            return toast(format!("couldn't save: {e}"));
        }
        sh.baseline = b;
        if on {
            self.mark_findings(id, true);
            self.clamp(sh, cx);
            return toast(format!("{what}: expected (baseline.toml)"));
        }
        // Still expected: the config says so, which sentry-server doesn't rewrite.
        let cfg = &self.remote.cfg;
        let still = cfg
            .findings
            .iter()
            .any(|g| sentry_core::baseline::glob(g, id))
            || keys.iter().any(|k| {
                cfg.listeners
                    .iter()
                    .any(|p| sentry_core::baseline::listener_entry_matches(p, k))
            });
        if still {
            toast("still expected by server_config.yaml".into())
        } else {
            self.mark_findings(id, false);
            self.clamp(sh, cx);
            toast(format!("{what}: no longer expected"))
        }
    }

    /// After `e`: read server_config.yaml again; on an error, keep what was loaded.
    fn reload_config(&mut self, cx: &Cx) -> Vec<Effect> {
        let loaded = crate::config::load().and_then(|(f, w)| {
            let s = f.servers.get(&self.remote.name).cloned().ok_or_else(|| {
                format!("{} is no longer in server_config.yaml", self.remote.name)
            })?;
            Ok((s, w))
        });
        let said = match loaded {
            Ok((s, warnings)) => {
                let problems = crate::config::lint(&self.remote.name, &s);
                self.remote = Remote::new(&self.remote.name, &s).with_inventory();
                self.fetch(Kind::Maint, cx);
                match warnings.iter().chain(&problems).next() {
                    Some(p) => format!("reloaded · {p}"),
                    None => "server_config.yaml reloaded".into(),
                }
            }
            Err(e) => format!("not reloaded: {e}"),
        };
        vec![Effect::Toast(said)]
    }

    /// After a run that changed the server: what Maintenance and Containers show was read
    /// with sudo before it. With the password held it's read again by itself (a read);
    /// without, `I` does it.
    fn reread(&mut self, cx: &Cx) -> Vec<Effect> {
        if !std::mem::take(&mut self.offer_reread) {
            return Vec::new();
        }
        if cx.root {
            return vec![Own::Inventory.into()];
        }
        vec![Effect::Toast(
            "what was read with sudo is from before this change · I reads it again".into(),
        )]
    }

    /// `I`: read what needs root, once (the password is asked for if sudo wants one and
    /// none is held; they are all reads, so nothing else is asked).
    fn inventory(&mut self, mode: Option<SudoMode>) -> Vec<Effect> {
        let toast = |s: &str| vec![Effect::Toast(s.to_string())];
        match mode {
            Some(SudoMode::NoPasswd) => {
                return toast("sudo doesn't ask for a password here: it's all read live");
            }
            Some(SudoMode::Absent) => return toast("this login has no sudo on the server"),
            _ => {}
        }
        if crate::inventory::script(&self.remote).is_empty() {
            return toast("nothing to read: no sudo: entries in server_config.yaml");
        }
        vec![Own::Inventory.into()]
    }

    fn after_inventory(&mut self, out: Result<String, String>, cx: &Cx) -> Vec<Effect> {
        let toast = |s: String| vec![Effect::Toast(s)];
        let inv = match out {
            Ok(text) => crate::inventory::parse(&text),
            Err(e) => return toast(format!("the read didn't finish: {e}")),
        };
        if inv.outputs.is_empty() {
            return toast("nothing was read: nothing changed".into());
        }
        let n = inv.outputs.len();
        match crate::inventory::save(&self.remote.name, &inv) {
            Ok(at) => self.inventory_at = Some(at),
            Err(e) => return toast(format!("couldn't save it: {e}")),
        }
        for k in [
            Kind::Docker,
            Kind::Smart,
            Kind::Jails,
            Kind::Crowdsec,
            Kind::Journal,
            Kind::Listeners,
            Kind::Maint,
        ] {
            self.fetch(k, cx);
        }
        toast(format!(
            "read {n} command(s) with sudo · c on Maintenance audits with them"
        ))
    }

    /// How sudo behaves right now, checked again (the server's sudoers can change while this
    /// is open); tests use what the store has.
    fn fresh_sudo(&mut self, cx: &Cx) -> Option<SudoMode> {
        if !cx.offline {
            let m = self.remote.sudo_mode();
            self.store.sudo.set(m);
        }
        self.store.sudo.value
    }

    /// The reads Claude asked for that need root: all on the gateway's read-only list, so
    /// with the password held they run by themselves; without, the one prompt covers them.
    fn root_reads(&self, reads: Vec<Vec<String>>, to: ReadsFor) -> Vec<Effect> {
        let first = reads
            .first()
            .map(|argv| argv.iter().take(2).cloned().collect::<Vec<_>>().join(" "))
            .unwrap_or_default();
        let what = match reads.len() {
            1 => format!("for Claude's read: {first}"),
            n => format!("for Claude's {n} reads: {first}, …"),
        };
        vec![Effect::RootRead(effect::RootRead {
            what,
            line: crate::inventory::root_line(&crate::inventory::reads_script(&reads)),
            skipped: match to {
                // The plan waits for an answer either way.
                ReadsFor::Plan => vec![Own::ReadsSkipped.into()],
                ReadsFor::Chat => Vec::new(),
            },
            own: effect::Own(std::rc::Rc::new(Own::AfterReads(reads, to))),
        })]
    }

    /// The reads ran: send their output back to Claude.
    fn after_reads(
        &mut self,
        reads: &[Vec<String>],
        to: ReadsFor,
        out: Result<String, String>,
    ) -> Vec<Effect> {
        let toast = |s: String| vec![Effect::Toast(s)];
        let inv = match out {
            Ok(text) => crate::inventory::parse(&text),
            Err(e) => return toast(format!("the reads didn't run: {e}")),
        };
        if inv.outputs.is_empty() {
            return toast("nothing was read".into());
        }
        let mut text = String::from(
            "Here is the output of the commands you asked to read with sudo (I ran them):\n",
        );
        for argv in reads {
            let line = argv
                .iter()
                .map(|a| sentry_core::exec::sh_quote(a))
                .collect::<Vec<_>>()
                .join(" ");
            let Some(c) = inv.outputs.get(&line) else {
                continue;
            };
            let out: Vec<&str> = c.out.lines().collect();
            let shown = if out.len() > 300 {
                format!(
                    "{}\n… ({} more lines cut)",
                    out[out.len() - 300..].join("\n"),
                    out.len() - 300
                )
            } else {
                out.join("\n")
            };
            text.push_str(&format!("\n$ sudo {line}   (exit {})\n{shown}\n", c.code));
        }
        text.push_str("\nContinue from here.");
        match to {
            ReadsFor::Plan => vec![Effect::WriterFollow(planview::reads_back(&text))],
            // Said by the app if the conversation was closed meanwhile.
            ReadsFor::Chat => vec![Effect::ChatTurn(text)],
        }
    }

    fn item_ids(&self) -> Vec<String> {
        self.remote
            .cfg
            .maintenance
            .items
            .iter()
            .map(|i| i.id.clone())
            .collect()
    }

    /// A workflow for Claude: what it does and its steps, in order.
    fn steps_text<'a>(sh: &'a Shared) -> impl Fn(&str) -> String + 'a {
        |wf| sh.workflow_text(APP, wf)
    }
}

/// The view over a store (a free function, so the screens can be borrowed beside it).
fn view_of<'a>(
    store: &'a Store,
    remote: &'a Remote,
    inventory_at: Option<jiff::Timestamp>,
    sh: &'a Shared,
    cx: &'a Cx,
    cur: usize,
) -> View<'a> {
    View {
        t: cx.theme,
        s: store,
        sh,
        cfg: &remote.cfg,
        name: &remote.name,
        cur,
        now: cx.now,
        filter: cx
            .filter
            .filter(|f| !f.is_empty() && Screens::filterable(cx.screen)),
        inventory: inventory_at.filter(|_| store.sudo.value == Some(SudoMode::Password)),
        inventory_stale: inventory_at
            .zip(cx.last_change)
            .is_some_and(|(read, changed)| read < changed),
        upstream: store.upstream_at,
        everything: cx.everything,
        auto: cx.auto,
        plans: &sh.plans,
        wf: cx.run.and_then(|r| r.as_any().downcast_ref::<Session>()),
        wf_list: &sh.wf_list,
    }
}

impl Target for ServerTarget {
    fn ident(&self) -> &Ident {
        &self.ident
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn start(&mut self, _sh: &mut Shared, cx: &Cx) -> Vec<Effect> {
        self.fetch(Kind::Host, cx);
        self.fetch(Kind::Sudo, cx);
        if !cx.offline {
            let name = &self.remote.name;
            sentry_core::maint::retention::cap_reports(
                &crate::audit::reports_dir(name),
                sentry_core::config::Config::load().0.retention.reports,
            );
            self.inventory_at = crate::inventory::load(name).map(|c| c.fetched_at);
            self.store.upstream_at = crate::maint::upstream::load(name).map(|c| c.fetched_at);
            self.has_ring = sentry_core::recorder::ring::path(name).exists();
            // After the review dates were read: the old plans' file also held them.
            crate::maint::migrate_plans(name);
        }
        Vec::new()
    }

    fn enter(&mut self, from: ScreenId, now: Instant, sh: &Shared, cx: &Cx) -> Vec<Effect> {
        let id = cx.screen;
        // Arriving at Maintenance from elsewhere: its list, not a view left open.
        if id == ScreenId::Maint && from != ScreenId::Maint {
            self.screens.maint.view = None;
        }
        self.due.clear();
        for p in Screens::polls(id, &self.remote.cfg) {
            self.fetch(p.kind, cx);
            if let Some(every) = p.every {
                self.due.insert(p.kind, now + every);
            }
        }
        // A process's share of a core needs two samples: the second comes sooner.
        if id == ScreenId::Proc {
            self.due
                .insert(Kind::Procs, now + super::screens::processes::SECOND);
        }
        self.with_screens(sh, cx, |s, v, _| s.on_enter(id, v))
    }

    fn due(&mut self, now: Instant, cx: &Cx) -> bool {
        if self.reboot_wait.is_some() && self.reboot_probe.is_none_or(|t| now >= t) {
            // Every 2 s on any screen until the boot id changes.
            self.fetch(Kind::Probe, cx);
            self.reboot_probe = Some(now + Duration::from_secs(2));
        }
        // Only what the screen in view polls, and only while the server has the window.
        if !cx.focused {
            return false;
        }
        for p in Screens::polls(cx.screen, &self.remote.cfg) {
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
        // Out of view only the wait for a reboot sets a time.
        let mut due = self.due.values().copied().min().filter(|_| cx.focused);
        if let Some(t) = self.reboot_probe.filter(|_| self.reboot_wait.is_some()) {
            due = Some(due.map_or(t, |d| d.min(t)));
        }
        due
    }

    fn on_data(&mut self, data: Box<dyn Any + Send>, _sh: &mut Shared, cx: &Cx) -> Vec<Effect> {
        let Ok(data) = data.downcast::<Data>() else {
            return Vec::new();
        };
        let Data(k, res) = *data;
        let mut fx = Vec::new();
        if k == Kind::Upstream && res.is_ok() {
            fx.push(Effect::Toast("newer versions looked up".into()));
            self.fetch(Kind::Maint, cx);
        }
        if k == Kind::Audit && res.is_ok() {
            fx.push(Effect::Toast("audit done · report saved".into()));
        }
        if k == Kind::Audit
            && let Err(e) = res.as_ref()
        {
            fx.push(Effect::Toast(format!("audit failed: {e}")));
        }
        let ok = res.is_ok();
        self.store.apply(k, *res);
        if k == Kind::Audit {
            fx.push(Effect::AuditEnded(ok));
        }
        // What a review at start is told about: the host and the items.
        if self.store.host.value.is_some() && self.store.maint.value.is_some() {
            fx.push(Effect::Loaded);
        }
        if k == Kind::Probe {
            fx.extend(self.check_back(cx));
        }
        fx.extend(self.record_sample(cx));
        if k == Kind::History {
            let recorded = |h: &sentry_core::tui::histview::HistData| h.header.is_some();
            self.has_ring |= self.store.history.value.as_ref().is_some_and(recorded);
        }
        fx
    }

    fn on_stream(&mut self, id: u64, m: &StreamMsg, _cx: &Cx) -> Option<Vec<Effect>> {
        if self.wf_reboot_id != Some(id) {
            return None;
        }
        // The reboot command's own output and its exit (255 as ssh drops) are expected.
        Some(match m {
            StreamMsg::Exit { .. } => vec![Effect::RunNote(
                "… waiting for the server to come back".into(),
                LogKind::Info,
            )],
            _ => Vec::new(),
        })
    }

    fn refresh(&mut self, why: Why, cx: &Cx) -> Vec<Effect> {
        match why {
            Why::Lists => self.fetch(Kind::Maint, cx),
            Why::Step => {
                for k in [Kind::Units, Kind::Docker] {
                    self.fetch(k, cx);
                }
            }
            // What the run changed shows at once: the updates waiting, the kernel, the
            // services and containers, and each item's standing (a retirement done).
            Why::Run => {
                for k in [
                    Kind::Host,
                    Kind::Apt,
                    Kind::Units,
                    Kind::Docker,
                    Kind::Maint,
                ] {
                    self.fetch(k, cx);
                }
            }
            // What was read with sudo is from before this run: offer to read it again.
            Why::Changed => {
                self.offer_reread = self.store.sudo.value == Some(SudoMode::Password)
                    && self.inventory_at.is_some();
            }
            // Findings on a server are verified by Claude's own read-only check.
            Why::Reaudit => {}
            // Nothing of the server's follows the log or the baseline file.
            Why::Logged | Why::Baseline => {}
            Why::Audit => {
                self.fetch(Kind::Audit, cx);
                return vec![Effect::Toast("auditing… (a few seconds)".into())];
            }
            Why::Edited => return self.reload_config(cx),
        }
        Vec::new()
    }

    fn on_own(&mut self, fx: &effect::Own, sh: &mut Shared, cx: &Cx) -> Vec<Effect> {
        let Some(own) = fx.0.downcast_ref::<Own>() else {
            return Vec::new();
        };
        let name = self.remote.name.clone();
        let toast = |s: String| vec![Effect::Toast(s)];
        match own {
            Own::Fetch(k) => {
                self.fetch(*k, cx);
                if *k == Kind::Audit {
                    return toast("auditing… (a few seconds)".into());
                }
                Vec::new()
            }
            // `id` may be a pattern (`B`: `srv:container:*`).
            Own::Expected(id, on) => self.expected(id, *on, sh, cx),
            Own::ListenExpected { keys, id, what, on } => {
                self.listen_expected(keys, id, what, *on, sh, cx)
            }
            Own::Inventory => vec![Effect::RootRead(effect::RootRead {
                what: format!("to read what needs root on {name}"),
                line: crate::inventory::root_line(&crate::inventory::script(&self.remote)),
                skipped: Vec::new(),
                own: effect::Own(std::rc::Rc::new(Own::AfterInventory)),
            })],
            Own::ReadsSkipped => vec![Effect::WriterFollow(planview::reads_skipped())],
            Own::Track(item) => {
                let id = item.id.clone();
                match tracked::track(&name, (**item).clone()) {
                    Ok(()) => {
                        let mut fx = self.reload_config(cx);
                        fx.push(Effect::Toast(format!(
                            "tracking {id} (servers/{name}/items.toml)"
                        )));
                        fx
                    }
                    Err(e) => toast(format!("couldn't track it: {e}")),
                }
            }
            Own::Ignore(key, id) => match tracked::ignore(&name, key) {
                Ok(()) => {
                    self.store.maint_found.candidates.retain(|c| &c.key != key);
                    toast(format!("{id} won't be suggested again"))
                }
                Err(e) => toast(format!("couldn't save it: {e}")),
            },
            Own::Untrack(id) => match tracked::untrack(&name, id) {
                Ok(true) => {
                    let mut fx = self.reload_config(cx);
                    fx.push(Effect::Toast(format!("{id}: no longer tracked")));
                    fx
                }
                Ok(false) => toast(format!(
                    "{id} is in server_config.yaml: remove it there (e opens it)"
                )),
                Err(e) => toast(format!("couldn't save it: {e}")),
            },
            Own::FixFinding(id) => {
                if !claude::available() {
                    return toast("Claude Code isn't installed (or not on PATH)".into());
                }
                let v = self.view(sh, cx);
                match super::screens::maint::finding(&v, id) {
                    Some(f) => vec![Effect::AskConsent(Box::new(super::ask::ask_finding(
                        &v,
                        &self.remote,
                        f,
                    )))],
                    None => Vec::new(),
                }
            }
            Own::MaintFind(prefix) => {
                let v = self.view(sh, cx);
                let at = super::screens::maint::recs(&v)
                    .iter()
                    .position(|r| r.key.starts_with(prefix.as_str()))
                    .map(|i| (i, super::screens::maint::row_key_at(&v, i)));
                match at {
                    Some((i, key)) => self.screens.maint.select(i, key),
                    // Not read yet: selected when it's there.
                    None => self.screens.maint.find = Some(prefix.clone()),
                }
                Vec::new()
            }
            Own::MaintJump(id) => {
                let row = super::screens::maint::row_of(&self.view(sh, cx), id);
                if let Some(i) = row {
                    self.screens.maint.select(i, Some(format!("item:{id}")));
                }
                Vec::new()
            }
            Own::OpenReport => self.screens.maint.open_report(),
            Own::ItemsChanged(items) => {
                // What was tracked or ignored isn't "found" any more.
                self.store.maint_found.candidates.retain(|c| {
                    !items.ignore.contains(&c.key) && !items.items.iter().any(|i| i.id == c.item.id)
                });
                if cx.offline {
                    self.remote.cfg = tracked::merged(&self.remote.cfg, items).into();
                    if let Some(st) = self.store.maint.value.as_mut() {
                        st.retain(|s| !items.untracked.contains(&s.id));
                    }
                    Vec::new()
                } else {
                    self.reload_config(cx)
                }
            }
            Own::RebootWait => {
                // ssh drops (255) as the server goes down: that's the reboot happening.
                self.reboot_wait = Some((Instant::now(), self.boot_id()));
                vec![Effect::PaneLine(
                    "… waiting for the server to come back".into(),
                )]
            }
            // These come back through `root_read`.
            Own::AfterInventory | Own::AfterReads(..) => Vec::new(),
        }
    }

    fn root_read(
        &mut self,
        own: &effect::Own,
        out: Result<String, String>,
        _sh: &mut Shared,
        cx: &Cx,
    ) -> Vec<Effect> {
        match own.0.downcast_ref::<Own>() {
            Some(Own::AfterReads(reads, to)) => self.after_reads(reads, *to, out),
            Some(Own::AfterInventory) => self.after_inventory(out, cx),
            _ => Vec::new(),
        }
    }

    /// Nothing of the server's has the terminal: sudo never does.
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
        if a == Action::Char('I') {
            let m = self.fresh_sudo(cx);
            return self.inventory(m);
        }
        // The rest is the screen's: moving, Enter, r, c and its own letters.
        let id = cx.screen;
        if let Action::Char(c) = a
            && self.with_screens(sh, cx, |s, v, _| s.uses_root(id, c, v))
        {
            self.fresh_sudo(cx);
        }
        self.with_screens(sh, cx, |s, v, r| s.handle(id, a, v, r))
    }

    fn render(&mut self, f: &mut Frame, area: Rect, sh: &Shared, cx: &Cx) {
        let id = cx.screen;
        self.with_screens(sh, cx, |s, v, _| s.render(id, f, area, v));
    }

    fn hints(&self, help: bool, sh: &Shared, cx: &Cx) -> Hints {
        let mut keys = self.screens.hints(cx.screen, &self.view(sh, cx));
        if !help {
            keys.extend(super::actions::hints(cx.screen));
            // sudo asks for a password: say where the root-only data comes from.
            if self.store.sudo.value == Some(SudoMode::Password) {
                keys.push(("I", "read as root"));
            }
            return keys;
        }
        // Maintenance: every row key, not only the selected row's.
        if cx.screen == ScreenId::Maint {
            let row = ["Enter", "p", "P", "t", "d", "e", "m", "x", "B", "z", "A"];
            keys = sentry_core::tui::maintlist::GRAMMAR
                .iter()
                .copied()
                .chain(keys.into_iter().filter(|(k, _)| !row.contains(k)))
                // Not on the key bar, to keep it to what the row takes.
                .chain([
                    ("F", "the audit report"),
                    ("w", "the workflows (0)"),
                    ("e", "edit server_config.yaml (on an item)"),
                ])
                .collect();
        }
        keys.extend(super::actions::hints(cx.screen));
        keys
    }

    fn tabs(&self, sh: &Shared, cx: &Cx) -> Vec<TabInfo> {
        let v = self.view(sh, cx);
        self.visible(cx.screen)
            .into_iter()
            .map(|id| TabInfo {
                id,
                badge: match id {
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
                    self.screens.maint.sel = super::screens::maint::row_key(&view_of(
                        &self.store,
                        &self.remote,
                        self.inventory_at,
                        sh,
                        cx,
                        self.screens.cur(cx.screen),
                    ));
                }
            }
            Settle::Lists => self.clamp(sh, cx),
            Settle::Filter | Settle::FilterCleared => self.screens.reset_cursor(cx.screen),
            Settle::Ticks(left) => self.screens.maint.ticks = left.into_iter().collect(),
            Settle::Workflow(i) => self.screens.upgrade.cur.sel = i,
        }
    }

    /// The top bar: what the server runs and how long it's been up; the connection.
    fn top(&self, cx: &Cx) -> (Vec<String>, (String, Color)) {
        let t = cx.theme;
        let s = &self.store;
        let mut facts = Vec::new();
        if let Some((os, kernel)) = &s.host.value {
            facts.push(os.clone());
            facts.push(format!("kernel {kernel}"));
        }
        if let Some(p) = &s.probe.value {
            facts.push(format!("up {}", sentry_core::fmt::uptime(p.uptime_s)));
        }
        let state = match &s.unreachable {
            Some(_) => ("○ unreachable · retrying".to_string(), t.red),
            None if s.rebooted() => ("● rebooted".to_string(), t.mag),
            None if s.probe.value.is_some() || s.host.value.is_some() => {
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
        match (cmd, arg) {
            ("audit", Some("now")) => Some(vec![Own::fetch(Kind::Audit)]),
            // The audit report, over Maintenance.
            ("audit", None) => Some(vec![Effect::Goto(ScreenId::Maint), Own::OpenReport.into()]),
            _ => None,
        }
    }
}

impl Host for ServerTarget {
    fn command(&self, line: &str) -> Cmd {
        self.remote.sh(line)
    }

    fn sudo_asks(&mut self, cx: &Cx) -> Result<bool, String> {
        match self.fresh_sudo(cx) {
            Some(SudoMode::NoPasswd | SudoMode::Root) => Ok(false),
            Some(SudoMode::Password) => Ok(true),
            Some(SudoMode::Absent) => Err("this login has no sudo on the server".into()),
            None => Err("couldn't check how sudo works on the server".into()),
        }
    }

    fn workflows(&self) -> (Vec<Entry>, std::path::PathBuf) {
        let name = &self.remote.name;
        (workflow::list_for(name), workflow::dir_for(name))
    }

    fn begin_run(
        &mut self,
        entry: &Entry,
        vars: BTreeMap<String, String>,
        _sh: &Shared,
    ) -> Result<Box<dyn WfRun>, String> {
        match workflow::begin(entry, &self.remote, vars) {
            Ok(s) => Ok(Box::new(s)),
            Err(e) => Err(e.to_string()),
        }
    }

    fn resume_run(&self) -> Option<Box<dyn WfRun>> {
        let s = workflow::resume(&self.remote)?;
        Some(Box::new(s))
    }

    /// The sudo mode for the workflow's next step is checked again only when it uses sudo.
    fn run_go(&mut self, run: &mut dyn WfRun, auto: bool, cx: &Cx) -> Result<Option<Exec>, String> {
        let Some(s) = run.as_any_mut().downcast_mut::<Session>() else {
            return Ok(None);
        };
        let sudo = if s.next_uses_sudo() {
            self.fresh_sudo(cx)
        } else {
            self.store.sudo.value
        };
        if auto { Ok(s.auto(sudo)) } else { s.go(sudo) }
    }

    fn step_ended(&mut self, run: &dyn WfRun, cx: &Cx) {
        let refused = run
            .as_any()
            .downcast_ref::<Session>()
            .is_some_and(|s| s.sudo_refused());
        if refused {
            // sudo changed under us: r now retries with the terminal.
            self.fresh_sudo(cx);
        }
    }

    fn reboot(&mut self, cmd: Cmd, old_boot: String, cx: &Cx) -> Vec<Effect> {
        let id = self.mail.next();
        self.wf_reboot_id = Some(id);
        self.reboot_wait = Some((Instant::now(), old_boot));
        if !cx.offline {
            let _ = self.mail.stream(id, &cmd);
        }
        Vec::new()
    }
}

/// What a maintenance item is, for the log.
fn item_kind(it: &crate::config::MaintItem) -> &'static str {
    if it.retire.is_some() {
        "retire"
    } else if it.image.is_some() {
        "image"
    } else if !it.apt.is_empty() {
        "packages"
    } else if it.version_cmd.is_some() {
        "app"
    } else {
        "release"
    }
}

/// Test support: reaching the server behind the app, and the events its tests feed it.
#[cfg(test)]
pub mod testing {
    use super::*;
    use crate::remote::SrvError;
    use crate::tui::data::Payload;
    use sentry_app::{App, Event};

    /// The server in the app's one slot.
    pub fn srv(a: &App) -> &ServerTarget {
        a.slot()
            .target
            .as_any()
            .downcast_ref()
            .expect("the server target")
    }

    pub fn srv_mut(a: &mut App) -> &mut ServerTarget {
        a.slot_mut()
            .target
            .as_any_mut()
            .downcast_mut()
            .expect("the server target")
    }

    /// The workflow run in progress.
    pub fn wf(a: &App) -> Option<&Session> {
        a.slot().run.as_ref()?.as_any().downcast_ref()
    }

    fn id(a: &App) -> String {
        a.slot().target.ident().id.clone()
    }

    /// What a fetch would have sent.
    pub fn data_ev(a: &App, k: Kind, res: Box<Result<Payload, SrvError>>) -> Event {
        Event::Data(id(a), Box::new(Data(k, res)))
    }

    /// A line or the exit of a stream.
    pub fn run_ev(a: &App, sid: u64, m: StreamMsg) -> Event {
        Event::Stream(id(a), sid, m)
    }

    /// Output fetched for the pane.
    pub fn text_ev(a: &App, tid: u64, res: Result<String, String>) -> Event {
        Event::Text(id(a), tid, res)
    }

    /// What the screen in view fetches again by itself.
    pub fn polled_for_test(a: &App) -> Vec<Kind> {
        srv(a).due.keys().copied().collect()
    }

    /// When the server was read with sudo, and when it last changed.
    pub fn set_inventory_times(a: &mut App, read: jiff::Timestamp, changed: jiff::Timestamp) {
        srv_mut(a).inventory_at = Some(read);
        a.set_last_change_for_test(changed);
    }

    /// A chat turn ended (online: reads Claude asked for are offered).
    pub fn turn_ended_online_for_reads(a: &mut App) {
        let (s, w) = a.parts();
        s.offer_reads(w, ReadsFor::Chat, false);
    }
}
