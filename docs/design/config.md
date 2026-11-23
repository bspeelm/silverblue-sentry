# sentry config: a setup flow and a Config tab

## Context

sentry works well once configured, but configuring it is hand-work: three files
(`config.toml`, `server_config.yaml`, `network_config.yaml`), two `init` commands that draft text,
`lint`/`check` commands you have to know about, and nothing in the window that says any of it
exists. A fresh `sentry` opens on this machine and never mentions servers or networks. Config
problems surface as one 2.6 s toast; `lint` never runs at start.

Wanted: a **Config area** in the window. On a first run it opens by itself as a setup flow; after
that it is a tab in the strip beside the systems, visibly different when you are in it. Saving asks
first and states the scope. A wizard agent helps. The first setup step connects the agent.

Decisions made:
- Agents: **Claude Code CLI only for now**; other agents, API connections, API keys and locally
  deployed models are one later effort. The setting still gets a home so that effort adds options.
- sentry **rewrites the config files** (backup kept; hand-written comments are lost on first save).
- Setup **offers what it finds** (ssh hosts, the gateway, the agent CLI); you tick, then it probes.
- Forms cover **every setting**: the common ones first, the rest in groups that start folded
  (first decided as "the essentials, the rest in `$EDITOR`"; see "As built", every setting).
  `e` still opens the file for whoever prefers it; nothing needs it.
- The wizard agent **advises, proposes changes you tick, and may re-run read-only discovery**.
- A saved change is followed **at once** (targets appear/close without a restart).
- Existing setups: **nothing opens by itself**; the tab is just there.

## What it looks like

```
 sentry config   F1 laptop  F2 myserver  F3 home  F4 config*          Mon 23 Nov 13:10
 1 Overview   2 Agent   3 This machine   4 Servers 1   5 Networks   6 Window
────────────────────────────────────────────────────────────────────────────────────────
┌ Systems ───────────────────────────────┐ ┌ myserver · server ───────────────────────────┐
│ ● this machine   laptop            │ │ Connection   ssh myserver          ✓ 41 ms   │
│ ● myserver          server   1 problem    │ │ sudo         asks for a password          │
│ ● home           network               │ │ Watched      6 services · 4 timers · 3 d… │
│ + add a system…                        │ │ ! timer backup.timer: no such unit        │
├ Pending · 2 changes ───────────────────┤ │                                           │
│ [x] myserver  timers  − backup.timer      │ │ Enter opens it · e its file in $EDITOR    │
│ [x] window targets  + srv:other  (Claude)│ │                                           │
└────────────────────────────────────────┘ └───────────────────────────────────────────┘
 Enter open  Space tick  s save…  A wizard  c check  e editor  u undo  ?  q
```

- **Colour**: while in Config the top-left chip reads `sentry config` on magenta (elsewhere cyan
  `sentry`), the focused strip tab is magenta, and the rule under the tab row is magenta. `*` on
  the tab = unsaved changes, `!` = problems found.
- **Save box** (`s`): nothing is written before it.
  ```
  Save configuration
    server_config.yaml    myserver: 1 timer removed
    config.toml           targets: + srv:other
  What follows: myserver reloads · other gets a tab
  Kept before saving: server_config.yaml.bak-20261123T1810
  ! server_config.yaml was written by hand: its comments and layout are not kept.
  Enter save · Esc back
  ```

## Architecture

### Where it lives: an area of the window, not a target
A `Target` has 42 required methods that assume a host, and every slot is surveyed as a peer of
sessions. Config is neither. So:

- `sentry_app::App` gains `config: ConfigArea` and `Focus::{Slot(usize), Config}` (today `focus:
  usize`). `App::on_event`/`draw`/`tick` branch on it; slots keep running out of view as they do.
- Strip: `frame::TargetTab` and `frame::Top` gain `accent: Option<Color>`; `target_spans` and the
  chip use it (the only two hard-coded colours today). The Config tab is always last; its key is
  the next by place (`Keymap::target`), plus `:config`. The strip therefore always shows (today it
  hides with one target).
- Its six screens are its own small enum drawn through the existing `frame::draw_tabs`; `ScreenId`
  (closed, host-shaped) is untouched.

### One writer per file (the model from the last change, applied to config)
Config is "what you said": one file each, never a host fact, never two homes. So no overlay file.

`crates/sentry-core/src/cfg/` (new, pure):
```rust
pub trait ConfigFile: Serialize + DeserializeOwned + Default + PartialEq + Clone {
    const FILE: FileId; const FIELDS: &'static [Field];                    // beside each type
    fn parse(text: &str) -> Result<(Self, Vec<String>), String>; }
pub struct Doc<T> { pub path: PathBuf, pub on_disk: String,                 // one per file
                    pub stamp: Option<Stamp> /* None: no file */, pub now: T }
pub struct Change { pub file: FileId, pub path: String,                    // "servers.myserver.timers[2]"
                    pub from: Option<Value>, pub to: Option<Value>,
                    pub by: By /* You | Agent */, pub on: bool }
pub fn render<T: ConfigFile>(v: &T) -> Result<String, String>;            // the ONLY file writer
pub fn save(path: &Path, text: &str) -> io::Result<Option<PathBuf> /*backup*/>; // .bak-<stamp> (keep 5), write_atomic
pub fn diff<T: ConfigFile>(before: &T, after: &T) -> Result<Vec<Change>, String>;
pub fn apply<T: ConfigFile>(doc: &mut T, c: &Change) -> Result<(), String>;
```
- `render`: `serde_saphyr` / `toml::to_string_pretty` (both already in the tree), a fixed
  header, defaults omitted so files stay short: generically, a setting is left out when the
  value reads back the same without it (no `skip_serializing_if` on the types, so nothing a
  file parses to changes), and a text that doesn't read back equal is refused. Gate test:
  `parse(render(x)) == x` for the example files and for generated values of every config type.
- Pending changes are path-based, so when a file changes on disk underneath (`Stamp`, checked at
  the existing `look` points) they are re-applied on the new text; one whose `from` no longer
  matches is shown as a conflict and left unticked. Nothing is silently dropped or overwritten.
- `sentry-server init --write` and `sentry-network init` are rebuilt on the same path: discovery
  returns a typed `Server`/`Network` plus notes (today's comments), `render` writes it. One writer.
  The server header comment that still names the old baseline path is corrected.

### Each kind describes itself (as targets do)
`sentry-app` cannot depend on the target crates, so, like `Target`, a trait the binary registers:
```rust
pub trait Kind {                                   // sentry-app/src/cfgarea/kind.rs
    fn id(&self) -> FileId;                        // App | Servers | Networks
    fn load(&self) -> Result<Box<dyn DocAny>, String>;
    fn entries(&self, d: &dyn DocAny) -> Vec<Entry>;            // name, one-line summary
    fn sections(&self, d: &dyn DocAny, entry: &str) -> Vec<Section>;   // forms: essentials only
    fn set(&self, d: &mut dyn DocAny, entry: &str, field: &str, v: Value) -> Result<(), String>;
    fn problems(&self, d: &dyn DocAny) -> Vec<Problem>;         // the existing `config::lint`s
    fn probe(&self, ssh: &str) -> Probe;           // runs on a worker: existing init::discover, reads only
    fn check(&self, d: &dyn DocAny, entry: &str) -> Vec<CheckLine>;   // existing `check` logic
    fn explain(&self, path: &str) -> Option<&'static str>;      // the field's doc, for forms and the agent
}
```
Implemented in `sentry-local` (config.toml), `sentry-server`, `sentry-network`; registered in
`crates/sentry/src/tui.rs` beside the target makers. Field tables (label, help, kind, validation)
live with the types they describe and feed forms, `explain`, and the agent's change validation.

Essentials in forms: **Agent** (kind, command, test). **This machine**: reviews at start/after a
run, notes files, terminal. **Server**: name, ssh, sudo allowlist, the drafted lists (services,
timers, disks, smart, compose, listeners) as tick-lists, notes, cadence. **Network**: name, router
ssh, zones/forwards as drafted, device names, backup recipient (makes a key via the existing
`backup key`), notes, share-WAN-address. **Window**: which targets show and their order, keys,
retention. Everything else: `e` opens the file (`Effect::Edit` exists); on return it is re-read,
linted, and its problems listed. That editor path is unchanged.

### Upkeep: workflows and how often (per system)
How it is today, kept as it is: a workflow's **steps** are shared per kind of device (seeded to
`workflows/`, `server-workflows/`, `network-workflows/`); one device may have its **own set**
(`servers/<name>/workflows/`, `networks/<name>/workflows/`), which replaces the whole shared set
for it; **how often** is per device (`maintenance.cadence`, this machine's `[jobs]`); which
workflow moves a tracked item is per device (`MaintItem.workflow`).

Each system's sections gain **Upkeep** (`Kind::upkeep(entry) -> Vec<WfRow>`; reuses
`Host::workflows`, the workflow `lint_with`, `tasks::effective`):
- its workflows: name, shared or its own, draft, lint problems;
- how often each is due: a `Dur` field writing that device's cadence (`off` allowed);
- "its own copy": copies the WHOLE shared set into the device's folder (so nothing vanishes, the
  trap today), then `e` opens the chosen one. Steps are edited in `$EDITOR`, not in forms.
- a tracked item's workflow is a `Pick` among that system's workflows.
The setup flow adds a step after Review: **Routine upkeep** for each system added, with defaults
(Enter accepts): which routine workflows to schedule and how often.

### Forms (new widget; none exists)
`crates/sentry-core/src/tui/form.rs`: `Form { fields, cur }`, `Field { key, label, help, value,
problem }`, `Value::{Text, Bool, Pick, Num, Dur, List, Rows}`. j/k move, Enter edits in place
(a real line editor with cursor movement, replacing append-only for this widget), Space toggles,
`n`/`x` add/remove in lists, Esc back. A field's problem (from `Kind::problems`) is drawn under it.
Record lists (devices, timers, items) are a table whose Enter opens that row's form. The tick-list
generalises the network family filter's `Menu` (moved to core, the filter then uses it).

### The setup flow is the same machinery, walked in order
First run = none of the three files exists. `tui::run` then opens with `Focus::Config` and
`ConfigArea.guide = Some(step)`: a step rail over the same sections and the same pending list.
1. **Agent**: finds `claude` (`Cmd::host(cmd).available()`, `--version`); Enter tests one turn with
   no tools ("not logged in" is caught here, not after a failed fix). "Go on without" is allowed.
2. **This machine**: says what sentry does here; two toggles (reviews); nothing required.
3. **Systems**: what it found, unticked: `Host` entries of `~/.ssh/config` (no wildcards), the
   default gateway as a likely router, plus "add by name". Tick, Enter. One box states what a
   probe reads and that nothing is changed; then each is probed on a worker (`Kind::probe`,
   `BatchMode`, 5 s). An OpenWrt answer becomes a network draft, anything else a server draft;
   a refusal says why (key login needed) and stays in the list to retry.
4. **Review** each draft section by section (tick-lists of what discovery proposes to watch).
5. **Save box**, then the targets appear and the first one has the window.
Esc at any step leaves the rest for later; finishing or skipping writes `config.toml`, which is
what ends "first run". No marker file.

### Following a save at once
`App::retarget(&plan)` (new; nothing rebuilds slots today): by id, not position.
- Added id → `App::add` with the registered maker (it appends; order follows `[targets] show`,
  slots re-sorted and `focus`/`handed` remapped by id).
- Removed id → dropped only if `!slot.at_work()` (exists from the last change). Otherwise the
  save box refuses and names what is running there.
- Changed entry → the existing `Why::Edited` reload. `[keys]`, `[review]`, `[retention]` are
  re-read into `Win`/slots on save (today: restart).

### The agent setting
`config.toml`: `[agent] kind = "claude-code"`, `command = "claude"`. `claude::available()` and
`turn_cmd_with` read `command` instead of the literal. That is the whole of it now: the later
multi-agent effort adds `kind` values, a stream adapter per CLI, and sentry's own tool loop.

### The wizard agent (`A` in Config)
A chat on the area (`ConfigArea.chat`, the existing `Chat`), never a session: it cannot save.
- Briefed each turn with: the pending changes, the problems, what discovery found (a router's
  through the existing `redact` scrubbing), and where it is in the flow.
- Profile: `Bash(sentry config explain:*)`, `Bash(sentry config show:*)`, `Bash(sentry config
  probe:*)`; no Read, no web, every config and data directory denied as today.
  - `explain <path>` prints a setting's doc from the field tables. `show` prints a file as on disk
    (network identities scrubbed). `probe <ssh>` re-runs the read-only discovery and prints the
    draft, **only for hosts you ticked in this window** (the window lists them in
    `$XDG_RUNTIME_DIR/sentry/config-hosts`, the pattern the server's read queue uses); any other
    host is refused with why. The gateway decides, not the model.
- It proposes with one ` ```sentry-config ` block (`[[set]]`/`[[add]]`/`[[remove]]`, by path).
  `cfg::changes::take` validates each against the field tables and drops what doesn't fit with a
  reason (as `sentry-changes` does). They land in Pending marked `(Claude)`, ticked; the save box
  lists them apart from yours.

### Problems are seen
At start every file is linted offline (cheap) and the result drives the tab's `!`, the Overview
and each field. `c` in Config runs the connection checks. `sentry config check` prints the same on
the command line; `sentry config` opens the window on the tab.

## As built (where the code went another way)

Part 2 (the area):
- **Focus** is `App.focus: usize` (the slot in view, or the one that was before the Config
  tab took the window) plus `App.in_config: bool`, not an enum: every existing use of `focus`
  (`slot()`, `parts()`, `with_one`'s parking, `needs`, the tests) keeps meaning what it did,
  and a slot's keymap and input line stay parked in `Win` while the area has the window.
- **`Kind`** is smaller than sketched: `id`, `load(path)`, `fields`, `entries`, `sections`,
  `entry_of`, `problems(doc, warnings)`, `explain` (defaulted from the table). `set` is one
  generic function (`cfgarea::kind::set(doc, path, to, by) -> Change`: the tree and the type
  validate, so no kind writes its own), and the document is `DocAny`, `cfg::Doc<T>` with its
  type erased (tree, base, defaults, apply, reset, rebase, save, handwritten). `probe`, `check`
  and `upkeep` are not there yet (part 3 adds them with defaults).
- **A form field is one change**: a list (`maintenance.notes`, `targets.show`) or a table
  (`keys`) is staged whole at its own path (`from` the old list, `to` the new), not element by
  element. One pending change per setting; a conflict is the setting's.
- **Problems** in the area are of the files as they are to be (staged changes made), found by
  each kind's own lint (`sentry_local::cfgkind::problems` and the two others, which
  `cfgcmd::read` calls too) plus `cfgarea::targets_problems`. So a fix in a form takes its
  problem away before the save, and a staged mistake shows under its field. Unknown keys are
  the file's as read: they go with the save that drops them (the save box says so).
- **`[targets] show` live** (`App::retarget`, by id): the targets the window has are put in
  that order, and one left out is *hidden* (`Slot.hidden`: no tab, no key, no `:` name), not
  closed: it runs on out of view and comes back when shown again. Closing one (refused while
  `at_work`) and adding one with its registered maker are part 3.
- **The save box** also lists each change under its file's scope line, and what was unticked
  or no longer fits stays staged after the save.
- **The tick-list** was not moved to core (the family filter keeps its `Menu`): it didn't fall
  out of the forms built here; part 3's drafted lists are where it is needed.
- **`claude::available()`** stays the cached lookup of the configured command;
  `claude::set_command` forgets that command's cached answer, and the Agent screen's own
  lookup (`claude::find`) never uses the cache.

Part 3 (systems):
- **`Kind`** gained, each with a default: `blank(list)` (a new record), `choices(path)` (a
  tracked item's workflow), `action(path)`/`act(path, arg)` (a field's own key: a network's
  backup recipients make a key), `check(doc, entry) -> Option<Checker>` (a closure the area
  runs on a worker, since a document can't cross threads), `probe(ssh, name) -> Probe`,
  `upkeep(doc, entry, disk) -> Upkeep` and `cadence(doc, entry, workflow, every)` (the
  setting to stage and its whole value). `Entry` gained `ssh`, `DocAny` gained `on_disk()`.
- **Which kind a host is** is decided in the binary (`crates/sentry/src/tui.rs` `probe`): one
  cheap read (`ubus` there, or os-release `ID=openwrt`) then `NetworksKind.probe` or
  `ServersKind.probe`, each `init::discover` + `init::draft`. `sentry-app` has only the
  `Prober` it is handed (`ConfigArea::set_prober`), the refusal's words (`discover::refusal`)
  and the list of hosts ticked and confirmed (`ConfigArea::hosts_asked`): what part 4's
  `probe` gateway is to check.
- **Renaming** a saved system is refused in its form, saying why (its log, plans, baseline and
  runs are under `servers/<name>/`; nothing in the window moves or deletes records) and to use
  the file. A system only staged (drafted, not saved) has no records and is renamed freely:
  its staged add moves to the new key.
- **A drafted system is one staged change** (`servers.<name>`, `from` nothing, `By::You`):
  every later edit of it (the review's ticks, its ssh, its cadence, a form's field) is folded
  into that change's value (`ConfigArea::stage`), so undoing it undoes all of it and no change
  can outlive the entry it is in.
- **A list of records is staged whole** at its own path, like every list (part 2's rule): a
  row's form sets one field in the list's value. `n` adds what `Kind::blank` gives and opens
  it; `x` removes. The form widget hands these to its owner (`Fx::Add`, `Fx::Remove`).
- **Essential flags changed**: a network's `devices[].mac`, `hostname`, `leave_alone`,
  `private_mac` and `backup.keep`; a server's `maintenance.items` with `id`, `source`, `risk`,
  `workflow` (so the item form's workflow is a pick among that server's workflows). A system's
  `maintenance.cadence` stays essential but is shown as its Upkeep section, not as a field.
- **Upkeep is the last group of the system's form**, a field per workflow whose value is how
  often it is due (a duration, `off`, or empty). `off` and empty are the same for a server
  and a network (a workflow that isn't in the cadence isn't on a clock); for this machine's
  jobs empty is the job's own default and `off` is off. This machine's workflows have no
  cadence (they run when something waits) and say so; its jobs are listed beside them.
- **"Its own copy"** (`o`) is a box of its own, never part of the save box (`upkeep::copy_set`
  copies every `*.toml` of the shared set, writes over nothing). A system that already has
  its own set, and this machine (one set, nobody's to share), open the file at once.
- **The tick-list** is core `tui/ticklist.rs` (`TickList`, `Row`, headings, notes, a state per
  row, Space / `a` / `/`, `draw_panels` with the owner's lines under the selected row's). It
  is used for the hosts to look at, the review of a draft, the setup's routine upkeep and
  which targets the strip shows (Space on that field: the order stays the list's own, `J`/`K`).
  The network's family filter keeps its `Menu`: its rows carry the device's own state and
  warnings and its tests are of that widget, so moving it was not a clean swap.
- **The setup's keys**: Enter goes on, `b` or Backspace goes back, Esc leaves (asked once). In
  a step that is a form (Agent, This machine) Space edits or toggles the field under the
  cursor, since Enter is the flow's. On Agent, Enter first tests the agent when it is there
  and untested, and `n` goes on without one. The screens' own keys (digits, Tab) do nothing
  while the flow is on: the rail is the way round.
- **Leaving the setup** (Esc, then Enter in its box) writes `config.toml` when there is none:
  as it is on disk, every setting at its default, nothing staged in it. That is the one write
  outside the save box, said in the box that asks; what is staged stays staged. `:setup`
  picks the flow up at the step it was left. The last step's save box has `config.toml` in it
  whatever is staged (`write_app`), so finishing always ends a first run.
- **Following a save** (`App::sync_targets`): ids the files gained are built by the registered
  `Maker` (`App::set_maker`: the binary's `tui::make`, the function its own start uses),
  added asleep, and put where they would be at the next start (the files' order, then
  `[targets] show`'s); ids they lost are closed (`App::close`) unless at work; a slot whose entry's
  file changed looks at its files (`Why::Edited`), and one that never had the window is built
  again from the file as it is now. What was added or lost is told by comparing the files on
  disk with what they said before (`ConfigArea::targets_changed`), so a window that never had
  a target (left out by `[targets] show` at start) doesn't lose anything by a save.
- **A system staged for removal** leaves the Overview's systems at once and is a row under
  Pending (`u` there takes it back). The save box refuses while it is at work, before
  anything is written.
- **`live_setup`** is one test in the binary's crate (`crates/sentry/src/cfgtests.rs`), run by
  both scripts with `SENTRY_SETUP_HOST` / `SENTRY_SETUP_KIND`: the prober, the makers and all
  three kinds only meet there.
- **`sentry-server` / `sentry-network` without any config file** open the window on the setup
  (the same first-run condition as `sentry`). With another file there and none of their own
  they still say to run `init`, as the commands without a window do.

Every setting in the forms (after part 3; the decision changed):
- **Every leaf setting of the three files is in a form.** `Kind::sections` returns the groups
  of the common settings first (open, as they were, in the same order) and then the rest as
  `Section::folded(title, about, items)`. A system's form is: the common groups, Upkeep, then
  "More settings": a header row per folded group (`▸ name · N set / all defaults · a line about
  it`). The setup's steps are unchanged (This machine still shows its first group only; the
  review still proposes only the common lists).
- **Where they went.** This machine: Refresh rates (`[ui]` rates), Update checks (`[cache]`),
  Audit, Flatpak rules, Recorder, Cleanup, Expected (`[baseline]`): all of it is what this
  machine's target reads. Window keeps what every target goes by (targets, keys, retention)
  and gained nothing; `[jobs]` stays Upkeep's. A server: Thresholds, Container rules, Expected
  findings, Custom actions. A network: Router (its kind), On the router (expected listeners
  and services), Thresholds, Guard, Maintenance items.
- **`Field.essential` is `Field.common`**: it no longer says "in the forms" (everything is)
  but "one of the common ones": in an open group, a column of its list of records, proposed
  by the setup's review. `cfg::Kind::Date` is new (`review_by`).
- **Every setting has one home** (`cfgarea::kind::misplaced`, a test per kind): a table entry
  that holds a value is an item of exactly one section, a field of the row form of a list
  that is one (`kind::record_fields`), a zone's list under its map, or what Upkeep holds
  (the cadence, `[jobs]`). A setting added to a type without a home fails its kind's test,
  as one without a table entry already did.
- **The form widget folds** (`tui/form.rs`): a `Value::Fold(summary, open)` field is a
  group's header, the fields naming it in `Field::fold` are in it. Closed, they aren't drawn
  and the cursor goes past them; Enter or Space on the header toggles; `Form::new` opens a
  group that holds a problem or a change, `Form::at` keeps a group as it was left and opens
  one in which something newly needs seeing; `Form::go` opens the group of the field it goes
  to. Each group's fields have their own label column, so opening one moves nothing above
  it. A form without such a field behaves as before.
- **A record's row has every field of it**: the common ones, then "More about it", then each
  record within it (an item's `image`, its `retire`) under a heading of its own, at
  `list[i].image.service`. Such a record is made by its first setting and unset again with
  its last (`systems::set_within`): `image: {}` and no image differ to the type.
- **Unset, default, set.** A setting whose default is unset (`Option`) is `optional`: an
  empty text or date means unset and is staged as null, which `render` leaves out; one the
  type needs stays an empty text. A value equal to the default (`Kind::entry_default`: an
  entry with nothing set; `Kind::record_default` for a record's fields) is marked
  `(default)` and the side panel says the file doesn't say it; any other says what the
  default is. Setting a value back to its default is a change to what `render` omits (or no
  change at all when the file never said it): `cfgforms.rs` sets every setting of each file
  through the forms, saves, compares the parsed file with the typed value, sets all back and
  finds `servers:\n  myserver: {}` (config.toml: the header alone).
- **A problem finds its field** in a system's form too: `Problem::about` also matches a lint
  line that starts `section: leaf` (`guard: window: 3 s`), so the group holding it opens.

Part 4 (the wizard agent):
- **The chat is the area's** (`ConfigArea.chat`, the existing `Chat` and its drawing;
  `cfgarea/wizard.rs`). A turn's process is started by the area and its lines come back as
  `Event::Config(wizard::Msg::Stream(id, …))`: the area was already the owner of that event,
  so no slot is faked and the stream plumbing is as it was. Offline and with
  `Win.scripted_turns` nothing is started (`wizard_answer_for_test` hands the answer in).
- **The agent's `show` is `show-agent`**, a command of its own; the human `show` is as it
  was. `probe` takes a **system's name** (`newbox`, or `srv:newbox`), not an ssh target: the
  wizard is never told what ssh connects to, so the window's list
  (`$XDG_RUNTIME_DIR/sentry/config-hosts`, a line per system: its id, a tab, what ssh
  connects to) is also where the name is turned into the host. Only systems whose host was
  ticked and confirmed in this window are in it.
- **What hides what** is each kind's own (`Kind::for_agent(tree) -> AgentView`,
  `agent_note`, `agent_problem`; free functions `for_agent` in the three `cfgkind`s), since
  `sentry-app` can't know a network's salt or a server's fields. `cfg::hide::mask` is the
  net under all of them. The brief, `show-agent` and `probe` go through the same functions.
- **A network without a salt**: `show-agent` leaves it out and says so, as designed. The
  brief and `probe` can't leave a drafted router out (it is what is being asked about), so
  there it is counted: devices and zones as counts, a listener without its zone, forwards
  with name, protocol and port but never where they go.
- **A proposal is staged at its setting**, not at the path it names: a list, a list of
  records or named entries is one change of the whole setting (parts 2 and 3's rule), so
  `[[set]] servers.x.timers[0].max_age` stages `servers.x.timers`. `cfg::changes::Proposed`
  carries both (`path` to stage, `at` as written, `said` in a few words), and the Pending
  row and the save box say an agent's change in its own words (`said`), not as the list
  before and after.
- **Inside a system still being drafted**, what the agent proposes is a change of its own
  laid over the draft (`stage` folds into the draft only for `By::You`): it is seen, marked
  and unticked by itself. The user's own edits of a draft are part of the draft, so "you
  changed this yourself" can only be told for settings outside one.
- **More than `agent.*` can never be proposed** (`cfg::changes::NEVER`): also every other
  command sentry would run (`audit.outside`, `ui.terminal`, a server's `sudo`, `actions`,
  an item's `version_cmd`), every host it would connect to (`ssh`), every notes file (what
  an agent may read later), a network's backup recipients (who can decrypt) and its
  `claude` settings (what an agent may see). A record added to a list is checked field by
  field, so none of these comes in inside one.
- **`[[remove]]` takes an optional `value`**: the element is removed only if that is what
  is there (an index read from an older `show-agent` can't take the wrong one). On a
  setting that is neither a list element nor a named entry it unsets it, if its type has
  an unset.
- **No grants, no continuing elsewhere**: a tool call the agent is refused is said once and
  dropped (`Chat.requests` is emptied; nothing in this chat can allow anything), and the
  chat's `C` (continue in Claude Code) is not offered (`Chat.stays_here`): outside the
  window it would have tools it must not have. Tab shows the whole brief before it is sent
  (`Chat.brief_open`).
- **The key bar's `A  wizard`** is the first hint to go where the hints don't fit
  (`ConfigArea::hints_in`), so no narrow screen lost a key of its own to it.
- **Two windows** share the one list file: the last to write wins, and a window's wizard
  removes a list it didn't write before its turn starts. Not solved further.

## Order of work (one PR at a time)

1. **One writer**: `core/cfg` (`render`, `save` + backups, `diff`/`apply`), `Serialize` clean-up,
   round-trip tests, both `init`s rebuilt on it, lint at start, `sentry config check|show|explain`.
2. **The area**: `Focus`, accent colours, the tab, Overview, the form widget, Agent / This machine
   / Window sections, pending list, save box, `[agent]`.
3. **Systems**: `Kind` for servers and networks, discovery, Upkeep (workflows and cadence per
   system), the setup flow, `App::retarget`.
4. **The wizard agent**: brief, profile, `probe` gateway, `sentry-config` changes.


## Not in this work
Other agents, API/local connections, API keys and the keyring (one later effort). Keeping comments
in rewritten files. Themes. (A form for every setting was here; it was built after part 3.)

## Verification
- `make check`, `make privacy-check` per PR (real exit codes). Fixtures stay synthetic.
- PR 1: `parse(render(x)) == x` (examples + generated), backup rotation, a file changed on disk
  under pending changes (re-applied / conflict), `init` output parses and lints clean.
- PR 2: render snapshots of the tab (accent, `*`, `!`, narrow), form editing, the save box's scope
  text, nothing written before Enter (offline tests assert no file), keys/review live after save.
- PR 3: window tests: first run opens the flow; a probe result (fed as an event) becomes a draft;
  save adds a tab; removing a target with a run in progress is refused; `plan_all` order honoured.
  Live, disposable containers only: `scripts/live-container.sh` and `scripts/live-router.sh` gain a
  `live_setup` test (fresh scratch XDG, the flow adds the container as a server / the router as a
  network, the result lints clean and the target reads).
- PR 4: scripted turns: a `sentry-config` block lands as ticked `(Claude)` changes; an invalid path
  is dropped with its reason; `sentry config probe` refuses a host not ticked; the brief carries
  no router identity (canary test, as `the_security_brief_has_no_far_end_addresses`).
- By hand each time: scratch `XDG_CONFIG_HOME`, run `sentry`, walk the flow (discovery is reads only).
