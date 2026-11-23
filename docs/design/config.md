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
- Forms cover the **essentials**; rarer settings open the file in `$EDITOR` from the same window.
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

## Order of work (one PR at a time)

1. **One writer**: `core/cfg` (`render`, `save` + backups, `diff`/`apply`), `Serialize` clean-up,
   round-trip tests, both `init`s rebuilt on it, lint at start, `sentry config check|show|explain`.
2. **The area**: `Focus`, accent colours, the tab, Overview, the form widget, Agent / This machine
   / Window sections, pending list, save box, `[agent]`.
3. **Systems**: `Kind` for servers and networks, discovery, Upkeep (workflows and cadence per
   system), the setup flow, `App::retarget`.
4. **The wizard agent**: brief, profile, `probe` gateway, `sentry-config` changes.


## Not in this work
Other agents, API/local connections, API keys and the keyring (one later effort). A form for every
setting. Keeping comments in rewritten files. Themes.

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
