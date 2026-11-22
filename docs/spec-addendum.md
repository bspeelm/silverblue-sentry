# Spec addendum: binding amendments to `spec.md`

Decided 2026-10-23 during build prep, after probing the target machine. Where this file and `spec.md` disagree, **this file wins**.

## A1. Runtime environment
- Development happens inside a Fedora 44 **toolbox**. `rpm-ostree`, `flatpak` and `podman` exist only on the host. Every external command goes through `crates/sentry-core/src/exec.rs`. When `/run/.containerenv` exists it adds the prefix `flatpak-spawn --host`. Binary availability is probed by path (`/run/host/usr/bin/<bin>` in a toolbox, `$PATH` otherwise) **before** spawning, because a missing binary via flatpak-spawn shows up as exit 1 with a portal error rather than 127.
- Host `/etc` is read via `paths::host_root()` (`/run/host` in a toolbox). `/proc`, `/sys` and `/var/lib/flatpak` are shared and read directly.
- `SENTRY_HOST_EXEC=direct|spawn` overrides the detection.

## A2. Binary
"Single static binary" becomes **a single binary linked only against glibc**. No musl target is available without rustup, and host and toolbox are both F44.

## A3. NVIDIA model (replaces §9.5 assumptions)
- The driver kmod is a **locally built, MOK-signed `kmod-nvidia-<kver>` RPM layered as a LocalPackage**, produced by akmods. `rpmfusion-{free,nonfree}-release-N` are also LocalPackages. Secure Boot is enforcing.
- The kernel-change ritual:
  1. `rpm-ostree upgrade --uninstall <exact old kmod>`, then reboot.
  2. Make sure `/var/cache/akmods/nvidia/kmod-nvidia-$(uname -r)-*.rpm` exists (otherwise `sudo akmods --force --kernels $(uname -r)`), then `rpm-ostree install` it, then reboot.
  3. Run `nvidia-smi`, then check that Flatpak `GL.nvidia` and `GL32.nvidia` are at the same version.
- Workflow template built-ins added: `old_kmod`, `pending_kernel`. Checks added: `kmod-local`, `akmods-built`, `flatpak-gl-nvidia`, `flatpak-idle`, `booted-kernel`, `master-repo-present`.
- `when` accepts a leading `!` for negation.
- Steps marked `rollback = true` are skipped in the normal sequence and only offered from "abandon".
- `release-rebase.toml` ships with `draft = true`. It cannot start until its dry-run step has succeeded once and the user removes the flag.

## A4. Updates data source
`rpm-ostree status --json` → `cached-update.rpm-diff` is the structured source for available updates and kernel-change detection. "Check now" runs `rpm-ostree upgrade --preview`, which refreshes it. Sentry stores only the check time (`~/.cache/sentry/ostree-check.json`).

## A5. Flatpak permissions are read live
Permissions are computed by parsing the app `metadata` keyfiles and applying override keyfiles (system/user, global/per-app, with `!` negation) in Flatpak's order. This is cheap (no subprocess per app), so it runs on screen entry and is **not cached**. Only the update check (network) is cached: what `flatpak update` would do, its prompt answered `n` (`remote-ls --updates` also lists the fedora remote's rebuilt images that `flatpak update` has nothing to do for).

## A6. Baseline storage
- `config.toml [baseline]` is user-authored and never written by sentry.
- `~/.config/sentry/baseline.toml` is machine-written from the TUI (`listeners`, later `findings`).
- The effective baseline is the union of the two.
- Listener keys are `addr:port/process`; `*` globs are allowed.
- Listener classes: `baseline` (matched), `local` (loopback, not baselined, not a finding), `NEW` (non-loopback, not baselined, becomes a high finding in the audit).

## A7. UI
- Keys follow spec §11. History is `H`; the mockup's `h` is overridden.
- Colors are the mockup palette in truecolor when `COLORTERM` is `truecolor` or `24bit`, otherwise the nearest of the 16 ANSI colors. The terminal background is never painted.
- Design size is about 158×41 cells. Supported down to 80×24.
- Per-core CPU grid: 4 columns at ≥ 17 threads.

## A8. Refresh cadences
- Dashboard: 1 Hz (CPU/mem/net counters from `/proc`), GPU and temps every 5 s, disks/units/ostree every 60 s.
- Processes: 2 Hz.
- Network screen: `ss` every 3 s.
- Everything else refreshes on screen entry or on `r`.
- Disk breakdown (directory walk) is cached and refreshed only on `r` from the dashboard.

## A9. Audit (milestone 3)
- Design: `docs/design/m3-m7.md`. Reports store diffable facts only. Journal **messages are never stored**, only counts (they can contain secrets).
- Findings have stable ids (`listener:<key>`, `flatpak-perm:<app>:<flag>`, `repo:<file>`, …). `baseline.toml findings` holds ids or `*` globs. `config.toml [baseline] findings` is the user-authored equivalent.
- "Gained" (high) only applies relative to a previous report. On the first report, Flatpak filesystem flags and COPRs are medium, because nothing was gained.
- Host-specific additions to spec §7:
  - medium: enabled third-party repo files (catches a leftover `updates-master.repo`).
  - low: unused runtimes, a stale `GL.nvidia-*` extension, failed logins.
- UDP sockets on ephemeral ports (≥ `ip_local_port_range` low) are client sockets: class `client` on the Network screen. They're excluded from reports and findings. TCP listeners on any port stay `NEW`.
- `B` writes a broader pattern after a confirm modal: `*/proc` for a listener, `flatpak-perm:<app>:*`, `repo:<prefix>*`, `unit-failed:<scope>:*`.
- `similar` is not used. Kargs are an unordered set, and no free-text sections are stored.

## A10. rpm-ostree has no dry-run for upgrade/rebase
On this host, `rpm-ostree upgrade` offers `--preview`/`--check` and `rebase` offers nothing. Only `install`/`uninstall` take `-n/--dry-run`. The spec's "`--dry-run` sibling" therefore means: `--preview` for upgrade, `--dry-run` for install/uninstall, and none for rebase (the card says so; `rpm-ostree cleanup -p` undoes a staged deployment). The seeded `release-rebase.toml` step `rebase-dry` used a nonexistent flag. It now validates that the target ref exists instead.
`--preview` exits 77 when no update is available. As a dry run that means "nothing to do": the step is skipped with that note instead of failing. Every dry run's exit code is kept in `state.json` (`dry_code`) and in the step's log, and `D` (skip the dry run) is logged too. The seeded `quick-update` gates its routine upgrade and reboot on `routine_update` (an update is waiting and keeps the kernel), so with nothing to upgrade neither is offered.

## A11. Jobs (milestone 4)
- Every job is `sentry job <name>`. The TUI streams that same command (with `--yes`, after its own confirm modal), so output, reports and last-run records are identical either way. Headless runs prompt `[y/N]` on a terminal. With no terminal and no `--yes` they refuse, exit 1, and record nothing.
- `--only k1,k2` runs selected plan items (Cleanup screen). Without it, a run does only the default items. Opt-ins such as `rpm-ostree cleanup -b` always need `--only`.
- Last runs live in the maintenance log (`kind = "job"`; was `jobs.json`, migrated once). Cadences are recurring tasks: `tasks.toml` (written by `e` on the task's row), then `config.toml [jobs]`, then the spec default; the four cleanups are one task (`job-cleanup`, the soonest cadence). A job that has never run counts as due. `c` in the TUI counts as an update-check run. (Revised 2026-11, maintenance clean-up.)
- `cleanup-podman` never prunes toolbox/distrobox containers; they're listed for manual removal. `cleanup-flatpak` also offers stale `GL.nvidia-*`/`GL32.nvidia-*` extensions, which `--unused` keeps. `cleanup-cache` deletes only `[cleanup.cache].delete_dirs` entries that are plain child names of `~/.cache`.
- `update-apply` refuses an upgrade that changes the kernel (kmod ritual): that path is the `quick-update` workflow.
- Flatpak has no dry-run. The "unused" preview pipes `n` into `flatpak uninstall --unused`, which prints the transaction and changes nothing.

## A12. Workflows (milestone 5)
- Seeded TOMLs are written to `~/.config/sentry/workflows/` only where missing. A run copies its TOML into the run dir (`workflow.toml`) and uses that copy, so editing a file mid-run can't shift step indices.
- Extra fields: `manual` (card text, required for `kind = "manual"`, `gate = "manual"` and `on_fail = "manual"`), `draft`, `dry_run`. Unknown fields are lint errors.
- Templating is hand-rolled (`{{ ident }}`, integers, `"strings"`, `+`/`-`); `minijinja` isn't used.
- **Freezing.** A `when` condition is evaluated the first time a step needs it, then stored in `state.json`. Built-ins (`current_version`, `pending_kernel`, `old_kmod`) are frozen at first use, and all of them are frozen before any reboot. `booted_kernel` and `home` stay live. This is why `kernel_changed` and `pending_kernel` stay correct after the reboots that make the live checks false.
- `pending_kernel` is in `uname -r` form (`7.2.11-200.fc44.x86_64`). rpm-ostree's rpm-diff omits the arch.
- Steps run as `bash -c` on the host with `set -o pipefail`, a `sentry` shell function pointing at this binary, `SENTRY_WORKFLOW_RUN` exported (preflight ignores its own run), and output tee'd to `steps/<id>.log`.
- Steps containing `sudo` (outside `toolbox run`/`distrobox enter`/`podman exec`) run with the TUI suspended so sudo can prompt. Inside a toolbox, `flatpak-spawn --host` gives the host process no controlling terminal. Such steps therefore refuse to start there, with "run sentry from a host terminal; state is saved".
- After a resume, auto steps wait until the Upgrade screen is opened (the banner says "press 0 to continue"). A step interrupted by sentry exiting counts as failed.
- `SENTRY_NO_REBOOT=1` replaces `systemctl reboot` with a message (testing). Simulate a reboot by changing the step's `boot_id` in `state.json`.
- The `quick-update` `preview` step treats exit 77 ("no update") as success.
- `sentry workflow list|lint [name]|abandon|<name> [--var k=v]`.

## A13. Recorder and History (milestone 6)
- `metrics/ring.bin` is a 64-byte header followed by fixed 128-byte records (layout in `crates/sentry-core/src/recorder/ring.rs`). Capacity is min(`retention_hours`, `max_mb`), so the file never grows. A file with a different shape is moved to `ring.bin.old` rather than reinterpreted.
- `metrics/recorder.pid` marks a live recorder. Only one runs at a time, and the file is removed on Ctrl-C/SIGTERM/SIGHUP.
- Footprint, measured on the host with a release build at a 10 s interval: **0.07% of one core including children, 9.8 MB RSS**. Getting there meant:
  - top-3 processes from a CPU-only process refresh (kernel names) once a minute;
  - nvidia-smi every 3 minutes;
  - the `new_listener` alert reads `/proc/net/{tcp,udp}[6]` instead of spawning `ss`. Keys are `addr:port/?`, and the baseline matches them on the address alone.
- Alert rules: `cpu|mem|swap|cpu_temp|gpu_temp>N[%][:dur]`, `disk_free<N%`, `new_listener`. Each fires once when its condition has held for `dur`, and re-arms when the condition clears. Alerts go to `notify-send` and `metrics/alerts.log` (the History screen shows the last 3).
- History graphs show per-bucket means, with gaps left blank. Avg/max stats come from the raw samples, so spikes aren't flattened. The tab appears once `ring.bin` exists.
- The dashboard pre-fills its CPU and net graphs from the recording at startup, but only when the newest sample is under 5 minutes old.

## A14. Polish (milestone 7)
- `?` shows the global keys plus the current screen's keys. `:workflow <name>` opens Upgrade and starts that workflow the way `Enter` does. `:job <name>` opens its plan.
- Below 110 columns, Audit shows one pane at a time (`C-h`/`C-l` switch). Jobs shows the date only in LAST RUN.
- Missing tools: collectors return `unavailable` (exit 3 from `collect`). A screen shows `— <tool> not found`. A job plan lists the job as unavailable instead of offering a command, and a check exits 2.
- A dry run never writes a last-run record, even if printing fails (`| head`).
- Footprint re-measured on the host after M3–M6: TUI dashboard at 1 Hz uses 0.77% of one core including children, 8.3 MB RSS. Recorder: 0.07%, 9.8 MB.

## A15. Toolbox package updates
- Containers shows pending `dnf` updates inside every toolbox/distrobox: an UPDATES column plus a pane for the selected one (`old → new`, repo). Checks run on `c` (here or on the dashboard) and in `update-check`, and are cached in `toolbox-updates.json`.
- A check is `podman exec <name> sh -c 'dnf -q check-update; rpm -qa …'`. Exit 100 means updates, 0 means none, and a container without dnf shows `n/a`. Stopped containers are started for the check and stopped again.
- Starting a container moves podman's exit time to now, which would hide staleness. When sentry stops a container it started, it records podman's new exit time and the original one in `~/.local/share/sentry/container-stops.json`. The podman collector reports the original for as long as the exit time is still sentry's.
- Upgrades (`u`/`U`, the `update-apply` toolboxes item, `quick-update`) run `podman exec --user root <name> dnf -y upgrade`. Running as root through podman needs no sudo, so no terminal either. A stopped container is started for the upgrade and stopped again; an upgrade counts as use, so its exit time isn't preserved.

## A16. release-rebase revisions (reviewed with the user)
- **RPM Fusion:** the swap moved to a one-time `rpmfusion-migrate` workflow, run on the current release. It does `rpm-ostree install --uninstall <exact local release RPMs> rpmfusion-free-release rpmfusion-nonfree-release`, then a reboot. `install`, unlike `update`, doesn't pull a pending base upgrade. release-rebase stops if the release packages are still pinned (`rpmfusion-pinned --expect unpinned`).
- **New checks:**
  - `repos-ready --target N`: fetches each enabled third-party repo's `repomd.xml` or metalink with `$releasever=N`.
  - `booted-pinned`.
  - `nothing-staged`.
  - preflight now reports whether a current-release update is pending, or how old the last update check is.
- **Rollback:** today's deployment is pinned (`sudo ostree admin pin booted`) before the rebase, and its version is frozen as `{{ booted_version }}`. `rpm-ostree rollback` isn't offered any more, because after the rebase and kmod deployments it points at "target without kmod". The rollback step finds the pinned deployment's index in `ostree admin status` and runs `ostree admin set-default`. An optional final step unpins it.
- **Toolboxes:** each toolbox's `dnf repoquery --userinstalled` is saved to `<run>/toolboxes/<name>.txt`. Then an optional `dnf --releasever=N distro-sync` runs as root via podman.
- **Seeding:** `.seeded.json` records the hash of every seed sentry writes. A workflow file is upgraded only while it still matches what sentry wrote, or one of the historical versions listed in `SHIPPED` (copies from before the record existed). New seeds don't need entries in `SHIPPED`.

## A17. Audit, explained (supersedes parts of A9)
- Every finding carries `what` / `why` / `fix` text. The screen shows them in a detail box, and the raw evidence underneath.
- Severity is shown as **check** (high), **review** (medium) or **info** (low). Stored values are unchanged.
- **Listeners are grouped by service.** `crates/sentry-local/src/audit/known.rs` maps ports to names, descriptions and advice: mDNS, LLMNR, DHCPv6, wsdd, SSH, CUPS, Syncthing, RDP/VNC, Samba, and so on.
  - Reach is described in words (all networks / LAN / VPN / link-local).
  - An unknown root-owned service is **check**, with the `sudo ss` command that names it.
  - A known remote-access service open to every network is **review**. A stock desktop service is **info**.
  - `b` baselines every address of the group.
- **Repos are grouped by vendor** (RPM Fusion, Brave, …) as **info**. A COPR is individual (review, or check when new). `updates-master.repo` gets its own explanation.
- **Flatpak access is summarised** in one "N apps can read your files" **info** finding. A permission gained since the last audit, or a talk-name sandbox escape, is reported on its own.
- **The diff never treats "not collected" as "empty".** Report `i` is compared with `i-1`, with any missing section borrowed from the newest earlier report that has it, and a note says so. A section with no source says "not collected". Only reachable listeners are diffed. "Gained" findings use the same merged report.
- The rpm-ostree status timeout is 60 s. It was 10 s, and that timeout caused a report with no package section.

## A18. Ask Claude (local Claude Code passthrough)
- `A` on any tab builds a context for the selected thing (`Screens::ask`, one formatter per tab) and shows it verbatim in a consent modal. `y` runs `claude -p` on the host (`Cmd::host`). The CLI uses the user's Claude Code login, so there's no API key.
- Flags:
  - `--output-format stream-json --verbose --include-partial-messages`;
  - `--append-system-prompt` (sentry's role plus machine facts);
  - `--tools Bash Read Grep Glob`, `--allowedTools ALLOWED` (read-only), `--disallowedTools Write Edit … Bash(sudo:*) Bash(rm:*)`;
  - `--strict-mcp-config`.
- The working directory is `<cache>/sentry/claude`, so no project instructions get picked up. Follow-ups use `--resume <session_id>`.
- Claude Code refuses tools outside the allowlist in `-p` mode, including compound commands with a disallowed part. The live tests confirmed this: `| head`, `firewall-cmd`, `systemctl list-sockets` were refused; the latter two were then added as read-only.
- The chat pane streams text deltas and shows each tool call and its result summary. Esc kills the turn; killing `flatpak-spawn` also ends the host process, which the live test verified. Sentry kills it on exit too.
- Per-tab questions are listed in the plan (Dashboard, Processes, Network, Updates, Containers, Flatpaks, Audit, Jobs, Cleanup, Upgrade, History).
- **Overlap between tabs, resolved:**
  - on a kernel change, Updates `u` starts quick-update; it no longer stages ritual step 1 by itself;
  - Jobs Enter on a cleanup job opens Cleanup with only that job's items selected;
  - `b` marks things expected on both Network and Audit, and a known service is marked on all its sockets;
  - stale GL extensions and the cache size point to Cleanup;
  - the toolbox upgrade is one command (`sentry toolbox upgrade`), used by Containers, update-apply and quick-update;
  - the Dashboard status rows are jump links.
- `known.rs` gained passim (tcp 27500, the fwupd firmware cache), learned from a live answer.

## A19. Fixing findings (`f`)
- `audit::fix::fixes(&Finding)` derives concrete fixes from the finding id, so they work on old reports too. There are three kinds:
  - a shell command (`sudo` flagged);
  - opening an rc file in `$EDITOR` at the line;
  - jumping to the tab that owns it (Flatpaks, or Cleanup focused on a job).
- `f` shows the exact command and the undo, and asks first. With several fixes it shows a numbered picker (`1`–`9`).
  - sudo fixes run with the TUI suspended, so the password prompt works. They're refused inside a toolbox, as for workflows.
  - Other fixes stream in the run pane.
  - Anything that changes the system re-runs the audit afterwards. Read-only "show why" fixes don't.
- No fix is offered for:
  - vendor repos (RPM Fusion provides the NVIDIA driver);
  - unknown services (identify them first; that's the offered action);
  - unverified origins and bad signatures.

  For those, `f` says why and points to "To do" or `A`.

## A20. Fixing findings with Claude (supersedes the `f` flow of A19 when Claude Code is available)
- `f` → consent modal → chat with `Ask::fix(&Finding)`. The prompt includes:
  - the finding;
  - sentry's known fixes (from A19), numbered with their commands and undo;
  - the required answer shape: What's going on / Recommendation / Commands, one fenced block each with a `# why:` line.
- **Claude's tools are unchanged** (A18 allowlist; `sudo`, `rm` and writes denied).
- `claude::parse_commands` turns fenced blocks into `Proposed {cmd, why, undo, known}`.
  - `known`/`undo` are set when a block matches a known fix exactly.
  - The proposals are refreshed after every turn that produced any.
- **Running a proposal** (`r`, then `1`–`9`): a confirm modal shows the command, the why, the undo, sudo and a `risky()` warning.
  - sudo runs suspended, tee'd to `<cache>/sentry/claude/last-run.{txt,code}`, and is refused in a toolbox.
  - Other proposals stream into the chat (`chat::Job`).
  - Anything that isn't `read_only()` is followed by `sentry job audit`. The chat then reports whether the finding id is still in the latest report.
- **Output back to Claude** only on `s`, through the consent modal (the last 60 lines plus the audit result).
- **`C` hand-off:** `claude::interactive_cmd(session)` runs `claude --resume` with the same allowlist, the same denials and the system prompt, plus "the user runs anything that changes the system".
  - It runs suspended with a short banner; afterwards sentry re-audits (for fix chats).
  - Claude Code asks once whether to trust its scratch working directory. That decision is left to the user.
- Letter keys in the chat (`r`, `s`, `C`) act only while the input line is empty; otherwise they're typed.
- Without Claude Code, `f` is A19's static picker. In tests, `claude::TEST_AVAILABLE` fixes availability.

## A21. Fixing failed workflow steps with Claude
- `Ask.target: Option<Target>` replaces A20's `finding`:
  - `Target::Finding(id)` re-audits after changes;
  - `Target::Step{workflow, idx, id}` never re-audits; it offers a retry instead.
- **`f` on a failed step** (`Next::Stopped` or a failed `Manual`) → `upgrade::step_facts(&Session)` → `Ask::step_fix(&StepFacts)`. The facts are:
  - the position and the neighbouring step titles;
  - the rendered command, exit code and vars;
  - the 60-line log tail;
  - the step's `manual` text;
  - the actions valid now, by name (retry, done by hand, skip, rollback only if any, abandon), and the pending later steps (A22).
- **The question** is the shared `fix_question()`, plus: name one of the actions, and never propose `rpm-ostree upgrade/rebase/rollback/cleanup`, `ostree admin` or reboots.
- **Proposals:**
  - refused while a step is live;
  - `touches_deployment()` adds a warning line (never a block) while a workflow is open;
  - the "audits again" line only appears for finding chats.
- **`t`** (`chat::StepState` Failed or DryOk) → a confirm box with the step's command → `ChatRetryStep`, which does `WfCmd::Retry`, then `wf_auto()`, then `WfCmd::Go` if the step is at a confirm gate (this box was the gate; the dry-run-first rule still applies).
- **Feedback:** `chat_step_exit` runs after `Session::on_exit`, on both the stream and the suspended (sudo) paths.
  - It sets Done, DryOk or Failed, adds an Info line, and sets the `s` offer to the step's log tail.
  - One Claude session spans the retries.
- The Upgrade key bar shows `d` for every failed step (A22).

## A22. Failed steps are never a dead end
- **`d` on a failed `on_fail = "stop"` step** marks it done by hand after a confirm box (the step, its command, "mark it done only if you've made sure of this yourself"). Failed `manual` steps keep `d` without a box.
- **`s` on a step that isn't optional** skips it after a confirm box ("later steps may expect it to have run"). Optional steps still skip at once.
- **Enter on a failed step** names the options in a toast; the key bar drops "Enter run" while a step is failed.
- **The log is `L`**: `l` is next-tab everywhere (vim), so the old `l` on Upgrade never reached the screen.
- **Built-ins freeze after every successful step** (`runner::complete`), not only at a reboot. `pending_kernel` comes from rpm-ostree's cached update, which staging clears, so the reboot was too late and `verify-kernel` failed after it with "no pending kernel update".
- **A reboot is refused** while a built-in that a step still to run needs can't be resolved ("not rebooting: later steps need pending_kernel: …"), instead of rebooting with the value lost. Steps ruled out by a frozen `when` don't count.
- **A command that can't be filled in** says which value (`can't fill in {{ pending_kernel }}: …`), and the line goes into `steps/<id>.log` too, so `L` and fix with Claude see why the step never ran.
- **Fix with Claude** also gets the pending later steps, and is told not to install/uninstall/override packages, run akmods, or do a later step itself; if the system already satisfies the step, it recommends done by hand.
- **quick-update fixes the GL runtimes itself:** a `flatpak-gl-update` step (`flatpak update -y`, confirm, `when = "!flatpak_gl_nvidia"`) runs before the `flatpak-gl` check. The earlier `flatpak` step runs before the new driver is loaded, so it can't pull the matching GL runtimes; the check used to fail and leave the command to the user.

## A23. sentry-server
- A second kind of target (`crates/sentry-server`, a library; the command `sentry-server` is the one binary `crates/sentry` under that name) over the shared library (`crates/sentry-core`). It monitors and maintains a server over ssh; the server is described in `~/.config/sentry/server_config.yaml` (`crates/sentry-server/src/config.rs`, sample in `assets/`).
- Transport: `exec::Site::Ssh`. Captured commands share one multiplexed connection (`ControlPersist=15s`); streamed and interactive ones get their own, so killing them stops the remote side (`-tt`). Exit 127 = not found there, 255 = unreachable.
- Collectors (`crates/sentry-server/src/collect/`) parse synthetic fixtures in `tests/fixtures/server/`; the audit (`crates/sentry-server/src/audit.rs`) derives `srv:*` findings from a snapshot.
- Workflows reuse `workflows::runner` with a remote `Env` (built-ins and conditions over ssh, `Env::builtins`/`live`), `LintRules`, and runs under the server's own data dir. `sentry-server cond` steps run locally and read the server.
- Ask Claude uses `claude::Profile`: Claude may only run `sentry-server exec <server>` (`crates/sentry-server/src/gateway.rs` allowlist); ssh, scp, sftp and rsync are denied.

## A24. Workspace (2026-11)
- One repo, a cargo workspace: `sentry-core` (what every target shares: `exec`, `paths`, `config`, `baseline`, `finding`, `claude`, `maint`, the workflow format and runner, a few parsers, the TUI kit), `sentry-app` (the app: one window, a slot per target), the targets `sentry-local` (this machine) and `sentry-server`, and `sentry`, the one binary over both. The compiler keeps the direction: core depends on nothing above it, and targets never depend on each other.
- `sentry` re-exports the core modules under their old names (`crate::exec`, `crate::maint`, …), and its `maint`, `workflows`, `collectors` and `tui` add their local parts to core's. sentry-server names core as `sentry_core::…` (its own `config`, `maint`, `tui` and `audit` would clash).
- Tests: core's `testing` feature (scratch dirs per process, Claude Code counted as installed) is turned on only by the other crates' dev-dependencies; release builds never have it.

## A25. Apply with Claude, and a quieter Maintenance (2026-11)
- `A` on a Maintenance row or in the Plan view: 1 help me apply it, 2 just ask (a finding keeps its fix flow). Applying, Claude answers before / change / verify / roll back; you run each command (`r`, confirm), output goes back with `s`.
- When a workflow makes the change, Claude never proposes its commands: `w` in the chat starts the workflow (a plan's values when there's one) and the chat steps aside; a failed step or the run's end is offered to Claude (`s`). `d` marks a task or a by-hand plan done. Commands that change something are logged `kind = "apply"`, tagged `apply:<row key>` (never `task:`).
- The key bar shows the selected row's keys (Enter named by what it does) and `c`, `v`, `R`; the rest is in `?`. Details say what Enter does once, without key hints; the update list is in Details only.

## A26. Granting files to Claude (2026-11)
- Chats may read the configured notes files (as plans and reviews do). Anything else Claude is refused shows in the chat; `g` lists the files (read or edit) and `y` grants them for the rest of that conversation, by exact path, then tells Claude to carry on.
- Edits: only files under $HOME; never `~/.ssh`, `~/.gnupg`, `~/.local/share/keyrings`, `~/.password-store`. The file is backed up first (`~/.cache/sentry/claude/backups/`); a change shows in the chat and is logged (`kind = "edit"`, `file:<path>`).
- Commands are unchanged: Claude proposes, the user runs them behind a confirm box.

## A27. Apply with Claude: one plan, approved once (2026-11, replaces the four-part answer of A25)
- Applying, Claude answers with one plan (a ```` ```sentry-apply ```` TOML block): steps in order, each `edit` (exact old → new text in a file under $HOME), `check` (must exit 0), `run` (changes something; sudo hands the terminal over) or `workflow` (started; the plan waits for its run). No other code blocks, so no list of proposals to pick from.
- `a` shows the whole plan with its diffs; `y` approves it once. sentry backs up every edited file and runs the steps in order; a failing step stops the rest. The report goes to Claude with `s` (on a failure, the steps done, for a plan for the rest). One log entry per run (`kind = "apply"`).
- A plan with an edit that doesn't fit the file, a file outside home or an unknown workflow can't be approved (shown in red).

## A28. Applying is one session (2026-11, replaces A27's approval box, offers and `s`)
- `apply::Session` (sentry-core) is the whole of it, a state machine both programs drive: Brief → Investigating → Review → (sudo check → inline password) → Applying → Verifying → Settled. Two decisions are the user's: start (Enter on the brief) and approve (Enter on the plan). Everything else follows by itself.
- No consent box: the brief is shown in the window, with an input to add to it; Enter sends. Follow-ups you type are sent as typed. The same for ask and fix chats (their first turn opens as a brief). Modals take Enter as yes.
- A plan with problems, or a failed step, goes back to Claude without a key (at most 2 rounds, then the user says what to do). After the last step the results go to Claude to verify; it answers with a ```` ```sentry-verdict ```` block (`done` / `more` + a new plan / `failed`). `done` tags the apply log entry `task:<id>`, which marks the task done.
- Root edits: an `edit` of a root-owned file under /etc (not sudoers, PAM, passwd/shadow/group) is written with sudo: backup as the user, new text to a 0600 temp file, `sudo sh -c 'cat "$1" > "$2"'` keeps owner, mode and label. A sudo password is typed inline, checked (`sudo -S`), and fed on stdin to the step's shell, where a `sudo` stand-in first on PATH (a private temp dir, removed after) hands it to the real sudo, so a `sudo` nested in `sh -c`, `xargs` or a script gets it too (`apply::sudo::wrap`); `Cmd::input` writes stdin, and ssh gets no tty then, so nothing is echoed.
- In an apply session there are no proposals and no offers. The ask and fix chats keep theirs (`r`, `s`); their sudo proposals still hand the terminal over.

## A29. Checks for later, and desktop settings Claude may read (2026-11)
- A verdict may carry a `[follow_up]` (`title`, read-only `steps`, `after`): on `done`, sentry adds it to `tasks.toml` as a one-time by-hand task (`check-<slug>-<date>`), so the check doesn't depend on remembering it.
- `Task.after`: a sentry workflow (due once it next ends well after the task was added) or a wait (`7d` from when it was added). An `after` sentry doesn't know goes into the steps, and the task is due now.
- Claude's read-only allowlist includes `gsettings get/list-keys/list-recursively/range/describe` (never `set`/`reset`).

## A30. Every fix is an apply session; chats only explain (2026-11, replaces the proposals of A20–A26 and the last line of A28)
- `fix_question`, proposals (`r`), offers (`s`), the chat's jobs and the terminal handover for a proposal's sudo are gone. `Ask::for_finding` and `Ask::step_fix` are apply asks (`Apply.finding`, `Apply.step`); so are sentry-server's finding, unit and container fixes and a failed step in its run view (`remote: true`).
- A finding's session audits again after the last step (`Fx::Reaudit`, local) and tells Claude whether the finding is gone; its log entry is tagged `finding:<id>`. A step's session ends with Enter retrying the step (`Fx::RetryStep`).
- Settled, Enter on an empty input does the next thing: close (done), retry the step, audit again (a finding not done), mark it done (a task Claude didn't verify). Review without a plan: Enter asks for one.
- A chat explains; `a` hands it to a session (`Session::from_chat`: the transcript and Claude's session go on) when its screen has an apply ask for the selection (`A` → 2 keeps it as `Chat::apply_with`).
- A missing or broken verdict is asked for again as a verify turn.

## A31. sentry-server: plan to decide, apply session to do (2026-11)
- Both stay, with one job each. The plan writer (`p`) researches and decides (target or wait, a durable `plans/<item>.md`); the apply session is the only way anything changes on the server.
- Enter on a ready plan (the "Apply the plan" recommendation, or the Plan view) opens an apply session seeded with the plan (its body and the workflow's values), not the workflow directly and never the "done by hand?" box. Done, the plan closes (`Fx::PlanDone`; or when its workflow's run ends well, as before).
- A session's `workflow` step takes values (`vars = { … }`, `Kind::Workflow { name, vars }`); the server starts it with the plan's values as the base and the step's on top (`BeginPrefilled`, so they're shown filled in). `problems()` flags a value the workflow doesn't declare (`WfInfo`).
- Apply sessions on a server get WebFetch/WebSearch, as plans do.

## A32. sentry-server has sentry's screens (2026-11)
- The server's tabs are screens with sentry's numbers and names where they are the same thing: `1` Dashboard (was Overview), `4` Containers, `5` Services (the slot sentry gives Flatpaks), `6` Maintenance, `0` the workflow run. `2`, `3`, `7` and `H` are not bound there yet. `:dashboard`, `:dash`, `:cont`, `:svc`, `:maint`, a prefix of three letters or more, and the old `:overview` all work.
- One `ScreenId` in core names every screen either program has; each program declares its own in a `ScreenSet`. The strip is core's `frame::draw_tabs` (short names, then keys only, as it narrows), and `[keys]` in `config.toml` applies to both programs (a `screen.<slug>` of the other program's screen is skipped quietly).
- Each server screen is a struct with its own cursor behind `Screens` (`crates/sentry-server/src/tui/screens/`); what a screen fetches is declared in `Screens::polls` and fetched only while it is the one in view. `a` (your actions) and `B` (reboot) are Dashboard keys; `I` stays global.

## A33. sentry-server draws in sentry's frame (2026-11)
- The server's frame is core's (`tui/frame.rs`), so it is sentry's: the top bar keeps the connection state where sentry says live or idle and gains the clock; a workflow's banner has its own row; a toast sits at the right of the key bar for 2.6 s beside the hints instead of replacing them.
- Boxes, choices and the streamed-output pane are drawn inside the body over the screen dimmed. A confirm box's keys are `Enter confirm · Esc cancel` (`y` and `n` still work); a choice is numbered and names its keys; the pane is sentry's run box.
- One order for keys, pastes and the key bar's hints (`frame::layer`): run pane, choice, box, apply session, chat, the line being typed, Records/plan/review, the screen. While a chat or an apply window is in front the key bar shows no hints (the window has its own key line).
- One input line (`Input<Prompt>`): `/`, `:`, a workflow's values, a plan's note, a plan's revision, a log note. Backspace on nothing closes a filter or a command, never a prompt; a value left empty with no default is asked again, with why.
- `?` is sentry's help layout, with the server's own keys (`I`, `0`) under `sentry-server:`.

## A34. sentry-server: screen `0` is Upgrade, as in sentry (2026-11)
- `0` is a real screen and always on the strip (` ●` while a run is in progress). With nothing running it lists the workflows as sentry's Upgrade does (core `tui/wflist.rs`, used by both): steps, draft, lint, last run, and the selected one's chain and start card. `Enter` starts the one selected: its values are asked first when it takes any (the key bar's prompt), otherwise the box that says what starting does. `e` edits its file, `r` reads them again, `v` opens Records.
- A run is followed on the same screen (steps, log, the step's card; Enter, `s`, `d`, `r`, `a`, `L`; `C-c` stops a running step). Its auto steps run only while `0` is in view; on any other screen the banner row says where it stands. A finished run stays until Enter closes it.
- `w` on Maintenance goes to `0` (the chooser is gone); `:wf` opens it and `:wf <name>` does what Enter on that workflow does. Tab and `h`/`l` walk all the screens, `0` included.

## A35. One program, a window with targets (2026-11)
- One binary, `sentry` (`crates/sentry`), over the target libraries (`sentry-local`, `sentry-server`). `sentry-server …` is the same executable under that name (a symlink beside it) and `sentry server …` the same command line; every command's output is unchanged.
- `sentry` opens this machine plus one target per server in `server_config.yaml`; `sentry-server [name]` the same window on that server. `[targets] show` orders and hides them. With one target there is no strip and nothing differs from before.
- The target strip is in the top bar: `F1`… by place, `{` / `}`, `:local`, `:server <name>` (`[keys] target.*`). A character bound to a target is text wherever text is typed. Each entry shows `*` (at work), `!` (needs you) and `auto`.
- A target reads and fetches nothing until it first has the window (a run left in progress is still picked up). Only the target in view polls for its screen.
- Work is parallel across targets and one after another within one. A run goes on whatever screen or target is in view: this replaces A34's "auto steps run only while `0` is in view". A target out of view never takes a key: what only the user can answer waits there, flagged in the strip and said once with the target's name. Auto mode keeps answering out of view what it may answer in view.
- Each target has its own sudo password; a prompt belongs to the target that asked and is shown only while that target is in view.
- This machine's reboot waits while another target is at work, says for which, and goes when that settles.
- `q` with several targets lists what each has going; quitting does for each what it did for one.

## A36. Plans are a session's (2026-11, replaces A31's plan writer)
- There is no plan writer. A session whose ask names a plan (a server's item, a workflow here) researches first (the ledger, the notes, the web) and answers with its assessment and one plan, or with a verdict `status = "wait"` (nothing changed, put off in `later.toml`, a `kind = "wait"` log entry). What it answered is kept as `plans/<key>.md` (the assessment and the plan's block); a ready plan on disk opens the session on it, at Review.
- `p` reads the kept plan, `P` starts over (the old one goes to `plans/done/`), `Enter` in the Plan view applies it in a session, `x` drops it. The document writer writes reviews only.
- A workflow starts without a start box (replaces A34's "the box that says what starting does"): Enter was the approval; values are asked first, confirm steps still ask.

## A37. One sudo password per target (2026-11, replaces the terminal handover of A27/A28 and extends A35)
- Asked once, in the window (the session's line, or the same line in the key bar), when the first thing needs root and sudo there wants a password; held in memory for that target while the window is open. `C-f`, quitting and a password sudo refuses forget it.
- Everything that needs root uses it: a workflow's sudo step, a session's, a server action, a kill, the reboot, the audit's sudo fix, the inventory and Claude's queued root reads. The step's shell gets a `sudo` stand-in that reads it through a pipe only the wrapper holds: no argv, environment, file or log has it. Nothing sentry runs for Claude or as a step has a stdin.
- The terminal is handed over only for an editor, a shell step, a pager, `toolbox enter` and Claude Code, never for sudo. `sentry workflow` in a terminal still lets sudo ask there.
- Stopping a step reaches what it started as root: each sudo runs in its own session, and the wrapper signals those groups, waits 5 s and kills what stays.

## A38. Auto mode (2026-11)
- `C-a` toggles it per target; off at start, never saved. Turning it on asks for the sudo password at once when sudo wants one.
- One pure rule (`auto::answers`) is asked at each decision point: a session's brief, plan and requests, a workflow's values when each has a default, its confirm steps, the log note, a series' next row. At most a fixed number in a row, and never while the user types.
- Never answered: a reboot, a manual or shell step, a step with `risky = true`, a command that upgrades, rebases, rolls back or flashes, what `claude::grantable` refuses, a box (actions, kill, cleanup), a wrong password, a verdict that isn't done. The one exception is a step with `stage = true`, which lint allows only where the command stages an `rpm-ostree upgrade` without a reboot.
- What auto answered is logged: the tag `auto`, "confirmed by auto" in the step's row, an "Answered by auto" section.

## A39. The network target (2026-11)
- A third kind of target (`crates/sentry-network`; `sentry-network …` and `sentry network …` are the one binary): a home network through its router, OpenWrt over ssh as root, described in `~/.config/sentry/network_config.yaml`, which sentry never rewrites. Scope `net:<name>`; in the strip after the servers (`:net <name>`).
- Nothing is installed on the router and nothing runs there between two looks. Screens: Dashboard, Clients (`2`), Network, Maintenance, Upgrade, History. Fixtures are synthetic; a real router is only ever read while developing, and everything that changes one is proven against a disposable router (`scripts/live-router.sh`).
- Secrets never leave the read that found them: a `uci` option that holds one is a tag (`redacted:<8 hex>`, a keyed hash with the network's own salt) from the parser on. Config backups are the router's own archive, encrypted on this machine as it arrives (age, recipients only); the plain archive never touches this disk.
- Workflows are the shared format with a router's `Env`: `config-backup`, `package-update` (named packages only; auto confirms it only when the simulated transaction touches nothing but leaves), `guarded-change`, and `firmware-upgrade` as a draft.

## A40. A router's read grammar and the guard (2026-11)
- The login is root, so sentry reads every line itself. A read is plain commands from a fixed list with literal arguments; the router runs what sentry rebuilt from its own reading, never the line as written. What follows a pipe is done on this machine, on the scrubbed output. Everything Claude is shown is scrubbed (secrets as tags, the uplink's addresses, MACs, SSIDs, hostnames).
- Every other line is one of: never (whoever allows it), a request the user is shown and allows (apply sessions only), only as a guard step, only as a workflow step (upgrades, the flash, a reboot). A router's session allows nothing by auto and has no web.
- The guard is the one way the network, firewall, wireless, dhcp, dropbear and uhttpd configs change: preflight, snapshot, a detached revert armed on the router before anything is staged, then stage, commit, reload, reconnect on a new connection and confirm twice a moment apart. Kept only when the router says its own claim was the one that held; a Wi-Fi or uplink change stays armed until the user says keep. While armed, the snapshot and a one-shot boot hook are on the router's flash, so a restart inside the window reverts too; both are removed after.
- A secret a guarded change sets is never written down on this machine: the run's `state.json`, its step logs, the guard's `pending.json`, the maintenance log and its ledger, a kept plan and what goes back to Claude have its tag, and the value is held in memory by the window that was given it. What is typed for it shows as dots. A tag is never applied as a value: a run resumed after a restart, or a plan opened later, stops at its guard step with nothing changed and says the value must be given again.

## A41. One session, every target (2026-11)
- The targets of a window are one system. An apply session reads on any of them (each through its own gateway, under its own read rules and scrubbing) and its one plan may have steps on several: `on = "<target id>"` on a step, the target it started on when left out. One approval; sentry runs each step on its target with that target's mechanics: its sudo password (asked once, in the session's own line, naming the target), a router's guard for its guarded configs, its workflows for upgrades and reboots. When a step fails because of something on another target, Claude fixes it there and retries, in the same session; there is no hand-off session and no to-do fallback. Not done only when the cause is outside every target the window has.
- Values travel inside the plan: `capture = "name"` keeps the last line a step prints on stdout, `{{name}}` uses it in a later step on any target, `secret = true` keeps it out of the plan, the pane, every log, every state file and every prompt (it is filled in as the step runs, in memory only). An `ask` step is the one way a value comes from the user: typed into the session's line, hidden, and the plan goes on. Claude never tells the user to enter, paste, set or run anything.
- What stays, because it protects the user rather than separating devices: approval before anything changes; each target's own rules for a step on it, whoever's session it is; `claude::grantable`; a router's scrubbing and its denials, which hold for every session that can reach it (the web aside: A43); auto answers only what it would on every target the session touches, so never with a router; one log entry per target touched, sharing a run id.
- `Task.after = "task:<target id>/<task id>"`: not due until that task is logged done under that target.

## A42. Security: threats you act on, and an audit of the whole system (2026-11)
- A network's Security (`4`) opens on a list: **Needs attention** in plain sentences (act now / look / note; what was seen, why it matters, what Enter does), **How you're covered** (a sentence and ok / weak / off per part), **Blocked by you**. The traffic panels are its evidence (`d`). Enter never toggles: a fixed remedy runs as the `security-action` workflow (its plan shown first, then one Enter; a config change through the guard), a real choice is asked first, anything else is a session with Claude. `x`/`b` expected, `z` later, as on Maintenance, with the same ids.
- The security audit is the window's: every target as one system. `S` on Maintenance or Security of any target, `:audit security`, and `sentry audit security`. Reads only; never a scan or a probe; no score. Its report (Do these first / Worth doing / Fine / Couldn't check) opens when the targets are read; Claude then reviews the evidence with the web and nothing else ("What matters most here"). The evidence carries no address, MAC, hostname or SSID.
- Each item is one row on one target: the network's Security for its own and for what spans targets, the others' Maintenance for theirs alone. Where a target already has the row for that subject (the one with the action), that row stays and takes the audit's why; nothing is listed twice. Enter on an item is a session that fixes it, across whatever targets it takes (A41); what only the user knows is a pick (yes / no / don't know) and the list follows the answer. What couldn't be checked says what to do in sentry's terms, never a command to run.
- It is a task of this machine's, every 30 days and after a firmware or OS upgrade; Enter runs it.
- What a server's guard reports (CrowdSec: attackers blocked today, whether the router enforces the bans) is on the network's Security when the window has such a server: said by the server target, carried by the app, read by name. CrowdSec at the edge is one row whose Enter is one session across the server and the router.

## A43. A session's web access goes by what it has read (2026-11, narrows A41)
- A session keeps the web until it has read from a router (a call through its gateway, a step or a request there) or was opened on something a router said. From the next turn on it has none, for the rest of the session, and says so once: "the web is off for this session: it has read from the router". What a router prints is partly other people's text; with the web beside it, a line planted there could ask for something to be sent out.
- A session started on a network never has the web. Sessions on a server or this machine research as before, a router in the window or not.
- A review can run nothing and write nothing: it keeps the web, the security audit's review included.

## A44. A resolved row leaves at once (2026-11)
- Everything that can change the Maintenance rows ends in one path, `Slot::rows_changed`: the records are read again (`tasks.toml`, `later.toml`, `baseline.toml`, `plans/`, `log/`, `reviews/`), the target makes again what it derives from them (`Target::refresh(Why::Lists, …)`), the cursors follow, and Records, if open, lists what there is now. A task done or removed, a row put off or marked expected, a review's changes, a run or a session ending, a log entry: all of them.
- What a stored audit report says was expected is what was expected when it was written. Whoever shows one marks it again from the baseline as it is now; a row marked expected no longer comes back when its screen is entered.
- What changed on disk without sentry is found by `Slot::look`, which compares the files' times (a handful of `stat`s): on `r`, on entering a screen, when the target gets the window back, after a turn of Claude's and after an editor. The target's own files count (`Target::files`: its config YAML, `items.toml`, `watch.toml`). Nothing watches in the background.
- The ways are listed once (`sentry_app::resolve::Way`) and driven the same on every kind of target through its `Rig`; a new way or a new target can't leave one out.

## A45. Done is the audit's to say (2026-11)
- After a finding's plan, sentry audits again by itself on every target, a server too (it used to leave that to Claude's own check), and the list is made from the new report. Where sudo asks and the password is held, what needs root is read again first.
- While the audit still reports the finding, the session can't settle done: Claude is told how it stands (the audit's message and evidence) and carries on, twice at most; after that it is the user's, not done, and what it logs says "Not resolved". A finding is never logged done while it is still reported.

## A46. Stop watching what was retired on purpose (2026-11)
- `watch.toml` beside a target's records (`maint::watch`): `[[unwatched]]` with `kind`, `name`, `since`, `why`. Applied over the config wherever it is read (`Remote::new`, `Router::new`); the YAML is never rewritten. Records › Later lists the entries; `u` watches the thing again and audits.
- A server: `timers`, `services`, `disks`, `smart`, and one container (it joins `containers.ignore`). A network: `expect.services`, `expect.forwards`. A maintenance item keeps its own way (`untracked` in items.toml). Lists that say what is allowed rather than what must be there (listeners, zones, the baseline's patterns) aren't covered: taking an entry out would add findings.
- A session reaches it as a plan step, `unwatch = "<kind>:<name>"` with `why`: shown and approved like any step, carried out by sentry (nothing on the host changes), tagged `unwatch:<key>` in the log. It may name only what the brief lists for its own target.
- Auto mode never approves a plan with such a step: what sentry stops looking for is the user's to decide.
- Marking a finding expected stays what it was: one finding id hidden, the thing still watched. A finding's brief tells Claude the difference: retired on purpose → stop watching it; should exist → fix it.

## A47. A level is a priority (2026-11)
- Shown: now / soon / normal / tidy. `routine` read as "recurring" on a one-time task; it never meant that. Files keep `level = "routine"` (written so, as before); `normal` is read too.
- Whether a task recurs is said beside its name, and only then: "· every 30d". A task without it is done once.
- A review is told that a level is priority only, that most one-time checks are `normal`, and that recurrence is `every`.

## A48. The audit looks behind each door (2026-11)
- For each TCP port a router forwards to one of sentry's own machines (not its ssh, not a range), sentry asks that machine once from this machine: `GET /` on the inside address and the port the forward arrives on, no login, no redirect followed, 5 s (`secaudit::probe`). First over HTTPS with the certificate checked (a failed check stops before any request), then without the check if that failed, or over plain HTTP if the port isn't TLS. Exactly one HTTP request per door; nothing of the answer is kept but its class and the certificate's days and kind of issuer.
- A 401/403, a redirect to a login page or a page with a password field: "asks for a login", and the door's question isn't asked. A page with content: the question becomes "it answers without a login: is that on purpose?". Anything else leaves the question as it was. An answer given before still decides.
- The door's item names what answers (the tracked item and its version, else the container, else the program) and whether it is behind; what runs there may come from the server's inventory, said with its age (older than three days: "may be out of date"); without it, the evidence says to press `I` on the server target.
- A door that speaks HTTPS gets a certificate item: expired → do first; under 14 days → worth doing; self-signed or from an authority this machine doesn't know → worth doing; else fine.
- The operating system's release (`/etc/os-release`) on every server and this machine is looked up on endoflife.date (a day's cache): past its end of support → do first on a server the internet reaches, worth doing elsewhere; within six months on a server, two months on this machine → worth doing. Not found or not known: couldn't check.
- A server's system log: forgotten at a restart, or reaching back under 14 days → worth doing; read without root where the login may read the journal, else as root through the sudo list or the inventory; else couldn't check.
- This machine's waiting updates count its Flatpak and toolbox updates (only counts taken after the last good quick-update), and "last update run" is that run.
- The flat-network item says how many of the devices are named and how many are on a cable or on Wi-Fi, and that the router can run a separate network itself when it has Wi-Fi. It still never guesses what a device is.
- The report: one line on what runs while sentry is closed (CrowdSec's bans, automatic security updates); "Do these first" holds five at most, the rest lead "Worth doing" and the header says how many; "Couldn't check" and "Needs your answer" are two sections, the questions last.
- `--outside` without `[audit] outside` says in three lines what to put there.

## A49. Log entries of the same minute (2026-11)
- An entry's file is `YYYY-MM-DD-HHMM-<what>.md` when that is free. When another entry has that name, the later of the two gets its seconds, `HHMM.SS-<what>.md` (`HHMM.SS-2-…` within the same second), so names still sort by time and the plain name stays the minute's earliest. Nothing reads entries by name: removal, replacement, retention and the ledger's links go by the file an entry is in; references (`run:<file>`, a review's run) keep naming the plain name as before.
||||||| parent of 739fd22 (Router firmware upgrade: owut's check and download read from its source, a flash that says what happens, a draft started only from its box)

## A50. The router's firmware upgrade, and how a draft starts (2026-11)
- `firmware-upgrade` is rewritten from owut's own source and a real router's answers: check → backup → plan (owut check) → download (confirm) → flash (confirm, risky, a box first) → wait → after → add-missing (confirm, risky, only when packages went missing). Every step is `sentry-network firmware <step>`; the image is `/tmp/sentry-firmware.bin` on the router, its record `networks/<name>/firmware.json` here.
- Only a patch release of the series the router runs; another series is refused with why. Anything owut warns about stops the plan before any download, said in plain words; what doesn't stop it is a short list (`firmware::HARMLESS`).
- Without `backup.recipients` the upgrade isn't offered: the firmware row's box says what to set.
- The download is checked by sentry too (the server's checksum and size, the version, every top-level package in the image, `sysupgrade --test`, memory left); anything wrong removes the image and nothing is flashed.
- The flash runs apart from the ssh session (`setsid`); sentry then waits up to 15 minutes from the flash for a new boot. Not back: the wait fails with what was running, when the settings were backed up and that recovery is the device's own procedure; opening the window again later carries on with the checks once the router answers.
- A draft starts in exactly one way: Enter on the firmware row opens a box that says what has and hasn't been proven, and its Enter starts the run. `:wf`, screen `0`, a series, a session's plan and auto mode still refuse it. After a good run sentry offers to take `draft = true` out of the file (only that line).
- A confirm step may carry `ask = "…"` (workflow format): its Enter on screen `0` shows that text in a box first (network target).
- Auto mode never confirms `firmware download` or `firmware add-missing`, besides `firmware flash`.
