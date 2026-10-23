# Sentry — Silverblue Monitor & Maintenance TUI: Build Spec

Oct 23, 2026 · @Shadow Beard

Target: Fedora Silverblue, RPM Fusion akmod-nvidia (layered), GNOME · Language: Rust + ratatui

## 1. Goal

A daemon-free Rust TUI for Fedora Silverblue that:

1. Shows live system health while open (btop-lite).
2. Runs security audits with month-over-month diff reports — on demand only.
3. Runs cleanup jobs (ostree, Flatpak, podman, caches) with dry-run preview and confirm.
4. Shows update and container status, and can apply updates.
5. Drives multi-reboot upgrade workflows (quick update, release rebase with NVIDIA rebuild) as a resumable state machine defined in editable TOML.
6. Optionally records metrics history via a foreground process the user starts by hand.

**Non-goals (v1):** multi-host, GUI, replacing btop, anything that runs without the user starting it.

## 2. Hard constraints

- **No background processes.** No systemd units, no timers, no sockets, no autostart. When `sentry` is closed, the only trace is files under `~/.config/sentry`, `~/.local/share/sentry`, `~/.cache/sentry`.
- Single static binary. Runtime deps limited to what Silverblue ships: `rpm-ostree`, `flatpak`, `podman`, `systemctl`, `ss`, `journalctl`, `notify-send`, `sudo`.
- Never requires root. Privileged ops go through `rpm-ostree` (polkit) or `sudo` steps that prompt in the terminal (TUI suspends raw mode).
- All destructive actions: dry-run preview → explicit confirm → streamed output.
- Live metrics refresh only while a live screen is in view. Slow/network collectors (update checks, Flatpak permission scans) never run automatically on open; they use an on-disk cache with age shown and a key to refresh.
- Light enough to leave open in a tmux pane: target < 1% CPU at 1 Hz dashboard refresh, < 40 MB RSS.

## 3. Run model & subcommands

One binary:

| Command | Purpose |
| --- | --- |
| `sentry` | Open the TUI. Resumes any in-progress workflow. |
| `sentry job <name> [--dry-run] [--tag T]` | Run one job headless. |
| `sentry check <name> [args]` | Built-in checks used by workflows (exit 0/1 + one-line reason). |
| `sentry workflow <name> [--var k=v]` | Start/continue a workflow headless (interactive prompts in terminal). |
| `sentry workflow lint <name>` | Validate a workflow file. |
| `sentry status [--short]` | One-line summary from state files only (due jobs, workflow in progress). Milliseconds, no collectors. Suitable for a shell prompt — opt-in by the user. |
| `sentry record [--interval 10s]` | Foreground metrics recorder (see §10). Exits on Ctrl-C. |
| `sentry collect <name> --json` | Dump any collector as JSON (scripting/testing). |

Concurrency: `std::thread` + channels for streaming command output into the UI. `tokio` optional; pick whichever is simpler.

## 4. Crates

| Purpose | Crate |
| --- | --- |
| TUI | `ratatui`, `crossterm` |
| Metrics | `sysinfo` |
| Serde | `serde`, `serde_json`, `toml` |
| Time | `jiff` (or `chrono`) |
| Diff | `similar` |
| CLI | `clap` |
| Logging | `tracing`, `tracing-subscriber` |
| Templating (workflows) | `minijinja` (small) or hand-rolled `{{ }}` |
| Errors | `anyhow`, `thiserror` |

Avoid `zbus`/D-Bus in v1; shell out to `notify-send`/`systemctl`.

## 5. Module layout

```
src/
  main.rs               # clap dispatch
  config.rs             # ~/.config/sentry/config.toml
  cache.rs              # on-disk cache of slow collector results, with timestamps
  status.rs             # `sentry status`
  collectors/           # read-only; each returns a serde struct
    system.rs           # cpu, mem, swap, load, uptime, temps (sysinfo)
    gpu.rs              # nvidia-smi --query-gpu (util, vram, temp, driver); optional
    disk.rs             # mounts, usage, /var and ~ breakdown (containers, flatpak, ~/.cache, ostree)
    net.rs              # iface throughput; ss listening + established
    ostree.rs           # rpm-ostree status --json; upgrade --check (cached)
    flatpak.rs          # list, remotes, permissions (cached), updates (cached), overrides
    podman.rs           # ps -a / images / volumes (json); toolbox/distrobox detection
    units.rs            # enabled user/system units, failed units, autostart
    repos.rs            # /etc/yum.repos.d third-party detection
    shell.rs            # suspicious patterns in rc files
    journal.rs          # recent warnings/errors, failed logins
  jobs/
    mod.rs              # Job trait + last_run/cadence tracking
    audit.rs
    cleanup_ostree.rs
    cleanup_flatpak.rs
    cleanup_podman.rs
    cleanup_cache.rs    # list-only unless dirs are opted in for deletion
    update_check.rs
    update_apply.rs     # rpm-ostree upgrade / flatpak update
  checks/               # `sentry check *`
  workflows/
    mod.rs              # loader, lint, templating
    runner.rs           # step state machine, gates, log capture
    state.rs            # run dirs, state.json, boot-id resume
  reports/              # store, list, diff, render
  recorder/             # `sentry record` + ring-buffer file reader
  tui/
    app.rs              # state machine, key handling (vim + [keys] overrides), startup resume
    screens/
      dashboard.rs  processes.rs  network.rs  updates.rs  containers.rs
      flatpaks.rs   audit.rs      jobs.rs     cleanup.rs  upgrade.rs  history.rs
    widgets/            # sparkline, gauge, table, log pane, modal, toast, key bar
```

## 6. Collectors — commands & gotchas

- **ostree**: `rpm-ostree status --json`. Extract booted/pending/rollback deployments, version, `requested-packages` (layered), base removals, overrides, GPG signature state, kargs (`rpm-ostree kargs`). Updates: `rpm-ostree upgrade --check` — cached, on demand only.
- **flatpak**: `flatpak list --app --columns=application,origin,version,installation`; `flatpak remotes --columns=name,url`; permissions from `flatpak info --show-permissions <id>` (or `~/.local/share/flatpak/app/<id>/current/active/metadata` — verify which parses cleaner). Flag rules (config): `filesystems` ∋ host/home/host-os; `session-bus` talk-name `org.freedesktop.Flatpak`; `devices=all`. Overrides dir `~/.local/share/flatpak/overrides/`. Updates: `flatpak remote-ls --updates` — cached.
- **podman**: `podman ps -a --format json`, `podman image ls --format json`, `podman volume ls --format json`. Detect toolbox/distrobox via labels (`com.github.containers.toolbox`, `manager=distrobox`). Stale = stopped > `stale_container_days`. Flag containers mounting `$HOME`.
- **net**: `ss -tulpnH`, `ss -tpH state established`. Parse (proto, local, pid, process). Known-listener baseline in config; new listeners are findings.
- **units**: `systemctl --user list-unit-files --state=enabled --no-legend`; same for system (read-only); `systemctl --failed`; `~/.config/autostart/*.desktop`.
- **repos**: files in `/etc/yum.repos.d/` not starting with `fedora`; parse section names + baseurl.
- **shell**: grep `curl|wget|base64|eval` in `~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc`.
- **journal**: `journalctl --user -p warning --since -24h -o json` (capped); system `-p err` if readable.
- **system**: `sysinfo`, selective refresh; 1 Hz on dashboard, 2 Hz on processes, idle elsewhere.

* **gpu** (optional): `nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu,driver_version --format=csv,noheader`; panel hidden when the binary is missing or fails.

Every collector: `--json` output, graceful "binary not found" handling.

## 7. Audit report, findings, diff, baseline

- Snapshot → `~/.local/share/sentry/reports/YYYY-MM-DD[-tag].json` mirroring collector sections + derived `findings[]` {severity, category, message, evidence}.
- Diff vs previous snapshot (structural: layered pkgs, repos, Flatpaks, permission flags, listeners, units, autostart, kargs) → rendered `.md` alongside; `similar` for text sections.
- Severity: **high** — new listener not in baseline, Flatpak gained host/home FS, new COPR, suspicious rc pattern, bad GPG sig. **medium** — new app from unverified origin, stale container with home mounted, failed units. **low** — unused runtimes, cache over threshold.
- Baseline: mark a finding "expected" in the TUI → `baseline.toml`, suppressed thereafter.
- Retention: 12 months (config).

## 8. Jobs, cadence, cleanup

Job trait:

```rust
trait Job {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn dry_run(&self) -> anyhow::Result<Preview>;
    fn run(&self, log: &mut dyn Write) -> anyhow::Result<Outcome>;
}
```

| Job | Suggested cadence | Action |
| --- | --- | --- |
| `audit` | 30d | snapshot + diff + findings |
| `update-check` | 7d | rpm-ostree + flatpak availability (no apply) |
| `update-apply` | — | `rpm-ostree upgrade` (stages, prompts reboot), `flatpak update -y` |
| `cleanup-flatpak` | 30d | `flatpak uninstall --unused` |
| `cleanup-podman` | 30d | prune stopped containers older than N days, dangling images |
| `cleanup-ostree` | 30d | `rpm-ostree cleanup -m`; `-b`/`-r` opt-in |
| `cleanup-cache` | off | report `~/.cache` entries over threshold; delete only opted-in dirs |

**Cadence is a reminder, never a trigger.** `last_run + suggested_every` → "due" badge on Jobs screen and dashboard count. Nothing runs unless the user presses go. Cadence per job is editable or disableable.

## 9. Upgrade workflows

### 9.1 Concept

A workflow = ordered steps in `~/.config/sentry/workflows/<name>.toml`, run as a resumable state machine. Each step runs only when the user confirms (default gate). Position persists to disk; reboots mid-workflow are normal. Resume happens when `sentry` is next opened (no daemon).

Shipped, editable: `quick-update.toml` (rpm-ostree upgrade + flatpak update, conditional NVIDIA step if kernel changed) and `release-rebase.toml` (seeded from the user's upgrade cheatsheet — to be provided to Claude Code).

### 9.2 File format

```toml
name = "release-rebase"
description = "Rebase Silverblue to a new Fedora release with NVIDIA re-install"

[vars]
target = { prompt = "Target Fedora version", default = "{{ current_version + 1 }}" }

[[steps]]
id = "preflight"
title = "Pre-flight checks"
run = "sentry check preflight --target {{ target }}"
gate = "auto"

[[steps]]
id = "snapshot"
title = "Record pre-upgrade state"
run = "sentry job audit --tag pre-rebase-{{ target }}"
gate = "auto"

[[steps]]
id = "rpmfusion"
title = "Swap RPM Fusion release packages to {{ target }}"
run = "rpm-ostree update --uninstall rpmfusion-free-release-{{ current_version }} --uninstall rpmfusion-nonfree-release-{{ current_version }} --install rpmfusion-free-release-{{ target }} --install rpmfusion-nonfree-release-{{ target }}"
gate = "confirm"
when = "rpmfusion_pinned"

[[steps]]
id = "rebase-dry"
title = "Dry-run the rebase"
run = "rpm-ostree rebase --dry-run fedora:fedora/{{ target }}/x86_64/silverblue"
gate = "confirm"
on_fail = "stop"

[[steps]]
id = "rebase"
title = "Rebase to Fedora {{ target }}"
run = "rpm-ostree rebase fedora:fedora/{{ target }}/x86_64/silverblue"
gate = "confirm"
timeout = "60m"

[[steps]]
id = "reboot-1"
title = "Reboot into new deployment"
kind = "reboot"

[[steps]]
id = "verify-boot"
title = "Confirm booted into Fedora {{ target }}"
run = "sentry check booted-version --expect {{ target }}"
gate = "auto"
on_fail = "stop"

[[steps]]
id = "nvidia-rebuild"
title = "Rebuild NVIDIA kernel modules"
run = "sudo akmods --force --kernels $(uname -r)"
gate = "confirm"
timeout = "30m"

[[steps]]
id = "nvidia-verify"
title = "Verify nvidia module built for running kernel"
run = "sentry check nvidia-module"
gate = "auto"
on_fail = "manual"

[[steps]]
id = "reboot-2"
title = "Reboot to load drivers"
kind = "reboot"

[[steps]]
id = "final-verify"
title = "Post-upgrade verification"
run = "sentry check nvidia-loaded && sentry check booted-version --expect {{ target }} && sentry check kargs"
gate = "auto"

[[steps]]
id = "post-snapshot"
title = "Record post-upgrade state and diff"
run = "sentry job audit --tag post-rebase-{{ target }} --diff-against pre-rebase-{{ target }}"
gate = "auto"

[[steps]]
id = "cleanup"
title = "Remove old deployment (optional)"
run = "rpm-ostree cleanup -r"
gate = "confirm"
optional = true
```

Field semantics:

- `run` — `sh -c` command; stdout/stderr streamed to UI and saved. `sudo` prompts in terminal.
- `kind` — `run` (default) | `reboot` (persist state, confirm, `systemctl reboot`) | `shell` (interactive shell; resumes on exit) | `manual` (instructions + "done" button).
- `gate` — `auto` | `confirm` (default) | `manual`. Reboot steps are always `confirm`.
- `on_fail` — `stop` (default) | `manual` (drop to a manual step showing failure output) | `continue`.
- `when` — condition name from the check suite (e.g. `kernel_changed`, `rpmfusion_pinned`).
- `timeout`, `optional`, `rollback = true` (marks a step runnable from "abandon").
- Templating: vars + built-ins `current_version`, `booted_kernel`, `pending_kernel`, `home`.
- `rpm-ostree` steps automatically get a `--dry-run` sibling shown first unless `dry_run = false`.

### 9.3 State & resume

`~/.local/share/sentry/workflows/<name>/run-<timestamp>/{state.json, steps/<id>.log}`. `state.json`: vars, current index, per-step status, boot ID recorded at each step. On TUI start (and `sentry status`): find in-progress runs; if last completed step is a reboot and saved boot ID ≠ `/proc/sys/kernel/random/boot_id`, the reboot happened → next step is ready; if equal, reboot never executed → ask. One workflow in progress at a time. Reboot card text: "State saved — run `sentry` after login to continue."

### 9.4 `sentry check` suite

- `preflight --target N` — free space on `/` and `/var`, no pending deployment, AC or battery > 50%, network, no in-progress workflow.
- `booted-version --expect N`
- `kernel-changed` — booted ≠ pending/staged kernel.
- `nvidia-module` — `modinfo -n nvidia` resolves for `uname -r`.
- `nvidia-loaded` — `lsmod` has nvidia and `nvidia-smi` succeeds.
- `rpmfusion-version` / `rpmfusion_pinned` — release RPMs match target / are version-pinned.
- `kargs` — `rd.driver.blacklist=nouveau modprobe.blacklist=nouveau nvidia-drm.modeset=1` present.
- `secureboot-mok` — if SB enabled, MOK key enrolled (`mokutil --sb-state`).

Add more as the cheatsheet reveals them.

### 9.5 NVIDIA-specific notes

- RPM Fusion release RPMs are usually layered version-pinned; must be swapped to the new version or akmods won't build.
- Kargs should survive the rebase; verify anyway.
- `akmods --force` can take minutes; show "still building" with elapsed time, generous timeout.
- Secure Boot: akmod signing must still work with enrolled MOK.

### 9.6 Safety

- Reboot never auto-executes.
- `sentry workflow lint`: unknown fields, missing/duplicate ids, undefined vars, unknown `when`/check names.
- Abandon: leave as-is, or run steps marked `rollback = true` (e.g. `rpm-ostree rollback`).
- Pre/post audit snapshots diffed at the end of every workflow run.

## 10. Recorder (optional, foreground)

`sentry record [--interval 10s]` — foreground process run in a tmux pane or spare terminal; samples CPU/mem/net/disk/temps/top-N processes; writes a compact ring-buffer file in `~/.local/share/sentry/metrics/` (config: `retention_hours`, `max_mb`); exits on Ctrl-C. No unit, no autostart. Target < 0.1% CPU, \~10 MB RSS.

TUI reads the file if present: dashboard sparklines extend back over the recording; **History** screen scrubs a time window. Optional threshold alerts (config) fire `notify-send` only while the recorder runs: `cpu > 90% for 5m`, `disk_free < 5%`, `new_listener`.

## 11. TUI screens & keys

Layout follows the Claude Design mockup (`Sentry TUI.dc.html`, attached to the repo): top bar `sentry · silverblue <ver> · kernel · uptime · live/paused · clock`, a tab strip with badges, a workflow banner when a run is in progress, a bottom key hint bar, toasts, and centered confirm modals (`y`/`Enter` confirm, `n`/`Esc` cancel).

Screen keys: `1–9` as numbered below, `0` Upgrade, `H` History; `Tab`/`Shift-Tab` cycle. Global: `?` help, `q` quit (confirm), `r` refresh current, `/` filter, `c` check now (network collectors; also rescans Flatpak perms on that screen).

**Vim navigation is the default and works on every screen.** `j`/`k` move the cursor in lists and tables, `h`/`l` move between screens (hence History on `H`, not `h`), `gg`/`G` jump to top/bottom, `Ctrl-d`/`Ctrl-u` page, `Enter` selects, `Esc` cancels/closes a pane, `/` opens a filter and `n`/`N` step through matches, `:` opens a command line (`:q`, `:job audit`, `:workflow release-rebase`). Arrow keys and PgUp/PgDn work too. In split screens (Upgrade, Audit), `Ctrl-h`/`Ctrl-l` move focus between panes and `Ctrl-j`/`Ctrl-k` scroll the log pane. Bindings live in `[keys]` in config and are overridable. (The mockup implements `j`/`k` and the screen keys; the rest is spec-only.)

1. **Dashboard** — CPU (total + per-core bars, temps cpu/gpu/nvme), memory + zram swap, GPU (util/VRAM/driver, if `nvidia-smi` present), disks with breakdown (containers, flatpak, \~/.cache, ostree), net sparklines with listening/established counts, and a Status panel: pending updates (cached, with age), findings by severity, failed units, due jobs, workflow in progress, recorder state. Keys: `c` check updates.
2. **Processes** — top by CPU/mem. `C`/`M` sort, `x` kill (confirm), `/` filter.
3. **Network** — listeners (`ss -tulpn`) with process; established. `e` mark listener expected → `[baseline].listeners`.
4. **Updates** — rpm-ostree deployments (booted/pending/rollback, layered pkgs) + available ostree and Flatpak updates (cached, age shown); warns when the kernel changes and points to `quick-update`. `c` check now, `u` upgrade (dry-run preview → confirm → stages, reboot required), `f` flatpak update, `R` rollback.
5. **Containers** — name, kind (toolbox/distrobox/other), status, age, `$HOME` mount flag, image; images/dangling/volumes summary. `Enter` enter (spawn `$TERMINAL`/`xdg-terminal-exec`), `s` stop, `d` remove.
6. **Flatpaks** — app, origin, version, permission flags; perms cache age + overrides count. `o` open in Flatseal if installed, `c` rescan perms.
7. **Audit** — findings (severity, category, message) with evidence pane; diff pane vs previous report. `Enter` run audit, `b` accept as baseline, `[`/`]` browse reports.
8. **Jobs** — job, last run, every, status, action. `Enter` run now, `e` edit cadence. Footer: "Cadence is a reminder. Nothing runs until you press Enter."
9. **Cleanup** — reclaimable estimates from dry-run with checkboxes and a selected total; right pane streams output. `Space` toggle, `Enter` preview & confirm.
10. **Upgrade** (`0`) — idle: workflow list (name, step count, description, last result); `Enter` start, `e` edit TOML. Running: step list with status glyphs (left), streaming log (right), vars + run dir shown, gate card for confirm/reboot/manual steps; `Enter` run, `s` skip optional, `a` abandon, `l` log. Reboot card runs `systemctl reboot` only after confirm and shows "run `sentry` after login to continue".
11. **History** (`H`) — shown only when recorder data exists; otherwise a hint to run `sentry record`. Per-metric sparklines over a window, alerts list, recorder pid/interval. `[`/`]` change window (6h/24h/72h), `←`/`→` scrub.

## 12. Config — `~/.config/sentry/config.toml`

```toml
[ui]
dashboard_hz = 1
processes_hz = 2

[cache]
update_check_max_age = "24h"     # show age; never auto-refresh

[audit]
retention_months = 12
stale_container_days = 30
cache_warn_mb = 2048

[flatpak]
flag_filesystems = ["host", "home", "host-os"]
flag_talk_names = ["org.freedesktop.Flatpak"]

[jobs]
audit.suggested_every = "30d"
update-check.suggested_every = "7d"
cleanup-flatpak.suggested_every = "30d"
cleanup-podman.suggested_every = "30d"
cleanup-ostree.suggested_every = "30d"

[cleanup.cache]
delete_dirs = []                 # opt-in, e.g. ["pip", "yarn"]

[recorder]
interval = "10s"
retention_hours = 72
max_mb = 50
alerts = ["cpu>90%:5m", "disk_free<5%", "new_listener"]

[baseline]
listeners = ["127.0.0.1:631/cupsd"]
```

## 13. Milestones

1. **Skeleton** — clap, config, TUI shell, static dashboard, startup resume hook (no-op).
2. **Collectors + screens** — all collectors with `--json`; on-disk cache; dashboard, processes, network, updates, containers, flatpaks.
3. **Audit** — snapshot, findings, diff, baseline, audit screen.
4. **Jobs** — Job trait, cleanup jobs with dry-run, last-run/cadence, jobs + cleanup screens, update-apply.
5. **Workflows** — TOML loader + lint, templating, runner with gates/log capture, reboot + boot-ID resume, check suite, upgrade screen, `quick-update` seeded; `release-rebase` seeded from cheatsheet.
6. **Recorder + History** — `sentry record`, ring-buffer format, history screen, alerts.
7. **Polish** — `sentry status --short`, missing-binary handling, footprint measurement, README.

## 14. Verify on the machine before coding against it

- [ ] Exact JSON shapes: `rpm-ostree status --json`, `podman ps --format json`, `podman image ls --format json` on installed versions.
- [ ] Whether `flatpak info --show-permissions` or the app `metadata` file is the better permissions source.
- [ ] `notify-send` behavior on the installed GNOME (used only by recorder alerts).
- [ ] Build environment: toolbox with `rust`/`cargo` vs layered; install target `~/.local/bin` vs `~/.cargo/bin`.
- [ ] Whether RPM Fusion release packages are version-pinned on this system; Secure Boot state; current kargs.
- [ ] The user's upgrade cheatsheet → map each line to a step; ask about anything that isn't `run`/`reboot`/`shell`/`manual`.

## 15. Open questions (defaults chosen)

- Name `sentry` — rename if it clashes.
- Process kill and `rpm-ostree upgrade` from the TUI included; drop for strictly read-only + cleanup.
- Terminal default colors only; themes deferred.
- `cleanup-ostree` with `-r` (remove rollback) stays opt-in and is the last optional step of `release-rebase`, never part of `quick-update`.
