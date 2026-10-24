# Spec addendum: binding amendments to `spec.md`

Decided 2026-10-23 during build prep, after probing the target machine. Where this file and `spec.md` disagree, **this file wins**.

## A1. Runtime environment
- Development happens inside a Fedora 44 **toolbox**. `rpm-ostree`, `flatpak` and `podman` exist only on the host. Every external command goes through `src/exec.rs`. When `/run/.containerenv` exists it adds the prefix `flatpak-spawn --host`. Binary availability is probed by path (`/run/host/usr/bin/<bin>` in a toolbox, `$PATH` otherwise) **before** spawning, because a missing binary via flatpak-spawn shows up as exit 1 with a portal error rather than 127.
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
Permissions are computed by parsing the app `metadata` keyfiles and applying override keyfiles (system/user, global/per-app, with `!` negation) in Flatpak's order. This is cheap (no subprocess per app), so it runs on screen entry and is **not cached**. Only `flatpak remote-ls --updates` (network) is cached.

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

## A11. Jobs (milestone 4)
- Every job is `sentry job <name>`. The TUI streams that same command (with `--yes`, after its own confirm modal), so output, reports and last-run records are identical either way. Headless runs prompt `[y/N]` on a terminal. With no terminal and no `--yes` they refuse, exit 1, and record nothing.
- `--only k1,k2` runs selected plan items (Cleanup screen). Without it, a run does only the default items. Opt-ins such as `rpm-ostree cleanup -b` always need `--only`.
- Last runs live in `~/.local/share/sentry/jobs.json`. Cadence is resolved as `~/.config/sentry/cadence.toml` (written by `e`), then `config.toml [jobs]`, then the spec default. A job that has never run counts as due. `c` in the TUI counts as an update-check run.
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
- `metrics/ring.bin` is a 64-byte header followed by fixed 128-byte records (layout in `src/recorder/ring.rs`). Capacity is min(`retention_hours`, `max_mb`), so the file never grows. A file with a different shape is moved to `ring.bin.old` rather than reinterpreted.
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
- **Listeners are grouped by service.** `src/audit/known.rs` maps ports to names, descriptions and advice: mDNS, LLMNR, DHCPv6, wsdd, SSH, CUPS, Syncthing, RDP/VNC, Samba, and so on.
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
