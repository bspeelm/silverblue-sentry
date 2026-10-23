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
- The kernel-change ritual (see `docs/cheatsheets/silverblue-upgrade-cheatsheet.md` §2):
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
