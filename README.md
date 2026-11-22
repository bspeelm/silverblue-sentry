# silverblue-sentry

A daemon-free monitor and maintenance TUI for **Fedora Silverblue**: live system health, security audits with month-over-month diffs, dry-run-first cleanup, and resumable multi-reboot upgrade workflows that know about the NVIDIA kmod dance. The binary is called `sentry`.

```
 sentry   silverblue 44.20261002.0  up 3d 04:12  ● live 1 Hz   Fri 23 Oct 16:04
 1 Dashboard   2   3 12   4 !   5   6   7   8   9   0
────────────────────────────────────────────────────────────────────────────────
┌ CPU · i9-14900K · 24c/32t ───────────────────────────────────────────────────┐
│ total  ██████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░  34%   load 0.95 1.02 0.91 │
│ ▃▁▁▂▄▅▆▆▆▅▄▂ ▂▃▅▆▆▆▆▅▃▁▁▃▄▅▆▆▆▅▄▂ ▂▃▅▆▆▆▆▄▃▁▁▃▄▆▆▆▆▅▄▂ ▂▄▅▆▆▆▆▄▃▁▁▃▄▆▆▆▆▅▄▂  │
│ cores  ▁▁▂▂▃▃▄▄▅▅▆▆▇▇█▁▂▂▃▃▄▄▅▅▆▆▇▇█▁▂▂                                      │
│ temp   cpu 53°C   gpu 36°C   nvme 44°C                                       │
└──────────────────────────────────────────────────────────────────────────────┘
┌ Memory ──────────────────────────────┐ ┌ Status ─────────────────────────────┐
│ mem   20.0 / 64.0 GiB                │ │ updates       216 os · 5 fp  2h ago │
│ █████████░░░░░░░░░░░░░░░░░░░░░  31%  │ │               kernel changes  kmod… │
│                                      │ │ findings      0 high · 2 med · 1 low│
└──────────────────────────────────────┘ └─────────────────────────────────────┘
 1-0  screens   c  check updates   r  measure disks   ?  help   q  quit
```

## Who it's for

People running Fedora Silverblue (or another rpm-ostree desktop) who want one place to see what the system is doing and to do routine maintenance carefully. It's most useful if you run **NVIDIA through RPM Fusion akmods with the built `kmod-nvidia` layered as a local package** (needed with Secure Boot): `quick-update` encodes the drop-old-kmod → reboot → build/layer-new-kmod → reboot ritual so you can't skip a step. Without NVIDIA, the GPU parts simply hide and the routine upgrade path is a single step.

It is opinionated about one kind of setup and encodes procedures proven on one machine. Read a workflow's TOML (`e` on the Upgrade screen) before trusting it on yours.

## Status and safety

**v0.5.1, early.** Everything here is built and tested against fixtures and a real Silverblue 44 machine, a real server and a real OpenWrt router. The quick-update kernel path (`rpm-ostree upgrade`, both reboots, layering the kmod, the GL runtimes) has been run end to end on that machine. Some paths have still only been exercised up to their confirm modal, never executed for real during development: `rpm-ostree rollback`/`cleanup`, `akmods` building a kmod, `flatpak uninstall`, `podman` prune/remove, and on a router the flash of the `firmware-upgrade` workflow (a draft: its check, plan and download have run on a real router, the rest only on a stand-in) and a reboot in the middle of a guarded change.

- Nothing runs in the background: no services, timers or autostart. The recorder is a foreground process you start and stop.
- Every destructive action shows a preview, waits for your confirmation, and streams its output. Reboots never happen on their own.
- `release-rebase` ships as a **draft** and refuses to start until you've reviewed it and removed `draft = true`.
- Workflow steps that need `sudo` must run from a host terminal, not from inside a toolbox.
- Never root: privileged operations go through `rpm-ostree` (polkit) or `sudo`. In the TUI sudo's password is asked once per target, in the window, and kept only while it is open (`C-f` forgets it); the terminal is never handed over for it. `sentry workflow` in a terminal lets sudo ask there.

## Install

One program, `sentry`. `sentry-server` and `sentry-network` are names for the same executable (links beside it), and `sentry server …` / `sentry network …` are the same commands without the links.

From source, which is how to get what this README describes (a toolbox with `cargo` and `make` works fine; Rust 1.95+):

```sh
make install-binary      # builds sentry and copies it to ~/.local/bin, with sentry-server and sentry-network as links to it
```

`make uninstall-binary` removes all three again, and `make check` runs the build, tests, clippy and fmt.

From a release (x86_64; built on Fedora 44 and linked only against glibc). One binary, `sentry`; make the two links yourself:

```sh
curl -LO https://github.com/bspeelm/silverblue-sentry/releases/download/v0.5.1/silverblue-sentry-0.5.1-x86_64-linux-gnu.tar.gz
curl -LO https://github.com/bspeelm/silverblue-sentry/releases/download/v0.5.1/silverblue-sentry-0.5.1-x86_64-linux-gnu.tar.gz.sha256
sha256sum -c silverblue-sentry-0.5.1-x86_64-linux-gnu.tar.gz.sha256
tar xf silverblue-sentry-0.5.1-x86_64-linux-gnu.tar.gz
install -Dm755 silverblue-sentry-0.5.1/sentry ~/.local/bin/sentry
ln -sfn sentry ~/.local/bin/sentry-server    # optional: servers over ssh
ln -sfn sentry ~/.local/bin/sentry-network   # optional: a network through its router
```

v0.4.0 and earlier shipped two separate binaries, `sentry` and `sentry-server`; if you are upgrading, the old `sentry-server` file is replaced by the link.

Inside a toolbox, host tools (`rpm-ostree`, `flatpak`, `podman`, …) are reached through `flatpak-spawn --host`, so `sentry` works from either side. It leaves files only under `~/.config/sentry`, `~/.local/share/sentry` and `~/.cache/sentry` (or the `XDG_*_HOME` locations).

## Commands

| Command | What it does |
|---|---|
| `sentry` | Open the TUI and resume any workflow in progress |
| `sentry job <name> [--dry-run] [--yes] [--only k1,k2] [--tag T] [--diff-against T]` | Run a job (below). It prints its plan, asks `[y/N]` on a terminal, then runs. Without a terminal it needs `--yes`. |
| `sentry check <name> [args]` | A built-in check: exit 0/1 plus one line of reason (2 = usage error) |
| `sentry workflow <name> [--var k=v]` | Start or continue a workflow in this terminal |
| `sentry workflow list` · `lint [name]` · `abandon` | List workflows, validate them, or abandon the run in progress |
| `sentry record [--interval 10s]` | Foreground metrics recorder for a spare terminal or tmux pane; Ctrl-C stops it |
| `sentry status [--short]` | One line from state files only (workflow, due jobs, high findings); runs no collectors. `--short` prints nothing when there's nothing to say. |
| `sentry audit security [--json] [--outside]` · `answers [<key> yes\|no]` | The security audit across this machine, every server and every network (below) |
| `sentry collect <name>` | A collector as JSON: `system processes gpu disk disk-breakdown net ostree flatpak flatpak-updates podman units repos shell journal`. Exit 3 = the tool it needs isn't installed. |

**Jobs:** `audit`, `update-check`, `update-apply`, `cleanup-flatpak`, `cleanup-podman`, `cleanup-ostree`, `cleanup-cache`. `--dry-run` shows the plan (what would run, what it would free) and changes nothing.

**Checks:** `preflight --target N`, `booted-version --expect N`, `booted-kernel --expect KVER`, `kernel-changed`, `nvidia-module`, `nvidia-loaded`, `rpmfusion-version --target N`, `rpmfusion-pinned`, `kargs`, `secureboot-mok`, `kmod-local [--exactly-one]`, `akmods-built [--exactly-one]`, `flatpak-gl-nvidia`, `flatpak-idle [--app ID]`, `master-repo-present`.

## Screens

| Key | Screen | Highlights |
|---|---|---|
| `1` | Dashboard | CPU (per-core), memory/zram, GPU, disks + breakdown, network graphs, status (updates, a staged reboot, findings, failed units, due jobs, workflow, recorder); `Enter` on a row opens its recommendation on Maintenance |
| `2` | Processes | `C`/`M` sort, `x` SIGTERM (confirmed) |
| `3` | Network | listeners as `baseline` / `local` / `client` / `NEW`; `e` marks one expected |
| `4` | Containers | toolbox / distrobox / podman, stale and `$HOME` flags, and pending dnf updates inside each toolbox (`old → new`). `c` checks (stopped toolboxes are started, then stopped again), `u`/`U` upgrade one/all, `Enter` opens a shell, `s` stops, `d` removes |
| `5` | Flatpaks | permission flags from metadata + overrides, GL.nvidia pair check, `o` opens Flatseal |
| `6` | Maintenance | what to do on this machine next (below), the deployments, and the selected recommendation's details. Views: `F` the audit report, `v` the maintenance log, `R` Claude's review |
| `7` | Cleanup | reclaimable space from dry runs (old deployments, unused Flatpak runtimes, podman leftovers, `~/.cache`); `Space` toggles, `Enter` previews, confirms and runs the selection, `r` re-plans |
| `0` | Upgrade | workflows: start, step cards (confirm / reboot / manual), streaming log, `s` skip (asks first unless the step is optional), `a` abandon, `R` roll back, `L` the step's log, `v` the maintenance log, `p` the saved plan, `P` plan it with Claude. On a failed step: `r` retry, `d` done by hand (asks first for a failed check), `f` fix with Claude; `A` on a run that has ended asks what happened |
| `H` | History | recorder data over 6h/24h/72h (`[`/`]`), `←`/`→` to scrub; the tab appears once `sentry record` has run |

### Maintenance

Maintenance is one loop, the same on every target: **notice** what needs doing (the list), **decide** (do it, put it off, or never), **plan** a big change with Claude, **do** it behind a confirm, **record** it (the maintenance log), and get **reminded** when it's due again (tasks). The list is screen `6` on every target; what's kept about it is **Records** (`v`).

**The list holds what's due or urgent, and is empty when nothing is** (every target). What nothing asks for yet waits out of sight: a newer version with no security fix, package or Flatpak updates nobody is waiting on, things to track, and anything at the tidy level (a low finding, a tidy task): tidy never needs doing. It comes up when something asks for it: a security fix, an end of life, a review date, a full disk, or the recurring task that covers it becoming due (a due `apt-maintenance` or `quick-update` run takes the updates in). The panel says how many wait (`3 can wait (o)`), and `o` lists everything, `o` again only what's needed. A cadence or job that has never run isn't due at once: its interval counts from when the maintenance log began (a task you or a review put in `tasks.toml` is due as soon as it's there).

**A series does several rows with one start** (every target): `Space` ticks a row (`a` ticks every row that can be, `Esc` unticks them all) and `Enter` then does the ticked rows one after another, in the list's order. Each opens by itself when the one before ended well: a finding or a task done by hand is an apply session that starts without its Enter; a workflow starts (Enter on the series was its start); on a server, an item's row is a session too, on its saved plan when there is one, and the series moves on when Claude's answer is to wait. What stays yours: `Enter` on each plan Claude proposes, a workflow's own confirm steps and values, and the sudo password, asked once per target and kept while the window is open. A row that doesn't end well stays open so you can read it: `Enter` goes on with the next, `Esc` stops the series. Stopped, the rows not done stay ticked and `Enter` on Maintenance goes on with them. Nothing is asked between rows: a run's log note can be added in Records, and the review of what's still due comes once, at the end. Rows that are one key anyway can't be ticked (a reboot, cleanup, track, check for updates).

**Auto mode** (`C-a`, every target; off at start, per target, never saved) answers the routine questions for you: a session's brief, its plan and what Claude asks to read, a workflow's values when each has a default, its confirm steps, the log note, a series' next row. Turning it on asks for the sudo password at once when sudo wants one. It never answers a reboot, a manual or shell step, a step marked `risky = true`, an upgrade, rebase, rollback or firmware command (the one exception: quick-update's steps that only stage an `rpm-ostree upgrade`), anything in a box (actions, kill, cleanup), a wrong password, or a verdict that isn't done: those ask as before and say why. What it answered is in the log (the `auto` tag, "confirmed by auto" on the step).

**Recommended** ranks what to do next, now / soon / normal / tidy (how soon it matters; a task that recurs says "· every 30d" beside its name), each with why; `Enter` does what it says:
- **The audit's findings**, each explained (what it is, why it's listed, what to do): `Enter` fixes it (with Claude Code, an apply session: Claude looks into it and proposes one plan, which sentry carries out once you approve it, see below; without it, sentry's own fixes: the exact command and how to undo it, asked first, sudo's password asked in the window, then a re-audit). `x` marks it expected (it asks first), `B` everything like it.
- **Updates waiting** (the OS, Flatpaks, toolboxes; the details show what changes, old → new, and whether the kernel changes): `Enter` starts `quick-update`, the one path that does Flatpaks, toolboxes, the OS and, when the kernel changes, the NVIDIA kmod ritual. It's the same workflow listed on Upgrade (`0`): starting it from either screen is the same run, shown on Upgrade, and while it runs Maintenance shows the run instead of the updates. `P` has Claude plan it first; `p` reads the plan that's kept.
- **A deployment staged** and waiting for a reboot (now after 14 days): `Enter` reboots after a confirm.
- **Tasks due**: the jobs' cadences (audit, check for updates, clean up; `[jobs]` in `config.toml`) and the tasks you took from reviews. A job whose last run failed. Cadence is a reminder; nothing runs by itself.
- **Space to reclaim** from the cleanup dry runs (now when a disk is past 90%): `Enter` opens Cleanup (`7`).
- **A workflow left in progress**, and **plans ready** to apply.

**The same keys on every target.** The key bar shows the keys the selected row takes; `?` lists them all.

| Key | On a row |
|---|---|
| `Enter` | do what it says |
| `p` / `P` | read its saved plan / have Claude plan it from the start (a plan it replaces goes to `plans/done/`) |
| `t` | track it (sentry-server: something discovery found) |
| `d` | done by hand (a task): logged at once, then a note if you like |
| `e` | how often a task recurs (`30d`, `off`) |
| `m` | a task done by hand: its steps, to do it yourself, then mark it done (`Enter` works it out with Claude) |
| `x` | dismiss it, after a confirm: a finding expected, a discovery ignored, a gone item untracked, a task removed (a built-in one turned off), a plan dropped |
| `B` | a finding: everything like it is expected |
| `z` | look again in 7, 30 or 90 days |
| `A` | Claude: **1** help me apply it, **2** just ask about it (a finding: its fix) |

The key bar shows only the selected row's keys (`Enter` names what it does: `install`, `fix`, `start`, `open plan`…) and three of the screen's: `c` checks everything (the audit, OS, Flatpak and toolbox updates, what cleanup could free), `v` opens Records, `R` reviews it all with Claude. The rest are in `?`: `w` the workflows (Upgrade), `F` the full audit report (marked `check` / `review` / `info`, known services named and grouped, the diff against the previous audit, `[`/`]` to browse reports, with the list's keys: `Enter` fixes, `x` expected on/off, `B`, and `c` audits again), `C` Cleanup. `:audit` opens the report, `:job <name>` shows a job's plan and runs it after a confirm; `:rollback` rolls back to the previous deployment behind its confirm.

**Records** (`v`, `:records`, `:log`, `:tasks`, `:plans`, `:reviews`, `:later`; every target) keep everything about the maintenance in one view, a section each (`[`/`]` switch):
- **Tasks**: every task that applies, due or not: what it does, how often, when it was last done and is next due, where it comes from (built in, the config, `tasks.toml`). `Enter` does it now, `d` done, `e` every, `x` remove (or off).
- **Log**: the ledger; `Enter` opens an entry, `n` adds a dated note to it.
- **Plans**: the open ones (`Enter` opens the Plan view: `Enter` applies it, `P` starts over, `x` drops it) and those done, applied, dropped or replaced (`Enter` reads it).
- **Reviews**: every review Claude wrote, and how many of its changes are still to apply; `Enter` opens one, `R` starts a new one. (`R` on Maintenance goes straight to the review window.)
- **Later**: what's put off with `z` (until when), findings and listeners marked expected, discoveries ignored; `u` brings one back.

What's put off is in `later.toml` (`~/.config/sentry/`, or `servers/<name>/` for a server; the old `maint.toml` and `servers/<name>.maint.toml` are moved there once).

`A` asks Claude about the selected thing (see below). Vim keys work everywhere: `j/k`, `gg/G`, `C-d/C-u`, `h/l` (previous/next screen), `/` filter with `n/N`, and `:` commands (`:q`, `:net`, `:job audit`, `:workflow quick-update`, `:log`). `C-h`/`C-l` switch panes and `C-j`/`C-k` scroll logs. `?` shows the keys for the current screen.

**Refresh:**
- Live data refreshes only while its screen is visible: the dashboard at 1 Hz, Processes at 2 Hz, Network every 3 s.
- Update checks (`c`), the disk breakdown (`r` on the dashboard) and cleanup plans run only when you ask, and are cached.
- Every destructive action shows a preview, asks you to confirm, then streams its output.

Measured on the host: the open dashboard uses about 0.8% of one core including children, and 8 MB of memory. The recorder uses 0.07% and 10 MB.

## Ask Claude

Press **`A`** on any tab to ask your local [Claude Code](https://claude.com/claude-code) about the selected thing: a finding, a listener, a process, a container, a Flatpak, a pending update, a cleanup item, a failed workflow step, or the dashboard as a whole. It uses the `claude` CLI and the login you already have, so there's no API key and nothing to configure. If `claude` isn't installed, `A` just says so.

- **You see what's sent.** A conversation opens showing the exact text that will go to Anthropic, with a line to add to it; nothing leaves before Enter. What you type later is sent as you typed it.
- **Claude can investigate, read-only.** It may run a fixed allowlist of read-only commands (`ss`, `systemctl status`, `journalctl`, `rpm -q`, `rpm-ostree status`, `flatpak info`, `podman inspect`, `firewall-cmd --list-all`, `gsettings get`, …) and read `/etc`, `/proc` and `/usr/lib/systemd`. It may also read your notes files (`[maintenance] notes`, or a server's `notes:`). Claude Code refuses anything else, including `sudo` and any writes, unless you grant it (below). The list is `ALLOWED` in `crates/sentry-core/src/claude.rs`.
- **In an apply session Claude finds out whatever it needs.** There (`A` → 1, or Enter on a task) it may run any command that needs no root and read any file but your keys and passwords, as you would in a terminal. `sudo` is refused, so it comes to you: Enter allows the exact command, your password is asked once, and sentry runs it and sends Claude the output. The same goes for removing or stopping containers and for `rpm-ostree` changes; upgrades, rebases, rollbacks and reboots are never run as commands, only by sentry's workflows. Your files change only when you allow it, and a plan runs only once you approve it. A command that needs no root and changes something would run unasked: the brief says to put changes in the plan, but nothing enforces that. The rules are `ASKS_FIRST` in the same file.
- **Granting files (`g`).** When Claude tries to read or edit a file it isn't allowed, the chat says so ("Claude asked to read … · g grants it"). `g` shows exactly which files, read or edit; Enter grants them for the rest of that conversation and tells Claude to carry on. Only that file is opened, by its exact path. Edits are only for files you own (anywhere, a work tree under `/var/mnt` too; never root's), never `~/.ssh`, `~/.gnupg`, keyrings or `~/.password-store`, and the file is backed up first (`~/.cache/sentry/claude/backups/`). After each answer, a file Claude changed shows in the chat ("✎ edited … · backup …") and goes in the maintenance log (`kind = "edit"`). What Claude reads is sent to Anthropic. A command Claude was refused is a request the same way, never something for you to run or paste: Enter allows one that only reads, and one that changes something goes to an apply session.
- **The answer streams into a chat pane.** You'll see the commands Claude ran and their results. A chat only explains: commands in an answer are text, never run from it. When what you asked about can be applied, **`a`** turns the conversation into an apply session (below) without starting over. Type a follow-up and press Enter to continue the same session. Esc while Claude is still answering hides the pane and lets it finish (the key bar says so; `A` brings it back); Esc on a finished answer closes it. Quitting sentry stops Claude.

### Applying a recommendation or a plan with Claude (`A` → 1, every target)

`A` on a Maintenance row (or in the Plan view) offers **1 help me apply it** or **2 just ask about it**; `Enter` on a task done by hand is **1** straight away. Applying is one session in one window, start to finish. You make two decisions, and the rest follows by itself:

**One session works across targets.** With several targets open (this machine, a server, a network) a session started on one reads on all of them and its plan may have steps on each (the plan view says whose each step is). You approve once; a server's sudo password is asked in the session's own line. A value one step makes (a key the server prints) is used by a later step on another target without ever being shown or written down, and a value only you have is asked for by the plan itself, typed hidden. If the cause of a failure is on another target, Claude fixes it there and retries. Each target's maintenance log gets its own entry. Auto mode never answers a session that involves a router. A session keeps the web for research until it has read from a router; from then on it has none, and says so once ("the web is off for this session: it has read from the router").

1. **Start (Enter).** The window shows what will be sent to Claude (the row: the updates waiting, the item's standing, the task's steps, the plan written earlier, the workflow that does it). Type anything Claude should also know, or just press Enter. Tab shows the whole brief.
2. **Claude looks into it** read-only, then answers with **one plan**: exact steps, in order.
   - **`edit`**: a file change, as the exact old text and its replacement (shown as a diff). Your own files anywhere, and root's configuration under /etc (written with your sudo; never sudoers, PAM or the password files). On a server, only files on this machine (the notes); the server's files change with `run` steps.
   - **`check`**: a command that must succeed; a failing check stops the plan.
   - **`run`**: a command that changes something.
   - **`workflow`**: when one of sentry's workflows makes the change (quick-update, apt-maintenance, a compose bump): it's started with its own confirm steps, and the plan waits for its run to end.

   A plan sentry can't use as written (old text that isn't in the file, a file it may not edit, a workflow that doesn't exist) goes back to Claude by itself for a corrected one (twice at most; then it's yours to tell Claude what to do).
3. **Approve (Enter).** The plan on screen is what runs; typing instead asks Claude for a change. If a step needs sudo and sudo asks for a password, it's asked once, inline (masked), checked with sudo, and handed to each sudo that follows through a pipe only that step holds: never in a command line, the environment, a file or the log. It's kept for that target while the window is open; `C-f`, quitting, or sudo refusing it forgets it.
4. **sentry carries it out**, step by step, each step's output under it as it runs. Every edited file is backed up first (`~/.cache/sentry/claude/backups/`). A step that fails stops the plan and goes back to Claude by itself, with its output, for a plan for the rest. `C-c` stops a step (nothing is sent). A workflow step shows how its run is doing; when it needs you, Enter opens it, and the session comes back when the run ends.
5. **Claude checks the result** (sent by itself once the last step is done) and gives a verdict: **done** (the task is marked done), **more** (with a plan for what's left: approve it the same way), or **not done**. What to do later (reboot to confirm, say) is said in words, never as commands. Something that can only be confirmed later becomes a **follow-up**: a one-time task on Maintenance, due after the next good run of the workflow Claude names (`after = "quick-update"`) or after a wait (`after = "7d"`). Enter on it works it out with Claude, like any task done by hand.

The window's top line says where it stands (`brief › investigate › plan › apply › verify › done`) and the key bar shows only what makes sense now. Esc hides a session that's working (`A` brings it back) and closes one that's done. Everything that ran is one entry in the maintenance log (`kind = "apply"`, tagged with the row, every file edited and, when done, the task; backups and how to undo it listed).

### Fixing a finding, a failed step, a unit or a container

Fixing anything is the same apply session as above, never a chat with commands to run:

- **A finding** (`Enter` on it on Maintenance, `f` in the audit report): Claude gets the finding, its evidence and sentry's own fixes for it. If leaving it alone is right, it says so and sends no plan (mark it expected with `x`). After the plan has run, sentry audits again before Claude checks the result (on a server and a network too), and the list is made from the new report: the row leaves only when the audit no longer has the finding, and the session can't end as done while it does (Claude is told how it stands and carries on). When the thing was retired on purpose and sentry only reports it because its config still lists it (a server's timer or service, a network's expected service or forward), the plan is one step that stops sentry watching it: nothing on the host changes, the config file isn't rewritten (`watch.toml` beside the records is applied over it), and Records › Later lists it, where `u` watches it again. The log entry is tagged with the finding. If it's still there when the session ends, Enter audits again.
- **A failed workflow step** (`f` on its card on Upgrade): Claude gets the step's command, exit code, log, the workflow's own advice and the steps still to come, and is told not to change deployments, run akmods, reboot or do a later step itself. When the fix is done, **Enter retries the step** and shows the run.
- **sentry-server**: a finding, a unit (Services) or a container (Containers), and a failed step of a run (screen `0`), the same way; commands run on the server, sudo's password asked inline.

When a session ends without Claude saying it's done (a task, or a plan done by hand), Enter marks it done by hand.

### Plans and reviews by Claude

For a bigger move, a release rebase or an update that changes the kernel, **`P`** (on a workflow in Upgrade, or on the updates recommendation) opens an apply session that researches first: the maintenance log, your own notes (`[maintenance] notes = ["~/notes/upgrades.md"]` in `config.toml`), release notes and known issues on the web, and this machine read-only. It answers with its assessment and one plan (what to check first, the workflow with its values, how to verify), or with the advice to wait and until when. Either is kept as `~/.config/sentry/plans/<workflow>.md` (a `+++` header, then Markdown), whether or not you approve the plan now. **`p`** reads it; `Enter` there, or on its "plan ready" row, opens the session on it again, at the plan to approve; `x` drops it and `P` starts over. A plan carried out moves to `plans/done/`. There is no separate plan writer: a plan is a session's. **`R`** on Maintenance has Claude review everything recommended and write what to do now, soon and routinely (`reviews/`); a review changes nothing on the machine.

**Two reviews start by themselves** (every target; `[review] at_start = false` or `after_run = false` in `config.toml` turns one off). When a workflow run ends well and tasks are still due, Claude reads the run's log entry and says which tasks it did (`[[done]]`, dated at the run) and which matter more because of it; the review window opens with them ticked and Enter applies them. At each start of the TUI a quick one checks whether anything changed since the tasks were last done (a new deployment or kernel, a new finding) and marks such tasks due again (`[[again]]`, with the reason shown on the row); it says so in one line only when it found something (`R` shows it). Each is one Claude turn in the background.

**A review changes the list in one go** (every target): `R` on Maintenance opens the review window. Before a review it shows what Claude will read, and `Enter` starts it. Claude looks at everything on the list (recommendations, tasks, what's put off; on a server the tracked items and what discovery found) and ends its review with the changes it proposes: tasks to add, remove or change (cadence, level), rows to put off until a date or bring back and, on a server, things to track, stop tracking or never suggest again, and an item's risk, hold reason, constraint or source. They're listed at the top of the window, ticked, each with its reason; `Space` unticks one and `Enter` applies those left ticked together, with no further questions (what couldn't be used is listed as "not used", with why). Only sentry's own files change: `tasks.toml`, `later.toml` and, for a server, `servers/<name>/items.toml` (`~/.config/sentry/…`; edit them freely). A server's `server_config.yaml` is never rewritten: what a review changes about an item defined there is kept in `items.toml` and applied over it (`untracked = ["<id>"]`, `[set.<id>]`; Records › Later lists what was untracked, `u` tracks it again). What was applied is one entry in the maintenance log. Nothing is changed without that `Enter`.

**Tasks**: a task is either once or recurring (`every = "90d"`), may wait for something first (`after = "quick-update"`: not due before that workflow's next good run; `after = "7d"`: a week after it was added), and does one thing: `run <workflow>`, `plan <item>` (sentry-server), `audit`, `job <name>` (sentry), or `by-hand` with Claude's steps. Recurring work the programs know is a task too, without being written anywhere: sentry's jobs (`[jobs]` in `config.toml`, else their defaults) and a server's `maintenance.cadence`. While it's due it's a row on Maintenance like any other: `Enter` does it (by hand: it opens Apply with Claude, which plans the change for sentry to apply; `m` shows the steps to do it yourself, then marks it done), `d` marks it done (logged at once as a by-hand entry tagged `task:<id>`; then a note if you like), `e` changes how often it recurs (asked in the key bar: `30d`, `off`; written to `tasks.toml`, where it takes the place of a cadence from the config, on every target), `x` removes it (a built-in one is turned off: `off = true` in `tasks.toml`), `z` puts it off. A task and a rule about the same thing are one row (a due `apt-maintenance` run takes in the updates waiting, and keeps their urgency); a task twice overdue is soon. Whether it's done is read from the maintenance log: a one-time task leaves when its workflow or item change ends well after it was added (or `d`); a recurring one comes back `every` after it was last done.

### The maintenance log

Everything done is written to `~/.config/sentry/log/`: every workflow run when it ends, each job's run (`sentry job`, or from the TUI; the audit and the update check keep only their latest), a reboot, an apply session, a toolbox upgrade, a task done by hand. A workflow run gets one Markdown entry (a `+++` header with the workflow, result, from/to versions, the steps that failed or were done by hand, the plan it applied, a summary and tags, among them `task:<id>` for the tasks it did, then the steps as a table and your note) and `LOG.md`, a ledger of every entry. The old `jobs.json` and `cadence.toml` are moved into the log and `tasks.toml` once, and renamed `*.migrated`. The key bar asks what to know next time. `v` (or `:log`) opens it in Records; Claude's plans start from the ledger.

**Retention** (`[retention]` in `config.toml`, every target): log entries past 12 months go (the newest 20 always stay, and `LOG.md` follows), each workflow keeps its newest 10 run directories (never one in progress), closed plans and one-time tasks done go after 12 months, reviews past the newest 10, and audit reports past 100 (besides `audit.retention_months`). Pruned when the TUI starts and after writes; nothing runs in the background.

## Workflows

Workflows are TOML files in `~/.config/sentry/workflows/`. The shipped ones are written there the first time you open Upgrade. A copy you haven't edited is upgraded when a new version ships; a copy you have edited is never touched.
- `quick-update`: A routine upgrade is one step. When the kernel changes, it runs the NVIDIA kmod ritual: drop the exact layered kmod, reboot, build or layer the new kmod, reboot, then verify the driver and Flatpak GL.
- `rpmfusion-migrate` (one time): RPM Fusion's release packages, installed from a URL, are pinned local packages tied to one Fedora version. This swaps them for the repo-tracked packages (one reboot), so they move with the system and a release rebase needs no swap.
- `release-rebase` ships with `draft = true`: sentry won't start it until you've read it and deleted that line. Before anything is staged, it checks:
  - that every enabled third-party repo (COPRs, RPM Fusion, vendor repos) already has metadata for the target release;
  - that `rpmfusion-migrate` is done.

  Then it pins today's deployment, so a current Fedora N stays in the boot menu after the two new deployments, and does the rebase with the kmod ritual. Optionally it then distro-syncs your toolboxes, after saving each one's package list. Abandoning offers `rollback`, which makes the pinned deployment the next boot.

Each run lives in `~/.local/share/sentry/workflows/<name>/run-<time>/`, holding `state.json`, a copy of the TOML, and `steps/<id>.log`; the newest 10 per workflow are kept. What each run did is in the maintenance log.

Reboots happen only after you confirm them. After one, open `sentry` again. Sentry compares boot ids to tell whether the reboot actually happened, and continues once you open Upgrade (`0`).

Lint (`sentry workflow lint`) checks for unknown fields, duplicate ids, undefined variables, unknown `when` conditions and unknown `sentry check` names. The file format is spec §9.2 plus a few additions described in `docs/spec-addendum.md` A3/A12.

## sentry-server: a server over ssh

`sentry-server` is the same program under a second name (`sentry server …` is the same thing), for a server you reach with `ssh`: a Debian or Ubuntu box running systemd services, timers and docker compose. It follows the same rules as `sentry`:
- **Nothing is installed on the server.** It runs read-only commands through one multiplexed ssh connection while you have it open. That connection closes by itself 15 s after the last command.
- **Nothing changes without your key**: a confirm box showing the exact command, a workflow's confirm step, or the plan you approve in an apply session.
- **The server is described in one file you write,** `~/.config/sentry/server_config.yaml` ([sample](assets/server_config.example.yaml)). sentry-server never rewrites it.

**Setting up a server:**

```sh
sentry-server init myserver --write   # look around (read-only) and draft its entry
$EDITOR ~/.config/sentry/server_config.yaml
sentry-server lint                     # the file, and that what it names exists there
sentry-server check                    # connection, sudo, tools, and each sudo entry
sentry-server                          # the TUI (or: sentry-server myserver)
```

**One window, several targets.** Once a server is configured, `sentry` opens with a target strip in the top bar: this machine, then each server, then each network. `sentry-server [name]` opens the same window on that server (`sentry-network [name]` on that network). Each target keeps its own screens, runs, sessions, sudo password and auto mode (`C-a`).

| Key | Does |
|---|---|
| `F1` … | the target at that place in the strip |
| `{` / `}` | the previous / next target |
| `:local`, `:server <name>`, `:net <name>` | by name (the start of it is enough) |

- **Work goes on in parallel across targets**: a server's package update and this machine's quick-update can run at once. Within one target it stays one thing after another.
- **A target out of view never takes a key.** When it comes to something only you can answer (a confirm step, a plan to approve, the sudo password, a failed step), its strip entry shows `!`, one message names it, and it waits until you look. `*` means it's at work; `auto` that auto mode is on there, which keeps answering the routine questions out of view too.
- **A target costs nothing until you look at it**: no ssh, no fetch, no review at start. Only the target in view polls for its screen. A run left in progress last time is still picked up at start.
- **This machine's reboot waits** while another target is at work, says for which, and goes by itself when that settles.
- **`q` lists what each target still has going** before you confirm. Quitting does for each what it always did: a run's state is saved and it carries on next time; a session's Claude is stopped.

`[targets] show = ["local", "srv:myserver"]` in `config.toml` orders the strip or hides a target (default: all, this machine first); `[keys] target.next`, `target.prev` and `target.1`… rebind the keys. With no server or network configured there is no strip, and with only one target shown the window is that target's alone.

Key-based ssh login is required. **`sudo:` lists read-only commands** sentry-server may run as `sudo -n` (`docker ps`, `smartctl`, `journalctl`, …), because the docker socket, SMART and system journals usually need root. Write commands are refused there. What changes the server uses sudo behind its own key. sudo is checked again before each: if it asks for a password, sentry asks for it once, in the window (the key bar, or the session's own line), keeps it for that server while the window is open (`C-f` forgets it) and hands it to each sudo that follows. The terminal is never handed over for sudo, and the password is in no command line, file or log. If sudo asks for a password, the read-only commands in `sudo:` can't run in the background; **`I` reads them once with your password** (containers, compose files, SMART, the journal, fail2ban: one sudo, all read-only), and Containers, SMART and the audit use that read, with its age shown, until it is read again (by itself after a run, while the password is held). Workflow checks never use it: they need the server as it is now.

The screens have sentry's numbers and names wherever they are the same thing (`:overview` still works; `[keys]` in `config.toml` applies here too):

| Screen | What it shows | Keys |
|---|---|---|
| `1` Dashboard | CPU, memory and network at 1 Hz; temperatures and GPU; disks against their thresholds, SMART (sleeping disks are left asleep); status rows that jump to their screen | `a` your actions, `B` reboot |
| `2` Processes | the server's processes, top by CPU or memory like sentry's; one sample (`ps` and /proc, no sudo) every 2 s while the screen is shown, CPU as a share of one core between two samples | `C`/`M` sort, `/` filter, `r` now, `x` SIGTERM after a box showing the command (another user's process: through sudo, like the other actions; nothing is signalled if the pid is no longer that process) |
| `3` Network | what listens on the server, as `baseline` / `local` / `client` / `NEW` (the audit's own rule, so the red count on the screen's name and the listener findings on Maintenance agree), and the established connections; read with one `ss` every 5 s while the screen is open, without sudo. A process only root can see shows as the container publishing the port, or `needs I` / `needs sudo: ss -tulpn` | `b` marks the port expected on every address, and its finding (`servers/<name>/baseline.toml`); `b` again takes that back |
| `4` Containers | containers by compose project: state, health, restarts, ports; `c` loads CPU/mem | `R` restart, `L` logs, `p` pull, `u` up -d |
| `5` Services | configured services and timers (last run, next run, result), failed units | `R` restart (or run a timer's job now), `x` reset failed, `L` journal |
| `6` Maintenance | **Recommended** first: everything that needs doing on the server, ranked now / soon / normal / tidy, each with why: the audit's findings (services down, stale or failing timers, containers down or restarted, the docker socket mounted in a container, unexpected listeners, SMART damage, full or missing disks…), security fixes, ends of life, drift, reviews due, plans ready, workflows due by `cadence:`, package updates and reboots waiting (their details show the packages old → new, held back, and why a reboot is needed), an audit over a week old, things on the server that aren't tracked, tracked things that are gone. Below it, what's kept at a deliberate version (`maintenance:` in the config): images, held packages, apps, an OS's end of life, things to retire. Pinned vs running vs newest upstream (looked up from this machine, at most daily unless you press `c`), security releases marked ⚠, why it's held, its review date. Findings wait for a held item's review date | `Enter` does what's recommended (a finding: ask Claude to fix it; updates: start `apt-maintenance`), `x` dismisses it after a confirm (a finding: expected; a discovery: ignored; gone: untracked; an item: drop its plan), `t` tracks, `z` puts it off, `A` asks Claude about any row, `c` audits and looks upstream up, `Enter` on an item with something to do opens its apply session, which researches and plans the move (the plan is kept as a Markdown file; one kept earlier is where the session starts), `p` reads the kept plan (there: `Enter` applies it, `x` drops it), `P` plans it again from the start, `w` starts a workflow, `R` Claude reviews it all, `v` Records (tasks, log, plans, reviews, what's put off; as in sentry), `e` edit the config (on a task: where it's written) |
| `H` History | what was recorded for the server, as sentry's graphs over 6h / 24h / 72h. The ring is on this machine (`~/.local/share/sentry/servers/<name>/metrics/ring.bin`, 10 s, 72 h, 3.3 MB) and is written only while sentry-server samples the server: the Dashboard or Processes open, or `sentry-server record <name>` in a spare terminal (foreground, until Ctrl-C). Times nobody sampled are gaps. Nothing records on the server. In the strip once there's a ring | `[` `]` window, `←` `→` scrub, `r` reload |

Maintenance on a server is laid out and keyed like sentry's: Recommended over **Items** (where sentry shows its deployments), Details on the right. `F` opens the audit report over it (a report's findings with the selected one explained, beside what is new, gone and unchecked since the report before; `[` `]` browse the reports kept, `x` marks a finding expected or takes that back, `B` everything like it (`srv:<kind>:*`), `Enter` fixes it with Claude, `Esc` goes back; `:audit` opens it from anywhere, `:audit now` audits). `B` works on a finding's row too. `z` offers 7, 30 or 90 days on every row (an item's date is its review date). `e` on a task asks how often it recurs; on an item it opens `server_config.yaml`, where items are defined. `Enter` on an item opens its session (on its plan when one is kept) when there are newer versions or it's to be retired, and otherwise opens its log. `w` goes to the workflows on screen `0`.

**Workflows** are multi-step maintenance in the same TOML format as the local workflows: `apt-maintenance` and `compose-update` are seeded in `~/.config/sentry/server-workflows/`. A server's own workflows go in `~/.config/sentry/servers/<name>/workflows/` and replace the generic ones for that server; `[vars]` are asked for when one starts. They're on screen `0` (**Upgrade**, as in sentry; `w` on Maintenance and `:wf` go there): the list with each one's steps, lint and last run, `Enter` to start the one selected (its values first, when it takes any; there is no start box: Enter was the approval, and its confirm steps still ask), `e` to edit its file, `r` to read them again. A run also starts from a recommendation, a plan or `:wf <name>`, and is followed on the same screen: its steps, step cards and log, with Enter, `s`, `d`, `r`, `a`, `L` as in sentry, and `C-c` to stop a running step. A run goes on whatever screen or target is in view; away from screen `0` a banner under the strip says where it stands, and when it needs you (`press 0 to continue`).

On Services, Containers and Maintenance, `/` filters the list (any column, case-insensitive; `n`/`N` step through, `Esc` clears); each screen keeps its own filter.

A reboot, from `B` or a workflow step, waits in place: sentry-server polls the server's boot id and says when it's back, then a workflow carries on. **`A` asks Claude** about whatever is selected. Claude reaches the server only through `sentry-server exec <server> -- <command>`, an allowlist of read-only commands with no shell, and ssh itself is denied. An apply session also has `sentry-server run <server> -- '<command line>'`, which runs anything as your login (no root): turning the server off and files that may hold secrets are refused, and a line with `sudo` becomes a request that Enter allows, run with your password. A read that needs root while sudo asks for a password is queued: when Claude's answer ends you see the exact commands, one sudo with your password runs them (read-only), and the output goes back to Claude. What it proposes in an apply session is one plan: you approve it, sentry-server runs it.

### Deliberate maintenance

Pinning everything is fine for a while; eventually the pins have to move. `maintenance:` in the config lists what you keep at a deliberate version: compose images, held packages, apps on the host, an OS release's end of life, and things you mean to retire. Each item says why it's held, what limits the choice and when to look at it again. sentry-server then keeps that list honest without ever upgrading anything by itself:

1. **Track** (screen `6`, `sentry-server maint`): pinned vs running vs the newest upstream release, looked up from your machine. Discovery keeps the list in step with the server: compose services, other containers, held packages, the kernel, GPU driver and container engine, and the OS release that aren't tracked are suggested (`t` tracks them into `servers/<name>/items.toml`, beside your config), and tracked things that are gone are flagged. Newer releases whose notes mention a security fix are marked; so are drift (what runs isn't the pin), end of life and review dates that have passed. A held item doesn't nag until its review date.
2. **Review**: the Recommended list, by rules, always on; and `R`, where Claude reviews it all (every item's standing, the ledger, upstream's release notes, your notes) and writes what to do now, soon and routinely, and why, to `servers/<name>/reviews/<date>.md`. It ends with how the list should change (tasks, tracked items, what can wait), ticked in one list that `Enter` applies together (see *A review changes the list in one go* above).
3. **Plan** (`Enter` on the item, or `P`): an apply session that researches first (release notes, your notes, the server read-only; reads that need root are asked for) and answers with the target and its assessment, what to check and back up before, the item's workflow with its values, how to verify and roll back, or with the advice to wait. It's kept as `~/.config/sentry/servers/<name>/plans/<item>.md`: a header saying how to apply it (target, workflow, its values, status), then the plan. `p` shows it as a document; `P` starts over.
4. **Apply** (`Enter` on the "Apply the plan" recommendation, or in the Plan view): an apply session opens on the kept plan, ready to approve: its Before checks, the item's workflow with the plan's values (filled in when the workflow asks for them), or the commands when no workflow applies it (an item without a `workflow:`), and its Verify checks. You approve it once; sentry-server runs it (sudo asked inline), Claude verifies, and when it's done the plan moves to `plans/done/` and the run is in the log. Sessions on a server may read the web too, for release notes. `z` moves the review date instead. (`p` reads an item's plan, `P` plans again.)
5. **Log**: every workflow run, from a plan or not, is written to `~/.config/sentry/servers/<name>/log/` when it ends: one Markdown entry per run (a `+++` header with item, kind, from/to, workflow, result, when, the steps that failed or were done by hand, the plan it applied, a one-line summary and `key:value` tags, then the steps as a table and your note on what to know next time), and `LOG.md`, a ledger of every entry with its summary and tags. Plans and reviews start from the ledger: Claude picks the earlier runs that bear on the change and reads those entries. `v` on Maintenance (or `:log`) opens it in Records: the ledger as a list (the selected item's entries marked), `Enter` opens an entry, `n` adds a note.

A server's own workflows (`~/.config/sentry/servers/<name>/workflows/`) are where its specific procedure lives: what to check before, the exact pin change, how to verify and roll back.

Headless: `sentry-server audit`, `record [server]` (metrics every 10 s into the server's ring for History, from this machine, until Ctrl-C), `collect <server> <kind>` (JSON), `cond <server> <condition> [--wait]`, `workflow list|lint [server]`, `maint [server] [--refresh]` (each maintenance item's standing; see `maintenance:` in the sample config). Reports, run state and baselines live under `~/.local/share/sentry/servers/<name>/` and `~/.config/sentry/servers/`.

## sentry-network: a home network through its router

`sentry-network` is the same program under a third name (`sentry network …` is the same thing), for the router of a network you run: OpenWrt, reached with `ssh` as root (a GL.iNet GL-MT6000 on OpenWrt 25.12 is what it was built against). The same rules hold: nothing is installed on the router and nothing runs there between two looks; sentry looks, compares with what you said to expect, and tells you. Built so far: the Dashboard, who is on the network, the firewall and what listens, an audit with its findings on Maintenance, the firmware and the packages against what's released, encrypted config backups, its workflows (`config-backup`, `package-update`, `guarded-change`; `firmware-upgrade` as a draft), Claude through a gateway, and History. It changes the router only through its workflows and the guard (below), and Claude reads it only through a gateway that hides what is private.

```sh
sentry-network init myrouter     # look at the router (read-only) and write a starter network_config.yaml
sentry-network lint              # the file, checked without contacting the router
sentry-network check             # reachable as root? the release and board, the ports, the uplink, the tools
sentry-network audit             # what needs attention, written to a report
sentry-network backup            # back the config up, encrypted to backup.recipients
sentry-network                   # the TUI (or: sentry-network home)
```

**The network is described in one file you write,** `~/.config/sentry/network_config.yaml` ([sample](assets/network_config.example.yaml)): the router's ssh name, what the firewall should look like (zones, port forwards, what may listen), the devices you know (by MAC, or by hostname for one with a private MAC), thresholds, who can decrypt a config backup, and what maintenance to keep up. `init` drafts it from what the router reports, with every device holding a lease listed for you to name, and never touches a file that is already there. sentry never rewrites it. `notes` are the files Claude may read; `claude: { share_wan_address: true }` leaves the uplink's address in what it is shown; `guard: { window: 300 }` is how long the router waits before it takes an unconfirmed change back.

Once a network is configured, `sentry` shows it in the target strip after the servers (`F3`, `}`, or `:net home`); `sentry-network [name]` opens the same window on it. Nothing is read from a router until its target first has the window.

| Screen | Shows | Keys |
|---|---|---|
| `1` Dashboard | the router (release, board, uptime, load, CPU, temperature, memory, flash in use), the uplink (address, gateway, the DHCP lease, DNS, the IPv6 prefix; "down" when it is), and a row per port and Wi-Fi radio: which network it belongs to, link and speed, and how fast it moves data in and out now, with the last minutes as a sparkline when there's room | `r` read again |
| `2` Clients | every device on the network, once: its name (from `devices:`, else the hostname it gives, else its MAC; `~` marks a private, randomised MAC), how it's connected (the wired port, the radio with signal bars and dBm, or a routed port such as a DMZ), its address, how long its lease runs, when it was last seen. Unknown ones first, marked `NEW`. Read every 10 s while in view. No key does anything to a device | `Enter` details and the line that names it in the config, `s` sort (name, link, signal, lease), `b` expected on/off, `/` filter |
| `3` Network | the firewall's zones and port forwards beside what `expect:` says, differences marked; under them every listening socket on the router with its status: `local`, `client`, `baseline` (expected) or `NEW` | `b` expected on/off, `/` filter, `r` read again |
| `4` Security | **Needs attention**: what was seen, in plain sentences, ranked act now / look / note, each with why it matters and what Enter does about it. **How you're covered** under it: what the internet can reach, who is on the network, the sides kept apart, the filter for bad sites, Wi-Fi, admin access. **Blocked by you** when something is. Beside them the selected row's detail and the numbers behind it; `d` shows all the numbers (ingress, egress, zones, DNS, Wi-Fi). Counters every 10 s, flows every 30 s, the log on entry | `Enter` what the row names (decide about a device, close a door, keys only, HTTPS, refresh, unblock…), `x`/`b` expected, `z` later, `o` what is only good to know, `A` Claude, `d` the numbers (there: `Enter` a device's flows, `s` sort), `/` filter, `r` read again |
| `6` Maintenance | what the audit found, most pressing first, what the firmware, the packages and the backups ask for, and the tasks due (`tasks.toml`, and `maintenance.cadence`: `config-backup every 30d` is a task whose Enter runs it). Under the list the Items, on the same cursor: firmware (installed → latest, end of life), packages (how many could be upgraded, how old the index is), backup (how old the newest is, changed since or not); then what the last audit looked at. Entering it audits again when the last report is a week old | `Enter` the finding in the report, or the row's workflow, or how the item stands; `Space`/`a` tick rows for a series, `x`/`b` expected, `B` all like it, `z` later, `o` what can wait too, `d`/`e`/`m` on a task, `r` refresh, `c` audit, `F` the report, `v` records |
| `0` Upgrade | the network's workflows (seeded: `config-backup`, `package-update`, `guarded-change`, `security-action` (what Enter on Security runs), and `firmware-upgrade` as a draft; your own in `~/.config/sentry/networks/<name>/workflows/` replace them), and the run in progress, as on a server | `Enter` start / run the step, `s` skip, `a` abandon, `L` log, `C-a` auto |
| `H` History | what was recorded for the router, as sentry's graphs over 6h / 24h / 72h. The ring is on this machine (`~/.local/share/sentry/networks/<name>/metrics/ring.bin`) and is written only while sentry samples the router: its Dashboard open, or `sentry-network record <name>` in a spare terminal (foreground, until Ctrl-C). In the strip once there's a ring | `[` `]` window, `←` `→` scrub, `r` reload |

A rate is the router's own byte counters over its own clock (`Δbytes · 8 / Δuptime`), so a slow ssh round trip doesn't bend it; a port shows `–` until there are two samples, and after a counter reset or a reboot. The lease line is exact only until the lease is first renewed: after that the router says only how long the lease is, so it reads "renewed, 1h–2h left". While the Dashboard is in view the router is asked once a second (one ssh exec, about 4 ms of shell there) and its interfaces every 30 s; out of view, nothing.

**Security** opens on what needs you. A row says what was seen ("A device nobody has named joined the Wi-Fi 20 minutes ago", "Something on the server's side is talking to a device on your home side: that should never happen", "Someone tried a wrong Wi-Fi password 12 times in the last 2 h 40 min"), why it matters, and what Enter does. Enter never flips a switch: it shows a plan first (a step that only reads), and the change waits for one more Enter. What it can do:

- **A device**: give it a name (kept in sentry's own `~/.config/sentry/networks/<name>/names.toml`; `network_config.yaml` stays yours), block it from the internet or from everything, pause it for an hour or until the morning, send it off the Wi-Fi for ten minutes. A block is a firewall rule by MAC named `sentry-block-…`; "Blocked by you" lists them, and Enter there removes exactly that rule. A pause has no timer on the router: when it ends, a row offers to lift it.
- **A door** (port forward) you haven't listed: close it (it can be opened again from the same place), remove it, or say it is meant.
- **ssh with keys only**: sentry first proves on a new connection that a key gets in, and again before the change is kept; if the first proof fails nothing is changed.
- **The admin page on HTTPS**: kept only if the page still answers on HTTPS from your machine.
- **The list of bad sites**: fetch it again (the blocklist package's own download), or turn its own schedule on.
- **A new Wi-Fi password**, typed as dots and never written down, kept only when you say a device could join.

Every config change goes through the guard: the router is armed to undo it by itself before anything changes, and the change is kept only if the router still answers as before. A row can be marked expected (`x`, `b`) or put off (`z`): the same lists Maintenance uses, so it is gone there too. What has no fixed remedy (a live connection across sides that are kept apart, a service down) is a session with Claude: it plans, you approve. `sentry-network security [name]` prints the list and the cover as text (`--json` as data). Not shown to work on a real router yet: that a block really stops the device (the test router can't load a firewall), the HTTPS and blocklist actions, sending a station off the Wi-Fi.

The numbers (`d`) are the firewall's own counters and the connections the router tracks right now; it is not intrusion detection, and it looks inside no packet. What each number is not is said on the screen and in `?`: a rule's counter counts packets that open a flow (new connections, rejected packets), never traffic, and starts over when the firewall reloads; every zone allowed out shares one counter; a device's bytes are those of flows still open, so there are no totals and no history; traffic the firewall rejects between two inside zones has no counter on a default OpenWrt, so that separation is shown from live flows (none should cross) and blocked tries aren't seen; dnsmasq counts no blocked names (they are inside "answered locally"); DNS over HTTPS to other resolvers looks like any HTTPS; ssh and Wi-Fi numbers cover only the router's log, a few hours long, and sentry's own logins are left out of them. A few things are marked as worth a look (a device with flows out to telnet, SMB, RDP, IRC and the like, a login from an address no named device has, a wrong Wi-Fi passphrase, an old blocklist); two are audit findings: a live flow between zones the firewall keeps apart, and refused ssh logins. Nothing is installed for it, and no key on the numbers changes anything. What would show more, each yours to install or switch on: `nlbwmon` (per-device volume over time), a `log` option on the uplink's zone (which ports are probed, and from where), a counted reject rule from the DMZ to the LAN (blocked tries as a number), CrowdSec's bouncer (below), flow accounting if `nf_conntrack_acct` is off. `A` there sends Claude counts, ports and your devices' names, never the far end of a flow.

**The audit** reads the firewall, what listens, how ssh and the web interface are set up, the web interface's certificate, who is on the network and which services run (six reads, about a fifth of a second), and lists what differs from `expect:` or is worth knowing:

- a port forward you didn't list, or one you listed that is gone or switched off; a zone whose interfaces differ, or an uplink zone that accepts what nobody asked for;
- something listening on the router that the internet can reach (high), or that only the inside can reach and `expect.listeners` doesn't have (low: shown with `o`);
- ssh accepting passwords, the web interface answering over plain HTTP, its certificate at its end;
- config changes staged with `uci set` and never committed;
- a device nobody named. A phone's private (randomised) MAC on Wi-Fi is never one: it holds the passphrase. A vendor's MAC that isn't under `devices:` with a `name:`, or any unnamed MAC on a wired or DMZ port, is, once it has held a lease two reads running;
- a live connection from one zone into another that the firewall has nothing for (high), and ssh logins refused in the log's window from somewhere that isn't this machine (medium);
- the uplink down, dnsmasq / dropbear / uhttpd (and `expect.services`) not running, memory or load over the thresholds.

`b` marks a finding, a listener or a device expected (the network's `baseline.toml`; `b` again, or Records › Later, takes it back); naming a device is a line in the config. Secrets never leave the read that found them: every `uci` option that holds one (a Wi-Fi passphrase, a PPPoE password, a private key) is replaced by a tag as it is parsed, keyed with a random salt kept in `~/.config/sentry/networks/<name>/salt`, so a report can say a passphrase *changed* and never what it is.

**Firmware and packages.** Whether a newer OpenWrt is out is looked up from this machine, never by the router: the release it runs (`ubus call system board`) against endoflife.date's `openwrt` (the series' end of life, its latest release) and GitHub's `openwrt/openwrt` releases (the patch level, and whether a release's notes list security fixes), cached for a day. A newer release of the same series is a row; it waits behind `o` unless its notes list security fixes (or they couldn't be read). A series past its end of life is a row too. Packages are what `apk --no-network list --upgradable` lists against the index the router already has; that index lives in the router's RAM and is only as new as the last time it was fetched, so the row says its age. `r` on Maintenance is the one thing that fetches it again (`apk update`: it writes that RAM cache and nothing else), with upstream and the audit; nothing refreshes it by itself. Upgradable packages never ask for anything (`o` shows them). `Enter` on the Packages item starts `package-update`: it refreshes the index and lists, backs the config up, then upgrades the packages you NAME (never all of them: OpenWrt's packages are built against one firmware release); a list with a base-system package in it (kernel modules, busybox, netifd, firewall4, dnsmasq, dropbear, hostapd…) is a step auto mode never confirms. `firmware-upgrade` upgrades the router to the newest release of its series with `owut` (OpenWrt's upgrade tool): it checks the router is ready, makes an encrypted backup (it needs `backup.recipients`), shows what changes and stops on anything owut warns about, downloads the new firmware into the router's memory and checks it against the upgrade server's checksum (your Enter), flashes it after a box that says what happens and for how long (your Enter again; the internet and Wi-Fi are off for a few minutes), waits up to 15 minutes for the router to come back (if it is still running its old firmware with the flash over, it says the flash did not happen and nothing was changed, instead of waiting), then checks the version, your add-on packages (it offers to install any that went missing), the services, the internet, the devices, audits and backs up again. It is still a draft, since no router has been flashed by it yet: Enter on the firmware row opens a box that says what has and hasn't been proven, and only its Enter starts it (the flash box says once more that sentry has never flashed a router before) (never auto mode, a series or `:wf`); after one good run sentry offers to mark it proven. Auto mode never confirms its download, flash or reinstall.

**Config backups.** `sentry-network backup [name]` (and the `config-backup` workflow: the same, then a check) has the router make its own backup archive (`sysupgrade --create-backup -`, which writes nothing there) and encrypts it on this machine as it arrives, with [age](https://age-encryption.org) built in (no `age` program needed), into `~/.local/share/sentry/networks/<name>/backups/<UTC time>-<release>.tar.gz.age` (the directory 0700, files 0600). The plain archive never touches this machine's disk. Beside each backup are two plain files that hold no secret: which files it holds, each with a keyed tag of its hash, and the config by option with every secret already a tag. From those sentry says whether the config changed since the last backup, and what (`wireless.default_radio0.key changed`: named, never shown), without decrypting anything, which it couldn't anyway: it only ever has the public half of the key.

- Set a recipient first. `sentry-network backup key ~/keys/router-backup.txt` makes a key file (0600; it won't overwrite one) and prints the line for `network_config.yaml`: `backup: { recipients: [ "age1…" ] }`. Any age public key works, or a file holding one a line; several recipients can each decrypt. **Keep the key file somewhere that isn't this machine too:** without it no backup can be read, by you or by sentry.
- `backup list` shows what's kept: the newest `backup.keep` (12), plus the first of each month for a year.
- A config that isn't backed up is an audit finding (`net:config:unsaved`, with what changed); a backup older than `thresholds.backup_age` is a Maintenance row. Enter on either runs `config-backup`.
- Restoring is yours: `sentry-network backup decrypt <file> -i <key file>` writes the plain `.tar.gz` (or `-o -` to pipe it on), which OpenWrt restores: LuCI's System › Backup / Flash Firmware › Restore, or `sysupgrade -r <file>` on the router. That archive holds the Wi-Fi passphrase and the router's private keys: remove it afterwards. sentry never restores anything itself.

**Claude on a router.** The login is root, so there is no sudo line between looking and changing; sentry reads every command line itself before anything is sent, and only what it positively understands as a read is one.

- **Reads run, rebuilt and scrubbed.** `A` (a chat), `R` (a review) and an apply session reach the router only through `sentry-network exec|run <name> -- …`. A read is a line of plain commands from a fixed list (`uci show`, `ubus call … status`, `nft list`, `logread`, `ip … show`, `cat` of the lease files and named files under `/proc` and `/sys`, `ls`, `find` by name…) with literal arguments: no variables, substitutions, backslashes or comments. The router never runs the line as written: sentry sends what it rebuilt from its own reading of it, one command at a time, every argument quoted. Before Claude sees a byte, a secret option's value becomes a tag (`redacted:…`), the uplink's address, gateway and network `‹wan›` / `‹wan-gw›` / `‹wan-net›` / `‹wan6›`, a device you named `‹name›`, any other MAC its vendor half (in an IPv6 address made from it too), an SSID `‹ssid-N›`, an unnamed hostname `‹host-…›`. What follows a pipe (`grep`, `head`, `tail`, `sort`, `uniq`, `wc`, `cut`) is done on this machine, on the scrubbed text: a pattern matched on the router could be used to ask about what is hidden. There is no `awk`, `sed`, `tr` or `hexdump` without asking.
- **Never, whoever allows it:** `/etc/shadow`, the ssh host keys and `authorized_keys`, `/etc/config/*` raw, a plain `sysupgrade -b`, `passwd`, `firstboot`, `mtd`, writing under `/etc`, `/proc` or `/sys`, fetch-and-run, a `kill` by number or of a daemon the network runs on, removing a base package, starting anything that listens, `tc`/`rmmod` and the like, and a `uci` option that names a script or a file a daemon serves (`firewall` includes, `dhcpscript`, uhttpd's `interpreter`, dropbear's `BannerFile`…).
- **A request (you see the exact line, Enter runs it, logged):** anything else that changes something that can't cut you off (`apk add tcpdump`, a file under `/tmp`, `uci set system.…`), any file outside the short list read freely, a ping, anything written in a way sentry doesn't read as a read. Only in an apply session; a chat changes nothing.
- **Only as a guard step:** anything that touches the network, firewall, wireless, dhcp, dropbear or uhttpd config or reloads their services (`uci commit`, `wifi`, `ifup`, `nft add`, `ip … add`).
- **Only as a workflow step:** `apk upgrade`, `sysupgrade`, `owut`, `reboot`.
- **Auto mode (`C-a`) answers less here than elsewhere.** In a router's session nothing Claude asks for is allowed by auto: not its plan, not a command, not a file on this machine. The guard's apply and keep and the flash are always your Enter. A package upgrade is simulated first (`apk upgrade --simulate`) and auto confirms it only when everything the upgrade would touch is on a short list of leaves (`luci-app-*`, translations, themes, a few tools); a library or a daemon riding along makes it yours. It still runs a workflow's auto steps and goes on to a series' next row.
- Claude can read the maintenance log, the plans and your `notes:` files, and nothing else sentry keeps about the network: not the encrypted backups, the salt behind the tags, `network_config.yaml`, the audit reports, a workflow run's log or `~/.ssh`; it can't write a workflow file. An apply session that starts on the network has no web access, and one that starts elsewhere loses it once it has read from the router (a review keeps it: it can't run anything). Every prompt says that what the router prints (a device's name, a log line) is data, never instructions. Devices marked `leave_alone: true` are named to it with the instruction never to probe or reconfigure anything for them.

Scrubbing is by what the router says about itself at that moment and by pattern; it is not a proof. A name that appears only in free text sentry has no rule for (an old log line of another daemon, say) can get through.

**The guard** (`guarded-change`, `sentry-network guard <name> preview|apply|keep`) is the one way those six configs change. It reads first (the router answers, nobody else's changes are staged, how the uplink and default route are), copies the configs aside on the router, and **before changing anything** starts a detached sleeper there that, unless it is disarmed within `guard.window` seconds (300), copies them back, reloads the same services and says so in the router's log. Only once that sleeper is seen alive are the lines staged, committed and the services reloaded. sentry then reconnects on a new connection and disarms only if the router answers, has stopped changing (the same answer twice, a moment apart), the uplink and default route are as before, the firewall's closed zones are still closed and the forwards you expect are still there. If anything is off, or sentry or the link dies, it does nothing: the router restores itself. Only one of the two can have a guard: the sleeper and a disarm each take it by renaming its marker, so a disarm that arrives as the timer fires either wins cleanly or does nothing, and sentry says "kept" only when the router said so. A change to Wi-Fi (or one meant to change the uplink) stays armed and asks **keep?**, because ssh over a cable can't tell that Wi-Fi works; no answer within the window and it is taken back.

A restart inside the window is covered as well: while a guard is armed its snapshot is on the router's flash (`/etc/sentry-guard/<token>/`) with a one-shot script in `/etc/uci-defaults/`, which OpenWrt runs once at the next boot, before any service starts, and which puts the configs back. Both are deleted when the change is kept or taken back. That is a copy of each config touched and one small script written and removed per guarded change; nothing else of sentry's is ever written to a router's flash, and the sleeper is the only thing it ever leaves running there, for at most the window.

A secret the change sets (an option named like a key, a password or a token: a new Wi-Fi passphrase) goes to the router and is written down nowhere else: the run's state and step logs, the maintenance log, a kept plan and what is said back to Claude have its tag (`redacted:…`), and what you type for it shows as dots. A run picked up after sentry was closed therefore no longer has the value: its guard step stops, changes nothing, and says to start the change again.

Everything that changes a router is developed against a disposable one (`scripts/live-router.sh up|test|down`: OpenWrt's own userland under podman), never a real one.

Headless: `sentry-network collect [probe|ifaces|clients|listeners|uci|cert|services|updates|counters|flows|seclog|dnsstate] [name]` (JSON; all without a kind; `flows` and `seclog` print addresses: every far end the network talks to, who logged in), `audit [name]`, `backup [name] [--verify]`, `backup list|key|decrypt`, `record [name]`, `run|exec <name> -- …` (the gateways), `guard <name> preview|apply|keep`, `packages <name> preview|plan|upgrade|check`.

## CrowdSec

Read only, and only where it is installed: sentry installs nothing, registers no bouncer and never adds or deletes a decision. A host without it shows nothing new.

- **A server with `cscli`**: a Dashboard status row (agent running, bans active with how many are local, alerts in 24 h) and the findings `srv:crowdsec:down` (the agent's unit isn't active: high), `srv:crowdsec:bouncer:<name>` (a registered bouncer hasn't asked for decisions in over an hour: medium; mark a retired one expected) and `srv:crowdsec:hub` (hub items with an update, or edited locally: low, listed with `o`). `cscli` usually needs root: add `cscli decisions list`, `cscli alerts list`, `cscli hub list`, `cscli bouncers list` and `cscli metrics` to `sudo:` (`sentry-server init` drafts them when it finds `cscli`). They are read when the Dashboard is entered, on `r`, by the audit and in `I`'s one read, never on a timer.
- **A router with `crowdsec-firewall-bouncer`**: a Status row, `crowdsec N blocked` (the elements of its nft sets, counted on the router), and the finding `net:crowdsec:bouncer`: switched on and not running (high), installed and never switched on, or running for over a day with empty sets (both low).

Blocked and banned addresses never reach a report or Claude: only counts, scenario names and bouncer names leave the collectors.

## Security audit

**`S`** on Maintenance or Security of any target (or `:audit security`) runs it in the window: while it reads, every target says so; then the report opens, each item is a row on the target it belongs to (the network's Security for its own and for what spans devices, Maintenance elsewhere), and Enter on a row is a session with Claude that fixes it, on whichever devices that takes. A question only you can answer is a pick: yes, no, or you don't know. After the checks Claude reads the evidence (addresses and names are never in it) and looks up advisories for the versions found: "What matters most here", at the top of the report. `S` again shows the report; `S` there runs the audit again. It is also a task every 30 days.

`sentry audit security` reads this machine, every server and every network as one system and prints a short report in plain language: **Do these first** (five at most; the rest of the pressing ones lead **Worth doing**), **Worth doing**, **Fine**, **Couldn't check**, and **Needs your answer** last. It follows what an attacker would try: getting in from the internet (each port the router forwards, matched with what answers on the server behind it), known holes (firmware, packages, the OS and when its release stops getting fixes, tracked apps), logins (ssh passwords, Wi-Fi, sudo), moving around once inside (is the network split, is what the internet reaches kept apart, containers with too much control) and noticing and recovering (CrowdSec and where its bans are enforced, backups, how long logs are kept). One line says what goes on while sentry is closed: sentry itself only looks while it is open.

- It reads configuration and state, and gives no score. It never scans or attacks anything. The one thing it sends: for each port your router forwards to one of sentry's own servers, one request from this machine to that server's front page on that port (no login, nothing followed, 5 seconds a try), to say whether it asks for a login and what certificate it shows. It is sent every time the audit runs and shows in that server's access log as `User-Agent: sentry-security-audit`; it never goes through a proxy, and only whether it asked for a login and the certificate's days and kind of issuer are kept. A page that answers without a login is asked as a question, not called a fault.
- What runs behind a door (the container, its image and version, the maintenance item that tracks it) comes from the server's inventory when its sudo asks for a password: press `I` on the server target first; the report says how old the inventory was.
- A line appears only on evidence. What couldn't be read is listed as such, with what it would take.
- What only you know (does that web app need a login? was a restore ever tested?) is asked once: `sentry audit security answers` lists the questions, `… answers <key> yes|no` remembers one with its date.
- Reports are kept in `~/.config/sentry/system/security/` (the newest 24) and each is compared with the one before: new, fixed, worse.
- What the internet can reach is read from the router's settings. To have it confirmed from outside, give sentry a command of your own in `config.toml` and pass `--outside` (without one, `--outside` says what to put there). sentry never scans: the command is yours, and it must try the ports from somewhere outside your home network. sentry fills in `{address}` (your public IPv4 address) and `{ports}` (the forwarded ports and a few management ports, comma separated); the command prints the ports that answer, one per line. Two worked examples:

```toml
[audit]
# 1. Through a remote shell host you have (a VPS, a friend's machine): ssh there and try
#    each port with nc, two seconds each.
outside = "ssh vps 'for p in $(echo {ports} | tr , \" \"); do nc -zw2 {address} $p && echo $p; done'"

# 2. Through a VPN on this machine, kept in a network namespace of its own (here one
#    called `vpn`, set up by your VPN tool), so the tries leave through the VPN and arrive
#    from outside like anyone else's:
# outside = "sudo ip netns exec vpn sh -c 'for p in $(echo {ports} | tr , \" \"); do nc -zw2 {address} $p && echo $p; done'"
```

## Config

`~/.config/sentry/config.toml` follows `docs/spec.md` §12, and every key is optional. Additions:
- `[ui] terminal = "ghostty -e"`: the terminal used to enter containers.
- `[flatpak] trusted_origins = ["flathub", "fedora"]`: remotes that aren't flagged as unverified.
- `[baseline] findings = ["repo:rpmfusion-*"]`: audit findings to treat as expected (globs allowed).
- `[keys]`: rebinds, for example `quit = "Q"`, `"screen.history" = "F9"` or `"target.next" = "C-n"`.
- `[targets] show = ["local", "srv:myserver", "net:home"]`: which targets the window opens, in the strip's order (default: this machine, then every server, then every network).

Sentry never writes `config.toml`. What you decide in the TUI goes to machine-written files next to it:
- `baseline.toml`: listeners and findings marked expected.
- `tasks.toml`: tasks taken from reviews, and the cadences changed with `e` (or turned off with `x`).

## Development

`make check` (build, tests, clippy, fmt) over the cargo workspace: `crates/sentry-core` (the kit), `crates/sentry-app` (the app and its flows, and the pieces of a host reached over ssh), `crates/sentry-local` (this machine), `crates/sentry-server` (a server) and `crates/sentry-network` (a network's router), and `crates/sentry`, the one binary over all three. Parsers are tested against fixtures captured from a real machine (`scripts/capture-fixtures.sh` scrubs usernames, addresses and interface names); sentry-server's and sentry-network's fixtures are synthetic, in the real commands' formats. Screens have insta snapshot tests. `make privacy-check` keeps private strings (listed one per line in a gitignored `.private-patterns`) out of tracked files, unpushed commit messages and release tarballs. `CLAUDE.md` holds the working notes the project was built with.

## Docs

- `docs/spec.md`: the build spec.
- `docs/spec-addendum.md`: binding amendments made after probing the real machine.
- `docs/design/m3-m7.md`: design for the audit, jobs, workflows and recorder.
- `docs/design/sentry-tui.dc.html`: the visual target.

## License

MIT. See [LICENSE](LICENSE).
