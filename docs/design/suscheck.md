# SusCheck in sentry: reviewing how a household's checks went

## Context

SusCheck is a separate project: a home service on a server that looks at a screenshot of a
suspicious email or web page with a local vision model and answers "don't trust this / be careful /
no obvious warning signs". It runs for several computers in a household. It keeps every check as an
**incident** (a record and the picture) in one folder on the server, and publishes that folder's
format as a contract (`incident-format.md`, schema 1, with synthetic samples).

Sentry's part is the owner's view: how SusCheck is being used and how it is behaving. It only reads.
Decisions made with the owner: nothing alerts by itself (it is seen when sentry is next opened);
SusCheck's own name for a computer is enough (no joining to network devices); retention is
SusCheck's (30 days); this module is built in sentry against the published format.

## The one thing that must hold: sentry's Claude never reads an incident

Incident text was written by a model that had just read attacker content, and the pictures are a
household's private mail. A sentry session on that server runs commands as the server's ssh login,
so "the folder is readable by the login" would mean a cloud model can read it.

Two layers, in this order of strength:

1. **A login of its own (the real control).** `suscheck.ssh` names a second ssh login that is in the
   incidents folder's group; the server's ordinary login is not. Sentry's collector reads through
   it; sessions, chats and reviews keep using the ordinary login and get "permission denied" from
   the server itself. Without `suscheck.ssh` the collector uses the server's own login, and the
   config lints a warning that says exactly this.
2. **The gateways refuse the folder (best effort).** `sentry-server exec` and `run` refuse any line
   that names the configured folder, its pointer file, or `incident.json` / `screenshot.png` /
   `index.jsonl`. A shell line can be written to dodge a word match, which is why this is the second
   layer and not the first.

And in sentry itself: nothing of an incident (text, brand, domain, device name, picture) is ever put
into a brief, a session, a review, a stored audit report, a log entry or a fixture. `A` is not
offered on the screen. The stored snapshot keeps counts only.

## Shape

```
config: servers.<name>.suscheck { dir, ssh?, recent=200 }      absent = off
collect/suscheck.rs   one exec, no sudo, through `ssh?`:
      date -u · status.json · devices.json · tail -n <recent> index.jsonl
      parse() pure: strict ids, 1024-byte lines, schema, every string stripped
   -> data::Kind::Suscheck -> Store.suscheck
   -> on demand: Kind::SusIncident(id)  (cat <dir>/<id>/incident.json, size-capped)
   -> on demand: the picture, raw bytes to a private cache, opened in the desktop's viewer
screen `8 SusCheck` (only where configured)
audit: srv:suscheck:* findings from counts
records: servers/<name>/suscheck.toml on this machine: marks, and how far you have looked
```

### Reading (`crates/sentry-server/src/collect/suscheck.rs`)
- One command with `@@` sections; the folder path is single-quoted from config after `lint` proved
  it absolute. Exit 127-style "not there" and "permission denied" are told apart and said plainly
  (`Unreadable::{NoFolder, NotInGroup}`), never retried another way.
- `parse()`: an index line over 1024 bytes, not JSON, or with an id outside
  `[0-9]{8}T[0-9]{6}Z-[a-z0-9]{4}` (whole string, ASCII) is skipped and counted. `schema` other
  than 1 → `Format::Newer(n)`: the screen says so and shows nothing else from that file. Unknown
  fields ignored; unknown enum values kept as text. Every string goes through one `clean()` (control
  and format characters, escape sequences) before it is stored.
- An id is validated again wherever a path is built from it (`incident(id)`, `picture(id)`).
- Fetched on entering the screen, on `r`, and once when the server's Dashboard is first entered (so
  the badge and the Status row are right); never on a timer.

### What it shows (`tui/screens/suscheck.rs`, `ScreenId::Sus`, key `8`)
- **Summary**: checks in the last 7 and 30 days by verdict; errors; share incomplete; how often
  SusCheck's fixed rules overrode the model; typical time; how many you marked wrong; the service
  (version, model, prompt version, heartbeat by the SERVER's clock).
- **Computers** (from `devices.json` joined with the index): name, app or web, version, checks,
  last seen; "never used", "not seen for N days", "older app than the others".
- **Checks**: time, computer, verdict, brand, domain, domain check; unseen ones marked; `/` filters.
  Enter loads that incident: reasons, the advice shown, extracted facts, both domain readings,
  searches and what came back, what the model said against what counted, time per stage.
- `o`: the picture. Fetched with `Cmd::bytes_to` into `<cache>/suscheck/<server>/` (0700, file
  0600), refused over 16 MB or without a PNG signature, opened with the desktop's opener through
  `exec::Cmd` detached. The cache is emptied at start and at exit. This is the one place sentry
  starts a program it does not wait for; it is the user's viewer, asked for by a key.
- `m`: mark it right, or wrong and what it should have been. `x` clears the mark.
- Domains are shown as text, never resolved, looked up or opened.

### Seen next time you open sentry
`suscheck.toml` keeps `seen` (the newest id you have had on screen). Checks newer than it rated
`likely_malicious`, and errors, are a Maintenance row ("2 checks said don't trust this since you
last looked", Enter goes to the screen) and the screen's badge; looking at the list moves `seen`.

### Findings (counts only; `srv:suscheck:*`)
`down` (heartbeat older than 5 min by the server's clock: medium), `unreadable` (configured, folder
not there or this login not in its group: medium), `errors` (3 or more failed checks in 24 h:
medium), `format` (a schema this sentry doesn't know: low).

### Config
`suscheck: { dir, ssh, recent }` on a server: the `Server` struct, `FIELDS`, `lint` (absolute `dir`;
the same-login warning), one folded group in the server's form, the forms round-trip test, the
example YAML. `suscheck.dir` and `suscheck.ssh` join `cfg::changes::NEVER` and are hidden from the
wizard. Discovery reads `/etc/suscheck/incidents.path` (first line, absolute, no control characters)
and proposes the block.

## Not in this work
Alerts. Joining a computer to a network device. Deleting or changing anything in the folder.
Showing pictures in the terminal. Anything of SusCheck's on this machine or a router.

## Verification
- Fixtures: the published synthetic samples, copied to `tests/fixtures/server/suscheck/`.
- `parse()` table tests: the samples; a bad id; an over-long line; a newer schema; hostile strings
  (escape sequences, direction overrides) cleaned; unknown enum values kept.
- Gateway: every refused spelling, for `exec` and `run`; nothing else newly refused.
- Canary: with a store full of incident text, no brief, profile, session prompt, stored report or
  log entry contains any of it.
- Window: the screen from the samples (158 and 80), marks survive a restart, `seen` moves, the
  Maintenance row comes and goes, the block removed → no screen, no findings.
- Config: lint, forms round trip, the wizard cannot propose `dir`/`ssh`, discovery proposes the block.
- Live (disposable container only): the samples copied into the container under a group the test
  login is in; the collector, an incident and a picture fetched for real; a second login without
  the group gets the plain "not in its group" message.

## As built

Built as designed, with these differences (each for the reason given):

- **`suscheck` is a section, not an optional block.** `Server.suscheck: Suscheck { dir:
  Option, ssh: Option, recent: u32 }`, on when `dir` is set (`Suscheck::on`). The config's
  writer leaves out whatever is at its default, so a server without it still has no key in the
  file, and the forms get plain fields (an optional block at an entry's top would have needed a
  new kind of form field). `ssh` without `dir` is a lint error.
- **The same-login warning is a note, a new and small notion.** Every lint line was an error.
  `config::notes(name, &Server)` returns advice that is never a problem: `sentry-server lint`,
  `sentry-server check`, `sentry config check` and the Config area's `c` print it with `·`, and
  no exit code or problem count changes. `lint` is untouched.
- **Section marks carry a per-call mark** (`@@<16 hex>:status`), not a bare `@@status`: a file
  whose text has a line that looks like a section line stays that file's text.
- **A check's time is its id's**, not the `time` field: the id's grammar is already proven, and
  ids are what sort. The `time` field isn't read.
- **Format characters are a written-out list.** `clean()` removes escape sequences, controls,
  Cf ranges (direction marks, zero-width, the BOM, tags, variation selectors), private use and
  noncharacters. There is no table of Unicode categories in the workspace, so code points
  Unicode has not assigned (Cn) are not caught; a terminal draws those as a box.
- **`Kind::SusPicture(id)` beside `Kind::SusIncident(id)`**: the picture is a fetch like any
  other (its own thread), and nothing of it is kept in the store; the target opens it when it
  arrives.
- **The model's raw replies (`model_raw`) are not shown and not kept.** The detail shows the
  model's validated answer against what counted; the raw text adds up to 16 000 characters of
  attacker-influenced output for no judgement the rest doesn't allow.
- **The records file is read by its own stamp**, on `Target::enter` (which follows the app's
  `look`), not through `Target::files`: a change in one of those files means "the user edited
  the target's config" (the YAML is read again and said so), which sentry's own save of a mark
  would have triggered.
- **The gateway rule also covers `Host::command` and the queued root reads**, not only `exec`
  and `run`: a plan's step, a request the user (or auto) allowed, and a read queued for the
  sudo password would otherwise have reached the folder as root. A sudo step of the user's own
  workflow that names the folder is refused by the same rule (sentry never touches the folder
  but through its reader); a plain step of a workflow isn't a session's command and isn't
  looked at.
- **Without the block, `8` goes back** to the screen it came from and says SusCheck isn't set
  up: every key of a program's screen set is bound, so "no screen" is that plus no tab.
- **`A` on the screen**: a new default-true hook (`Asks::asks_here(screen)`) keeps it out of
  the key bar; pressed, the toast says why. `Target::shutdown` is new too (default: nothing):
  where the cache is emptied.
- **A Maintenance finding's Enter is still a session with Claude** (`srv:suscheck:*` are
  findings like any other): its brief holds the finding, which is made of counts.
- **`sentry-server collect <name> suscheck`** prints `Counts` as JSON, never a check.

What the gateway's word match doesn't stop (and the folder's own login does): `cd` into the
parent and a relative path, a glob (`inc*`), a variable or a name put together by a command,
a symlink that leads there, `find <parent> -exec`, a tool that reads a list of paths. With no
`suscheck.ssh` those reach the folder; `sentry config check` says so.

### Email files and page addresses (the format's later additions)

SusCheck's format grew without a schema change: a check can be made from an email file, from
the page's address as its desktop app reads it out of the window, from a screenshot, or from a
combination. The fixtures are the eight published samples, byte for byte: one in the old shape
(the first release's: no `input`, `message`, `domain.source` or text-recogniser fields), five in
today's full shape, an email file with `message.txt` and no picture, a picture beside the
window's exact address.

- **Parsing.** An index line's `input` is kept as cleaned text (`Check.input`): a line without
  the key is `image` (older lines), null is "nothing recorded", an unknown combination is shown
  as it is. `Incident` gained `input`, `email`, `links`, `page`, `message` and, in `domain`,
  `source`, `exact`, `ocr_reading`, `ocr_available`; `stages_ms.ocr`. Every block may be null,
  not an object, or empty; every string goes through `clean()` and is cut at sentry's own cap, a
  little over the format's (nothing fails for being long); attachments stop at 20 and links at
  50, and what was beyond them is counted from the totals. The published record in the old
  shape parses as a picture's (`input = ["image"]`), and every newer one stripped of the new
  fields still parses (both tested).
- **After the format's revision** (still schema 1). "And N more" under Links is the record's
  own `links_total` less the list; that count is from before exact repeats were merged, so the
  line says "exact repeats of these included". A record without it falls back to the email's
  and the page's totals. `stages_ms`: null is a stage that did not run, a number one that ran
  (0: in under a millisecond); "How it ran" gives the times, then `· not run: reread, ocr`. The
  old shape wrote 0 for a stage that did not run, so a 0 there is read as not run. The format's
  caps are on the plain value, which is stored defanged: sentry's are a little over the stored
  sizes (a link's text 410, a target and the page's address 210). A failed check's index line
  says what it was given, so its From is `picture`, not `–`. In what the model read, one clause
  says whose value it is where the format does: the sender (the header's exact values), the
  address bar (the window's exact address), the link texts (the model's reading: go by Links).
- **The list** has a From column in plain words (`picture`, `email`, `picture + email`,
  `picture + page address`), as wide as the widest. At 158 columns there is no room for it
  beside Brand and Domain check and a readable domain (18 columns), so those two give way,
  Brand first: with the longest word in the list both go, with `picture + email` only Brand.
  Both are in the check itself. The narrow list has no From column: the check says "Made from".
- **The summary** has one line by kind over 7 and 30 days. A check made from two inputs counts
  under both.
- **The check**, after what the model read, and only where the record has them: where the
  address came from (the email's own header / read out of the window by the app / read from
  the picture; exact text or a reading; what the model read in the picture all the same, when
  it differs; the text recogniser's reading when it differs), the email's headers (reply-to
  and return-path only when they differ from the sender; authentication as the message reports
  it; attachments by declared name, type and size), the links (text → target domain, scheme,
  what code found, in words), the page. Link targets and the page's address are drawn exactly
  as SusCheck stored them, defanged; `domain`, `email` and the index are not defanged by
  SusCheck and are drawn as they are. Nothing is resolved, opened or copied to a clipboard.
- **The message's text is deliberately not shown.** `message.txt` is a household member's mail
  and possibly a scammer's words. The format lets a reader show it when a person asks; sentry
  doesn't: where `message` is true the check says "The email's text is kept on the server with
  this check (quarantined). sentry doesn't show it.", no key fetches it, `path_of` makes a path
  only to `incident.json` and `screenshot.png`, and there is no `Kind` for it. Whoever wants to
  read it does so on the server, as the folder's own login. The gateways refuse its name like
  the folder's other names, and the profiles' off-limits sentence names the quarantined copies.
- **`o` without a picture** asks the server nothing where it is already known there is none
  (the index says the check was made from the email itself or the page's address; or the open
  record says none was kept) and says which. From the list, a failed check's `o` still asks
  (its index line says a picture was sent; none was kept) and gets the same plain answer.
- **Wording.** Every rule the format lists but `lookalike`, and the tag `ocr_differs`, has a
  short phrase by the format's own line for it (`tag()`); any other
  value is its own text with spaces for underscores. Three or more rules are listed one a line
  (a check of an email file has six).
- **The detail scrolls by wrapped rows.** It used to stop at the count of unwrapped lines, which
  on a narrow window left the end of a long check out of reach.

Assumed, not seen: that in a record from before `links_total` the email's and the page's totals
add up to the list's (`links_more` adds the two only there); that a 0 in an old-shape record's
`stages_ms` is a stage that did not run and never one that took under a millisecond.

Verified: the unit and window tests the Verification section lists, the canary, and
`live_suscheck` in both disposable containers (the folder's own login reads; the server's
ordinary login is refused by the server; the same through a copy the test login may read; a
picture fetched, private, byte for byte, gone at shutdown; nothing written in the folder; the
check made from an email file read with no picture and its text not shown; `message.txt`
refused to the server's ordinary login by the server and by both gateways).
Not verified anywhere: a real SusCheck install, and the desktop's opener (no test starts it).
