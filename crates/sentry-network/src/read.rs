//! What a read is, positively: the only lines that run on a router without the user's
//! Enter. A line is a read when it parses under the small grammar here, and then the
//! router's shell never sees the line Claude wrote: it sees what sentry rebuilt from the
//! parse, one simple command at a time, the program's name taken from the list here and
//! every argument single-quoted by sentry. A difference between this parser and the
//! router's shell can therefore change what a read prints, never what runs.
//!
//! The grammar: simple commands joined by `|`, `;`, `&&`, `||`. A simple command is a
//! program on the list (`rule`) with literal arguments its rule allows, flag by flag; the
//! only redirections are `2>&1`, `2>/dev/null` and `>/dev/null`. Single quotes and plain
//! double quotes group; nothing expands: no `$`, backtick, backslash, `#`, `~`, braces,
//! parentheses, `<`, `&`, assignments, line breaks or control characters. A `*` or `?`
//! outside quotes is a pattern only in a path under `GLOB_DIRS` (sent unquoted);
//! elsewhere it puts the line outside the grammar (quote it to mean the character).
//!
//! Only the first command of a pipeline runs on the router (`Source::Remote`). What comes
//! after a `|` (grep, head, tail, sort, uniq, wc, cut) and a filter's own file (`grep x
//! /tmp/dhcp.leases` is `cat` there, grep here) is done on this machine, after the
//! scrubbing (`filter`): a pattern matched on the router would be an oracle for what the
//! scrubbing hides. For the same reason no program on the list takes a pattern or an
//! address to select by (`logread -e` is a grep here; `ip … show` takes a device, never a
//! prefix).

use crate::filter::{self, Filter, Take};
use crate::policy::{UBUS_NEVER, UBUS_READS, secret_path};

/// One word of a line, unquoted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Arg {
    pub text: String,
    /// A `*` or `?` outside quotes.
    pub star: bool,
    /// A `[` or `]` outside quotes.
    pub bracket: bool,
    /// Part of it was quoted.
    pub quoted: bool,
}

/// How a pipeline follows the one before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Join {
    First,
    /// `;`
    Seq,
    /// `&&`
    And,
    /// `||`
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redir {
    /// `2>&1`
    ErrOut,
    /// `2>/dev/null`
    ErrNull,
    /// `>/dev/null`
    OutNull,
}

impl Redir {
    fn text(self) -> &'static str {
        match self {
            Redir::ErrOut => "2>&1",
            Redir::ErrNull => "2>/dev/null",
            Redir::OutNull => ">/dev/null",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Simple {
    pub words: Vec<Arg>,
    pub redirs: Vec<Redir>,
}

/// A line as its pipelines.
pub type Parsed = Vec<(Join, Vec<Simple>)>;

enum Tok {
    Word(Arg),
    Pipe,
    Join(Join),
    Redir(Redir),
}

const REDIRS: &str = "the only redirections are `2>&1`, `2>/dev/null` and `>/dev/null`";

fn lex(line: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let mut cur: Option<Arg> = None;
    let cs: Vec<char> = line.chars().collect();
    let mut i = 0;
    let flush = |cur: &mut Option<Arg>, out: &mut Vec<Tok>| {
        if let Some(w) = cur.take() {
            out.push(Tok::Word(w));
        }
    };
    while i < cs.len() {
        let c = cs[i];
        i += 1;
        if c.is_control() {
            return Err("a line break or a control character".into());
        }
        match c {
            ' ' => flush(&mut cur, &mut out),
            '\'' | '"' => {
                let w = cur.get_or_insert_with(Arg::default);
                w.quoted = true;
                loop {
                    let Some(&n) = cs.get(i) else {
                        return Err("a quote that isn't closed".into());
                    };
                    i += 1;
                    if n == c {
                        break;
                    }
                    if n.is_control() {
                        return Err("a line break or a control character".into());
                    }
                    if c == '"' && matches!(n, '$' | '`' | '\\') {
                        return Err(format!(
                            "`{n}` in double quotes (the shell would expand it: use single quotes)"
                        ));
                    }
                    w.text.push(n);
                }
            }
            '\\' => return Err("a backslash".into()),
            '$' => return Err("a `$` (a variable or a substitution)".into()),
            '`' => return Err("a backtick (a substitution)".into()),
            '#' => return Err("a `#` (a comment)".into()),
            '~' => return Err("a `~`".into()),
            '{' | '}' => return Err("a brace".into()),
            '(' | ')' => return Err("a parenthesis".into()),
            '<' => return Err("a `<` (input from a file or a here-document)".into()),
            '*' | '?' => {
                let w = cur.get_or_insert_with(Arg::default);
                w.star = true;
                w.text.push(c);
            }
            '[' | ']' => {
                let w = cur.get_or_insert_with(Arg::default);
                w.bracket = true;
                w.text.push(c);
            }
            '|' => {
                flush(&mut cur, &mut out);
                if cs.get(i) == Some(&'|') {
                    i += 1;
                    out.push(Tok::Join(Join::Or));
                } else {
                    out.push(Tok::Pipe);
                }
            }
            '&' => {
                flush(&mut cur, &mut out);
                if cs.get(i) == Some(&'&') {
                    i += 1;
                    out.push(Tok::Join(Join::And));
                } else {
                    return Err("a `&` (something left running in the background)".into());
                }
            }
            ';' => {
                flush(&mut cur, &mut out);
                out.push(Tok::Join(Join::Seq));
            }
            '>' => {
                // A number right before it is the descriptor.
                let mut fd = 1;
                match &cur {
                    Some(w) if !w.quoted && w.text == "2" => {
                        fd = 2;
                        cur = None;
                    }
                    Some(w) if !w.quoted && w.text.chars().all(|d| d.is_ascii_digit()) => {
                        return Err(REDIRS.into());
                    }
                    _ => flush(&mut cur, &mut out),
                }
                let rest: String = cs[i..].iter().collect();
                let ends = |n: usize| rest[n..].chars().next().is_none_or(|c| " |&;".contains(c));
                let target = rest.trim_start_matches(' ');
                let skipped = rest.len() - target.len();
                if fd == 2 && rest.starts_with("&1") && ends(2) {
                    i += 2;
                    out.push(Tok::Redir(Redir::ErrOut));
                } else if target.starts_with("/dev/null") && ends(skipped + 9) {
                    i += skipped + 9;
                    out.push(Tok::Redir(if fd == 2 {
                        Redir::ErrNull
                    } else {
                        Redir::OutNull
                    }));
                } else {
                    return Err(REDIRS.into());
                }
            }
            c => cur.get_or_insert_with(Arg::default).text.push(c),
        }
    }
    flush(&mut cur, &mut out);
    Ok(out)
}

/// The line as the grammar reads it. Err: what puts it outside.
pub fn parse(line: &str) -> Result<Parsed, String> {
    let mut out: Parsed = vec![(Join::First, vec![Simple::default()])];
    let toks = lex(line)?;
    let n = toks.len();
    for (k, t) in toks.into_iter().enumerate() {
        let (_, stages) = out.last_mut().expect("one at least");
        let cur = stages.last_mut().expect("one at least");
        match t {
            Tok::Word(w) => cur.words.push(w),
            Tok::Redir(r) => {
                if cur.words.is_empty() {
                    return Err("a redirection before its command".into());
                }
                cur.redirs.push(r);
            }
            Tok::Pipe | Tok::Join(_) if cur.words.is_empty() => {
                return Err("an empty command".into());
            }
            Tok::Pipe => stages.push(Simple::default()),
            // A `;` may end the line.
            Tok::Join(Join::Seq) if k + 1 == n => {}
            Tok::Join(j) => out.push((j, vec![Simple::default()])),
        }
    }
    if out
        .iter()
        .any(|(_, s)| s.iter().any(|c| c.words.is_empty()))
    {
        return Err("an empty command".into());
    }
    Ok(out)
}

// ---- paths

/// A path made plain: `//` collapsed, `.` dropped, `..` resolved by its text. None: not
/// absolute, or it climbs above the root.
pub fn normal(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }
    let mut out: Vec<&str> = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                out.pop()?;
            }
            c => out.push(c),
        }
    }
    Some(format!("/{}", out.join("/")))
}

fn under(path: &str, dirs: &[&str]) -> bool {
    dirs.iter()
        .any(|d| path == *d || path.starts_with(&format!("{d}/")))
}

/// The files a read prints without asking: the router's state under /proc and /sys by
/// name, the lease files, and the few files under /etc that hold no secret. Nothing else:
/// not /proc or /sys as a whole (`/proc/<pid>/cmdline`, `/sys/kernel/debug`), no other
/// way to the config (`/rom/etc`, `/overlay/upper/etc`, `/proc/<pid>/root`, `/proc/self`),
/// nothing under /dev.
pub const READ_FILES: &[&str] = &[
    "/proc/loadavg",
    "/proc/uptime",
    "/proc/meminfo",
    "/proc/stat",
    "/proc/cpuinfo",
    "/proc/version",
    "/proc/cmdline",
    "/proc/mounts",
    "/proc/filesystems",
    "/proc/partitions",
    "/proc/mtd",
    "/proc/interrupts",
    "/proc/softirqs",
    "/proc/modules",
    "/proc/devices",
    "/proc/diskstats",
    "/proc/vmstat",
    "/proc/slabinfo",
    "/proc/zoneinfo",
    "/proc/buddyinfo",
    "/proc/swaps",
    "/tmp/dhcp.leases",
    "/tmp/odhcpd.leases",
    "/tmp/resolv.conf",
    "/tmp/TZ",
    "/etc/openwrt_release",
    "/etc/openwrt_version",
    "/etc/os-release",
    "/usr/lib/os-release",
    "/etc/board.json",
    "/etc/banner",
    "/etc/hosts",
    "/etc/ethers",
    "/etc/resolv.conf",
    "/etc/TZ",
    "/etc/group",
    "/etc/services",
    "/etc/protocols",
    "/etc/sysctl.conf",
    "/etc/sysupgrade.conf",
    "/lib/functions.sh",
];

pub const READ_DIRS: &[&str] = &[
    "/proc/net",
    "/proc/sys",
    "/sys/class/net",
    "/sys/class/thermal",
    "/sys/class/hwmon",
    "/sys/class/ieee80211",
    "/sys/class/leds",
    "/sys/devices/system/cpu",
    "/sys/devices/virtual/thermal",
    "/tmp/hosts",
    "/tmp/resolv.conf.d",
    "/tmp/sysinfo",
    "/etc/apk",
    "/etc/sysctl.d",
    "/etc/init.d",
    "/etc/nftables.d",
    "/etc/modules.d",
    "/lib/upgrade/keep.d",
    "/lib/functions",
    "/usr/share",
];

/// Where a `*` or `?` is expanded: kernel state, where a pattern is the only way to ask
/// about every interface or zone at once, and where every name it can match is readable.
pub const GLOB_DIRS: &[&str] = &[
    "/sys/class/net",
    "/sys/class/thermal",
    "/sys/class/hwmon",
    "/sys/class/ieee80211",
    "/sys/devices/system/cpu",
    "/proc/net",
    "/proc/sys/net",
];

/// Where `find` may start.
const FIND_ROOTS: &[&str] = &[
    "/etc", "/tmp", "/var", "/usr", "/lib", "/overlay", "/rom", "/root", "/www", "/sbin", "/bin",
    "/mnt",
];

/// `/proc/<pid>/stat` and the like: numbers about a process, never its command line,
/// environment, memory or files.
fn proc_pid(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/proc/") else {
        return false;
    };
    matches!(rest.split_once('/'), Some((pid, f))
        if !pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit())
            && matches!(f, "stat" | "status" | "statm" | "comm"))
}

pub fn readable_path(path: &str) -> bool {
    READ_FILES.contains(&path) || under(path, READ_DIRS) || proc_pid(path)
}

/// One argument as it is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    /// Single-quoted by sentry.
    Lit(String),
    /// A pattern under `GLOB_DIRS`, sent bare for the router's shell to expand.
    Glob(String),
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

impl Out {
    fn text(&self) -> String {
        match self {
            Out::Lit(s) => quote(s),
            Out::Glob(s) => s.clone(),
        }
    }
}

type Res<T> = Result<T, String>;

/// A literal: nothing in it that the shell would have expanded.
fn lit(a: &Arg) -> Res<&str> {
    if a.star || a.bracket {
        return Err(format!(
            "`{}`: a pattern outside quotes is expanded only in a path under {} (quote it to mean the characters)",
            a.text,
            GLOB_DIRS.join(", ")
        ));
    }
    Ok(&a.text)
}

/// The same, where an unquoted `[0]` is what is meant (`uci show firewall.@zone[0]`, a
/// grep's `[d]nsmasq`): sent quoted, which is what a shell makes of it when no file matches.
fn lit_brackets(a: &Arg) -> Res<&str> {
    if a.star {
        lit(a)?;
    }
    Ok(&a.text)
}

fn lits(args: &[Arg]) -> Res<Vec<&str>> {
    args.iter().map(lit).collect()
}

/// A name: an interface, a service, an object, a package.
fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.starts_with(|c: char| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.@+-".contains(c))
}

/// A device's name: never something a tool would read as an address.
fn ifname(s: &str) -> bool {
    name(s) && s.len() <= 15 && s.starts_with(|c: char| c.is_ascii_alphabetic())
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.len() <= 6 && s.chars().all(|c| c.is_ascii_digit())
}

/// A path that is only named or listed (ls, stat, du, df, test, find): anywhere but where
/// even the names are the guard's.
fn listable(a: &Arg) -> Res<Out> {
    if a.bracket {
        lit(a)?;
    }
    let Some(p) = normal(&a.text) else {
        return Err(format!("`{}`: name it by its full path", a.text));
    };
    if let Some(why) = secret_path(&p, true) {
        return Err(format!("`{p}`: {why}"));
    }
    if a.star {
        return glob(&p);
    }
    Ok(Out::Lit(p))
}

/// A file whose contents are printed.
fn readable(a: &Arg) -> Res<Out> {
    if a.bracket {
        lit(a)?;
    }
    let Some(p) = normal(&a.text) else {
        return Err(format!("`{}`: name the file by its full path", a.text));
    };
    if let Some(why) = secret_path(&p, false) {
        return Err(format!("`{p}`: {why}"));
    }
    if a.star {
        return glob(&p);
    }
    if !readable_path(&p) {
        return Err(format!("`{p}` isn't one of the files read without asking"));
    }
    Ok(Out::Lit(p))
}

/// A pattern the router's shell expands: under `GLOB_DIRS`, of plain characters, and no
/// part of it able to match `..`.
fn glob(p: &str) -> Res<Out> {
    let plain = p
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_./*?-".contains(c));
    let below = GLOB_DIRS.iter().any(|d| p.starts_with(&format!("{d}/")));
    if !plain || !below || p.split('/').any(|c| c.starts_with('.')) {
        return Err(format!(
            "`{p}`: a pattern is expanded only in a path under {}",
            GLOB_DIRS.join(", ")
        ));
    }
    Ok(Out::Glob(p.into()))
}

/// A command's leading flags, each one on its program's list, and what follows them.
struct Got<'a> {
    flags: Vec<(char, Option<String>)>,
    rest: &'a [Arg],
}

impl Got<'_> {
    fn has(&self, c: char) -> bool {
        self.flags.iter().any(|(f, _)| *f == c)
    }

    fn val(&self, c: char) -> Option<&str> {
        self.flags
            .iter()
            .rev()
            .find(|(f, _)| *f == c)
            .and_then(|(_, v)| v.as_deref())
    }

    fn vals(&self, c: char) -> Vec<String> {
        self.flags
            .iter()
            .filter(|(f, _)| *f == c)
            .filter_map(|(_, v)| v.clone())
            .collect()
    }

    /// The flags as they are sent: one each, a value as its own word. A cluster
    /// (`-uo/etc/passwd`) can't hide anything: it was taken apart letter by letter.
    fn out(&self) -> Vec<Out> {
        let mut out = Vec::new();
        for (f, v) in &self.flags {
            out.push(Out::Lit(format!("-{f}")));
            if let Some(v) = v {
                out.push(Out::Lit(v.clone()));
            }
        }
        out
    }
}

/// Flags first (`bools` take nothing, `vals` take the rest of their word or the next
/// one), then operands: an operand that starts with `-` is refused, so no flag hides
/// among the files whatever the program's own parser thinks of the order.
fn getopt<'a>(prog: &str, args: &'a [Arg], bools: &str, vals: &str) -> Res<Got<'a>> {
    let mut flags = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let t = a.text.as_str();
        if !t.starts_with('-') || t.len() < 2 {
            break;
        }
        lit(a)?;
        i += 1;
        if t == "--" {
            break;
        }
        if t.starts_with("--") {
            return Err(format!("`{t}` isn't a flag `{prog}` is run with here"));
        }
        let cs: Vec<char> = t[1..].chars().collect();
        let mut k = 0;
        while k < cs.len() {
            let c = cs[k];
            k += 1;
            if bools.contains(c) {
                flags.push((c, None));
            } else if vals.contains(c) {
                let v: String = if k < cs.len() {
                    cs[k..].iter().collect()
                } else {
                    let Some(n) = args.get(i) else {
                        return Err(format!("`-{c}` of `{prog}` needs a value"));
                    };
                    i += 1;
                    lit_brackets(n)?.to_string()
                };
                flags.push((c, Some(v)));
                break;
            } else {
                return Err(format!("`-{c}` isn't a flag `{prog}` is run with here"));
            }
        }
    }
    let rest = &args[i..];
    if let Some(a) = rest.iter().find(|a| a.text.starts_with('-')) {
        return Err(format!(
            "`{}`: flags come before the operands (and no operand starts with `-`)",
            a.text
        ));
    }
    Ok(Got { flags, rest })
}

/// A filter, as it is shown and as it is done here.
#[derive(Debug, Clone)]
pub struct Stage {
    pub shown: String,
    pub filter: Filter,
}

/// A program on the router with the arguments it gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub prog: String,
    pub args: Vec<Out>,
    pub redirs: Vec<Redir>,
}

impl Remote {
    /// The one line the router's shell is handed.
    pub fn line(&self) -> String {
        let mut parts = vec![self.prog.clone()];
        parts.extend(self.args.iter().map(Out::text));
        parts.extend(self.redirs.iter().map(|r| r.text().to_string()));
        parts.join(" ")
    }
}

#[derive(Debug, Clone)]
pub enum Source {
    Remote(Remote),
    /// `echo`: said here.
    Echo(String),
    /// `true`, `false`.
    Status(i32),
    Sleep(u64),
}

/// One pipeline: where its text comes from, and what is done to it here.
#[derive(Debug, Clone)]
pub struct Line {
    pub join: Join,
    pub source: Source,
    pub filters: Vec<Stage>,
    /// It ends in `>/dev/null`.
    pub discard: bool,
}

/// A read, as it will be carried out.
#[derive(Debug, Clone)]
pub struct Plan {
    pub lines: Vec<Line>,
}

impl Plan {
    /// Everything that will run on the router, in order.
    pub fn remotes(&self) -> Vec<&Remote> {
        self.lines
            .iter()
            .filter_map(|l| match &l.source {
                Source::Remote(r) => Some(r),
                _ => None,
            })
            .collect()
    }

    /// The line as sentry understood it.
    pub fn shown(&self) -> String {
        let mut out = String::new();
        for l in &self.lines {
            out.push_str(match l.join {
                Join::First => "",
                Join::Seq => "; ",
                Join::And => " && ",
                Join::Or => " || ",
            });
            out.push_str(&match &l.source {
                Source::Remote(r) => r.line(),
                Source::Echo(t) => format!("echo {}", quote(t.trim_end_matches('\n'))),
                Source::Status(0) => "true".into(),
                Source::Status(_) => "false".into(),
                Source::Sleep(n) => format!("sleep {n}"),
            });
            for f in &l.filters {
                out.push_str(" | ");
                out.push_str(&f.shown);
            }
            if l.discard && !l.filters.is_empty() {
                out.push_str(" >/dev/null");
            }
        }
        out
    }
}

/// A program's rule gave this.
struct Built {
    prog: String,
    args: Vec<Out>,
    /// Done here afterwards (`logread -e`).
    post: Vec<Stage>,
}

fn built(prog: &str, args: Vec<Out>) -> Res<Built> {
    Ok(Built {
        prog: prog.into(),
        args,
        post: Vec::new(),
    })
}

fn quoted_all(v: &[&str]) -> Vec<Out> {
    v.iter().map(|s| Out::Lit(s.to_string())).collect()
}

/// The programs a read may run on the router.
pub const PROGRAMS: &[&str] = &[
    "ubus",
    "uci",
    "nft",
    "fw4",
    "logread",
    "dmesg",
    "ip",
    "iw",
    "iwinfo",
    "brctl",
    "netstat",
    "apk",
    "owut",
    "service",
    "wifi",
    "ifstatus",
    "devstatus",
    "ps",
    "top",
    "df",
    "free",
    "uptime",
    "date",
    "uname",
    "id",
    "whoami",
    "hostname",
    "lsmod",
    "pidof",
    "pgrep",
    "mount",
    "block",
    "sysctl",
    "ls",
    "stat",
    "du",
    "readlink",
    "realpath",
    "which",
    "test",
    "find",
    "cat",
];

/// The filters, done here.
pub const FILTERS: &[&str] = &[
    "grep", "egrep", "fgrep", "head", "tail", "sort", "uniq", "wc", "cut",
];

/// Said here, never sent.
pub const LOCAL: &[&str] = &["echo", "true", "false", "sleep"];

/// One program's allowed forms: its arguments, validated and as they are sent.
fn rule(prog: &str, args: &[Arg]) -> Res<Built> {
    let no_args = |what: &str| -> Res<Built> {
        if args.is_empty() {
            built(prog, Vec::new())
        } else {
            Err(format!("`{prog}` reads without asking only {what}"))
        }
    };
    match prog {
        "ubus" => {
            let g = getopt(prog, args, "v", "t")?;
            if g.val('t').is_some_and(|t| !digits(t)) {
                return Err("`ubus -t` takes seconds".into());
            }
            let w = g.rest.iter().map(lit_brackets).collect::<Res<Vec<_>>>()?;
            let mut out = g.out();
            match w.as_slice() {
                ["list"] => out.push(Out::Lit("list".into())),
                ["list", pat]
                    if pat
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_.*@-".contains(c)) =>
                {
                    out.extend(quoted_all(&["list", pat]));
                }
                ["call", obj, method, rest @ ..] if rest.len() <= 1 => {
                    if !name(obj) || !name(method) {
                        return Err("`ubus call <object> <method>`: plain names".into());
                    }
                    let obj_base = obj.split('.').next().unwrap_or(obj);
                    if UBUS_NEVER.contains(&obj_base) {
                        return Err(format!("the ubus object `{obj}` is never called"));
                    }
                    let reads = if *obj == "service" {
                        *method == "list"
                    } else {
                        UBUS_READS.contains(method)
                    };
                    if !reads {
                        return Err(format!(
                            "`{method}` isn't one of the ubus methods known to only read"
                        ));
                    }
                    out.extend(quoted_all(&["call", obj, method]));
                    if let Some(msg) = rest.first() {
                        if !serde_json::from_str::<serde_json::Value>(msg)
                            .is_ok_and(|v| v.is_object())
                        {
                            return Err("a ubus message is one JSON object".into());
                        }
                        out.push(Out::Lit(msg.to_string()));
                    }
                }
                _ => {
                    return Err(
                        "`ubus` reads as `ubus [-v] list [<object>]` or `ubus call <object> <method> ['<json>']`"
                            .into(),
                    );
                }
            }
            built(prog, out)
        }
        "uci" => {
            let g = getopt(prog, args, "q", "")?;
            let w = g.rest.iter().map(lit_brackets).collect::<Res<Vec<_>>>()?;
            let path_ok = |p: &str, min: usize, max: usize| {
                let n = p.split('.').count();
                n >= min
                    && n <= max
                    && p.split('.').all(|s| !s.is_empty())
                    && p.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_.@[]-".contains(c))
            };
            let mut out = g.out();
            match w.as_slice() {
                [verb @ ("show" | "changes" | "export")] => out.push(Out::Lit(verb.to_string())),
                [verb @ ("show" | "changes"), p] if path_ok(p, 1, 3) => {
                    out.extend(quoted_all(&[verb, p]));
                }
                ["export", p] if path_ok(p, 1, 1) => out.extend(quoted_all(&["export", p])),
                ["get", p] if path_ok(p, 2, 3) => {
                    if crate::redact::secret(p) {
                        return Err(format!(
                            "`uci get {p}` would print a secret: `uci show` shows that it is set, as a tag"
                        ));
                    }
                    out.extend(quoted_all(&["get", p]));
                }
                _ => {
                    return Err(
                        "`uci` reads as `uci [-q] show|changes [<config>[.<section>[.<option>]]]`, `uci export [<config>]` or `uci get <config>.<section>[.<option>]`"
                            .into(),
                    );
                }
            }
            built(prog, out)
        }
        "nft" => {
            let g = getopt(prog, args, "ansjty", "")?;
            let w = lits(g.rest)?;
            let plain = |s: &&str| {
                !s.is_empty()
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c))
            };
            match w.as_slice() {
                ["list", what @ ..] if (1..=4).contains(&what.len()) && what.iter().all(plain) => {
                    let mut out = g.out();
                    out.extend(quoted_all(&w));
                    built(prog, out)
                }
                _ => Err("`nft` reads as `nft [-a] [-n] [-s] [-j] list <what> [<family> <table> [<name>]]`".into()),
            }
        }
        "fw4" => match lits(args)?.as_slice() {
            [v @ ("print" | "check")] => built(prog, quoted_all(&[v])),
            _ => Err("`fw4` reads as `fw4 print` or `fw4 check`".into()),
        },
        "logread" => {
            let g = getopt(prog, args, "t", "le")?;
            if !g.rest.is_empty() || g.val('l').is_some_and(|n| !digits(n)) {
                return Err("`logread` reads as `logread [-l <n>] [-e <pattern>] [-t]`".into());
            }
            let mut out = Vec::new();
            if let Some(n) = g.val('l') {
                out.extend(quoted_all(&["-l", n]));
            }
            if g.has('t') {
                out.push(Out::Lit("-t".into()));
            }
            // Its pattern is matched here, on the scrubbed log.
            let mut post = Vec::new();
            let pats = g.vals('e');
            if !pats.is_empty() {
                post.push(Stage {
                    shown: format!(
                        "grep -E {}",
                        pats.iter()
                            .map(|p| format!("-e {}", quote(p)))
                            .collect::<Vec<_>>()
                            .join(" ")
                    ),
                    filter: Filter::Grep {
                        re: filter::pattern(&pats, true, false, false, false, false)?,
                        invert: false,
                        count: false,
                        number: false,
                        quiet: false,
                        max: None,
                        before: 0,
                        after: 0,
                    },
                });
            }
            Ok(Built {
                prog: prog.into(),
                args: out,
                post,
            })
        }
        "dmesg" | "uptime" | "whoami" | "hostname" | "lsmod" | "mount" => {
            no_args("without arguments")
        }
        "ip" => {
            // Spelled out: busybox takes any beginning of a word (`ip r d default`), and a
            // selector that is an address or a prefix would be a question about the
            // uplink's address answered before the scrubbing.
            const FLAGS: &[&str] = &[
                "-4",
                "-6",
                "-0",
                "-s",
                "-d",
                "-o",
                "-j",
                "-p",
                "-br",
                "-brief",
                "-stats",
                "-statistics",
                "-details",
                "-oneline",
                "-json",
                "-pretty",
                "-h",
                "-human",
            ];
            const OBJECTS: &[&str] = &[
                "addr",
                "address",
                "a",
                "link",
                "l",
                "route",
                "r",
                "neigh",
                "neighbor",
                "neighbour",
                "n",
                "rule",
                "tunnel",
                "maddr",
                "mroute",
            ];
            let w = lits(args)?;
            let nflags = w.iter().take_while(|x| x.starts_with('-')).count();
            let (flags, rest) = w.split_at(nflags);
            let usage = "`ip` reads as `ip [-4|-6|-s|-d|-o|-j|-br] <object> [show [dev <device>] [default] [table <table>] [up]]` (spelled out)";
            if let Some(f) = flags.iter().find(|f| !FLAGS.contains(f)) {
                return Err(format!("`ip {f}`: {usage}"));
            }
            let Some((&obj, sel)) = rest.split_first() else {
                return Err(usage.into());
            };
            if !OBJECTS.contains(&obj) {
                return Err(usage.into());
            }
            let mut out = quoted_all(flags);
            out.push(Out::Lit(obj.to_string()));
            if let Some((&verb, sel)) = sel.split_first() {
                if !matches!(verb, "show" | "list") {
                    return Err(usage.into());
                }
                out.push(Out::Lit(verb.to_string()));
                let mut it = sel.iter().copied();
                while let Some(s) = it.next() {
                    match s {
                        "default" | "up" => out.push(Out::Lit(s.to_string())),
                        "dev" | "master" => match it.next() {
                            Some(d) if ifname(d) => out.extend(quoted_all(&[s, d])),
                            _ => return Err(usage.into()),
                        },
                        "table" => match it.next() {
                            Some(t)
                                if digits(t)
                                    || matches!(t, "all" | "main" | "local" | "default") =>
                            {
                                out.extend(quoted_all(&[s, t]));
                            }
                            _ => return Err(usage.into()),
                        },
                        "scope" => match it.next() {
                            Some(t @ ("global" | "link" | "host")) => {
                                out.extend(quoted_all(&[s, t]));
                            }
                            _ => return Err(usage.into()),
                        },
                        // `ip addr show br-lan`.
                        d if ifname(d)
                            && matches!(obj, "addr" | "address" | "a" | "link" | "l") =>
                        {
                            out.extend(quoted_all(&["dev", d]));
                        }
                        _ => return Err(usage.into()),
                    }
                }
            }
            built(prog, out)
        }
        "iw" => {
            let w = lits(args)?;
            let ok = match w.as_slice() {
                ["list" | "dev" | "phy"] | ["reg", "get"] => true,
                ["dev", d, "info" | "link"] => ifname(d),
                ["dev", d, "station" | "survey" | "mpath", "dump"] => ifname(d),
                ["phy", p, "info" | "channels"] => name(p),
                ["phy", p, "reg", "get"] => name(p),
                _ => false,
            };
            if !ok {
                // (No scan: the neighbours' networks are theirs, and a scan is a change
                // on the air.)
                return Err("`iw` reads as `iw dev`, `iw phy`, `iw list`, `iw reg get`, `iw dev <if> info|link`, `iw dev <if> station|survey dump`, `iw phy <phy> info|channels`".into());
            }
            built(prog, quoted_all(&w))
        }
        "iwinfo" => {
            let w = lits(args)?;
            match w.as_slice() {
                [] => built(prog, Vec::new()),
                [d, what @ ("info" | "assoclist" | "txpowerlist" | "freqlist" | "countrylist"
                | "htmodelist")]
                    if ifname(d) =>
                {
                    built(prog, quoted_all(&[d, what]))
                }
                _ => Err("`iwinfo` reads as `iwinfo` or `iwinfo <if> info|assoclist|freqlist|txpowerlist|countrylist` (no scan)".into()),
            }
        }
        "brctl" => {
            let w = lits(args)?;
            match w.as_slice() {
                ["show"] => built(prog, quoted_all(&w)),
                [v @ ("show" | "showmacs" | "showstp"), b] if ifname(b) => {
                    built(prog, quoted_all(&[v, b]))
                }
                _ => Err(
                    "`brctl` reads as `brctl show [<bridge>]`, `brctl showmacs|showstp <bridge>`"
                        .into(),
                ),
            }
        }
        "netstat" => {
            let g = getopt(prog, args, "alntuwxrepW", "")?;
            if !g.rest.is_empty() {
                return Err("`netstat` takes flags only".into());
            }
            built(prog, g.out())
        }
        "apk" => {
            let w = lits(args)?;
            if w == ["--version"] {
                return built(prog, quoted_all(&w));
            }
            const FLAGS: &[&str] = &[
                "--no-network",
                "--installed",
                "-I",
                "--upgradable",
                "-u",
                "--available",
                "-a",
                "--orphaned",
                "-O",
                "--manifest",
                "-v",
                "-q",
                "--quiet",
                "-d",
                "--description",
                "-L",
                "--contents",
                "-s",
                "--size",
                "-w",
                "--webpage",
                "-e",
                "-R",
                "--depends",
                "-r",
                "--rdepends",
                "-P",
                "--provides",
                "-x",
                "--exact",
                "-o",
                "--origin",
            ];
            const SUBS: &[&str] = &["list", "info", "search", "version", "policy", "query"];
            let usage = "`apk` reads as `apk --no-network list|info|search|version|policy|query …` (the index it has: nothing is fetched)";
            if !w.contains(&"--no-network") {
                return Err(usage.into());
            }
            let mut sub = false;
            let mut it = w.iter();
            while let Some(a) = it.next() {
                let ok = match *a {
                    f if FLAGS.contains(&f) => true,
                    "-l" | "--limit" => it
                        .next()
                        .is_some_and(|v| !v.is_empty() && v.chars().all(|c| "<>=?".contains(c))),
                    "--format" => it
                        .next()
                        .is_some_and(|v| matches!(*v, "json" | "yaml" | "default")),
                    "--fields" => it.next().is_some_and(|v| {
                        !v.is_empty()
                            && v.chars()
                                .all(|c| c.is_ascii_alphanumeric() || ",_-".contains(c))
                    }),
                    s if !sub && SUBS.contains(&s) => {
                        sub = true;
                        true
                    }
                    // A package's name, or apk's own pattern for one.
                    p => {
                        sub && !p.starts_with('-')
                            && !p.is_empty()
                            && p.chars()
                                .all(|c| c.is_ascii_alphanumeric() || "+._*?-".contains(c))
                    }
                };
                if !ok {
                    return Err(format!("`{a}`: {usage}"));
                }
            }
            if !sub {
                return Err(usage.into());
            }
            built(prog, quoted_all(&w))
        }
        "owut" => match lits(args)?.as_slice() {
            ["--version"] => built(prog, quoted_all(&["--version"])),
            _ => Err("`owut` reads only as `owut --version` (the rest fetches or flashes)".into()),
        },
        "service" => match lits(args)?.as_slice() {
            [] => built(prog, Vec::new()),
            [s, v @ ("status" | "enabled" | "running")] if name(s) && !s.starts_with('.') => {
                built(&format!("/etc/init.d/{s}"), quoted_all(&[v]))
            }
            _ => Err("a service is read as `/etc/init.d/<service> status|enabled|running`".into()),
        },
        "wifi" => match lits(args)?.as_slice() {
            ["status"] => built(prog, quoted_all(&["status"])),
            _ => Err("`wifi` reads only as `wifi status`".into()),
        },
        "ifstatus" | "devstatus" => match lits(args)?.as_slice() {
            [d] if name(d) => built(prog, quoted_all(&[d])),
            _ => Err(format!("`{prog} <name>`")),
        },
        "ps" => match lits(args)?.as_slice() {
            [] => built(prog, Vec::new()),
            ["w" | "ww" | "-w" | "-ww"] => built(prog, quoted_all(&["w"])),
            _ => Err("`ps` reads as `ps` or `ps w`".into()),
        },
        "top" => {
            let g = getopt(prog, args, "b", "n")?;
            if !g.has('b') || g.val('n') != Some("1") || !g.rest.is_empty() {
                return Err("`top` reads only as `top -b -n 1`".into());
            }
            built(prog, quoted_all(&["-b", "-n", "1"]))
        }
        "df" => {
            let g = getopt(prog, args, "hPkmTia", "")?;
            let mut out = g.out();
            for a in g.rest {
                out.push(listable(a)?);
            }
            built(prog, out)
        }
        "free" => {
            let g = getopt(prog, args, "hmkgb", "")?;
            if !g.rest.is_empty() {
                return Err("`free` takes flags only".into());
            }
            built(prog, g.out())
        }
        "date" => {
            let w = lits(args)?;
            let ok = w.iter().all(|a| {
                matches!(*a, "-u" | "-R")
                    || a.strip_prefix("-I")
                        .is_some_and(|r| r.chars().all(|c| c.is_ascii_alphabetic()))
                    || a.starts_with('+')
            }) && w.iter().filter(|a| a.starts_with('+')).count() <= 1;
            if !ok {
                return Err("`date` reads as `date [-u] [-R] [-I…] [+<format>]` (anything else may set the clock)".into());
            }
            built(prog, quoted_all(&w))
        }
        "uname" => {
            let g = getopt(prog, args, "amnrsvpio", "")?;
            if !g.rest.is_empty() {
                return Err("`uname` takes flags only".into());
            }
            built(prog, g.out())
        }
        "id" => match lits(args)?.as_slice() {
            [] => built(prog, Vec::new()),
            [f @ ("-u" | "-g" | "-G" | "-un" | "-gn" | "-Gn")] => built(prog, quoted_all(&[f])),
            _ => Err("`id` reads as `id [-u|-g|-G|-un|-gn]`".into()),
        },
        "pidof" => match lits(args)?.as_slice() {
            [n] if name(n) => built(prog, quoted_all(&[n])),
            _ => Err("`pidof <name>`".into()),
        },
        "pgrep" => {
            // By the process's name only: `-f` would match command lines, which hold
            // what the scrubbing hides.
            let g = getopt(prog, args, "lx", "")?;
            match lits(g.rest)?.as_slice() {
                [n] if name(n) => {
                    let mut out = g.out();
                    out.push(Out::Lit(n.to_string()));
                    built(prog, out)
                }
                _ => Err("`pgrep [-l] [-x] <name>` (a process's name, no pattern, no -f)".into()),
            }
        }
        "block" => match lits(args)?.as_slice() {
            ["info"] => built(prog, quoted_all(&["info"])),
            _ => Err("`block` reads only as `block info`".into()),
        },
        "sysctl" => {
            let g = getopt(prog, args, "ane", "")?;
            let w = lits(g.rest)?;
            // (No `/`: busybox makes a path of the key, and `..` would leave /proc/sys.)
            let key = |k: &&str| {
                !k.is_empty()
                    && k.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
            };
            if !w.iter().all(key) || (w.is_empty() && !g.has('a')) {
                return Err("`sysctl` reads as `sysctl [-n] <key>…` or `sysctl -a` (a key with dots; never `key=value`)".into());
            }
            let mut out = g.out();
            out.extend(quoted_all(&w));
            built(prog, out)
        }
        "ls" => {
            let g = getopt(prog, args, "lahAd1trSnFpL", "")?;
            let mut out = g.out();
            for a in g.rest {
                out.push(listable(a)?);
            }
            built(prog, out)
        }
        "stat" => {
            let g = getopt(prog, args, "Lt", "")?;
            if g.rest.is_empty() {
                return Err("`stat <path>…`".into());
            }
            let mut out = g.out();
            for a in g.rest {
                out.push(listable(a)?);
            }
            built(prog, out)
        }
        "du" => {
            let g = getopt(prog, args, "shkmacx", "d")?;
            if g.val('d').is_some_and(|d| !digits(d)) {
                return Err("`du -d <depth>`".into());
            }
            let mut out = g.out();
            for a in g.rest {
                out.push(listable(a)?);
            }
            built(prog, out)
        }
        "readlink" | "realpath" => {
            let g = getopt(prog, args, if prog == "readlink" { "f" } else { "" }, "")?;
            match g.rest {
                [a] => {
                    let mut out = g.out();
                    out.push(listable(a)?);
                    built(prog, out)
                }
                _ => Err(format!("`{prog} <path>`")),
            }
        }
        "which" => {
            let w = lits(args)?;
            if w.is_empty() || w.len() > 8 || !w.iter().all(|n| name(n)) {
                return Err("`which <command>…`".into());
            }
            built(prog, quoted_all(&w))
        }
        "test" => {
            let usage = "`test` reads as `test -e|-f|-d|-s|-L|-r|-x <path>`";
            let [f, p] = args else {
                return Err(usage.into());
            };
            let f = lit(f)?;
            if !matches!(f, "-e" | "-f" | "-d" | "-s" | "-L" | "-h" | "-r" | "-x") || p.star {
                return Err(usage.into());
            }
            built(prog, vec![Out::Lit(f.to_string()), listable(p)?])
        }
        "find" => {
            // Names only, from a few roots, by an allowed list of tests: nothing that runs
            // (`-exec`, `-ok`), deletes (`-delete`) or writes (`-fprint`, `-fls`).
            let nroots = args.iter().take_while(|a| !a.text.starts_with('-')).count();
            if nroots == 0 {
                return Err("`find <directory>… [tests]`: name where to look".into());
            }
            let mut out = Vec::new();
            for a in &args[..nroots] {
                let Out::Lit(p) = listable(a)? else {
                    return Err("`find` starts from a directory named exactly".into());
                };
                if !under(&p, FIND_ROOTS) {
                    return Err(format!(
                        "`find` starts under one of {} (not `{p}`)",
                        FIND_ROOTS.join(", ")
                    ));
                }
                out.push(Out::Lit(p));
            }
            let w = lits(&args[nroots..])?;
            let mut it = w.iter();
            let number = |s: &str, units: &str| {
                let s = s.trim_start_matches(['+', '-']);
                let s = s.trim_end_matches(|c| units.contains(c));
                digits(s)
            };
            while let Some(t) = it.next() {
                let ok = match *t {
                    "-print" | "-xdev" => true,
                    "-name" | "-iname" | "-path" => it.next().is_some_and(|v| !v.is_empty()),
                    "-type" => it.next().is_some_and(|v| matches!(*v, "f" | "d" | "l")),
                    "-maxdepth" | "-mindepth" => it.next().is_some_and(|v| digits(v)),
                    "-mtime" | "-mmin" => it.next().is_some_and(|v| number(v, "")),
                    "-size" => it.next().is_some_and(|v| number(v, "ckMG")),
                    _ => {
                        return Err(format!(
                            "`find {t}`: only -name, -iname, -path, -type, -maxdepth, -mindepth, -mtime, -mmin, -size, -xdev and -print (never -exec, -ok, -delete, -fprint)"
                        ));
                    }
                };
                if !ok {
                    return Err(format!("`find {t}` needs its value"));
                }
            }
            out.extend(quoted_all(&w));
            built(prog, out)
        }
        "cat" => {
            if args.is_empty() {
                return Err("`cat <file>…`".into());
            }
            if let Some(a) = args.iter().find(|a| a.text.starts_with('-')) {
                return Err(format!("`cat {}`: no flags", a.text));
            }
            built(prog, args.iter().map(readable).collect::<Res<Vec<_>>>()?)
        }
        _ => Err(format!(
            "`{prog}` isn't one of the programs that read without asking"
        )),
    }
}

/// A filter's arguments: the filter, and the one file it was pointed at (read on the
/// router with `cat`; the filter itself is done here).
fn filter_of(prog: &str, args: &[Arg]) -> Res<(Stage, Option<Out>)> {
    let mut shown = vec![prog.to_string()];
    let one_file = |rest: &[Arg]| -> Res<Option<Out>> {
        match rest {
            [] => Ok(None),
            [f] => Ok(Some(readable(f)?)),
            _ => Err(format!(
                "`{prog}` on several files at once (one file, or `cat` them)"
            )),
        }
    };
    let number = |s: &str| -> Res<usize> {
        s.parse::<usize>()
            .ok()
            .filter(|_| s.len() <= 9)
            .ok_or_else(|| format!("`{prog}`: `{s}` isn't a number"))
    };
    let (filter, file) = match prog {
        "grep" | "egrep" | "fgrep" => {
            let g = getopt(prog, args, "ivcnEFwxqsh", "emABC")?;
            let mut pats = g.vals('e');
            let mut rest = g.rest;
            if pats.is_empty() {
                let Some((p, r)) = rest.split_first() else {
                    return Err(format!("`{prog}` needs a pattern"));
                };
                pats.push(lit_brackets(p)?.to_string());
                rest = r;
            }
            let ctx = |c: char| -> Res<usize> {
                match g.val(c).or(g.val('C')) {
                    Some(n) => number(n).map(|n| n.min(1000)),
                    None => Ok(0),
                }
            };
            for (c, _) in g.flags.iter().filter(|(c, _)| !"emABCsh".contains(*c)) {
                shown.push(format!("-{c}"));
            }
            for c in ['m', 'A', 'B', 'C'] {
                if let Some(v) = g.val(c) {
                    shown.push(format!("-{c} {}", quote(v)));
                }
            }
            shown.extend(pats.iter().map(|p| format!("-e {}", quote(p))));
            (
                Filter::Grep {
                    re: filter::pattern(
                        &pats,
                        g.has('E') || prog == "egrep",
                        g.has('F') || prog == "fgrep",
                        g.has('i'),
                        g.has('w'),
                        g.has('x'),
                    )?,
                    invert: g.has('v'),
                    count: g.has('c'),
                    number: g.has('n'),
                    quiet: g.has('q'),
                    max: g.val('m').map(number).transpose()?,
                    before: ctx('B')?,
                    after: ctx('A')?,
                },
                one_file(rest)?,
            )
        }
        "head" | "tail" => {
            // `-20` is `-n 20`. Never `-c` (bytes) or `-f` (it never ends).
            let (n, rest): (Option<String>, &[Arg]) = match args.split_first() {
                Some((a, rest))
                    if a.text.len() > 1
                        && a.text.starts_with('-')
                        && a.text[1..].chars().all(|c| c.is_ascii_digit()) =>
                {
                    (Some(a.text[1..].to_string()), rest)
                }
                _ => {
                    let g = getopt(prog, args, "", "n")?;
                    (g.val('n').map(str::to_string), g.rest)
                }
            };
            let n = n.unwrap_or_else(|| "10".into());
            shown.push(format!("-n {}", quote(&n)));
            let take = match (prog, n.strip_prefix('+'), n.strip_prefix('-')) {
                ("tail", Some(from), _) => Take::Rest(number(from)?),
                ("head", _, Some(but)) => Take::Rest(number(but)?),
                ("tail", _, Some(last)) => Take::N(number(last)?),
                _ => Take::N(number(&n)?),
            };
            let f = if prog == "head" {
                Filter::Head(take)
            } else {
                Filter::Tail(take)
            };
            (f, one_file(rest)?)
        }
        "sort" => {
            // Never `-o` (it writes a file) or `-T`.
            let g = getopt(prog, args, "urnf", "kt")?;
            shown.extend(g.out().iter().map(Out::text));
            let key = g.val('k').map(number).transpose()?.filter(|k| *k > 0);
            let sep = match g.val('t') {
                None => None,
                Some(t) if t.chars().count() == 1 => t.chars().next(),
                Some(_) => return Err("`sort -t` takes one character".into()),
            };
            (
                Filter::Sort {
                    unique: g.has('u'),
                    reverse: g.has('r'),
                    numeric: g.has('n'),
                    fold: g.has('f'),
                    key,
                    sep,
                },
                one_file(g.rest)?,
            )
        }
        "uniq" => {
            let g = getopt(prog, args, "cdui", "")?;
            shown.extend(g.out().iter().map(Out::text));
            (
                Filter::Uniq {
                    count: g.has('c'),
                    dups: g.has('d'),
                    uniques: g.has('u'),
                    fold: g.has('i'),
                },
                one_file(g.rest)?,
            )
        }
        "wc" => {
            let g = getopt(prog, args, "lwcm", "")?;
            shown.extend(g.out().iter().map(Out::text));
            let file = one_file(g.rest)?;
            (
                Filter::Wc {
                    lines: g.has('l'),
                    words: g.has('w'),
                    bytes: g.has('c') || g.has('m'),
                    name: file.as_ref().map(|f| match f {
                        Out::Lit(p) | Out::Glob(p) => p.clone(),
                    }),
                },
                file,
            )
        }
        "cut" => {
            let g = getopt(prog, args, "s", "dfc")?;
            shown.extend(g.out().iter().map(Out::text));
            let delim = match g.val('d') {
                None => '\t',
                Some(d) if d.chars().count() == 1 => d.chars().next().expect("one"),
                Some(_) => return Err("`cut -d` takes one character".into()),
            };
            let list = |c: char| -> Res<Option<filter::Ranges>> {
                match g.val(c) {
                    None => Ok(None),
                    Some(l) => filter::ranges(l)
                        .map(Some)
                        .ok_or_else(|| format!("`cut -{c} {l}` isn't a list like 1,3-5")),
                }
            };
            let (fields, chars) = (list('f')?, list('c')?);
            if fields.is_some() == chars.is_some() {
                return Err("`cut` takes -f <list> or -c <list>".into());
            }
            (
                Filter::Cut {
                    delim,
                    fields,
                    chars,
                    only_delimited: g.has('s'),
                },
                one_file(g.rest)?,
            )
        }
        _ => {
            return Err(format!(
                "`| {prog}`: after a pipe only {} are done (here, on what was scrubbed)",
                FILTERS.join(", ")
            ));
        }
    };
    Ok((
        Stage {
            shown: shown.join(" "),
            filter,
        },
        file,
    ))
}

fn pipeline(join: Join, stages: &[Simple]) -> Res<Line> {
    let (first, rest) = stages
        .split_first()
        .expect("parse leaves no empty pipeline");
    // `>/dev/null` only where the pipeline ends.
    if stages[..stages.len() - 1]
        .iter()
        .any(|s| s.redirs.contains(&Redir::OutNull))
    {
        return Err("`>/dev/null` before a pipe".into());
    }
    let (w, args) = first.words.split_first().expect("not empty");
    let prog = lit(w)?;
    let mut filters = Vec::new();
    let mut redirs = first.redirs.clone();
    let source = if let Some(svc) = prog.strip_prefix("/etc/init.d/") {
        // Sent as the same path, made here from a name that is only a name.
        let mut a = vec![Arg {
            text: svc.to_string(),
            ..Default::default()
        }];
        a.extend(args.iter().cloned());
        if a.len() != 2 {
            return Err(
                "a service is read as `/etc/init.d/<service> status|enabled|running`".into(),
            );
        }
        let b = rule("service", &a)?;
        Source::Remote(Remote {
            prog: b.prog,
            args: b.args,
            redirs: redirs.clone(),
        })
    } else if FILTERS.contains(&prog) {
        let (stage, file) = filter_of(prog, args)?;
        let Some(file) = file else {
            return Err(format!("`{prog}` with nothing to read"));
        };
        filters.push(stage);
        // The file is read there, whole; where its text goes is decided here.
        redirs.retain(|r| *r != Redir::OutNull);
        Source::Remote(Remote {
            prog: "cat".into(),
            args: vec![file],
            redirs: redirs.clone(),
        })
    } else if LOCAL.contains(&prog) {
        let w = lits(args)?;
        match prog {
            "echo" => {
                let (nl, w) = match w.split_first() {
                    Some((&"-n", rest)) => ("", rest),
                    _ => ("\n", &w[..]),
                };
                Source::Echo(format!("{}{nl}", w.join(" ")))
            }
            "true" | "false" if w.is_empty() => Source::Status(i32::from(prog == "false")),
            "sleep" => match w.as_slice() {
                [n] if digits(n) && n.parse::<u64>().is_ok_and(|n| n <= 30) => {
                    Source::Sleep(n.parse().expect("checked"))
                }
                _ => return Err("`sleep <seconds>`, 30 at most".into()),
            },
            _ => return Err(format!("`{prog}` takes no arguments")),
        }
    } else if PROGRAMS.contains(&prog) {
        let b = rule(prog, args)?;
        filters.extend(b.post);
        if !filters.is_empty() {
            redirs.retain(|r| *r != Redir::OutNull);
        }
        Source::Remote(Remote {
            prog: b.prog,
            args: b.args,
            redirs: redirs.clone(),
        })
    } else {
        return Err(format!(
            "`{prog}` isn't one of the programs that read without asking"
        ));
    };
    for s in rest {
        let (w, args) = s.words.split_first().expect("not empty");
        let (stage, file) = filter_of(lit(w)?, args)?;
        if file.is_some() {
            return Err(format!(
                "`| {}` with a file of its own: it would ignore what is piped to it",
                w.text
            ));
        }
        filters.push(stage);
    }
    let last = stages.last().expect("not empty");
    // The router's own `>/dev/null` stays in the line it is sent; one after a filter is
    // carried out here.
    let discard = last.redirs.contains(&Redir::OutNull);
    Ok(Line {
        join,
        source,
        filters,
        discard,
    })
}

/// How a line is carried out, if it is a read. Err: why it isn't one.
pub fn plan(line: &str) -> Res<Plan> {
    if line.len() > 2000 {
        return Err("the line is too long to be read as a read".into());
    }
    let parsed = parse(line)?;
    if parsed.len() > 12 {
        return Err("too many commands in one line".into());
    }
    let lines = parsed
        .iter()
        .map(|(j, stages)| pipeline(*j, stages))
        .collect::<Res<Vec<_>>>()?;
    Ok(Plan { lines })
}

/// The same for one command given as its words (`exec`): nothing is parsed, so nothing in
/// a word is syntax.
pub fn plan_argv(argv: &[String]) -> Res<Plan> {
    if argv.is_empty() {
        return Err("no command".into());
    }
    if argv.iter().any(|a| a.chars().any(char::is_control)) {
        return Err("a line break or a control character".into());
    }
    let words = argv
        .iter()
        .map(|a| Arg {
            text: a.clone(),
            quoted: true,
            ..Default::default()
        })
        .collect();
    let stage = Simple {
        words,
        redirs: Vec::new(),
    };
    Ok(Plan {
        lines: vec![pipeline(Join::First, &[stage])?],
    })
}

#[cfg(test)]
mod tests;
