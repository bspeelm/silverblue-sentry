use super::*;

fn shown(line: &str) -> Result<String, String> {
    plan(line).map(|p| p.shown())
}

/// What goes to the router for a line, each as it is sent.
fn sent(line: &str) -> Vec<String> {
    plan(line)
        .unwrap_or_else(|e| panic!("{line}: {e}"))
        .remotes()
        .iter()
        .map(|r| r.line())
        .collect()
}

#[test]
fn a_read_is_rebuilt_from_what_was_understood() {
    // (as written, as understood: what is sent is the part before any `|`)
    let table: &[(&str, &str)] = &[
        ("uci show dhcp", "uci 'show' 'dhcp'"),
        ("uci -q show wireless", "uci '-q' 'show' 'wireless'"),
        (
            "uci show firewall.@zone[0]",
            "uci 'show' 'firewall.@zone[0]'",
        ),
        (
            "uci get \"dropbear.main.Port\"",
            "uci 'get' 'dropbear.main.Port'",
        ),
        (
            "ubus call service list '{\"name\":\"dnsmasq\"}'",
            "ubus 'call' 'service' 'list' '{\"name\":\"dnsmasq\"}'",
        ),
        ("ubus -v list 'hostapd.*'", "ubus '-v' 'list' 'hostapd.*'"),
        (
            "ip -4 route show default",
            "ip '-4' 'route' 'show' 'default'",
        ),
        ("ip addr show br-lan", "ip 'addr' 'show' 'dev' 'br-lan'"),
        (
            "nft -an list table inet fw4",
            "nft '-a' '-n' 'list' 'table' 'inet' 'fw4'",
        ),
        ("netstat -lntup", "netstat '-l' '-n' '-t' '-u' '-p'"),
        ("/etc/init.d/dnsmasq status", "/etc/init.d/dnsmasq 'status'"),
        ("service dropbear enabled", "/etc/init.d/dropbear 'enabled'"),
        ("service", "service"),
        ("ps w", "ps 'w'"),
        ("top -bn1", "top '-b' '-n' '1'"),
        ("df -h 2>/dev/null", "df '-h' 2>/dev/null"),
        ("ls -la /etc/config", "ls '-l' '-a' '/etc/config'"),
        ("ls /etc//dropbear/./", "ls '/etc/dropbear'"),
        ("cat /proc//net/../loadavg", "cat '/proc/loadavg'"),
        (
            "cat /sys/class/net/*/carrier",
            "cat /sys/class/net/*/carrier",
        ),
        ("ls -d /sys/class/net/lan?", "ls '-d' /sys/class/net/lan?"),
        (
            "find /etc -name '*.conf' -type f",
            "find '/etc' '-name' '*.conf' '-type' 'f'",
        ),
        (
            "test -e /tmp/x && echo yes",
            "test '-e' '/tmp/x' && echo 'yes'",
        ),
        ("date -u +%s", "date '-u' '+%s'"),
        (
            "apk --no-network version -l '<'",
            "apk '--no-network' 'version' '-l' '<'",
        ),
        // A filter is done here; its file is read there with cat, whole.
        (
            "grep -c lan /tmp/dhcp.leases",
            "cat '/tmp/dhcp.leases' | grep -c -e 'lan'",
        ),
        (
            "cut -d' ' -f2 /tmp/dhcp.leases",
            "cat '/tmp/dhcp.leases' | cut '-d' ' ' '-f' '2'",
        ),
        ("head -5 /proc/meminfo", "cat '/proc/meminfo' | head -n '5'"),
        (
            "tail -n +2 /proc/net/arp",
            "cat '/proc/net/arp' | tail -n '+2'",
        ),
        ("wc -l /tmp/dhcp.leases", "cat '/tmp/dhcp.leases' | wc '-l'"),
        (
            "uci -q show dhcp | grep -v '^dhcp.lan' | sort | head -n 20",
            "uci '-q' 'show' 'dhcp' | grep -v -e '^dhcp.lan' | sort | head -n '20'",
        ),
        (
            "logread -l 50 -e dropbear | tail -20",
            "logread '-l' '50' | grep -E -e 'dropbear' | tail -n '20'",
        ),
        (
            "dmesg 2>&1 | grep -i [m]t76",
            "dmesg 2>&1 | grep -i -e '[m]t76'",
        ),
        (
            "uptime; free && true || false",
            "uptime; free && true || false",
        ),
        (
            "uci changes >/dev/null 2>&1;",
            "uci 'changes' >/dev/null 2>&1",
        ),
        (
            "ps w | grep -q dnsmasq >/dev/null",
            "ps 'w' | grep -q -e 'dnsmasq' >/dev/null",
        ),
    ];
    for (line, want) in table {
        assert_eq!(shown(line).as_deref(), Ok(*want), "{line}");
    }
    // Only the first command of a pipeline is the router's; the rest never leaves here.
    assert_eq!(
        sent("uci show wireless | grep key; grep -c x /tmp/dhcp.leases; echo a | wc -l"),
        ["uci 'show' 'wireless'", "cat '/tmp/dhcp.leases'"]
    );
    assert_eq!(sent("logread -e 'key=.'"), ["logread"]);
    assert!(sent("echo 'reboot; wifi down' | grep -c reboot").is_empty());
    // One command given as its words: nothing in a word is syntax.
    let argv = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(
        plan_argv(&argv(&["uci", "show", "dhcp; reboot"])).map(|p| p.shown()),
        Err("`uci` reads as `uci [-q] show|changes [<config>[.<section>[.<option>]]]`, `uci export [<config>]` or `uci get <config>.<section>[.<option>]`".into())
    );
    assert_eq!(
        plan_argv(&argv(&["grep", "it's $x", "/proc/version"]))
            .unwrap()
            .remotes()[0]
            .line(),
        "cat '/proc/version'"
    );
    // (A `*` in a word is the character: quoted, it names no file.)
    assert_eq!(
        plan_argv(&argv(&["cat", "/sys/class/net/*/address"]))
            .unwrap()
            .shown(),
        "cat '/sys/class/net/*/address'"
    );
    // However the program's name is quoted, what is sent is the name from the list.
    assert_eq!(sent("'ca't \"/proc\"/uptime"), ["cat '/proc/uptime'"]);
    assert!(plan_argv(&argv(&["sh", "-c", "uci show dhcp"])).is_err());
    assert!(plan_argv(&[]).is_err());
}

#[test]
fn outside_the_grammar() {
    // (the line, a word of why)
    let table: &[(&str, &str)] = &[
        ("echo $HOME", "`$`"),
        ("echo \"$(wifi down)\"", "`$` in double quotes"),
        ("echo \"`uci commit network`\"", "in double quotes"),
        ("echo \"a\\\"b\"", "in double quotes"),
        ("X=\"$(reboot)\"", "in double quotes"),
        ("echo `id`", "backtick"),
        ("echo x #'", "`#`"),
        ("echo x # y", "`#`"),
        ("uptime\nwifi down", "line break"),
        ("uptime\twifi", "control character"),
        ("echo $'\\'' ; wifi down #'", "`$`"),
        ("echo a\\ b", "backslash"),
        ("ls ~", "`~`"),
        ("echo {a,b}", "brace"),
        ("(uptime)", "parenthesis"),
        ("cat < /proc/uptime", "`<`"),
        ("cat <<EOF", "`<`"),
        ("sleep 5 &", "`&`"),
        ("uptime &> /dev/null", "`&`"),
        ("echo x > /tmp/x", "only redirections"),
        ("echo x >> /dev/null", "only redirections"),
        ("echo x 1>/dev/null", "only redirections"),
        ("echo x 2>/dev/nullx", "only redirections"),
        ("echo x 3>&1", "only redirections"),
        ("echo x >&2", "only redirections"),
        ("echo x 2>&12", "only redirections"),
        ("echo 'x", "isn't closed"),
        ("uptime | | free", "empty command"),
        ("| uptime", "empty command"),
        ("uptime &&", "empty command"),
        (";", "empty command"),
        ("", "empty command"),
        ("2>/dev/null uptime", "before its command"),
        // Parsed, and not a program that reads.
        ("X=1 uptime", "`X=1` isn't one of the programs"),
        ("LC_ALL=C df -h", "isn't one of the programs"),
        (
            "/bin/cat /proc/uptime",
            "`/bin/cat` isn't one of the programs",
        ),
        (
            "busybox cat /proc/uptime",
            "`busybox` isn't one of the programs",
        ),
        ("/tmp/cat /proc/uptime", "isn't one of the programs"),
        ("./ls", "isn't one of the programs"),
        ("env uci show dhcp", "isn't one of the programs"),
        ("sh -c 'uci show dhcp'", "isn't one of the programs"),
        ("if true; then uptime; fi", "isn't one of the programs"),
        ("! uptime", "isn't one of the programs"),
        ("c*t /proc/uptime", "a pattern outside quotes"),
        // A pattern outside quotes, where none is expanded.
        ("cat /etc/*", "a pattern is expanded only"),
        ("cat /proc/*/cmdline", "a pattern is expanded only"),
        ("ls /tmp/*", "a pattern is expanded only"),
        ("cat /sys/class/net/.?/x", "a pattern is expanded only"),
        (
            "cat /sys/class/net/*/../../../kernel/debug/x",
            "debug files hold keys",
        ),
        ("cat /sys/class/net/*/../../x", "a pattern is expanded only"),
        (
            "cat /sys/class/net/[a-z]*/address",
            "a pattern outside quotes",
        ),
        ("grep foo* /proc/version", "a pattern outside quotes"),
        ("apk --no-network search luci-*", "a pattern outside quotes"),
        // After a pipe, only the filters; and none with a file of its own.
        ("uci show dhcp | awk '{print $1}'", "after a pipe only"),
        ("uci show dhcp | tr -d =", "after a pipe only"),
        ("uci show dhcp | sh", "after a pipe only"),
        ("uci show dhcp | xargs echo", "after a pipe only"),
        ("uci show dhcp | cat", "after a pipe only"),
        ("uptime | grep x /proc/version", "a file of its own"),
        ("uci show dhcp >/dev/null | wc -l", "before a pipe"),
        ("grep x", "nothing to read"),
        ("grep x /proc/version /proc/uptime", "several files"),
    ];
    for (line, says) in table {
        match plan(line) {
            Ok(p) => panic!("{line:?} is a read: {}", p.shown()),
            Err(e) => assert!(e.contains(says), "{line:?}: {e}"),
        }
    }
}

#[test]
fn each_program_takes_only_the_flags_on_its_list() {
    // (program, forms that read, forms that don't)
    let table: &[(&str, &[&str], &[&str])] = &[
        (
            "ubus",
            &[
                "list",
                "-v list system",
                "-t 5 call system board",
                "call network.interface.wan status",
            ],
            &[
                "-S call network.wireless status",
                "call file read '{\"path\":\"/etc/shadow\"}'",
                "call uci get '{\"config\":\"wireless\"}'",
                "call session list",
                "call system reboot",
                "call network reload",
                "call service delete '{\"name\":\"dropbear\"}'",
                "call system board notjson",
                "send foo",
                "monitor",
                "-s /tmp/x list",
            ],
        ),
        (
            "uci",
            &[
                "show",
                "show network.lan",
                "changes",
                "export dhcp",
                "get system.@system[0].hostname",
            ],
            &[
                "get wireless.default_radio0.key",
                "get network.wg0.private_key",
                "get wireless",
                "-c /tmp/x show wireless",
                "-X show wireless",
                "-d , show wireless",
                "-p /tmp/.uci show",
                "show a b",
                "set system.x.y=1",
                "commit",
                "batch",
                "import dhcp",
                "show 'dhcp; reboot'",
            ],
        ),
        (
            "nft",
            &[
                "list ruleset",
                "-j list tables",
                "-nn list chain inet fw4 input",
            ],
            &[
                "-f /tmp/x",
                "--file=/tmp/x",
                "-af /tmp/x",
                "-i",
                "list ruleset; flush ruleset",
                "'list ruleset; flush ruleset'",
                "flush ruleset",
                "monitor",
                "-c list ruleset",
            ],
        ),
        (
            "fw4",
            &["print", "check"],
            &["reload", "restart", "flush", ""],
        ),
        (
            "logread",
            &["", "-l 20", "-t", "-e dnsmasq -l 5"],
            &[
                "-f",
                "-F /tmp/log",
                "-r 192.0.2.9 514",
                "-p /tmp/pid",
                "-l x",
                "x",
            ],
        ),
        ("dmesg", &[""], &["-c", "-C", "-n 1", "-w"]),
        (
            "ip",
            &[
                "addr",
                "a",
                "-6 route show",
                "neigh show dev br-lan",
                "route show table all",
                "-s link show dev wan",
                "link show up",
            ],
            &[
                "",
                "route get 192.0.2.1",
                "addr show to 192.0.2.0/24",
                "route show 192.0.2.0/24",
                "route show match 192.0.2.1",
                "neigh show 192.0.2.5",
                "addr show 10.0.0.1",
                "r d default",
                "a f dev br-lan",
                "link set br-lan down",
                "route del default",
                "addr add 192.0.2.9/24 dev br-lan",
                "neigh flush all",
                "-batch /tmp/x",
                "-force -b -",
                "-r addr",
                "netns exec x sh",
                "monitor",
                "route sh",
            ],
        ),
        (
            "iw",
            &[
                "dev",
                "list",
                "reg get",
                "dev phy0-ap0 info",
                "dev phy0-ap0 station dump",
                "phy phy0 channels",
            ],
            &[
                "dev phy0-ap0 scan",
                "dev phy0-ap0 scan dump",
                "dev phy0-ap0 station get 02:00:5e:00:53:01",
                "dev phy0-ap0 set txpower fixed 100",
                "dev phy0-ap0 del",
                "phy phy0 interface add x type monitor",
                "event",
            ],
        ),
        (
            "iwinfo",
            &["", "phy0-ap0 assoclist", "phy0-ap0 info"],
            &["phy0-ap0 scan", "phy0-ap0"],
        ),
        (
            "brctl",
            &["show", "showmacs br-lan"],
            &["delif br-lan lan1", "addbr x", ""],
        ),
        ("netstat", &["", "-lntup", "-rn", "-W -l"], &["-c", "x"]),
        (
            "apk",
            &[
                "--version",
                "--no-network list --upgradable",
                "list --no-network --installed --manifest",
                "--no-network info -L dnsmasq",
                "--no-network search 'luci-app-*'",
                "--no-network query --upgradable --format json --fields name,version '*'",
            ],
            &[
                "list --upgradable",
                "--no-network upgrade",
                "--no-network upgrade --simulate",
                "--no-network add tcpdump",
                "--no-network del tcpdump",
                "update",
                "--no-network fix",
                "--no-network --root /tmp/x list",
                "--no-network -X http://192.0.2.9/x list",
                "--no-network --repositories-file /tmp/r list",
                "--no-network info --who-owns /etc/shadow",
                "--no-network --allow-untrusted list",
                "--no-network list --format json;x",
                "--no-network",
            ],
        ),
        (
            "owut",
            &["--version"],
            &["check", "upgrade", "download", "list", ""],
        ),
        (
            "service",
            &["", "dnsmasq status", "firewall enabled", "cron running"],
            &[
                "network restart",
                "dropbear stop",
                "dnsmasq info",
                "../../sbin/reboot status",
                "a b c",
                "dnsmasq",
            ],
        ),
        (
            "wifi",
            &["status"],
            &["", "down", "reload", "up", "status x"],
        ),
        ("ifstatus", &["wan"], &["", "wan x", "'wan; reboot'"]),
        ("ps", &["", "w", "ww"], &["-o pid,args", "aux", "-ef"]),
        (
            "top",
            &["-bn1", "-b -n 1", "-n1 -b"],
            &["", "-b", "-n 5 -b", "-d 1"],
        ),
        (
            "df",
            &["", "-h", "-P /tmp", "-hT /overlay"],
            &["-x", "tmp", "--output=x"],
        ),
        ("free", &["", "-h", "-m"], &["-s 1", "x"]),
        ("uptime", &[""], &["-s", "x"]),
        (
            "date",
            &["", "-u", "-R", "-Iseconds", "+%s", "-u '+%Y-%m-%d %H:%M'"],
            &[
                "-s '2020-01-01 00:00'",
                "010100002020",
                "-d x",
                "-r /etc/shadow",
                "+%s +%s",
                "--set x",
            ],
        ),
        ("uname", &["", "-a", "-rm"], &["-x", "x"]),
        ("id", &["", "-u", "-un"], &["root", "-x"]),
        ("hostname", &[""], &["evil", "-F /tmp/x", "-i"]),
        ("lsmod", &[""], &["x"]),
        ("pidof", &["dnsmasq"], &["", "a b", "'a;b'"]),
        (
            "pgrep",
            &["dnsmasq", "-l dropbear", "-x netifd"],
            &[
                "-f password",
                "-f 'password a'",
                "-a x",
                "'pass.*'",
                "",
                "-l",
            ],
        ),
        ("mount", &[""], &["-o remount,rw /", "/dev/sda1 /mnt", "-a"]),
        ("block", &["info"], &["mount", "umount", ""]),
        (
            "sysctl",
            &["net.ipv4.ip_forward", "-n kernel.hostname", "-a"],
            &[
                "-w net.ipv4.ip_forward=0",
                "net.ipv4.ip_forward=0",
                "-p",
                "-p /tmp/x",
                "/../../etc/shadow",
                "net/ipv4/ip_forward",
                "",
            ],
        ),
        (
            "ls",
            &[
                "",
                "-la /etc/config",
                "/tmp /root",
                "-d /sys/class/net/*",
                "-ltr /etc/dropbear",
            ],
            &[
                "-R /",
                "tmp",
                "/tmp/sentry-guard-0123456789abcdef",
                "/etc/sentry-guard/0123456789abcdef",
                "/proc/1/root",
                "/proc/self/fd",
                "/tmp/../../x",
                "/tmp -l",
                "--color=always /tmp",
            ],
        ),
        (
            "stat",
            &["/etc/config/wireless", "-L /tmp/x"],
            &["", "-c %n /tmp", "x"],
        ),
        (
            "du",
            &["-sh /overlay", "-d 1 /tmp", "-a /etc/config"],
            &["-s x", "-d x /tmp"],
        ),
        (
            "readlink",
            &["/sys/class/net/br-lan", "-f /etc/localtime"],
            &["", "/proc/1/exe", "a b"],
        ),
        ("which", &["nft", "apk owut"], &["", "'a;b'", "/bin/sh"]),
        (
            "test",
            &["-e /tmp/x", "-d /etc/config", "-s /tmp/dhcp.leases"],
            &[
                "-e",
                "-e x",
                "/tmp/x",
                "-e /tmp/x -a -e /tmp/y",
                "1 -eq 1",
                "-n x",
                "-e /tmp/*",
            ],
        ),
        (
            "find",
            &[
                "/etc -name '*.conf'",
                "/tmp /var -type f -maxdepth 2",
                "/etc/config -mtime -1 -print",
                "/overlay/upper -size +100k -xdev",
            ],
            &[
                "",
                "/",
                "/proc -name x",
                "/sys -name x",
                "/dev",
                "-name x",
                "/tmp -exec ls {} ;",
                "/tmp -exec reboot ;",
                "/tmp -ok rm ;",
                "/tmp -delete",
                "/tmp -fprint /tmp/x",
                "/tmp -fls /tmp/x",
                "/tmp -newer /etc/shadow",
                "/tmp -name",
                "/tmp -type x",
                "/tmp/sentry-guard-0123456789abcdef",
                "/etc/../proc",
                "tmp",
            ],
        ),
        (
            "cat",
            &[
                "/proc/loadavg",
                "/tmp/dhcp.leases /tmp/odhcpd.leases",
                "/proc/net/arp",
                "/proc/sys/kernel/random/boot_id",
                "/proc/1234/stat",
                "/sys/class/net/br-lan/address",
                "/etc/init.d/dnsmasq",
                "/tmp/hosts/odhcpd",
            ],
            &[
                "",
                "-v /proc/loadavg",
                "/etc/shadow",
                "/etc/passwd",
                "/etc/config/wireless",
                "/etc/dropbear/authorized_keys",
                "/etc/uhttpd.key",
                "/root/notes",
                "notes",
                "/dev/mtd0",
                "/dev/null",
                "/dev/mem",
                // Another way to the same files.
                "/rom/etc/shadow",
                "/rom/etc/config/wireless",
                "/overlay/upper/etc/config/network",
                "/proc/1/root/etc/shadow",
                "/proc/self/root/etc/config/wireless",
                "/proc/self/environ",
                "/proc/self/stat",
                "/proc/1/cmdline",
                "/proc/1/environ",
                "/proc/1234/fd/3",
                "/proc/kcore",
                "/proc/kallsyms",
                "/sys/kernel/debug/ieee80211/phy0/keys/0/key",
                "/sys//kernel/debug/ieee80211/phy0/keys/0/key",
                "/sys/class/net/../../kernel/debug/ieee80211/phy0/keys/0/key",
                "/proc/net/../../etc/shadow",
                "/tmp/dhcp.leases/../../etc/shadow",
                "/tmp/sentry-guard-0123456789abcdef/config/wireless",
                "/etc/sentry-guard/0123456789abcdef/config/wireless",
                "/tmp/.uci/wireless",
                "/var/run/hostapd-phy0.conf",
                "/tmp/run/wpa_supplicant-phy0.conf",
                "/etc/apk/keys/x.pem",
            ],
        ),
    ];
    let mut seen: Vec<&str> = Vec::new();
    for (prog, reads, not) in table {
        seen.push(prog);
        for a in *reads {
            let line = format!("{prog} {a}");
            if let Err(e) = plan(&line) {
                panic!("`{line}` should read: {e}");
            }
        }
        for a in *not {
            let line = format!("{prog} {a}");
            if let Ok(p) = plan(&line) {
                panic!("`{line}` shouldn't read: {}", p.shown());
            }
        }
    }
    // Every program on the list has its rows here.
    for p in PROGRAMS {
        assert!(
            seen.contains(p) || matches!(*p, "devstatus" | "whoami" | "realpath"),
            "no rows for `{p}`"
        );
    }
    // The filters' flags.
    for (line, ok) in [
        ("uptime | grep -i up", true),
        ("uptime | grep -ivc -e up -e load", true),
        ("uptime | grep -m 1 -A 2 up", true),
        ("uptime | egrep 'a|b'", true),
        ("uptime | fgrep a.b", true),
        ("uptime | grep -o up", false),
        ("uptime | grep -r up", false),
        ("uptime | grep -f /tmp/p", false),
        ("uptime | grep --only-matching up", false),
        ("uptime | grep -io up", false),
        ("uptime | grep", false),
        ("uptime | head", true),
        ("uptime | head -n 3", true),
        ("uptime | head -3", true),
        ("uptime | head -n -3", true),
        ("uptime | head -c 10", false),
        ("uptime | tail -n +2", true),
        ("uptime | tail -c 40", false),
        ("uptime | tail -f", false),
        ("uptime | tail -5f", false),
        ("uptime | tail --follow", false),
        ("uptime | sort -u", true),
        ("uptime | sort -rn -k 2 -t ,", true),
        ("uptime | sort -o /tmp/x", false),
        ("uptime | sort -uo/etc/passwd", false),
        ("uptime | sort -T /tmp", false),
        ("uptime | sort --output=/tmp/x", false),
        ("uptime | uniq -c", true),
        ("uptime | uniq /tmp/out", false),
        ("uptime | wc -l", true),
        ("uptime | wc --files0-from=x", false),
        ("uptime | cut -d, -f1,3-", true),
        ("uptime | cut -c 1-9", true),
        ("uptime | cut -f1 -c2", false),
        ("uptime | cut -b 1", false),
    ] {
        assert_eq!(plan(line).is_ok(), ok, "{line}: {:?}", shown(line));
    }
    // A cluster is taken apart: what is sent has one flag a word, and `-o` isn't one.
    assert!(plan("sort -uo/etc/passwd /proc/uptime").is_err());
    assert!(plan("sort -u -o /tmp/x /proc/uptime").is_err());
    assert_eq!(sent("sort -ur /proc/uptime"), ["cat '/proc/uptime'"]);
}

#[test]
fn paths_are_made_plain_before_they_are_looked_at() {
    for (path, want) in [
        ("/proc/loadavg", Some("/proc/loadavg")),
        ("/proc//loadavg", Some("/proc/loadavg")),
        ("/proc/./loadavg/", Some("/proc/loadavg")),
        ("//proc///net//arp", Some("/proc/net/arp")),
        ("/proc/net/../loadavg", Some("/proc/loadavg")),
        ("/sys//kernel/debug", Some("/sys/kernel/debug")),
        ("/a/b/../../c", Some("/c")),
        ("/", Some("/")),
        ("/..", None),
        ("/a/../..", None),
        ("/tmp/../../etc/shadow", None),
        ("etc/shadow", None),
        ("./x", None),
        ("", None),
    ] {
        assert_eq!(normal(path).as_deref(), want, "{path}");
    }
    for yes in [
        "/proc/loadavg",
        "/proc/net/arp",
        "/proc/net/stat/nf_conntrack",
        "/proc/sys/net/ipv4/ip_forward",
        "/proc/42/status",
        "/sys/class/net/br-lan/statistics/rx_bytes",
        "/tmp/dhcp.leases",
        "/etc/hosts",
        "/usr/share/libubox/jshn.sh",
    ] {
        assert!(readable_path(yes), "{yes}");
    }
    for no in [
        "/proc",
        "/sys",
        "/proc/1/cmdline",
        "/proc/1/environ",
        "/proc/self/stat",
        "/proc/x/stat",
        "/proc//stat",
        "/proc/kcore",
        "/proc/netx",
        "/sys/kernel/debug",
        "/sys/class",
        "/dev/null",
        "/dev/mtd0",
        "/etc",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/config/network",
        "/rom/etc/hosts",
        "/overlay/upper/etc/hosts",
        "/tmp",
        "/tmp/dhcp.leases.bak",
        "/root",
    ] {
        assert!(!readable_path(no), "{no}");
    }
    // What is sent is the plain path, whatever was written.
    assert_eq!(sent("cat /proc/./net//arp"), ["cat '/proc/net/arp'"]);
}

// ---- the invariant

/// A word, and whether it stood bare (unquoted).
type Seen = (String, bool);

/// A shell's reading of the one shape sentry sends: bare words of harmless characters,
/// single-quoted words (`'\''` for a quote), and the three redirections. None: anything
/// a shell would act on (a `;`, `|`, `&`, `$`, backtick, `<`, a bare quote…). Written
/// apart from the parser above on purpose.
fn reference(line: &str) -> Option<(Vec<Seen>, Vec<String>)> {
    let mut words: Vec<(String, bool)> = Vec::new();
    let mut redirs = Vec::new();
    for raw in split_outside_quotes(line)? {
        if matches!(raw.as_str(), "2>&1" | "2>/dev/null" | ">/dev/null") {
            redirs.push(raw);
            continue;
        }
        let mut word = String::new();
        let mut bare = true;
        let mut cs = raw.chars().peekable();
        while let Some(c) = cs.next() {
            match c {
                '\'' => {
                    bare = false;
                    loop {
                        match cs.next()? {
                            '\'' => break,
                            c => word.push(c),
                        }
                    }
                }
                '\\' => {
                    if cs.next()? != '\'' {
                        return None;
                    }
                    word.push('\'');
                }
                c if c.is_ascii_alphanumeric() || "_./*?-".contains(c) => word.push(c),
                _ => return None,
            }
        }
        words.push((word, bare));
    }
    Some((words, redirs))
}

fn split_outside_quotes(line: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in line.chars() {
        if c == '\'' {
            quoted = !quoted;
        }
        if c == ' ' && !quoted {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if quoted {
        return None;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Some(out)
}

/// The invariant for one read: every line it sends is, to a shell, exactly one simple
/// command, the program from the list, the arguments the classifier saw.
pub(crate) fn holds(line: &str, p: &Plan) {
    for r in p.remotes() {
        let sent = r.line();
        let (words, redirs) =
            reference(&sent).unwrap_or_else(|| panic!("{line:?} sends shell syntax: {sent}"));
        let (prog, args) = words.split_first().expect("a program");
        assert!(prog.1, "{line:?}: the program is quoted in {sent}");
        let init = prog.0.strip_prefix("/etc/init.d/").is_some_and(|n| {
            !n.is_empty()
                && !n.starts_with('.')
                && n.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_.@+-".contains(c))
        });
        assert!(
            PROGRAMS.contains(&prog.0.as_str()) || init,
            "{line:?} runs `{}`: {sent}",
            prog.0
        );
        assert_eq!(prog.0, r.prog);
        assert_eq!(args.len(), r.args.len(), "{line:?}: {sent}");
        for ((text, bare), a) in args.iter().zip(&r.args) {
            match a {
                Out::Lit(t) => assert!(!bare && t == text, "{line:?}: {sent}"),
                Out::Glob(t) => {
                    assert!(*bare && t == text, "{line:?}: {sent}");
                    assert!(
                        GLOB_DIRS.iter().any(|d| t.starts_with(&format!("{d}/")))
                            && !t.split('/').any(|c| c.starts_with('.')),
                        "{line:?} expands {t}"
                    );
                }
            }
        }
        assert_eq!(redirs.len(), r.redirs.len(), "{line:?}: {sent}");
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick<'a>(&mut self, of: &[&'a str]) -> &'a str {
        of[(self.next() % of.len() as u64) as usize]
    }
}

#[test]
fn whatever_is_a_read_sends_only_what_was_understood() {
    const COMMANDS: &[&str] = &[
        "uci show wireless",
        "uci get dropbear.main.Port",
        "ubus call system board",
        "cat /proc/uptime",
        "cat /tmp/dhcp.leases",
        "cat /sys/class/net/*/address",
        "ls -la /tmp",
        "ip addr show",
        "logread -l 5",
        "grep -c x /proc/version",
        "find /tmp -maxdepth 0",
        "sort -u /proc/uptime",
        "echo x",
        "test -e /tmp/x",
        "/etc/init.d/dnsmasq status",
        "service dropbear status",
        "uptime",
        "ps w",
        "reboot",
        "wifi down",
        "uci commit network",
        "rm -rf /",
        "touch /tmp/sentry-canary",
        "sysupgrade -n /tmp/x",
        "cat /etc/shadow",
        "firstboot -y",
        "mtd erase rootfs_data",
        "sh -c reboot",
        "/sbin/reboot",
        "busybox reboot",
        "ifconfig br-lan -arp",
        "kill 1",
    ];
    const BITS: &[&str] = &[
        " ",
        " ",
        " ",
        ";",
        " ; ",
        "|",
        " | ",
        "&&",
        " && ",
        "||",
        "&",
        " & ",
        "$(",
        ")",
        "`",
        "\"",
        "'",
        "\\",
        "#",
        " #",
        "\n",
        ">",
        "<",
        ">>",
        " 2>&1",
        " 2>/dev/null",
        " >/dev/null",
        "$'",
        "{",
        "}",
        "~",
        "*",
        "?",
        "[",
        "]",
        "$X",
        "${x}",
        "=",
        "X=",
        "\\;",
        "{}",
        "-exec",
        "-delete",
        "-o/etc/passwd",
        "-uo/etc/passwd",
        "-f",
        "-c",
        "/etc/shadow",
        "/etc/config/wireless",
        "..",
        "/../",
        "//",
        "/./",
        "\t",
        "$((1))",
        "<<EOF",
        "!",
        "\\'",
        "''",
        "\"\"",
        "%",
        "@",
        ":",
        ",",
        "grep",
        "head",
        "wc -l",
        "cut -c1-9",
        "tr -d :",
        "awk",
        "sed",
        "xargs",
        "eval",
        "exec",
        "env",
        "nohup",
        "/tmp/sentry-canary",
        "-",
        "--",
        "\r",
        "\u{0}",
        "\u{1b}[0m",
    ];
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let (mut reads, mut total) = (0, 0);
    for _ in 0..150_000 {
        let mut line = String::new();
        for _ in 0..(1 + rng.next() % 7) {
            if rng.next().is_multiple_of(3) {
                line.push_str(rng.pick(COMMANDS));
            } else {
                line.push_str(rng.pick(BITS));
            }
            if rng.next().is_multiple_of(4) {
                line.push(' ');
            }
        }
        total += 1;
        let v = crate::policy::verdict(&line);
        let p = plan(&line);
        // The class and the plan agree: a read is exactly what has a plan.
        assert_eq!(
            v.class == crate::policy::Class::Read,
            p.is_ok(),
            "{line:?}: {v:?}"
        );
        if let Ok(p) = p {
            reads += 1;
            holds(&line, &p);
            assert_eq!(v.run.as_deref(), Some(p.shown().as_str()));
        }
    }
    // Not vacuous: thousands of the lines are reads.
    assert!(reads > 3_000 && reads < total / 2, "{reads} of {total}");
}
