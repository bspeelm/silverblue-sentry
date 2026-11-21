//! Which packages are which, and what an upgrade would really do. OpenWrt's packages are
//! built against one firmware release: upgrading the wrong one alone can leave a router
//! that doesn't boot or doesn't answer. So an upgrade is never judged by the names it was
//! asked for: `apk upgrade <names>` takes whatever those depend on along, and the whole
//! transaction (`apk upgrade --simulate`, which changes nothing) is what is looked at.
//! Auto mode confirms an upgrade only when every package in it is on the short list of
//! leaves here; anything else is the user's Enter.

use crate::remote::Router;

/// Packages a router doesn't boot or answer without: upgrading one of these alone, against
/// the firmware it was built with, is the risky kind.
pub fn base_package(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "base-files",
        "busybox",
        "libc",
        "musl",
        "kernel",
        "netifd",
        "procd",
        "firewall",
        "firewall4",
        "dropbear",
        "uci",
        "fstools",
        "fwtool",
        "mtd",
        "apk",
        "opkg",
        "zlib",
        "logd",
        "urngd",
        "getrandom",
        "ubox",
        "jshn",
        "jsonfilter",
        "uhttpd",
        "usign",
        "ucert",
        "openwrt-keyring",
        "wireless-regdb",
        "wifi-scripts",
        "iw",
        "iw-full",
        "iwinfo",
        "ip-tiny",
        "ip-full",
        "swconfig",
        "bridger",
        "uclient-fetch",
        "block-mount",
    ];
    const STARTS: &[&str] = &[
        "kmod-",
        "hostapd",
        "wpad",
        "wpa-supplicant",
        "wpa-cli",
        "dnsmasq",
        "odhcp",
        "ppp",
        "procd-",
        "ubus",
        "rpcd",
        "ucode",
        "apk-",
        "nftables",
        "iptables",
        "ip6tables",
        "xtables",
        "uhttpd-",
        "px5g",
        "libubox",
        "libubus",
        "libuci",
        "libuclient",
        "libucode",
        "libustream",
        "libblobmsg-json",
        "libjson-c",
        "libjson-script",
        "libnl",
        "libnftnl",
        "libmnl",
        "libxtables",
        "libip4tc",
        "libip6tc",
        "libiwinfo",
        "libmbedtls",
        "libopenssl",
        "libwolfssl",
        "libapk",
        "libgcc",
        "libpthread",
        "librt",
        "libatomic",
        "libblkid",
        "libuuid",
        "jansson",
        "ath10k-",
        "ath11k-",
        "ath12k-",
        "ipq-wifi-",
        "brcmfmac-",
        "iwlwifi-",
        "mt76",
    ];
    EXACT.contains(&name) || STARTS.iter().any(|s| name.starts_with(s)) || name.contains("firmware")
}

/// The packages auto mode may see upgraded without asking: the web interface's own pages,
/// translations and themes, and a few tools nothing on the router depends on. A short
/// list on purpose: everything not on it asks.
pub fn leaf_package(name: &str) -> bool {
    const STARTS: &[&str] = &[
        "luci-app-",
        "luci-i18n-",
        "luci-theme-",
        "zoneinfo-",
        "tcpdump",
        "nano",
        "htop",
        "iperf",
        "mtr",
        "bind-dig",
    ];
    const EXACT: &[&str] = &["less", "terminfo", "owut"];
    !base_package(name) && (EXACT.contains(&name) || STARTS.iter().any(|s| name.starts_with(s)))
}

/// A package's name as apk takes it, and nothing a shell would read as anything else.
pub fn package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 80
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+._-".contains(c))
}

/// One package of a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tx {
    /// Upgrading, Installing, Purging, Downgrading, Reinstalling, Replacing.
    pub action: String,
    pub name: String,
    /// `(old -> new)`, `(version)`.
    pub versions: String,
}

impl Tx {
    pub fn line(&self) -> String {
        format!(
            "  {} {} {}{}",
            self.action.to_lowercase(),
            self.name,
            self.versions,
            if base_package(&self.name) {
                "  (base system)"
            } else if leaf_package(&self.name) {
                ""
            } else {
                "  (not on the list auto upgrades by itself)"
            }
        )
    }
}

/// What `apk upgrade --simulate` printed, as its packages: `(3/7) Upgrading name (1.0-r1 ->
/// 1.1-r1)`. Err: it isn't a simulation's output as apk 3 prints it (a line that starts
/// like a step and doesn't read as one, or no closing `OK:`), so nothing can be said of it.
pub fn transaction(text: &str) -> Result<Vec<Tx>, String> {
    let mut out = Vec::new();
    let mut ok = false;
    for l in text.lines().map(str::trim) {
        if l.starts_with("OK:") {
            ok = true;
            continue;
        }
        if !l.starts_with('(') {
            continue;
        }
        let step = l.split_once(") ").and_then(|(n, rest)| {
            let (i, of) = n.trim_start_matches('(').split_once('/')?;
            (i.parse::<u32>().is_ok() && of.parse::<u32>().is_ok()).then_some(rest)
        });
        let parsed = step.and_then(|rest| {
            let mut w = rest.splitn(3, ' ');
            let (action, name) = (w.next()?, w.next()?);
            let known = matches!(
                action,
                "Upgrading"
                    | "Installing"
                    | "Purging"
                    | "Downgrading"
                    | "Reinstalling"
                    | "Replacing"
            );
            (known && package_name(name)).then(|| Tx {
                action: action.to_string(),
                name: name.to_string(),
                versions: w.next().unwrap_or("").to_string(),
            })
        });
        match parsed {
            Some(t) => out.push(t),
            None => {
                return Err(format!(
                    "apk's simulation has a line sentry can't read: {l}"
                ));
            }
        }
    }
    if !ok {
        return Err(text
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("apk said nothing")
            .trim()
            .to_string());
    }
    Ok(out)
}

/// The command a simulation is: nothing is installed, removed or written.
pub fn simulate_line(names: &[&str]) -> String {
    format!("apk upgrade --simulate {}", names.join(" "))
}

/// What upgrading `names` would do, all of it: the packages named and whatever they take
/// along. Reads only (apk may refresh its index in memory first, as any apk command does).
pub fn simulate(r: &Router, names: &[&str]) -> Result<Vec<Tx>, String> {
    if names.is_empty() {
        return Err("no package named: sentry never upgrades every package at once".into());
    }
    if let Some(bad) = names.iter().find(|n| !package_name(n)) {
        return Err(format!("`{bad}` isn't a package's name"));
    }
    let o = r
        .sh(&simulate_line(names))
        .timeout(Some(std::time::Duration::from_secs(120)))
        .run()
        .map_err(|e| e.to_string())?;
    if o.code != 0 {
        return Err(format!(
            "apk couldn't work the upgrade out: {}",
            o.stderr
                .lines()
                .chain(o.stdout.lines())
                .rfind(|l| !l.trim().is_empty())
                .unwrap_or("(it said nothing)")
                .trim()
        ));
    }
    transaction(&o.stdout)
}

/// Every package of the transaction is a leaf, and there is one: what auto may confirm.
pub fn all_leaves(tx: &[Tx]) -> bool {
    !tx.is_empty() && tx.iter().all(|t| leaf_package(&t.name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_packages_leaves_and_names() {
        for b in [
            "base-files",
            "busybox",
            "libc",
            "netifd",
            "procd",
            "firewall4",
            "dnsmasq",
            "dnsmasq-full",
            "dropbear",
            "hostapd-common",
            "wpad-basic-mbedtls",
            "kmod-mt7915e",
            "kernel",
            "libubox20240329",
            "uci",
            // The safety review's list (2026-11): what `apk upgrade <leaf>` can pull along.
            "ucode",
            "ucode-mod-fs",
            "libucode20230711",
            "libnl-tiny1",
            "libblobmsg-json20260213",
            "libjson-c5",
            "jsonfilter",
            "jshn",
            "ubox",
            "libmbedtls21",
            "libustream-mbedtls20201210",
            "libmnl0",
            "jansson4",
            "ppp",
            "ppp-mod-pppoe",
            "mt7981-wo-firmware",
            "mt7986-wo-firmware",
            "wireless-regdb",
            "libiwinfo20230701",
            "libiwinfo-data",
            "uhttpd",
            "uhttpd-mod-ubus",
            "rpcd",
            "rpcd-mod-file",
            "ubus",
            "ubusd",
            "odhcpd-ipv6only",
            "odhcp6c",
            "nftables-json",
            "apk-mbedtls",
            "iw",
            "wifi-scripts",
        ] {
            assert!(base_package(b) && !leaf_package(b), "{b}");
        }
        for leaf in [
            "luci-app-firewall",
            "luci-app-attendedsysupgrade",
            "luci-i18n-base-de",
            "luci-theme-bootstrap",
            "tcpdump",
            "tcpdump-mini",
            "nano",
            "htop",
            "owut",
        ] {
            assert!(leaf_package(leaf) && !base_package(leaf), "{leaf}");
        }
        // Neither: not the base system, and not something auto upgrades by itself.
        for other in [
            "adblock-fast",
            "curl",
            "luci",
            "luci-base",
            "luci-mod-admin-full",
            "luci-proto-ppp",
            "ca-bundle",
            "cgi-io",
            "https-dns-proxy",
            "libpcap1",
            "crowdsec-firewall-bouncer",
        ] {
            assert!(!leaf_package(other) && !base_package(other), "{other}");
        }
        for ok in [
            "tcpdump",
            "luci-app-firewall",
            "libstdcpp6",
            "kmod-mt7915e",
            "a.b+c_d",
        ] {
            assert!(package_name(ok), "{ok}");
        }
        for bad in [
            "",
            "-x",
            "a;reboot",
            "a b",
            "$(reboot)",
            "a|b",
            "--force",
            "a'b",
            "a/b",
            "*",
        ] {
            assert!(!package_name(bad), "{bad}");
        }
    }

    #[test]
    fn a_simulation_is_read_as_its_whole_transaction() {
        // As apk-tools 3.0.5 prints it (the disposable router, 2026-11-21).
        let one = "(1/1) Upgrading ca-bundle (20260601-r1 -> 20260816-r2)\nOK: 11.4 MiB in 136 packages\n";
        assert_eq!(
            transaction(one).unwrap(),
            [Tx {
                action: "Upgrading".into(),
                name: "ca-bundle".into(),
                versions: "(20260601-r1 -> 20260816-r2)".into()
            }]
        );
        // A leaf asked for, and what it takes along.
        let pulled = "(1/3) Upgrading libubox20240329 (2026.06.19~7dd12784-r1 -> 2026.11.02~ff13b89e-r1)\n(2/3) Installing libfoo1 (1.0-r1)\n(3/3) Upgrading luci-app-firewall (26.100-r1 -> 26.300-r1)\nOK: 11.4 MiB in 137 packages\n";
        let tx = transaction(pulled).unwrap();
        assert_eq!(tx.len(), 3);
        assert!(!all_leaves(&tx), "a base library rides along");
        assert!(tx[0].line().ends_with("(base system)"), "{}", tx[0].line());
        assert!(tx[1].line().contains("not on the list"), "{}", tx[1].line());
        assert_eq!(
            tx[2].line(),
            "  upgrading luci-app-firewall (26.100-r1 -> 26.300-r1)"
        );
        let leaves = "(1/2) Upgrading luci-app-firewall (1 -> 2)\n(2/2) Upgrading luci-i18n-firewall-de (1 -> 2)\nOK: 1 MiB in 2 packages\n";
        assert!(all_leaves(&transaction(leaves).unwrap()));
        // Nothing to do isn't something to confirm unasked.
        let none = transaction("OK: 11.4 MiB in 136 packages\n").unwrap();
        assert!(none.is_empty() && !all_leaves(&none));
        // What can't be read says nothing, least of all "only leaves".
        for bad in [
            "",
            "ERROR: unable to select packages:\n  nosuch (no such package)\n",
            "(1/1) Frobnicating luci-app-x (1 -> 2)\nOK: 1 MiB\n",
            "(1/1) Upgrading luci-app-x;reboot (1 -> 2)\nOK: 1 MiB\n",
            "(1/1) Upgrading luci-app-x (1 -> 2)\n",
            "(x/1) Upgrading luci-app-x (1 -> 2)\nOK: 1 MiB\n",
        ] {
            assert!(transaction(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            simulate_line(&["luci-app-firewall", "nano"]),
            "apk upgrade --simulate luci-app-firewall nano"
        );
    }
}
