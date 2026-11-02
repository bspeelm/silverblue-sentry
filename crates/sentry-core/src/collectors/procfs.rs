//! Pure parsers for `/proc` files, used on this machine and on a server's output.

pub fn meminfo_kib(meminfo: &str, key: &str) -> u64 {
    meminfo
        .lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

pub fn swap_kind(proc_swaps: &str) -> String {
    let devs: Vec<&str> = proc_swaps
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    match devs.as_slice() {
        [] => "none".into(),
        d if d.iter().all(|d| d.starts_with("/dev/zram")) => "zram".into(),
        _ => "file".into(),
    }
}

/// Interface of the default IPv4 route, from /proc/net/route.
pub fn default_iface() -> Option<String> {
    parse_default_iface(&std::fs::read_to_string("/proc/net/route").ok()?)
}

pub fn parse_default_iface(route: &str) -> Option<String> {
    route.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() > 2 && f[1] == "00000000").then(|| f[0].to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_parsers() {
        assert_eq!(
            meminfo_kib("MemTotal: 10 kB\nCached:   6400 kB\n", "Cached:"),
            6400
        );
        assert_eq!(
            swap_kind("Filename Type\n/dev/zram0 partition 8388604 0 100\n"),
            "zram"
        );
        assert_eq!(swap_kind("Filename Type\n"), "none");
        let route = "Iface\tDestination\tGateway\nwlp0s20f3\t0000A8C0\t00000000\nenp6s0\t00000000\t0101A8C0\n";
        assert_eq!(parse_default_iface(route).as_deref(), Some("enp6s0"));
    }
}
