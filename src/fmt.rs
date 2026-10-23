//! Human-readable formatting shared by the CLI and the TUI.

const KIB: f64 = 1024.0;

/// `612 MiB`, `1.8 GiB`, `412 KiB`.
pub fn bytes(n: u64) -> String {
    let n = n as f64;
    let (v, unit) = if n >= KIB.powi(4) {
        (n / KIB.powi(4), "TiB")
    } else if n >= KIB.powi(3) {
        (n / KIB.powi(3), "GiB")
    } else if n >= KIB.powi(2) {
        (n / KIB.powi(2), "MiB")
    } else if n >= KIB {
        (n / KIB, "KiB")
    } else {
        return format!("{n} B");
    };
    if v >= 100.0 {
        format!("{v:.0} {unit}")
    } else {
        format!("{v:.1} {unit}")
    }
}

/// Compact form for tight columns: `22.1G`, `412M`.
pub fn bytes_short(n: u64) -> String {
    bytes(n)
        .replace(" GiB", "G")
        .replace(" MiB", "M")
        .replace(" KiB", "K")
        .replace(" TiB", "T")
}

pub fn gib(n: u64) -> f64 {
    n as f64 / KIB.powi(3)
}

/// Rate in bytes/s: `3.1 MB/s`, `412 KB/s`.
pub fn rate(bps: f64) -> String {
    if bps >= 1e6 {
        format!("{:.1} MB/s", bps / 1e6)
    } else if bps >= 1e3 {
        format!("{:.0} KB/s", bps / 1e3)
    } else {
        format!("{bps:.0} B/s")
    }
}

/// Coarse age: `just now`, `14m`, `3h`, `2d`.
pub fn age(secs: i64) -> String {
    let s = secs.max(0);
    match s {
        0..60 => "just now".into(),
        60..3600 => format!("{}m", s / 60),
        3600..86400 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86400),
    }
}

/// `2d ago` / `just now`.
pub fn ago(secs: i64) -> String {
    match age(secs).as_str() {
        "just now" => "just now".into(),
        a => format!("{a} ago"),
    }
}

/// Uptime like the mockup: `3d 04:12`.
pub fn uptime(secs: u64) -> String {
    format!(
        "{}d {:02}:{:02}",
        secs / 86400,
        (secs % 86400) / 3600,
        (secs % 3600) / 60
    )
}

/// Process CPU time: `2:14:08`.
pub fn hms(secs: u64) -> String {
    format!("{}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(bytes(612 * 1024 * 1024), "612 MiB");
        assert_eq!(bytes(1932735283), "1.8 GiB");
        assert_eq!(bytes_short(23729694310), "22.1G");
        assert_eq!(age(30), "just now");
        assert_eq!(ago(2 * 86400 + 5), "2d ago");
        assert_eq!(uptime(3 * 86400 + 4 * 3600 + 12 * 60), "3d 04:12");
        assert_eq!(hms(8048), "2:14:08");
        assert_eq!(rate(3_100_000.0), "3.1 MB/s");
    }
}
