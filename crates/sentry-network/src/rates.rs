//! How fast each port moves data: `Δbytes · 8 / Δuptime`, both from the router (its counters,
//! its clock), so a slow or jittery ssh round trip doesn't bend the number. No rate on the
//! first sample, across a reboot (a new boot id), when the clock didn't advance, or for a
//! port whose counter went back (a reset): those draw `–`.

use std::collections::HashMap;

use crate::collect::probe::Probe;

/// Bits per second, in and out.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rate {
    pub rx: f64,
    pub tx: f64,
}

impl Rate {
    pub fn total(self) -> f64 {
        self.rx + self.tx
    }
}

#[derive(Debug, Default)]
pub struct Rates {
    prev: Option<Prev>,
}

#[derive(Debug)]
struct Prev {
    boot: String,
    uptime: f64,
    bytes: HashMap<String, (u64, u64)>,
}

impl Rates {
    /// The rates between the sample before and this one, by port. A port with no rate isn't
    /// in the answer.
    pub fn feed(&mut self, p: &Probe) -> HashMap<String, Rate> {
        let now = Prev {
            boot: p.host.boot_id.clone(),
            uptime: p.uptime,
            bytes: p
                .ports
                .iter()
                .map(|x| (x.name.clone(), (x.rx_bytes, x.tx_bytes)))
                .collect(),
        };
        let mut out = HashMap::new();
        if let Some(prev) = &self.prev
            && prev.boot == now.boot
            && now.uptime > prev.uptime
        {
            let dt = now.uptime - prev.uptime;
            for (name, (rx, tx)) in &now.bytes {
                let Some((prx, ptx)) = prev.bytes.get(name) else {
                    continue;
                };
                if rx < prx || tx < ptx {
                    continue;
                }
                out.insert(
                    name.clone(),
                    Rate {
                        rx: (rx - prx) as f64 * 8.0 / dt,
                        tx: (tx - ptx) as f64 * 8.0 / dt,
                    },
                );
            }
        }
        self.prev = Some(now);
        out
    }
}

/// A rate in bits per second: `940 Mbit/s`, `12.3 Mbit/s`, `412 kbit/s`, `0 bit/s`.
pub fn bits(bps: f64) -> String {
    if bps >= 1e9 {
        format!("{:.2} Gbit/s", bps / 1e9)
    } else if bps >= 1e8 {
        format!("{:.0} Mbit/s", bps / 1e6)
    } else if bps >= 1e6 {
        format!("{:.1} Mbit/s", bps / 1e6)
    } else if bps >= 1e3 {
        format!("{:.0} kbit/s", bps / 1e3)
    } else {
        format!("{bps:.0} bit/s")
    }
}

/// A link speed in Mbit/s as it's said: `2.5G`, `1G`, `100M`.
pub fn speed(mbit: u32) -> String {
    match mbit {
        m if m >= 1000 && m.is_multiple_of(1000) => format!("{}G", m / 1000),
        m if m >= 1000 => format!("{:.1}G", m as f64 / 1000.0),
        m => format!("{m}M"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::probe::Port;

    fn sample(boot: &str, uptime: f64, ports: &[(&str, u64, u64)]) -> Probe {
        let mut p = Probe {
            uptime,
            ports: ports
                .iter()
                .map(|(n, rx, tx)| Port {
                    name: n.to_string(),
                    carrier: Some(true),
                    speed: Some(1000),
                    rx_bytes: *rx,
                    tx_bytes: *tx,
                })
                .collect(),
            ..Default::default()
        };
        p.host.boot_id = boot.into();
        p
    }

    /// What each pair of samples gives for `wan`: the table the Dashboard's `–` follows.
    #[test]
    fn rate_table() {
        struct Case {
            what: &'static str,
            before: Option<Probe>,
            now: Probe,
            want: Option<(f64, f64)>,
        }
        let a = || sample("boot-a", 100.0, &[("wan", 1_000_000, 500_000)]);
        let cases = [
            Case {
                what: "the first sample has nothing to compare with",
                before: None,
                now: a(),
                want: None,
            },
            Case {
                what: "one second on: bytes times eight",
                before: Some(a()),
                now: sample("boot-a", 101.0, &[("wan", 1_125_000, 500_250)]),
                want: Some((1_000_000.0, 2_000.0)),
            },
            Case {
                what: "the router's clock is what divides, to the hundredth",
                before: Some(a()),
                now: sample("boot-a", 102.5, &[("wan", 1_312_500, 500_000)]),
                want: Some((1_000_000.0, 0.0)),
            },
            Case {
                what: "a counter that went back was reset: no rate",
                before: Some(a()),
                now: sample("boot-a", 101.0, &[("wan", 900, 500_250)]),
                want: None,
            },
            Case {
                what: "a new boot id: the counters are another boot's",
                before: Some(a()),
                now: sample("boot-b", 12.0, &[("wan", 2_000_000, 900_000)]),
                want: None,
            },
            Case {
                what: "a new boot id even when everything grew",
                before: Some(a()),
                now: sample("boot-b", 101.0, &[("wan", 2_000_000, 900_000)]),
                want: None,
            },
            Case {
                what: "a clock that didn't advance divides by nothing",
                before: Some(a()),
                now: sample("boot-a", 100.0, &[("wan", 1_125_000, 500_250)]),
                want: None,
            },
            Case {
                what: "a port that wasn't there before has no rate yet",
                before: Some(sample("boot-a", 100.0, &[("lan1", 5, 5)])),
                now: sample("boot-a", 101.0, &[("wan", 1_125_000, 500_250)]),
                want: None,
            },
        ];
        for c in cases {
            let mut r = Rates::default();
            if let Some(b) = &c.before {
                assert!(r.feed(b).is_empty(), "{}", c.what);
            }
            let got = r.feed(&c.now).get("wan").map(|x| (x.rx, x.tx));
            assert_eq!(got, c.want, "{}", c.what);
        }
    }

    #[test]
    fn each_port_stands_alone_and_the_next_sample_recovers() {
        let mut r = Rates::default();
        r.feed(&sample(
            "b",
            10.0,
            &[("wan", 1000, 1000), ("lan1", 1000, 1000)],
        ));
        // lan1's counter was reset; wan carries on.
        let got = r.feed(&sample("b", 11.0, &[("wan", 2000, 1000), ("lan1", 10, 10)]));
        assert_eq!(got.get("wan").map(|x| x.rx), Some(8000.0));
        assert!(!got.contains_key("lan1"));
        // From the reset on, lan1 has a rate again.
        let got = r.feed(&sample(
            "b",
            12.0,
            &[("wan", 2000, 1000), ("lan1", 135, 10)],
        ));
        assert_eq!(
            got["lan1"],
            Rate {
                rx: 1000.0,
                tx: 0.0
            }
        );
        assert_eq!(got["wan"].total(), 0.0);
        // After a reboot the first sample is a first sample; the second has rates.
        assert!(r.feed(&sample("c", 3.0, &[("wan", 50, 50)])).is_empty());
        assert_eq!(
            r.feed(&sample("c", 4.0, &[("wan", 175, 50)]))["wan"].rx,
            1000.0
        );
    }

    #[test]
    fn rates_and_speeds_as_said() {
        assert_eq!(bits(0.0), "0 bit/s");
        assert_eq!(bits(999.0), "999 bit/s");
        assert_eq!(bits(412_000.0), "412 kbit/s");
        assert_eq!(bits(12_340_000.0), "12.3 Mbit/s");
        assert_eq!(bits(940_000_000.0), "940 Mbit/s");
        assert_eq!(bits(2_350_000_000.0), "2.35 Gbit/s");
        assert_eq!(
            [
                speed(10),
                speed(100),
                speed(1000),
                speed(2500),
                speed(10000)
            ],
            ["10M", "100M", "1G", "2.5G", "10G"]
        );
    }
}
