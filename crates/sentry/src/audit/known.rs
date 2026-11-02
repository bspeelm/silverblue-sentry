//! Well-known listening services and how far an address reaches, so findings and the Network
//! screen can say "mDNS (Avahi), reachable on your LAN" instead of `0.0.0.0:5353 (?)`.

pub struct Service {
    pub name: &'static str,
    /// One sentence: what it is.
    pub what: &'static str,
    /// Stock on a Fedora desktop (low severity when exposed).
    pub normal: bool,
    /// Remote access to this machine (medium when open to every network).
    pub remote_access: bool,
    /// What to do about it.
    pub advice: &'static str,
}

const MDNS: Service = Service {
    name: "mDNS (Avahi)",
    what: "Announces and discovers devices on the local network: printers, Chromecasts, file shares.",
    normal: true,
    remote_access: false,
    advice: "Normal on Fedora. Keep it if you print or cast; otherwise `sudo systemctl disable --now avahi-daemon.socket avahi-daemon.service`.",
};
const LLMNR: Service = Service {
    name: "LLMNR (systemd-resolved)",
    what: "Answers Windows-style name lookups for this machine on the local network.",
    normal: true,
    remote_access: false,
    advice: "Rarely needed. To turn it off: put `[Resolve]` and `LLMNR=no` in /etc/systemd/resolved.conf.d/no-llmnr.conf, then `sudo systemctl restart systemd-resolved`.",
};
const DHCP6: Service = Service {
    name: "DHCPv6 client (NetworkManager)",
    what: "Receives this machine's IPv6 address from your router.",
    normal: true,
    remote_access: false,
    advice: "Needed for IPv6. Nothing to do.",
};
const WSDD: Service = Service {
    name: "WS-Discovery (wsdd)",
    what: "Makes this computer show up in Windows' Network view (installed with GNOME file sharing / Samba).",
    normal: true,
    remote_access: false,
    advice: "Keep it if Windows machines browse your shares; otherwise `sudo systemctl disable --now wsdd`.",
};
const SSH: Service = Service {
    name: "SSH server",
    what: "Remote shell logins to this machine.",
    normal: false,
    remote_access: true,
    advice: "Expected if you log in remotely; then use keys, not passwords. Otherwise `sudo systemctl disable --now sshd`.",
};
const CUPS: Service = Service {
    name: "CUPS (printing)",
    what: "The print service.",
    normal: true,
    remote_access: false,
    advice: "Fine on loopback. Open to the network only if you share a printer.",
};
const KDECONNECT: Service = Service {
    name: "KDE Connect / GSConnect",
    what: "Pairs your phone with this desktop.",
    normal: false,
    remote_access: false,
    advice: "Expected if you use phone pairing; otherwise remove the extension or app.",
};
const SYNCTHING: Service = Service {
    name: "Syncthing",
    what: "Peer-to-peer file sync.",
    normal: false,
    remote_access: false,
    advice: "Expected if you run Syncthing.",
};
const SYNCTHING_UI: Service = Service {
    name: "Syncthing web UI",
    what: "Syncthing's control page.",
    normal: false,
    remote_access: true,
    advice: "Should listen on 127.0.0.1 only; if not, set the GUI listen address to 127.0.0.1:8384.",
};
const STEAM: Service = Service {
    name: "Steam Remote Play / LAN transfer",
    what: "Steam streaming and local game transfers.",
    normal: false,
    remote_access: false,
    advice: "Expected while Steam runs with Remote Play or LAN transfers enabled.",
};
const RDP: Service = Service {
    name: "RDP (remote desktop)",
    what: "Remote desktop access to this machine.",
    normal: false,
    remote_access: true,
    advice: "Expected only if you enabled Remote Desktop in Settings → System; otherwise turn it off there.",
};
const VNC: Service = Service {
    name: "VNC (remote desktop)",
    what: "Remote desktop access to this machine.",
    normal: false,
    remote_access: true,
    advice: "Expected only if you enabled screen sharing; otherwise turn it off in Settings.",
};
const SAMBA: Service = Service {
    name: "Samba file sharing",
    what: "Windows-style file shares from this machine.",
    normal: false,
    remote_access: true,
    advice: "Expected if you share folders; otherwise `sudo systemctl disable --now smb nmb`.",
};
const RPCBIND: Service = Service {
    name: "rpcbind (NFS)",
    what: "Port mapper for NFS.",
    normal: false,
    remote_access: true,
    advice: "Only needed for NFS; otherwise `sudo systemctl disable --now rpcbind.socket rpcbind`.",
};

const PASSIM: Service = Service {
    name: "passim (fwupd firmware cache)",
    what: "Fedora's local cache server for firmware files: fwupd starts it so machines on your LAN can share firmware downloads.",
    normal: true,
    remote_access: false,
    advice: "Harmless and read-only, but it advertises itself on the network. To stop sharing (fwupd still works): `sudo systemctl mask --now passim.service`.",
};

pub fn service(proto: &str, port: u16) -> Option<&'static Service> {
    let udp = proto.starts_with("udp");
    Some(match port {
        5353 if udp => &MDNS,
        5355 => &LLMNR,
        546 if udp => &DHCP6,
        3702 if udp => &WSDD,
        5357 if !udp => &WSDD,
        22 if !udp => &SSH,
        631 => &CUPS,
        1714..=1764 => &KDECONNECT,
        22000 | 21027 => &SYNCTHING,
        8384 if !udp => &SYNCTHING_UI,
        27031..=27036 => &STEAM,
        3389 => &RDP,
        5900..=5903 if !udp => &VNC,
        137..=139 | 445 => &SAMBA,
        111 => &RPCBIND,
        27500 if !udp => &PASSIM,
        _ => return None,
    })
}

/// How far an address reaches, in words.
pub fn scope(addr: &str) -> String {
    let (ip, iface) = match addr.split_once('%') {
        Some((a, i)) => (a, Some(i)),
        None => (addr, None),
    };
    let ip = ip.trim_start_matches('[').trim_end_matches(']');
    let vpn = |i: &str| {
        ["wg", "tun", "tap", "proton", "mullvad", "nordlynx"]
            .iter()
            .any(|p| i.starts_with(p))
            || i.contains("-wg-")
    };
    match (ip, iface) {
        ("0.0.0.0" | "::" | "*", _) => "every network you're connected to".into(),
        (_, Some(i)) if vpn(i) => format!("the VPN ({i})"),
        (a, Some(i)) if a.to_ascii_lowercase().starts_with("fe80") => {
            format!("the local link on {i} only")
        }
        (a, _) if a.starts_with("10.") || a.starts_with("100.64.") => {
            format!("a private network ({a}; often a VPN or container bridge)")
        }
        (a, _) if a.starts_with("192.168.") || a.starts_with("172.") => {
            format!("your LAN ({a})")
        }
        (a, _) => format!("networks reaching {a}"),
    }
}

/// `addr:port/process` → (addr, port, process).
pub fn split_key(key: &str) -> (&str, u16, &str) {
    let (addr_port, proc_) = key.rsplit_once('/').unwrap_or((key, "?"));
    let (addr, port) = addr_port.rsplit_once(':').unwrap_or((addr_port, "0"));
    (addr, port.parse().unwrap_or(0), proc_)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_by_port() {
        assert_eq!(service("udp", 5353).unwrap().name, "mDNS (Avahi)");
        assert!(service("tcp", 5353).is_none());
        assert_eq!(
            service("tcp", 5355).unwrap().name,
            "LLMNR (systemd-resolved)"
        );
        assert!(service("tcp", 22).unwrap().remote_access);
        assert_eq!(
            service("tcp", 27500).unwrap().name,
            "passim (fwupd firmware cache)"
        );
        assert!(service("tcp", 27501).is_none());
    }

    #[test]
    fn scopes() {
        assert_eq!(scope("0.0.0.0"), "every network you're connected to");
        assert_eq!(scope("[::]"), "every network you're connected to");
        assert_eq!(scope("192.168.1.180"), "your LAN (192.168.1.180)");
        assert_eq!(scope("[fe80::1]%enp4s0"), "the local link on enp4s0 only");
        assert_eq!(scope("[fe80::1]%us-qas-wg-101"), "the VPN (us-qas-wg-101)");
        assert!(scope("10.68.1.2").starts_with("a private network"));
        assert_eq!(
            split_key("[fe80::1]%enp4s0:546/?"),
            ("[fe80::1]%enp4s0", 546, "?")
        );
    }
}
