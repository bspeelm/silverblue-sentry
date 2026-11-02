//! `metrics/ring.bin`: a fixed-size ring of fixed-size records, so the file never grows past
//! `capacity × 128` bytes and a reader can parse it without an index.
//!
//! Header (64 bytes, little endian): magic `SNTYREC1`, version u32, record size u32,
//! capacity u64, records written u64 (slot = n % capacity), interval seconds u32, zero pad.
//! Record (128 bytes): ts i64, then f32s cpu %, mem used GiB, swap used GiB, rx B/s, tx B/s,
//! load1, cpu °C, gpu %, gpu °C, `/` used %; then 3 × (name [u8;16], cpu f32); zero pad.
//! Missing values are NaN.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const MAGIC: &[u8; 8] = b"SNTYREC1";
pub const VERSION: u32 = 1;
pub const HEADER: usize = 64;
pub const REC: usize = 128;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Rec {
    pub ts: i64,
    pub cpu: f32,
    pub mem_gib: f32,
    pub swap_gib: f32,
    pub rx: f32,
    pub tx: f32,
    pub load1: f32,
    pub cpu_temp: f32,
    pub gpu: f32,
    pub gpu_temp: f32,
    pub disk_pct: f32,
    pub top: Vec<(String, f32)>,
}

impl Rec {
    pub fn encode(&self) -> [u8; REC] {
        let mut b = [0u8; REC];
        b[0..8].copy_from_slice(&self.ts.to_le_bytes());
        let fs = [
            self.cpu,
            self.mem_gib,
            self.swap_gib,
            self.rx,
            self.tx,
            self.load1,
            self.cpu_temp,
            self.gpu,
            self.gpu_temp,
            self.disk_pct,
        ];
        for (i, v) in fs.iter().enumerate() {
            b[8 + i * 4..12 + i * 4].copy_from_slice(&v.to_le_bytes());
        }
        for (i, (name, cpu)) in self.top.iter().take(3).enumerate() {
            let o = 48 + i * 20;
            let n = name.as_bytes();
            let len = n.len().min(16);
            b[o..o + len].copy_from_slice(&n[..len]);
            b[o + 16..o + 20].copy_from_slice(&cpu.to_le_bytes());
        }
        b
    }

    pub fn decode_metrics(b: &[u8]) -> Self {
        let f = |i: usize| f32::from_le_bytes(b[8 + i * 4..12 + i * 4].try_into().unwrap());
        Self {
            ts: i64::from_le_bytes(b[0..8].try_into().unwrap()),
            cpu: f(0),
            mem_gib: f(1),
            swap_gib: f(2),
            rx: f(3),
            tx: f(4),
            load1: f(5),
            cpu_temp: f(6),
            gpu: f(7),
            gpu_temp: f(8),
            disk_pct: f(9),
            top: Vec::new(),
        }
    }

    pub fn decode(b: &[u8]) -> Self {
        let f = |i: usize| f32::from_le_bytes(b[8 + i * 4..12 + i * 4].try_into().unwrap());
        let top = (0..3)
            .filter_map(|i| {
                let o = 48 + i * 20;
                let raw = &b[o..o + 16];
                let end = raw.iter().position(|c| *c == 0).unwrap_or(16);
                let name = String::from_utf8_lossy(&raw[..end]).into_owned();
                (!name.is_empty()).then(|| {
                    (
                        name,
                        f32::from_le_bytes(b[o + 16..o + 20].try_into().unwrap()),
                    )
                })
            })
            .collect();
        Self {
            ts: i64::from_le_bytes(b[0..8].try_into().unwrap()),
            cpu: f(0),
            mem_gib: f(1),
            swap_gib: f(2),
            rx: f(3),
            tx: f(4),
            load1: f(5),
            cpu_temp: f(6),
            gpu: f(7),
            gpu_temp: f(8),
            disk_pct: f(9),
            top,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Header {
    pub capacity: u64,
    pub written: u64,
    pub interval_s: u32,
}

impl Header {
    fn encode(&self) -> [u8; HEADER] {
        let mut b = [0u8; HEADER];
        b[0..8].copy_from_slice(MAGIC);
        b[8..12].copy_from_slice(&VERSION.to_le_bytes());
        b[12..16].copy_from_slice(&(REC as u32).to_le_bytes());
        b[16..24].copy_from_slice(&self.capacity.to_le_bytes());
        b[24..32].copy_from_slice(&self.written.to_le_bytes());
        b[32..36].copy_from_slice(&self.interval_s.to_le_bytes());
        b
    }

    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < HEADER || &b[0..8] != MAGIC {
            return None;
        }
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        if u32_at(8) != VERSION || u32_at(12) as usize != REC || u64_at(16) == 0 {
            return None;
        }
        Some(Self {
            capacity: u64_at(16),
            written: u64_at(24),
            interval_s: u32_at(32),
        })
    }
}

pub fn dir() -> PathBuf {
    crate::paths::data_dir().join("metrics")
}

pub fn path() -> PathBuf {
    dir().join("ring.bin")
}

/// Records the ring holds: `retention_hours` at `interval`, capped by `max_mb`.
pub fn capacity(retention_hours: u32, interval_s: u32, max_mb: u32) -> u64 {
    let by_time = retention_hours as u64 * 3600 / interval_s.max(1) as u64;
    let by_size = (max_mb as u64 * 1024 * 1024).saturating_sub(HEADER as u64) / REC as u64;
    by_time.min(by_size).max(1)
}

pub struct Writer {
    f: File,
    h: Header,
}

impl Writer {
    /// Open (or create) the ring. An incompatible file (other format, capacity or interval)
    /// is moved aside to `ring.bin.old` rather than overwritten in place.
    pub fn open(p: &Path, capacity: u64, interval_s: u32) -> std::io::Result<Self> {
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        let existing = std::fs::read(p).ok().and_then(|b| Header::decode(&b));
        match existing {
            Some(h) if h.capacity == capacity && h.interval_s == interval_s => {
                let f = OpenOptions::new().read(true).write(true).open(p)?;
                Ok(Self { f, h })
            }
            other => {
                if other.is_some() || p.exists() {
                    let _ = std::fs::rename(p, p.with_extension("bin.old"));
                }
                let mut f = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(p)?;
                let h = Header {
                    capacity,
                    written: 0,
                    interval_s,
                };
                f.write_all(&h.encode())?;
                f.set_len(HEADER as u64 + capacity * REC as u64)?;
                Ok(Self { f, h })
            }
        }
    }

    pub fn push(&mut self, r: &Rec) -> std::io::Result<()> {
        let slot = self.h.written % self.h.capacity;
        self.f
            .seek(SeekFrom::Start(HEADER as u64 + slot * REC as u64))?;
        self.f.write_all(&r.encode())?;
        // Record first, header second: a reader never sees a count ahead of the data.
        self.h.written += 1;
        self.f.seek(SeekFrom::Start(0))?;
        self.f.write_all(&self.h.encode())?;
        Ok(())
    }
}

/// All records, oldest first, plus the header.
#[cfg(test)]
pub fn read(p: &Path) -> Option<(Header, Vec<Rec>)> {
    read_with(p, true)
}

/// Like `read`, skipping the top-process names (the History screen's graphs don't need them,
/// and 70k records × 3 strings is most of the parse cost).
pub fn read_metrics(p: &Path) -> Option<(Header, Vec<Rec>)> {
    read_with(p, false)
}

fn read_with(p: &Path, top: bool) -> Option<(Header, Vec<Rec>)> {
    let mut b = Vec::new();
    File::open(p).ok()?.read_to_end(&mut b).ok()?;
    let h = Header::decode(&b)?;
    let n = h.written.min(h.capacity);
    let first = if h.written > h.capacity {
        h.written % h.capacity
    } else {
        0
    };
    let mut v = Vec::with_capacity(n as usize);
    for k in 0..n {
        let slot = (first + k) % h.capacity;
        let o = HEADER + slot as usize * REC;
        if o + REC > b.len() {
            break;
        }
        let mut r = Rec::decode_metrics(&b[o..o + REC]);
        if top {
            r.top = Rec::decode(&b[o..o + REC]).top;
        }
        if r.ts > 0 {
            v.push(r);
        }
    }
    Some((h, v))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(ts: i64) -> Rec {
        Rec {
            ts,
            cpu: ts as f32,
            gpu: f32::NAN,
            top: vec![
                ("firefox".into(), 12.5),
                ("a-very-long-process-name".into(), 1.0),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn roundtrip_and_wraparound() {
        let d = std::env::temp_dir().join(format!("sentry-ring-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let p = d.join("ring.bin");
        let mut w = Writer::open(&p, 4, 10).unwrap();
        for ts in 1..=6 {
            w.push(&rec(ts)).unwrap();
        }
        assert_eq!(
            std::fs::metadata(&p).unwrap().len(),
            (HEADER + 4 * REC) as u64
        );
        let (h, v) = read(&p).unwrap();
        assert_eq!(h.written, 6);
        assert_eq!(v.iter().map(|r| r.ts).collect::<Vec<_>>(), vec![3, 4, 5, 6]);
        assert!(v[0].gpu.is_nan());
        assert_eq!(v[0].top[0], ("firefox".to_string(), 12.5));
        assert_eq!(
            v[0].top[1].0, "a-very-long-proc",
            "names are cut at 16 bytes"
        );
        // Reopening with the same shape appends; a different shape starts over.
        let mut w = Writer::open(&p, 4, 10).unwrap();
        w.push(&rec(7)).unwrap();
        assert_eq!(read(&p).unwrap().1.last().unwrap().ts, 7);
        Writer::open(&p, 8, 10).unwrap();
        assert!(read(&p).unwrap().1.is_empty());
        assert!(p.with_extension("bin.old").exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn capacity_rules() {
        assert_eq!(capacity(72, 10, 50), 72 * 360);
        assert_eq!(capacity(72, 1, 1), (1024 * 1024 - 64) / 128);
    }
}
