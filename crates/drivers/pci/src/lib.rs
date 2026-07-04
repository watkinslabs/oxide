// PCI / PCIe enumeration. v1 implements legacy PCI config space
// (CF8/CFC port pair on x86) + a `ConfigSpaceReader` trait so an
// arch crate can hook in PCIe MMIO config later. Pure parser/
// walker over a `ConfigSpaceReader` so hosted tests can exercise
// the enumeration without real hardware.
//
// Per docs/34 (FROZEN).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;
use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { NotImplemented, NoMem, Inval, Io, NotFound }

pub type KResult<T> = core::result::Result<T, Error>;

/// (bus, device, function) tuple.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Bdf { pub bus: u8, pub device: u8, pub function: u8 }

impl Bdf {
    /// 16-bit packed encoding for indexing.
    /// # C: O(1)
    pub const fn raw(self) -> u16 {
        ((self.bus as u16) << 8) | ((self.device as u16) << 3) | (self.function as u16)
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_byte(s: &[u8]) -> Option<u8> {
    Some((hex_nibble(*s.first()?)? << 4) | hex_nibble(*s.get(1)?)?)
}

/// Parse a PCI model address in the kernel's canonical
/// `0000:bb:dd.f` form. # C: O(1)
pub fn parse_bdf_addr(addr: &str) -> Option<Bdf> {
    let b = addr.as_bytes();
    if b.len() != 12 || b[4] != b':' || b[7] != b':' || b[10] != b'.' {
        return None;
    }
    Some(Bdf {
        bus: hex_byte(&b[5..7])?,
        device: hex_byte(&b[8..10])?,
        function: hex_nibble(b[11])?,
    })
}

/// `ConfigSpaceReader`: arch-specific accessor for the per-BDF
/// 256-byte config space. x86 uses CF8/CFC; AArch64 ECAM MMIO.
pub trait ConfigSpaceReader: Send + Sync {
    /// Read a u32 from `(bdf, offset)`. Offset must be 4-aligned.
    fn read32(&self, bdf: Bdf, offset: u8) -> u32;
    /// Optional write (for BAR programming, MSI setup, etc.).
    fn write32(&self, bdf: Bdf, offset: u8, val: u32);
}

/// PCI command register bit: I/O Space Enable.
pub const COMMAND_IO: u16 = 1 << 0;
/// PCI command register bit: Memory Space Enable.
pub const COMMAND_MEMORY: u16 = 1 << 1;
/// PCI command register bit: Bus Master Enable.
pub const COMMAND_BUS_MASTER: u16 = 1 << 2;

/// Read the low 16-bit PCI command register. # C: O(1)
pub fn read_command<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> u16 {
    (r.read32(bdf, 0x04) & 0xFFFF) as u16
}

/// Write the low 16-bit PCI command register while preserving status bits.
/// # C: O(1)
pub fn write_command<R: ConfigSpaceReader>(r: &R, bdf: Bdf, command: u16) {
    let cur = r.read32(bdf, 0x04);
    r.write32(bdf, 0x04, (cur & 0xFFFF_0000) | command as u32);
}

/// Enable Memory Space and Bus Master for a function claimed by a driver.
/// Returns the previous command value so a driver can restore it on failed
/// probe or remove when it owns that policy.
/// # C: O(1)
pub fn enable_mem_bus_master<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> u16 {
    let old = read_command(r, bdf);
    let new = old | COMMAND_MEMORY | COMMAND_BUS_MASTER;
    if new != old {
        write_command(r, bdf, new);
    }
    old
}

/// Disable Memory Space and Bus Master for a function.
///
/// Returns the previous command value so callers can restore it if desired.
/// # C: O(1)
pub fn disable_mem_bus_master<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> u16 {
    let old = read_command(r, bdf);
    let restored = old & !(COMMAND_MEMORY | COMMAND_BUS_MASTER);
    if restored != old {
        write_command(r, bdf, restored);
    }
    old
}

/// Per-device decoded summary for the kernel's device list.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PciDevice {
    pub bdf:        Bdf,
    pub vendor_id:  u16,
    pub device_id:  u16,
    pub class_code: u8,
    pub subclass:   u8,
    pub prog_if:    u8,
    pub revision:   u8,
    pub header_type: u8,
}

impl PciDevice {
    /// # C: O(1)
    pub fn from_config<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> Option<Self> {
        let id = r.read32(bdf, 0x00);
        if id == 0xFFFF_FFFF || (id & 0xFFFF) == 0xFFFF { return None; }
        let vendor_id = (id & 0xFFFF) as u16;
        let device_id = (id >> 16) as u16;
        let class_rev = r.read32(bdf, 0x08);
        let revision  = (class_rev & 0xFF) as u8;
        let prog_if   = ((class_rev >> 8) & 0xFF) as u8;
        let subclass  = ((class_rev >> 16) & 0xFF) as u8;
        let class_code = ((class_rev >> 24) & 0xFF) as u8;
        let header_type = ((r.read32(bdf, 0x0C) >> 16) & 0xFF) as u8;
        Some(Self {
            bdf, vendor_id, device_id, class_code, subclass, prog_if, revision, header_type,
        })
    }
}

// ---------------------------------------------------------------------------
// Capability list walk per PCI Local Bus 3.0 §6.7. Header type 0 (the only
// one v1 cares about) puts the cap-list head at offset 0x34 IFF the status
// register at 0x06 has bit 4 (CAP_LIST) set. Each cap is `{u8 id, u8 next,
// ...}`; chain ends when `next == 0`. Caps are 4-byte aligned in practice.
// ---------------------------------------------------------------------------

/// Standard PCI capability IDs the kernel needs to recognise.
pub const CAP_ID_MSI:    u8 = 0x05;
pub const CAP_ID_VENDOR: u8 = 0x09;  // virtio caps live here
pub const CAP_ID_MSIX:   u8 = 0x11;
pub const CAP_ID_PCIE:   u8 = 0x10;

/// One PCI capability descriptor as the walker observed it. Body
/// reads (cap-specific) are left to the caller via `r.read32` at
/// `cfg_off + 4..`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PciCap {
    /// Capability ID (PCI Local Bus §H or PCIe §7.5).
    pub id:      u8,
    /// Byte offset within the device's 256-byte config space.
    pub cfg_off: u8,
}

/// MSI-X cap layout (PCI Local Bus 3.0 §6.8.2). Header lives in PCI
/// config space at the cap_id=0x11 cap offset:
///
/// | off | field            | desc                                 |
/// | 0x0 | cap_id (1B)      | 0x11                                 |
/// | 0x1 | cap_next (1B)    | next cap pointer                     |
/// | 0x2 | message_control  | le16: bit15=enable, bit14=fn_mask,   |
/// |     |                  |       bits[10:0]=table_size (N-1)    |
/// | 0x4 | table_offset_bir | le32: bits[2:0]=BIR, bits[31:3]<<3   |
/// | 0x8 | pba_offset_bir   | le32: bits[2:0]=BIR, bits[31:3]<<3   |
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MsixCap {
    /// True when bit 15 of message_control is set.
    pub enabled:      bool,
    /// True when bit 14 of message_control is set (all-vectors mask).
    pub function_mask: bool,
    /// Number of vectors the table holds (1..=2048).
    pub table_size:   u16,
    /// BAR index (0..5) holding the table.
    pub table_bir:    u8,
    /// Byte offset within `table_bir` of the table base.
    pub table_offset: u32,
    /// BAR index (0..5) holding the PBA (Pending Bit Array).
    pub pba_bir:      u8,
    /// Byte offset within `pba_bir` of the PBA base.
    pub pba_offset:   u32,
}

/// Decode the MSI-X cap header (3 dwords at `cfg_off`). Returns None
/// if `cfg_off` doesn't actually point at an MSI-X cap.
/// # C: O(1)
pub fn decode_msix_cap<R: ConfigSpaceReader>(r: &R, bdf: Bdf, cfg_off: u8) -> Option<MsixCap> {
    let off = cfg_off & 0xFC;
    let w0 = r.read32(bdf, off);
    if (w0 & 0xFF) as u8 != CAP_ID_MSIX { return None; }
    let mc = ((w0 >> 16) & 0xFFFF) as u16;
    let enabled       = mc & 0x8000 != 0;
    let function_mask = mc & 0x4000 != 0;
    let table_size    = (mc & 0x07FF) + 1;
    let tob = r.read32(bdf, off.wrapping_add(4));
    let table_bir    = (tob & 0x7) as u8;
    let table_offset = tob & !0x7;
    let pba = r.read32(bdf, off.wrapping_add(8));
    let pba_bir    = (pba & 0x7) as u8;
    let pba_offset = pba & !0x7;
    Some(MsixCap {
        enabled, function_mask, table_size,
        table_bir, table_offset, pba_bir, pba_offset,
    })
}

/// Walk a device's capability chain. Returns up to 16 caps in order
/// (more would indicate a malformed device); silently stops on the
/// first cycle / out-of-range pointer to avoid wedging on garbage.
///
/// # C: O(N_caps) — typical N is 1–6.
pub fn capabilities<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> heapless_caps::CapVec {
    let mut out = heapless_caps::CapVec::new();
    // Status reg at 0x06. CAP_LIST bit 4.
    let cmd_status = r.read32(bdf, 0x04);
    let status = (cmd_status >> 16) as u16;
    if status & (1 << 4) == 0 { return out; }
    // Cap-list head is at 0x34 for header type 0; low 6 bits are
    // the offset, top 2 bits reserved per spec.
    let mut next = (r.read32(bdf, 0x34) & 0xFC) as u8;
    let mut seen: u32 = 0;
    while next != 0 && out.len() < out.cap() {
        if next < 0x40 || next as u32 >= 256 { break; }
        // Cycle guard via bitmap of visited offsets divided by 4.
        let bit = 1u32 << ((next >> 2) & 0x1F);
        if seen & bit != 0 { break; }
        seen |= bit;
        // Read header — cap_id at +0, next_ptr at +1.
        // ConfigSpaceReader returns u32; cap header is 2 bytes.
        let hdr = r.read32(bdf, next & 0xFC);
        let id      = (hdr & 0xFF) as u8;
        let next_p  = ((hdr >> 8) & 0xFC) as u8;
        out.push(PciCap { id, cfg_off: next });
        next = next_p;
    }
    out
}

/// Tiny inline-arena vec so callers don't need an allocator just to
/// list a handful of caps. Cap of 16 covers any sane device.
pub mod heapless_caps {
    use super::PciCap;
    /// Max caps a single device may chain in this kernel's view.
    pub const MAX: usize = 16;

    /// Fixed-cap stack-allocated Vec for cap descriptors.
    pub struct CapVec {
        items: [PciCap; MAX],
        len:   usize,
    }
    impl CapVec {
        /// Construct an empty cap vec. # C: O(1)
        pub const fn new() -> Self {
            Self { items: [PciCap { id: 0, cfg_off: 0 }; MAX], len: 0 }
        }
        /// Number of caps stored. # C: O(1)
        pub fn len(&self) -> usize { self.len }
        /// Maximum capacity (compile-time constant). # C: O(1)
        pub fn cap(&self) -> usize { MAX }
        /// True iff no caps stored. # C: O(1)
        pub fn is_empty(&self) -> bool { self.len == 0 }
        /// Append a cap; silently dropped if at capacity. # C: O(1)
        pub fn push(&mut self, c: PciCap) {
            if self.len < MAX { self.items[self.len] = c; self.len += 1; }
        }
        /// Iterator over stored caps. # C: O(1) per next()
        pub fn iter(&self) -> core::slice::Iter<'_, PciCap> {
            self.items[..self.len].iter()
        }
        /// First cap matching `id`, or None. # C: O(N_caps)
        pub fn find(&self, id: u8) -> Option<PciCap> {
            self.iter().find(|c| c.id == id).copied()
        }
    }
    impl Default for CapVec {
        fn default() -> Self { Self::new() }
    }
}

// ---------------------------------------------------------------------------
// BAR decoder per PCI Local Bus 3.0 §6.2.5.1. Pure read of the values the
// firmware already programmed — no write-probe sizing here (that needs the
// command register decode disabled and is for the driver, not enumeration).
// ---------------------------------------------------------------------------

/// One decoded BAR. Header-type-0 devices have BAR0..BAR5.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Bar {
    /// Empty / unprogrammed slot (reads as 0).
    None,
    /// I/O port range. v1 only sees these on x86 legacy.
    Io { port: u32 },
    /// 32-bit memory BAR.
    Mem32 { base: u32, prefetch: bool },
    /// 64-bit memory BAR. Consumes BAR_N AND BAR_N+1.
    Mem64 { base: u64, prefetch: bool },
    /// The high half of a 64-bit BAR — caller already consumed it as
    /// part of the prior `Mem64`. Listed here so the index<->BAR_N map
    /// stays 1:1.
    HighHalfConsumed,
}

/// Linux-compatible resource flag bits for PCI BAR resources. These mirror the
/// common `IORESOURCE_*` values exposed by `/sys/bus/pci/devices/.../resource`.
pub const IORESOURCE_IO:       u64 = 0x0000_0100;
pub const IORESOURCE_MEM:      u64 = 0x0000_0200;
pub const IORESOURCE_PREFETCH: u64 = 0x0000_2000;

/// One sized PCI BAR resource.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Resource {
    pub start: u64,
    pub end:   u64,
    pub flags: u64,
}

impl Bar {
    /// Physical base of a memory BAR, or None for I/O/empty BAR slots.
    /// # C: O(1)
    pub const fn mem_base(self) -> Option<u64> {
        match self {
            Bar::Mem32 { base, .. } => Some(base as u64),
            Bar::Mem64 { base, .. } => Some(base),
            _ => None,
        }
    }
}

/// BAR offset in config space for header type 0. # C: O(1)
pub const fn bar_offset(idx: u8) -> u8 {
    debug_assert!(idx < 6);
    0x10 + idx * 4
}

/// Decode all 6 BARs of a header-type-0 device. # C: O(1) — at most 12 reads.
pub fn decode_bars<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> [Bar; 6] {
    let mut out = [Bar::None; 6];
    let mut idx = 0u8;
    while idx < 6 {
        let off = bar_offset(idx);
        let raw = r.read32(bdf, off);
        if raw == 0 {
            out[idx as usize] = Bar::None;
            idx += 1;
            continue;
        }
        if raw & 0x1 != 0 {
            out[idx as usize] = Bar::Io { port: raw & 0xFFFF_FFFC };
            idx += 1;
            continue;
        }
        let prefetch = raw & 0x8 != 0;
        let kind = (raw >> 1) & 0x3;
        let lo = (raw & 0xFFFF_FFF0) as u64;
        if kind == 0x2 && idx + 1 < 6 {
            let hi = r.read32(bdf, bar_offset(idx + 1)) as u64;
            out[idx as usize] = Bar::Mem64 { base: (hi << 32) | lo, prefetch };
            out[(idx + 1) as usize] = Bar::HighHalfConsumed;
            idx += 2;
        } else {
            out[idx as usize] = Bar::Mem32 { base: lo as u32, prefetch };
            idx += 1;
        }
    }
    out
}

fn bar_size32(mask: u32, low_bits: u32) -> u64 {
    let m = mask & !low_bits;
    if m == 0 {
        0
    } else {
        (!m).wrapping_add(1) as u64
    }
}

fn bar_size64(mask: u64, low_bits: u64) -> u64 {
    let m = mask & !low_bits;
    if m == 0 {
        0
    } else {
        (!m).wrapping_add(1)
    }
}

/// Size the programmed BARs of a header-type-0 function and return Linux
/// resource records. Temporarily disables I/O and memory decode while probing,
/// then restores every BAR and the command register.
/// # C: O(1) — at most 6 BARs, with bounded config-space writes.
pub fn probe_bar_resources<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> [Option<Resource>; 6] {
    let mut out = [None; 6];
    let cmd_status = r.read32(bdf, 0x04);
    let cmd = cmd_status & 0xFFFF;
    r.write32(bdf, 0x04, (cmd_status & 0xFFFF_0000) | (cmd & !0x3));

    let mut idx = 0u8;
    while idx < 6 {
        let off = bar_offset(idx);
        let orig = r.read32(bdf, off);
        if orig == 0 || orig == 0xFFFF_FFFF {
            idx += 1;
            continue;
        }

        if orig & 0x1 != 0 {
            r.write32(bdf, off, 0xFFFF_FFFF);
            let mask = r.read32(bdf, off);
            r.write32(bdf, off, orig);
            let start = (orig & 0xFFFF_FFFC) as u64;
            let size = bar_size32(mask, 0x3);
            if start != 0 && size != 0 {
                out[idx as usize] = Some(Resource {
                    start,
                    end: start.saturating_add(size).saturating_sub(1),
                    flags: IORESOURCE_IO,
                });
            }
            idx += 1;
            continue;
        }

        let prefetch = orig & 0x8 != 0;
        let kind = (orig >> 1) & 0x3;
        if kind == 0x2 && idx + 1 < 6 {
            let off_hi = bar_offset(idx + 1);
            let orig_hi = r.read32(bdf, off_hi);
            r.write32(bdf, off, 0xFFFF_FFFF);
            r.write32(bdf, off_hi, 0xFFFF_FFFF);
            let mask_lo = r.read32(bdf, off) as u64;
            let mask_hi = r.read32(bdf, off_hi) as u64;
            r.write32(bdf, off_hi, orig_hi);
            r.write32(bdf, off, orig);
            let start = ((orig_hi as u64) << 32) | ((orig & 0xFFFF_FFF0) as u64);
            let mask = (mask_hi << 32) | mask_lo;
            let size = bar_size64(mask, 0xF);
            if start != 0 && size != 0 {
                out[idx as usize] = Some(Resource {
                    start,
                    end: start.saturating_add(size).saturating_sub(1),
                    flags: IORESOURCE_MEM | if prefetch { IORESOURCE_PREFETCH } else { 0 },
                });
            }
            idx += 2;
        } else {
            r.write32(bdf, off, 0xFFFF_FFFF);
            let mask = r.read32(bdf, off);
            r.write32(bdf, off, orig);
            let start = (orig & 0xFFFF_FFF0) as u64;
            let size = bar_size32(mask, 0xF);
            if start != 0 && size != 0 {
                out[idx as usize] = Some(Resource {
                    start,
                    end: start.saturating_add(size).saturating_sub(1),
                    flags: IORESOURCE_MEM | if prefetch { IORESOURCE_PREFETCH } else { 0 },
                });
            }
            idx += 1;
        }
    }

    r.write32(bdf, 0x04, cmd_status);
    out
}

/// Walk the PCI bus: 256 buses × 32 devices × 8 functions.
/// Returns every present device. Skips multi-function probing
/// past function 0 unless the header_type's MF bit (0x80) is set.
/// # C: O(256 × 32 × 8) — single sweep at boot
pub fn enumerate<R: ConfigSpaceReader>(r: &R) -> Vec<PciDevice> {
    enumerate_buses(r, 256)
}

/// Like `enumerate` but caps the bus scan at `n_buses`. Used by
/// callers where the per-arch `ConfigSpaceReader` only has the
/// first N buses device-mapped (v1 aarch64 ECAM maps bus 0 only;
/// scanning past it would dereference an unmapped page).
/// # C: O(n_buses × 32 × 8)
pub fn enumerate_buses<R: ConfigSpaceReader>(r: &R, n_buses: u16) -> Vec<PciDevice> {
    let mut out = Vec::new();
    let cap = (n_buses as u32).min(256);
    for bus in 0u32..cap {
        for dev in 0u8..32 {
            for func in 0u8..8 {
                let bdf = Bdf { bus: bus as u8, device: dev, function: func };
                let d_opt = PciDevice::from_config(r, bdf);
                if let Some(d) = d_opt {
                    out.push(d);
                    if func == 0 && (d.header_type & 0x80) == 0 {
                        break;
                    }
                } else if func == 0 {
                    break;
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MapReader {
        m: Mutex<HashMap<(Bdf, u8), u32>>,
    }
    impl ConfigSpaceReader for MapReader {
        fn read32(&self, bdf: Bdf, offset: u8) -> u32 {
            self.m.lock().unwrap().get(&(bdf, offset)).copied().unwrap_or(0xFFFF_FFFF)
        }
        fn write32(&self, bdf: Bdf, offset: u8, val: u32) {
            self.m.lock().unwrap().insert((bdf, offset), val);
        }
    }

    #[test]
    fn enumerate_finds_one_device() {
        let r = MapReader { m: Mutex::new(HashMap::new()) };
        let bdf = Bdf { bus: 0, device: 5, function: 0 };
        r.write32(bdf, 0x00, 0x1041_1AF4);   // virtio-net vendor/device
        r.write32(bdf, 0x08, 0x0200_0000);   // class=2 (network)
        r.write32(bdf, 0x0C, 0);             // header_type=0
        let v = enumerate(&r);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].vendor_id, 0x1AF4);
        assert_eq!(v[0].device_id, 0x1041);
        assert_eq!(v[0].class_code, 0x02);
    }

    #[test]
    fn parse_bdf_addr_kernel_model_form() {
        assert_eq!(
            parse_bdf_addr("0000:00:1f.2"),
            Some(Bdf { bus: 0x00, device: 0x1f, function: 2 })
        );
        assert_eq!(
            parse_bdf_addr("0000:ab:0C.7"),
            Some(Bdf { bus: 0xab, device: 0x0c, function: 7 })
        );
        assert_eq!(parse_bdf_addr("00:1f.2"), None);
        assert_eq!(parse_bdf_addr("0000:00:1f:x"), None);
    }

    #[test]
    fn enable_mem_bus_master_preserves_status_bits() {
        let r = MapReader { m: Mutex::new(HashMap::new()) };
        let bdf = Bdf { bus: 0, device: 6, function: 0 };
        r.write32(bdf, 0x04, 0x1234_0001);

        let old = enable_mem_bus_master(&r, bdf);

        assert_eq!(old, COMMAND_IO);
        assert_eq!(r.read32(bdf, 0x04), 0x1234_0007);
    }

    #[test]
    fn disable_mem_bus_master_preserves_status_bits() {
        let r = MapReader { m: Mutex::new(HashMap::new()) };
        let bdf = Bdf { bus: 0, device: 6, function: 0 };
        r.write32(bdf, 0x04, 0x1234_0007);

        let old = disable_mem_bus_master(&r, bdf);

        assert_eq!(old, COMMAND_MEMORY | COMMAND_BUS_MASTER | COMMAND_IO);
        assert_eq!(r.read32(bdf, 0x04), 0x1234_0001);
    }

    #[test]
    fn decode_mem64_bar() {
        let r = MapReader { m: Mutex::new(HashMap::new()) };
        let bdf = Bdf { bus: 0, device: 1, function: 0 };
        // BAR0: Mem64 prefetch, base=0x1_0000_0000
        // raw lo = base_lo | type=10b<<1 | prefetch<<3 = 0 | 0x4 | 0x8 = 0x0C
        r.write32(bdf, 0x10, 0x0000_000C);
        // BAR1 = high half = 0x00000001
        r.write32(bdf, 0x14, 0x0000_0001);
        // Zero remaining BARs (test reader defaults to 0xFFFFFFFF).
        r.write32(bdf, 0x18, 0);
        r.write32(bdf, 0x1C, 0);
        r.write32(bdf, 0x20, 0);
        r.write32(bdf, 0x24, 0);
        let bars = decode_bars(&r, bdf);
        assert_eq!(bars[0], Bar::Mem64 { base: 0x1_0000_0000, prefetch: true });
        assert_eq!(bars[0].mem_base(), Some(0x1_0000_0000));
        assert_eq!(bars[1], Bar::HighHalfConsumed);
        assert_eq!(bars[1].mem_base(), None);
        assert_eq!(bars[2], Bar::None);
    }

    #[test]
    fn decode_mem32_and_io() {
        let r = MapReader { m: Mutex::new(HashMap::new()) };
        let bdf = Bdf { bus: 0, device: 2, function: 0 };
        // BAR0: Mem32 base=0x1000_0000, no prefetch
        r.write32(bdf, 0x10, 0x1000_0000);
        // BAR1: I/O port 0xC000
        r.write32(bdf, 0x14, 0x0000_C001);
        r.write32(bdf, 0x18, 0);
        r.write32(bdf, 0x1C, 0);
        r.write32(bdf, 0x20, 0);
        r.write32(bdf, 0x24, 0);
        let bars = decode_bars(&r, bdf);
        assert_eq!(bars[0], Bar::Mem32 { base: 0x1000_0000, prefetch: false });
        assert_eq!(bars[1], Bar::Io { port: 0xC000 });
    }

    #[test]
    fn probe_bar_resources_restores_command_and_bars() {
        let r = MapReader { m: Mutex::new(HashMap::new()) };
        let bdf = Bdf { bus: 0, device: 3, function: 0 };
        r.write32(bdf, 0x04, 0x0010_0007);
        r.write32(bdf, 0x10, 0x1000_0000);
        r.write32(bdf, 0x14, 0x0000_C001);
        r.write32(bdf, 0x18, 0);
        r.write32(bdf, 0x1C, 0);
        r.write32(bdf, 0x20, 0);
        r.write32(bdf, 0x24, 0);

        let res = probe_bar_resources(&r, bdf);

        assert_eq!(r.read32(bdf, 0x04), 0x0010_0007);
        assert_eq!(r.read32(bdf, 0x10), 0x1000_0000);
        assert_eq!(r.read32(bdf, 0x14), 0x0000_C001);
        assert_eq!(res[0], Some(Resource {
            start: 0x1000_0000,
            end: 0x1000_000f,
            flags: IORESOURCE_MEM,
        }));
        assert_eq!(res[1], Some(Resource {
            start: 0xC000,
            end: 0xC003,
            flags: IORESOURCE_IO,
        }));
    }

    #[test]
    fn decode_msix_cap_basic() {
        let r = MapReader { m: Mutex::new(HashMap::new()) };
        let bdf = Bdf { bus: 0, device: 1, function: 0 };
        // cfg_off = 0x40
        // dword0: cap_id=0x11, cap_next=0x00, mc=0x8003 (enable + table_size=4)
        r.write32(bdf, 0x40, 0x8003_0011);
        // dword1: BIR=4, offset=0x1000 -> 0x1004
        r.write32(bdf, 0x44, 0x0000_1004);
        // dword2: BIR=4, offset=0x2000 -> 0x2004
        r.write32(bdf, 0x48, 0x0000_2004);
        let m = decode_msix_cap(&r, bdf, 0x40).unwrap();
        assert!(m.enabled);
        assert!(!m.function_mask);
        assert_eq!(m.table_size, 4);
        assert_eq!(m.table_bir, 4);
        assert_eq!(m.table_offset, 0x1000);
        assert_eq!(m.pba_bir, 4);
        assert_eq!(m.pba_offset, 0x2000);
    }

    #[test]
    fn decode_msix_cap_rejects_non_msix() {
        let r = MapReader { m: Mutex::new(HashMap::new()) };
        let bdf = Bdf { bus: 0, device: 1, function: 0 };
        r.write32(bdf, 0x40, 0x0000_0009); // cap_id=0x09 (vendor)
        assert!(decode_msix_cap(&r, bdf, 0x40).is_none());
    }

    #[test]
    fn empty_bus_returns_nothing() {
        let r = MapReader { m: Mutex::new(HashMap::new()) };
        let v = enumerate(&r);
        assert!(v.is_empty());
    }
}
