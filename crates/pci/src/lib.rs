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

/// `ConfigSpaceReader`: arch-specific accessor for the per-BDF
/// 256-byte config space. x86 uses CF8/CFC; AArch64 ECAM MMIO.
pub trait ConfigSpaceReader: Send + Sync {
    /// Read a u32 from `(bdf, offset)`. Offset must be 4-aligned.
    fn read32(&self, bdf: Bdf, offset: u8) -> u32;
    /// Optional write (for BAR programming, MSI setup, etc.).
    fn write32(&self, bdf: Bdf, offset: u8, val: u32);
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
    fn empty_bus_returns_nothing() {
        let r = MapReader { m: Mutex::new(HashMap::new()) };
        let v = enumerate(&r);
        assert!(v.is_empty());
    }
}
