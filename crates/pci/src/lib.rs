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

/// Walk the PCI bus: 256 buses × 32 devices × 8 functions.
/// Returns every present device. Skips multi-function probing
/// past function 0 unless the header_type's MF bit (0x80) is set.
/// # C: O(256 × 32 × 8) — single sweep at boot
pub fn enumerate<R: ConfigSpaceReader>(r: &R) -> Vec<PciDevice> {
    let mut out = Vec::new();
    for bus in 0u32..=255 {
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
