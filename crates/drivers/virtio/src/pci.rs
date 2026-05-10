// Modern virtio-pci transport (Virtio 1.2 §4.1). Decoder over the
// vendor-specific PCI capability list — each cap_id=0x09 cap holds
// `{u8 cap_vndr; u8 cap_next; u8 cap_len; u8 cfg_type; u8 bar;
// u8 padding[3]; le32 offset; le32 length;}` plus optional trailers.
//
// v1 surface = decode + log only. BAR mapping + register access ride
// alongside the real driver work (F21+).

use pci::{Bdf, ConfigSpaceReader, PciCap, CAP_ID_VENDOR};

/// `cfg_type` values per spec §4.1.4.3.
pub const VIRTIO_PCI_CAP_COMMON_CFG:        u8 = 1;
pub const VIRTIO_PCI_CAP_NOTIFY_CFG:        u8 = 2;
pub const VIRTIO_PCI_CAP_ISR_CFG:           u8 = 3;
pub const VIRTIO_PCI_CAP_DEVICE_CFG:        u8 = 4;
pub const VIRTIO_PCI_CAP_PCI_CFG:           u8 = 5;
pub const VIRTIO_PCI_CAP_SHARED_MEMORY_CFG: u8 = 8;

/// Virtio Red Hat vendor ID.
pub const VIRTIO_PCI_VENDOR_RH:      u16 = 0x1AF4;
/// Modern-only device-ID base (non-transitional). 0x1041+ per spec §4.1.2.
pub const VIRTIO_PCI_MODERN_ID_BASE: u16 = 0x1040;
/// Transitional device-ID range: 0x1000..=0x103F. These speak both legacy
/// port-IO AND the modern PCI cap-based transport when caps are present.
pub const VIRTIO_PCI_TRANSITIONAL_LO: u16 = 0x1000;
pub const VIRTIO_PCI_TRANSITIONAL_HI: u16 = 0x103F;

/// Decoded virtio-pci vendor cap. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtioPciCap {
    pub cfg_type: u8,
    pub bar:      u8,
    pub offset:   u32,
    pub length:   u32,
    /// Only meaningful for NOTIFY_CFG; trailer u32 at +16.
    pub notify_off_multiplier: u32,
}

/// True iff `(vendor, device)` is a modern-only virtio-pci device.
/// # C: O(1)
pub const fn is_modern_only(vendor: u16, device: u16) -> bool {
    vendor == VIRTIO_PCI_VENDOR_RH && device >= VIRTIO_PCI_MODERN_ID_BASE
}

/// True iff the device may speak the modern (cap-based) transport — that
/// covers both modern-only IDs and transitional IDs (which advertise the
/// same caps when running under a 1.0+ host). The cap walker still has
/// final say: a transitional ID without virtio caps is legacy-only.
/// # C: O(1)
pub const fn is_modern(vendor: u16, device: u16) -> bool {
    vendor == VIRTIO_PCI_VENDOR_RH
        && device >= VIRTIO_PCI_TRANSITIONAL_LO
        && device <= 0x107F
}

/// Decode one virtio vendor cap from config space. Returns None if the
/// underlying cap isn't actually a virtio vendor cap.
/// # C: O(1) — five u32 reads.
pub fn decode_one<R: ConfigSpaceReader>(r: &R, bdf: Bdf, cap: PciCap) -> Option<VirtioPciCap> {
    if cap.id != CAP_ID_VENDOR { return None; }
    let off = cap.cfg_off & 0xFC;
    let w0 = r.read32(bdf, off);
    let cap_vndr = (w0 & 0xFF) as u8;
    if cap_vndr != CAP_ID_VENDOR { return None; }
    let cap_len = ((w0 >> 16) & 0xFF) as u8;
    let cfg_type = ((w0 >> 24) & 0xFF) as u8;
    let w1 = r.read32(bdf, off.wrapping_add(4));
    let bar = (w1 & 0xFF) as u8;
    let offset = r.read32(bdf, off.wrapping_add(8));
    let length = r.read32(bdf, off.wrapping_add(12));
    let notify_mult = if cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG && cap_len >= 20 {
        r.read32(bdf, off.wrapping_add(16))
    } else {
        0
    };
    Some(VirtioPciCap {
        cfg_type, bar, offset, length,
        notify_off_multiplier: notify_mult,
    })
}

/// Heapless collector for decoded virtio caps. A modern device chains
/// 5–7 vendor caps in practice (one per cfg_type the device supports).
pub mod heapless_v {
    use super::VirtioPciCap;
    pub const MAX: usize = 8;

    pub struct VCapVec {
        items: [VirtioPciCap; MAX],
        len:   usize,
    }
    impl VCapVec {
        /// # C: O(1)
        pub const fn new() -> Self {
            Self {
                items: [VirtioPciCap {
                    cfg_type: 0, bar: 0, offset: 0, length: 0, notify_off_multiplier: 0,
                }; MAX],
                len: 0,
            }
        }
        /// # C: O(1)
        pub fn len(&self) -> usize { self.len }
        /// # C: O(1)
        pub fn is_empty(&self) -> bool { self.len == 0 }
        /// # C: O(1)
        pub fn push(&mut self, c: VirtioPciCap) {
            if self.len < MAX { self.items[self.len] = c; self.len += 1; }
        }
        /// # C: O(1) per next()
        pub fn iter(&self) -> core::slice::Iter<'_, VirtioPciCap> {
            self.items[..self.len].iter()
        }
        /// # C: O(N)
        pub fn find(&self, cfg_type: u8) -> Option<VirtioPciCap> {
            self.iter().find(|c| c.cfg_type == cfg_type).copied()
        }
    }
    impl Default for VCapVec {
        fn default() -> Self { Self::new() }
    }
}

/// Decode every virtio vendor cap on `bdf`. Caller has already walked
/// the PCI cap list via `pci::capabilities`.
/// # C: O(N_caps)
pub fn decode_all<R: ConfigSpaceReader>(
    r: &R,
    bdf: Bdf,
    caps: &pci::heapless_caps::CapVec,
) -> heapless_v::VCapVec {
    let mut out = heapless_v::VCapVec::new();
    for c in caps.iter() {
        if let Some(v) = decode_one(r, bdf, *c) {
            out.push(v);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MapR { m: Mutex<HashMap<(Bdf, u8), u32>> }
    impl ConfigSpaceReader for MapR {
        fn read32(&self, b: Bdf, o: u8) -> u32 {
            self.m.lock().unwrap().get(&(b, o)).copied().unwrap_or(0xFFFF_FFFF)
        }
        fn write32(&self, b: Bdf, o: u8, v: u32) {
            self.m.lock().unwrap().insert((b, o), v);
        }
    }

    #[test]
    fn decode_common_cfg_cap() {
        let r = MapR { m: Mutex::new(HashMap::new()) };
        let bdf = Bdf { bus: 0, device: 1, function: 0 };
        // {cap_vndr=09, cap_next=00, cap_len=10, cfg_type=01}
        r.write32(bdf, 0x40, 0x0110_0009);
        // bar=4, padding=0
        r.write32(bdf, 0x44, 0x0000_0004);
        // offset=0x1000
        r.write32(bdf, 0x48, 0x0000_1000);
        // length=0x100
        r.write32(bdf, 0x4C, 0x0000_0100);
        let v = decode_one(&r, bdf, PciCap { id: CAP_ID_VENDOR, cfg_off: 0x40 }).unwrap();
        assert_eq!(v.cfg_type, VIRTIO_PCI_CAP_COMMON_CFG);
        assert_eq!(v.bar, 4);
        assert_eq!(v.offset, 0x1000);
        assert_eq!(v.length, 0x100);
    }

    #[test]
    fn modern_id_check() {
        assert!(is_modern_only(0x1AF4, 0x1041));
        assert!(is_modern_only(0x1AF4, 0x1042));
        assert!(!is_modern_only(0x1AF4, 0x1000));
        assert!(!is_modern_only(0x8086, 0x1041));
        // Transitional + modern-only both pass the loose check.
        assert!(is_modern(0x1AF4, 0x1000));
        assert!(is_modern(0x1AF4, 0x1041));
        assert!(!is_modern(0x1AF4, 0x1080));
        assert!(!is_modern(0x8086, 0x1000));
    }
}
