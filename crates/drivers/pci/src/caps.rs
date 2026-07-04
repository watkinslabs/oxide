use crate::{Bdf, ConfigSpaceReader};

/// Standard PCI capability IDs the kernel needs to recognise.
pub const CAP_ID_MSI: u8 = 0x05;
pub const CAP_ID_VENDOR: u8 = 0x09;
pub const CAP_ID_PCIE: u8 = 0x10;
pub const CAP_ID_MSIX: u8 = 0x11;

/// One PCI capability descriptor as the walker observed it. Body reads
/// (cap-specific) are left to the caller via `r.read32` at `cfg_off + 4..`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PciCap {
    /// Capability ID (PCI Local Bus §H or PCIe §7.5).
    pub id: u8,
    /// Byte offset within the device's 256-byte config space.
    pub cfg_off: u8,
}

/// MSI-X cap layout (PCI Local Bus 3.0 §6.8.2).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MsixCap {
    /// True when bit 15 of message_control is set.
    pub enabled: bool,
    /// True when bit 14 of message_control is set (all-vectors mask).
    pub function_mask: bool,
    /// Number of vectors the table holds (1..=2048).
    pub table_size: u16,
    /// BAR index (0..5) holding the table.
    pub table_bir: u8,
    /// Byte offset within `table_bir` of the table base.
    pub table_offset: u32,
    /// BAR index (0..5) holding the PBA (Pending Bit Array).
    pub pba_bir: u8,
    /// Byte offset within `pba_bir` of the PBA base.
    pub pba_offset: u32,
}

/// Decode the MSI-X cap header (3 dwords at `cfg_off`). Returns None if
/// `cfg_off` doesn't actually point at an MSI-X cap.
/// # C: O(1)
pub fn decode_msix_cap<R: ConfigSpaceReader>(r: &R, bdf: Bdf, cfg_off: u8) -> Option<MsixCap> {
    let off = cfg_off & 0xFC;
    let w0 = r.read32(bdf, off);
    if (w0 & 0xFF) as u8 != CAP_ID_MSIX {
        return None;
    }
    let mc = ((w0 >> 16) & 0xFFFF) as u16;
    let enabled = mc & 0x8000 != 0;
    let function_mask = mc & 0x4000 != 0;
    let table_size = (mc & 0x07FF) + 1;
    let tob = r.read32(bdf, off.wrapping_add(4));
    let table_bir = (tob & 0x7) as u8;
    let table_offset = tob & !0x7;
    let pba = r.read32(bdf, off.wrapping_add(8));
    let pba_bir = (pba & 0x7) as u8;
    let pba_offset = pba & !0x7;
    Some(MsixCap {
        enabled,
        function_mask,
        table_size,
        table_bir,
        table_offset,
        pba_bir,
        pba_offset,
    })
}

/// Walk a device's capability chain. Returns up to 16 caps in order; silently
/// stops on the first cycle or out-of-range pointer.
///
/// # C: O(N_caps) - typical N is 1-6.
pub fn capabilities<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> heapless_caps::CapVec {
    let mut out = heapless_caps::CapVec::new();
    let cmd_status = r.read32(bdf, 0x04);
    let status = (cmd_status >> 16) as u16;
    if status & (1 << 4) == 0 {
        return out;
    }

    let mut next = (r.read32(bdf, 0x34) & 0xFC) as u8;
    let mut seen: u32 = 0;
    while next != 0 && out.len() < out.cap() {
        if next < 0x40 || next as u32 >= 256 {
            break;
        }
        let bit = 1u32 << ((next >> 2) & 0x1F);
        if seen & bit != 0 {
            break;
        }
        seen |= bit;
        let hdr = r.read32(bdf, next & 0xFC);
        let id = (hdr & 0xFF) as u8;
        let next_p = ((hdr >> 8) & 0xFC) as u8;
        out.push(PciCap { id, cfg_off: next });
        next = next_p;
    }
    out
}

/// Tiny inline-arena vec so callers don't need an allocator just to list a
/// handful of caps. Cap of 16 covers sane devices.
pub mod heapless_caps {
    use super::PciCap;

    /// Max caps a single device may chain in this kernel's view.
    pub const MAX: usize = 16;

    /// Fixed-cap stack-allocated Vec for cap descriptors.
    pub struct CapVec {
        items: [PciCap; MAX],
        len: usize,
    }

    impl CapVec {
        /// Construct an empty cap vec. # C: O(1)
        pub const fn new() -> Self {
            Self {
                items: [PciCap { id: 0, cfg_off: 0 }; MAX],
                len: 0,
            }
        }

        /// Number of caps stored. # C: O(1)
        pub fn len(&self) -> usize {
            self.len
        }

        /// Maximum capacity (compile-time constant). # C: O(1)
        pub fn cap(&self) -> usize {
            MAX
        }

        /// True iff no caps stored. # C: O(1)
        pub fn is_empty(&self) -> bool {
            self.len == 0
        }

        /// Append a cap; silently dropped if at capacity. # C: O(1)
        pub fn push(&mut self, c: PciCap) {
            if self.len < MAX {
                self.items[self.len] = c;
                self.len += 1;
            }
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
        fn default() -> Self {
            Self::new()
        }
    }
}
