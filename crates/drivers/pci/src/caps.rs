use crate::{Bdf, ConfigSpaceReader};

/// Standard PCI capability IDs the kernel needs to recognise.
pub const CAP_ID_MSI: u8 = 0x05;
pub const CAP_ID_VENDOR: u8 = 0x09;
pub const CAP_ID_PCIE: u8 = 0x10;
pub const CAP_ID_MSIX: u8 = 0x11;
/// PCIe extended capability ID for a Device Serial Number.
pub const EXT_CAP_ID_DSN: u16 = 0x0003;
const EXT_CAP_FIRST: u16 = 0x100;
const EXT_CAP_NEXT_MASK: u32 = 0xFFF << 20;
const EXT_CAP_MAX_STEPS: usize = 960;
pub const MSI_ENABLE: u32 = 1u32 << 16;
pub const MSIX_ENABLE: u32 = 1u32 << 31;
pub const MSIX_FUNCTION_MASK: u32 = 1u32 << 30;
pub const MSIX_VECTOR_CONTROL_MASKED: u32 = 1;
pub const MSIX_TABLE_ENTRY_BYTES: u64 = 16;
pub const MSIX_MESSAGE_ADDR_LOW_OFF: u64 = 0;
pub const MSIX_MESSAGE_ADDR_HIGH_OFF: u64 = 4;
pub const MSIX_MESSAGE_DATA_OFF: u64 = 8;
pub const MSIX_VECTOR_CONTROL_OFF: u64 = 12;

const MSI_MME_MASK: u32 = 0x7u32 << 20;
const MSI_CONTROL_MMC_SHIFT: u16 = 1;
const MSI_CONTROL_MME_SHIFT: u16 = 4;
const MSI_CONTROL_WIDTH_MASK: u16 = 0x7;
const MSI_CONTROL_64_BIT: u16 = 1 << 7;
const MSI_CONTROL_PER_VECTOR_MASK: u16 = 1 << 8;
const MSI_MESSAGE_ADDR_LOW_CFG_OFF: u8 = 4;
const MSI_MESSAGE_ADDR_HIGH_CFG_OFF: u8 = 8;
const MSI_32_MESSAGE_DATA_CFG_OFF: u8 = 8;
const MSI_64_MESSAGE_DATA_CFG_OFF: u8 = 12;
const MSI_32_MASK_BITS_CFG_OFF: u8 = 12;
const MSI_64_MASK_BITS_CFG_OFF: u8 = 16;
const MSI_VECTOR_ZERO_MASK: u32 = 1;

/// One PCI capability descriptor as the walker observed it. Body reads
/// (cap-specific) are left to the caller via `r.read32` at `cfg_off + 4..`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PciCap {
    /// Capability ID (PCI Local Bus §H or PCIe §7.5).
    pub id: u8,
    /// Byte offset within the device's 256-byte config space.
    pub cfg_off: u8,
}

/// Return the Device Serial Number from the bounded extended-capability chain.
/// A malformed loop, all-zero header, or absent DSN has no serial number.
/// # C: O(extended capabilities)
pub fn device_serial_number<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> Option<u64> {
    let mut off = EXT_CAP_FIRST;
    for _ in 0..EXT_CAP_MAX_STEPS {
        let hdr = r.read32_ext(bdf, off);
        if hdr == 0 || hdr == u32::MAX { return None; }
        if (hdr & 0xFFFF) as u16 == EXT_CAP_ID_DSN {
            let lo = r.read32_ext(bdf, off + 4);
            let hi = r.read32_ext(bdf, off + 8);
            return Some((u64::from(hi) << 32) | u64::from(lo));
        }
        let next = ((hdr & EXT_CAP_NEXT_MASK) >> 20) as u16;
        if next < EXT_CAP_FIRST || next <= off { return None; }
        off = next;
    }
    None
}

/// MSI capability shape (PCI Local Bus 3.0 §6.8.1).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MsiCap {
    pub enabled: bool,
    pub multiple_message_capable: u8,
    pub multiple_message_enabled: u8,
    pub address_64: bool,
    pub per_vector_mask: bool,
}

/// Decode one MSI capability header. # C: O(1)
pub fn decode_msi_cap<R: ConfigSpaceReader>(r: &R, bdf: Bdf, cfg_off: u8) -> Option<MsiCap> {
    let w0 = r.read32(bdf, cfg_off & 0xFC);
    if (w0 & 0xFF) as u8 != CAP_ID_MSI { return None; }
    let control = (w0 >> 16) as u16;
    Some(MsiCap {
        enabled: control & 1 != 0,
        multiple_message_capable:
            ((control >> MSI_CONTROL_MMC_SHIFT) & MSI_CONTROL_WIDTH_MASK) as u8,
        multiple_message_enabled:
            ((control >> MSI_CONTROL_MME_SHIFT) & MSI_CONTROL_WIDTH_MASK) as u8,
        address_64: control & MSI_CONTROL_64_BIT != 0,
        per_vector_mask: control & MSI_CONTROL_PER_VECTOR_MASK != 0,
    })
}

/// Compute a single-message MSI control header, forcing MME=0.
/// # C: O(1)
pub const fn msi_single_control_value(cur: u32, enabled: bool) -> u32 {
    let single = cur & !MSI_MME_MASK;
    if enabled { single | MSI_ENABLE } else { single & !MSI_ENABLE }
}

/// Program one MSI address/data tuple while MSI is disabled, then enable it.
///
/// Rejects message data wider than the PCI field and high addresses on a
/// 32-bit-only capability.
/// # C: O(1)
pub fn program_msi_single<R: ConfigSpaceReader>(
    r: &R,
    bdf: Bdf,
    cfg_off: u8,
    address: u64,
    data: u32,
) -> bool {
    let Some(cap) = decode_msi_cap(r, bdf, cfg_off) else { return false; };
    if data > u16::MAX as u32 || (!cap.address_64 && address > u32::MAX as u64) {
        return false;
    }
    let off = cfg_off & 0xFC;
    let header = r.read32(bdf, off);
    r.write32(bdf, off, msi_single_control_value(header, false));
    let _ = r.read32(bdf, off);
    r.write32(
        bdf,
        off.wrapping_add(MSI_MESSAGE_ADDR_LOW_CFG_OFF),
        address as u32,
    );
    let data_off = if cap.address_64 {
        r.write32(
            bdf,
            off.wrapping_add(MSI_MESSAGE_ADDR_HIGH_CFG_OFF),
            (address >> 32) as u32,
        );
        MSI_64_MESSAGE_DATA_CFG_OFF
    } else {
        MSI_32_MESSAGE_DATA_CFG_OFF
    };
    let old_data = r.read32(bdf, off.wrapping_add(data_off));
    r.write32(
        bdf,
        off.wrapping_add(data_off),
        (old_data & 0xFFFF_0000) | data,
    );
    let _ = r.read32(bdf, off.wrapping_add(data_off));
    if cap.per_vector_mask {
        let mask_off = if cap.address_64 {
            MSI_64_MASK_BITS_CFG_OFF
        } else {
            MSI_32_MASK_BITS_CFG_OFF
        };
        let mask = r.read32(bdf, off.wrapping_add(mask_off));
        r.write32(
            bdf,
            off.wrapping_add(mask_off),
            mask & !MSI_VECTOR_ZERO_MASK,
        );
        let _ = r.read32(bdf, off.wrapping_add(mask_off));
    }
    r.write32(bdf, off, msi_single_control_value(header, true));
    let _ = r.read32(bdf, off);
    true
}

/// Disable one MSI capability and force MME back to the single-message value.
/// # C: O(1)
pub fn disable_msi<R: ConfigSpaceReader>(r: &R, bdf: Bdf, cfg_off: u8) -> bool {
    if decode_msi_cap(r, bdf, cfg_off).is_none() { return false; }
    let off = cfg_off & 0xFC;
    let header = r.read32(bdf, off);
    r.write32(bdf, off, msi_single_control_value(header, false));
    let _ = r.read32(bdf, off);
    true
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

/// Compute the byte offset of one MSI-X table entry, rejecting indexes outside
/// the decoded table size.
/// # C: O(1)
pub fn msix_table_entry_offset(m: MsixCap, entry_index: u16) -> Option<u64> {
    if entry_index >= m.table_size {
        return None;
    }
    let entry_bytes = (entry_index as u64).checked_mul(MSIX_TABLE_ENTRY_BYTES)?;
    (m.table_offset as u64).checked_add(entry_bytes)
}

/// Compute the MSI-X message-control update for enable/disable.
///
/// Enabling clears the function mask after table entries have been programmed;
/// disabling sets the function mask while clearing MSI-X enable.
/// # C: O(1)
pub const fn msix_control_value(cur: u32, enabled: bool) -> u32 {
    if enabled {
        (cur | MSIX_ENABLE) & !MSIX_FUNCTION_MASK
    } else {
        (cur & !MSIX_ENABLE) | MSIX_FUNCTION_MASK
    }
}

/// Compute MSI-X enable with all function vectors masked.
/// # C: O(1)
pub const fn msix_control_enable_masked(cur: u32) -> u32 {
    cur | MSIX_ENABLE | MSIX_FUNCTION_MASK
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MsixTeardownStep {
    MaskEntry(usize),
    DisableFunction,
    DisableMemBusMaster,
}

/// Emit Linux-style MSI-X teardown ordering for one PCI function.
///
/// All table entries are masked before function MSI-X is disabled; PCI command
/// memory/bus-master decode drops only after MSI-X is off.
/// # C: O(N_entries)
pub fn emit_msix_teardown_steps<F: FnMut(MsixTeardownStep)>(entries: usize, mut f: F) {
    let mut idx = 0usize;
    while idx < entries {
        f(MsixTeardownStep::MaskEntry(idx));
        idx += 1;
    }
    if entries != 0 {
        f(MsixTeardownStep::DisableFunction);
    }
    f(MsixTeardownStep::DisableMemBusMaster);
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

#[cfg(test)]
mod msi_tests {
    use super::*;
    use std::sync::Mutex;

    struct Config {
        words: Mutex<[u32; 1024]>,
    }

    impl Config {
        fn new() -> Self { Self { words: Mutex::new([0; 1024]) } }
    }

    impl ConfigSpaceReader for Config {
        fn read32(&self, _bdf: Bdf, offset: u8) -> u32 {
            self.words.lock().unwrap()[offset as usize / 4]
        }
        fn write32(&self, _bdf: Bdf, offset: u8, val: u32) {
            self.words.lock().unwrap()[offset as usize / 4] = val;
        }
        fn read32_ext(&self, _bdf: Bdf, offset: u16) -> u32 {
            self.words.lock().unwrap()[offset as usize / 4]
        }
        fn write32_ext(&self, _bdf: Bdf, offset: u16, val: u32) {
            self.words.lock().unwrap()[offset as usize / 4] = val;
        }
    }

    const BDF: Bdf = Bdf { bus: 0, device: 1, function: 0 };
    const CAP: u8 = 0x80;

    #[test]
    fn dsn_is_read_from_the_extended_capability_chain() {
        let cfg = Config::new();
        cfg.write32_ext(BDF, 0x100, 0x120 << 20 | 1);
        cfg.write32_ext(BDF, 0x120, EXT_CAP_ID_DSN as u32);
        cfg.write32_ext(BDF, 0x124, 0x5566_7788);
        cfg.write32_ext(BDF, 0x128, 0x1122_3344);
        assert_eq!(device_serial_number(&cfg, BDF), Some(0x1122_3344_5566_7788));
    }

    #[test]
    fn program_single_64_bit_msi_preserves_reserved_data_half() {
        let cfg = Config::new();
        cfg.write32(BDF, CAP, CAP_ID_MSI as u32 | (0x01B5u32 << 16));
        cfg.write32(BDF, CAP + MSI_64_MESSAGE_DATA_CFG_OFF, 0xA5A5_0000);
        cfg.write32(BDF, CAP + MSI_64_MASK_BITS_CFG_OFF, u32::MAX);
        let cap = decode_msi_cap(&cfg, BDF, CAP).unwrap();
        assert!(cap.enabled);
        assert_eq!(cap.multiple_message_capable, 2);
        assert_eq!(cap.multiple_message_enabled, 3);
        assert!(cap.address_64);
        assert!(cap.per_vector_mask);

        assert!(program_msi_single(&cfg, BDF, CAP, 0x1_FEE0_0000, 0x51));
        assert_eq!(cfg.read32(BDF, CAP + 4), 0xFEE0_0000);
        assert_eq!(cfg.read32(BDF, CAP + 8), 1);
        assert_eq!(cfg.read32(BDF, CAP + 12), 0xA5A5_0051);
        assert_eq!(
            cfg.read32(BDF, CAP + MSI_64_MASK_BITS_CFG_OFF),
            u32::MAX & !MSI_VECTOR_ZERO_MASK,
        );
        let programmed = cfg.read32(BDF, CAP);
        assert_ne!(programmed & MSI_ENABLE, 0);
        assert_eq!(programmed & MSI_MME_MASK, 0);
        assert!(disable_msi(&cfg, BDF, CAP));
        assert_eq!(cfg.read32(BDF, CAP) & MSI_ENABLE, 0);
    }

    #[test]
    fn program_32_bit_msi_rejects_high_address_and_wide_data() {
        let cfg = Config::new();
        cfg.write32(BDF, CAP, CAP_ID_MSI as u32);
        assert!(!program_msi_single(&cfg, BDF, CAP, 1u64 << 32, 0x51));
        assert!(!program_msi_single(&cfg, BDF, CAP, 0xFEE0_0000, 1u32 << 16));
        assert!(program_msi_single(&cfg, BDF, CAP, 0xFEE0_0000, 0x51));
        assert_eq!(cfg.read32(BDF, CAP + 8) & 0xFFFF, 0x51);
    }
}
