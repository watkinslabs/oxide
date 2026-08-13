// Register and descriptor ABI for the Intel legacy e1000 DMA register file.
// All ring decisions stay host-testable in this module.

/// PCI IDs owned by Linux's legacy `e1000` driver, not `e1000e` or `igb`.
///
/// The reset sequence in this crate is 82540-class-specific. PCH integrated
/// NICs and 82580-class adapters have superficially similar descriptor
/// registers but require Linux's separate `e1000e` and `igb` hardware paths,
/// so they must remain unbound until those drivers exist. # C: O(1)
pub const LEGACY_PCI_IDS: &[u16] = &[
    0x100e, 0x100f, 0x1015, 0x1016, 0x1017, 0x1018, 0x1075, 0x1076,
    0x1077, 0x1078, 0x1079, 0x107a, 0x10b5,
];
pub const E1000E_82574_PCI_IDS: &[u16] = &[0x10d3, 0x10f6];

/// Return the DMA aperture for one controller profile. # C: O(1)
#[inline]
pub const fn dma_mask(supports_64bit: bool) -> u64 {
    if supports_64bit { u64::MAX } else { u32::MAX as u64 }
}

pub const CTRL: u64 = 0x00000;
pub const ICR: u64 = 0x000c0;
#[allow(dead_code)]
pub const IMS: u64 = 0x000d0;
pub const IMC: u64 = 0x000d8;
pub const RCTL: u64 = 0x00100;
pub const TCTL: u64 = 0x00400;
pub const RDBAL: u64 = 0x02800;
pub const RDBAH: u64 = 0x02804;
pub const RDLEN: u64 = 0x02808;
pub const RDH: u64 = 0x02810;
pub const RDT: u64 = 0x02818;
pub const TDBAL: u64 = 0x03800;
pub const TDBAH: u64 = 0x03804;
pub const TDLEN: u64 = 0x03808;
pub const TDH: u64 = 0x03810;
pub const TDT: u64 = 0x03818;
pub const RAL0: u64 = 0x05400;
pub const RAH0: u64 = 0x05404;
pub const EXTCNF_CTRL: u64 = 0x00f00;

pub const CTRL_RST: u32 = 1 << 26;
pub const EXTCNF_CTRL_MDIO_SW_OWNERSHIP: u32 = 1 << 5;
pub const TCTL_PSP: u32 = 1 << 3;
pub const RCTL_EN: u32 = 1 << 1;
pub const RCTL_BAM: u32 = 1 << 15;
pub const RCTL_SECRC: u32 = 1 << 26;
pub const RCTL_SZ_2048: u32 = 0;
pub const TCTL_EN: u32 = 1 << 1;
pub const TCTL_CT_SHIFT: u32 = 4;
pub const TCTL_COLD_SHIFT: u32 = 12;
pub const IMS_RXT0: u32 = 1 << 7;
pub const IMS_RXO: u32 = 1 << 6;
pub const IMS_RXDMT0: u32 = 1 << 4;
pub const IMS_LSC: u32 = 1 << 2;
pub const IMS_TXDW: u32 = 1;
#[allow(dead_code)]
pub const IMS_DEFAULT: u32 = IMS_RXT0 | IMS_RXO | IMS_RXDMT0 | IMS_LSC | IMS_TXDW;

pub const RX_DESC_DONE: u8 = 1;
pub const TX_CMD_EOP: u8 = 1;
pub const TX_CMD_IFCS: u8 = 1 << 1;
pub const TX_CMD_RS: u8 = 1 << 3;
pub const TX_STATUS_DD: u8 = 1;
pub const RING_COUNT: usize = 256;
pub const BUFFER_BYTES: usize = 2048;
pub const ETH_MAX_FRAME: usize = 1518;
/// 82540-class EEPROM auto-read window after a global reset. # C: O(1)
pub const RESET_AUTO_READ_NS: u64 = 5_000_000;
pub const E1000E_82574_RESET_NS: u64 = 25_000_000;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct RxDesc {
    pub addr: u64,
    pub length: u16,
    pub checksum: u16,
    pub status: u8,
    pub errors: u8,
    pub special: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct TxDesc {
    pub addr: u64,
    pub length: u16,
    pub cso: u8,
    pub cmd: u8,
    pub status: u8,
    pub css: u8,
    pub special: u16,
}

/// Descriptor-ring register length. # C: O(1)
pub fn ring_bytes<T>() -> u32 { (core::mem::size_of::<T>() * RING_COUNT) as u32 }
/// Split one DMA address for low/high register programming. # C: O(1)
pub fn split_dma(pa: u64) -> (u32, u32) { (pa as u32, (pa >> 32) as u32) }
/// Convert an unbounded software cursor to one hardware ring tail. # C: O(1)
pub fn ring_tail(next: usize) -> u32 { (next % RING_COUNT) as u32 }

/// Admit only complete Ethernet frames fitting one hardware RX/TX slot. # C: O(1)
pub fn valid_frame_len(len: usize) -> bool { (14..=ETH_MAX_FRAME).contains(&len) }
/// Test whether an entire DMA allocation stays within the selected aperture. # C: O(1)
pub fn dma_range_fits(pa: u64, bytes: usize, dma_mask: u64) -> bool {
    bytes != 0 && pa.checked_add(bytes as u64 - 1).is_some_and(|end| end <= dma_mask)
}
/// Decode a station address from the first receive-address register pair. # C: O(1)
pub fn mac_from_rar(low: u32, high: u32) -> Option<[u8; 6]> {
    let mac = [low as u8, (low >> 8) as u8, (low >> 16) as u8, (low >> 24) as u8,
        high as u8, (high >> 8) as u8];
    (mac != [0; 6] && mac != [0xff; 6]).then_some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptor_abi_is_exactly_16_bytes() {
        assert_eq!(core::mem::size_of::<RxDesc>(), 16);
        assert_eq!(core::mem::size_of::<TxDesc>(), 16);
        assert_eq!(ring_bytes::<RxDesc>(), 4096);
    }
    #[test]
    fn dma_split_and_ring_wrap_are_lossless() {
        assert_eq!(split_dma(0x1234_5678_9abc_def0), (0x9abc_def0, 0x1234_5678));
        assert_eq!(ring_tail(RING_COUNT), 0);
        assert_eq!(ring_tail(RING_COUNT + 7), 7);
    }
    #[test]
    fn frame_and_mac_admission_are_explicit() {
        assert!(valid_frame_len(14)); assert!(valid_frame_len(ETH_MAX_FRAME));
        assert!(!valid_frame_len(13)); assert!(!valid_frame_len(ETH_MAX_FRAME + 1));
        assert_eq!(mac_from_rar(0x3322_1100, 0x5544), Some([0, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert_eq!(mac_from_rar(0, 0), None);
        assert!(dma_range_fits(0xffff_f000, 4096, dma_mask(false)));
        assert!(!dma_range_fits(0xffff_f000, 4097, dma_mask(false)));
        assert!(dma_range_fits(1 << 40, 4096, dma_mask(true)));
    }
    #[test]
    fn only_linux_legacy_e1000_ids_match_the_82540_reset_path() {
        assert!(LEGACY_PCI_IDS.contains(&0x100e));
        assert!(LEGACY_PCI_IDS.contains(&0x10b5));
        // e1000e: PCH integrated devices.
        assert!(!LEGACY_PCI_IDS.contains(&0x10ea));
        assert!(!LEGACY_PCI_IDS.contains(&0x1502));
        // igb: 82580 devices.
        assert!(!LEGACY_PCI_IDS.contains(&0x150e));
        assert!(E1000E_82574_PCI_IDS.contains(&0x10d3));
        assert!(!E1000E_82574_PCI_IDS.contains(&0x10ea));
        assert_eq!(dma_mask(false), u32::MAX as u64);
        assert_eq!(dma_mask(true), u64::MAX);
        assert_eq!(E1000E_82574_RESET_NS, 25_000_000);
    }
}
