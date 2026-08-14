// Register and descriptor ABI for the Intel legacy e1000 DMA register file.
// All ring decisions stay host-testable in this module.

/// PCI IDs owned by the legacy `e1000` controller path, not `e1000e` or `igb`.
///
/// The reset sequence in this crate is 82540-class-specific. PCH integrated
/// NICs and 82580-class adapters have superficially similar descriptor
/// registers but require Linux's separate `e1000e` and `igb` hardware paths,
/// so they must remain unbound until those drivers exist. # C: O(1)
pub const INTEL_VENDOR: u16 = 0x8086;
pub const ETHERNET_CLASS: u32 = 0x02_00_00;
pub const E1000_82540EP_LP: u16 = 0x101e;
pub const LEGACY_PCI_IDS: &[u16] = &[
    0x100e, 0x100f, 0x1015, 0x1016, 0x1017, 0x1018, 0x1075, 0x1076,
    0x1077, 0x1078, 0x1079, 0x107a, E1000_82540EP_LP, 0x10b5,
];
pub const E1000E_82574_PCI_IDS: &[u16] = &[0x10d3, 0x10f6];

/// Match an Intel Ethernet function owned by the 82540 reset and DMA path. # C: O(n)
#[inline]
pub const fn legacy_pci_match(vendor_id: u16, class: u32, device_id: u16) -> bool {
    vendor_id == INTEL_VENDOR && class == ETHERNET_CLASS && legacy_pci_id_supported(device_id)
}

/// Admit a PCI ID only when the legacy reset path programs its controller family. # C: O(n)
#[inline]
pub const fn legacy_pci_id_supported(device_id: u16) -> bool {
    let mut index = 0;
    while index < LEGACY_PCI_IDS.len() {
        if LEGACY_PCI_IDS[index] == device_id { return true; }
        index += 1;
    }
    false
}

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
pub const EECD: u64 = 0x00010;
pub const EERD: u64 = 0x00014;
pub const MDIC: u64 = 0x00020;
pub const EXTCNF_CTRL: u64 = 0x00f00;
pub const FCT: u64 = 0x00030;
pub const FCAH: u64 = 0x00028;
pub const FCAL: u64 = 0x0002c;
pub const FCTTV: u64 = 0x00170;
pub const FCRTL: u64 = 0x02160;
pub const FCRTH: u64 = 0x02168;

pub const CTRL_RST: u32 = 1 << 26;
pub const CTRL_SLU: u32 = 1 << 6;
pub const CTRL_FRCSPD: u32 = 1 << 11;
pub const CTRL_FRCDPX: u32 = 1 << 12;
pub const CTRL_RFCE: u32 = 1 << 27;
pub const CTRL_TFCE: u32 = 1 << 28;
pub const EXTCNF_CTRL_MDIO_SW_OWNERSHIP: u32 = 1 << 5;
pub const EECD_NVM_REQUEST: u32 = 1 << 6;
pub const EECD_NVM_GRANT: u32 = 1 << 7;
pub const EECD_AUTO_READ_DONE: u32 = 1 << 9;
pub const EERD_START: u32 = 1;
pub const EERD_DONE: u32 = 1 << 1;
pub const EERD_ADDRESS_SHIFT: u32 = 2;
pub const EERD_DATA_SHIFT: u32 = 16;
pub const MDIC_REGISTER_SHIFT: u32 = 16;
pub const MDIC_PHY_SHIFT: u32 = 21;
pub const MDIC_WRITE: u32 = 1 << 26;
pub const MDIC_READ: u32 = 1 << 27;
pub const MDIC_READY: u32 = 1 << 28;
pub const MDIC_ERROR: u32 = 1 << 30;
pub const MDIC_REGISTER_MASK: u32 = 0x1f << MDIC_REGISTER_SHIFT;
pub const NVM_CHECKSUM_WORD: u16 = 0x003f;
pub const NVM_CHECKSUM_SUM: u16 = 0xbaba;
pub const BM_PHY_ADDRESS: u32 = 1;
pub const BM_PHY_ID_HIGH: u8 = 2;
pub const BM_PHY_ID_LOW: u8 = 3;
pub const BM_PHY_ID_R2: u32 = 0x0141_0cb1;
pub const MII_BMCR: u8 = 0;
pub const MII_BMSR: u8 = 1;
pub const MII_ADVERTISE: u8 = 4;
pub const MII_LPA: u8 = 5;
pub const MII_CTRL1000: u8 = 9;
pub const MII_BMCR_AN_ENABLE: u16 = 0x1000;
pub const MII_BMCR_AN_RESTART: u16 = 0x0200;
pub const MII_BMSR_AN_COMPLETE: u16 = 0x0020;
pub const MII_ADVERTISE_10_HALF: u16 = 0x0020;
pub const MII_ADVERTISE_10_FULL: u16 = 0x0040;
pub const MII_ADVERTISE_100_HALF: u16 = 0x0080;
pub const MII_ADVERTISE_100_FULL: u16 = 0x0100;
pub const MII_ADVERTISE_PAUSE: u16 = 0x0400;
pub const MII_ADVERTISE_ASYM_PAUSE: u16 = 0x0800;
pub const MII_ADVERTISE_SPEEDS: u16 = MII_ADVERTISE_10_HALF | MII_ADVERTISE_10_FULL | MII_ADVERTISE_100_HALF | MII_ADVERTISE_100_FULL;
pub const MII_CTRL1000_FULL: u16 = 0x0200;
pub const MII_CTRL1000_HALF: u16 = 0x0100;
pub const FLOW_CONTROL_TYPE: u32 = 0x8808;
pub const FLOW_CONTROL_ADDRESS_HIGH: u32 = 0x0000_0100;
pub const FLOW_CONTROL_ADDRESS_LOW: u32 = 0x00c2_8001;
pub const FLOW_CONTROL_PAUSE_TIME: u32 = 0x0680;
pub const FLOW_CONTROL_PBA_BYTES: u32 = 32 << 10;
pub const FLOW_CONTROL_HIGH_WATER: u32 = (FLOW_CONTROL_PBA_BYTES * 9 / 10) & !7;
pub const FLOW_CONTROL_LOW_WATER: u32 = FLOW_CONTROL_HIGH_WATER - 8;
pub const FCRTL_XON: u32 = 1 << 31;
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
pub const NVM_AUTO_READ_TIMEOUT_NS: u64 = 10_000_000;
pub const RESET_STATUS_POLL_NS: u64 = 1_000_000;

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

/// Encode one bounded EERD request. # C: O(1)
pub const fn eerd_command(word: u16) -> u32 { ((word as u32) << EERD_ADDRESS_SHIFT) | EERD_START }
/// Extract one completed EERD response word. # C: O(1)
pub const fn eerd_data(value: u32) -> u16 { (value >> EERD_DATA_SHIFT) as u16 }
/// Encode one MDIC transaction for the fixed BM PHY address. # C: O(1)
pub const fn mdic_command(register: u8, write: Option<u16>) -> u32 {
    let op = if write.is_some() { MDIC_WRITE } else { MDIC_READ };
    let data = match write { Some(value) => value, None => 0 };
    (data as u32) | ((register as u32) << MDIC_REGISTER_SHIFT) | (BM_PHY_ADDRESS << MDIC_PHY_SHIFT) | op
}
/// Accept the 64-word NVM checksum contract. # C: O(n)
pub fn nvm_checksum_valid(words: &[u16]) -> bool {
    words.len() == NVM_CHECKSUM_WORD as usize + 1 && words.iter().fold(0u16, |sum, word| sum.wrapping_add(*word)) == NVM_CHECKSUM_SUM
}
/// Decide whether the reset NVM auto-read completed. # C: O(1)
pub const fn e1000e_auto_read_done(eecd: u32) -> bool { eecd & EECD_AUTO_READ_DONE != 0 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum PauseMode { None, Rx, Tx, Full }
/// Resolve copper pause capability after auto-negotiation. # C: O(1)
pub(crate) const fn resolve_pause(advertisement: u16, partner: u16) -> PauseMode {
    let local_pause = advertisement & MII_ADVERTISE_PAUSE != 0;
    let local_asym = advertisement & MII_ADVERTISE_ASYM_PAUSE != 0;
    let peer_pause = partner & MII_ADVERTISE_PAUSE != 0;
    let peer_asym = partner & MII_ADVERTISE_ASYM_PAUSE != 0;
    if local_pause && peer_pause { PauseMode::Full }
    else if !local_pause && local_asym && peer_pause && peer_asym { PauseMode::Tx }
    else if local_pause && local_asym && !peer_pause && peer_asym { PauseMode::Rx }
    else { PauseMode::None }
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
        // The 82583 shares the e1000e PCI family but requires the BM PHY and
        // NVM initialization path before it may enter the generic ring path.
        assert!(!E1000E_82574_PCI_IDS.contains(&0x150c));
        assert_eq!(dma_mask(false), u32::MAX as u64);
        assert_eq!(dma_mask(true), u64::MAX);
        assert_eq!(E1000E_82574_RESET_NS, 25_000_000);
    }
    #[test]
    fn e82540ep_lp_probe_match_requires_the_legacy_intel_ethernet_tuple() {
        assert!(legacy_pci_id_supported(E1000_82540EP_LP));
        assert!(legacy_pci_match(INTEL_VENDOR, ETHERNET_CLASS, E1000_82540EP_LP));
        assert!(!legacy_pci_match(0x1234, ETHERNET_CLASS, E1000_82540EP_LP));
        assert!(!legacy_pci_match(INTEL_VENDOR, 0x01_08_02, E1000_82540EP_LP));
        assert!(!legacy_pci_match(INTEL_VENDOR, ETHERNET_CLASS, 0x1539));
    }
    #[test]
    fn e1000e_nvm_and_bm_phy_commands_preserve_the_hardware_abi() {
        assert_eq!(eerd_command(NVM_CHECKSUM_WORD), 0xfd);
        assert_eq!(eerd_data(0x1234_0002), 0x1234);
        assert_eq!(mdic_command(BM_PHY_ID_HIGH, None), 0x0822_0000);
        assert_eq!(mdic_command(BM_PHY_ID_LOW, Some(0xabcd)), 0x0423_abcd);
        let mut nvm = [0u16; NVM_CHECKSUM_WORD as usize + 1];
        nvm[NVM_CHECKSUM_WORD as usize] = NVM_CHECKSUM_SUM;
        assert!(nvm_checksum_valid(&nvm));
        nvm[0] = 1;
        assert!(!nvm_checksum_valid(&nvm));
        assert!(e1000e_auto_read_done(EECD_AUTO_READ_DONE));
        assert!(!e1000e_auto_read_done(0));
        assert_eq!(resolve_pause(MII_ADVERTISE_PAUSE, MII_ADVERTISE_PAUSE), PauseMode::Full);
        assert_eq!(resolve_pause(MII_ADVERTISE_ASYM_PAUSE, MII_ADVERTISE_PAUSE | MII_ADVERTISE_ASYM_PAUSE), PauseMode::Tx);
        assert_eq!(resolve_pause(MII_ADVERTISE_PAUSE | MII_ADVERTISE_ASYM_PAUSE, MII_ADVERTISE_ASYM_PAUSE), PauseMode::Rx);
        assert_eq!(resolve_pause(0, MII_ADVERTISE_PAUSE | MII_ADVERTISE_ASYM_PAUSE), PauseMode::None);
    }
}
