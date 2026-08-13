//! I225/I226 register and descriptor ABI.

pub const INTEL_VENDOR: u16 = 0x8086;
pub const ETHERNET_CLASS: u32 = 0x02_00_00;
pub const I225_LM: u16 = 0x15f2; pub const I225_V: u16 = 0x15f3; pub const I225_I: u16 = 0x15f8; pub const I220_V: u16 = 0x15f7;
pub const I225_K: u16 = 0x3100; pub const I225_K2: u16 = 0x3101; pub const I226_K: u16 = 0x3102; pub const I225_LMVP: u16 = 0x5502;
pub const I226_LMVP: u16 = 0x5503; pub const I225_IT: u16 = 0x0d9f; pub const I226_LM: u16 = 0x125b; pub const I226_V: u16 = 0x125c;
pub const I226_IT: u16 = 0x125d; pub const I221_V: u16 = 0x125e; pub const I226_BLANK_NVM: u16 = 0x125f; pub const I225_BLANK_NVM: u16 = 0x15fd;
pub const PCI_IDS: [u16; 16] = [I225_LM, I225_V, I225_I, I220_V, I225_K, I225_K2, I226_K, I225_LMVP,
    I226_LMVP, I225_IT, I226_LM, I226_V, I226_IT, I221_V, I226_BLANK_NVM, I225_BLANK_NVM];

pub const CTRL: u64 = 0x00000; pub const STATUS: u64 = 0x00008; pub const CTRL_EXT: u64 = 0x00018;
pub const EECD: u64 = 0x00010;
pub const ICR: u64 = 0x01500; pub const IMS: u64 = 0x01508; pub const IMC: u64 = 0x0150c;
pub const RCTL: u64 = 0x00100; pub const TCTL: u64 = 0x00400; pub const RAL0: u64 = 0x05400; pub const RAH0: u64 = 0x05404;
pub const RDBAL0: u64 = 0x0c000; pub const RDBAH0: u64 = 0x0c004; pub const RDLEN0: u64 = 0x0c008; pub const RDH0: u64 = 0x0c010; pub const RDT0: u64 = 0x0c018;
pub const SRRCTL0: u64 = 0x0c00c; pub const RXDCTL0: u64 = 0x0c028;
pub const TDBAL0: u64 = 0x0e000; pub const TDBAH0: u64 = 0x0e004; pub const TDLEN0: u64 = 0x0e008; pub const TDH0: u64 = 0x0e010; pub const TDT0: u64 = 0x0e018;
pub const TXDCTL0: u64 = 0x0e028;
pub const CTRL_RST: u32 = 1 << 26; pub const CTRL_EXT_DRV_LOAD: u32 = 1 << 28; pub const RCTL_EN: u32 = 1 << 1; pub const RCTL_BAM: u32 = 1 << 15;
pub const RCTL_SECRC: u32 = 1 << 26; pub const TCTL_EN: u32 = 1 << 1; pub const TCTL_PSP: u32 = 1 << 3;
pub const EECD_AUTO_RD: u32 = 1 << 9;
pub const ICR_TXDW: u32 = 1; pub const ICR_LSC: u32 = 1 << 2; pub const ICR_RXO: u32 = 1 << 6; pub const ICR_RXT0: u32 = 1 << 7;
pub const IMS_DEFAULT: u32 = ICR_TXDW | ICR_LSC | ICR_RXO | ICR_RXT0; pub const RAH_AV: u32 = 1 << 31;
pub const RXD_STAT_DD: u32 = 1;
pub const TXD_STAT_DD: u32 = 1;
pub const ADVTXD_DTYP_DATA: u32 = 0x0030_0000;
pub const ADVTXD_DCMD_EOP: u32 = 0x0100_0000;
pub const ADVTXD_DCMD_IFCS: u32 = 0x0200_0000;
pub const ADVTXD_DCMD_RS: u32 = 0x0800_0000;
pub const ADVTXD_DCMD_DEXT: u32 = 0x2000_0000;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct AdvRxDesc { pub packet_addr: u64, pub header_addr: u64 }
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct AdvRxWriteback { pub lower: u64, pub status_error: u32, pub length: u16, pub vlan: u16 }
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct AdvTxDesc { pub buffer_addr: u64, pub cmd_type_len: u32, pub olinfo_status: u32 }
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct AdvTxWriteback { pub reserved: u64, pub next_seq_seed: u32, pub status: u32 }

/// Tests the completed advanced RX descriptor's status and error word.
/// # C: O(1)
pub const fn rx_status_error(desc: &AdvRxWriteback) -> u32 { desc.status_error }

/// Tests whether an advanced RX descriptor has been completed by the device.
/// # C: O(1)
pub const fn rx_done(desc: &AdvRxWriteback) -> bool { desc.status_error & RXD_STAT_DD != 0 }

/// Tests whether an advanced TX descriptor has been completed by the device.
/// # C: O(1)
pub const fn tx_done(desc: &AdvTxWriteback) -> bool { desc.status & TXD_STAT_DD != 0 }

pub fn supported(vendor: u16, device: u16) -> bool { vendor == INTEL_VENDOR && PCI_IDS.contains(&device) }
pub const fn split_dma(dma: u64) -> (u32, u32) { (dma as u32, (dma >> 32) as u32) }
/// Releases driver ownership while preserving every firmware-owned control bit. # C: O(1)
pub const fn release_driver_control(ctrl_ext: u32) -> u32 { ctrl_ext & !CTRL_EXT_DRV_LOAD }

#[cfg(test)]
mod tests { use super::*;
    #[test] fn igc_ids_do_not_overlap_legacy_e1000() { assert!(supported(INTEL_VENDOR, I226_V)); assert!(!supported(INTEL_VENDOR, 0x100e)); }
    #[test] fn queue_zero_offsets_match_the_igc_window() { assert_eq!(RDBAL0, 0x0c000); assert_eq!(TDBAL0, 0x0e000); assert_eq!(ICR, 0x01500); }
    #[test] fn descriptors_are_hardware_sized() { assert_eq!(core::mem::size_of::<AdvRxDesc>(), 16); assert_eq!(core::mem::size_of::<AdvRxWriteback>(), 16); assert_eq!(core::mem::size_of::<AdvTxDesc>(), 16); assert_eq!(core::mem::size_of::<AdvTxWriteback>(), 16); }
    #[test] fn advanced_tx_command_requires_data_and_extension() { assert_eq!(ADVTXD_DTYP_DATA | ADVTXD_DCMD_DEXT, 0x2030_0000); }
    #[test] fn release_driver_control_preserves_firmware_state() { assert_eq!(release_driver_control(0xf123_4567 | CTRL_EXT_DRV_LOAD), 0xe123_4567); }
    #[test] fn completion_is_read_from_the_device_writeback_view() { let rx = AdvRxWriteback { status_error: RXD_STAT_DD, length: 1500, ..Default::default() }; let tx = AdvTxWriteback { status: TXD_STAT_DD, ..Default::default() }; assert!(rx_done(&rx)); assert_eq!(rx.length, 1500); assert!(tx_done(&tx)); }
}
