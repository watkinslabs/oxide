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
pub const ICR: u64 = 0x01500; pub const IMS: u64 = 0x01508; pub const IMC: u64 = 0x0150c;
pub const RCTL: u64 = 0x00100; pub const TCTL: u64 = 0x00400; pub const RAL0: u64 = 0x05400; pub const RAH0: u64 = 0x05404;
pub const RDBAL0: u64 = 0x0c000; pub const RDBAH0: u64 = 0x0c004; pub const RDLEN0: u64 = 0x0c008; pub const RDH0: u64 = 0x0c010; pub const RDT0: u64 = 0x0c018;
pub const TDBAL0: u64 = 0x0e000; pub const TDBAH0: u64 = 0x0e004; pub const TDLEN0: u64 = 0x0e008; pub const TDH0: u64 = 0x0e010; pub const TDT0: u64 = 0x0e018;
pub const CTRL_RST: u32 = 1 << 26; pub const CTRL_EXT_DRV_LOAD: u32 = 1 << 28; pub const RCTL_EN: u32 = 1 << 1; pub const RCTL_BAM: u32 = 1 << 15;
pub const RCTL_SECRC: u32 = 1 << 26; pub const TCTL_EN: u32 = 1 << 1; pub const TCTL_PSP: u32 = 1 << 3;
pub const ICR_TXDW: u32 = 1; pub const ICR_LSC: u32 = 1 << 2; pub const ICR_RXO: u32 = 1 << 6; pub const ICR_RXT0: u32 = 1 << 7;
pub const IMS_DEFAULT: u32 = ICR_TXDW | ICR_LSC | ICR_RXO | ICR_RXT0; pub const RAH_AV: u32 = 1 << 31;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct LegacyRxDesc { pub addr: u64, pub length: u16, pub checksum: u16, pub status: u8, pub errors: u8, pub special: u16 }
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct LegacyTxDesc { pub addr: u64, pub length: u16, pub cso: u8, pub cmd: u8, pub status: u8, pub css: u8, pub special: u16 }

pub fn supported(vendor: u16, device: u16) -> bool { vendor == INTEL_VENDOR && PCI_IDS.contains(&device) }
pub const fn split_dma(dma: u64) -> (u32, u32) { (dma as u32, (dma >> 32) as u32) }

#[cfg(test)]
mod tests { use super::*;
    #[test] fn igc_ids_do_not_overlap_legacy_e1000() { assert!(supported(INTEL_VENDOR, I226_V)); assert!(!supported(INTEL_VENDOR, 0x100e)); }
    #[test] fn queue_zero_offsets_match_the_igc_window() { assert_eq!(RDBAL0, 0x0c000); assert_eq!(TDBAL0, 0x0e000); assert_eq!(ICR, 0x01500); }
    #[test] fn descriptors_are_hardware_sized() { assert_eq!(core::mem::size_of::<LegacyRxDesc>(), 16); assert_eq!(core::mem::size_of::<LegacyTxDesc>(), 16); }
}
