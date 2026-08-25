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

const BDF: Bdf = Bdf { segment: 0, bus: 0, device: 1, function: 0 };
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
fn acs_requires_every_isolation_capability_and_control() {
    let cfg = Config::new();
    cfg.write32_ext(BDF, 0x100, EXT_CAP_ID_ACS as u32);
    cfg.write32_ext(BDF, 0x104, u32::from(ACS_ISOLATION_FLAGS) | (u32::from(ACS_ISOLATION_FLAGS) << 16));
    assert!(acs_isolation_enabled(&cfg, BDF));
    cfg.write32_ext(BDF, 0x104, u32::from(ACS_ISOLATION_FLAGS) | (u32::from(ACS_ISOLATION_FLAGS & !0x10) << 16));
    assert!(!acs_isolation_enabled(&cfg, BDF));
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
