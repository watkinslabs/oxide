// AHCI HBA + port register layout and the pure bit-packing / FIS-encode /
// IDENTIFY-decode helpers (AHCI 1.3.1 §3 HBA regs, §4 port regs; SATA/ATA8
// H2D Register FIS + IDENTIFY DEVICE word layout). Everything here is
// arithmetic only — no MMIO — so it host-tests without a boot. The MMIO/port
// mechanics that USE these live in `port.rs`.

/// Generic HBA (global) register byte offsets in the ABAR (AHCI §3.1).
pub const HBA_CAP:  u64 = 0x00; // Host Capabilities
pub const HBA_GHC:  u64 = 0x04; // Global Host Control
pub const HBA_IS:   u64 = 0x08; // Interrupt Status (port bitmap)
pub const HBA_PI:   u64 = 0x0C; // Ports Implemented (bitmap)
pub const HBA_VS:   u64 = 0x10; // Version

/// GHC bits (AHCI §3.1.2).
pub const GHC_HR: u32 = 1 << 0;  // HBA Reset
pub const GHC_IE: u32 = 1 << 1;  // Interrupt Enable
pub const GHC_AE: u32 = 1 << 31; // AHCI Enable

/// Per-port register block base + stride (AHCI §3.3): port N regs live at
/// ABAR + 0x100 + N*0x80.
pub const PORT_BASE:   u64 = 0x100;
pub const PORT_STRIDE: u64 = 0x80;

/// Per-port register byte offsets, relative to the port block (AHCI §3.3).
pub const P_CLB:  u64 = 0x00; // Command List Base (1 KiB aligned)
pub const P_CLBU: u64 = 0x04; // Command List Base upper 32
pub const P_FB:   u64 = 0x08; // FIS Base (256 B aligned)
pub const P_FBU:  u64 = 0x0C; // FIS Base upper 32
pub const P_IS:   u64 = 0x10; // Interrupt Status
pub const P_IE:   u64 = 0x14; // Interrupt Enable
pub const P_CMD:  u64 = 0x18; // Command and Status
pub const P_TFD:  u64 = 0x20; // Task File Data
pub const P_SIG:  u64 = 0x24; // Signature
pub const P_SSTS: u64 = 0x28; // SATA Status (SStatus)
pub const P_SCTL: u64 = 0x2C; // SATA Control
pub const P_SERR: u64 = 0x30; // SATA Error
pub const P_SACT: u64 = 0x34; // SATA Active
pub const P_CI:   u64 = 0x38; // Command Issue (bit per slot)

/// PxCMD bits (AHCI §3.3.7).
pub const CMD_ST:  u32 = 1 << 0;  // Start
pub const CMD_FRE: u32 = 1 << 4;  // FIS Receive Enable
pub const CMD_FR:  u32 = 1 << 14; // FIS Receive Running
pub const CMD_CR:  u32 = 1 << 15; // Command List Running

/// PxTFD status bits (AHCI §3.3.8 — the ATA status register image).
pub const TFD_ERR: u32 = 1 << 0; // Error
pub const TFD_DRQ: u32 = 1 << 3; // Data Request
pub const TFD_BSY: u32 = 1 << 7; // Busy

/// PxSIG value for a non-port-multiplier SATA disk (AHCI §3.3.9).
pub const SIG_SATA_DISK: u32 = 0x0000_0101;

/// PxSSTS DET (device detection) in bits 3:0: 3 = device present + PHY up.
pub const SSTS_DET_MASK:  u32 = 0xF;
pub const SSTS_DET_READY: u32 = 0x3;

/// H2D Register FIS type byte (SATA spec §10.3.4).
pub const FIS_TYPE_H2D: u8 = 0x27;
/// FIS byte 1 bit 7 = C (command, not control) — set for a command FIS.
pub const FIS_H2D_C: u8 = 1 << 7;

/// ATA commands used here (ATA8-ACS).
pub const ATA_IDENTIFY:      u8 = 0xEC;
pub const ATA_READ_DMA_EXT:  u8 = 0x25;
pub const ATA_WRITE_DMA_EXT: u8 = 0x35;
pub const ATA_FLUSH_EXT:     u8 = 0xEA;

/// Device register LBA-mode bit (bit 6) for the H2D FIS.
pub const ATA_DEV_LBA: u8 = 0x40;

/// Byte offset (from ABAR) of port `n`'s register block. # C: O(1)
#[inline]
pub fn port_off(n: u32) -> u64 { PORT_BASE + (n as u64) * PORT_STRIDE }

/// Byte offset (from ABAR) of port `n`'s register `reg`. # C: O(1)
#[inline]
pub fn port_reg(n: u32, reg: u64) -> u64 { port_off(n) + reg }

/// Pack a Command Header dword0 (AHCI §4.2.2): CFL (command-FIS length in
/// dwords, bits 4:0), `W` write bit (bit 6), PRDTL (PRD table length in
/// entries, bits 31:16). Other optional bits (A/P/R/B/C/PMP) left 0.
/// # C: O(1)
#[inline]
pub fn cmd_header_dw0(cfl_dwords: u32, write: bool, prdtl: u32) -> u32 {
    (cfl_dwords & 0x1F)
        | (if write { 1u32 << 6 } else { 0 })
        | ((prdtl & 0xFFFF) << 16)
}

/// Encode an H2D Register FIS into a 20-byte (5-dword) command-FIS image.
/// `cmd` is the ATA command; `lba` is the 48-bit LBA; `count` is the sector
/// count (0 means 65536 per ATA, but callers cap below that). `device` is
/// the device register (LBA mode = 0x40). Returns the 20 raw bytes; bytes
/// beyond index 19 of the command table's CFIS region stay zero.
/// AHCI/SATA H2D Register FIS layout (SATA §10.3.4):
///   b0 = 0x27, b1 = 0x80|PMP (C bit), b2 = command, b3 = features[7:0],
///   b4..b6 = LBA[23:0], b7 = device,
///   b8..b10 = LBA[47:24], b11 = features[15:8],
///   b12 = count[7:0], b13 = count[15:8], b14 = ICC, b15 = control,
///   b16..b19 = reserved.
/// # C: O(1)
#[inline]
pub fn h2d_fis(cmd: u8, lba: u64, count: u16, device: u8) -> [u8; 20] {
    let mut f = [0u8; 20];
    f[0] = FIS_TYPE_H2D;
    f[1] = FIS_H2D_C;            // C=1, PMP=0
    f[2] = cmd;
    f[3] = 0;                    // features[7:0]
    f[4] = (lba & 0xFF) as u8;
    f[5] = ((lba >> 8) & 0xFF) as u8;
    f[6] = ((lba >> 16) & 0xFF) as u8;
    f[7] = device;
    f[8] = ((lba >> 24) & 0xFF) as u8;
    f[9] = ((lba >> 32) & 0xFF) as u8;
    f[10] = ((lba >> 40) & 0xFF) as u8;
    f[11] = 0;                   // features[15:8]
    f[12] = (count & 0xFF) as u8;
    f[13] = ((count >> 8) & 0xFF) as u8;
    f
}

/// Decode the LBA sector count from an IDENTIFY DEVICE buffer (256 u16
/// words, little-endian on the wire → already host u16 here). Prefers the
/// 48-bit count (words 100..103) when word 83 bit 10 (LBA48 supported) is
/// set and the value is non-zero; else the 28-bit count (words 60..61).
/// `words` must be ≥ 104 long. # C: O(1)
#[inline]
pub fn identify_sector_count(words: &[u16]) -> u64 {
    let lba28 = (words[60] as u64) | ((words[61] as u64) << 16);
    let lba48 = (words[100] as u64)
        | ((words[101] as u64) << 16)
        | ((words[102] as u64) << 32)
        | ((words[103] as u64) << 48);
    let lba48_supported = (words[83] & (1 << 10)) != 0;
    if lba48_supported && lba48 != 0 { lba48 } else { lba28 }
}

/// Logical sector size from an IDENTIFY DEVICE buffer. Word 106 bit 14 set
/// + bit 12 set ⇒ logical sector > 512 B, size = words[117..118] in u16
/// units ×2 bytes. Otherwise 512. `words` must be ≥ 118 long. # C: O(1)
#[inline]
pub fn identify_sector_size(words: &[u16]) -> u32 {
    let w106 = words[106];
    if (w106 & (1 << 14)) != 0 && (w106 & (1 << 13)) == 0 && (w106 & (1 << 12)) != 0 {
        let words_per_sector = (words[117] as u32) | ((words[118] as u32) << 16);
        if words_per_sector != 0 { return words_per_sector * 2; }
    }
    512
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_offset_math() {
        // Port 0 regs at ABAR+0x100; port 1 at +0x180.
        assert_eq!(port_off(0), 0x100);
        assert_eq!(port_off(1), 0x180);
        assert_eq!(port_off(2), 0x200);
        // PxCI of port 0 / port 3.
        assert_eq!(port_reg(0, P_CI), 0x138);
        assert_eq!(port_reg(3, P_CI), 0x100 + 3 * 0x80 + 0x38);
        // PxSSTS of port 1.
        assert_eq!(port_reg(1, P_SSTS), 0x180 + 0x28);
    }

    #[test]
    fn cmd_header_packing() {
        // 5-dword H2D FIS, read, PRDTL=1.
        let dw0 = cmd_header_dw0(5, false, 1);
        assert_eq!(dw0 & 0x1F, 5);          // CFL
        assert_eq!((dw0 >> 6) & 1, 0);      // W=0
        assert_eq!((dw0 >> 16) & 0xFFFF, 1); // PRDTL
        // write variant sets W.
        let dw0w = cmd_header_dw0(5, true, 1);
        assert_eq!((dw0w >> 6) & 1, 1);
        // PRDTL field is the upper 16 bits.
        assert_eq!(cmd_header_dw0(5, false, 8) >> 16, 8);
    }

    #[test]
    fn h2d_fis_identify() {
        // IDENTIFY: no LBA/count, device 0.
        let f = h2d_fis(ATA_IDENTIFY, 0, 0, 0);
        assert_eq!(f[0], 0x27);
        assert_eq!(f[1], 0x80);            // C bit
        assert_eq!(f[2], 0xEC);
        assert_eq!(&f[4..7], &[0, 0, 0]);
        assert_eq!(f[12], 0);
    }

    #[test]
    fn h2d_fis_read_lba48() {
        // READ DMA EXT, LBA = 0x0001_0203_0405, count 8, LBA mode device.
        let f = h2d_fis(ATA_READ_DMA_EXT, 0x0001_0203_0405, 8, ATA_DEV_LBA);
        assert_eq!(f[2], 0x25);
        assert_eq!(f[7], 0x40);            // device LBA bit
        // LBA[23:0] in b4..b6, LBA[47:24] in b8..b10.
        assert_eq!(f[4], 0x05);
        assert_eq!(f[5], 0x04);
        assert_eq!(f[6], 0x03);
        assert_eq!(f[8], 0x02);
        assert_eq!(f[9], 0x01);
        assert_eq!(f[10], 0x00);
        // count[7:0]=8, count[15:8]=0.
        assert_eq!(f[12], 8);
        assert_eq!(f[13], 0);
    }

    #[test]
    fn identify_count_lba48_preferred() {
        let mut w = [0u16; 256];
        // LBA48 supported (word 83 bit 10) + a 48-bit count.
        w[83] = 1 << 10;
        w[100] = 0x4000; w[101] = 0x0001; // 0x1_4000 = 81920 sectors
        // a stale/smaller LBA28 value that must be ignored.
        w[60] = 0x2000; w[61] = 0;
        assert_eq!(identify_sector_count(&w), 0x1_4000);
    }

    #[test]
    fn identify_count_lba28_fallback() {
        let mut w = [0u16; 256];
        // LBA48 NOT supported → use words 60-61.
        w[60] = 0x8000; w[61] = 0x0000; // 32768 sectors
        w[100] = 0xFFFF; w[101] = 0xFFFF; // present but must be ignored
        assert_eq!(identify_sector_count(&w), 0x8000);
        // LBA48 supported but zero → fall back to LBA28 too.
        w[83] = 1 << 10;
        w[100] = 0; w[101] = 0; w[102] = 0; w[103] = 0;
        assert_eq!(identify_sector_count(&w), 0x8000);
    }

    #[test]
    fn identify_size_default_512() {
        let w = [0u16; 256];
        assert_eq!(identify_sector_size(&w), 512);
    }

    #[test]
    fn identify_size_4k() {
        let mut w = [0u16; 256];
        // word 106: bit 14 set (word valid), bit 13 clear (not multiple
        // logical per physical relevant here), bit 12 set (logical > 512).
        w[106] = (1 << 14) | (1 << 12);
        w[117] = 2048; w[118] = 0; // 2048 words = 4096 bytes
        assert_eq!(identify_sector_size(&w), 4096);
    }
}
