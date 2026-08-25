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
#[allow(dead_code, reason = "AHCI 1.3.1 §3.1 global-register offset table kept complete; the version register is informational")]
pub const HBA_VS:   u64 = 0x10; // Version

/// GHC bits (AHCI §3.1.2).
pub const GHC_HR: u32 = 1 << 0;  // HBA Reset
pub const GHC_IE: u32 = 1 << 1;  // Interrupt Enable
pub const GHC_AE: u32 = 1 << 31; // AHCI Enable

/// CAP bits (AHCI §3.1.1).
pub const CAP_NP_MASK: u32 = 0x1F; // implemented port count minus one
pub const CAP_S64A: u32 = 1 << 31; // Supports 64-bit Addressing

/// AHCI PRDT byte-count field is 22 bits plus one, so one entry can describe
/// up to 4 MiB of a contiguous physical data run.
pub const PRDT_MAX_BYTES: u64 = 1 << 22;

/// Whether one DMA byte count fits one AHCI PRDT entry. # C: O(1)
#[inline]
pub fn prdt_entry_fits(bytes: u64) -> bool { bytes != 0 && bytes <= PRDT_MAX_BYTES }

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
#[allow(dead_code, reason = "AHCI 1.3.1 §3.3 port-register offset table kept complete; PxSACT is NCQ-only and this driver issues non-queued commands")]
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

/// PxIS/PxIE bits used by Linux's `DEF_PORT_IRQ` AHCI interrupt-enable set.
pub const PIS_DHRS: u32 = 1 << 0;
pub const PIS_PSS:  u32 = 1 << 1;
pub const PIS_DSS:  u32 = 1 << 2;
pub const PIS_SDBS: u32 = 1 << 3;
pub const PIS_UFS:  u32 = 1 << 4;
pub const PIS_DPS:  u32 = 1 << 5;
pub const PIS_PCS:  u32 = 1 << 6;
pub const PIS_PRCS: u32 = 1 << 22;
pub const PIS_IPMS: u32 = 1 << 23;
pub const PIS_IFS:  u32 = 1 << 27;
pub const PIS_HBDS: u32 = 1 << 28;
pub const PIS_HBFS: u32 = 1 << 29;
pub const PIS_TFES: u32 = 1 << 30;

pub const PIS_ERROR: u32 =
    PIS_UFS | PIS_PCS | PIS_PRCS | PIS_IPMS | PIS_IFS | PIS_HBDS | PIS_HBFS | PIS_TFES;
pub const PIS_ENABLE: u32 =
    PIS_ERROR | PIS_DPS | PIS_SDBS | PIS_DSS | PIS_PSS | PIS_DHRS;
/// Link-state-change causes that require process-context media inspection.
/// Mechanical-presence and power-management causes do not prove a SATA
/// device departed, so they are deliberately excluded.
pub const PIS_LINK_CHANGE: u32 = PIS_PCS | PIS_PRCS;

/// PxSIG value for a non-port-multiplier SATA disk (AHCI §3.3.9).
pub const SIG_SATA_DISK: u32 = 0x0000_0101;

/// PxSSTS DET (device detection) in bits 3:0: 3 = device present + PHY up.
pub const SSTS_DET_MASK:  u32 = 0xF;
pub const SSTS_DET_READY: u32 = 0x3;

/// Whether a sampled SATA status reports an online physical link. # C: O(1)
#[inline]
pub const fn link_is_online(sstatus: u32) -> bool {
    sstatus & SSTS_DET_MASK == SSTS_DET_READY
}

/// Whether an acknowledged port interrupt requires a live link inspection.
/// # C: O(1)
#[inline]
pub const fn irq_reports_link_change(pis: u32) -> bool {
    pis & PIS_LINK_CHANGE != 0
}

/// H2D Register FIS type byte (SATA spec §10.3.4).
pub const FIS_TYPE_H2D: u8 = 0x27;
/// D2H Register FIS type retained at the AHCI receive-buffer D2H slot.
pub const FIS_TYPE_D2H: u8 = 0x34;
/// FIS byte 1 bit 7 = C (command, not control) — set for a command FIS.
pub const FIS_H2D_C: u8 = 1 << 7;

/// ATA commands used here (ATA8-ACS).
pub const ATA_IDENTIFY:      u8 = 0xEC;
pub const ATA_READ_DMA_EXT:  u8 = 0x25;
pub const ATA_WRITE_DMA_EXT: u8 = 0x35;
pub const ATA_FLUSH_EXT:     u8 = 0xEA;

/// Device register LBA-mode bit (bit 6) for the H2D FIS.
pub const ATA_DEV_LBA: u8 = 0x40;
/// ATA device-select bit for the second legacy device position.
pub const ATA_DEV1: u8 = 0x10;

/// Offset of the received D2H Register FIS in an AHCI receive-FIS page.
pub const RFIS_D2H_OFFSET: usize = 0x40;

/// Byte offset (from ABAR) of port `n`'s register block. # C: O(1)
#[inline]
pub fn port_off(n: u32) -> u64 { PORT_BASE + (n as u64) * PORT_STRIDE }

/// Byte offset (from ABAR) of port `n`'s register `reg`. # C: O(1)
#[inline]
pub fn port_reg(n: u32, reg: u64) -> u64 { port_off(n) + reg }

/// Keep only PI bits representable by CAP.NP and the mapped ABAR aperture.
/// # C: O(1)
pub fn usable_port_map(cap: u32, ports_implemented: u32, abar_bytes: u64) -> u32 {
    let cap_ports = (cap & CAP_NP_MASK).saturating_add(1);
    let map_ports = abar_bytes.saturating_sub(PORT_BASE) / PORT_STRIDE;
    let count = core::cmp::min(u64::from(cap_ports), map_ports).min(32) as u32;
    let mask = if count == 32 { u32::MAX } else { (1u32 << count).saturating_sub(1) };
    ports_implemented & mask
}

/// Whether the complete DMA range is addressable by this HBA. # C: O(1)
#[inline]
pub fn dma_range_fits(cap: u32, pa: u64, bytes: u64) -> bool {
    let Some(last) = bytes.checked_sub(1).and_then(|span| pa.checked_add(span)) else {
        return false;
    };
    cap & CAP_S64A != 0 || last <= u32::MAX as u64
}

/// Highest DMA address accepted by this HBA. # C: O(1)
#[inline]
pub const fn dma_mask(cap: u32) -> u64 {
    if cap & CAP_S64A != 0 { u64::MAX } else { u32::MAX as u64 }
}

/// Whether one enabled port interrupt terminates slot-zero waiting. # C: O(1)
pub fn irq_finishes_slot(pis: u32, ci: u32, tfd: u32) -> bool {
    pis & PIS_ERROR != 0
        || tfd & TFD_ERR != 0
        || (pis & PIS_ENABLE != 0 && ci & 1 == 0)
}

/// Whether an interrupt terminates a command this driver has actually issued.
/// PxCI being idle does not itself imply ownership: an old port interrupt can
/// arrive after the next request prepared its wait state but before its
/// doorbell. Completion therefore requires explicit command ownership. # C: O(1)
#[inline]
pub fn irq_finishes_issued_slot(issued: bool, pis: u32, ci: u32, tfd: u32) -> bool {
    issued && irq_finishes_slot(pis, ci, tfd)
}

/// Whether completion state carries a terminal command error. # C: O(1)
pub fn irq_status_failed(pis: u32, tfd: u32) -> bool {
    pis & PIS_ERROR != 0 || tfd & TFD_ERR != 0
}

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

/// Encode one validated ATA taskfile into an AHCI H2D Register FIS. AHCI has
/// one device per active port, so the legacy device-one selector is cleared.
/// # C: O(1)
pub fn h2d_taskfile(taskfile: &ata::Taskfile) -> [u8; 20] {
    let mut f = [0u8; 20];
    f[0] = FIS_TYPE_H2D;
    f[1] = FIS_H2D_C;
    f[2] = taskfile.command;
    f[3] = taskfile.feature;
    f[4] = taskfile.lbal;
    f[5] = taskfile.lbam;
    f[6] = taskfile.lbah;
    f[7] = taskfile.device & !ATA_DEV1;
    f[8] = taskfile.hob_lbal;
    f[9] = taskfile.hob_lbam;
    f[10] = taskfile.hob_lbah;
    f[11] = taskfile.hob_feature;
    f[12] = taskfile.nsect;
    f[13] = taskfile.hob_nsect;
    f[16..20].copy_from_slice(&taskfile.auxiliary.to_le_bytes());
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

/// Decode the WCE bit after the caller has already extracted IDENTIFY word 85.
/// # C: O(1)
#[inline]
pub fn identify_write_cache_word(word: u16) -> bool {
    word & (1 << 5) != 0
}

/// Decode the ATA IDENTIFY DEVICE serial field (words 10..19). ATA strings
/// store each two-byte word with characters in high-byte, low-byte order even
/// though the word itself is little-endian in memory. Leading/trailing space
/// and NUL padding is not part of the identity. Returns the decoded bytes and
/// valid length; an all-padding field returns length 0. # C: O(1)
pub fn identify_serial(words: &[u16]) -> ([u8; 20], usize) {
    let mut raw = [0u8; 20];
    let mut i = 0usize;
    while i < 10 {
        let w = words[10 + i];
        raw[i * 2] = (w >> 8) as u8;
        raw[i * 2 + 1] = (w & 0xff) as u8;
        i += 1;
    }

    let mut start = 0usize;
    while start < raw.len() && (raw[start] == b' ' || raw[start] == 0) {
        start += 1;
    }
    let mut end = raw.len();
    while end > start && (raw[end - 1] == b' ' || raw[end - 1] == 0) {
        end -= 1;
    }

    let mut out = [0u8; 20];
    let mut len = 0usize;
    while start + len < end {
        out[len] = raw[start + len];
        len += 1;
    }
    (out, len)
}

#[cfg(test)]
mod tests;
