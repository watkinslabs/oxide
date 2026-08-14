// NVMe controller register layout + the pure bit-packing / decode helpers
// (NVMe 1.4 §3.1 controller registers, §5.15 Identify, §4.2 commands).
// Everything here is arithmetic only — no MMIO — so it host-tests without a
// boot. The MMIO/queue mechanics that USE these live in `queue.rs`.

/// Controller register byte offsets in the BAR0 register file (§3.1).
pub const REG_CAP:    u64 = 0x00; // Controller Capabilities (64-bit)
#[allow(dead_code, reason = "NVMe 1.4 §3.1 controller-register offset table kept complete; the version register is informational")]
pub const REG_VS:     u64 = 0x08; // Version (32-bit)
pub const REG_CC:     u64 = 0x14; // Controller Configuration (32-bit)
pub const REG_CSTS:   u64 = 0x1C; // Controller Status (32-bit)
pub const REG_AQA:    u64 = 0x24; // Admin Queue Attributes (32-bit)
pub const REG_ASQ:    u64 = 0x28; // Admin SQ Base Address (64-bit)
pub const REG_ACQ:    u64 = 0x30; // Admin CQ Base Address (64-bit)
/// Doorbell array base (§3.1.24); per-queue doorbells start here.
pub const REG_DOORBELL_BASE: u64 = 0x1000;

/// CC field bits.
pub const CC_EN:        u32 = 1 << 0;        // Enable
pub const CC_CSS_NVM:   u32 = 0 << 4;        // I/O Command Set = NVM
pub const CC_MPS_SHIFT: u32 = 7;             // Memory Page Size (2^(12+MPS))
pub const CC_IOSQES_SH: u32 = 16;            // I/O SQ entry size (log2)
pub const CC_IOCQES_SH: u32 = 20;            // I/O CQ entry size (log2)

/// CSTS field bits.
pub const CSTS_RDY: u32 = 1 << 0; // Ready
pub const CSTS_CFS: u32 = 1 << 1; // Controller Fatal Status

/// SQ/CQ entry sizes are log2(bytes): SQE = 64B (2^6), CQE = 16B (2^4).
pub const IOSQES_LOG2: u32 = 6;
pub const IOCQES_LOG2: u32 = 4;

/// Admin command opcodes (§5).
pub const ADMIN_CREATE_IO_SQ: u8 = 0x01;
pub const ADMIN_CREATE_IO_CQ: u8 = 0x05;
pub const ADMIN_IDENTIFY:     u8 = 0x06;
pub const ADMIN_ABORT:        u8 = 0x08;

/// NVM I/O command opcodes (§6).
pub const IO_FLUSH: u8 = 0x00;
pub const IO_WRITE: u8 = 0x01;
pub const IO_READ:  u8 = 0x02;

/// Host page size selected by CC.MPS=0 for queue and PRP addressing.
pub const NVME_PAGE_BYTES: u64 = 4096;
/// A one-page PRP list describes all pages after PRP1 in this data run.
pub const MAX_PRP_DATA_PAGES: u64 = 512;

/// Default DMA mask for an NVMe controller.
pub const DMA_MASK_64: u64 = u64::MAX;
/// Controllers with the address-width erratum must receive only 48-bit DMA.
pub const DMA_MASK_48: u64 = (1u64 << 48) - 1;

/// Select the controller DMA address mask from its PCI identity. # C: O(1)
pub const fn dma_mask(vendor_id: u16, device_id: u16) -> u64 {
    if vendor_id == 0x1d0f && matches!(device_id, 0x0061 | 0x0065 | 0x8061 | 0xcd00 | 0xcd01 | 0xcd02) {
        DMA_MASK_48
    } else {
        DMA_MASK_64
    }
}

/// Encoding selected for PRP2 after the first data page.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PrpSecond { None, DirectPage, List { entries: usize } }

/// Select the legal PRP2 form for a page-aligned contiguous transfer. # C: O(1)
#[inline]
pub fn prp_second(bytes: u64) -> Option<PrpSecond> {
    if bytes == 0 || bytes > NVME_PAGE_BYTES * MAX_PRP_DATA_PAGES { return None; }
    let pages = bytes.saturating_add(NVME_PAGE_BYTES - 1) / NVME_PAGE_BYTES;
    if pages == 1 { Some(PrpSecond::None) }
    else if pages == 2 { Some(PrpSecond::DirectPage) }
    else { Some(PrpSecond::List { entries: (pages - 1) as usize }) }
}

/// Identify CNS values (§5.15.1).
pub const CNS_NAMESPACE:  u32 = 0x00;
pub const CNS_CONTROLLER: u32 = 0x01;
pub const CNS_ACTIVE_NAMESPACE_LIST: u32 = 0x02;

/// Byte containing the controller's 0-based Abort Command Limit in an
/// Identify-Controller payload. The host may have this many Abort commands
/// outstanding, so a serialized timeout worker always stays within it.
pub const ID_CTRL_ACL_BYTE: usize = 258;

/// Return the controller's concurrent Admin-Abort limit. A valid controller
/// encodes this as a zero-based value, so even zero permits one command.
/// # C: O(1)
pub fn abort_limit_from_identify(bytes: &[u8]) -> Option<u16> {
    bytes.get(ID_CTRL_ACL_BYTE).map(|acl| u16::from(*acl) + 1)
}

/// Return the first nonzero namespace ID from one active-namespace list page.
/// # C: O(namespace-list entries)
pub fn first_active_namespace(bytes: &[u8]) -> Option<u32> {
    for word in bytes.chunks_exact(4) {
        let nsid = u32::from_le_bytes(word.try_into().ok()?);
        if nsid != 0 { return Some(nsid); }
    }
    None
}

/// CREATE I/O CQ CDW11 bits: physically contiguous and interrupt enabled.
pub const CREATE_CQ_PHYS_CONTIG: u32 = 1 << 0;
pub const CREATE_CQ_IRQ_ENABLED: u32 = 1 << 1;
pub const CREATE_CQ_VECTOR_SHIFT: u32 = 16;

/// Pack CREATE I/O CQ CDW11 for a non-polled queue. # C: O(1)
#[inline]
pub fn create_io_cq_flags(vector: u16) -> u32 {
    CREATE_CQ_PHYS_CONTIG | CREATE_CQ_IRQ_ENABLED
        | ((vector as u32) << CREATE_CQ_VECTOR_SHIFT)
}

/// Decode CAP.DSTRD (doorbell stride, bits 35:32). Each doorbell is then
/// `4 << DSTRD` bytes apart (NVMe §3.1.1).
/// # C: O(1)
#[inline]
pub fn cap_dstrd(cap: u64) -> u32 { ((cap >> 32) & 0xF) as u32 }

/// Decode CAP.MQES (max queue entries supported, bits 15:0; 0-based →
/// +1 for the real maximum). # C: O(1)
#[inline]
pub fn cap_mqes(cap: u64) -> u32 { ((cap & 0xFFFF) as u32) + 1 }

/// Clamp a desired I/O queue depth to CAP.MQES. Admin queue depth is
/// independently programmed through AQA and is not governed by MQES.
/// # C: O(1)
#[inline]
pub fn io_queue_entries(cap: u64, desired: u32) -> u32 {
    desired.min(cap_mqes(cap))
}

/// Decode CAP.TO (timeout, bits 31:24) in units of 500 ms — the worst-case
/// time the controller may take to set/clear CSTS.RDY. # C: O(1)
#[inline]
pub fn cap_to_ms(cap: u64) -> u64 { (((cap >> 24) & 0xFF) as u64) * 500 }

/// Byte offset (from BAR0) of a queue's doorbell register. `qid` is the
/// queue pair id (0 = admin); `is_cq` selects the completion (true) vs
/// submission (false) doorbell. Layout: SQ0TDBL, CQ0HDBL, SQ1TDBL, …,
/// each `4 << DSTRD` bytes apart (NVMe §3.1.24).
/// # C: O(1)
#[inline]
pub fn doorbell_off(qid: u32, is_cq: bool, dstrd: u32) -> u64 {
    let stride = 4u64 << dstrd;
    let slot = (2 * qid + (is_cq as u32)) as u64;
    REG_DOORBELL_BASE + slot * stride
}

/// Pack the CC value for enabling the controller: NVM command set, host
/// page size = 4 KiB (MPS=0), IOSQES=6, IOCQES=4, EN=1. # C: O(1)
#[inline]
pub fn cc_enable() -> u32 {
    CC_EN | CC_CSS_NVM
        | (0 << CC_MPS_SHIFT)
        | (IOSQES_LOG2 << CC_IOSQES_SH)
        | (IOCQES_LOG2 << CC_IOCQES_SH)
}

/// Pack AQA: ACQS (bits 27:16) and ASQS (bits 11:0), each a 0-based count
/// of entries (NVMe §3.1.8). `entries` is the real entry count per queue.
/// # C: O(1)
#[inline]
pub fn aqa(entries: u32) -> u32 {
    let z = entries.saturating_sub(1) & 0xFFF;
    (z << 16) | z
}

/// Decode an LBA Format's LBADS (LBA Data Size, log2 bytes) into a block
/// size. The Identify-Namespace LBA Format dword has LBADS in bits 23:16
/// (NVMe §5.15.2.1 LBAF). A LBADS < 9 (512B) is invalid → clamp to 512.
/// # C: O(1)
#[inline]
pub fn lba_size_from_lbaf(lbaf_dword: u32) -> u32 {
    let lbads = (lbaf_dword >> 16) & 0xFF;
    if lbads < 9 || lbads > 12 { 512 } else { 1u32 << lbads }
}

/// Completion-queue entry phase bit + status. CQE dword3 = (status<<16)|cid;
/// status bit 0 (of the 16-bit status field) is the Phase Tag, bits 15:1 are
/// the status code. Returns (phase, status_code, cid). # C: O(1)
#[inline]
pub fn cqe_decode(dword2: u32, dword3: u32) -> (bool, u16, u16) {
    let cid = (dword3 & 0xFFFF) as u16;
    let status_field = (dword3 >> 16) as u16;
    let phase = (status_field & 0x1) != 0;
    let status_code = status_field >> 1;
    // dword2 = (sq_id<<16)|sq_head; unused by the simple poller but decoded
    // for completeness so callers can validate the SQ head pointer.
    let _ = dword2;
    (phase, status_code, cid)
}

/// True when CQE status carries the cursor's expected phase tag. # C: O(1)
#[inline]
pub fn cqe_pending(dword3: u32, expected_phase: bool) -> bool {
    (((dword3 >> 16) & 1) != 0) == expected_phase
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dstrd_doorbell_math() {
        // DSTRD=0 → 4-byte stride. admin SQ tail @0x1000, admin CQ head @0x1004.
        assert_eq!(doorbell_off(0, false, 0), 0x1000);
        assert_eq!(doorbell_off(0, true,  0), 0x1004);
        // I/O qid=1 SQ tail @0x1008, CQ head @0x100C.
        assert_eq!(doorbell_off(1, false, 0), 0x1008);
        assert_eq!(doorbell_off(1, true,  0), 0x100C);
        // DSTRD=2 → stride 16. admin CQ head @0x1010, qid1 SQ tail @0x1020.
        assert_eq!(doorbell_off(0, true, 2), 0x1010);
        assert_eq!(doorbell_off(1, false, 2), 0x1020);
    }

    #[test]
    fn controller_dma_mask_selects_the_48_bit_erratum_only() {
        assert_eq!(dma_mask(0x1d0f, 0x0061), DMA_MASK_48);
        assert_eq!(dma_mask(0x1d0f, 0xcd02), DMA_MASK_48);
        assert_eq!(dma_mask(0x1d0f, 0x0062), DMA_MASK_64);
        assert_eq!(dma_mask(0x1b36, 0x0010), DMA_MASK_64);
    }

    #[test]
    fn identify_abort_limit_is_zero_based_and_requires_the_acl_byte() {
        let mut identify = [0u8; ID_CTRL_ACL_BYTE + 1];
        assert_eq!(abort_limit_from_identify(&identify[..ID_CTRL_ACL_BYTE]), None);
        assert_eq!(abort_limit_from_identify(&identify), Some(1));
        identify[ID_CTRL_ACL_BYTE] = 7;
        assert_eq!(abort_limit_from_identify(&identify), Some(8));
    }

    #[test]
    fn cap_field_decode() {
        // MQES (bits 15:0) 0-based: raw 0x3F → 64 entries.
        assert_eq!(cap_mqes(0x3F), 64);
        assert_eq!(io_queue_entries(0x0F, 32), 16);
        assert_eq!(io_queue_entries(0x3F, 32), 32);
        // DSTRD bits 35:32.
        assert_eq!(cap_dstrd(0x2_0000_0000), 2);
        // TO bits 31:24, units of 500ms: 0x14 → 20*500 = 10000ms.
        assert_eq!(cap_to_ms(0x14 << 24), 10_000);
    }

    #[test]
    fn cc_aqa_packing() {
        let cc = cc_enable();
        assert_eq!(cc & CC_EN, CC_EN);
        assert_eq!((cc >> CC_IOSQES_SH) & 0xF, 6);
        assert_eq!((cc >> CC_IOCQES_SH) & 0xF, 4);
        assert_eq!((cc >> CC_MPS_SHIFT) & 0xF, 0);
        // 32 entries → ASQS/ACQS = 31 in both halves.
        let a = aqa(32);
        assert_eq!(a & 0xFFF, 31);
        assert_eq!((a >> 16) & 0xFFF, 31);
    }

    #[test]
    fn lbaf_block_size() {
        // LBADS=9 → 512, LBADS=12 → 4096, LBADS=0 (unset) → clamp 512.
        assert_eq!(lba_size_from_lbaf(9 << 16), 512);
        assert_eq!(lba_size_from_lbaf(12 << 16), 4096);
        assert_eq!(lba_size_from_lbaf(0), 512);
        assert_eq!(lba_size_from_lbaf(20 << 16), 512); // out of range → clamp
    }

    #[test]
    fn cqe_phase_and_cid() {
        // status_field with phase bit set + status_code 0 + cid 7.
        let (phase, sc, cid) = cqe_decode(0, (0x0001u32 << 16) | 7);
        assert!(phase);
        assert_eq!(sc, 0);
        assert_eq!(cid, 7);
        // status_code = 4 (bits 15:1), phase clear.
        let (phase, sc, cid) = cqe_decode(0, ((4u32 << 1) << 16) | 0x0042);
        assert!(!phase);
        assert_eq!(sc, 4);
        assert_eq!(cid, 0x42);
        assert!(cqe_pending(0x0001 << 16, true));
        assert!(!cqe_pending(0x0001 << 16, false));
        assert!(cqe_pending(0, false));
    }

    #[test]
    fn io_completion_queue_enables_its_assigned_msi_vector() {
        let flags = create_io_cq_flags(7);
        assert_ne!(flags & CREATE_CQ_PHYS_CONTIG, 0);
        assert_ne!(flags & CREATE_CQ_IRQ_ENABLED, 0);
        assert_eq!(flags >> CREATE_CQ_VECTOR_SHIFT, 7);
    }

    #[test]
    fn prp_second_field_uses_direct_then_list_forms() {
        assert_eq!(prp_second(NVME_PAGE_BYTES), Some(PrpSecond::None));
        assert_eq!(prp_second(NVME_PAGE_BYTES + 1), Some(PrpSecond::DirectPage));
        assert_eq!(prp_second(3 * NVME_PAGE_BYTES), Some(PrpSecond::List { entries: 2 }));
        assert_eq!(prp_second(MAX_PRP_DATA_PAGES * NVME_PAGE_BYTES), Some(PrpSecond::List { entries: 511 }));
        assert_eq!(prp_second(MAX_PRP_DATA_PAGES * NVME_PAGE_BYTES + 1), None);
    }

    #[test]
    fn active_namespace_list_skips_empty_slots() {
        let mut list = [0u8; 16];
        list[4..8].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(first_active_namespace(&list), Some(7));
        assert_eq!(first_active_namespace(&[0; 8]), None);
    }
}
