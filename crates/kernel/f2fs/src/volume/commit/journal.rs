use super::*;

pub fn p16(b: &mut [u8], at: usize, v: u16) { b[at..at + 2].copy_from_slice(&v.to_le_bytes()); }
pub fn p32(b: &mut [u8], at: usize, v: u32) { b[at..at + 4].copy_from_slice(&v.to_le_bytes()); }
pub fn p64(b: &mut [u8], at: usize, v: u64) { b[at..at + 8].copy_from_slice(&v.to_le_bytes()); }

/// Lay a node-table journal into a summary block. # C: O(entries)
pub fn write_nat_journal(block: &mut [u8], entries: &[(u32, NatEntry)]) {
    let off = crate::summary::at::NORMAL;
    let n = entries.len().min(NAT_JOURNAL_ENTRIES);
    p16(block, off, n as u16);
    for (i, (nid, e)) in entries.iter().take(n).enumerate() {
        let at = off + 2 + i * NAT_JOURNAL_ENTRY_SIZE;
        p32(block, at, *nid);
        block[at + 4 + NAT_VERSION] = e.version;
        p32(block, at + 4 + NAT_INO, e.ino);
        p32(block, at + 4 + NAT_BLOCK_ADDR, e.block_addr);
    }
}

/// Lay a segment-table journal into a summary block. # C: O(entries)
pub fn write_sit_journal(block: &mut [u8], entries: &[(u32, SitEntry)]) {
    let off = crate::summary::at::NORMAL;
    let n = entries.len().min(SIT_JOURNAL_ENTRIES);
    p16(block, off, n as u16);
    for (i, (segno, e)) in entries.iter().take(n).enumerate() {
        let at = off + 2 + i * SIT_JOURNAL_ENTRY_SIZE;
        p32(block, at, *segno);
        p16(block, at + 4 + SIT_VBLOCKS, e.vblocks);
        block[at + 4 + SIT_VALID_MAP..at + 4 + SIT_VALID_MAP + SIT_VBLOCK_MAP_SIZE]
            .copy_from_slice(&e.valid_map);
        p64(block, at + 4 + SIT_MTIME, e.mtime);
    }
}

/// How many logs' summaries a pack of this kind carries. # C: O(1)
pub fn summaries_in_pack(reason: CpReason) -> usize {
    match reason {
        CpReason::Umount => NR_CURSEG_PERSIST_TYPE,
        CpReason::Sync => NR_CURSEG_DATA_TYPE,
    }
}
