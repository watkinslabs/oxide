//! The superblock, the checkpoint packs, and the two tables.

use alloc::vec;
use alloc::vec::Vec;

use crate::checksum;
use crate::flags::*;
use crate::uapi::*;

use super::*;

/// Write every metadata structure the volume needs. # C: O(table bytes)
pub fn write_all(b: &mut Builder) {
    write_nat(b);
    write_sit(b);
    write_super(b);
    write_pack(b, CP_BLKADDR, b.cp_version);
    let v2 = b.cp2_version.unwrap_or(b.cp_version.wrapping_sub(1));
    write_pack(b, CP_BLKADDR + BLKS_PER_SEG, v2);
}

/// Both superblock copies. # C: O(1)
pub fn write_super(b: &mut Builder) {
    let sb = super_bytes(b);
    for copy in 0..SUPER_COPIES {
        let at = copy as usize * BLKSIZE + SUPER_OFFSET;
        b.bytes[at..at + SUPER_SIZE].copy_from_slice(&sb);
    }
    if b.break_super0 {
        // One byte of the FIRST copy's body, past nothing else a reader looks
        // at, so the copy fails only its checksum.
        b.bytes[SUPER_OFFSET + SB_VOLUME_NAME] ^= 0xFF;
    }
}

/// One superblock copy's bytes, checksum included. # C: O(SUPER_SIZE)
pub fn super_bytes(b: &Builder) -> Vec<u8> {
    let mut s = vec![0u8; SUPER_SIZE];
    put32(&mut s, SB_MAGIC, MAGIC);
    put16(&mut s, SB_MAJOR_VER, 1);
    put16(&mut s, SB_MINOR_VER, 15);
    put32(&mut s, SB_LOG_SECTORSIZE, BLKSIZE_BITS);
    put32(&mut s, SB_LOG_SECTORS_PER_BLOCK, 0);
    put32(&mut s, SB_LOG_BLOCKSIZE, BLKSIZE_BITS);
    put32(&mut s, SB_LOG_BLOCKS_PER_SEG, LOG_BLKS_PER_SEG);
    put32(&mut s, SB_SEGS_PER_SEC, 1);
    put32(&mut s, SB_SECS_PER_ZONE, 1);
    put32(&mut s, SB_CHECKSUM_OFFSET, SB_CRC as u32);
    put64(&mut s, SB_BLOCK_COUNT, BLOCK_COUNT);
    put32(&mut s, SB_SECTION_COUNT, SEG_MAIN);
    put32(&mut s, SB_SEGMENT_COUNT, SEGMENT_COUNT);
    put32(&mut s, SB_SEGMENT_COUNT_CKPT, SEG_CKPT);
    put32(&mut s, SB_SEGMENT_COUNT_SIT, SEG_SIT);
    put32(&mut s, SB_SEGMENT_COUNT_NAT, SEG_NAT);
    put32(&mut s, SB_SEGMENT_COUNT_SSA, SEG_SSA);
    put32(&mut s, SB_SEGMENT_COUNT_MAIN, SEG_MAIN);
    put32(&mut s, SB_SEGMENT0_BLKADDR, CP_BLKADDR);
    put32(&mut s, SB_CP_BLKADDR, CP_BLKADDR);
    put32(&mut s, SB_SIT_BLKADDR, SIT_BLKADDR);
    put32(&mut s, SB_NAT_BLKADDR, NAT_BLKADDR);
    put32(&mut s, SB_SSA_BLKADDR, SSA_BLKADDR);
    put32(&mut s, SB_MAIN_BLKADDR, MAIN_BLKADDR);
    put32(&mut s, SB_ROOT_INO, b.root_ino);
    put32(&mut s, SB_NODE_INO, b.node_ino);
    put32(&mut s, SB_META_INO, b.meta_ino);
    s[SB_UUID..SB_UUID + SB_UUID_LEN].copy_from_slice(&b.uuid);
    for (i, u) in "oxide".encode_utf16().enumerate() {
        put16(&mut s, SB_VOLUME_NAME + i * 2, u);
    }
    put32(&mut s, SB_EXTENSION_COUNT, 2);
    s[SB_EXTENSION_LIST..SB_EXTENSION_LIST + 3].copy_from_slice(b"jpg");
    s[SB_EXTENSION_LIST + EXTENSION_LEN..SB_EXTENSION_LIST + EXTENSION_LEN + 3]
        .copy_from_slice(b"mp4");
    put32(&mut s, SB_CP_PAYLOAD, b.cp_payload);
    put32(&mut s, SB_FEATURE, b.feature);
    let crc = checksum::crc32(&s[..SB_CRC]);
    put32(&mut s, SB_CRC, crc);
    s
}

/// One checkpoint pack: head, summaries, tail. # C: O(pack blocks)
pub fn write_pack(b: &mut Builder, start: u32, version: u64) {
    let head = cp_bytes(b, version);
    b.put_block(start, &head);
    for i in 1..=b.cp_payload { b.put_block(start + i, &vec![0u8; BLKSIZE]); }
    write_summaries(b, start);
    b.put_block(start + CP_PACK_BLOCKS - 1, &head);
}

/// The checkpoint header block. # C: O(BLKSIZE)
pub fn cp_bytes(b: &Builder, version: u64) -> Vec<u8> {
    let mut c = vec![0u8; BLKSIZE];
    let large = b.cp_flags & CP_LARGE_NAT_BITMAP_FLAG != 0;
    put64(&mut c, CP_CHECKPOINT_VER, version);
    put64(&mut c, CP_USER_BLOCK_COUNT, u64::from(SEG_MAIN * BLKS_PER_SEG));
    put64(&mut c, CP_VALID_BLOCK_COUNT, b.valid_block_count);
    put32(&mut c, CP_FREE_SEGMENT_COUNT, SEG_MAIN - NR_CURSEG_PERSIST_TYPE as u32);
    // Each log gets a segment of its own, the way a formatter leaves them:
    // six logs sharing one segment would hand the same block to all six.
    for i in 0..NR_CURSEG_DATA_TYPE {
        put32(&mut c, CP_CUR_DATA_SEGNO + i * 4, i as u32);
        put16(&mut c, CP_CUR_DATA_BLKOFF + i * 2, if i == 0 { b.used_in_seg0() } else { 0 });
        c[CP_ALLOC_TYPE + i] = ALLOC_LFS;
    }
    for i in 0..NR_CURSEG_NODE_TYPE {
        let log = NR_CURSEG_DATA_TYPE + i;
        put32(&mut c, CP_CUR_NODE_SEGNO + i * 4, log as u32);
        put16(&mut c, CP_CUR_NODE_BLKOFF + i * 2, 0);
        c[CP_ALLOC_TYPE + log] = ALLOC_LFS;
    }
    put32(&mut c, CP_CKPT_FLAGS, b.cp_flags);
    put32(&mut c, CP_PACK_TOTAL_BLOCK_COUNT, CP_PACK_BLOCKS + b.cp_payload);
    put32(&mut c, CP_PACK_START_SUM, PACK_START_SUM + b.cp_payload);
    put32(&mut c, CP_VALID_NODE_COUNT, b.valid_node_count);
    put32(&mut c, CP_VALID_INODE_COUNT, b.valid_inode_count);
    put32(&mut c, CP_NEXT_FREE_NID, b.next_nid);
    put32(&mut c, CP_SIT_VER_BITMAP_BYTESIZE, BITMAP_BYTES);
    put32(&mut c, CP_NAT_VER_BITMAP_BYTESIZE, BITMAP_BYTES);
    // The large layout parks the checksum where the bitmaps would start and
    // pushes both past it; the ordinary layout puts the checksum at the end of
    // the block and puts SIT first.
    let crc_off = if large { CP_SIT_NAT_VERSION_BITMAP } else { CP_MAX_CHKSUM_OFFSET };
    put32(&mut c, CP_CHECKSUM_OFFSET_FIELD, crc_off as u32);
    let (nat_at, sit_at) = if large {
        (CP_SIT_NAT_VERSION_BITMAP + 4, CP_SIT_NAT_VERSION_BITMAP + 4 + BITMAP_BYTES as usize)
    } else {
        (CP_SIT_NAT_VERSION_BITMAP + BITMAP_BYTES as usize, CP_SIT_NAT_VERSION_BITMAP)
    };
    c[nat_at..nat_at + b.nat_bitmap.len()].copy_from_slice(&b.nat_bitmap);
    c[sit_at..sit_at + b.sit_bitmap.len()].copy_from_slice(&b.sit_bitmap);
    let crc = checksum::crc32(&c[..crc_off]);
    put32(&mut c, crc_off, crc);
    c
}

/// The six current-segment summary blocks, with the two journals in them.
///
/// The journals go where the flags say: one block holding both when the pack
/// is compact, and the hot-data and cold-data blocks otherwise.
/// # C: O(journal entries)
pub fn write_summaries(b: &mut Builder, start: u32) {
    let total = CP_PACK_BLOCKS + b.cp_payload;
    if b.cp_flags & CP_COMPACT_SUM_FLAG != 0 {
        let mut blk = vec![0u8; BLKSIZE];
        write_nat_journal(&mut blk, 0, &b.nat_journal);
        put16(&mut blk, SUM_JOURNAL_SIZE, 0);
        b.put_block(start + PACK_START_SUM + b.cp_payload, &blk);
        return;
    }
    let base = if b.cp_flags & (CP_UMOUNT_FLAG | CP_FASTBOOT_FLAG) != 0 {
        NR_CURSEG_PERSIST_TYPE
    } else {
        NR_CURSEG_DATA_TYPE
    };
    for log in 0..base {
        let addr = crate::summary::normal_sum_addr(start, total, base, log);
        let mut blk = vec![0u8; BLKSIZE];
        if log == CURSEG_HOT_DATA { write_nat_journal(&mut blk, SUM_JOURNAL_OFF, &b.nat_journal); }
        if log == CURSEG_COLD_DATA { put16(&mut blk, SUM_JOURNAL_OFF, 0); }
        b.put_block(addr, &blk);
    }
}

/// A node-table journal at `off`. # C: O(entries)
pub fn write_nat_journal(blk: &mut [u8], off: usize, entries: &[(u32, NatEntry)]) {
    put16(blk, off, entries.len() as u16);
    for (i, (nid, e)) in entries.iter().enumerate() {
        let at = off + 2 + i * NAT_JOURNAL_ENTRY_SIZE;
        put32(blk, at, *nid);
        blk[at + 4 + NAT_VERSION] = e.version;
        put32(blk, at + 4 + NAT_INO, e.ino);
        put32(blk, at + 4 + NAT_BLOCK_ADDR, e.block_addr);
    }
}

/// The node table's current copy, and a STALE second copy.
///
/// The stale copy is not decoration: it is what a reader that ignores the
/// version bitmap or the journal lands on, so it carries a different address
/// for every entry.
/// # C: O(entries)
pub fn write_nat(b: &mut Builder) {
    let nat_blocks = (SEG_NAT / 2) * BLKS_PER_SEG;
    let mut current: Vec<(u32, Vec<u8>)> = Vec::new();
    for (nid, e) in b.nat.clone() {
        let (block_off, at) = crate::nat::locate(nid);
        let slot = current.iter().position(|(o, _)| *o == block_off);
        let idx = match slot {
            Some(i) => i,
            None => { current.push((block_off, vec![0u8; BLKSIZE])); current.len() - 1 }
        };
        let blk = &mut current[idx].1;
        blk[at + NAT_VERSION] = e.version;
        put32(blk, at + NAT_INO, e.ino);
        put32(blk, at + NAT_BLOCK_ADDR, e.block_addr);
    }
    for (block_off, blk) in current {
        let base = NAT_BLKADDR + (block_off << 1) - (block_off & (BLKS_PER_SEG - 1));
        let cur_is_second = crate::checkpoint::test_bit(&b.nat_bitmap, block_off as usize);
        let (cur, stale) = if cur_is_second {
            (base + BLKS_PER_SEG, base)
        } else {
            (base, base + BLKS_PER_SEG)
        };
        b.put_block(cur, &blk);
        // The other copy holds the same entries pointing one block earlier —
        // a plausible previous checkpoint, and a wrong answer.
        let mut old = blk.clone();
        for i in 0..NAT_ENTRY_PER_BLOCK {
            let at = i * NAT_ENTRY_SIZE;
            let addr = le32(&old, at + NAT_BLOCK_ADDR).unwrap_or(0);
            if addr != 0 { put32(&mut old, at + NAT_BLOCK_ADDR, addr.wrapping_sub(1)); }
        }
        if stale < NAT_BLKADDR + nat_blocks * 2 { b.put_block(stale, &old); }
    }
}

/// The segment table's current copy. # C: O(main segments)
pub fn write_sit(b: &mut Builder) {
    let sit_blocks = (SEG_SIT / 2) * BLKS_PER_SEG;
    let mut blk = vec![0u8; BLKSIZE];
    for segno in 0..SEG_MAIN {
        let live = b.sit_valid[segno as usize];
        let (_, at) = crate::sit::locate(segno);
        put16(&mut blk, at + SIT_VBLOCKS, live);
        for i in 0..live as usize {
            blk[at + SIT_VALID_MAP + i / 8] |= 1 << (i % 8);
        }
        put64(&mut blk, at + SIT_MTIME, 1000 + u64::from(segno));
    }
    let cur_is_second = crate::checkpoint::test_bit(&b.sit_bitmap, 0);
    let addr = if cur_is_second { SIT_BLKADDR + sit_blocks } else { SIT_BLKADDR };
    b.put_block(addr, &blk);
}

/// # C: O(1)
pub fn put16(b: &mut [u8], at: usize, v: u16) { b[at..at + 2].copy_from_slice(&v.to_le_bytes()); }
/// # C: O(1)
pub fn put32(b: &mut [u8], at: usize, v: u32) { b[at..at + 4].copy_from_slice(&v.to_le_bytes()); }
/// # C: O(1)
pub fn put64(b: &mut [u8], at: usize, v: u64) { b[at..at + 8].copy_from_slice(&v.to_le_bytes()); }
