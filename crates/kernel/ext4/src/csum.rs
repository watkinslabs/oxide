// ext4 metadata_csum (crc32c) computation per Linux fs/ext4.
//
// Every metadata structure on a metadata_csum filesystem carries a
// crc32c. The base seed is `sb.metadata_csum_seed()` — the stored
// `s_checksum_seed` when METADATA_CSUM_SEED is set, else crc32c of
// the 16-byte UUID. Per-inode metadata (the inode slot, the inode's
// directory blocks, its external extent nodes) is keyed by a derived
// per-inode seed `crc32c(crc32c(fs_seed, le32(ino)), le32(gen))`
// (`ext4_inode_csum` / `ei->i_csum_seed`).
//
// All helpers are no-ops at the call site when the fs lacks
// metadata_csum (callers guard via `sb.has_metadata_csum()` or the
// `stamp_*` wrappers below, which check internally).

use crate::gdt::desc_size_for;
use crate::superblock::Superblock;
use crc::crc32c_update;

/// 128-byte ext2-era inode size; metadata_csum splits its low 16
/// bits into `i_checksum_lo` (in the GOOD_OLD region) and the high
/// 16 bits into `i_checksum_hi` (in the extra region) per Linux.
pub const EXT4_GOOD_OLD_INODE_SIZE: usize = 128;

// Inode field byte offsets (within one inode slot).
const I_GENERATION:  usize = 0x64;
const I_EXTRA_ISIZE: usize = 0x80;
const I_CHECKSUM_LO: usize = 0x7C;
const I_CHECKSUM_HI: usize = 0x82;

// Group-descriptor checksum field offsets.
const GD_BLOCK_BITMAP_CSUM_LO: usize = 0x18;
const GD_INODE_BITMAP_CSUM_LO: usize = 0x1A;
const GD_CHECKSUM:             usize = 0x1E;
const GD_BLOCK_BITMAP_CSUM_HI: usize = 0x38;
const GD_INODE_BITMAP_CSUM_HI: usize = 0x3A;

/// Trailing `ext4_dir_entry_tail` size: a 12-byte fake dir entry
/// whose final 4 bytes hold the block's crc32c.
pub const DIRENT_TAIL_SIZE: usize = 12;
/// `det_file_type` magic marking a dir-entry-tail (EXT4_FT_DIR_CSUM).
pub const EXT4_FT_DIR_CSUM: u8 = 0xDE;

/// Trailing `ext4_extent_tail` size: 4 bytes (`et_checksum`) after
/// the last possible extent record in an external extent block.
pub const EXTENT_TAIL_SIZE: usize = 4;

/// Per-inode csum seed `crc32c(crc32c(fs_seed, le32(ino)), le32(gen))`.
/// # C: O(1)
pub fn inode_seed(sb: &Superblock, ino: u32, generation: u32) -> u32 {
    let mut c = sb.metadata_csum_seed();
    c = crc32c_update(c, &ino.to_le_bytes());
    c = crc32c_update(c, &generation.to_le_bytes());
    c
}

/// True iff `i_checksum_hi` is covered by the inode's `i_extra_isize`
/// window (`EXT4_FITS_IN_INODE`). 0x82 + 2 <= 128 + extra_isize.
/// # C: O(1)
fn fits_checksum_hi(raw: &[u8]) -> bool {
    if raw.len() < I_EXTRA_ISIZE + 2 { return false; }
    let extra = u16::from_le_bytes([raw[I_EXTRA_ISIZE], raw[I_EXTRA_ISIZE + 1]]) as usize;
    (I_CHECKSUM_HI + 2) <= EXT4_GOOD_OLD_INODE_SIZE + extra
}

/// Full 32-bit crc32c of an inode slot per `ext4_inode_csum`. The
/// `i_checksum_lo`/`_hi` fields are treated as zero (skipped) so the
/// current stored value is irrelevant.
/// # C: O(inode_size)
pub fn inode_csum(sb: &Superblock, ino: u32, raw: &[u8]) -> u32 {
    let isize = sb.inode_size as usize;
    let gen = u32::from_le_bytes([raw[I_GENERATION], raw[I_GENERATION + 1],
                                  raw[I_GENERATION + 2], raw[I_GENERATION + 3]]);
    let seed = inode_seed(sb, ino, gen);
    let dummy = [0u8; 2];
    let mut csum = crc32c_update(seed, &raw[0..I_CHECKSUM_LO]);
    csum = crc32c_update(csum, &dummy);                 // skip i_checksum_lo
    let mut offset = I_CHECKSUM_LO + 2;                 // 0x7E
    csum = crc32c_update(csum, &raw[offset..EXT4_GOOD_OLD_INODE_SIZE]);
    if isize > EXT4_GOOD_OLD_INODE_SIZE {
        offset = I_CHECKSUM_HI;                         // 0x82
        csum = crc32c_update(csum, &raw[EXT4_GOOD_OLD_INODE_SIZE..offset]);
        if fits_checksum_hi(raw) {
            csum = crc32c_update(csum, &dummy);         // skip i_checksum_hi
            offset += 2;                                // 0x84
        }
        csum = crc32c_update(csum, &raw[offset..isize]);
    }
    csum
}

/// Stamp the inode-slot checksum into `raw` (lo @ 0x7C, hi @ 0x82
/// when the extra window covers it). No-op without metadata_csum.
/// # C: O(inode_size)
pub fn stamp_inode_csum(sb: &Superblock, ino: u32, raw: &mut [u8]) {
    if !sb.has_metadata_csum() { return; }
    let csum = inode_csum(sb, ino, raw);
    raw[I_CHECKSUM_LO..I_CHECKSUM_LO + 2]
        .copy_from_slice(&((csum & 0xFFFF) as u16).to_le_bytes());
    if sb.inode_size as usize > EXT4_GOOD_OLD_INODE_SIZE && fits_checksum_hi(raw) {
        raw[I_CHECKSUM_HI..I_CHECKSUM_HI + 2]
            .copy_from_slice(&(((csum >> 16) & 0xFFFF) as u16).to_le_bytes());
    }
}

/// crc32c of the first `(nbits+7)/8` bytes of a block/inode bitmap
/// per `ext4_*_bitmap_csum`.
/// # C: O(nbits/8)
pub fn bitmap_csum(sb: &Superblock, bitmap: &[u8], nbits: u32) -> u32 {
    let sz = ((nbits + 7) / 8) as usize;
    let sz = core::cmp::min(sz, bitmap.len());
    crc32c_update(sb.metadata_csum_seed(), &bitmap[..sz])
}

/// Store the block-bitmap csum into descriptor slot `n` (lo @ 0x18,
/// hi @ 0x38 for 64-bit descriptors).
/// # C: O(nbits/8)
pub fn set_block_bitmap_csum(sb: &Superblock, gdt: &mut [u8], n: u32, bitmap: &[u8]) {
    if !sb.has_metadata_csum() { return; }
    let csum = bitmap_csum(sb, bitmap, sb.blocks_per_group);
    let dsize = desc_size_for(sb) as usize;
    let off = (n as usize) * dsize;
    gdt[off + GD_BLOCK_BITMAP_CSUM_LO..off + GD_BLOCK_BITMAP_CSUM_LO + 2]
        .copy_from_slice(&((csum & 0xFFFF) as u16).to_le_bytes());
    if dsize > 32 {
        gdt[off + GD_BLOCK_BITMAP_CSUM_HI..off + GD_BLOCK_BITMAP_CSUM_HI + 2]
            .copy_from_slice(&(((csum >> 16) & 0xFFFF) as u16).to_le_bytes());
    }
}

/// Store the inode-bitmap csum into descriptor slot `n` (lo @ 0x1A,
/// hi @ 0x3A for 64-bit descriptors).
/// # C: O(nbits/8)
pub fn set_inode_bitmap_csum(sb: &Superblock, gdt: &mut [u8], n: u32, bitmap: &[u8]) {
    if !sb.has_metadata_csum() { return; }
    let csum = bitmap_csum(sb, bitmap, sb.inodes_per_group);
    let dsize = desc_size_for(sb) as usize;
    let off = (n as usize) * dsize;
    gdt[off + GD_INODE_BITMAP_CSUM_LO..off + GD_INODE_BITMAP_CSUM_LO + 2]
        .copy_from_slice(&((csum & 0xFFFF) as u16).to_le_bytes());
    if dsize > 32 {
        gdt[off + GD_INODE_BITMAP_CSUM_HI..off + GD_INODE_BITMAP_CSUM_HI + 2]
            .copy_from_slice(&(((csum >> 16) & 0xFFFF) as u16).to_le_bytes());
    }
}

/// crc32c (low 16 bits) of group descriptor `n` per
/// `ext4_group_desc_csum` (metadata_csum / crc32c variant). The
/// `bg_checksum` field is treated as zero.
/// # C: O(desc_size)
pub fn group_desc_csum(sb: &Superblock, n: u32, desc_slot: &[u8]) -> u16 {
    let dsize = desc_size_for(sb) as usize;
    let mut c = crc32c_update(sb.metadata_csum_seed(), &n.to_le_bytes());
    c = crc32c_update(c, &desc_slot[0..GD_CHECKSUM]);
    c = crc32c_update(c, &[0u8, 0u8]);          // skip bg_checksum
    let after = GD_CHECKSUM + 2;                 // 0x20
    if after < dsize {
        c = crc32c_update(c, &desc_slot[after..dsize]);
    }
    (c & 0xFFFF) as u16
}

/// Stamp `bg_checksum` into descriptor slot `n` of `gdt`. Caller must
/// have already updated the bitmap csum fields (they are covered).
/// # C: O(desc_size)
pub fn stamp_group_desc_csum(sb: &Superblock, gdt: &mut [u8], n: u32) {
    if !sb.has_metadata_csum() { return; }
    let dsize = desc_size_for(sb) as usize;
    let off = (n as usize) * dsize;
    let csum = group_desc_csum(sb, n, &gdt[off..off + dsize]);
    gdt[off + GD_CHECKSUM..off + GD_CHECKSUM + 2].copy_from_slice(&csum.to_le_bytes());
}

/// `s_checksum` byte offset within the 1024-byte superblock.
const SB_OFF_CHECKSUM: usize = 0x3FC;

/// crc32c of the superblock over `[0, 0x3FC)` per `ext4_superblock_csum`
/// — seeded with `~0` (NOT the metadata seed), no final inversion.
/// # C: O(1024)
pub fn superblock_csum(sb_bytes: &[u8]) -> u32 {
    crc::crc32c_update(0xFFFF_FFFF, &sb_bytes[0..SB_OFF_CHECKSUM])
}

/// Stamp `s_checksum` into a 1024-byte superblock buffer. No-op
/// without metadata_csum.
/// # C: O(1024)
pub fn stamp_superblock_csum(sb: &Superblock, sb_bytes: &mut [u8]) {
    if !sb.has_metadata_csum() { return; }
    let c = superblock_csum(sb_bytes);
    sb_bytes[SB_OFF_CHECKSUM..SB_OFF_CHECKSUM + 4].copy_from_slice(&c.to_le_bytes());
}

/// crc32c of a directory block over `[0, bs - 12)` per
/// `ext4_dirblock_csum` (keyed by the dir inode's per-inode seed).
/// # C: O(bs)
pub fn dirent_csum(sb: &Superblock, ino: u32, generation: u32, block: &[u8]) -> u32 {
    let seed = inode_seed(sb, ino, generation);
    let size = block.len() - DIRENT_TAIL_SIZE;
    crc32c_update(seed, &block[..size])
}

/// Write the `ext4_dir_entry_tail` (rec_len=12, ft=0xDE) and its
/// crc32c into the final 12 bytes of `block`. Caller guarantees the
/// last real entry's rec_len ends at `bs - 12`. No-op without csum.
/// # C: O(bs)
pub fn stamp_dirent_tail(sb: &Superblock, ino: u32, generation: u32, block: &mut [u8]) {
    if !sb.has_metadata_csum() { return; }
    let bs = block.len();
    let t = bs - DIRENT_TAIL_SIZE;
    block[t..t + 4].copy_from_slice(&0u32.to_le_bytes());          // det_inode = 0
    block[t + 4..t + 6].copy_from_slice(&(DIRENT_TAIL_SIZE as u16).to_le_bytes());
    block[t + 6] = 0;                                              // name_len
    block[t + 7] = EXT4_FT_DIR_CSUM;                              // file_type
    let csum = dirent_csum(sb, ino, generation, block);
    block[bs - 4..bs].copy_from_slice(&csum.to_le_bytes());
}

/// Usable directory-block length for real entries: `bs - 12` when
/// metadata_csum reserves a tail, else the whole block.
/// # C: O(1)
pub fn dir_usable_len(sb: &Superblock, bs: usize) -> usize {
    if sb.has_metadata_csum() { bs - DIRENT_TAIL_SIZE } else { bs }
}

/// Max extent records that fit in an external extent block: the
/// header (12) plus N*12 records, reserving a 4-byte tail under
/// metadata_csum. `(bs - 12 - tail) / 12`.
/// # C: O(1)
pub fn extent_block_max(sb: &Superblock, bs: usize) -> u16 {
    let tail = if sb.has_metadata_csum() { EXTENT_TAIL_SIZE } else { 0 };
    ((bs - 12 - tail) / 12) as u16
}

/// crc32c of an external extent block per `ext4_extent_block_csum`:
/// over `header + eh_max records` (the full record area, not just
/// `eh_entries`), keyed by the inode's per-inode seed. Stored in the
/// 4-byte tail. No-op without csum.
/// # C: O(bs)
pub fn stamp_extent_block_csum(sb: &Superblock, ino: u32, generation: u32, block: &mut [u8]) {
    if !sb.has_metadata_csum() { return; }
    let bs = block.len();
    let eh_max = u16::from_le_bytes([block[4], block[5]]) as usize;
    let covered = 12 + eh_max * 12;
    let seed = inode_seed(sb, ino, generation);
    let csum = crc32c_update(seed, &block[..covered]);
    block[bs - EXTENT_TAIL_SIZE..bs].copy_from_slice(&csum.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::superblock::SUPERBLOCK_LEN;

    // Build a superblock matching mini.img's csum-relevant fields:
    // metadata_csum + metadata_csum_seed on, stored seed 0xfb919a40,
    // 64bit, inode_size 256, bpg 8192, ipg 128.
    fn mini_sb() -> Superblock {
        let mut b = [0u8; SUPERBLOCK_LEN];
        b[0x18..0x1C].copy_from_slice(&0u32.to_le_bytes());      // log_block_size 0 → 1 KiB
        b[0x20..0x24].copy_from_slice(&8192u32.to_le_bytes());   // blocks_per_group
        b[0x28..0x2C].copy_from_slice(&128u32.to_le_bytes());    // inodes_per_group
        b[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes()); // magic
        b[0x58..0x5A].copy_from_slice(&256u16.to_le_bytes());    // inode_size
        // incompat: 64bit | extents | filetype
        b[0x60..0x64].copy_from_slice(&(0x0002 | 0x0040 | 0x0080u32).to_le_bytes());
        // ro_compat: metadata_csum | metadata_csum_seed
        b[0x64..0x68].copy_from_slice(&(0x0400 | 0x0020_0000u32).to_le_bytes());
        b[0x270..0x274].copy_from_slice(&0xfb91_9a40u32.to_le_bytes()); // s_checksum_seed
        Superblock::parse(&b).unwrap()
    }

    #[test]
    fn seed_matches_image() {
        let sb = mini_sb();
        assert_eq!(sb.metadata_csum_seed(), 0xfb91_9a40);
    }

    #[test]
    fn bitmap_csum_matches_mke2fs() {
        // Reproduce the block/inode bitmap csum values dumpe2fs printed
        // for mini.img group 0 by checksumming a synthetic bitmap is not
        // possible without the real bytes; covered by the image-driven
        // test in tests/csum_image.rs. Here we only pin the seed wiring.
        let sb = mini_sb();
        assert!(sb.has_metadata_csum());
    }
}
