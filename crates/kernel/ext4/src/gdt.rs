// ext4 group descriptor table parser per Linux fs/ext4/ext4.h
// `ext4_group_desc`. The GDT lives in the block immediately
// following the superblock (block 1 for 1 KiB-block FS, block
// 1 still for 4 KiB FS where superblock + padding share block 0).
//
// Each group descriptor is 32 bytes for ext2/3 and "legacy"
// ext4, or 64 bytes when INCOMPAT_64BIT is set in the
// superblock. We support both via `desc_size_for(sb)`.

use crate::superblock::{Superblock, INCOMPAT_64BIT};

/// Size of a single group descriptor record on this fs.
/// 32 bytes pre-64bit, 64 bytes when INCOMPAT_64BIT is on.
/// # C: O(1)
pub fn desc_size_for(sb: &Superblock) -> u16 {
    if (sb.feature_incompat & INCOMPAT_64BIT) != 0 { 64 } else { 32 }
}

/// Errors decoded from `parse_descriptor`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GdtError {
    /// Buffer shorter than `desc_size_for(sb)`.
    BadLen,
    /// Inode number was 0 or > sb.inodes_count.
    BadInode,
}

/// Decoded subset of one group descriptor.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GroupDesc {
    pub inode_table:        u64,   // LBA of this group's inode table (lo|hi merged)
    pub block_bitmap:       u64,
    pub inode_bitmap:       u64,
    pub free_blocks_count:  u32,
    pub free_inodes_count:  u32,
    pub used_dirs_count:    u32,
}

/// Field byte-offsets within one group descriptor record.
pub const GD_OFF_FREE_BLOCKS_LO: usize = 0x0C;
pub const GD_OFF_FREE_INODES_LO: usize = 0x0E;
pub const GD_OFF_USED_DIRS_LO:   usize = 0x10;
pub const GD_OFF_CHECKSUM:       usize = 0x1E;
/// 64-bit hi halves (only present when `desc_size_for == 64`).
pub const GD_OFF_FREE_BLOCKS_HI: usize = 0x2C;
pub const GD_OFF_FREE_INODES_HI: usize = 0x2E;
pub const GD_OFF_USED_DIRS_HI:   usize = 0x30;

/// Parse the `n`-th group descriptor out of `buf`. `buf` must
/// hold at least `(n+1) * desc_size_for(sb)` bytes.
/// # C: O(1)
pub fn parse_descriptor(buf: &[u8], n: u32, sb: &Superblock) -> Result<GroupDesc, GdtError> {
    let dsize = desc_size_for(sb) as usize;
    let off = (n as usize) * dsize;
    if off + dsize > buf.len() {
        return Err(GdtError::BadLen);
    }
    let bbm_lo = u32::from_le_bytes([buf[off],     buf[off+1], buf[off+2], buf[off+3]]) as u64;
    let ibm_lo = u32::from_le_bytes([buf[off+4],   buf[off+5], buf[off+6], buf[off+7]]) as u64;
    let it_lo  = u32::from_le_bytes([buf[off+8],   buf[off+9], buf[off+10], buf[off+11]]) as u64;
    let fb_lo  = u16::from_le_bytes([buf[off+GD_OFF_FREE_BLOCKS_LO],   buf[off+GD_OFF_FREE_BLOCKS_LO+1]]) as u32;
    let fi_lo  = u16::from_le_bytes([buf[off+GD_OFF_FREE_INODES_LO],   buf[off+GD_OFF_FREE_INODES_LO+1]]) as u32;
    let ud_lo  = u16::from_le_bytes([buf[off+GD_OFF_USED_DIRS_LO],     buf[off+GD_OFF_USED_DIRS_LO+1]]) as u32;
    let (bbm_hi, ibm_hi, it_hi, fb_hi, fi_hi, ud_hi) = if dsize == 64 {
        let bh = u32::from_le_bytes([buf[off+0x20], buf[off+0x21], buf[off+0x22], buf[off+0x23]]) as u64;
        let ih = u32::from_le_bytes([buf[off+0x24], buf[off+0x25], buf[off+0x26], buf[off+0x27]]) as u64;
        let th = u32::from_le_bytes([buf[off+0x28], buf[off+0x29], buf[off+0x2A], buf[off+0x2B]]) as u64;
        let fbh = u16::from_le_bytes([buf[off+GD_OFF_FREE_BLOCKS_HI], buf[off+GD_OFF_FREE_BLOCKS_HI+1]]) as u32;
        let fih = u16::from_le_bytes([buf[off+GD_OFF_FREE_INODES_HI], buf[off+GD_OFF_FREE_INODES_HI+1]]) as u32;
        let udh = u16::from_le_bytes([buf[off+GD_OFF_USED_DIRS_HI],   buf[off+GD_OFF_USED_DIRS_HI+1]]) as u32;
        (bh, ih, th, fbh, fih, udh)
    } else { (0, 0, 0, 0, 0, 0) };
    Ok(GroupDesc {
        block_bitmap:      (bbm_hi << 32) | bbm_lo,
        inode_bitmap:      (ibm_hi << 32) | ibm_lo,
        inode_table:       (it_hi  << 32) | it_lo,
        free_blocks_count: (fb_hi << 16) | fb_lo,
        free_inodes_count: (fi_hi << 16) | fi_lo,
        used_dirs_count:   (ud_hi << 16) | ud_lo,
    })
}

/// Write back the counter fields of `gd` to the `n`-th descriptor
/// slot in `buf`. Only mutates the free-blocks / free-inodes /
/// used-dirs counters and clears the legacy + 64-bit checksum
/// fields (real driver computes a CRC; v1 uses a non-checksumming
/// image — see `Mount::open` rejection of GDT_CSUM if enabled).
/// # C: O(1)
pub fn write_descriptor_counters(buf: &mut [u8], n: u32, sb: &Superblock, gd: &GroupDesc)
    -> Result<(), GdtError>
{
    let dsize = desc_size_for(sb) as usize;
    let off = (n as usize) * dsize;
    if off + dsize > buf.len() { return Err(GdtError::BadLen); }
    buf[off+GD_OFF_FREE_BLOCKS_LO  ..off+GD_OFF_FREE_BLOCKS_LO+2]
        .copy_from_slice(&((gd.free_blocks_count & 0xFFFF) as u16).to_le_bytes());
    buf[off+GD_OFF_FREE_INODES_LO  ..off+GD_OFF_FREE_INODES_LO+2]
        .copy_from_slice(&((gd.free_inodes_count & 0xFFFF) as u16).to_le_bytes());
    buf[off+GD_OFF_USED_DIRS_LO    ..off+GD_OFF_USED_DIRS_LO+2]
        .copy_from_slice(&((gd.used_dirs_count   & 0xFFFF) as u16).to_le_bytes());
    // Zero checksum slot — image MUST NOT have GDT_CSUM feature.
    buf[off+GD_OFF_CHECKSUM..off+GD_OFF_CHECKSUM+2].copy_from_slice(&0u16.to_le_bytes());
    if dsize == 64 {
        buf[off+GD_OFF_FREE_BLOCKS_HI..off+GD_OFF_FREE_BLOCKS_HI+2]
            .copy_from_slice(&((gd.free_blocks_count >> 16) as u16).to_le_bytes());
        buf[off+GD_OFF_FREE_INODES_HI..off+GD_OFF_FREE_INODES_HI+2]
            .copy_from_slice(&((gd.free_inodes_count >> 16) as u16).to_le_bytes());
        buf[off+GD_OFF_USED_DIRS_HI  ..off+GD_OFF_USED_DIRS_HI+2]
            .copy_from_slice(&((gd.used_dirs_count   >> 16) as u16).to_le_bytes());
    }
    Ok(())
}

/// Locate inode `ino` (1-indexed) on the FS. Returns
/// `(group, index_in_group)`. Caller reads
/// `gd[group].inode_table` at `index_in_group * sb.inode_size`
/// to fetch the inode bytes.
/// # C: O(1)
pub fn locate_inode(sb: &Superblock, ino: u32) -> Result<(u32, u32), GdtError> {
    if ino == 0 || ino > sb.inodes_count { return Err(GdtError::BadInode); }
    if sb.inodes_per_group == 0 { return Err(GdtError::BadInode); }
    let i = ino - 1;
    Ok((i / sb.inodes_per_group, i % sb.inodes_per_group))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::superblock::SUPERBLOCK_LEN;

    fn make_sb(incompat: u32, inodes_count: u32, ipg: u32, isize: u16) -> Superblock {
        let mut b = [0u8; SUPERBLOCK_LEN];
        b[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes());
        b[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        b[0x00..0x04].copy_from_slice(&inodes_count.to_le_bytes());
        b[0x28..0x2C].copy_from_slice(&ipg.to_le_bytes());
        b[0x60..0x64].copy_from_slice(&incompat.to_le_bytes());
        b[0x58..0x5A].copy_from_slice(&isize.to_le_bytes());
        Superblock::parse(&b).unwrap()
    }

    fn put_desc32(out: &mut std::vec::Vec<u8>, bbm: u32, ibm: u32, it: u32) {
        out.extend_from_slice(&bbm.to_le_bytes());
        out.extend_from_slice(&ibm.to_le_bytes());
        out.extend_from_slice(&it.to_le_bytes());
        for _ in 0..(32 - 12) { out.push(0); }
    }

    fn put_desc64(out: &mut std::vec::Vec<u8>, bbm: u64, ibm: u64, it: u64) {
        out.extend_from_slice(&((bbm & 0xFFFF_FFFF) as u32).to_le_bytes());
        out.extend_from_slice(&((ibm & 0xFFFF_FFFF) as u32).to_le_bytes());
        out.extend_from_slice(&((it  & 0xFFFF_FFFF) as u32).to_le_bytes());
        for _ in 0..(0x20 - 12) { out.push(0); }
        out.extend_from_slice(&((bbm >> 32) as u32).to_le_bytes());
        out.extend_from_slice(&((ibm >> 32) as u32).to_le_bytes());
        out.extend_from_slice(&((it  >> 32) as u32).to_le_bytes());
        for _ in 0..(0x40 - 0x20 - 12) { out.push(0); }
    }

    #[test]
    fn desc_size_legacy_vs_64bit() {
        let sb_legacy = make_sb(0, 1024, 1024, 256);
        let sb_64bit  = make_sb(INCOMPAT_64BIT, 1024, 1024, 256);
        assert_eq!(desc_size_for(&sb_legacy), 32);
        assert_eq!(desc_size_for(&sb_64bit),  64);
    }

    #[test]
    fn parse_legacy_descriptor() {
        let sb = make_sb(0, 1024, 1024, 256);
        let mut b = std::vec::Vec::new();
        put_desc32(&mut b, 100, 200, 300);
        put_desc32(&mut b, 400, 500, 600);
        let d0 = parse_descriptor(&b, 0, &sb).unwrap();
        let d1 = parse_descriptor(&b, 1, &sb).unwrap();
        assert_eq!(d0.block_bitmap, 100);
        assert_eq!(d0.inode_bitmap, 200);
        assert_eq!(d0.inode_table,  300);
        assert_eq!(d1.inode_table,  600);
    }

    #[test]
    fn parse_64bit_descriptor_high_halves() {
        let sb = make_sb(INCOMPAT_64BIT, 1024, 1024, 256);
        let mut b = std::vec::Vec::new();
        put_desc64(&mut b, 0x00000001_00000064, 0x00000001_000000C8, 0x00000001_0000012C);
        let d = parse_descriptor(&b, 0, &sb).unwrap();
        assert_eq!(d.block_bitmap, 0x0000_0001_0000_0064);
        assert_eq!(d.inode_bitmap, 0x0000_0001_0000_00C8);
        assert_eq!(d.inode_table,  0x0000_0001_0000_012C);
    }

    #[test]
    fn parse_descriptor_rejects_bad_len() {
        let sb = make_sb(0, 1024, 1024, 256);
        let b  = std::vec![0u8; 16];  // < 32-byte descriptor
        assert_eq!(parse_descriptor(&b, 0, &sb), Err(GdtError::BadLen));
    }

    #[test]
    fn locate_inode_canonical() {
        let sb = make_sb(0, 8192, 1024, 256);
        // Inode 1 → group 0, index 0.
        assert_eq!(locate_inode(&sb, 1).unwrap(), (0, 0));
        // Inode 1024 → group 0, index 1023.
        assert_eq!(locate_inode(&sb, 1024).unwrap(), (0, 1023));
        // Inode 1025 → group 1, index 0.
        assert_eq!(locate_inode(&sb, 1025).unwrap(), (1, 0));
        // Inode 8192 → group 7, index 1023.
        assert_eq!(locate_inode(&sb, 8192).unwrap(), (7, 1023));
    }

    #[test]
    fn locate_inode_rejects_zero() {
        let sb = make_sb(0, 8192, 1024, 256);
        assert_eq!(locate_inode(&sb, 0), Err(GdtError::BadInode));
    }

    #[test]
    fn locate_inode_rejects_overflow() {
        let sb = make_sb(0, 8192, 1024, 256);
        assert_eq!(locate_inode(&sb, 8193), Err(GdtError::BadInode));
    }

    #[test]
    fn locate_inode_rejects_zero_ipg() {
        let sb = make_sb(0, 8192, 0, 256);
        assert_eq!(locate_inode(&sb, 1), Err(GdtError::BadInode));
    }
}
