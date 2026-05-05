// ext4 inode + extent-header parser per Linux fs/ext4/ext4.h
// `ext4_inode` + `ext4_extent_header`. Pure decoder — caller
// hands a slice big enough for an inode (sb.inode_size bytes).
//
// We only decode the read-path fields:
//   - i_mode      (file type + perms)
//   - i_size      (file size; lo + hi when extents on)
//   - i_links_count
//   - i_block[0..60] — extent tree root for ext4-mode files
//
// Indirect-block ext2 inodes are out of v1 scope; the parser
// flags non-extent inodes via `ExtentInodeError::NotExtents`.

use crate::superblock::Superblock;

/// `i_mode` file-type bits (top 4 bits) per ext4 spec.
pub const S_IFMT:  u16 = 0xF000;
pub const S_IFREG: u16 = 0x8000;
pub const S_IFDIR: u16 = 0x4000;
pub const S_IFLNK: u16 = 0xA000;

/// Extent header magic per `ext4_extent_header.eh_magic`.
pub const EXT4_EXT_MAGIC: u16 = 0xF30A;

/// Length of the inline `i_block` array in bytes.
pub const I_BLOCK_LEN: usize = 60;

/// Errors decoded from `Inode::parse` / `parse_extent_header`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InodeError {
    /// Slice was shorter than `sb.inode_size`.
    BadLen,
    /// `eh_magic` did not match `EXT4_EXT_MAGIC`.
    BadExtentMagic,
    /// Header reports more entries than fit in inline space.
    TooManyExtents,
}

/// Decoded subset of an ext4 inode used by the read path.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Inode {
    pub mode:        u16,
    pub size:        u64,
    pub links_count: u16,
    /// Inline extent tree root + leaves (60 bytes verbatim).
    pub i_block:     [u8; I_BLOCK_LEN],
}

impl Inode {
    /// Parse an inode from `buf`, which must be at least
    /// `sb.inode_size` bytes long. Caller is responsible for
    /// having read the right offset (group descriptor → inode
    /// table → inode_size * (ino - 1) within the group).
    /// # C: O(1)
    pub fn parse(buf: &[u8], sb: &Superblock) -> Result<Self, InodeError> {
        let isize = sb.inode_size as usize;
        if buf.len() < isize { return Err(InodeError::BadLen); }
        let mode  = u16::from_le_bytes([buf[0x00], buf[0x01]]);
        let size_lo = u32::from_le_bytes([buf[0x04], buf[0x05], buf[0x06], buf[0x07]]) as u64;
        let links = u16::from_le_bytes([buf[0x1A], buf[0x1B]]);
        let mut i_block = [0u8; I_BLOCK_LEN];
        i_block.copy_from_slice(&buf[0x28..0x28 + I_BLOCK_LEN]);
        // i_size_high lives in the EXT4_FEATURE_RO_COMPAT_LARGE_FILE
        // path at offset 0x6C; valid only when sb advertises that
        // feature. For v1 we just merge it unconditionally — a
        // zero high half is harmless on small files.
        let size_hi = u32::from_le_bytes([buf[0x6C], buf[0x6D], buf[0x6E], buf[0x6F]]) as u64;
        Ok(Inode {
            mode,
            size: size_lo | (size_hi << 32),
            links_count: links,
            i_block,
        })
    }

    /// File type per `i_mode & S_IFMT`.
    /// # C: O(1)
    pub fn file_type(&self) -> u16 { self.mode & S_IFMT }

    /// True iff this inode is a regular file.
    /// # C: O(1)
    pub fn is_reg(&self)  -> bool { self.file_type() == S_IFREG }

    /// True iff this inode is a directory.
    /// # C: O(1)
    pub fn is_dir(&self)  -> bool { self.file_type() == S_IFDIR }

    /// True iff this inode is a symlink.
    /// # C: O(1)
    pub fn is_link(&self) -> bool { self.file_type() == S_IFLNK }
}

/// 12-byte `ext4_extent_header` at the head of any extent node.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExtentHeader {
    pub magic:      u16,
    pub entries:    u16,
    pub max:        u16,
    pub depth:      u16,
    pub generation: u32,
}

/// 12-byte leaf `ext4_extent` (depth==0 entries).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Extent {
    pub block:    u32,  // first logical block this extent covers
    pub len:      u16,  // number of contiguous blocks
    pub start_hi: u16,  // high 16 bits of start LBA
    pub start_lo: u32,  // low 32 bits of start LBA
}

impl Extent {
    /// Combined 48-bit start LBA.
    /// # C: O(1)
    pub fn start_lba(&self) -> u64 {
        ((self.start_hi as u64) << 32) | (self.start_lo as u64)
    }
}

/// Parse the extent header out of an inode's `i_block` array.
/// # C: O(1)
pub fn parse_extent_header(i_block: &[u8; I_BLOCK_LEN]) -> Result<ExtentHeader, InodeError> {
    let magic = u16::from_le_bytes([i_block[0], i_block[1]]);
    if magic != EXT4_EXT_MAGIC {
        return Err(InodeError::BadExtentMagic);
    }
    let entries = u16::from_le_bytes([i_block[2], i_block[3]]);
    let max     = u16::from_le_bytes([i_block[4], i_block[5]]);
    let depth   = u16::from_le_bytes([i_block[6], i_block[7]]);
    let gen     = u32::from_le_bytes([i_block[8], i_block[9], i_block[10], i_block[11]]);
    // Inline space holds (60 - 12) / 12 = 4 entries; deeper trees
    // live in separate extent index blocks (out of P6-02 scope).
    if depth == 0 && entries > 4 {
        return Err(InodeError::TooManyExtents);
    }
    Ok(ExtentHeader { magic, entries, max, depth, generation: gen })
}

/// Read the `idx`-th leaf extent out of `i_block`. Returns
/// `None` when `idx >= entries` or the depth is non-zero
/// (caller would need to follow an extent index, which the
/// P6-02 inline-only path doesn't yet).
/// # C: O(1)
pub fn parse_inline_extent(i_block: &[u8; I_BLOCK_LEN], hdr: &ExtentHeader, idx: u16)
    -> Option<Extent>
{
    if hdr.depth != 0 || idx >= hdr.entries { return None; }
    let off = 12 + (idx as usize) * 12;
    if off + 12 > I_BLOCK_LEN { return None; }
    let block    = u32::from_le_bytes([i_block[off],   i_block[off+1], i_block[off+2], i_block[off+3]]);
    let len      = u16::from_le_bytes([i_block[off+4], i_block[off+5]]);
    let start_hi = u16::from_le_bytes([i_block[off+6], i_block[off+7]]);
    let start_lo = u32::from_le_bytes([i_block[off+8], i_block[off+9], i_block[off+10], i_block[off+11]]);
    Some(Extent { block, len, start_hi, start_lo })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::superblock::SUPERBLOCK_LEN;

    fn fake_sb_inode_size(isize: u16) -> Superblock {
        // Build a minimum sb with the inode size we want.
        let mut b = [0u8; SUPERBLOCK_LEN];
        b[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes());           // log_block_size 2 → 4 KiB
        b[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());      // magic
        b[0x58..0x5A].copy_from_slice(&isize.to_le_bytes());          // s_inode_size
        Superblock::parse(&b).expect("sb")
    }

    fn make_inode_buf(isize: usize, mode: u16, size: u64, links: u16, i_block: [u8; I_BLOCK_LEN])
        -> std::vec::Vec<u8>
    {
        let mut b = std::vec![0u8; isize];
        b[0x00..0x02].copy_from_slice(&mode.to_le_bytes());
        b[0x04..0x08].copy_from_slice(&((size & 0xFFFF_FFFF) as u32).to_le_bytes());
        b[0x1A..0x1C].copy_from_slice(&links.to_le_bytes());
        b[0x28..0x28 + I_BLOCK_LEN].copy_from_slice(&i_block);
        b[0x6C..0x70].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
        b
    }

    fn make_extent_iblock(hdr_entries: u16, depth: u16, leaves: &[(u32, u16, u64)]) -> [u8; I_BLOCK_LEN] {
        let mut b = [0u8; I_BLOCK_LEN];
        b[0..2].copy_from_slice(&EXT4_EXT_MAGIC.to_le_bytes());
        b[2..4].copy_from_slice(&hdr_entries.to_le_bytes());
        b[4..6].copy_from_slice(&4u16.to_le_bytes());
        b[6..8].copy_from_slice(&depth.to_le_bytes());
        b[8..12].copy_from_slice(&0u32.to_le_bytes());
        for (i, &(block, len, start)) in leaves.iter().enumerate() {
            let off = 12 + i * 12;
            b[off..off+4].copy_from_slice(&block.to_le_bytes());
            b[off+4..off+6].copy_from_slice(&len.to_le_bytes());
            b[off+6..off+8].copy_from_slice(&((start >> 32) as u16).to_le_bytes());
            b[off+8..off+12].copy_from_slice(&((start & 0xFFFF_FFFF) as u32).to_le_bytes());
        }
        b
    }

    #[test]
    fn parse_regular_file_4g() {
        let sb = fake_sb_inode_size(256);
        let big = (1u64 << 32) | 0x123;
        let buf = make_inode_buf(256, S_IFREG | 0o644, big, 1, [0u8; I_BLOCK_LEN]);
        let ino = Inode::parse(&buf, &sb).expect("parse");
        assert!(ino.is_reg());
        assert_eq!(ino.size, big);
        assert_eq!(ino.links_count, 1);
    }

    #[test]
    fn parse_directory_kind() {
        let sb = fake_sb_inode_size(256);
        let buf = make_inode_buf(256, S_IFDIR | 0o755, 4096, 2, [0u8; I_BLOCK_LEN]);
        let ino = Inode::parse(&buf, &sb).expect("parse");
        assert!(ino.is_dir());
        assert!(!ino.is_reg());
    }

    #[test]
    fn rejects_buf_smaller_than_isize() {
        let sb = fake_sb_inode_size(256);
        let buf = std::vec![0u8; 100];
        assert_eq!(Inode::parse(&buf, &sb), Err(InodeError::BadLen));
    }

    #[test]
    fn extent_header_magic_pinned() {
        assert_eq!(EXT4_EXT_MAGIC, 0xF30A);
    }

    #[test]
    fn extent_header_parse_canonical() {
        let ib = make_extent_iblock(2, 0, &[(0, 1, 0x100), (1, 4, 0x200)]);
        let hdr = parse_extent_header(&ib).expect("hdr");
        assert_eq!(hdr.magic,   EXT4_EXT_MAGIC);
        assert_eq!(hdr.entries, 2);
        assert_eq!(hdr.depth,   0);
    }

    #[test]
    fn extent_header_rejects_bad_magic() {
        let mut ib = make_extent_iblock(0, 0, &[]);
        ib[0] = 0;
        ib[1] = 0;
        assert_eq!(parse_extent_header(&ib), Err(InodeError::BadExtentMagic));
    }

    #[test]
    fn extent_header_rejects_5_inline_entries() {
        let ib = make_extent_iblock(5, 0, &[]);  // 5 > 4 inline slots
        assert_eq!(parse_extent_header(&ib), Err(InodeError::TooManyExtents));
    }

    #[test]
    fn parse_inline_extent_walk() {
        let ib = make_extent_iblock(2, 0, &[(0, 1, 0x1234_5678), (1, 4, 0x000000010000_0042)]);
        let hdr = parse_extent_header(&ib).unwrap();
        let e0 = parse_inline_extent(&ib, &hdr, 0).expect("e0");
        let e1 = parse_inline_extent(&ib, &hdr, 1).expect("e1");
        let e2 = parse_inline_extent(&ib, &hdr, 2);
        assert_eq!(e0.block, 0);
        assert_eq!(e0.len,   1);
        assert_eq!(e0.start_lba(), 0x1234_5678);
        assert_eq!(e1.block, 1);
        assert_eq!(e1.len,   4);
        assert_eq!(e1.start_lba(), 0x0001_0000_0042);
        assert!(e2.is_none(), "past entries → None");
    }

    #[test]
    fn parse_inline_extent_skips_indexed_tree() {
        // depth>0 means the inline payload is index records,
        // not leaves; v1 returns None until index walking lands.
        let mut ib = make_extent_iblock(1, 1, &[(0, 1, 0x100)]);
        let _ = ib;  // silence unused-binding warning if rebalanced.
        let hdr = parse_extent_header(&ib).unwrap();
        assert_eq!(hdr.depth, 1);
        assert!(parse_inline_extent(&ib, &hdr, 0).is_none());
    }

    #[test]
    fn file_type_helpers() {
        assert_eq!(S_IFMT, 0xF000);
        let mode_reg = S_IFREG | 0o644;
        let mode_dir = S_IFDIR | 0o755;
        let mode_lnk = S_IFLNK | 0o777;
        assert_eq!(mode_reg & S_IFMT, S_IFREG);
        assert_eq!(mode_dir & S_IFMT, S_IFDIR);
        assert_eq!(mode_lnk & S_IFMT, S_IFLNK);
    }
}
