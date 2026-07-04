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

#[cfg(test)]
mod tests;

/// `i_mode` file-type bits (top 4 bits) per ext4 spec.
pub const S_IFMT:  u16 = 0xF000;
pub const S_IFREG: u16 = 0x8000;
pub const S_IFDIR: u16 = 0x4000;
pub const S_IFLNK: u16 = 0xA000;
pub const S_IFCHR: u16 = 0x2000;
pub const S_IFBLK: u16 = 0x6000;
pub const S_IFIFO: u16 = 0x1000;
pub const S_IFSOCK: u16 = 0xC000;

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
    /// On-disk `i_blocks` in 512-byte sectors (Linux `i_blocks_lo` @0x1C
    /// merged with `l_i_blocks_high` @0x74). The REAL allocation count —
    /// includes extent-tree metadata blocks and preallocated/`fallocate`d
    /// extents, so it diverges from `ceil(size / blocksize)` for sparse or
    /// preallocated files. Drives `st_blocks` (`getattr`) exactly as Linux
    /// `ext4_getattr`, not the size-derived `blocks_for` estimate.
    pub i_blocks:    u64,
    /// Owner uid: `i_uid` @0x02 (low u16) merged with `l_i_uid_high` @0x78
    /// (osd2 high u16). fs-domain id (Linux `i_uid`); the mount idmap maps it
    /// out at `getattr`. Drives `st_uid`.
    pub uid:         u32,
    /// Owner gid: `i_gid` @0x18 (low u16) merged with `l_i_gid_high` @0x7A
    /// (osd2 high u16). Drives `st_gid`.
    pub gid:         u32,
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
        // i_blocks_lo @0x1C (512-byte sectors) + l_i_blocks_high @0x74 (osd2,
        // u16). 0x74..0x76 is inside even a 128-byte inode, so the read is
        // always in range. HUGE_FILE (fs-block units) is not advertised by the
        // images we mount, so the count stays in 512-byte sectors.
        let blocks_lo = u32::from_le_bytes([buf[0x1C], buf[0x1D], buf[0x1E], buf[0x1F]]) as u64;
        let blocks_hi = u16::from_le_bytes([buf[0x74], buf[0x75]]) as u64;
        let i_blocks  = blocks_lo | (blocks_hi << 32);
        let mut i_block = [0u8; I_BLOCK_LEN];
        i_block.copy_from_slice(&buf[0x28..0x28 + I_BLOCK_LEN]);
        // i_size_high lives in the EXT4_FEATURE_RO_COMPAT_LARGE_FILE
        // path at offset 0x6C; valid only when sb advertises that
        // feature. For v1 we just merge it unconditionally — a
        // zero high half is harmless on small files.
        let size_hi = u32::from_le_bytes([buf[0x6C], buf[0x6D], buf[0x6E], buf[0x6F]]) as u64;
        // Owner ids: low u16 (0x02/0x18) merged with osd2 high u16 (0x78/0x7A).
        // 0x7A..0x7C lies inside even a 128-byte inode, so always in range.
        let uid = u16::from_le_bytes([buf[0x02], buf[0x03]]) as u32
                | ((u16::from_le_bytes([buf[0x78], buf[0x79]]) as u32) << 16);
        let gid = u16::from_le_bytes([buf[0x18], buf[0x19]]) as u32
                | ((u16::from_le_bytes([buf[0x7A], buf[0x7B]]) as u32) << 16);
        Ok(Inode {
            mode,
            size: size_lo | (size_hi << 32),
            links_count: links,
            i_blocks,
            uid,
            gid,
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

    /// True iff this inode is a character device.
    /// # C: O(1)
    pub fn is_chr(&self) -> bool { self.file_type() == S_IFCHR }

    /// True iff this inode is a block device.
    /// # C: O(1)
    pub fn is_blk(&self) -> bool { self.file_type() == S_IFBLK }

    /// Device number for a CHR/BLK node (`st_rdev`). ext4 stores the
    /// device in the inline `i_block` area: the Linux "small dev" layout
    /// (`create_mknod` here, matching the common case) writes it verbatim
    /// in `i_block[0..4]`. Meaningful only when `is_chr()`/`is_blk()`.
    /// # C: O(1)
    pub fn rdev(&self) -> u32 {
        u32::from_le_bytes([self.i_block[0], self.i_block[1], self.i_block[2], self.i_block[3]])
    }

    /// For a fast symlink (target length ≤ 60 bytes) the target text
    /// lives inline in `i_block`. Returns the target bytes if this is
    /// a symlink and the size fits in the inline area; `None` for slow
    /// symlinks (caller must read the first data block via the extent
    /// tree).
    /// # C: O(1)
    pub fn fast_symlink_target(&self) -> Option<&[u8]> {
        if !self.is_link() { return None; }
        let n = self.size as usize;
        if n == 0 || n > I_BLOCK_LEN { return None; }
        Some(&self.i_block[..n])
    }
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
    pub len:      u16,  // raw on-disk len: >32768 = UNWRITTEN, real = len-32768
    pub start_hi: u16,  // high 16 bits of start LBA
    pub start_lo: u32,  // low 32 bits of start LBA
}

impl Extent {
    /// Initialized-coverage length. ext4 encodes an unwritten (fallocated,
    /// never-written) extent as `len > 32768` with real length `len - 32768`;
    /// an initialized extent is capped at 32768 blocks. # C: O(1)
    pub fn real_len(&self) -> u32 {
        if self.len > 32768 { (self.len - 32768) as u32 } else { self.len as u32 }
    }
    /// True for an unwritten (fallocate-preallocated) extent — Linux serves
    /// ZEROS for it, never the stale on-disk bytes. # C: O(1)
    pub fn is_unwritten(&self) -> bool { self.len > 32768 }
}

/// 12-byte interior `ext4_extent_idx` (depth>0). Each idx points
/// to a child block that itself begins with an `ExtentHeader`
/// followed by either more idx records or leaf extents.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExtentIdx {
    pub block:    u32,  // first logical block covered by the subtree
    pub leaf_lo:  u32,  // low 32 bits of the LBA of the child block
    pub leaf_hi:  u16,  // high 16 bits
    pub _unused:  u16,
}

impl ExtentIdx {
    /// Combined 48-bit LBA of the child block.
    /// # C: O(1)
    pub fn leaf_lba(&self) -> u64 {
        ((self.leaf_hi as u64) << 32) | (self.leaf_lo as u64)
    }
}

/// Parse the `idx`-th interior extent_idx from a 12-byte-record
/// stream that starts at offset 12 within `buf`. Caller has
/// already verified the leading ExtentHeader has depth>0.
/// # C: O(1)
pub fn parse_extent_idx(buf: &[u8], hdr: &ExtentHeader, idx: u16) -> Option<ExtentIdx> {
    if hdr.depth == 0 || idx >= hdr.entries { return None; }
    let off = 12 + (idx as usize) * 12;
    if off + 12 > buf.len() { return None; }
    let block    = u32::from_le_bytes([buf[off],   buf[off+1], buf[off+2], buf[off+3]]);
    let leaf_lo  = u32::from_le_bytes([buf[off+4], buf[off+5], buf[off+6], buf[off+7]]);
    let leaf_hi  = u16::from_le_bytes([buf[off+8], buf[off+9]]);
    let unused   = u16::from_le_bytes([buf[off+10], buf[off+11]]);
    Some(ExtentIdx { block, leaf_lo, leaf_hi, _unused: unused })
}

impl Extent {
    /// Combined 48-bit start LBA.
    /// # C: O(1)
    pub fn start_lba(&self) -> u64 {
        ((self.start_hi as u64) << 32) | (self.start_lo as u64)
    }
}

/// Parse the extent header out of any buffer ≥ 12 bytes (used
/// for both inline `i_block` and external child blocks).
/// # C: O(1)
pub fn parse_extent_header_slice(buf: &[u8]) -> Result<ExtentHeader, InodeError> {
    if buf.len() < 12 { return Err(InodeError::BadLen); }
    let magic = u16::from_le_bytes([buf[0], buf[1]]);
    if magic != EXT4_EXT_MAGIC { return Err(InodeError::BadExtentMagic); }
    let entries = u16::from_le_bytes([buf[2], buf[3]]);
    let max     = u16::from_le_bytes([buf[4], buf[5]]);
    let depth   = u16::from_le_bytes([buf[6], buf[7]]);
    let gen     = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    Ok(ExtentHeader { magic, entries, max, depth, generation: gen })
}

/// Slice variants of leaf + idx parsing for external child
/// blocks (fs-block-sized buffers, not the 60-byte `i_block`).
/// # C: O(N)
pub fn parse_inline_extent_slice(buf: &[u8], hdr: &ExtentHeader, idx: u16) -> Option<Extent> {
    if hdr.depth != 0 || idx >= hdr.entries { return None; }
    let off = 12 + (idx as usize) * 12;
    if off + 12 > buf.len() { return None; }
    let block    = u32::from_le_bytes([buf[off],   buf[off+1], buf[off+2], buf[off+3]]);
    let len      = u16::from_le_bytes([buf[off+4], buf[off+5]]);
    let start_hi = u16::from_le_bytes([buf[off+6], buf[off+7]]);
    let start_lo = u32::from_le_bytes([buf[off+8], buf[off+9], buf[off+10], buf[off+11]]);
    Some(Extent { block, len, start_hi, start_lo })
}

/// # C: O(N)
pub fn parse_extent_idx_slice(buf: &[u8], hdr: &ExtentHeader, idx: u16) -> Option<ExtentIdx> {
    if hdr.depth == 0 || idx >= hdr.entries { return None; }
    let off = 12 + (idx as usize) * 12;
    if off + 12 > buf.len() { return None; }
    let block    = u32::from_le_bytes([buf[off],   buf[off+1], buf[off+2], buf[off+3]]);
    let leaf_lo  = u32::from_le_bytes([buf[off+4], buf[off+5], buf[off+6], buf[off+7]]);
    let leaf_hi  = u16::from_le_bytes([buf[off+8], buf[off+9]]);
    let unused   = u16::from_le_bytes([buf[off+10], buf[off+11]]);
    Some(ExtentIdx { block, leaf_lo, leaf_hi, _unused: unused })
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

/// Write an extent header into the leading 12 bytes of any
/// buffer ≥ 12 bytes (used by inline + child block writers).
/// # C: O(1)
pub fn write_extent_header_slice(buf: &mut [u8], hdr: &ExtentHeader) {
    buf[0..2].copy_from_slice(&hdr.magic.to_le_bytes());
    buf[2..4].copy_from_slice(&hdr.entries.to_le_bytes());
    buf[4..6].copy_from_slice(&hdr.max.to_le_bytes());
    buf[6..8].copy_from_slice(&hdr.depth.to_le_bytes());
    buf[8..12].copy_from_slice(&hdr.generation.to_le_bytes());
}

/// Write a leaf extent into a slice buffer at index `idx`.
/// # C: O(1)
pub fn write_inline_extent_slice(buf: &mut [u8], idx: u16, e: &Extent) {
    let off = 12 + (idx as usize) * 12;
    buf[off    ..off+ 4].copy_from_slice(&e.block.to_le_bytes());
    buf[off+ 4..off+ 6].copy_from_slice(&e.len.to_le_bytes());
    buf[off+ 6..off+ 8].copy_from_slice(&e.start_hi.to_le_bytes());
    buf[off+ 8..off+12].copy_from_slice(&e.start_lo.to_le_bytes());
}

/// Write an extent_idx into the inline `i_block` at index `idx`.
/// # C: O(1)
pub fn write_extent_idx(i_block: &mut [u8; I_BLOCK_LEN], idx: u16, e: &ExtentIdx) {
    let off = 12 + (idx as usize) * 12;
    i_block[off    ..off+ 4].copy_from_slice(&e.block.to_le_bytes());
    i_block[off+ 4..off+ 8].copy_from_slice(&e.leaf_lo.to_le_bytes());
    i_block[off+ 8..off+10].copy_from_slice(&e.leaf_hi.to_le_bytes());
    i_block[off+10..off+12].copy_from_slice(&0u16.to_le_bytes());
}

/// Slice variant for writing extent_idx records into an interior
/// (depth ≥ 1) block buffer. Same layout as the inline variant.
/// # C: O(1)
pub fn write_extent_idx_slice(buf: &mut [u8], idx: u16, e: &ExtentIdx) {
    let off = 12 + (idx as usize) * 12;
    buf[off    ..off+ 4].copy_from_slice(&e.block.to_le_bytes());
    buf[off+ 4..off+ 8].copy_from_slice(&e.leaf_lo.to_le_bytes());
    buf[off+ 8..off+10].copy_from_slice(&e.leaf_hi.to_le_bytes());
    buf[off+10..off+12].copy_from_slice(&0u16.to_le_bytes());
}

/// Write an extent header into the leading 12 bytes of `i_block`.
/// Caller is responsible for bringing leaves in sync with
/// `hdr.entries`; this helper only touches the header words.
/// # C: O(1)
pub fn write_extent_header(i_block: &mut [u8; I_BLOCK_LEN], hdr: &ExtentHeader) {
    i_block[0..2].copy_from_slice(&hdr.magic.to_le_bytes());
    i_block[2..4].copy_from_slice(&hdr.entries.to_le_bytes());
    i_block[4..6].copy_from_slice(&hdr.max.to_le_bytes());
    i_block[6..8].copy_from_slice(&hdr.depth.to_le_bytes());
    i_block[8..12].copy_from_slice(&hdr.generation.to_le_bytes());
}

/// Write the `idx`-th inline leaf extent. Caller already
/// updated the header's `entries` count to cover `idx`.
/// # C: O(1)
pub fn write_inline_extent(i_block: &mut [u8; I_BLOCK_LEN], idx: u16, e: &Extent) {
    let off = 12 + (idx as usize) * 12;
    i_block[off    ..off+ 4].copy_from_slice(&e.block.to_le_bytes());
    i_block[off+ 4..off+ 6].copy_from_slice(&e.len.to_le_bytes());
    i_block[off+ 6..off+ 8].copy_from_slice(&e.start_hi.to_le_bytes());
    i_block[off+ 8..off+12].copy_from_slice(&e.start_lo.to_le_bytes());
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
