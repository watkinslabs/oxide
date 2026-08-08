// ext4 inode + extent-header parser (on-disk `ext4_inode` +
// `ext4_extent_header` layout). Pure decoder — caller
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

use vfs::Timespec64;

use crate::superblock::Superblock;
use crate::timestamp as ts;

/// On-disk `i_flags` bit definitions and their statx attribute translation.
pub mod flags;
/// Direct-I/O alignment reporting for `STATX_DIOALIGN`.
pub mod dio;

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

/// Max extent-tree height (Linux `EXT4_MAX_EXTENT_DEPTH`). The root's
/// `eh_depth` cannot exceed this; every descent step strictly decreases depth,
/// so a walk is bounded — a corrupt/cyclic tree is rejected, not looped.
pub const EXT4_MAX_EXTENT_DEPTH: u16 = 5;

/// `EXT4_HUGE_FILE_FL` in `i_flags` — `i_blocks` is counted in fs-blocks, not
/// 512-byte sectors (only with the huge_file RO_COMPAT feature). # C: n/a
pub const EXT4_HUGE_FILE_FL: u32 = 0x0004_0000;

/// `EXT4_EXTENTS_FL` in `i_flags` — `i_block` holds an extent tree root, not
/// inline file/symlink bytes. # C: n/a
pub const EXT4_EXTENTS_FL: u32 = 0x0008_0000;

/// Valid extent-tree descent step: an interior node's child must be exactly one
/// level shallower (all ext4 leaves sit at the same depth). Bounds every tree
/// walk to the root depth — a step that is not strictly-decreasing-by-one marks
/// a corrupt/cyclic tree and is rejected instead of descended. # C: O(1)
#[inline]
pub fn extent_child_depth_ok(parent_depth: u16, child_depth: u16) -> bool {
    // `parent_depth - 1` (not `child_depth + 1`) so a `child_depth == u16::MAX`
    // from a corrupt node cannot overflow; the `!= 0` guard makes the sub safe.
    parent_depth != 0 && child_depth == parent_depth - 1
}

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
    /// `i_atime`: the SIGNED seconds base field @0x08 plus the epoch-high /
    /// nanosecond `i_atime_extra` @0x8C (present per `EXT4_FITS_IN_INODE`).
    /// Drives `st_atim`; the utimes writeback round-trips through it.
    pub atime:       Timespec64,
    /// `i_mtime` (`i_mtime` @0x10 + `i_mtime_extra` @0x88).
    pub mtime:       Timespec64,
    /// `i_ctime` (`i_ctime` @0x0C + `i_ctime_extra` @0x84).
    pub ctime:       Timespec64,
    /// `i_crtime` (creation/birth time; `i_crtime` @0x90 + `i_crtime_extra`
    /// @0x94). Drives `statx STATX_BTIME`. `None` when the inode's extra
    /// region does not reach `i_crtime` — the same predicate `ext4_getattr`
    /// uses to decide whether to set `STATX_BTIME` in `result_mask`. Absence is
    /// NOT an epoch sentinel: a file born at epoch second 0 is `Some(ZERO)`.
    pub crtime:      Option<Timespec64>,
    /// `i_flags` @0x20 — the ext4 inode flag word. Low bits are the `chattr`
    /// user flags (`EXT4_*_FL` == `FS_*_FL`: SECRM/UNRM/COMPR/SYNC/IMMUTABLE/
    /// APPEND/NODUMP/NOATIME/…); high bits are kernel-internal layout flags
    /// (EXTENTS_FL 0x80000, INLINE_DATA_FL 0x10000000). Drives
    /// `FS_IOC_GETFLAGS` and VFS immutable/append enforcement.
    pub i_flags:     u32,
    /// `i_projid` @0x9C — ext4 project id (Linux `struct ext4_inode::i_projid`).
    /// Meaningful only when the superblock advertises PROJECT and the inode is
    /// large enough to contain the field; otherwise Linux treats it as the
    /// default project id 0.
    pub i_projid:    u32,
    /// Inline extent tree root + leaves (60 bytes verbatim).
    pub i_block:     [u8; I_BLOCK_LEN],
    /// This inode's number, stamped by `read_inode` after parse (parse itself
    /// only sees the slot bytes). 0 = unknown (a bare `parse` result); read-side
    /// metadata_csum verify of this inode's dir blocks / external extent nodes
    /// keys on `inode_seed(ino, generation)`, so it is skipped when `ino == 0`.
    pub ino:         u32,
    /// `i_generation` @0x64 — the per-inode csum-seed input (with `ino`).
    pub generation:  u32,
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
        // i_blocks interpretation, exactly Linux `ext4_inode_blocks`:
        //  * huge_file feature CLEAR → 32-bit `i_blocks_lo` in 512-byte sectors;
        //    `0x74` is `l_i_reserved`, NOT high bits — merging it would corrupt
        //    the count on any pre-huge_file image.
        //  * huge_file feature SET → 48-bit `i_blocks_lo | (l_i_blocks_high<<32)`;
        //    if the inode's EXT4_HUGE_FILE_FL is set the unit is fs-BLOCKS, so
        //    shift up by `block_bits - 9` to normalise to 512-byte sectors.
        let i_flags_raw = u32::from_le_bytes([buf[0x20], buf[0x21], buf[0x22], buf[0x23]]);
        let blocks_lo = u32::from_le_bytes([buf[0x1C], buf[0x1D], buf[0x1E], buf[0x1F]]) as u64;
        let i_blocks = if sb.has_huge_file() {
            let blocks_hi = u16::from_le_bytes([buf[0x74], buf[0x75]]) as u64;
            let raw = blocks_lo | (blocks_hi << 32);
            if i_flags_raw & EXT4_HUGE_FILE_FL != 0 {
                raw << (sb.block_size.trailing_zeros().saturating_sub(9))
            } else {
                raw
            }
        } else {
            blocks_lo
        };
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
        // `EXT4_INODE_GET_{A,C,M}TIME` + `EXT4_EINODE_GET_XTIME(i_crtime)`.
        // Signed seconds: a pre-1970 base word
        // sign-extends rather than reading back as year 2106.
        let atime = ts::get_xtime(buf, isize, ts::I_ATIME, ts::I_ATIME_EXTRA);
        let ctime = ts::get_xtime(buf, isize, ts::I_CTIME, ts::I_CTIME_EXTRA);
        let mtime = ts::get_xtime(buf, isize, ts::I_MTIME, ts::I_MTIME_EXTRA);
        let crtime = ts::get_crtime(buf, isize);
        let i_projid = if isize >= 0xA0 {
            u32::from_le_bytes([buf[0x9C], buf[0x9D], buf[0x9E], buf[0x9F]])
        } else { 0 };
        Ok(Inode {
            mode,
            size: size_lo | (size_hi << 32),
            links_count: links,
            i_blocks,
            uid,
            gid,
            atime,
            mtime,
            ctime,
            crtime,
            i_flags: i_flags_raw,
            i_projid,
            i_block,
            ino: 0, // stamped by read_inode (parse has no ino)
            generation: u32::from_le_bytes([buf[0x64], buf[0x65], buf[0x66], buf[0x67]]),
        })
    }

    /// The four decoded timestamps as one value, for handing to the VFS inode
    /// builder without a positional 4-tuple. # C: O(1)
    pub fn times(&self) -> ts::InodeTimes {
        ts::InodeTimes { atime: self.atime, mtime: self.mtime, ctime: self.ctime, btime: self.crtime }
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
        if self.i_blocks != 0 || (self.i_flags & EXT4_EXTENTS_FL) != 0 { return None; }
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
