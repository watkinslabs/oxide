//! The inode block, and the one arithmetic nearly every read depends on.
//!
//! The address array does not begin where the layout puts it. Two regions are
//! carved out of the same space, at opposite ends:
//!
//! - The **extra attribute** region overlays the array's HEAD, so the first
//!   usable address sits `i_extra_isize` bytes further in.
//! - The **inline attribute** reservation takes the array's TAIL, so the last
//!   usable address sits that many slots earlier.
//!
//! Both are per-inode, not per-volume. Reading the array at its nominal offset
//! returns the extra attributes as if they were block addresses; reading it at
//! its nominal width runs into the attribute region. Neither fails: both
//! return numbers that look like addresses.

use crate::features;
use crate::flags::*;
use crate::uapi::*;

use super::footer::NodeError;

/// One inode, as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inode {
    pub mode: u16,
    pub advise: u8,
    pub inline: u8,
    pub uid: u32,
    pub gid: u32,
    pub links: u32,
    pub size: u64,
    pub blocks: u64,
    pub atime: (u64, u32),
    pub ctime: (u64, u32),
    pub mtime: (u64, u32),
    pub generation: u32,
    pub current_depth: u32,
    pub xattr_nid: u32,
    pub flags: u32,
    pub pino: u32,
    pub dir_level: u8,
    /// The one extent the inode caches: file offset, block address, length.
    pub ext: (u32, u32, u32),
    /// Bytes of extra attribute, zero when the inode carries none.
    pub extra_isize: usize,
    /// Address slots reserved for inline attributes, in units of four bytes.
    pub inline_xattr_addrs: usize,
    pub projid: u32,
    pub inode_checksum: u32,
    pub crtime: Option<(u64, u32)>,
    pub compress_algorithm: u8,
    pub log_cluster_size: u8,
}

impl Inode {
    /// Whether the named inline flag is set. # C: O(1)
    pub fn has(&self, flag: u8) -> bool { self.inline & flag != 0 }

    /// Whether the file's data lives in the inode block itself. # C: O(1)
    pub fn inline_data(&self) -> bool { self.has(INLINE_DATA) }

    /// Whether the directory's entries live in the inode block. # C: O(1)
    pub fn inline_dentry(&self) -> bool { self.has(INLINE_DENTRY) }

    /// Whether the file is stored compressed. # C: O(1)
    pub fn compressed(&self) -> bool { self.flags & F2FS_COMPR_FL != 0 }

    /// Whether the file's contents and name are encrypted. # C: O(1)
    pub fn encrypted(&self) -> bool { self.flags & F2FS_ENCRYPT_FL != 0 }

    /// Whether the directory resolves names case-insensitively. # C: O(1)
    pub fn casefolded(&self) -> bool { self.flags & F2FS_CASEFOLD_FL != 0 }

    /// Byte offset of the address array's first usable slot. # C: O(1)
    pub fn addr_base(&self) -> usize { OFFSET_OF_END_OF_I_EXT + self.extra_isize }

    /// Usable address slots, both carve-outs applied.
    ///
    /// This is the width the block-index walk splits its first range at, so it
    /// is also where the boundary between the inode's own addresses and the
    /// first direct node falls.
    /// # C: O(1)
    pub fn addrs_per_inode(&self) -> usize {
        (DEF_ADDRS_PER_INODE - self.extra_isize / 4).saturating_sub(self.inline_xattr_addrs)
    }

    /// Byte offset of the inline attribute region, and its length.
    ///
    /// The region is anchored to the array's NOMINAL end, not to the usable
    /// end, so it does not move when the extra attributes grow.
    /// # C: O(1)
    pub fn inline_xattr_span(&self) -> Option<(usize, usize)> {
        if !self.has(INLINE_XATTR) || self.inline_xattr_addrs == 0 { return None; }
        let at = OFFSET_OF_END_OF_I_EXT + (DEF_ADDRS_PER_INODE - self.inline_xattr_addrs) * 4;
        Some((at, self.inline_xattr_addrs * 4))
    }

    /// Byte offset of the inline data region, and its length. # C: O(1)
    pub fn inline_data_span(&self) -> (usize, usize) {
        let at = self.addr_base() + INLINE_RESERVED_SIZE * 4;
        let len = self.addrs_per_inode().saturating_sub(INLINE_RESERVED_SIZE) * 4;
        (at, len)
    }

    /// One address out of the inode's own array. # C: O(1)
    pub fn addr(&self, block: &[u8], index: usize) -> Option<u32> {
        if index >= self.addrs_per_inode() { return None; }
        le32(block, self.addr_base() + index * 4)
    }

    /// One of the five node ids the inode carries. # C: O(1)
    pub fn nid(&self, block: &[u8], slot: usize) -> Option<u32> {
        if slot >= DEF_NIDS_PER_INODE { return None; }
        le32(block, I_NID_OFF + slot * 4)
    }
}

/// Read an inode block.
///
/// `feature` decides two fields that are not self-describing: whether the
/// extra attribute region exists at all, and whether the inline attribute
/// reservation is the inode's own number or the fixed default.
/// # C: O(1)
pub fn parse(block: &[u8], feature: u32) -> Option<Inode> {
    if block.len() < BLKSIZE { return None; }
    let inline = *block.get(I_INLINE)?;
    let extra_isize = if inline & EXTRA_ATTR != 0 && features::has_extra_attr(feature) {
        le16(block, I_EXTRA_ISIZE)? as usize
    } else {
        0
    };
    let inline_xattr_addrs = if features::has_flexible_inline_xattr(feature) {
        le16(block, I_INLINE_XATTR_SIZE)? as usize
    } else if inline & (INLINE_XATTR | INLINE_DENTRY) != 0 {
        // A volume without the flexible reservation still carves the fixed
        // two hundred bytes out for an inode that has inline entries, even
        // when it holds no attributes: the entry layout was defined around it.
        DEFAULT_INLINE_XATTR_ADDRS
    } else {
        0
    };
    let fits = |field: usize, width: usize| field + width <= OFFSET_OF_END_OF_I_EXT + extra_isize;
    let crtime = if features::has_inode_crtime(feature) && fits(I_CRTIME, 8) {
        Some((le64(block, I_CRTIME)?, le32(block, I_CRTIME_NSEC)?))
    } else {
        None
    };
    Some(Inode {
        mode: le16(block, I_MODE)?,
        advise: *block.get(I_ADVISE)?,
        inline,
        uid: le32(block, I_UID)?,
        gid: le32(block, I_GID)?,
        links: le32(block, I_LINKS)?,
        size: le64(block, I_SIZE)?,
        blocks: le64(block, I_BLOCKS)?,
        atime: (le64(block, I_ATIME)?, le32(block, I_ATIME_NSEC)?),
        ctime: (le64(block, I_CTIME)?, le32(block, I_CTIME_NSEC)?),
        mtime: (le64(block, I_MTIME)?, le32(block, I_MTIME_NSEC)?),
        generation: le32(block, I_GENERATION)?,
        current_depth: le32(block, I_CURRENT_DEPTH)?,
        xattr_nid: le32(block, I_XATTR_NID)?,
        flags: le32(block, I_FLAGS)?,
        pino: le32(block, I_PINO)?,
        dir_level: *block.get(I_DIR_LEVEL)?,
        ext: (le32(block, I_EXT_FOFS)?, le32(block, I_EXT_BLK)?, le32(block, I_EXT_LEN)?),
        extra_isize,
        inline_xattr_addrs,
        projid: if features::has_project_quota(feature) && fits(I_PROJID, 4) {
            le32(block, I_PROJID)?
        } else {
            0
        },
        inode_checksum: if fits(I_INODE_CHECKSUM, 4) { le32(block, I_INODE_CHECKSUM)? } else { 0 },
        crtime,
        compress_algorithm: if fits(I_COMPRESS_FLAG, 2) { *block.get(I_COMPRESS_ALGORITHM)? } else { 0 },
        log_cluster_size: if fits(I_COMPRESS_FLAG, 2) { *block.get(I_LOG_CLUSTER_SIZE)? } else { 0 },
    })
}

/// Whether an inode's own fields can describe a real file.
///
/// A zero block count is the one that matters most: the count includes the
/// inode block itself, so zero means the inode was never written and every
/// address in it is whatever the segment held before.
/// # C: O(1)
pub fn sanity(i: &Inode, ino: u32, feature: u32) -> Result<(), NodeError> {
    if i.blocks == 0 { return Err(NodeError::Checksum); }
    if i.xattr_nid == ino { return Err(NodeError::BadNid(i.xattr_nid)); }
    if i.has(EXTRA_ATTR) {
        if !features::has_extra_attr(feature) { return Err(NodeError::Checksum); }
        if i.extra_isize > TOTAL_EXTRA_ATTR_SIZE
            || i.extra_isize < MIN_EXTRA_ATTR_SIZE
            || i.extra_isize % 4 != 0
        {
            return Err(NodeError::Checksum);
        }
    }
    if i.inline_xattr_addrs > DEF_ADDRS_PER_INODE - i.extra_isize / 4 {
        return Err(NodeError::Checksum);
    }
    Ok(())
}

/// Whether the block's stored inode checksum matches, when the volume keeps
/// one that this inode is wide enough to hold. # C: O(BLKSIZE)
pub fn checksum_ok(i: &Inode, block: &[u8], seed: u32, feature: u32) -> bool {
    if !features::has_inode_chksum(feature) || !i.has(EXTRA_ATTR) { return true; }
    if I_INODE_CHECKSUM + 4 > OFFSET_OF_END_OF_I_EXT + i.extra_isize { return true; }
    match crate::checksum::inode_chksum(seed, block) {
        Some(c) => c == i.inode_checksum,
        None => false,
    }
}

#[cfg(test)]
#[path = "../tests/inode.rs"]
mod tests;
