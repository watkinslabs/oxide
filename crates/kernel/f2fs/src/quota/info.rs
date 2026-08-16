//! The two headers at the front of a quota file, and what they imply.
//!
//! The first says which of the three kinds the file is and which revision its
//! records are in; the second says how much of the file is in use. Everything
//! the tree walk needs — the record width, the tree's depth, how many entries
//! a leaf holds — is derived from those two, not stored.

use super::uapi::*;
use super::QuotaError;

/// Which record layout the file's entries are in.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Revision {
    /// Four-byte limits.
    R0,
    /// Eight-byte limits.
    R1,
}

impl Revision {
    /// The revision a version word names. # C: O(1)
    pub fn from_version(version: u32) -> Result<Self, QuotaError> {
        match version {
            VERSION_R0 => Ok(Revision::R0),
            VERSION_R1 => Ok(Revision::R1),
            _ => Err(QuotaError::BadVersion),
        }
    }

    /// Bytes one record occupies. # C: O(1)
    pub fn entry_size(self) -> usize {
        match self { Revision::R0 => R0_SIZE, Revision::R1 => R1_SIZE }
    }

    /// Widest space limit, in bytes, this revision can express. # C: O(1)
    pub fn max_space_limit(self) -> u64 {
        match self { Revision::R0 => R0_MAX_SPACE_LIMIT, Revision::R1 => R1_MAX_LIMIT }
    }

    /// Widest inode limit this revision can express. # C: O(1)
    pub fn max_inode_limit(self) -> u64 {
        match self { Revision::R0 => R0_MAX_INODE_LIMIT, Revision::R1 => R1_MAX_LIMIT }
    }
}

/// The file's two headers, resolved.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Info {
    /// Which of the three kinds the magic named.
    pub kind: usize,
    pub revision: Revision,
    /// Seconds a soft limit may be exceeded before it becomes hard, one value
    /// for space and one for inodes.
    pub bgrace: u32,
    pub igrace: u32,
    pub flags: u32,
    /// Blocks of the file that are in use. Every block reference in the tree
    /// is checked against this, so a corrupted value here is what would let a
    /// walk read past the file.
    pub blocks: u32,
    pub free_blk: u32,
    pub free_entry: u32,
    /// Steps from the root to a leaf, derived from the block size. Carried
    /// rather than recomputed because it is what bounds the walk.
    pub depth: u32,
}

/// Read a four-byte little-endian field.
fn le32(b: &[u8], at: usize) -> Result<u32, QuotaError> {
    let s = b.get(at..at + U32_LEN).ok_or(QuotaError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Steps from the root of a tree whose blocks are `block_size` bytes.
///
/// Each level consumes as many bits of the id as a block holds references, so
/// the depth is however many levels it takes for the levels together to
/// address every id the four-byte identity space contains.
/// # C: O(depth)
pub fn depth_for(block_size: usize) -> u32 {
    let epb = (block_size >> REF_BITS) as u64;
    let mut entries = epb;
    let mut levels = 1;
    while entries < 1u64 << u32::BITS {
        entries = entries.saturating_mul(epb);
        levels += 1;
    }
    levels
}

/// References one tree block holds. # C: O(1)
pub fn refs_per_block(block_size: usize) -> u32 { (block_size >> REF_BITS) as u32 }

/// Records one leaf block holds, once its header is subtracted. # C: O(1)
pub fn entries_per_block(block_size: usize, rev: Revision) -> usize {
    (block_size - DQDH_SIZE) / rev.entry_size()
}

/// Which slot of the level at `depth` an id selects.
///
/// The most significant part of the id picks at the root and the least at the
/// leaf, so the level's divisor depends on how far the leaf still is.
/// # C: O(depth)
pub fn index_of(id: u32, depth: u32, tree_depth: u32, block_size: usize) -> u32 {
    let epb = refs_per_block(block_size);
    let mut id = id;
    let mut steps = tree_depth.saturating_sub(depth).saturating_sub(1);
    while steps > 0 { id /= epb; steps -= 1; }
    id % epb
}

/// Read both headers out of the front of a quota file.
///
/// `kind` is what the caller believes the file is; the magic must agree. A
/// user file mounted as the group file decodes without error and accounts
/// every identity against the wrong table, so the check is not optional.
/// # C: O(1)
pub fn parse(file: &[u8], kind: usize) -> Result<Info, QuotaError> {
    if kind >= MAX_QUOTAS { return Err(QuotaError::BadKind); }
    let magic = le32(file, DQH_MAGIC)?;
    if magic != MAGIC[kind] { return Err(QuotaError::BadMagic); }
    let version = le32(file, DQH_VERSION)?;
    if version > MAX_VERSION { return Err(QuotaError::BadVersion); }
    let revision = Revision::from_version(version)?;

    let blocks = le32(file, INFO_OFF + DQI_BLOCKS)?;
    let free_blk = le32(file, INFO_OFF + DQI_FREE_BLK)?;
    let free_entry = le32(file, INFO_OFF + DQI_FREE_ENTRY)?;
    let info = Info {
        kind,
        revision,
        bgrace: le32(file, INFO_OFF + DQI_BGRACE)?,
        igrace: le32(file, INFO_OFF + DQI_IGRACE)?,
        flags: le32(file, INFO_OFF + DQI_FLAGS)?,
        blocks,
        free_blk,
        free_entry,
        depth: depth_for(QT_BLOCK_SIZE),
    };
    check(&info, file.len())?;
    Ok(info)
}

/// Whether the headers can describe a file of `file_len` bytes.
///
/// A block count past the file's end is the one field that turns every later
/// range check into a permission to read past the end.
/// # C: O(1)
pub fn check(info: &Info, file_len: usize) -> Result<(), QuotaError> {
    let claimed = (info.blocks as u64) << QT_BLOCK_BITS;
    if claimed > file_len as u64 { return Err(QuotaError::BlocksPastEnd); }
    for head in [info.free_blk, info.free_entry] {
        if head != 0 && (head <= QT_TREE_OFF || head >= info.blocks) {
            return Err(QuotaError::BlockOutOfRange);
        }
    }
    Ok(())
}

/// Write both headers back over the front of a quota file. # C: O(1)
pub fn store(file: &mut [u8], info: &Info) -> Result<(), QuotaError> {
    if info.kind >= MAX_QUOTAS { return Err(QuotaError::BadKind); }
    let version = match info.revision { Revision::R0 => VERSION_R0, Revision::R1 => VERSION_R1 };
    let fields = [
        (DQH_MAGIC, MAGIC[info.kind]),
        (DQH_VERSION, version),
        (INFO_OFF + DQI_BGRACE, info.bgrace),
        (INFO_OFF + DQI_IGRACE, info.igrace),
        (INFO_OFF + DQI_FLAGS, info.flags),
        (INFO_OFF + DQI_BLOCKS, info.blocks),
        (INFO_OFF + DQI_FREE_BLK, info.free_blk),
        (INFO_OFF + DQI_FREE_ENTRY, info.free_entry),
    ];
    for (at, v) in fields {
        let s = file.get_mut(at..at + U32_LEN).ok_or(QuotaError::Truncated)?;
        s.copy_from_slice(&v.to_le_bytes());
    }
    Ok(())
}
