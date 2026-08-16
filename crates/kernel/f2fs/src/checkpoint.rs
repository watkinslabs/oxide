//! The checkpoint: which of the two packs is current, and what it says.
//!
//! A pack is valid only when its FIRST and LAST blocks carry the same version
//! number and both pass their own CRC. That pairing is the atomicity: a
//! checkpoint interrupted halfway leaves a head the tail does not match, and
//! the pack is rejected whole rather than half-believed.
//!
//! The two version bitmaps are the trap. Where they sit inside the block
//! depends on a flag and on the payload length, in three different ways, and
//! reading a bitmap at the wrong offset does not fail — it silently selects
//! the other copy of every NAT block, so every node id resolves to a stale
//! address and the volume reads as an older version of itself.
//!
//! Module manifest:
//! - `bitmap`: where the two version bitmaps live, and reading a bit.

use alloc::vec::Vec;

use crate::flags::*;
use crate::uapi::*;

pub mod bitmap;
pub mod sanity;

pub use bitmap::{nat_bitmap, sit_bitmap, test_bit};

/// One checkpoint pack's header, resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub version: u64,
    pub user_block_count: u64,
    pub valid_block_count: u64,
    pub rsvd_segment_count: u32,
    pub overprov_segment_count: u32,
    pub free_segment_count: u32,
    pub cur_node_segno: [u32; MAX_ACTIVE_NODE_LOGS],
    pub cur_node_blkoff: [u16; MAX_ACTIVE_NODE_LOGS],
    pub cur_data_segno: [u32; MAX_ACTIVE_DATA_LOGS],
    pub cur_data_blkoff: [u16; MAX_ACTIVE_DATA_LOGS],
    pub flags: u32,
    pub pack_total_block_count: u32,
    pub pack_start_sum: u32,
    pub valid_node_count: u32,
    pub valid_inode_count: u32,
    pub next_free_nid: u32,
    pub sit_ver_bitmap_bytesize: u32,
    pub nat_ver_bitmap_bytesize: u32,
    pub checksum_offset: u32,
    pub elapsed_time: u64,
    pub alloc_type: [u8; MAX_ACTIVE_LOGS],
    /// Which of the two packs this came from: block zero of the checkpoint
    /// area, or one segment further in.
    pub pack: Pack,
}

/// Which of a volume's two checkpoint packs is meant.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Pack {
    First,
    Second,
}

impl Checkpoint {
    /// Whether `flag` is set. # C: O(1)
    pub fn has(&self, flag: u32) -> bool { self.flags & flag != 0 }

    /// Whether the pack was written by a clean unmount, which is what decides
    /// where the current-segment summaries were stored. # C: O(1)
    pub fn node_summaries_present(&self) -> bool {
        self.has(CP_UMOUNT_FLAG) || self.has(CP_FASTBOOT_FLAG)
    }

    /// First block of this pack, given where the checkpoint area starts.
    /// # C: O(1)
    pub fn start(&self, cp_blkaddr: u32, blks_per_seg: u32) -> u32 {
        match self.pack {
            Pack::First => cp_blkaddr,
            Pack::Second => cp_blkaddr + blks_per_seg,
        }
    }
}

/// Read a checkpoint block's header. # C: O(1)
pub fn parse(cp: &[u8], pack: Pack) -> Option<Checkpoint> {
    if cp.len() < BLKSIZE { return None; }
    let mut cur_node_segno = [0u32; MAX_ACTIVE_NODE_LOGS];
    let mut cur_node_blkoff = [0u16; MAX_ACTIVE_NODE_LOGS];
    let mut cur_data_segno = [0u32; MAX_ACTIVE_DATA_LOGS];
    let mut cur_data_blkoff = [0u16; MAX_ACTIVE_DATA_LOGS];
    for i in 0..MAX_ACTIVE_NODE_LOGS {
        cur_node_segno[i] = le32(cp, CP_CUR_NODE_SEGNO + i * 4)?;
        cur_node_blkoff[i] = le16(cp, CP_CUR_NODE_BLKOFF + i * 2)?;
    }
    for i in 0..MAX_ACTIVE_DATA_LOGS {
        cur_data_segno[i] = le32(cp, CP_CUR_DATA_SEGNO + i * 4)?;
        cur_data_blkoff[i] = le16(cp, CP_CUR_DATA_BLKOFF + i * 2)?;
    }
    let mut alloc_type = [0u8; MAX_ACTIVE_LOGS];
    alloc_type.copy_from_slice(cp.get(CP_ALLOC_TYPE..CP_ALLOC_TYPE + MAX_ACTIVE_LOGS)?);
    Some(Checkpoint {
        version: le64(cp, CP_CHECKPOINT_VER)?,
        user_block_count: le64(cp, CP_USER_BLOCK_COUNT)?,
        valid_block_count: le64(cp, CP_VALID_BLOCK_COUNT)?,
        rsvd_segment_count: le32(cp, CP_RSVD_SEGMENT_COUNT)?,
        overprov_segment_count: le32(cp, CP_OVERPROV_SEGMENT_COUNT)?,
        free_segment_count: le32(cp, CP_FREE_SEGMENT_COUNT)?,
        cur_node_segno,
        cur_node_blkoff,
        cur_data_segno,
        cur_data_blkoff,
        flags: le32(cp, CP_CKPT_FLAGS)?,
        pack_total_block_count: le32(cp, CP_PACK_TOTAL_BLOCK_COUNT)?,
        pack_start_sum: le32(cp, CP_PACK_START_SUM)?,
        valid_node_count: le32(cp, CP_VALID_NODE_COUNT)?,
        valid_inode_count: le32(cp, CP_VALID_INODE_COUNT)?,
        next_free_nid: le32(cp, CP_NEXT_FREE_NID)?,
        sit_ver_bitmap_bytesize: le32(cp, CP_SIT_VER_BITMAP_BYTESIZE)?,
        nat_ver_bitmap_bytesize: le32(cp, CP_NAT_VER_BITMAP_BYTESIZE)?,
        checksum_offset: le32(cp, CP_CHECKSUM_OFFSET_FIELD)?,
        elapsed_time: le64(cp, CP_ELAPSED_TIME)?,
        alloc_type,
        pack,
    })
}

/// Why a pack was rejected.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CpError {
    /// The block is unreadable or too short.
    Truncated,
    /// Its CRC offset is outside the range the format allows, or the CRC
    /// itself does not match.
    Checksum,
    /// The pack claims a length that cannot fit in a segment, or that is
    /// shorter than the two blocks a pack always has.
    PackLength,
    /// Head and tail carry different versions: the write did not finish.
    Torn,
}

/// Validate one pack from its head and tail blocks.
///
/// `head` is the pack's first block; `tail` is the block `pack_total_block_count - 1`
/// further on. The caller reads the tail only after the head has named its
/// length, which is why the length is bounded before the tail is fetched.
/// # C: O(BLKSIZE)
pub fn validate(head: &[u8], tail: &[u8], blks_per_seg: u32, pack: Pack)
    -> Result<Checkpoint, CpError> {
    let cp = version_of(head)?;
    let blocks = cp.pack_total_block_count;
    if blocks > blks_per_seg || blocks <= CP_PACKS { return Err(CpError::PackLength); }
    let tail_cp = version_of(tail)?;
    if tail_cp.version != cp.version { return Err(CpError::Torn); }
    Ok(Checkpoint { pack, ..cp })
}

/// The block's header, once its CRC has been checked. # C: O(BLKSIZE)
fn version_of(block: &[u8]) -> Result<Checkpoint, CpError> {
    if block.len() < BLKSIZE { return Err(CpError::Truncated); }
    if crate::checksum::crc_offset(block).is_none() { return Err(CpError::Checksum); }
    if !crate::checksum::checkpoint_ok(block) { return Err(CpError::Checksum); }
    parse(block, Pack::First).ok_or(CpError::Truncated)
}

/// Which of two valid packs is current.
///
/// The comparison is a SIGNED difference, not a plain `>`: the version counter
/// wraps, and after it does the newer pack holds the smaller number. Taking
/// the larger one there would mount a checkpoint older than the volume.
/// # C: O(1)
pub fn newer(a: u64, b: u64) -> bool { (a.wrapping_sub(b) as i64) > 0 }

/// Pick between the two packs' outcomes, preferring the newer valid one.
/// # C: O(1)
pub fn choose(first: Option<Checkpoint>, second: Option<Checkpoint>) -> Option<Checkpoint> {
    match (first, second) {
        (Some(a), Some(b)) => Some(if newer(b.version, a.version) { b } else { a }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// The whole checkpoint, head block plus payload blocks, as one buffer.
///
/// The payload exists so a volume with more segments than one block of bitmap
/// can describe still has somewhere to put the rest, and the bitmap readers
/// index into this buffer rather than into the head block alone.
/// # C: O(payload bytes)
pub fn joined(head: &[u8], payload: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BLKSIZE * (1 + payload.len()));
    out.extend_from_slice(head);
    for block in payload { out.extend_from_slice(block); }
    out
}

#[cfg(test)]
#[path = "tests/checkpoint.rs"]
mod tests;
