//! Finding an identity's record: a radix walk over the file's own blocks.
//!
//! The file is a tree keyed by the identity itself. Each level consumes one
//! slice of the id and names the block holding the next level, until a leaf
//! block holds the records. Nothing in the file says a reference is sane, so
//! every step checks two things before following it — that the block is
//! inside the file the header describes, and that it is not one already on
//! the path. A tree that points back at itself is otherwise walked forever,
//! and a reference past the file's end reads whatever follows it.

use super::dqblk;
use super::info::{entries_per_block, index_of, Info};
use super::uapi::*;
use super::QuotaError;

/// One block of the file, by number.
fn block(file: &[u8], blk: u32) -> Result<&[u8], QuotaError> {
    let at = (blk as usize).checked_mul(QT_BLOCK_SIZE).ok_or(QuotaError::BlockOutOfRange)?;
    file.get(at..at + QT_BLOCK_SIZE).ok_or(QuotaError::Truncated)
}

/// The reference stored in slot `idx` of a tree block. # C: O(1)
fn reference(blk: &[u8], idx: u32) -> u32 {
    let at = (idx as usize) * REF_SIZE;
    u32::from_le_bytes([blk[at], blk[at + 1], blk[at + 2], blk[at + 3]])
}

/// Whether a reference names a block the file actually has.
///
/// The lower bound is the root, not zero: no reference may point at the block
/// holding the headers, and zero is spelled by the caller as "absent".
fn in_range(info: &Info, blk: u32) -> Result<(), QuotaError> {
    if blk < QT_TREE_OFF || blk >= info.blocks { return Err(QuotaError::BlockOutOfRange); }
    Ok(())
}

/// Byte offset of `id`'s record within the file, or `None` when the tree has
/// no record for it.
///
/// # C: O(depth + entries per block)
pub fn find_entry(file: &[u8], info: &Info, id: u32) -> Result<Option<usize>, QuotaError> {
    if info.depth == 0 || info.depth >= MAX_TREE_DEPTH { return Err(QuotaError::DepthTooBig); }
    if info.blocks <= QT_TREE_OFF { return Err(QuotaError::NoRoot); }
    let mut path = [0u32; MAX_PATH_BLOCKS];
    path[0] = QT_TREE_OFF;
    let mut depth = 0u32;
    loop {
        let here = block(file, path[depth as usize])?;
        let idx = index_of(id, depth, info.depth, QT_BLOCK_SIZE);
        let next = reference(here, idx);
        if next == 0 { return Ok(None); }
        in_range(info, next)?;
        if path[..=depth as usize].contains(&next) { return Err(QuotaError::Cycle); }
        path[depth as usize + 1] = next;
        depth += 1;
        if depth == info.depth { return find_in_block(file, info, id, next); }
    }
}

/// Byte offset of `id`'s record inside one leaf block.
///
/// A leaf reached through the tree is supposed to hold the record; when it
/// does not, the tree and the leaf disagree and that is corruption, not a
/// missing record. # C: O(entries per block)
pub fn find_in_block(
    file: &[u8],
    info: &Info,
    id: u32,
    blk: u32,
) -> Result<Option<usize>, QuotaError> {
    let leaf = block(file, blk)?;
    let size = info.revision.entry_size();
    let count = entries_per_block(QT_BLOCK_SIZE, info.revision);
    for i in 0..count {
        let at = DQDH_SIZE + i * size;
        if dqblk::id_of(&leaf[at..at + size], info.revision) == Some(id) {
            return Ok(Some((blk as usize) * QT_BLOCK_SIZE + at));
        }
    }
    Err(QuotaError::DanglingLeaf)
}

/// Records a leaf block claims to hold, checked against what one can hold.
/// # C: O(1)
pub fn block_entries(file: &[u8], info: &Info, blk: u32) -> Result<u16, QuotaError> {
    let leaf = block(file, blk)?;
    for at in [DQDH_NEXT_FREE, DQDH_PREV_FREE] {
        let v = u32::from_le_bytes([leaf[at], leaf[at + 1], leaf[at + 2], leaf[at + 3]]);
        if v >= info.blocks { return Err(QuotaError::BlockOutOfRange); }
    }
    let n = u16::from_le_bytes([leaf[DQDH_ENTRIES], leaf[DQDH_ENTRIES + 1]]);
    if n as usize > entries_per_block(QT_BLOCK_SIZE, info.revision) {
        return Err(QuotaError::BadEntryCount);
    }
    Ok(n)
}

/// Read `id`'s record. # C: O(depth + entries per block)
pub fn read(file: &[u8], info: &Info, id: u32) -> Result<Option<dqblk::Dqblk>, QuotaError> {
    let Some(at) = find_entry(file, info, id)? else { return Ok(None) };
    let size = info.revision.entry_size();
    let entry = file.get(at..at + size).ok_or(QuotaError::Truncated)?;
    Ok(Some(dqblk::parse(entry, info.revision)?))
}

/// Write a changed record back over the one already in the tree.
///
/// Only a record the tree already has a slot for is written here: making a
/// slot moves free lists and grows the file, which is the caller's business
/// and not a pure operation over these bytes.
/// # C: O(depth + entries per block)
pub fn write(
    file: &mut [u8],
    info: &Info,
    id: u32,
    d: &dqblk::Dqblk,
) -> Result<(), QuotaError> {
    if !dqblk::limits_fit(d, info.revision) { return Err(QuotaError::LimitTooWide); }
    let at = find_entry(file, info, id)?.ok_or(QuotaError::NoEntry)?;
    let bytes = dqblk::encode(d, id, info.revision);
    let slot = file.get_mut(at..at + bytes.len()).ok_or(QuotaError::Truncated)?;
    slot.copy_from_slice(&bytes);
    Ok(())
}
