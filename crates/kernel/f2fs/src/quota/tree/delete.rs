//! Removing an identity's record, and giving back what held it.
//!
//! The mirror of the insert, and it has to give back exactly what that took
//! or the file grows forever. Three things happen on the way out and each is
//! conditional:
//!
//! - The record's slot is zeroed. A leaf that was FULL gains a slot and so
//!   rejoins the free-entry list; one that is merely no longer full is
//!   already on it.
//! - A leaf that loses its last record leaves the free-entry list and joins
//!   the free-BLOCK list, because an empty leaf is a block, not a leaf.
//! - The reference to it is cleared in its parent — always, because the
//!   last level's slot belongs to this identity alone even when the leaf it
//!   names is shared. A parent left with no references at all follows the
//!   leaf onto the free-block list, up to but never including the root.

use alloc::vec::Vec;

use super::super::info::{entries_per_block, index_of, Info};
use super::super::uapi::*;
use super::super::QuotaError;
use super::block::{
    all_refs_absent, block, block_mut, check_header, entries, in_range, insert_free_entry,
    put_free_block, reference, remove_free_entry, set_entries, set_reference,
};
use super::find::{find_entry, find_in_block, walkable};

/// Remove `id`'s record.
///
/// An identity the tree has no slot for is not an error: it has nothing to
/// remove. Answers whether anything was removed, which is what tells the
/// caller its header changed.
/// # C: O(depth + entries per block)
pub fn delete(file: &mut Vec<u8>, info: &mut Info, id: u32) -> Result<bool, QuotaError> {
    walkable(info)?;
    if find_entry(file, info, id)?.is_none() { return Ok(false); }
    let mut path = [0u32; MAX_PATH_BLOCKS];
    path[0] = QT_TREE_OFF;
    ascend(file, info, id, &mut path, 0)?;
    Ok(true)
}

/// One level of the removal, on the way back up. # C: O(depth)
fn ascend(
    file: &mut Vec<u8>,
    info: &mut Info,
    id: u32,
    path: &mut [u32; MAX_PATH_BLOCKS],
    depth: u32,
) -> Result<(), QuotaError> {
    let here = path[depth as usize];
    let idx = index_of(id, depth, info.depth, QT_BLOCK_SIZE);
    let next = reference(block(file, here)?, idx);
    in_range(info, next)?;
    if path[..=depth as usize].contains(&next) { return Err(QuotaError::Cycle); }

    if depth + 1 == info.depth {
        free_entry(file, info, id, next)?;
        path[depth as usize + 1] = 0;
    } else {
        path[depth as usize + 1] = next;
        ascend(file, info, id, path, depth + 1)?;
    }

    if path[depth as usize + 1] == 0 {
        set_reference(block_mut(file, here)?, idx, 0);
        if here != QT_TREE_OFF && all_refs_absent(block(file, here)?) {
            put_free_block(file, info, here)?;
            path[depth as usize] = 0;
        }
    }
    Ok(())
}

/// Give back one record's slot in a leaf. # C: O(entries per block)
fn free_entry(
    file: &mut Vec<u8>,
    info: &mut Info,
    id: u32,
    blk: u32,
) -> Result<(), QuotaError> {
    check_header(file, info, blk)?;
    let at = find_in_block(file, info, id, blk)?.ok_or(QuotaError::DanglingLeaf)?;
    let per = entries_per_block(QT_BLOCK_SIZE, info.revision);
    // A leaf holding a record while claiming to hold none contradicts itself,
    // and taking one off that count would claim it holds every record there is.
    let left = entries(file, blk)?.checked_sub(1).ok_or(QuotaError::BadEntryCount)?;
    set_entries(file, blk, left)?;
    if left == 0 {
        remove_free_entry(file, info, blk)?;
        put_free_block(file, info, blk)?;
        return Ok(());
    }
    let size = info.revision.entry_size();
    file[at..at + size].fill(0);
    if left as usize == per - 1 { insert_free_entry(file, info, blk)?; }
    Ok(())
}
