//! Making a slot for an identity the tree has never held.
//!
//! A first allocation by a new uid, gid or project has nowhere to be recorded
//! until the tree grows a path down to a leaf with a slot spare. Growing it
//! touches four things that must all agree afterwards, which is why this is
//! one operation and not four:
//!
//! - the header's block count, when the file gains a block at its end;
//! - the free-BLOCK list, when it gains one from there instead;
//! - the free-ENTRY list, when a leaf is created, or fills up and leaves it;
//! - the reference in the parent block, written LAST, so a failure halfway
//!   down leaves no path pointing at a block that was given back.
//!
//! The blocks a failed insert took are returned on the way out, level by
//! level. A tree that keeps them leaks a block of the quota file per failed
//! allocation, and nothing ever finds them again.

use alloc::vec::Vec;

use super::super::dqblk::{self, Dqblk};
use super::super::info::{entries_per_block, index_of, Info};
use super::super::uapi::*;
use super::super::QuotaError;
use super::block::{
    block, block_mut, block_start, check_header, entries, in_range, put_free_block, reference,
    remove_free_entry, set_entries, set_reference, take_free_block,
};
use super::find::{find_entry, store_at, walkable};

/// Write `id`'s record, making a slot for it when the tree has none.
///
/// Answers whether a slot had to be made, which is what tells the caller its
/// header changed and must be stored back.
/// # C: O(depth + entries per block)
pub fn write_or_create(
    file: &mut Vec<u8>,
    info: &mut Info,
    id: u32,
    d: &Dqblk,
) -> Result<bool, QuotaError> {
    if !dqblk::limits_fit(d, info.revision) { return Err(QuotaError::LimitTooWide); }
    walkable(info)?;
    if let Some(at) = find_entry(file, info, id)? {
        store_at(file, info, at, id, d)?;
        return Ok(false);
    }
    let at = insert(file, info, id)?;
    store_at(file, info, at, id, d)?;
    Ok(true)
}

/// Grow a path down to a slot for `id`, and answer where that slot is.
/// # C: O(depth)
pub fn insert(file: &mut Vec<u8>, info: &mut Info, id: u32) -> Result<usize, QuotaError> {
    walkable(info)?;
    let mut path = [0u32; MAX_PATH_BLOCKS];
    path[0] = QT_TREE_OFF;
    descend(file, info, id, &mut path, 0)
}

/// One level of the insert.
///
/// `path[depth]` is the block this level lives in, zero when the level does
/// not exist yet. A block taken here is given back if anything below fails,
/// which is the only thing that keeps a failed insert from leaking blocks.
/// # C: O(depth)
fn descend(
    file: &mut Vec<u8>,
    info: &mut Info,
    id: u32,
    path: &mut [u32; MAX_PATH_BLOCKS],
    depth: u32,
) -> Result<usize, QuotaError> {
    let mut fresh = false;
    if path[depth as usize] == 0 {
        let blk = take_free_block(file, info)?;
        if path[..depth as usize].contains(&blk) { return Err(QuotaError::Cycle); }
        path[depth as usize] = blk;
        fresh = true;
    }
    let here = path[depth as usize];
    let idx = index_of(id, depth, info.depth, QT_BLOCK_SIZE);
    let next = reference(block(file, here)?, idx);
    if next != 0 {
        in_range(info, next)?;
        if path[..=depth as usize].contains(&next) { return Err(QuotaError::Cycle); }
    }

    let below = if depth + 1 == info.depth {
        // The last reference level names the leaf holding the record. A
        // reference already here means the walk that said the identity is
        // absent and the tree disagree.
        if next != 0 { return Err(QuotaError::DanglingLeaf); }
        free_entry_slot(file, info).map(|(blk, at)| { path[depth as usize + 1] = blk; at })
    } else {
        path[depth as usize + 1] = next;
        descend(file, info, id, path, depth + 1)
    };

    match below {
        Ok(at) => {
            if next == 0 {
                let child = path[depth as usize + 1];
                set_reference(block_mut(file, here)?, idx, child);
            }
            Ok(at)
        }
        Err(e) => {
            if fresh {
                put_free_block(file, info, here)?;
                path[depth as usize] = 0;
            }
            Err(e)
        }
    }
}

/// A leaf with a slot spare, and the offset of that slot.
///
/// The leaf comes off the free-entry list when one is on it; otherwise a
/// block is taken and becomes that list. A leaf that this fills leaves the
/// list, because a full leaf offered to the next insert is a leaf that
/// insert cannot use.
/// # C: O(entries per block)
fn free_entry_slot(file: &mut Vec<u8>, info: &mut Info) -> Result<(u32, usize), QuotaError> {
    let per = entries_per_block(QT_BLOCK_SIZE, info.revision);
    let blk = if info.free_entry != 0 {
        let blk = info.free_entry;
        in_range(info, blk)?;
        check_header(file, info, blk)?;
        blk
    } else {
        // Zeroed, so its two links are absent and it is a list of one.
        let blk = take_free_block(file, info)?;
        info.free_entry = blk;
        blk
    };
    let size = info.revision.entry_size();
    let start = block_start(blk)?;
    let at = (0..per)
        .map(|i| start + DQDH_SIZE + i * size)
        .find(|&at| dqblk::unused(&file[at..at + size]))
        .ok_or(QuotaError::BlockFull)?;
    let n = entries(file, blk)?;
    if n as usize + 1 >= per { remove_free_entry(file, info, blk)?; }
    set_entries(file, blk, n + 1)?;
    Ok((blk, at))
}
