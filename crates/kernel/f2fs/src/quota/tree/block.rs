//! One block of a quota file, and the two free lists that thread them.
//!
//! Every block reference in the file is untrusted, so nothing here follows one
//! before checking it against the header's block count. Two lists run through
//! the same blocks and they are NOT the same list:
//!
//! - The FREE-BLOCK list holds blocks that belong to the file and hold
//!   nothing. Its head is `free_blk`, it is singly linked, and a block is
//!   taken off it before it is used for anything.
//! - The FREE-ENTRY list holds LEAF blocks that still have a record slot
//!   spare. Its head is `free_entry` and it is doubly linked, because a leaf
//!   that fills up is unlinked from the middle.
//!
//! Both heads live in the file's header, so every operation that moves one
//! changes the info the caller must store back.

use alloc::vec::Vec;

use super::super::info::Info;
use super::super::uapi::*;
use super::super::QuotaError;

/// Byte offset a block starts at. # C: O(1)
pub fn block_start(blk: u32) -> Result<usize, QuotaError> {
    (blk as usize).checked_mul(QT_BLOCK_SIZE).ok_or(QuotaError::BlockOutOfRange)
}

/// One block of the file, by number. # C: O(1)
pub fn block(file: &[u8], blk: u32) -> Result<&[u8], QuotaError> {
    let at = block_start(blk)?;
    file.get(at..at + QT_BLOCK_SIZE).ok_or(QuotaError::Truncated)
}

/// One block of the file, to be changed. # C: O(1)
pub fn block_mut(file: &mut [u8], blk: u32) -> Result<&mut [u8], QuotaError> {
    let at = block_start(blk)?;
    file.get_mut(at..at + QT_BLOCK_SIZE).ok_or(QuotaError::Truncated)
}

/// A four-byte little-endian field of a block. # C: O(1)
pub fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Store one. # C: O(1)
pub fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + U32_LEN].copy_from_slice(&v.to_le_bytes());
}

/// The reference stored in slot `idx` of a tree block. # C: O(1)
pub fn reference(blk: &[u8], idx: u32) -> u32 { le32(blk, (idx as usize) * REF_SIZE) }

/// Point slot `idx` of a tree block at `to`. # C: O(1)
pub fn set_reference(blk: &mut [u8], idx: u32, to: u32) {
    put32(blk, (idx as usize) * REF_SIZE, to);
}

/// Whether every reference in a tree block is absent, which is what makes the
/// block returnable to the free-block list. # C: O(refs per block)
pub fn all_refs_absent(blk: &[u8]) -> bool {
    (0..refs_in_block()).all(|i| reference(blk, i) == 0)
}

/// References one block holds. # C: O(1)
pub fn refs_in_block() -> u32 { (QT_BLOCK_SIZE >> REF_BITS) as u32 }

/// Whether a reference names a block the file actually has.
///
/// The lower bound is the root, not zero: no reference may point at the block
/// holding the headers, and zero is spelled by the caller as "absent".
/// # C: O(1)
pub fn in_range(info: &Info, blk: u32) -> Result<(), QuotaError> {
    if blk < QT_TREE_OFF || blk >= info.blocks { return Err(QuotaError::BlockOutOfRange); }
    Ok(())
}

// -------------------------------------------------------------- leaf headers

/// Head of the free-entry list this leaf continues. # C: O(1)
pub fn next_free(file: &[u8], blk: u32) -> Result<u32, QuotaError> {
    Ok(le32(block(file, blk)?, DQDH_NEXT_FREE))
}

/// The leaf before this one on the free-entry list. # C: O(1)
pub fn prev_free(file: &[u8], blk: u32) -> Result<u32, QuotaError> {
    Ok(le32(block(file, blk)?, DQDH_PREV_FREE))
}

/// Records this leaf holds. # C: O(1)
pub fn entries(file: &[u8], blk: u32) -> Result<u16, QuotaError> {
    let b = block(file, blk)?;
    Ok(u16::from_le_bytes([b[DQDH_ENTRIES], b[DQDH_ENTRIES + 1]]))
}

/// Set one of the two link words of a leaf's header. # C: O(1)
pub fn set_link(file: &mut [u8], blk: u32, at: usize, to: u32) -> Result<(), QuotaError> {
    put32(block_mut(file, blk)?, at, to);
    Ok(())
}

/// Set the record count of a leaf. # C: O(1)
pub fn set_entries(file: &mut [u8], blk: u32, n: u16) -> Result<(), QuotaError> {
    let b = block_mut(file, blk)?;
    b[DQDH_ENTRIES..DQDH_ENTRIES + U16_LEN].copy_from_slice(&n.to_le_bytes());
    Ok(())
}

/// Whether a leaf's header describes a leaf of this file.
///
/// Both links are checked against the block count and the record count
/// against what one block can hold, because every later step trusts all
/// three. # C: O(1)
pub fn check_header(file: &[u8], info: &Info, blk: u32) -> Result<(), QuotaError> {
    for v in [next_free(file, blk)?, prev_free(file, blk)?] {
        if v >= info.blocks { return Err(QuotaError::BlockOutOfRange); }
    }
    if entries(file, blk)? as usize > super::super::info::entries_per_block(QT_BLOCK_SIZE, info.revision) {
        return Err(QuotaError::BadEntryCount);
    }
    Ok(())
}

// ----------------------------------------------------------- the free blocks

/// Take a block that holds nothing: off the free-block list when one is
/// there, otherwise a new one at the end of the file.
///
/// The block is handed back ZEROED, which is what both callers want — a tree
/// block full of stale references would be followed, and a leaf full of stale
/// records would report identities that were deleted.
/// # C: O(1), plus one block of growth
pub fn take_free_block(file: &mut Vec<u8>, info: &mut Info) -> Result<u32, QuotaError> {
    let blk = if info.free_blk != 0 {
        let blk = info.free_blk;
        in_range(info, blk)?;
        check_header(file, info, blk)?;
        info.free_blk = next_free(file, blk)?;
        blk
    } else {
        let blk = info.blocks;
        let end = block_start(blk)?.checked_add(QT_BLOCK_SIZE).ok_or(QuotaError::BlockOutOfRange)?;
        if file.len() < end { file.resize(end, 0); }
        info.blocks = info.blocks.checked_add(1).ok_or(QuotaError::BlockOutOfRange)?;
        blk
    };
    block_mut(file, blk)?.fill(0);
    Ok(blk)
}

/// Give a block back: it holds nothing and becomes the head of the
/// free-block list. # C: O(1)
pub fn put_free_block(file: &mut Vec<u8>, info: &mut Info, blk: u32) -> Result<(), QuotaError> {
    in_range(info, blk)?;
    block_mut(file, blk)?.fill(0);
    set_link(file, blk, DQDH_NEXT_FREE, info.free_blk)?;
    set_link(file, blk, DQDH_PREV_FREE, 0)?;
    set_entries(file, blk, 0)?;
    info.free_blk = blk;
    Ok(())
}

// ---------------------------------------------------------- the free entries

/// Take a leaf off the list of leaves with a slot spare.
///
/// The list is doubly linked precisely for this: a leaf that fills up is
/// unlinked from wherever it sits, and only when it is the head does the
/// header's own pointer move. # C: O(1)
pub fn remove_free_entry(file: &mut Vec<u8>, info: &mut Info, blk: u32) -> Result<(), QuotaError> {
    let next = next_free(file, blk)?;
    let prev = prev_free(file, blk)?;
    if next != 0 {
        in_range(info, next)?;
        set_link(file, next, DQDH_PREV_FREE, prev)?;
    }
    if prev != 0 {
        in_range(info, prev)?;
        set_link(file, prev, DQDH_NEXT_FREE, next)?;
    } else {
        info.free_entry = next;
    }
    set_link(file, blk, DQDH_NEXT_FREE, 0)?;
    set_link(file, blk, DQDH_PREV_FREE, 0)?;
    Ok(())
}

/// Put a leaf at the head of that list, because it now has a slot spare.
/// # C: O(1)
pub fn insert_free_entry(file: &mut Vec<u8>, info: &mut Info, blk: u32) -> Result<(), QuotaError> {
    in_range(info, blk)?;
    let head = info.free_entry;
    set_link(file, blk, DQDH_NEXT_FREE, head)?;
    set_link(file, blk, DQDH_PREV_FREE, 0)?;
    if head != 0 {
        in_range(info, head)?;
        set_link(file, head, DQDH_PREV_FREE, blk)?;
    }
    info.free_entry = blk;
    Ok(())
}
