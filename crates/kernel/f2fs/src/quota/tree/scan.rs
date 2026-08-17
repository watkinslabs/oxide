//! The next identity at or after a given one, which is what a caller asking
//! "who else has a record?" needs.
//!
//! Walking every id is not an option — the identity space is the whole of a
//! four-byte number — so the scan uses the tree's own shape. A reference that
//! is absent at some level stands for every id below it at once, and skipping
//! it advances the answer by exactly that many ids. Getting that step wrong is
//! silent: the scan still returns an id that exists, just not the FIRST one,
//! so an enumeration quietly drops identities in between.

use super::super::dqblk::Dqblk;
use super::super::info::{index_of, Info};
use super::super::uapi::*;
use super::super::QuotaError;
use super::block::{block, refs_in_block};
use super::find::{read, walkable};

/// The lowest identity at or after `from` that the tree holds a record for.
/// # C: O(refs per block * depth)
pub fn next_id(file: &[u8], info: &Info, from: u32) -> Result<Option<u32>, QuotaError> {
    walkable(info)?;
    let mut id = u64::from(from);
    if !step(file, info, &mut id, QT_TREE_OFF, 0)? { return Ok(None); }
    Ok(u32::try_from(id).ok())
}

/// That identity and its record together, which is the pair the interface
/// above hands back. # C: O(refs per block * depth)
pub fn next_record(
    file: &[u8],
    info: &Info,
    from: u32,
) -> Result<Option<(u32, Dqblk)>, QuotaError> {
    let Some(id) = next_id(file, info, from)? else { return Ok(None) };
    let d = read(file, info, id)?.ok_or(QuotaError::DanglingLeaf)?;
    Ok(Some((id, d)))
}

/// One level of the scan.
///
/// `id` is carried by reference because the skipping is the answer: every
/// absent slot passed over moves it on by the span of ids that slot covers.
/// # C: O(refs per block * remaining depth)
fn step(
    file: &[u8],
    info: &Info,
    id: &mut u64,
    blk: u32,
    depth: u32,
) -> Result<bool, QuotaError> {
    let epb = u64::from(refs_in_block());
    let mut span = 1u64;
    for _ in depth..info.depth - 1 { span = span.saturating_mul(epb); }
    let here = block(file, blk)?;
    let Ok(at) = u32::try_from(*id) else { return Ok(false) };
    let start = index_of(at, depth, info.depth, QT_BLOCK_SIZE);
    for i in start..refs_in_block() {
        let child = super::block::reference(here, i);
        if child == 0 { *id += span; continue; }
        if child >= info.blocks || child < QT_TREE_OFF { return Err(QuotaError::BlockOutOfRange); }
        if depth + 1 == info.depth { return Ok(true); }
        if step(file, info, id, child, depth + 1)? { return Ok(true); }
    }
    Ok(false)
}
