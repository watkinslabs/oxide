//! Attesting one block, climbing only as far as the tree is not yet known
//! good.
//!
//! The naive walk starts at the root and descends, re-hashing every block on
//! the path for every data block read. The path is `num_levels` blocks long
//! and its upper half is SHARED by an enormous number of data blocks, so a
//! sequential read of a large file re-hashes the root once per block.
//!
//! So the walk runs the other way. It climbs from the leaf, stopping at the
//! first hash block already recorded as checked, and only then descends,
//! verifying and recording each block it passes. A block's bit means it was
//! compared against the hash its PARENT holds for it — never that it was
//! merely read — so stopping at a set bit stops at a block whose contents are
//! already attested up to the root.
//!
//! Two failures this shape must not have, and does not:
//!
//! - **Nothing is trusted before it is checked.** The hash taken from a block
//!   is used only after that block matched its parent, or after its bit says
//!   it already did.
//! - **A block past the end of the data has no entry in the tree.** The tree
//!   covers the file's length, and the reference requires such a block to be
//!   all zeroes rather than skipping it — otherwise the tail of the last
//!   page, which userspace can see through a mapping, is unattested.

use alloc::vec::Vec;

use super::info::Verified;
use super::merkle::{Params, MAX_DIGEST_SIZE, MAX_LEVELS};
use super::VerityError;

/// One saved level of the climb.
#[derive(Clone)]
struct Step {
    block: Vec<u8>,
    index: u64,
    offset: usize,
}

/// Whether `data` really is the content of data block `index`.
///
/// `read_tree_block` is handed a tree-block index and returns that block's
/// bytes. `verified` records which tree blocks have already been checked and
/// is updated as the descent proves more of them; a caller with nothing
/// cached passes a freshly zeroed map and gets the full root-to-leaf walk.
/// # C: O(levels) blocks hashed, fewer once the upper tree is known
pub fn verify_block<F>(p: &Params, root: &[u8], verified: &mut Verified, index: u64,
                       data: &[u8], mut read_tree_block: F) -> Result<bool, VerityError>
where
    F: FnMut(u64) -> Result<Vec<u8>, VerityError>,
{
    if root.len() != p.digest_size { return Err(VerityError::Corrupted); }
    if data.len() != p.block_size { return Err(VerityError::BadBlockSize); }

    // The tree is built over the file's length. A block that starts at or
    // past it is covered by no hash, so the only thing that can be required
    // of it is that it holds nothing.
    let pos = index << p.log_blocksize;
    if pos >= p.data_size { return Ok(data.iter().all(|&b| b == 0)); }

    let mut climbed: Vec<Step> = Vec::with_capacity(p.num_levels);
    let mut want: Vec<u8> = Vec::new();
    let mut hidx = index;
    let mut level = 0usize;
    while level < p.num_levels {
        if level >= MAX_LEVELS { return Err(VerityError::TooManyLevels); }
        let next = hidx >> p.log_arity;
        let hblock = p.level_start[level] + next;
        let offset = ((hidx as usize) << p.digest_size.trailing_zeros()) & (p.block_size - 1);
        let block = read_tree_block(hblock)?;
        if block.len() != p.block_size { return Err(VerityError::BadBlockSize); }
        if verified.test(hblock) {
            // Already compared against its parent, so the hash it holds may
            // be believed without climbing any further.
            want = slice_at(&block, offset, p.digest_size)?;
            break;
        }
        climbed.push(Step { block, index: hblock, offset });
        hidx = next;
        level += 1;
    }
    // Reaching the top without a cached block leaves the descriptor's root as
    // the only thing to start from — which is the anchor the whole tree hangs
    // off, and the one value not read from the file's own blocks.
    if level == p.num_levels { want = root.to_vec(); }

    for step in climbed.iter().rev() {
        if p.hash_block(&step.block)?.as_bytes() != want.as_slice() { return Ok(false); }
        verified.set(step.index);
        want = slice_at(&step.block, step.offset, p.digest_size)?;
    }
    Ok(p.hash_block(data)?.as_bytes() == want.as_slice())
}

/// A digest-sized window of a tree block. # C: O(digest)
fn slice_at(block: &[u8], at: usize, len: usize) -> Result<Vec<u8>, VerityError> {
    let end = at.checked_add(len).ok_or(VerityError::Corrupted)?;
    Ok(block.get(at..end).ok_or(VerityError::Corrupted)?.to_vec())
}

/// A digest carried by value, for a caller building rather than checking.
/// # C: O(1)
pub fn digest_array(d: &super::merkle::Digest) -> [u8; MAX_DIGEST_SIZE] {
    let mut out = [0u8; MAX_DIGEST_SIZE];
    out[..d.as_bytes().len()].copy_from_slice(d.as_bytes());
    out
}

#[cfg(test)]
#[path = "../tests/veritywalk.rs"]
mod tests;
