//! A quota file a whole volume can be built around.
//!
//! The per-record fixtures under `tests/quota/` build one file to test the
//! decoder. This builds one an actual MOUNT can account against: planted at
//! the tree depth the format derives, with a record the walk will find.

use alloc::vec::Vec;

use crate::quota::info::{depth_for, Revision};
use crate::quota::uapi::{QT_BLOCK_SIZE, SPACE_UNIT};

#[path = "quota/image.rs"]
mod raw;

/// Blocks the file occupies: the header, then one per tree level, then the
/// leaf the record sits in.
pub fn blocks() -> u32 { depth_for(QT_BLOCK_SIZE) + 2 }

/// A user-quota file holding one record for `id`.
///
/// `bhard_units` and `ihard` are the hard limits, zero meaning unlimited —
/// which is what a volume with accounting and no limits looks like.
/// # C: O(file bytes)
pub fn user_file(id: u32, bhard_units: u64, ihard: u64) -> Vec<u8> {
    let depth = depth_for(QT_BLOCK_SIZE);
    let n = blocks();
    let mut f = raw::file(crate::volume::quotas::USRQUOTA, Revision::R1, n);
    // One tree block per level, laid consecutively after the header; the last
    // is the leaf the record lands in.
    let chain: Vec<u32> = (0..depth).map(|i| 2 + i).collect();
    raw::plant(&mut f, id, depth, &chain);
    let leaf = *chain.last().expect("at least one level");
    raw::r1_entry(&mut f, leaf, 0, id, ihard, 0, 0, bhard_units, 0, 0, 0, 0);
    f
}

/// The byte count a limit of `units` stands for. # C: O(1)
pub fn units(n: u64) -> u64 { n * SPACE_UNIT as u64 }
