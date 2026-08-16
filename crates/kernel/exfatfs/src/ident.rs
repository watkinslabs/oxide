//! What an inode NUMBER is on a filesystem that stores none.
//!
//! exFAT records no inode numbers, so identity must be derived, and the
//! derivation has to satisfy two things at once: the same file keeps the same
//! number across lookups, or a cache above sees two files where there is one;
//! and two files never share a number, or it sees one where there are two.
//!
//! The reference derives it from WHERE the entry set sits — the cluster of the
//! directory holding it, and the entry's index within that directory. That is
//! stable for as long as the entry stays put, and unique because no two sets
//! occupy one slot. Deriving it from the first cluster instead would give
//! every empty file the same number, since an empty file has no cluster.

use crate::uapi::{DENTRY_BITS, ROOT_INO};

/// Where an entry set sits.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Position {
    /// First cluster of the directory holding the set.
    pub dir_cluster: u32,
    /// Index of the set's FIRST entry within that directory.
    pub entry_index: u32,
}

/// The index a byte offset within a directory names. # C: O(1)
pub fn index_of_offset(offset: u64) -> u32 { (offset >> DENTRY_BITS) as u32 }

/// The byte offset an index names. # C: O(1)
pub fn offset_of_index(index: u32) -> u64 { u64::from(index) << DENTRY_BITS }

/// The inode number for a set at `pos`.
///
/// The directory's cluster occupies the high half and the entry index the low
/// half, so the pair is one number without either half being able to reach
/// into the other.
/// # C: O(1)
pub fn inode_number(pos: &Position) -> u64 {
    (u64::from(pos.dir_cluster) << 32) | u64::from(pos.entry_index)
}

/// The root's number, which has no entry set to derive one from. # C: O(1)
pub fn root_inode_number() -> u64 { ROOT_INO }

#[cfg(test)]
#[path = "tests/ident.rs"]
mod tests;
