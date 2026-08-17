//! How a reclaim budget is divided, and what counts as reclaimable.
//!
//! Separated from the mount list next door so the arithmetic can be checked
//! without a volume, a lock or an allocator. Every number reclaim acts on is
//! decided here; `registry` only walks mounts and applies these answers.

use super::super::freenid::limits::MAX_FREE_NIDS;

/// What one reclaim pass may take from each cache.
///
/// The two extent caches get a QUARTER of the budget each, and the node-id
/// cache gets whatever the two of them left. That is not an even split and is
/// not meant to be: an extent entry answers a block lookup that would otherwise
/// walk the node tree, so freeing one costs a future read, while a free node id
/// past the working set costs nothing to re-scan. Spending the budget on the
/// cheap cache first would free the expensive entries on the NEXT pass anyway,
/// at which point the reader has already paid; capping the expensive caches at
/// a quarter each is what keeps a single burst of pressure from emptying them.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Budget {
    /// Entries the block-age cache may lose. Ordered first: an age entry
    /// informs where a block is PLACED, which the next write can recompute,
    /// against a read entry that saves a read happening now.
    pub age: usize,
    /// Entries the read cache may lose.
    pub read: usize,
}

/// Divide `nr` between the two extent caches. # C: O(1)
pub fn split(nr: usize) -> Budget { Budget { age: nr >> 2, read: nr >> 2 } }

/// What is left of `nr` for the node-id cache once the extent caches have taken
/// `freed`.
///
/// Zero once the budget is met, so a pass that reached its target from the
/// extent caches alone does not go on to empty a cache the machine was not
/// asking it to touch.
/// # C: O(1)
pub fn remaining(nr: usize, freed: usize) -> usize { nr.saturating_sub(freed) }

/// Entries one mount could give back right now.
///
/// A zombie tree is an inode's runs whose inode is gone: nothing will ever ask
/// for them again, so they are counted with the live nodes rather than treated
/// as a separate class — reclaim's question is how many entries could go, not
/// which of them are still wanted.
///
/// Free node ids are reclaimable only ABOVE the working set. A mount holds
/// [`MAX_FREE_NIDS`] ids so that creating a file does not have to scan the node
/// table for one; giving those back reports memory freed and buys a table scan
/// on the next `create`, which is why the count starts above them and not at
/// zero.
/// # C: O(1)
pub fn reclaimable(read_entries: u64, age_entries: u64, free_nids: u32) -> usize {
    let nids = free_nids.saturating_sub(MAX_FREE_NIDS);
    let total = read_entries.saturating_add(age_entries).saturating_add(u64::from(nids));
    total.min(usize::MAX as u64) as usize
}

#[cfg(test)]
#[path = "../tests/shrink/budget.rs"]
mod tests;
