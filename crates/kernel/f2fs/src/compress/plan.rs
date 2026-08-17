//! What a cluster's address slots become when its bytes are rewritten, and
//! what that does to the file's two block counts.
//!
//! A compressed cluster does NOT give its space back. The image occupies fewer
//! blocks than the cluster covers, but the slots it no longer needs stay
//! RESERVED: the file is still charged for the whole cluster, and the saving
//! is recorded separately so that it can be handed back deliberately, once,
//! rather than by every writeback. Clearing those slots instead would give the
//! space away silently and leave the recorded saving describing blocks that
//! are already gone — a count a checker reads as a corrupt inode.
//!
//! The two counts answer different questions and neither can be derived from
//! the other: the block count is what the file is charged, and the saved count
//! is how much of that charge compression has already made unnecessary.

use alloc::vec::Vec;

use crate::uapi::{COMPRESS_ADDR, NULL_ADDR};

use super::cluster::is_data_addr;

/// What one address slot of a cluster becomes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Slot {
    /// The sentinel that marks the head of a compressed cluster.
    Sentinel,
    /// Write this block of the payload here.
    Data(usize),
    /// A slot the cluster still owns and stores nothing in.
    Reserved,
    /// Nothing here; the block reads as a hole.
    Hole,
}

impl Slot {
    /// Whether the file is charged for this slot. # C: O(1)
    pub fn owned(self) -> bool { !matches!(self, Slot::Hole) }
}

/// The blocks a cluster's stored image occupies, the sentinel counted.
///
/// `None` says the cluster is not compressed, which is a different thing from
/// a compressed cluster whose image is empty.
/// # C: O(cluster blocks)
pub fn compressed_extent(addrs: &[u32]) -> Option<usize> {
    if addrs.first().copied()? != COMPRESS_ADDR { return None; }
    let mut n = 1usize;
    for &a in &addrs[1..] {
        if !is_data_addr(a) { break; }
        n += 1;
    }
    Some(n)
}

/// The slots of a cluster stored as a compressed image of `blocks` blocks.
///
/// Everything past the image is reserved rather than cleared — including a
/// slot that held a real block before, whose block is released while the slot
/// itself stays charged.
/// # C: O(cluster blocks)
pub fn compressed(cluster_size: usize, blocks: usize) -> Vec<Slot> {
    (0..cluster_size)
        .map(|i| match i {
            0 => Slot::Sentinel,
            i if i <= blocks => Slot::Data(i - 1),
            _ => Slot::Reserved,
        })
        .collect()
}

/// The slots of a cluster stored plain, `live` saying which blocks exist.
/// # C: O(cluster blocks)
pub fn plain(live: &[bool]) -> Vec<Slot> {
    live.iter().enumerate().map(|(i, &l)| if l { Slot::Data(i) } else { Slot::Hole }).collect()
}

/// What a cluster's slots contribute to the file's block count.
///
/// Every slot that is not empty counts: an address, the sentinel, and a
/// reservation are all space the file holds.
/// # C: O(cluster blocks)
pub fn cluster_blocks(addrs: &[u32]) -> usize {
    addrs.iter().filter(|&&a| a != NULL_ADDR).count()
}

/// The file's saved-block count after one cluster is rewritten.
///
/// `was` and `now` are the image extents before and after, SENTINEL INCLUDED,
/// which is how the addresses read them back. The saving is measured without
/// it: the sentinel occupies a slot but holds no block, so a cluster whose
/// image is one block has saved one fewer than the cluster is wide, not two.
///
/// The subtraction is skipped when nothing is recorded as saved: the blocks a
/// release already handed back are not there to be handed back twice, and
/// subtracting anyway drives the count below zero.
/// # C: O(1)
pub fn compr_blocks_after(cur: u64, cluster_size: usize, was: Option<usize>, now: Option<usize>)
    -> u64 {
    let cs = cluster_size as u64;
    let saving = |extent: usize| cs.saturating_sub(extent as u64 - 1);
    let mut n = cur;
    if let Some(w) = was {
        if n != 0 { n = n.saturating_sub(saving(w)); }
    }
    if let Some(c) = now { n += saving(c); }
    n
}

/// Whether a whole cluster lies inside the file, which is what the format
/// requires before it will compress one.
///
/// A cluster the file's size stops part way through is stored plain: its tail
/// blocks are past the end, and an image that covered them would have to be
/// rewritten by the very next append.
/// # C: O(1)
pub fn may_compress(first_block: u64, cluster_size: usize, size: u64, block_size: usize) -> bool {
    first_block + cluster_size as u64 <= size.div_ceil(block_size as u64)
}
