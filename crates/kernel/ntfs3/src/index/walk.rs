//! Walking an index: in-order traversal, and the descent that finds one name.
//!
//! Both are here as PURE functions over a node reader, so the B-tree's shape
//! is tested against nodes laid out in memory rather than through a mount. A
//! descent that walks to the wrong child reports a file that is there as
//! absent, and nothing about the volume looks damaged when it does.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::upcase::{self, UpCase};

use super::entry::{self, IndexEntry};
use super::NodeHeader;

/// Where a node's bytes come from.
pub trait NodeSource {
    /// The bytes of the block numbered `vbn`, and where its header sits in
    /// them.
    fn block(&self, vbn: u64) -> Result<(alloc::vec::Vec<u8>, usize, NodeHeader), Errno>;
    /// The root node's bytes, and where its header sits.
    fn root(&self) -> Result<(alloc::vec::Vec<u8>, usize, NodeHeader), Errno>;
    /// The attribute type the index is keyed on.
    fn indexed_type(&self) -> u32;
}

/// Depth beyond which a tree is taken to be a loop rather than a deep one.
///
/// A cycle in the child pointers makes a descent run forever; the format's own
/// trees are shallow, so any depth past this is damage.
const MAX_DEPTH: usize = 64;

/// Every entry of the whole tree, in key order.
///
/// The order is the tree's own: for each entry, its child's entries come
/// FIRST, because a child holds the keys that sort before its parent entry.
/// Emitting the parent first lists a directory out of order, which every
/// caller that merges two listings then gets wrong.
/// # C: O(entries)
pub fn walk_all(src: &impl NodeSource) -> Result<Vec<IndexEntry>, Errno> {
    let mut out = Vec::new();
    let (bytes, at, header) = src.root()?;
    walk_node(src, &bytes, at, &header, 0, &mut out)?;
    Ok(out)
}

/// Walk one node and everything below it. # C: O(entries below)
fn walk_node(src: &impl NodeSource, bytes: &[u8], at: usize, header: &NodeHeader, depth: usize,
             out: &mut Vec<IndexEntry>) -> Result<(), Errno> {
    if depth > MAX_DEPTH { return Err(Errno::Eio); }
    for e in entry::entries(bytes, at, header, src.indexed_type()) {
        if let Some(vbn) = e.child {
            let (child, child_at, child_header) = src.block(vbn)?;
            walk_node(src, &child, child_at, &child_header, depth + 1, out)?;
        }
        if !e.is_last() { out.push(e); }
    }
    Ok(())
}

/// Find the entry whose name is `wanted`.
///
/// A descent, not a scan: at each node the first entry that sorts at or after
/// the name is the answer or names the subtree holding it. Scanning the root
/// alone finds the handful of names that fit there and no others.
/// # C: O(depth * entries per node)
pub fn find(src: &impl NodeSource, wanted: &[u16], table: &UpCase)
    -> Result<Option<IndexEntry>, Errno> {
    let (mut bytes, mut at, mut header) = src.root()?;
    for _ in 0..MAX_DEPTH {
        let entries = entry::entries(&bytes, at, &header, src.indexed_type());
        let mut descend: Option<u64> = None;
        for e in entries {
            if e.is_last() {
                descend = e.child;
                break;
            }
            let Some(name) = e.name() else { continue };
            match upcase::compare(&name.units, wanted, table, false) {
                core::cmp::Ordering::Less => continue,
                core::cmp::Ordering::Equal => return Ok(Some(e)),
                core::cmp::Ordering::Greater => { descend = e.child; break; }
            }
        }
        let Some(vbn) = descend else { return Ok(None) };
        let (next, next_at, next_header) = src.block(vbn)?;
        bytes = next;
        at = next_at;
        header = next_header;
    }
    Err(Errno::Eio)
}

/// Where a new entry belongs in one node's entry list, by key order.
///
/// The tree is ordered, so an insertion that appends produces a node a descent
/// cannot search: the entries after the insertion point sort before it.
/// # C: O(entries)
pub fn insert_position(entries: &[IndexEntry], wanted: &[u16], table: &UpCase) -> usize {
    for (index, e) in entries.iter().enumerate() {
        if e.is_last() { return index; }
        let Some(name) = e.name() else { continue };
        if upcase::compare(&name.units, wanted, table, false) == core::cmp::Ordering::Greater {
            return index;
        }
    }
    entries.len()
}
