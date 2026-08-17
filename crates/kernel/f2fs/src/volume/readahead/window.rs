//! What readahead decides before it touches a medium.
//!
//! Every rule here is arithmetic over addresses a caller has already
//! resolved, so it holds no volume and reaches no device: the window that
//! gets read, the runs it splits into, and — for metadata — which address a
//! readahead index names and whether that address is one this kind of
//! readahead is allowed to reach at all.
//!
//! Separated from the fetch because the fetch is untestable without a medium
//! and these answers are the ones that go wrong. A readahead that walks off
//! the end of its area does not fail; it reads a table block as a summary and
//! files it, and the wrong bytes are served later by something that never
//! asked for readahead.

use alloc::vec::Vec;

/// Sibling node blocks one walk will prefetch.
///
/// The count the reference uses, and the reason it is a count rather than the
/// whole nid array: a direct-node array names far more siblings than a walk
/// will ever want, and prefetching all of them turns one file's read into a
/// scan of the node area.
pub const MAX_RA_NODE: usize = 128;

/// Blocks one readahead request may cover.
///
/// A request is one transfer, and a transfer has a widest form; a run longer
/// than this is split rather than truncated, so nothing is dropped from the
/// window — it is only carried in more than one request.
pub const MAX_RA_BLOCKS: usize = 256;

/// Which metadata a readahead index names.
///
/// The kind is not decoration: it decides both how an index becomes a block
/// address and which span of the volume the result is allowed to lie in. One
/// kind's index is another kind's address, so a readahead that lost the kind
/// would resolve a segment number as a block number and read whatever is
/// there.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RaMeta {
    /// Node-table blocks, indexed by table block rather than by address.
    Nat,
    /// Segment-table blocks, indexed by table block.
    Sit,
    /// Summary blocks, indexed by their own address.
    Ssa,
    /// Checkpoint-pack blocks, indexed by their own address.
    Cp,
}

/// Where each area of a volume begins and ends, as readahead needs it.
///
/// Gathered once by the caller rather than re-derived per block: the bounds
/// are the same for every block of one request, and a bound recomputed inside
/// the loop is a bound that can be recomputed differently.
#[derive(Copy, Clone, Debug)]
pub struct Areas {
    /// First block of the mounted checkpoint pack.
    pub cp_start: u32,
    /// First block of the segment table, which is also the end of the
    /// checkpoint packs.
    pub sit_start: u32,
    /// Table blocks the volume's segments need — one block per group of
    /// segment entries, NOT the blocks the area reserves for them. The area
    /// is twice as large because it holds a second copy, and readahead that
    /// used the area's size would resolve an index the table cannot fill.
    pub sit_blocks: u32,
    /// First block of the summary area.
    pub ssa_start: u32,
    /// First block of the main area, which is the end of the summary area.
    pub main_start: u32,
    /// Node-table blocks the volume has, which bounds a node-table index.
    pub nat_blocks: u32,
}

/// Whether readahead of `ty` may reach index `blkno`.
///
/// The index is not an address for two of the kinds, so this checks the
/// INDEX against the count of things that kind has, and the address against
/// the area's span for the three that are addressed directly. Both refusals
/// stop the request where they occur rather than skipping the entry: a
/// readahead window is contiguous, and an index past the end means every
/// index after it is too.
/// # C: O(1)
pub fn meta_index_ok(ty: RaMeta, blkno: u32, a: &Areas) -> bool {
    match ty {
        // A node-table index wraps rather than stopping: the table is scanned
        // in a ring by the free-id builder, and the window that reaches its
        // end continues at the start.
        RaMeta::Nat => true,
        RaMeta::Sit => blkno < a.sit_blocks,
        RaMeta::Ssa => blkno >= a.ssa_start && blkno < a.main_start,
        RaMeta::Cp => blkno >= a.cp_start && blkno < a.sit_start,
    }
}

/// The index a node-table readahead actually reads, once wrapping is applied.
///
/// A window that runs off the end of the table starts again at its first
/// block instead of stopping, because the scan it serves is a ring.
/// # C: O(1)
pub fn nat_ra_index(blkno: u32, nat_blocks: u32) -> u32 {
    if nat_blocks == 0 || blkno < nat_blocks { blkno } else { 0 }
}

/// The segment a segment-table readahead index names. # C: O(1)
pub fn sit_ra_segno(blkno: u32, per_block: u32) -> u32 { blkno.saturating_mul(per_block) }

/// The node id a node-table readahead index names. # C: O(1)
pub fn nat_ra_nid(blkno: u32, per_block: u32) -> u32 { blkno.saturating_mul(per_block) }

/// One transfer: `len` blocks from `addr`, filling the window from `at`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Run {
    /// Offset into the window this run's first block fills.
    pub at: usize,
    /// Address of that first block.
    pub addr: u32,
    /// Blocks in the run.
    pub len: usize,
}

/// Split resolved window addresses into the transfers that will read them.
///
/// `None` is a slot readahead has nothing to do for — a hole, an address the
/// mapping already holds, one this readahead may not reach — and it ENDS the
/// run rather than being skipped inside one, because the blocks either side
/// of it are not adjacent on the medium in the way a single transfer needs.
///
/// Adjacency is checked against the medium, not the window: two window slots
/// belong to one transfer only when their addresses are consecutive, which a
/// fragmented file's blocks are not.
/// # C: O(len(addrs))
pub fn runs(addrs: &[Option<u32>]) -> Vec<Run> {
    let mut out: Vec<Run> = Vec::new();
    let mut cur: Option<Run> = None;
    for (i, slot) in addrs.iter().enumerate() {
        match *slot {
            None => { if let Some(r) = cur.take() { out.push(r); } }
            Some(addr) => {
                match cur {
                    Some(ref mut r)
                        if r.len < MAX_RA_BLOCKS
                            && u64::from(r.addr) + r.len as u64 == u64::from(addr) =>
                    {
                        r.len += 1;
                    }
                    _ => {
                        if let Some(r) = cur.take() { out.push(r); }
                        cur = Some(Run { at: i, addr, len: 1 });
                    }
                }
            }
        }
    }
    if let Some(r) = cur.take() { out.push(r); }
    out
}

#[cfg(test)]
#[path = "../../tests/readahead/window.rs"]
mod tests;
