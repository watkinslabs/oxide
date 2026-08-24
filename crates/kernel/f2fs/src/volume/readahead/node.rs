//! Node blocks, fetched before they are asked for.
//!
//! A walk down a file's node tree asks for one child at a time, and the
//! children of one parent are named side by side in the parent's own array.
//! Fetching the siblings while the parent is in hand is what turns a deep
//! file's read into one pass instead of one stall per level — and, when the
//! siblings were written together, their blocks are adjacent, so the fetch is
//! one transfer rather than one per node.
//!
//! Nothing here checks a node's footer. The check belongs where the node is
//! USED: a block filed by readahead is verified by the reader that takes it
//! out again, and checking it twice would refuse a readahead for a node
//! nobody was going to read.

use alloc::vec::Vec;

use sectors::SectorSource;

use crate::uapi::{BLKSIZE, NIDS_PER_BLOCK};

use super::super::Volume;
use super::window::{runs, MAX_RA_NODE};

impl<S: SectorSource> Volume<S> {
    /// The address readahead would fetch `nid` from, or `None` when there is
    /// nothing for readahead to do. # C: O(1) block
    fn ra_node_addr(&self, nid: u32) -> Option<u32> {
        if !crate::nat::nid_in_range(nid, self.max_nid()) { return None; }
        // A node the mapping already holds is left alone. So is one this mount
        // has changed and not yet placed: the table gives it the address of
        // the block it replaced, and fetching that would file the node's
        // PREVIOUS contents over the live ones.
        if self.node_cache.holds(nid) { return None; }
        let addr = self.node_addr(nid).ok()?;
        if crate::node::is_hole(addr) { return None; }
        if !self.sb.valid_main_blkaddr(addr) { return None; }
        Some(addr)
    }

    /// Fetch up to `n` of the sibling nodes `parent` names, from slot `start`.
    ///
    /// The siblings are resolved first and fetched second, so a group of them
    /// that landed next to each other costs one transfer. That is the whole
    /// gain: the same blocks either way, asked for in one request.
    /// # C: O(n) blocks, O(runs) transfers
    pub(crate) fn ra_node_pages(&self, parent: &[u8], start: usize, n: usize) {
        let end = (start + n).min(NIDS_PER_BLOCK);
        if start >= end { return; }
        let nids: Vec<u32> = (start..end)
            .map(|i| crate::node::indirect_nid(parent, i).unwrap_or(0))
            .collect();
        self.ra_node_ids(&nids);
    }

    /// Fetch the node blocks for `nids` into the node mapping.
    ///
    /// The one merge path every node readahead takes. A node id of zero is an
    /// empty slot rather than a node — the arrays these come out of are sparse
    /// — and an id outside the table names nothing at all; both resolve to
    /// nothing and end the run they were in.
    /// # C: O(len(nids)) blocks, O(runs) transfers
    pub fn ra_node_ids(&self, nids: &[u32]) {
        if nids.is_empty() { return; }
        let addrs: Vec<Option<u32>> = nids.iter().map(|&n| self.ra_node_addr(n)).collect();
        for run in runs(&addrs) {
            let Ok(bytes) = self.read_node_run(run.addr, run.len) else { continue };
            for j in 0..run.len {
                let block = &bytes[j * BLKSIZE..(j + 1) * BLKSIZE];
                self.node_cache.fill(nids[run.at + j], Vec::from(block));
                self.io_account(crate::stats::iostat::Io::FsNodeRead, BLKSIZE as u64, false);
            }
        }
    }

    /// The siblings a walk wants once it has read the child at `slot`: the
    /// ones after it, because a walk descends forwards.
    /// # C: as `ra_node_pages`
    pub(crate) fn ra_next_siblings(&self, parent: &[u8], slot: usize) {
        self.ra_node_pages(parent, slot + 1, MAX_RA_NODE);
    }

    /// Read `len` consecutive node blocks as ONE transfer.
    ///
    /// Node blocks are never enciphered by this filesystem — a node holds the
    /// file's structure, not its contents — so the run needs no context and
    /// the bytes that land are the bytes to file.
    /// # C: O(len * BLKSIZE)
    fn read_node_run(&self, addr: u32, len: usize) -> Result<Vec<u8>, syscall::errno::Errno> {
        use syscall::errno::Errno;
        if len == 0 { return Err(Errno::Einval); }
        let last = u64::from(addr) + len as u64 - 1;
        if !self.sb_main_contains(addr) || !self.sb.valid_main_blkaddr(last as u32) {
            return Err(Errno::Eio);
        }
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::ReadIo) {
            return Err(Errno::Eio);
        }
        self.read_source_run(addr, len)
    }
}

impl<S: SectorSource> Volume<S> {
    /// Whether a directory listing prefetches the node block of every inode it
    /// names. # C: O(1)
    pub fn readdir_ra(&self) -> bool { self.readdir_ra }

    /// Turn that prefetch on or off. # C: O(1)
    pub fn set_readdir_ra(&mut self, on: bool) { self.readdir_ra = on; }
}
