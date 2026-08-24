//! Walking the node chain the last checkpoint left dangling.
//!
//! A checkpoint records where each log had got to. Everything written after it
//! sits past that point, and each node block's footer carries the address of
//! the block the log handed out NEXT — so the blocks written since the
//! checkpoint form a singly linked list whose head the checkpoint itself
//! names. Following it is the whole of finding what a crash left behind.
//!
//! Two things end the walk and neither is an error: an address outside the
//! main area, and a block whose stamped version is not this checkpoint's. The
//! second is the one that matters — the log's blocks were live in an earlier
//! generation and still hold well-formed footers, so without the version test
//! the walk runs off into whatever the allocator wrote last time round.
//!
//! A LOOP is an error. A forward pointer that comes back to a block already
//! visited cannot be produced by an append-only log, so it means the footer
//! was corrupted, and following it never terminates. It is caught with two
//! pointers advancing at different rates rather than a visited set, so the
//! cost stays flat no matter how long the chain is.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::CP_NOCRC_RECOVERY_FLAG;
use crate::node::footer;
use crate::volume::curseg::{self, Kind};
use crate::volume::Volume;

use super::marks;

/// One node block the walk found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Found {
    pub addr: u32,
    pub nid: u32,
    pub ino: u32,
    /// The node's position in its inode's node tree.
    pub ofs: u32,
    pub is_inode: bool,
    /// Whether an `fsync` wrote this block for recovery.
    pub fsync: bool,
    /// Whether the file may still need its directory entry restored.
    pub dent: bool,
}

/// How many links the fast pointer takes per link of the slow one. Two is the
/// smallest that detects every cycle.
const FAST_STEPS: usize = 2;
const RECOVERY_MAX_RA_BLOCKS: u32 = super::super::readahead::window::MAX_RA_BLOCKS as u32;
const RECOVERY_MIN_RA_BLOCKS: u32 = 1;

impl<S: SectorSource> Volume<S> {
    /// Where a walk of the fsync chain begins: the block the file-node log
    /// would have handed out next when the checkpoint was written.
    /// # C: O(1)
    pub fn fsync_chain_start(&self) -> u32 {
        let log = curseg::log_for(Kind::FileNode, self.opts.active_logs);
        self.curseg[log].next_addr(self.sb.main_blkaddr)
    }

    /// Whether `addr` may be followed as the next link of a node chain.
    /// # C: O(1)
    fn chain_addr_ok(&self, addr: u32) -> bool { self.sb.valid_main_blkaddr(addr) }

    /// Read one link, or `None` when the chain ends here. # C: O(1 block)
    fn chain_link(&self, addr: u32) -> Result<Option<(footer::Footer, u32)>, Errno> {
        if !self.chain_addr_ok(addr) { return Ok(None); }
        let block = self.read_por_block(addr)?;
        let Some(f) = footer::parse(&block) else { return Ok(None) };
        let nocrc = self.cp.has(CP_NOCRC_RECOVERY_FLAG);
        if !marks::is_recoverable(&f, self.cp.version, nocrc) { return Ok(None); }
        let next = f.next_blkaddr;
        Ok(Some((f, next)))
    }

    /// Grow on a consecutive chain and shrink on an interior-segment jump. # C: O(1)
    fn adjust_por_ra_blocks(&self, ra: u32, addr: u32, next: u32) -> u32 {
        if addr.checked_add(1) == Some(next) {
            ra.saturating_mul(2).min(RECOVERY_MAX_RA_BLOCKS)
        } else if next % self.sb.blks_per_seg() != 0 {
            (ra / 2).max(RECOVERY_MIN_RA_BLOCKS)
        } else {
            ra
        }
    }

    /// Submit the next recovery window after inspecting its link. # C: O(ra blocks)
    fn prefetch_por(&self, addr: u32, ra: u32) {
        if ra != RECOVERY_MIN_RA_BLOCKS {
            self.ra_meta_pages(addr, ra, super::super::readahead::RaMeta::Por);
        }
    }

    /// Advance the fast pointer, and refuse a chain that comes back on itself.
    ///
    /// `detecting` goes false once the fast pointer runs off the end, because
    /// a chain that ends cannot loop and continuing to read ahead of the slow
    /// pointer would only cost blocks.
    /// # C: O(1 block) amortised
    fn chain_step_fast(&self, slow: u32, fast: &mut u32, detecting: &mut bool,
                       ra: &mut u32)
        -> Result<(), Errno> {
        if !*detecting { return Ok(()); }
        for _ in 0..FAST_STEPS {
            let at = *fast;
            match self.chain_link(at)? {
                None => { *detecting = false; return Ok(()); }
                // A block pointing at itself ends the chain for the slow
                // pointer too, so the fast one must stop rather than report
                // the two meeting there as a cycle.
                Some((_, next)) if next == *fast => { *detecting = false; return Ok(()); }
                Some((_, next)) => {
                    *ra = self.adjust_por_ra_blocks(*ra, at, next);
                    *fast = next;
                    self.prefetch_por(next, *ra);
                }
            }
        }
        if *fast == slow { return Err(Errno::Einval); }
        Ok(())
    }

    /// Hand every marked block of the chain from `head` to `take`, in the
    /// order the log wrote them, until it answers false.
    ///
    /// Blocks WITHOUT the fsync mark are part of the chain and are walked
    /// through, but are not offered: they were written by ordinary activity
    /// that no `fsync` promised, and replaying them would restore state the
    /// caller was never told was durable.
    /// # C: O(chain length) blocks
    pub(crate) fn walk_chain(&self, head: u32, take: &mut dyn FnMut(Found) -> bool)
        -> Result<(), Errno> {
        let mut slow = head;
        let mut fast = slow;
        let mut detecting = true;
        let mut ra = RECOVERY_MAX_RA_BLOCKS;
        loop {
            let Some((f, next)) = self.chain_link(slow)? else { return Ok(()) };
            if f.is_fsync() {
                let found = Found {
                    addr: slow,
                    nid: f.nid,
                    ino: f.ino,
                    ofs: f.ofs_of_node(),
                    is_inode: f.is_inode(),
                    fsync: true,
                    dent: f.is_dent(),
                };
                if !take(found) { return Ok(()); }
            }
            // A pointer at the block's own address does not advance the log
            // and so cannot name a successor: the chain ends here. That is
            // distinct from a pointer that advances and later comes back,
            // which no append-only log can produce and which the fast pointer
            // below refuses.
            if next == slow { return Ok(()); }
            ra = self.adjust_por_ra_blocks(ra, slow, next);
            slow = next;
            self.prefetch_por(slow, ra);
            self.chain_step_fast(slow, &mut fast, &mut detecting, &mut ra)?;
        }
    }

    /// Every node block of the current generation reachable from the chain
    /// head, in the order the log wrote them.
    /// # C: O(chain length) blocks
    pub fn scan_fsync_chain(&self) -> Result<Vec<Found>, Errno> {
        let mut out = Vec::new();
        self.walk_chain(self.fsync_chain_start(), &mut |f| { out.push(f); true })?;
        Ok(out)
    }

    /// Whether a crash left anything an `fsync` promised.
    ///
    /// This is the question a mount that may not write has to answer: it can
    /// neither replay the chain nor honestly pretend the data is not there.
    /// # C: O(chain length) blocks
    pub fn has_fsync_data(&self) -> Result<bool, Errno> {
        Ok(!self.scan_fsync_chain()?.is_empty())
    }
}

#[cfg(test)]
#[path = "../../tests/recover/chain.rs"]
mod tests;
