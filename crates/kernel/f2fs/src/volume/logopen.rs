//! Closing a log's segment and opening the next one.
//!
//! The one moment the allocator makes a CHOICE. Everything else about a write
//! is mechanical — the log is picked by what is being written and the block is
//! the next one in it — but a log whose segment has filled either appends to an
//! empty segment or writes into the gaps of a partly-used one, and which of
//! those it does decides how sequential the volume's writes are and whether the
//! cleaner has anywhere to move live blocks to. The decision itself is pure and
//! lives in `crate::place::ssr`; this is where it is asked and acted on.

use alloc::vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::*;

use super::curseg;
use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Close a log's segment and open another.
    ///
    /// The closing segment's summary block goes to the summary area first.
    /// That block is the only record of which node owns each block of the
    /// segment; a segment closed without it cannot be cleaned, and the space
    /// is lost for the life of the filesystem.
    /// # C: O(main segments)
    pub(crate) fn open_segment(&mut self, log: usize) -> Result<(), Errno> {
        self.load_segments()?;
        // The pinned log opens a whole SECTION, never a recycled segment: a
        // pinned block may not be moved, so it may not share a section with
        // blocks the cleaner is free to relocate.
        if log == crate::uapi::CURSEG_COLD_DATA_PINNED { return self.open_pinned_section(); }
        let old = self.curseg[log].segno;
        if old != NULL_SEGNO {
            let node = log >= NR_CURSEG_DATA_TYPE;
            self.curseg[log].seal(node);
            let at = sum_block_addr(self.sb.ssa_blkaddr, old);
            let block = self.curseg[log].sum.clone();
            self.write_block(at, &block)?;
        }
        let next_free = old != NULL_SEGNO && self.next_seg_free(old);
        // Whether this log recycles is decided HERE, per allocation, from the
        // volume's own pressure — not from what the mount asked for
        // (`crate::place::ssr`). Recycling buys sections the cleaner can move
        // live blocks into and costs a scattered write, so it is worth doing
        // exactly when the sections are running out. The age-threshold log
        // ALWAYS recycles, whatever the pressure: it exists to put old blocks
        // beside other old blocks, and a fresh empty segment is the one place
        // with nothing to put them beside.
        let choice = self.seg_choice(log, next_free);
        let recycle = !crate::place::ssr::need_new_seg(&choice, || self.need_ssr());
        // A segment the log is leaving empty is not free: the checkpoint on
        // the medium still names what was in it. Held here rather than at the
        // release that emptied it, because until now a log was appending to
        // it and it was nobody else's to take. After the decision above, which
        // reads the state of the segment being left.
        self.retire_segment(old);
        // Where the search for a fresh segment starts. The mount's allocation
        // mode reaches the decision here and nowhere else: `reuse` means start
        // from the low end, where the segments freed earliest are.
        let hint = if old == NULL_SEGNO {
            0
        } else {
            // The hot data log and the three node logs; the two in-memory logs
            // are cold data by temperature and search from where they are, as
            // the cold data log does.
            let soon = log == CURSEG_HOT_DATA
                || (log >= NR_CURSEG_DATA_TYPE && log < NR_CURSEG_PERSIST_TYPE);
            crate::place::ssr::next_segno_hint(
                soon, curseg::wants_recycle(self.opts.alloc_mode), old)
        };
        if recycle || log == CURSEG_ALL_DATA_ATGC {
            if let Some((segno, off)) = self.find_victim_seg(hint) {
                let at = sum_block_addr(self.sb.ssa_blkaddr, segno);
                let sum = self.read_block(at).unwrap_or_else(|_| vec![0u8; BLKSIZE]);
                self.curseg[log].segno = segno;
                self.curseg[log].next_blkoff = off;
                self.curseg[log].alloc_type = ALLOC_SSR;
                self.curseg[log].sum = sum;
                self.stamp_seg_type(segno, log);
                return Ok(());
            }
        }
        // Clean BEFORE the last segment goes, not after. The cleaner moves
        // live blocks out of a victim, which needs somewhere to put them, so a
        // volume with nothing free cannot clean at all — waiting until then
        // strands the space permanently. A failure to clean is not reported
        // here: it is only a failure if the allocation itself then fails.
        let reserve = self.gc_reserve();
        if !self.recovering && self.free_segment_count() <= reserve {
            let _ = self.collect(reserve + 1);
        }
        let segno = self.find_free_seg(hint).ok_or(Errno::Enospc)?;
        self.curseg[log].segno = segno;
        self.curseg[log].next_blkoff = 0;
        self.curseg[log].alloc_type = ALLOC_LFS;
        self.curseg[log].sum = vec![0u8; BLKSIZE];
        self.stamp_seg_type(segno, log);
        Ok(())
    }
}
