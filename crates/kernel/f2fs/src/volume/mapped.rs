//! What a MAPPING of a file asks the volume for, as opposed to what a
//! read or a write asks for.
//!
//! The bytes are the same bytes and come out of the same mapping of pages —
//! that is the invariant, and it is why nothing here fetches for itself. What
//! differs is who is asking, and the volume has to say so, because the report
//! splits its traffic by the layer that generated it and a fault is not a
//! `read`. A fault charged as a buffered read would say a program that never
//! called `read` did, and the mapped figure — which is the only way to see how
//! much of a volume's traffic is faults — would stay at zero however much of
//! it there was.
//!
//! The other three are residency questions rather than transfers. They exist
//! separately from the read path because a question about what is held must
//! not FILL what is not: a fault-around that fetched, or a residency query
//! that read the medium, turns a hint into I/O and defeats the reason the
//! caller asked instead of touching the page.

use sectors::SectorSource;

use syscall::errno::Errno;

use block::pagecache::PageState;

use crate::stats::iostat::Io;
use crate::uapi::BLKSIZE;

use super::Volume;

/// Pages populated per fetch when a caller asks for a window. A window is a
/// hint, so it is served in bounded pieces rather than in one allocation the
/// size of whatever was asked for.
const READAHEAD_CHUNK: u64 = 32;

impl<S: SectorSource> Volume<S> {
    /// The read behind a page FAULT.
    ///
    /// The same fill as a `read`, charged to the mapped layer instead of the
    /// buffered one, and with the file's own size and sealing rules applied by
    /// the shared reader rather than restated here.
    /// # C: O(bytes read)
    pub(crate) fn read_mapped(&self, ino: u32, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let inode = self.read_inode(ino)?;
        let got = self.read_file_inner(&inode, ino, off, buf)?;
        self.io_account(Io::AppMappedRead, got as u64, inode.compressed());
        Ok(got)
    }

    /// Bring `nr` pages from page `start` into the mapping without copying any
    /// of them out.
    ///
    /// Charged as the FILESYSTEM's read, which is what it is: nothing asked
    /// for these bytes yet. Charging them to the mapped layer would report
    /// faults that have not happened, and the mapped figure exists to say how
    /// many did.
    ///
    /// A page already held is skipped rather than re-fetched, and the first
    /// failure stops the window: a hint that kept going past an I/O error
    /// would pay for every remaining page to discard it.
    /// # C: O(nr) block reads
    pub(crate) fn populate_mapped(&self, ino: u32, start: u64, nr: u64) {
        if nr == 0 { return; }
        let Ok(inode) = self.read_inode(ino) else { return };
        let mut done = 0u64;
        while done < nr {
            let take = (nr - done).min(READAHEAD_CHUNK);
            let first = start + done;
            // A run whose every page is already held costs no fetch and no
            // buffer, which is the common case behind a sequential reader.
            let want = (first..first + take).filter(|i| !self.data_cache.held(ino, *i)).count();
            if want == 0 { done += take; continue; }
            let off = first.wrapping_mul(BLKSIZE as u64);
            if off >= inode.size { return; }
            let len = ((inode.size - off) as usize).min(take as usize * BLKSIZE);
            let mut scratch = alloc::vec![0u8; len];
            if self.read_file_inner(&inode, ino, off, &mut scratch).is_err() { return; }
            done += take;
        }
    }

    /// The file's length as the mapping reflects it. # C: O(1 block)
    pub(crate) fn mapped_size(&self, ino: u32) -> u64 {
        self.read_inode(ino).map(|i| i.size).unwrap_or(0)
    }

    /// Whether the mapping holds page `index` of `ino` right now — no fetch,
    /// no allocation, no block read. # C: O(height)
    pub(crate) fn page_held(&self, ino: u32, index: u64) -> bool {
        self.data_cache.held(ino, index)
    }

    /// Whether the FILE has contents at page `index`, held or not.
    ///
    /// A page not in the mapping is not a hole: the block may be on the medium,
    /// or the slot may hold a reservation for a write that has not been placed.
    /// Answering from residency alone would call a fault over either one a
    /// fault over a hole.
    /// # C: O(indirection depth) blocks
    pub(crate) fn page_backed(&self, ino: u32, index: u64) -> bool {
        if self.data_cache.held(ino, index) { return true; }
        let Ok(inode) = self.read_inode(ino) else { return false };
        let off = index.wrapping_mul(BLKSIZE as u64);
        if off >= inode.size { return false; }
        // Inline data has no block at all and every offset inside the file is
        // nonetheless backed by the inode's own block.
        if inode.inline_data() { return true; }
        !matches!(self.map_cluster_block(&inode, ino, index), Ok(super::map::Mapped::Hole))
    }

    /// Drop the mapping's pages for the WHOLE pages of `[start, end)`, and
    /// report how many went.
    ///
    /// Whole pages only. A page straddling either boundary keeps its contents
    /// because the caller is zeroing part of it, and dropping it would throw
    /// away the bytes on the other side of the cut.
    /// # C: O(pages in range)
    pub(crate) fn forget_whole_pages(&self, ino: u32, start: u64, end: u64) -> usize {
        let blk = BLKSIZE as u64;
        let first = start.div_ceil(blk);
        if end == u64::MAX {
            let mut gone = 0usize;
            for st in self.data_cache.states(ino, first, u64::MAX) {
                self.data_cache.forget(ino, st.index);
                gone += 1;
            }
            return gone;
        }
        if end < blk { return 0; }
        let last = (end / blk).saturating_sub(1);
        if last < first { return 0; }
        let mut gone = 0usize;
        for st in self.data_cache.states(ino, first, last) {
            self.data_cache.forget(ino, st.index);
            gone += 1;
        }
        gone
    }

    /// Drop what can be spared of `ino`'s pages in the INCLUSIVE index range.
    /// # C: O(pages in range)
    pub(crate) fn try_forget_pages(&self, ino: u32, lo: u64, hi: u64) -> usize {
        self.data_cache.try_forget(ino, lo, hi)
    }

    /// What the mapping holds for `ino` in the INCLUSIVE index range.
    /// # C: O(pages in range)
    pub(crate) fn page_states(&self, ino: u32, lo: u64, hi: u64) -> alloc::vec::Vec<PageState> {
        self.data_cache.states(ino, lo, hi)
    }
}

#[cfg(test)]
#[path = "../tests/mapped.rs"]
mod tests;
