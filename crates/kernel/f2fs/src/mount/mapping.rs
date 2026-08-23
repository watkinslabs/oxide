//! A file's address space, as the memory manager reaches it.
//!
//! `mmap` of a file is not a second way to read it. The reference installs the
//! file's own address-space operations on every regular inode, and a fault then
//! resolves through the SAME pages a `read` resolves through — which is the
//! whole point: a mapping that fetched for itself would hold a second copy of
//! every page it touched, and the two copies would disagree the moment either
//! side wrote. Without those operations the memory manager falls back to a
//! per-mapping byte cache of its own filled by `read`, which is exactly that
//! second copy, and none of the filesystem's own answers about a page —
//! whether it is held, whether it is dirty, whether it may be dropped —
//! reaches the caller asking.
//!
//! What each operation buys, and why it cannot be left at its default:
//!
//! | operation | the invariant |
//! |---|---|
//! | the fault's fill | a fault and a `read` see one copy of the page, so a write through either is visible to the other |
//! | the length | a fault past the end is a fault past the end, measured against the file NOW rather than when it was opened |
//! | residency | a hint or a query is answered without fetching, so asking does not become I/O |
//! | backing | a page absent from the mapping is not a hole: the block may be on the medium, or its slot may hold a reservation |
//! | the window | a run is brought in as a run, and charged to the filesystem rather than to faults that have not happened |
//! | the flush | a mapping reached with no open file — an `msync` — still has somewhere to write to |
//! | durability | the same chain-or-checkpoint decision an `fsync` through a descriptor makes, reached from the mapping |
//! | eviction | a truncate's pages go unconditionally; a hint leaves a dirty page alone |
//! | the census | `cachestat` counts what this file holds, not zero |
//!
//! Held state: NONE. The pages live in the mount's own mapping, keyed by inode
//! number, and are reached through it. That is not a shortcut — this object is
//! built per handle, and a handle is built per lookup, so anything cached here
//! would be per-opener and two openers of one file would stop agreeing about
//! it. The mount's mapping is the one place a file's pages live and the one
//! place they are asked for.

use alloc::sync::{Arc, Weak};
use sync::{Spinlock, TaskList};

use vfs::mapping::AddressSpaceOps;
use vfs::{CachestatCounts, CachestatRange, Inode, InodeRef, KResult, SharedFrame};

use crate::uapi::BLKSIZE;

use super::{errno_to_vfs, F2fs};

/// One regular file's address space.
pub(crate) struct F2fsMapping {
    pub(crate) fs: Arc<F2fs>,
    pub(crate) ino: u32,
    /// The file whose `page_mkwrite` timestamp contract this mapping serves.
    /// Weak avoids an inode↔address-space lifetime cycle; production inode
    /// construction binds it immediately after the inode is built.
    inode: Spinlock<Weak<Inode>, TaskList>,
}

impl F2fsMapping {
    /// The page a byte offset belongs to. # C: O(1)
    fn index(off: u64) -> u64 { off / BLKSIZE as u64 }

    /// Bind the address space to its owning VFS inode once construction has
    /// produced the canonical inode object. # C: O(1)
    pub(crate) fn bind(&self, inode: &InodeRef) { *self.inode.lock() = Arc::downgrade(inode); }
}

impl AddressSpaceOps for F2fsMapping {
    /// THE page this file holds at that offset, as a machine frame a user page
    /// table can point at.
    ///
    /// It is the same page a `read` and a `write` go through, converted in
    /// place: the mapping's page is a heap buffer while nothing maps it and the
    /// frame the bytes were MOVED into once something does, so there is never a
    /// second copy and a store through the mapping is visible to every other
    /// reader of the file. Handing out a frame FILLED from the page would be
    /// that second copy, and a shared writable mapping over it would diverge
    /// from the file at the first store.
    ///
    /// `map_ref_held` is false: the caller takes the mapping's reference when it
    /// installs the page-table entry and returns it when the entry goes, which
    /// is what keeps the frame alive for exactly as long as either this mapping
    /// or a mapper still wants it.
    ///
    /// `None` where this file's pages cannot be mapped — a compressed file,
    /// whose unpacked cluster is not held here at all. That is the honest
    /// answer; the write fault refuses rather than accepting a store it cannot
    /// keep.
    /// # Ctx: process # Sleeps: y # C: O(1 block read) on a miss
    fn shared_frame(&self, off: u64) -> KResult<Option<SharedFrame>> {
        let pa = self.fs.volume.lock().mapped_frame(self.ino, Self::index(off));
        Ok(pa.map(|pa| SharedFrame { pa, map_ref_held: false }))
    }

    /// A shared mapping is about to WRITE the page at `off`.
    ///
    /// The one event this filesystem sees for a mapped write, so everything a
    /// buffered write decides on the way in is decided here — the refusals, the
    /// block reservation that gives a hole somewhere to go, the zeroing of the
    /// tail past the end of the file, the dirty mark without which nothing ever
    /// writes the page, and the mapped-write charge. `mkwrite` carries the
    /// order and the reason for each step.
    ///
    /// The balance is OUTSIDE the volume's lock, exactly as the buffered write's
    /// is: over the machine's dirty limit it writes back, which re-enters this
    /// mount, so a caller still holding the guard would wait on itself.
    /// # Ctx: process # Sleeps: y # C: O(indirection depth) blocks
    fn page_mkwrite(&self, off: u64) -> KResult<()> {
        if let Some(inode) = self.inode.lock().upgrade() {
            let raw = vfs::inode_times::realtime_now_ns();
            if raw != 0 {
                let now = vfs::inode_times::current_time(&inode, raw);
                inode.update_time(now, vfs::S_MTIME | vfs::S_CTIME | vfs::S_VERSION)?;
            }
        }
        self.fs.volume_now().mkwrite_page(self.ino, Self::index(off)).map_err(errno_to_vfs)?;
        self.fs.balance_data(self.ino);
        Ok(())
    }

    /// The fault's fill, through the mount's mapping and charged to the mapped
    /// layer. # C: O(bytes)
    fn read_at(&self, off: u64, dst: &mut [u8]) -> KResult<usize> {
        self.fs.volume.lock().read_mapped(self.ino, off, dst).map_err(errno_to_vfs)
    }

    /// The file's length NOW.
    ///
    /// Read from the stored inode rather than remembered: a write through any
    /// descriptor moves it, and a mapping answering from a length captured when
    /// it was built would call a fault inside the file a fault past its end.
    /// # C: O(1 block)
    fn size(&self) -> u64 { self.fs.volume.lock().mapped_size(self.ino) }

    /// Held, without fetching. # C: O(height)
    fn mincore_page(&self, off: u64) -> bool {
        self.fs.volume.lock().page_held(self.ino, Self::index(off))
    }

    /// A page this file HAS at that offset, held or not — which is not the
    /// same question as residency and not the same answer.
    /// # C: O(indirection depth) blocks
    fn backing_holds_page(&self, off: u64) -> bool {
        self.fs.volume.lock().page_backed(self.ino, Self::index(off))
    }

    /// Already-resident only. A fault-around that fetched would turn one
    /// fault's worth of I/O into a window's worth, which is the opposite of
    /// what the caller asked for by looking instead of touching.
    /// # C: O(height)
    fn fault_around_frame(&self, _off: u64) -> KResult<Option<SharedFrame>> { Ok(None) }

    /// Bring a window in as a window.
    ///
    /// Overridden rather than left at its default because the default fills the
    /// window page by page THROUGH the fault's fill, which charges every
    /// speculative page to the mapped layer — reporting faults that never
    /// happened, and making the one figure that says how many did meaningless.
    /// # C: O(nr_pages) block reads
    fn readahead(&self, start: u64, nr_pages: u64) {
        self.fs.volume.lock().populate_mapped(self.ino, start, nr_pages);
    }

    /// Place every page of this file the mapping still holds unplaced.
    ///
    /// Reached from an `msync` and from inode eviction, neither of which has an
    /// open file to go through, and it is the same flush this filesystem's own
    /// flush points make.
    /// # Ctx: process # Sleeps: y # C: O(dirty pages)
    fn writeback(&self) -> Result<(), ()> {
        if !self.fs.is_writable() { return Ok(()); }
        self.fs.volume_now().flush_data_pages(self.ino).map_err(|_| ())
    }

    /// The pages of this file that lie in the byte range, and no others.
    ///
    /// Overridden rather than left at its default because the default flushes
    /// the WHOLE file — a correct superset that loses nothing, and makes a
    /// one-page `sync_file_range` over a large file rewrite every unplaced page
    /// of it. The reference honours the range its writeback control carries.
    /// A page outside the range keeps its dirty state and is the next unbounded
    /// flush's work.
    /// # Ctx: process # Sleeps: y # C: O(dirty pages in range)
    fn writeback_range(&self, start: u64, end: u64) -> Result<(), ()> {
        if !self.fs.is_writable() { return Ok(()); }
        if end <= start { return Ok(()); }
        let lo = Self::index(start);
        // Inclusive, and the last byte's page rather than the end's: a range
        // ending exactly on a page boundary does not reach into the page after
        // it, and `u64::MAX` means "to the end of the file".
        let hi = if end == u64::MAX { u64::MAX } else { Self::index(end - 1) };
        self.fs.volume_now().flush_data_pages_range(self.ino, lo, hi).map_err(|_| ())
    }

    /// The backend half of an `fsync` reached without a descriptor.
    ///
    /// The SAME decision `f_op->fsync` makes — a chain of this file's own node
    /// blocks where a later mount can replay it, a whole checkpoint where it
    /// cannot — so the two routes to durability cannot answer differently about
    /// one file.
    /// # Ctx: process # Sleeps: y # C: O(chain) or O(checkpoint)
    fn sync_backing(&self) -> Result<(), ()> {
        if !self.fs.is_writable() { return Ok(()); }
        self.fs.sync_file(self.ino, false).map_err(|_| ())
    }

    /// A truncate's pages: gone, whole pages only.
    /// # C: O(pages in range)
    fn invalidate_range(&self, start: u64, end: u64) -> usize {
        self.fs.volume.lock().forget_whole_pages(self.ino, start, end)
    }

    /// A hint's pages: whatever can be spared, and a dirty one cannot.
    /// # C: O(pages in range)
    fn try_invalidate_pages(&self, start_idx: u64, end_idx: u64) -> usize {
        self.fs.volume.lock().try_forget_pages(self.ino, start_idx, end_idx)
    }

    /// What this file holds in the range, classified.
    ///
    /// Only pages that EXIST are visited, so an unbounded request over a sparse
    /// file costs what the file holds. Nothing is reported evicted: this
    /// mapping keeps no history of a page it dropped, and inventing one would
    /// report a refault distance nothing measured.
    /// # C: O(pages in range)
    fn cachestat(&self, range: CachestatRange) -> CachestatCounts {
        let mut out = CachestatCounts::default();
        if range.last < range.first { return out; }
        let states = self.fs.volume.lock().page_states(self.ino, range.first, range.last);
        for st in states {
            out.account(vfs::PageState::Cache { dirty: st.dirty, writeback: st.writeback },
                        range.covered(st.index, 1));
        }
        out
    }

    /// These pages are a cache of blocks on a medium, not the storage itself.
    /// # C: O(1)
    fn is_shmem(&self) -> bool { false }
}

/// The address space a regular file's inode carries, or nothing for an inode
/// that has no file data to map.
///
/// Only a REGULAR file gets one, which is what the reference installs the data
/// operations on. A directory's blocks are read through the listing path and a
/// device node's are not its own, so giving either an address space would offer
/// the memory manager something to fault that the object does not have.
/// # C: O(1)
pub(crate) fn address_space(fs: &Arc<F2fs>, ino: u32, ftype: vfs::FileType)
    -> Option<Arc<F2fsMapping>>
{
    if ftype != vfs::FileType::Regular { return None; }
    Some(Arc::new(F2fsMapping { fs: Arc::clone(fs), ino, inode: Spinlock::new(Weak::new()) }))
}

#[cfg(test)]
#[path = "../tests/mapping.rs"]
mod tests;
