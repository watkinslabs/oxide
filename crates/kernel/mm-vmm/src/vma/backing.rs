// The mapped OBJECT behind a `VmaBacking::File` — Linux's
// `struct file`/`vm_operations_struct` pair as one trait.
//
// Split out of `vma.rs` (`08§7` cutoff) so the object surface and the VMA
// descriptor grow independently. Every method is a default where a sensible
// default exists, so a backing implements only what its object can answer.

use alloc::sync::Arc;

use crate::file_rmap::FileRmap;
use crate::vma::FileMmapSetup;

/// File-backed mmap surface, per `11§4` + `17§5`. The demand-page
/// handler calls `read_at(off, dst)` to populate a freshly-allocated
/// user frame; impls are expected to route through the page cache so
/// repeated faults at the same file offset hit cached bytes rather
/// than re-reading the block device. `size_hint` lets the handler
/// zero-fill the tail when a VMA extends past the file's end (Linux
/// returns zeroed-page-with-SIGBUS-past-end; v1 chooses the
/// zero-fill leg).
///
/// Trait-object behind `Arc<dyn FileBacking>` so `VmaBacking::File`
/// can be cloned cheaply across fork(2) without per-FS knowledge in
/// `mm-vmm`. Concrete impls live in `kernel/src/dev/...` (inode
/// wrapper) and pull `vfs::Inode::read` through the page cache.
pub trait FileBacking: Send + Sync {
    /// Establish file-specific VMA state after placement selected its exact
    /// range and before the VMA becomes visible to faults or other threads.
    /// # C: driver-dependent
    fn mmap_setup(&self, _setup: &mut FileMmapSetup) -> Result<(), FileBackingError> { Ok(()) }

    /// Fill `dst` with bytes starting at file offset `off`. Short
    /// reads are allowed; the handler zero-fills the unread tail.
    /// Errors retain their allocation or I/O cause so the fault path never
    /// converts an ENOMEM cache admission failure into a cache miss.
    fn read_at(&self, off: u64, dst: &mut [u8]) -> Result<usize, FileBackingError>;

    /// File size at last stat — used only to decide tail zero-fill.
    /// Stale values are harmless: the worst case is a non-zero tail
    /// that gets zero-filled anyway because `read_at` returned short.
    fn size_hint(&self) -> u64;

    /// Backing inode number — diagnostics only (identify which file a
    /// file-backed VMA maps). Default 0 for non-inode backings.
    fn ino(&self) -> u64 { 0 }

    /// Directory-entry count of the mapped object. Zero marks an object with
    /// no name in any directory — an unlinked file, or the anonymous shared
    /// memory a `MAP_SHARED|MAP_ANONYMOUS` mapping is built on — which is what
    /// separates the anonymous-shared core-dump class from the file-backed
    /// shared one. Default 1 for a backing that maps no inode.
    /// # C: O(1)
    fn i_nlink(&self) -> u32 { 1 }

    /// `i_mode` of the mapped object (file type plus permission bits). The
    /// core-dump header-page rule reads its execute bits to tell a program
    /// image from a plain data mapping. Default 0 for a backing that maps no
    /// inode.
    /// # C: O(1)
    fn i_mode(&self) -> u16 { 0 }

    /// Path the mapping was established from, as the mapper named it. `None`
    /// for a backing with no name in any directory — anonymous shared memory,
    /// a device ring, an unlinked file. A core dump's `NT_FILE` table is built
    /// from these, which is how a debugger reopens the objects a crashed
    /// process had mapped and recovers the pages the dump did not carry.
    /// # C: O(1)
    fn map_path(&self) -> Option<&[u8]> { None }

    /// Stable identity of the OBJECT behind this backing, shared by every
    /// mapping of it in every process, or 0 when the backing has no such
    /// identity.
    ///
    /// This is the value a shared-futex key is derived from — Linux keys a
    /// `!FUTEX_PRIVATE_FLAG` futex on `(inode, page index, offset)` rather than
    /// on an address or a physical page, precisely so that two processes
    /// mapping one file at different addresses hash to the same futex, and so
    /// that the key survives the page being evicted and re-read at a different
    /// physical address.
    ///
    /// It is NOT the inode number: that is only unique within a filesystem.
    /// Implementors return a per-inode kernel identity, and MUST return the
    /// same value for every mapping of the same object or cross-process wakes
    /// are lost.
    /// # C: O(1)
    fn object_id(&self) -> u64 { 0 }

    /// MAP_SHARED page-cache frame for page-aligned file offset `off`. Some =
    /// the persistent backing frame a shared mapping installs directly (Linux
    /// shmem); None (default) = no shareable frame → the fault handler copies
    /// via `read_at` (MAP_PRIVATE / non-page-frame backings). tmpfs/memfd
    /// supply a real frame so writes propagate to the file and other mappers.
    /// # C: O(log N_pages)
    fn shared_frame(&self, _off: u64) -> Result<Option<SharedFrame>, FileBackingError> { Ok(None) }

    /// Byte size of the huge page this backing is built on, or 0 when it maps
    /// ordinary base pages.
    ///
    /// A hugetlbfs file's pages ARE huge pages: a mapping of one resolves
    /// through a single page-table leaf covering the whole page, not through
    /// the base-page leaves the rest of this trait deals in. Reporting the size
    /// here is what sends the fault handler down that path, and it is the only
    /// place the fact is recorded — the VMA carries no second copy that could
    /// disagree with the file it maps.
    ///
    /// A non-zero value must be a granule the page tables express as one leaf,
    /// and `shared_frame` must then accept offsets aligned to it and return a
    /// physical base aligned to it.
    /// # C: O(1)
    fn huge_page_size(&self) -> u64 { 0 }

    /// A PRIVATE copy of the huge page at `off`, for a mapping whose writes
    /// must not reach the file.
    ///
    /// The frame comes back carrying the mapping's own reference and no other,
    /// so the mapping owns it outright and [`FileBacking::huge_put_frame`]
    /// returns it to whatever pool it came from. `None` = nothing to copy.
    /// # C: O(huge page)
    fn huge_cow_frame(&self, _off: u64) -> Result<Option<SharedFrame>, FileBackingError> {
        Ok(None)
    }

    /// Release one reference to a huge page this backing handed out. The
    /// backing owns the release because it is the only thing that knows which
    /// pool the page came from.
    /// # C: O(log nr)
    fn huge_put_frame(&self, _pa: u64) {}

    /// Retained cache frame for Linux-style `map_pages` fault-around. This
    /// MUST be a non-faulting lookup: no allocation, swap-in, or backing I/O.
    /// `None` means the page is not currently eligible. # C: O(log N_pages)
    fn fault_around_frame(&self, _off: u64) -> Result<Option<SharedFrame>, FileBackingError> { Ok(None) }

    /// Whether the mapped pages ARE the object's storage (memory-backed shared
    /// memory) rather than a cache of something durable behind it.
    ///
    /// This is the fact a userfaultfd minor-fault registration turns on: a
    /// minor fault means "the backing already holds this page, only the page
    /// table is missing it", which is only a meaningful distinction where the
    /// backing owns real frames. A backing that merely copies bytes on demand
    /// can never report a page as already resident.
    /// # C: O(1)
    fn is_shmem(&self) -> bool { false }

    /// Device-owned frame installed directly for either mapping type. # C: O(1)
    fn direct_frame(&self, _off: u64) -> Option<u64> { None }

    /// `FMODE_NOREUSE` on the open file this mapping was established from
    /// (`POSIX_FADV_NOREUSE`, `fadvise64(2)`) — read by
    /// [`crate::recency::vma_has_recency`] to suppress LRU promotion on
    /// access. Snapshotted at mapping-establishment time; a later
    /// `fadvise64` on the same fd does not retroactively change an
    /// already-mapped VMA (`52`: mm-vmm carries no live `vfs::File`
    /// reference, matching how this mapping already snapshots the file's
    /// readahead-state class of hints rather than tracking them live).
    /// Default false — the correct value for every non-file-open backing
    /// (anonymous, tmpfs-internal, device). # C: O(1)
    fn noreuse(&self) -> bool { false }

    /// The concrete backing object behind this mapping, for a subsystem that
    /// must recognise one of ITS OWN mappings by identity rather than by
    /// address — the equivalent of Linux comparing `vma->vm_ops` against the
    /// subsystem's own operations table. `None` (default) = the backing
    /// publishes no such identity. # C: O(1)
    fn as_object(&self) -> Option<&(dyn core::any::Any + 'static)> { None }

    /// Flush dirty cache pages overlapping `[start,end)` to the backing store.
    /// Default no-op covers shmem/memfd-style backings where mapped pages are
    /// already the store. # C: O(N_dirty in range)
    fn writeback_range(&self, _start: u64, _end: u64) -> Result<(), ()> { Ok(()) }

    /// `msync(MS_SYNC)`: make `[start,end)` DURABLE, not merely written —
    /// Linux's fsync-range call is page-cache writeback FOLLOWED BY the
    /// filesystem's journal commit and a device barrier.
    ///
    /// Distinct from [`Self::writeback_range`], which only hands the bytes to
    /// the filesystem. A backing that stops at `writeback_range` gives
    /// `MS_SYNC` no more durability than `MS_ASYNC`, which is the whole reason
    /// programs call it. Default forwards to `writeback_range` — correct for
    /// shmem/memfd, where the mapped pages ARE the store and there is nothing
    /// behind them to commit. # C: O(N_dirty in range) + O(journal tx)
    fn fsync_range(&self, start: u64, end: u64) -> Result<(), ()> {
        self.writeback_range(start, end)
    }

    /// Non-faulting Linux `mincore(2)` page-cache residency query for a
    /// page-aligned file offset. `true` means a fault would not need backing I/O.
    /// # C: O(log N_pages)
    fn mincore_page(&self, _off: u64) -> bool { false }

    /// Whether the object's page store OWNS this page-aligned offset in ANY
    /// form — resident, mid-migration, or evicted to swap — as opposed to the
    /// offset being a hole the object has never held contents for.
    ///
    /// Distinct from [`Self::fault_around_frame`], which answers the narrower
    /// "can a PTE be installed from this right now" and must therefore report
    /// nothing for an evicted page. This one answers "does the object hold this
    /// page at all", which is the fact a userfaultfd MINOR registration turns
    /// on: a minor fault means "the object already has these contents, only the
    /// page table is missing them", and that stays true across eviction.
    /// Deciding it from the narrower query silently downgrades a minor fault to
    /// a missing one — the monitor is then asked to supply contents that
    /// already exist, and the page it writes replaces them.
    ///
    /// Non-faulting like every other residency query: no allocation, no
    /// swap-in, no backing I/O.
    /// # C: O(log N_pages)
    fn backing_holds_page(&self, _off: u64) -> bool { false }

    /// Linux `can_do_mincore`: reveal exact file page-cache state only when the
    /// caller owns/can-write the mapped file; otherwise mincore reports resident.
    /// # C: O(1) or inode permission check
    fn mincore_can_reveal(&self) -> bool { true }

    /// Linux `MADV_REMOVE`: punch a shared writable file range with
    /// `FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE`.
    /// # C: filesystem-dependent
    fn madvise_remove(&self, _off: u64, _len: u64) -> Result<(), FileBackingError> {
        Err(FileBackingError::OpNotSupp)
    }

    fn madvise_pageout(&self, _off: u64, _len: u64) -> Option<Result<usize, FileBackingError>> { None }

    /// Linux `vm_operations_struct->open`: one more VMA now references this
    /// object. It runs on every VMA BIRTH — the establishing `mmap`, a fork
    /// copy, and each fragment a split leaves behind — never on a re-key.
    ///
    /// This is the object's own hook, the way Linux's is: the operations table
    /// belongs to whatever the mapping was created from, so a subsystem that
    /// must count its mappings does it here rather than in a registry beside
    /// the VMA tree that could disagree with it.
    /// # C: O(1)
    fn vma_open(&self) {}

    /// Linux `vm_operations_struct->close`: one VMA referencing this object is
    /// gone — `munmap`, the absorbed side of a merge, the original of a split,
    /// or address-space teardown.
    ///
    /// Paired with [`FileBacking::vma_open`] one-for-one, so a resource charged
    /// while the object is mapped is released exactly when the last mapping of
    /// it goes away. A charge taken without this hook is never given back: the
    /// mapping loop that a long-lived process runs then refuses forever.
    /// # C: O(1)
    fn vma_close(&self) {}

    /// Linux `vm_operations_struct->may_split`: whether a VMA of this object
    /// may be cut at an interior address. `false` refuses the `munmap` /
    /// `mprotect` / `mremap` that would split it, with `EINVAL`.
    ///
    /// An object whose accounting is per MAPPING rather than per page cannot
    /// survive a fragment carrying a different size and offset than the charge
    /// was taken for. Default `true` — an ordinary file mapping splits freely.
    /// # C: O(1)
    fn may_split(&self) -> bool { true }

    /// Canonical `address_space->i_mmap` owner for shared file pages.  A
    /// backing that exposes persistent shared frames must return the same
    /// owner for every handle to that inode.  Private/file-copy mappings and
    /// device-only backings return None. # C: O(1)
    fn file_rmap(&self) -> Option<Arc<FileRmap>> { None }
}

/// A page-cache frame handed to a MAP_SHARED fault.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SharedFrame { pub pa: u64, pub map_ref_held: bool }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileBackingError {
    Acces,
    Badf,
    Inval,
    Io,
    NoMem,
    OpNotSupp,
}
