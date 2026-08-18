//! `BdevMapping` — one block device's page cache (Linux `bdev->bd_mapping`,
//! the `address_space` of the block special file's own inode).
//!
//! One object per registered disk, shared by every raw open of it: a
//! `write(2)` to `/dev/<disk>` lands in a page here and is marked dirty, and
//! writeback (`fsync`, `sync(2)`'s device pass, final close) is what puts it on
//! the medium. Dirty bookkeeping is the SAME [`DirtyPages`] tag set every file
//! address space uses, so there is one writeback accounting shape in the tree.
//!
//! Page data lives in heap buffers rather than PMM frames: a raw device
//! mapping never hands a frame to a user PTE (see `shared_frame` in the file
//! mapping contract), so the frame store would buy nothing here.

extern crate alloc;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use sync::{Inode as InodeClass, Spinlock};
use vfs::mapping::DirtyPages;

use crate::blockdev::{BlockDevice, BlockRequest};
use crate::types::{BlockError, KResult, PAGE_BYTES};

/// Page granule of the cache — one PMM page, as for every other address space.
pub(super) const PG: u64 = PAGE_BYTES as u64;

/// Resident pages plus their writeback bookkeeping. One lock covers all three:
/// a page, its dirty tag and its in-flight state change together. It is a
/// spinning lock, so nothing that can sleep runs inside it: no device I/O is
/// issued while it is held, and no caller-supplied buffer is touched while it
/// is held either — that copy normally lands in user memory and can fault
/// (`06§3.6`).
pub(super) struct MappingState {
    /// Resident pages, keyed by page index (Linux `mapping->i_pages`).
    pub(super) pages: BTreeMap<u64, Vec<u8>>,
    /// Dirty tags + the sticky `AS_EIO`/`AS_ENOSPC` writeback-error latch.
    pub(super) dirty: DirtyPages,
    /// Indices handed to the driver and not yet completed (Linux
    /// `PG_writeback`). The wait half of `sync(2)` drains exactly this.
    pub(super) writeback: BTreeSet<u64>,
}

/// A block device's page cache.
pub struct BdevMapping {
    /// The device this cache is a cache OF. This is the accounted device
    /// handle, NOT the coherence decorator wrapped around it: writeback must
    /// not invalidate the very pages it is writing back.
    pub(super) dev: Arc<dyn BlockDevice>,
    pub(super) st: Spinlock<MappingState, InodeClass>,
    /// `mapping->nrpages`, kept outside the lock so the overwhelmingly common
    /// "this disk has never been opened raw" case costs one relaxed load on
    /// the filesystem's own I/O path.
    pub(super) nr: AtomicUsize,
    /// Pages currently under writeback, for the same lock-free reason.
    pub(super) inflight: AtomicUsize,
    /// Process-context waiters for the mapping writeback predicate.
    #[cfg(target_os = "oxide-kernel")]
    pub(super) writeback_wait: sched::live::WaitList,
    /// Surprise removal permanently rejects cached I/O from retained block
    /// file descriptions after the registry unlinks the disk.
    pub(super) dead: AtomicBool,
    /// A lifecycle owner has closed raw block-device writes while preserving
    /// reads and the dirty writeback it must drain before the transition ends.
    pub(super) writes_sealed: AtomicBool,
}

impl BdevMapping {
    /// Fresh, empty cache over `dev`. # C: O(1)
    pub fn new(dev: Arc<dyn BlockDevice>) -> Arc<Self> {
        Arc::new(Self {
            dev,
            st: Spinlock::new(MappingState {
                pages: BTreeMap::new(), dirty: DirtyPages::new(), writeback: BTreeSet::new(),
            }),
            nr: AtomicUsize::new(0),
            inflight: AtomicUsize::new(0),
            #[cfg(target_os = "oxide-kernel")]
            writeback_wait: sched::live::WaitList::new(),
            dead: AtomicBool::new(false),
            writes_sealed: AtomicBool::new(false),
        })
    }

    /// `mapping->nrpages` — resident page count. `sync(2)`'s device pass skips
    /// a mapping reporting zero, exactly as the reference does. # C: O(1)
    pub fn nrpages(&self) -> usize { self.nr.load(Ordering::Acquire) }

    /// Make retained raw block-device mappings fail I/O after surprise removal
    /// and discard their cache without attempting writeback to absent media.
    /// # C: O(resident pages)
    pub fn mark_dead(&self) {
        self.dead.store(true, Ordering::Release);
        let mut g = self.st.lock_bh::<crate::bh_gate::BlockBh>();
        g.pages.clear();
        g.dirty = DirtyPages::new();
        g.writeback.clear();
        drop(g);
        self.nr.store(0, Ordering::Release);
    }

    pub(super) fn check_live(&self) -> KResult<()> {
        if self.dead.load(Ordering::Acquire) { return Err(BlockError::Eio); }
        Ok(())
    }

    fn check_writable(&self) -> KResult<()> {
        if self.writes_sealed.load(Ordering::Acquire) { return Err(BlockError::Erofs); }
        Ok(())
    }

    /// Reject new raw writes while a lifecycle owner drains dirty pages. The
    /// mapping lock orders this seal against a writer's final dirty transition.
    /// # C: O(1)
    pub fn seal_writes(&self) {
        let _state = self.st.lock_bh::<crate::bh_gate::BlockBh>();
        self.writes_sealed.store(true, Ordering::Release);
    }

    /// Reopen raw writes after the owning device returned to writable state.
    /// # C: O(1)
    pub fn unseal_writes(&self) {
        let _state = self.st.lock_bh::<crate::bh_gate::BlockBh>();
        self.writes_sealed.store(false, Ordering::Release);
    }

    /// Pages handed to the driver whose completion has not run. # C: O(1)
    pub fn writeback_pages(&self) -> usize { self.inflight.load(Ordering::Acquire) }

    /// Dirty page count — the work the submit half of `sync(2)` has to do.
    /// # C: O(1)
    pub fn dirty_pages(&self) -> usize { self.st.lock_bh::<crate::bh_gate::BlockBh>().dirty.count() }

    /// Device capacity in bytes (Linux `bdev_nr_bytes`, the `i_size` of the
    /// block special inode). # C: O(1)
    pub fn size(&self) -> u64 {
        self.dev.capacity_blocks().saturating_mul(self.dev.block_size() as u64)
    }

    /// Read one page from the medium, zero-filling any part beyond capacity.
    /// Runs with no lock held. # C: O(PG / block_size)
    fn fill_page(&self, idx: u64) -> KResult<Vec<u8>> {
        let bs = self.dev.block_size() as u64;
        if bs == 0 || PG % bs != 0 { return Err(BlockError::Einval); }
        let off = idx.saturating_mul(PG);
        let cap = self.size();
        let mut page = vec![0u8; PAGE_BYTES];
        if off >= cap { return Ok(page); }
        let want = core::cmp::min(PG, cap - off);
        let blocks = ((want + bs - 1) / bs) as u32;
        let mut req = BlockRequest::new_read(off / bs, blocks, self.dev.block_size());
        self.dev.submit_sync(&mut req)?;
        let n = core::cmp::min(req.buffer.len(), PAGE_BYTES);
        page[..n].copy_from_slice(&req.buffer[..n]);
        crate::charge_io(n as u64, false);
        Ok(page)
    }

    /// Bring page `idx` into the cache, filling it from the medium unless the
    /// caller is about to overwrite every byte of it (Linux skips the read
    /// under `block_write_begin` for a full-folio write). # C: O(page fill)
    fn resident(&self, idx: u64, whole_page_write: bool) -> KResult<()> {
        if self.st.lock_bh::<crate::bh_gate::BlockBh>().pages.contains_key(&idx) { return Ok(()); }
        let page = if whole_page_write { vec![0u8; PAGE_BYTES] } else { self.fill_page(idx)? };
        let mut g = self.st.lock_bh::<crate::bh_gate::BlockBh>();
        if self.dead.load(Ordering::Acquire) { return Ok(()); }
        // Never overwrite: a concurrent writer may have inserted and DIRTIED
        // this page while the fill above ran with no lock held, and clobbering
        // it with the medium's older bytes would silently lose that write.
        if !g.pages.contains_key(&idx) {
            g.pages.insert(idx, page);
            self.nr.fetch_add(1, Ordering::AcqRel);
        }
        Ok(())
    }

    /// Byte range this request may touch, clamped to the device capacity.
    /// `None` when the request starts at or past the end — a read there is EOF
    /// and a write there is a no-op short write, both of which the reference
    /// reports as a zero count rather than an error. # C: O(1)
    fn clamp(&self, off: u64, len: usize) -> Option<usize> {
        let cap = self.size();
        if len == 0 || off >= cap { return None; }
        Some(core::cmp::min(len as u64, cap - off) as usize)
    }

    /// Copy `out.len()` bytes of resident page `idx`, starting at `inner`, out
    /// of the cache. The lock spans the page copy and nothing else.
    /// # Lk: mapping lock
    /// # Ctx: any
    /// # Sleeps: no
    /// # C: O(out.len())
    fn stage_out(&self, idx: u64, inner: usize, out: &mut [u8]) -> KResult<()> {
        let g = self.st.lock_bh::<crate::bh_gate::BlockBh>();
        if self.dead.load(Ordering::Acquire) { return Err(BlockError::Eio); }
        let page = g.pages.get(&idx).ok_or(BlockError::Eio)?;
        out.copy_from_slice(&page[inner..inner + out.len()]);
        Ok(())
    }

    /// Copy `src` into resident page `idx` at `inner` and tag it dirty. The
    /// lock spans the page copy and its dirty tag together, per the
    /// [`MappingState`] contract.
    /// # Lk: mapping lock
    /// # Ctx: any
    /// # Sleeps: no
    /// # C: O(src.len())
    fn stage_in(&self, idx: u64, inner: usize, src: &[u8]) -> KResult<()> {
        let mut g = self.st.lock_bh::<crate::bh_gate::BlockBh>();
        if self.dead.load(Ordering::Acquire) { return Err(BlockError::Eio); }
        if self.writes_sealed.load(Ordering::Acquire) { return Err(BlockError::Erofs); }
        let page = g.pages.get_mut(&idx).ok_or(BlockError::Eio)?;
        page[inner..inner + src.len()].copy_from_slice(src);
        g.dirty.set_dirty(idx);
        Ok(())
    }

    /// Cached `read(2)` on the block device (Linux `blkdev_read_iter` →
    /// `filemap_read`), handing each page's bytes to `sink` as
    /// `(offset within the request, bytes)`.
    ///
    /// `sink` runs with NO mapping lock held, which is the whole reason this
    /// shape exists: the caller's destination is normally a user address, so
    /// the copy can take a fault, and resolving a fault can sleep. The
    /// reference copies page-cache bytes out holding only a page REFERENCE —
    /// never the page-tree lock — and reschedules voluntarily between pages.
    /// A read past the end is EOF (`0`), never an error.
    /// # Lk: mapping lock per page, dropped before `sink`
    /// # Ctx: process
    /// # Sleeps: yes (page fill, and whatever `sink` does)
    /// # C: O(len / PG) page fills
    pub fn read_iter(&self, off: u64, len: usize,
                     mut sink: impl FnMut(usize, &[u8]) -> KResult<()>) -> KResult<usize> {
        self.check_live()?;
        let Some(len) = self.clamp(off, len) else { return Ok(0); };
        let mut stage = vec![0u8; PAGE_BYTES];
        let mut done = 0usize;
        while done < len {
            let cur = off + done as u64;
            let idx = cur / PG;
            let inner = (cur % PG) as usize;
            let take = core::cmp::min(PAGE_BYTES - inner, len - done);
            self.resident(idx, false)?;
            self.stage_out(idx, inner, &mut stage[..take])?;
            sink(done, &stage[..take])?;
            done += take;
        }
        Ok(done)
    }

    /// [`Self::read_iter`] into a caller slice. # C: O(len / PG) page fills
    pub fn read_at(&self, off: u64, dst: &mut [u8]) -> KResult<usize> {
        let len = dst.len();
        self.read_iter(off, len, |at, src| { dst[at..at + src.len()].copy_from_slice(src); Ok(()) })
    }

    /// Cached `write(2)` on the block device (Linux `blkdev_write_iter` →
    /// `iomap_file_buffered_write`): the bytes land in the cache and the page
    /// is tagged dirty. Nothing reaches the medium until writeback — which is
    /// what gives `sync(2)`'s device pass something to submit.
    ///
    /// `src` fills one page's worth of staging bytes with NO mapping lock
    /// held, for the same reason [`Self::read_iter`]'s sink does: reading the
    /// caller's source can fault, and a fault can sleep. The reference makes
    /// the same statement the other way round — its in-place copy runs with
    /// faults DISABLED and a short copy is retried after faulting the source
    /// in outside the locked section.
    /// # Lk: mapping lock per page, never across `src`
    /// # Ctx: process
    /// # Sleeps: yes (page fill, and whatever `src` does)
    /// # C: O(len / PG)
    pub fn write_iter(&self, off: u64, len: usize,
                      mut src: impl FnMut(usize, &mut [u8]) -> KResult<()>) -> KResult<usize> {
        self.check_live()?;
        self.check_writable()?;
        let Some(len) = self.clamp(off, len) else { return Ok(0); };
        let mut stage = vec![0u8; PAGE_BYTES];
        let mut done = 0usize;
        while done < len {
            let cur = off + done as u64;
            let idx = cur / PG;
            let inner = (cur % PG) as usize;
            let take = core::cmp::min(PAGE_BYTES - inner, len - done);
            // A full-page store within capacity needs no read-modify-write.
            let whole = take == PAGE_BYTES && (idx + 1) * PG <= self.size();
            self.resident(idx, whole)?;
            src(done, &mut stage[..take])?;
            self.stage_in(idx, inner, &stage[..take])?;
            done += take;
        }
        // A `write(2)` aimed straight at a block device is the caller's own
        // output, billed to the caller here; the cgroup charge happens when
        // writeback actually submits the page.
        crate::task_io::account_write(done as u64);
        Ok(done)
    }

    /// [`Self::write_iter`] from a caller slice. # C: O(len / PG)
    pub fn write_at(&self, off: u64, data: &[u8]) -> KResult<usize> {
        self.write_iter(off, data.len(), |at, dst| { dst.copy_from_slice(&data[at..at + dst.len()]); Ok(()) })
    }
}
