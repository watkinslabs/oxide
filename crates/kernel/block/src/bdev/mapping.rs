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

use core::sync::atomic::{AtomicUsize, Ordering};

use sync::{Inode as InodeClass, Spinlock};
use vfs::mapping::DirtyPages;

use crate::blockdev::{BlockDevice, BlockRequest};
use crate::types::{BlockError, KResult, PAGE_BYTES};

/// Page granule of the cache — one PMM page, as for every other address space.
pub(super) const PG: u64 = PAGE_BYTES as u64;

/// Resident pages plus their writeback bookkeeping. One lock covers all three:
/// a page, its dirty tag and its in-flight state change together, and no
/// device I/O is issued while it is held (`06§3.6`).
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
        })
    }

    /// `mapping->nrpages` — resident page count. `sync(2)`'s device pass skips
    /// a mapping reporting zero, exactly as the reference does. # C: O(1)
    pub fn nrpages(&self) -> usize { self.nr.load(Ordering::Acquire) }

    /// Pages handed to the driver whose completion has not run. # C: O(1)
    pub fn writeback_pages(&self) -> usize { self.inflight.load(Ordering::Acquire) }

    /// Dirty page count — the work the submit half of `sync(2)` has to do.
    /// # C: O(1)
    pub fn dirty_pages(&self) -> usize { self.st.lock().dirty.count() }

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
        if self.st.lock().pages.contains_key(&idx) { return Ok(()); }
        let page = if whole_page_write { vec![0u8; PAGE_BYTES] } else { self.fill_page(idx)? };
        let mut g = self.st.lock();
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

    /// Cached `read(2)` on the block device (Linux `blkdev_read_iter` →
    /// `filemap_read`): serve from resident pages, filling misses from the
    /// medium. A read past the end is EOF (`0`), never an error.
    /// # C: O(len / PG) page fills
    pub fn read_at(&self, off: u64, dst: &mut [u8]) -> KResult<usize> {
        let Some(len) = self.clamp(off, dst.len()) else { return Ok(0); };
        let mut done = 0usize;
        while done < len {
            let cur = off + done as u64;
            let idx = cur / PG;
            let inner = (cur % PG) as usize;
            let take = core::cmp::min(PAGE_BYTES - inner, len - done);
            self.resident(idx, false)?;
            let g = self.st.lock();
            let page = g.pages.get(&idx).ok_or(BlockError::Eio)?;
            dst[done..done + take].copy_from_slice(&page[inner..inner + take]);
            drop(g);
            done += take;
        }
        Ok(done)
    }

    /// Cached `write(2)` on the block device (Linux `blkdev_write_iter` →
    /// `iomap_file_buffered_write`): the bytes land in the cache and the page
    /// is tagged dirty. Nothing reaches the medium until writeback — which is
    /// what gives `sync(2)`'s device pass something to submit.
    /// # C: O(len / PG)
    pub fn write_at(&self, off: u64, data: &[u8]) -> KResult<usize> {
        let Some(len) = self.clamp(off, data.len()) else { return Ok(0); };
        let mut done = 0usize;
        while done < len {
            let cur = off + done as u64;
            let idx = cur / PG;
            let inner = (cur % PG) as usize;
            let take = core::cmp::min(PAGE_BYTES - inner, len - done);
            // A full-page store within capacity needs no read-modify-write.
            let whole = take == PAGE_BYTES && (idx + 1) * PG <= self.size();
            self.resident(idx, whole)?;
            let mut g = self.st.lock();
            let page = g.pages.get_mut(&idx).ok_or(BlockError::Eio)?;
            page[inner..inner + take].copy_from_slice(&data[done..done + take]);
            g.dirty.set_dirty(idx);
            drop(g);
            done += take;
        }
        // A `write(2)` aimed straight at a block device is the caller's own
        // output, billed to the caller here; the cgroup charge happens when
        // writeback actually submits the page.
        crate::task_io::account_write(done as u64);
        Ok(done)
    }
}
