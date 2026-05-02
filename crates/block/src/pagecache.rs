// Page cache per `17§4`. v1 sync surface: lookup-or-fault read,
// dirty-tracking write, fsync flushes dirty pages, invalidate drops
// per-inode entries.
//
// Backing-store dispatch is a `BlockDevice` reference passed at the
// boundary; the cache itself doesn't know about partitions / FS
// layouts. Mapping `(InodeId, file_off)` → `(start_block, len_blocks)`
// is the FS's job.
//
// Out of scope: radix-tree (using BTreeMap with composite key for
// now); writeback daemon + dirty list; PG_LOCKED waiters
// (`17§4.2` step 5); io_uring fixed buffers (`17§5.1`); per-NUMA
// page allocation.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Inode as InodeClass, Spinlock};

use crate::blockdev::{BlockDevice, BlockRequest};
use crate::types::{BlockError, InodeId, KResult, PageFlags, PAGE_BYTES};

/// One cached page per `17§4.1`. Owns a `PAGE_BYTES`-sized buffer in
/// place of the spec's `pfn: Pfn` so the cache works on hosted tests
/// without a live PMM. Once `kalloc` routes through PMM page-class
/// allocations, this morphs into the spec shape; the public surface
/// stays.
pub struct CachedPage {
    pub inode:  InodeId,
    pub offset: u64,
    pub flags:  AtomicU32,
    pub data:   Spinlock<Vec<u8>, InodeClass>,
}

impl CachedPage {
    /// Construct a fresh cached page. Visible to the cache itself and
    /// to in-crate tests; FSes go through `PageCache::read_page` /
    /// `write_page` rather than calling this directly.
    /// # C: O(1)
    pub fn new(inode: InodeId, offset: u64, data: Vec<u8>) -> Arc<Self> {
        debug_assert_eq!(data.len(), PAGE_BYTES);
        Arc::new(Self {
            inode, offset,
            flags: AtomicU32::new(PageFlags::UPTODATE.bits()),
            data:  Spinlock::new(data),
        })
    }

    /// # C: O(1)
    pub fn flags(&self) -> PageFlags {
        PageFlags::from_bits_retain(self.flags.load(Ordering::Acquire))
    }

    /// # C: O(1)
    pub fn is_dirty(&self) -> bool {
        self.flags().contains(PageFlags::DIRTY)
    }

    /// Set bits, return previous full word.
    /// # C: O(1)
    pub fn set_flags(&self, bits: PageFlags) -> PageFlags {
        let prev = self.flags.fetch_or(bits.bits(), Ordering::AcqRel);
        PageFlags::from_bits_retain(prev)
    }

    /// Clear bits, return previous full word.
    /// # C: O(1)
    pub fn clear_flags(&self, bits: PageFlags) -> PageFlags {
        let prev = self.flags.fetch_and(!bits.bits(), Ordering::AcqRel);
        PageFlags::from_bits_retain(prev)
    }
}

/// Page cache.
pub struct PageCache {
    entries: Spinlock<BTreeMap<(InodeId, u64), Arc<CachedPage>>, InodeClass>,
}

impl PageCache {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { entries: Spinlock::new(BTreeMap::new()) }
    }

    /// Number of currently-cached pages.
    /// # C: O(N)
    pub fn cached_count(&self) -> usize { self.entries.lock().len() }

    /// Look up `(inode, page_offset)`. `None` on miss; doesn't I/O.
    /// # C: O(log N)
    pub fn lookup(&self, inode: InodeId, page_offset: u64) -> Option<Arc<CachedPage>> {
        self.entries.lock().get(&(inode, page_offset)).cloned()
    }

    /// `read_page` per `17§4.2`. Returns the cached page; on miss,
    /// reads from `dev` (one PAGE_BYTES-sized transfer aligned to
    /// `page_offset`), inserts, returns. `page_offset` must be
    /// PAGE_BYTES-aligned.
    /// # C: O(log N) cache hit; O(I/O cost) on miss
    pub fn read_page(
        &self,
        inode: InodeId,
        page_offset: u64,
        dev:   &dyn BlockDevice,
    ) -> KResult<Arc<CachedPage>> {
        if page_offset % PAGE_BYTES as u64 != 0 { return Err(BlockError::Einval); }
        if let Some(p) = self.lookup(inode, page_offset) {
            p.set_flags(PageFlags::REFERENCED);
            return Ok(p);
        }

        // Miss. Translate file offset → block range. Caller is the
        // FS, which would normally do this; v1 cache assumes 1:1
        // (file == device range starting at offset 0).
        let bs = dev.block_size() as u64;
        if PAGE_BYTES as u64 % bs != 0 { return Err(BlockError::Einval); }
        let blocks_per_page = (PAGE_BYTES as u64 / bs) as u32;
        let start_block = page_offset / bs;

        let mut req = BlockRequest::new_read(start_block, blocks_per_page, dev.block_size());
        dev.submit_sync(&mut req)?;

        let p = CachedPage::new(inode, page_offset, req.buffer);
        let mut g = self.entries.lock();
        // Race-tolerant insert: another caller may have populated meanwhile.
        if let Some(existing) = g.get(&(inode, page_offset)).cloned() {
            return Ok(existing);
        }
        g.insert((inode, page_offset), Arc::clone(&p));
        Ok(p)
    }

    /// `write_page` per `17§4.3`. Marks `PG_DIRTY`. Caller (FS / VFS
    /// `File::write`) handles user-byte-range copy; this just stages
    /// the page. Synchronous in v1; async on async block layer.
    /// # C: O(log N)
    pub fn write_page(
        &self,
        inode: InodeId,
        page_offset: u64,
        data:  &[u8],
        dev:   &dyn BlockDevice,
    ) -> KResult<Arc<CachedPage>> {
        if data.len() != PAGE_BYTES { return Err(BlockError::Einval); }
        let p = self.read_page(inode, page_offset, dev)?;
        {
            let mut buf = p.data.lock();
            buf.copy_from_slice(data);
        }
        p.set_flags(PageFlags::DIRTY);
        Ok(p)
    }

    /// `fsync` per `17§4` — write every dirty page for `inode` to
    /// `dev`, clear DIRTY, return on completion. v1 walks per-inode
    /// pages in order; the dirty list optimization (`17§1` invariant
    /// 2) lands with the writeback daemon.
    /// # C: O(N) over cached pages
    pub fn fsync(&self, inode: InodeId, dev: &dyn BlockDevice) -> KResult<()> {
        // Snapshot the dirty pages under the cache lock; the actual
        // BlockDevice::submit_sync calls happen outside that lock per
        // `06§3.6` (no cross-subsystem call inside our spinlock).
        let dirty: Vec<Arc<CachedPage>> = {
            let g = self.entries.lock();
            g.iter()
                .filter(|((id, _), p)| *id == inode && p.is_dirty())
                .map(|(_, p)| Arc::clone(p))
                .collect()
        };
        let bs = dev.block_size() as u64;
        if PAGE_BYTES as u64 % bs != 0 { return Err(BlockError::Einval); }
        let blocks_per_page = (PAGE_BYTES as u64 / bs) as u32;
        for p in dirty {
            let payload = p.data.lock().clone();
            let start_block = p.offset / bs;
            let mut req = BlockRequest::new_write(start_block, blocks_per_page, payload);
            dev.submit_sync(&mut req)?;
            p.clear_flags(PageFlags::DIRTY);
        }
        dev.flush()?;
        Ok(())
    }

    /// Drop every cached page for `inode`. Used on file close / unlink.
    /// Dirty pages are dropped silently; the FS must `fsync` first if
    /// it wants durability.
    /// # C: O(N)
    pub fn invalidate(&self, inode: InodeId) {
        let mut g = self.entries.lock();
        let keys: Vec<_> = g.keys().filter(|(id, _)| *id == inode).copied().collect();
        for k in keys { g.remove(&k); }
    }
}

impl Default for PageCache {
    fn default() -> Self { Self::new() }
}
