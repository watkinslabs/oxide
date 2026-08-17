//! `PageCache` — the public surface of `17§4.2` / `17§4.3`.
//!
//! A `PageCache` owns a set of per-inode [`Mapping`]s; the LRU, the dirty
//! count and the thresholds those are measured against are machine-wide
//! (`global`), because memory pressure is not a property of one filesystem.
//!
//! Lock order: the inode map (`AddressSpace`) is only ever held long enough to
//! clone a mapping out, never across a mapping's own lock or any I/O.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::Ordering;

use sync::{AddressSpace as AsClass, Spinlock};

use crate::blockdev::BlockDevice;
use crate::types::{BlockError, InodeId, KResult, PageFlags, PAGE_BYTES};

use super::global;
use super::mapping::{Mapping, Writeback};
use super::page::CachedPage;
use super::writeback::{writeback_mapping, writeback_mapping_with, DevWriteback, Sink};

/// Page cache.
pub struct PageCache {
    maps: Spinlock<BTreeMap<InodeId, Arc<Mapping>>, AsClass>,
}

/// Byte offset → radix index. Every public entry point takes a byte offset,
/// which is what a filesystem has; the tree is indexed by page.
fn index_of(page_offset: u64) -> u64 { page_offset / PAGE_BYTES as u64 }

fn aligned(page_offset: u64) -> bool { page_offset % PAGE_BYTES as u64 == 0 }

impl PageCache {
    /// # C: O(1)
    pub const fn new() -> Self { Self { maps: Spinlock::new(BTreeMap::new()) } }

    /// The mapping for `inode`, or `None` if this cache holds no page of it.
    /// # C: O(log inodes)
    pub fn mapping(&self, inode: InodeId) -> Option<Arc<Mapping>> {
        self.maps.lock().get(&inode).cloned()
    }

    fn mapping_or_create(&self, inode: InodeId) -> Arc<Mapping> {
        let mut g = self.maps.lock();
        if let Some(m) = g.get(&inode) { return Arc::clone(m); }
        let m = Mapping::new(inode);
        g.insert(inode, Arc::clone(&m));
        m
    }

    /// Number of currently-cached pages. # C: O(inodes)
    pub fn cached_count(&self) -> usize {
        let maps: Vec<Arc<Mapping>> = self.maps.lock().values().cloned().collect();
        maps.iter().map(|m| m.nrpages()).sum()
    }

    /// Dirty pages this cache holds for `inode`. # C: O(1)
    pub fn dirty_count(&self, inode: InodeId) -> usize {
        self.mapping(inode).map_or(0, |m| m.nr_dirty())
    }

    /// Install where `inode`'s dirty pages get written. A filesystem that
    /// translates file offsets into physical blocks installs its own; a cache
    /// used over a raw device gets one installed for it on first write.
    /// # C: O(log inodes)
    pub fn set_writeback(&self, inode: InodeId, wb: Arc<dyn Writeback>) {
        self.mapping_or_create(inode).ensure_writeback(&wb);
    }

    /// Look up `(inode, page_offset)`. `None` on miss; doesn't I/O. A page
    /// still being fetched is not a hit — its contents are not the file's.
    /// # C: O(log inodes + height)
    pub fn lookup(&self, inode: InodeId, page_offset: u64) -> Option<Arc<CachedPage>> {
        let page = self.mapping(inode)?.get(index_of(page_offset))?;
        if !page.is_uptodate() { return None; }
        global::mark_accessed(&page);
        Some(page)
    }

    /// `read_page_with` per `17§4.2` — generic miss path. The caller-supplied
    /// `fetch` closure produces the page bytes when the cache misses; this lets
    /// filesystems that need logical-to-physical translation (ext4 extents)
    /// plug in without the cache knowing about FS metadata.
    ///
    /// The miss path publishes a LOCKED, not-uptodate page BEFORE it fetches
    /// (`17§4.2` steps 3-5), so a second caller racing the same index waits on
    /// the page lock and then gets those bytes. Exactly one fetch happens per
    /// miss, however many callers race it.
    /// # Ctx: process # Sleeps: y # C: O(height) hit; O(fetch) miss
    pub fn read_page_with<F>(&self, inode: InodeId, page_offset: u64, fetch: F)
        -> KResult<Arc<CachedPage>>
    where F: FnOnce() -> KResult<Vec<u8>>
    {
        if !aligned(page_offset) { return Err(BlockError::Einval); }
        let index = index_of(page_offset);
        let map = self.mapping_or_create(inode);
        let mut fetch = Some(fetch);
        loop {
            // A resident page: wait for whoever is filling it, then use it.
            if let Some(existing) = map.get(index) {
                existing.lock_page();
                let ready = existing.is_uptodate();
                existing.unlock_page();
                if ready { global::mark_accessed(&existing); return Ok(existing); }
                // The fetcher failed and unhooked its placeholder. Look again.
                continue;
            }
            let Some(f) = fetch.take() else { return Err(BlockError::Eio); };
            let placeholder = CachedPage::new_locked(inode, page_offset);
            if let Err(_raced) = map.insert_unique(index, Arc::clone(&placeholder)) {
                fetch = Some(f);
                continue;
            }
            // We own the page lock; everyone else waits on it.
            return match f() {
                Ok(bytes) => {
                    placeholder.finish_fetch(bytes);
                    global::add_lru(&map, index);
                    global::mark_accessed(&placeholder);
                    Ok(placeholder)
                }
                Err(e) => {
                    map.remove(index);
                    placeholder.unlock_page();
                    Err(e)
                }
            };
        }
    }

    /// Add a page the caller already holds the bytes of, if the mapping does
    /// not have that index yet and holds fewer than `max_pages`.
    ///
    /// Distinct from `read_page_with`, whose miss path FETCHES: a caller that
    /// read the bytes for its own reasons and is offering them to the cache
    /// must be able to have the offer declined without that turning into a
    /// second read. `false` is "not taken" — already present, or the mapping
    /// is full — and is never an error: the bytes the caller holds are the
    /// same bytes either way.
    ///
    /// The count is checked under the same lock as the insert, so a cap is a
    /// cap rather than a race. `usize::MAX` asks for no cap.
    /// # C: O(inodes + height)
    pub fn insert_new(&self, inode: InodeId, page_offset: u64, data: Vec<u8>, tag: u64, max_pages: usize)
        -> bool
    {
        if !aligned(page_offset) { return false; }
        if data.len() != PAGE_BYTES { return false; }
        let map = self.mapping_or_create(inode);
        // The cap is on the whole cache, the atomic check is on this mapping:
        // what the other inodes hold is subtracted first, then this mapping's
        // own ceiling is enforced together with the insert.
        let elsewhere = self.cached_count().saturating_sub(map.nrpages());
        let Some(cap) = max_pages.checked_sub(elsewhere) else { return false; };
        let page = CachedPage::new(inode, page_offset, data);
        page.set_tag(tag);
        let index = index_of(page_offset);
        if !map.insert_unique_capped(index, page, cap) { return false; }
        global::add_lru(&map, index);
        true
    }

    /// Drop `inode`'s cached pages whose offsets fall in `[start_off, end_off)`.
    ///
    /// Whole-inode invalidation is the wrong tool where the index is a device
    /// address: one address going out of use says nothing about the rest of
    /// the mapping, and dropping all of it would throw away every other file's
    /// pages as well.
    /// # C: O(height + dropped)
    pub fn invalidate_range(&self, inode: InodeId, start_off: u64, end_off: u64) {
        if end_off <= start_off { return; }
        let Some(map) = self.mapping(inode) else { return; };
        let lo = index_of(start_off);
        let hi = index_of(end_off.saturating_add(PAGE_BYTES as u64 - 1));
        self.drop_indexes(&map, map.keys_in_range(lo, hi));
    }

    /// Drop `inode`'s cached pages carrying owner note `tag`.
    ///
    /// The walk is the whole mapping's, because a tag is not part of the key —
    /// which is the same cost the tag exists to pay for: an owner that cannot
    /// be derived from the index has to be looked for.
    /// # C: O(pages of this inode)
    pub fn invalidate_tagged(&self, inode: InodeId, tag: u64) {
        let Some(map) = self.mapping(inode) else { return; };
        let victims: Vec<u64> = map.pages().into_iter()
            .filter(|(_, p)| p.tag() == tag).map(|(i, _)| i).collect();
        self.drop_indexes(&map, victims);
    }

    /// Drop every cached page for `inode`. Used on file close / unlink.
    /// Dirty pages are dropped silently; the FS must `fsync` first if
    /// it wants durability.
    /// # C: O(pages of this inode)
    pub fn invalidate(&self, inode: InodeId) {
        let Some(map) = self.maps.lock().remove(&inode) else { return; };
        let victims: Vec<u64> = map.pages().into_iter().map(|(i, _)| i).collect();
        self.drop_indexes(&map, victims);
    }

    /// Unhook the named pages and take them off the machine's accounting. The
    /// LRU keeps stale entries rather than paying a list walk per page; they
    /// are discarded by the next scan that meets them.
    fn drop_indexes(&self, map: &Arc<Mapping>, indexes: Vec<u64>) {
        let mut dropped = 0isize;
        let mut undirtied = 0isize;
        for index in indexes {
            match map.remove(index) {
                Some(was_dirty) => { dropped += 1; if was_dirty { undirtied += 1; } }
                None => {}
            }
        }
        global::account_cached(-dropped);
        global::account_dirty(-undirtied);
        if map.nr_dirty() == 0 { map.dirtied_when.store(0, Ordering::Release); }
    }

    /// `read_page` per `17§4.2`. Returns the cached page; on miss, reads from
    /// `dev` (one PAGE_BYTES-sized transfer aligned to `page_offset`), inserts,
    /// returns. `page_offset` must be PAGE_BYTES-aligned. Assumes file-offset
    /// == device-offset — use `read_page_with` for filesystems that translate
    /// logical → physical block ranges.
    /// # Ctx: process # Sleeps: y # C: O(height) hit; O(I/O) miss
    pub fn read_page(&self, inode: InodeId, page_offset: u64, dev: &Arc<dyn BlockDevice>)
        -> KResult<Arc<CachedPage>>
    {
        if !aligned(page_offset) { return Err(BlockError::Einval); }
        // The hit path costs a lookup and nothing else — no allocation, no
        // writeback bookkeeping (`17§6` budgets a cache hit at 600 cycles).
        if let Some(page) = self.lookup(inode, page_offset) { return Ok(page); }
        self.set_writeback(inode, DevWriteback::new(Arc::clone(dev)));
        let bs = dev.block_size() as u64;
        if bs == 0 || PAGE_BYTES as u64 % bs != 0 { return Err(BlockError::Einval); }
        let blocks = (PAGE_BYTES as u64 / bs) as u32;
        let dev = Arc::clone(dev);
        self.read_page_with(inode, page_offset, move || {
            let mut req = crate::blockdev::BlockRequest::new_read(page_offset / bs, blocks, dev.block_size());
            dev.submit_sync(&mut req)?;
            crate::charge_io(PAGE_BYTES as u64, false); // cgroup io.stat (read)
            Ok(req.buffer)
        })
    }

    /// `write_page` per `17§4.3`. Copies the bytes in, marks `PG_DIRTY`, puts
    /// the page on this inode's dirty list and steps the machine's dirty count,
    /// then returns — the medium is reached by the flusher or by `fsync`.
    ///
    /// Over the dirty limit the writer does writeback itself before returning
    /// (the reference's `balance_dirty_pages`), so a process that dirties
    /// without bound cannot outrun the flusher.
    /// # Ctx: process # Sleeps: y # C: O(height)
    pub fn write_page(&self, inode: InodeId, page_offset: u64, data: &[u8], dev: &Arc<dyn BlockDevice>)
        -> KResult<Arc<CachedPage>>
    {
        if data.len() != PAGE_BYTES { return Err(BlockError::Einval); }
        let page = self.read_page(inode, page_offset, dev)?;
        { let mut buf = page.data.lock(); buf.copy_from_slice(data); }
        self.mark_dirty(inode, page_offset)?;
        self.balance_dirty(inode);
        Ok(page)
    }

    /// Mark a resident page dirty — the reference's `->dirty_folio`, and the
    /// ONLY way a page becomes dirty. Reports whether this call is what turned
    /// it dirty.
    ///
    /// Does NOT balance. Balancing writes back, which re-enters the mapping's
    /// writeback target, so a filesystem that dirties a page while holding the
    /// lock its own target needs would deadlock on itself if the two were one
    /// call. The reference splits them for the same reason and puts the
    /// balance at the top of the write path, outside every filesystem lock —
    /// see [`Self::balance_dirty`].
    ///
    /// Refused when the mapping has no writeback target. A dirty page with
    /// nowhere to go is un-flushable: `fsync` reports success having written
    /// nothing, the flusher walks it forever, and reclaim may never evict it.
    /// # C: O(log dirty)
    pub fn mark_dirty(&self, inode: InodeId, page_offset: u64) -> KResult<bool> {
        if !aligned(page_offset) { return Err(BlockError::Einval); }
        let map = self.mapping_or_create(inode);
        if !map.has_writeback() { return Err(BlockError::Einval); }
        if !map.set_dirty(index_of(page_offset)) { return Ok(false); }
        global::account_dirty(1);
        if map.dirtied_when.load(Ordering::Acquire) == 0 {
            map.dirtied_when.store(global::now_ns().max(1), Ordering::Release);
        }
        global::queue_dirty_inode(&map);
        Ok(true)
    }

    /// Act on the machine's dirty state after a write dirtied pages — the
    /// reference's `balance_dirty_pages_ratelimited`.
    ///
    /// Called by the writer once its own locks are dropped, because over the
    /// limit this writes back, which enters the mapping's writeback target.
    /// # Ctx: process # Sleeps: y # C: O(pages written)
    pub fn balance_dirty(&self, inode: InodeId) {
        let Some(map) = self.mapping(inode) else { return; };
        self.balance_dirty_pages(&map);
    }

    /// Write back up to `max` of `inode`'s dirty pages through its installed
    /// target, reporting how many reached the medium.
    /// # Ctx: process # Sleeps: y # C: O(pages written)
    pub fn writeback(&self, inode: InodeId, max: usize) -> (usize, KResult<()>) {
        let Some(map) = self.mapping(inode) else { return (0, Ok(())); };
        let out = writeback_mapping(&map, max);
        if map.nr_dirty() == 0 { map.dirtied_when.store(0, Ordering::Release); }
        out
    }

    /// The same, into a sink the caller supplies rather than the installed
    /// target — what a filesystem's own flush point uses, per
    /// [`writeback_mapping_with`].
    /// # Ctx: process # Sleeps: y # C: O(pages written)
    pub fn writeback_with(&self, inode: InodeId, max: usize, sink: Sink<'_>)
        -> (usize, KResult<()>) {
        let Some(map) = self.mapping(inode) else { return (0, Ok(())); };
        let out = writeback_mapping_with(&map, max, sink);
        if map.nr_dirty() == 0 { map.dirtied_when.store(0, Ordering::Release); }
        out
    }

    /// Write back ONE named page through a sink the caller supplies, leaving
    /// it resident and CLEAN.
    ///
    /// [`Self::writeback_with`] for a caller that chooses its pages one at a
    /// time rather than handing the mapping a count — a filesystem whose flush
    /// point cares about the ORDER its pages reach the medium in, which no
    /// batch entry point can express because the mapping picks the batch.
    ///
    /// Without this such a caller has to place the bytes itself and then
    /// invalidate the index to stop the page being written a second time, so
    /// a page that is now clean and correct is dropped and the next read of it
    /// goes back to the medium. The page's dirty state is ended HERE, by the
    /// same claim-and-complete step every other writeback uses.
    /// # Ctx: process # Sleeps: y # C: O(1 page)
    pub fn writeback_page_with(&self, inode: InodeId, page_offset: u64, sink: Sink<'_>)
        -> (usize, KResult<()>) {
        if !aligned(page_offset) { return (0, Err(BlockError::Einval)); }
        let Some(map) = self.mapping(inode) else { return (0, Ok(())); };
        let out = super::writeback::writeback_page_with(&map, index_of(page_offset), sink);
        if map.nr_dirty() == 0 { map.dirtied_when.store(0, Ordering::Release); }
        out
    }

    /// Every inode this cache holds a dirty page of — what a whole-filesystem
    /// flush has to visit. Sampled under the inode map's lock and returned by
    /// value, because the flush enters the filesystem and may dirty more.
    /// # C: O(inodes)
    pub fn dirty_inodes(&self) -> Vec<InodeId> {
        let maps: Vec<Arc<Mapping>> = self.maps.lock().values().cloned().collect();
        maps.iter().filter(|m| m.nr_dirty() > 0).map(|m| m.ino()).collect()
    }

    /// Act on the machine's dirty state after dirtying a page.
    fn balance_dirty_pages(&self, map: &Arc<Mapping>) {
        match global::dirty_action(global::nr_dirty(), global::nr_writeback(), global::totalram_pages()) {
            global::DirtyAction::Proceed => {}
            global::DirtyAction::Wake => super::daemon::wake_flusher(),
            global::DirtyAction::Throttle => {
                super::daemon::wake_flusher();
                let _ = writeback_mapping(map, global::WRITEBACK_BATCH);
            }
        }
    }

    /// `fsync` per `17§4.3` step 6 — write every dirty page for `inode` and
    /// barrier the medium, so a page dirtied before the call is durable when
    /// it returns (`17§1` invariant 4). Walks this inode's dirty list, not its
    /// resident pages.
    /// # Ctx: process # Sleeps: y # C: O(dirty pages of this inode)
    pub fn fsync(&self, inode: InodeId, dev: &Arc<dyn BlockDevice>) -> KResult<()> {
        self.set_writeback(inode, DevWriteback::new(Arc::clone(dev)));
        if self.mapping(inode).is_none() { return dev.flush(); }
        self.sync(inode)
    }

    /// The same, through whatever target `inode` already has — what a
    /// filesystem that installed its own calls, having no block device of its
    /// own to name. A mapping with nothing to sync is not an error.
    /// # Ctx: process # Sleeps: y # C: O(dirty pages of this inode)
    pub fn sync(&self, inode: InodeId) -> KResult<()> {
        let Some(map) = self.mapping(inode) else { return Ok(()); };
        let (_, result) = writeback_mapping(&map, usize::MAX);
        result?;
        map.dirtied_when.store(0, Ordering::Release);
        if let Some(wb) = map.writeback_target() { wb.sync_medium()?; }
        Ok(())
    }
}

impl Default for PageCache {
    fn default() -> Self { Self::new() }
}

impl Drop for PageCache {
    /// A cache going away takes its pages off the machine's accounting with
    /// it. Its mappings then have no strong reference left, so the global
    /// lists' weak entries resolve to nothing and are discarded on the next
    /// scan. # C: O(pages held)
    fn drop(&mut self) {
        let maps: Vec<Arc<Mapping>> = self.maps.lock().values().cloned().collect();
        for map in maps {
            let pages = map.pages();
            let dirty = pages.iter().filter(|(_, p)| p.flags().contains(PageFlags::DIRTY)).count();
            global::account_cached(-(pages.len() as isize));
            global::account_dirty(-(dirty as isize));
        }
    }
}
