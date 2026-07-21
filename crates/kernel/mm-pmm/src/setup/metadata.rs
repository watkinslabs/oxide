use super::*;

struct PageMetaStorage(core::cell::UnsafeCell<core::mem::MaybeUninit<crate::PageMetaArr>>);
// SAFETY: boot publishes this cell exactly once before secondary CPUs start;
// readers acquire PAGE_META_PTR, which is stored only after initialization.
unsafe impl Sync for PageMetaStorage {}
struct ReclaimStorage(core::cell::UnsafeCell<core::mem::MaybeUninit<crate::reclaim::Reclaim>>);
// SAFETY: same one-shot publication contract as PageMetaStorage.
unsafe impl Sync for ReclaimStorage {}

static PAGE_META_STORAGE: PageMetaStorage = PageMetaStorage(core::cell::UnsafeCell::new(core::mem::MaybeUninit::uninit()));
static RECLAIM_STORAGE: ReclaimStorage = ReclaimStorage(core::cell::UnsafeCell::new(core::mem::MaybeUninit::uninit()));

static PAGE_META_PTR: core::sync::atomic::AtomicPtr<crate::PageMetaArr>
    = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
static RECLAIM_PTR: core::sync::atomic::AtomicPtr<crate::reclaim::Reclaim>
    = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

pub fn init_page_meta(pfn_max: u64) {
    use core::sync::atomic::Ordering;
    if pfn_max == 0 { return; }
    if !PAGE_META_PTR.load(Ordering::Acquire).is_null() { return; }
    let n = pfn_max as usize;
    let mut v: alloc::vec::Vec<crate::PageMeta>
        = alloc::vec::Vec::with_capacity(n);
    for _ in 0..n { v.push(crate::PageMeta::new()); }
    let leaked: &'static [crate::PageMeta] =
        alloc::boxed::Box::leak(v.into_boxed_slice());
    // SAFETY: leaked storage is initialized, uniquely owned during one-shot
    // setup, and lives for the kernel/hosted test lifetime.
    unsafe { init_page_meta_from_storage(leaked.as_ptr() as *mut crate::PageMeta, leaked.len()); }
}

/// Publish PageMeta storage reserved directly from the boot memory map.
/// This is the kernel path: the struct-page array is not allocated through
/// kalloc, so heap growth can never precede its ownership metadata.
///
/// # SAFETY
/// `storage..storage + len` is writable, properly aligned PageMeta storage,
/// exclusively reserved from usable RAM, and remains mapped for kernel life.
/// Called once before secondary CPUs or PMM consumers are released.
pub unsafe fn init_page_meta_from_storage(storage: *mut crate::PageMeta, len: usize) {
    use core::sync::atomic::Ordering;
    if storage.is_null() || len == 0 || !PAGE_META_PTR.load(Ordering::Acquire).is_null() { return; }
    for index in 0..len {
        // SAFETY: caller guarantees the full reserved PageMeta range.
        unsafe { storage.add(index).write(crate::PageMeta::new()); }
    }
    // SAFETY: every element was initialized immediately above and the boot
    // reservation outlives all PMM users.
    let table = unsafe { core::slice::from_raw_parts(storage, len) };
    let arr = crate::PageMetaArr::new(0, table);
    // SAFETY: one-shot boot publication; pointer remains stable forever.
    let raw = unsafe {
        let slot = &mut *PAGE_META_STORAGE.0.get();
        slot.write(arr) as *mut crate::PageMetaArr
    };
    PAGE_META_PTR.store(raw, Ordering::Release);
    // SAFETY: same one-shot publication; Reclaim contains no heap-owned
    // backing until pages are actually admitted later in boot.
    let reclaim = unsafe {
        let slot = &mut *RECLAIM_STORAGE.0.get();
        slot.write(crate::reclaim::Reclaim::new()) as *mut crate::reclaim::Reclaim
    };
    RECLAIM_PTR.store(reclaim, Ordering::Release);
    // debug-cow probe 1: size the allocated-frame shadow bitmap to the same
    // [0, pfn_max) span as the PageMeta array, so every frame the buddy can
    // hand out has a tracking bit. Idempotent.
    #[cfg(feature = "debug-cow")]
    alloc_integrity::init(len as u64);
}

/// F156-rmap: install the AnonVma reference for a frame. Mirrors
/// Linux `page_add_anon_rmap` shape — the page now belongs to that
/// anon-VMA family, with `page_index` as the page offset within the
/// originating VMA. Bumps the AnonVma's strong count via
/// `Arc::into_raw` and stashes the raw pointer in `PageMeta.mapping`.
/// If a previous AnonVma was bound it gets dropped (rare path:
/// re-bind on a recycled frame; the dec_and_maybe_free path normally
/// clears mapping before the frame is reused).
///
/// # SAFETY: `pa` is a live PMM-allocated frame whose PageMeta slot
/// belongs to the caller's mapping; `av` is alive at call time.
/// # C: O(1)
pub unsafe fn set_anon_rmap_for_pa(
    pa: u64,
    av: &alloc::sync::Arc<vmm::AnonVma>,
    page_index: u32,
) {
    let meta = match page_meta() { Some(m) => m, None => return };
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    let raw = alloc::sync::Arc::into_raw(alloc::sync::Arc::clone(av)) as *mut ();
    if let Some(prev) = meta.swap_mapping(pfn, raw) {
        if !prev.is_null() {
            // SAFETY: previous slot was set via set_anon_rmap_for_pa's
            // Arc::into_raw; reclaiming and dropping it balances that
            // strong-count bump.
            unsafe { drop(alloc::sync::Arc::from_raw(prev as *const vmm::AnonVma)); }
        }
    }
    let _ = meta.set_page_index(pfn, page_index);
    // F157-A3 (Linux `page_add_new_anon_rmap` -> the folio is born
    // exclusive): `set_anon_rmap_for_pa` is called exactly at the two
    // sites that mint a freshly-owned anon frame — the do_anonymous_page
    // zero-fill and the COW-copy destination — and only for VMAs that
    // carry an anon_vma (`VmaBacking::Anonymous`). Both produce a page
    // mapped by exactly one writable owner, so mark it ANON +
    // ANON_EXCLUSIVE. The exclusivity is revoked later by `inc_ref` the
    // moment a fork shares it.
    let _ = meta.set_flags(pfn, crate::PageFlags::ANON | crate::PageFlags::ANON_EXCLUSIVE);
}

/// Inverse of `set_anon_rmap_for_pa`. Loads the stored raw pointer,
/// stores null, drops the Arc. Idempotent on null. Called from
/// `dec_and_maybe_free_frame` when the refcount hits zero — the
/// frame is about to return to PMM, so we must drop our chain
/// reference first or leak the AnonVma.
///
/// # SAFETY: `pa` is a frame whose mapping slot is owned by the
/// caller's flow (no concurrent reader of the slot's pointee).
/// # C: O(1)
pub unsafe fn clear_anon_rmap_for_pa(pa: u64) {
    let meta = match page_meta() { Some(m) => m, None => return };
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    let memcg = meta.memcg(pfn).unwrap_or(cgroup::NO_MEMCG);
    if let Some(prev) = meta.swap_mapping(pfn, core::ptr::null_mut()) {
        if !prev.is_null() {
            // SAFETY: prev was installed via set_anon_rmap_for_pa's
            // Arc::into_raw; we now reclaim ownership and drop.
            unsafe { drop(alloc::sync::Arc::from_raw(prev as *const vmm::AnonVma)); }
        }
    }
    let _ = meta.set_page_index(pfn, 0);
    let _ = meta.set_memcg(pfn, cgroup::NO_MEMCG);
    if memcg != cgroup::NO_MEMCG {
        cgroup::uncharge_memcg(memcg, hal::PAGE_SIZE_BYTES);
    }
}

/// Bind a persistent shared file or shmem page to its inode's canonical
/// i_mmap owner. `page_index` is the backing-object page index, never a
/// virtual-address-derived substitute. `FILE_RMAP` records the raw mapping
/// pointer type only: it must not reclassify a SHMEM page onto the file LRU.
/// # C: O(1)
pub unsafe fn set_file_rmap_for_pa(pa: u64, rmap: &alloc::sync::Arc<vmm::FileRmap>, page_index: u32) {
    let Some(meta) = page_meta() else { return; };
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    let raw = alloc::sync::Arc::into_raw(alloc::sync::Arc::clone(rmap)) as *mut ();
    // Read the old type tag before replacing the raw owner pointer; the new
    // FILE_RMAP flag is not installed until after the previous Arc is dropped.
    let old_flags = meta.flags(pfn).unwrap_or_default();
    let previous = meta.swap_mapping(pfn, raw).unwrap_or(core::ptr::null_mut());
    if !previous.is_null() {
        // SAFETY: FILE_RMAP records the precise raw Arc type stored in mapping.
        if old_flags.contains(crate::PageFlags::FILE_RMAP) {
            unsafe { drop(alloc::sync::Arc::from_raw(previous as *const vmm::FileRmap)); }
        } else {
            unsafe { drop(alloc::sync::Arc::from_raw(previous as *const vmm::AnonVma)); }
        }
    }
    let _ = meta.set_page_index(pfn, page_index);
    // Regular cache pages were classified FILE before their first shared
    // mapping; tmpfs pages were classified SHMEM and remain swap-backed anon
    // LRU members. The rmap type is independent of that physical class.
    let _ = meta.set_flags(pfn, crate::PageFlags::FILE_RMAP);
}

/// Clone the canonical shared-file rmap owner for a resident frame. # C: O(1)
pub fn file_rmap_for_pa(pa: u64) -> Option<alloc::sync::Arc<vmm::FileRmap>> {
    let meta = page_meta()?;
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    if !meta.flags(pfn)?.contains(crate::PageFlags::FILE_RMAP) { return None; }
    let raw = meta.mapping(pfn)?;
    if raw.is_null() { return None; }
    // SAFETY: FILE_RMAP is set before the raw Arc is published and final free
    // takes the page lock before clearing it, so increment yields an owned clone.
    unsafe { alloc::sync::Arc::increment_strong_count(raw as *const vmm::FileRmap); }
    Some(unsafe { alloc::sync::Arc::from_raw(raw as *const vmm::FileRmap) })
}

/// Inverse of `set_file_rmap_for_pa`, type-selected by FILE_RMAP. # C: O(1)
pub unsafe fn clear_file_rmap_for_pa(pa: u64) {
    let Some(meta) = page_meta() else { return; };
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    let raw = meta.swap_mapping(pfn, core::ptr::null_mut()).unwrap_or(core::ptr::null_mut());
    let _ = meta.clear_flags(pfn, crate::PageFlags::FILE_RMAP);
    if !raw.is_null() {
        // SAFETY: FILE_RMAP selected this exact Arc element type before the bit was cleared.
        unsafe { drop(alloc::sync::Arc::from_raw(raw as *const vmm::FileRmap)); }
    }
}

/// Record the cgroup that owns a newly materialized anonymous page. # C: O(1)
pub fn set_memcg_for_pa(pa: u64, cgid: u64) {
    if let Some(meta) = page_meta() {
        let _ = meta.set_memcg(hal::Pfn(pa / hal::PAGE_SIZE_BYTES), cgid);
    }
}

/// Admit one fully-owned resident anonymous page to the inactive anonymous
/// LRU.  This is intentionally narrower than general LRU ownership: file and
/// shmem pages keep their future owning subsystem and are never inferred here.
/// # C: O(1); # Lk: TaskList
pub fn admit_anon_lru(pa: u64) -> Result<(), crate::reclaim::ReclaimError> {
    let meta = page_meta().ok_or(crate::reclaim::ReclaimError::OutOfRange)?;
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    let page = meta.get(pfn).ok_or(crate::reclaim::ReclaimError::OutOfRange)?;
    let flags = crate::PageFlags::from_bits_retain(page.flags.load(core::sync::atomic::Ordering::Acquire));
    if !flags.contains(crate::PageFlags::ANON)
        || flags.intersects(crate::PageFlags::FILE | crate::PageFlags::SHMEM)
        || page.mapping.load(core::sync::atomic::Ordering::Acquire).is_null()
        || page.memcg.load(core::sync::atomic::Ordering::Acquire) == cgroup::NO_MEMCG
        || page.mapcount.load(core::sync::atomic::Ordering::Acquire) == 0
        || page.refcount.load(core::sync::atomic::Ordering::Acquire) == 0
    {
        return Err(crate::reclaim::ReclaimError::Class);
    }
    let ptr = RECLAIM_PTR.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() { return Err(crate::reclaim::ReclaimError::State); }
    // SAFETY: init_page_meta publishes the heap allocation once and PMM never frees it.
    unsafe { (&*ptr).add(meta, pfn, crate::reclaim::Lru::InactiveAnon) }
}

/// Publish a regular page-cache frame as a file-LRU member. The filesystem
/// owns the mapping/index and the object reference; PMM owns only the stable
/// physical classification and reclaim membership. # C: O(1); # Lk: TaskList
pub fn admit_file_lru(pa: u64) -> Result<(), crate::reclaim::ReclaimError> {
    let Some(meta) = page_meta() else { return Ok(()); };
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    let page = meta.get(pfn).ok_or(crate::reclaim::ReclaimError::OutOfRange)?;
    let flags = crate::PageFlags::from_bits_retain(page.flags.load(core::sync::atomic::Ordering::Acquire));
    if !flags.contains(crate::PageFlags::FILE)
        || flags.intersects(crate::PageFlags::ANON | crate::PageFlags::SHMEM)
        || page.refcount.load(core::sync::atomic::Ordering::Acquire) == 0
    { return Err(crate::reclaim::ReclaimError::Class); }
    let ptr = RECLAIM_PTR.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() { return Err(crate::reclaim::ReclaimError::State); }
    // SAFETY: init_page_meta publishes the heap allocation once and PMM never frees it.
    unsafe { (&*ptr).add(meta, pfn, crate::reclaim::Lru::InactiveFile) }
}

/// Publish a tmpfs/shmem frame as a swap-backed anonymous-LRU member. Linux
/// treats shmem as swap-backed, not file-LRU, even though it is inode-owned.
/// # C: O(1); # Lk: TaskList
pub fn admit_shmem_lru(pa: u64) -> Result<(), crate::reclaim::ReclaimError> {
    let Some(meta) = page_meta() else { return Ok(()); };
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    let page = meta.get(pfn).ok_or(crate::reclaim::ReclaimError::OutOfRange)?;
    let flags = crate::PageFlags::from_bits_retain(page.flags.load(core::sync::atomic::Ordering::Acquire));
    if !flags.contains(crate::PageFlags::SHMEM)
        || flags.intersects(crate::PageFlags::ANON | crate::PageFlags::FILE)
        || page.refcount.load(core::sync::atomic::Ordering::Acquire) == 0
        || page.memcg.load(core::sync::atomic::Ordering::Acquire) == cgroup::NO_MEMCG
    { return Err(crate::reclaim::ReclaimError::Class); }
    let ptr = RECLAIM_PTR.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() { return Err(crate::reclaim::ReclaimError::State); }
    // SAFETY: init_page_meta publishes the heap allocation once and PMM never frees it.
    unsafe { (&*ptr).add(meta, pfn, crate::reclaim::Lru::InactiveAnon) }
}

/// Classify a newly published regular page-cache frame. # C: O(1)
pub fn classify_file_page(pa: u64, cgid: u64) {
    if let Some(meta) = page_meta() {
        let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
        let _ = meta.set_memcg(pfn, cgid);
        let _ = meta.set_flags(pfn, crate::PageFlags::FILE | crate::PageFlags::UPTODATE);
    }
}

/// Classify a newly published tmpfs/shmem frame. # C: O(1)
pub fn classify_shmem_page(pa: u64, cgid: u64) {
    if let Some(meta) = page_meta() {
        let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
        let _ = meta.set_memcg(pfn, cgid);
        let _ = meta.set_flags(pfn, crate::PageFlags::SHMEM | crate::PageFlags::UPTODATE);
    }
}

/// Sample a resident LRU page after a successful access. # C: O(1); # Lk: TaskList
pub fn mark_lru_referenced(pa: u64) -> Result<(), crate::reclaim::ReclaimError> {
    let meta = page_meta().ok_or(crate::reclaim::ReclaimError::OutOfRange)?;
    let ptr = RECLAIM_PTR.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() { return Err(crate::reclaim::ReclaimError::State); }
    // SAFETY: init_page_meta publishes the heap allocation once and PMM never frees it.
    unsafe { (&*ptr).mark_referenced(meta, hal::Pfn(pa / hal::PAGE_SIZE_BYTES)) }
}

/// Move a resident page to or from the unevictable LRU for mlock/munlock.
/// # C: O(N_lru); # Lk: TaskList
pub fn set_lru_unevictable(pa: u64, enabled: bool) -> Result<(), crate::reclaim::ReclaimError> {
    let meta = page_meta().ok_or(crate::reclaim::ReclaimError::OutOfRange)?;
    let ptr = RECLAIM_PTR.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() { return Err(crate::reclaim::ReclaimError::State); }
    // SAFETY: init_page_meta publishes the heap allocation once and PMM never frees it.
    unsafe { (&*ptr).set_unevictable(meta, hal::Pfn(pa / hal::PAGE_SIZE_BYTES), enabled) }
}

/// Remove the final PMM reference from its reclaim LRU before reuse.  An
/// isolated page is a reclaim transaction violation and must not reach buddy.
/// # C: O(N_lru); # Lk: TaskList
pub fn unlink_lru_for_final_free(pa: u64) -> Result<(), crate::reclaim::ReclaimError> {
    let Some(meta) = page_meta() else { return Ok(()); };
    let ptr = RECLAIM_PTR.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() { return Ok(()); }
    // SAFETY: init_page_meta publishes the heap allocation once and PMM never frees it.
    unsafe { (&*ptr).unlink_for_free(meta, hal::Pfn(pa / hal::PAGE_SIZE_BYTES)) }
}

/// Isolate the oldest inactive anonymous page for one direct-reclaim
/// transaction. The token keeps the original LRU class authoritative until
/// the transaction either puts the page back or releases it for final free.
/// No page-table or page lock is held while the reclaim lock is acquired.
/// # C: O(1); # Lk: TaskList
pub fn isolate_inactive_anon_lru() -> Result<Option<crate::reclaim::Isolation>, crate::reclaim::ReclaimError> {
    let meta = page_meta().ok_or(crate::reclaim::ReclaimError::OutOfRange)?;
    let ptr = RECLAIM_PTR.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() { return Err(crate::reclaim::ReclaimError::State); }
    // SAFETY: init_page_meta publishes the heap allocation once and PMM never frees it.
    unsafe { (&*ptr).isolate(meta, crate::reclaim::Lru::InactiveAnon) }
}

/// Isolate an inactive anonymous page charged to exactly `memcg`.  This is
/// the allocation/reclaim boundary for cgroup pressure: global aging remains
/// shared, while reclaim eligibility follows the page's immutable memcg
/// owner. # C: O(N_inactive_anon); # Lk: TaskList
pub fn isolate_inactive_anon_lru_memcg(memcg: u64) -> Result<Option<crate::reclaim::Isolation>, crate::reclaim::ReclaimError> {
    let meta = page_meta().ok_or(crate::reclaim::ReclaimError::OutOfRange)?;
    let ptr = RECLAIM_PTR.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() { return Err(crate::reclaim::ReclaimError::State); }
    // SAFETY: init_page_meta publishes the heap allocation once and PMM never frees it.
    unsafe { (&*ptr).isolate_memcg(meta, crate::reclaim::Lru::InactiveAnon, memcg) }
}

/// Isolate the oldest inactive regular file-cache page for a clean-eviction
/// transaction. The filesystem owner must either put it back or release it.
/// # C: O(1); # Lk: TaskList
pub fn isolate_inactive_file_lru() -> Result<Option<crate::reclaim::Isolation>, crate::reclaim::ReclaimError> {
    let meta = page_meta().ok_or(crate::reclaim::ReclaimError::OutOfRange)?;
    let ptr = RECLAIM_PTR.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() { return Err(crate::reclaim::ReclaimError::State); }
    // SAFETY: init_page_meta publishes the heap allocation once and PMM never frees it.
    unsafe { (&*ptr).isolate(meta, crate::reclaim::Lru::InactiveFile) }
}

/// Snapshot live user PTEs for a PMM frame. # C: O(1)
pub fn frame_mapcount(pa: u64) -> u32 {
    page_meta().and_then(|meta| meta.mapcount(hal::Pfn(pa / hal::PAGE_SIZE_BYTES))).unwrap_or(0)
}

/// Isolate a VMA-selected resident anonymous page without creating an
/// alternate pageout ownership path. The page must already have canonical LRU
/// membership; nonresident, unevictable, and non-anonymous pages are skipped.
/// # C: O(N_lru); # Lk: TaskList
pub fn isolate_anon_lru_pfn(pa: u64) -> Result<Option<crate::reclaim::Isolation>, crate::reclaim::ReclaimError> {
    let meta = page_meta().ok_or(crate::reclaim::ReclaimError::OutOfRange)?;
    let ptr = RECLAIM_PTR.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() { return Err(crate::reclaim::ReclaimError::State); }
    // SAFETY: init_page_meta publishes the heap allocation once and PMM never frees it.
    unsafe { (&*ptr).isolate_anon_pfn(meta, hal::Pfn(pa / hal::PAGE_SIZE_BYTES)) }
}

/// Return an unchanged direct-reclaim candidate to its original LRU.
/// # C: O(1); # Lk: TaskList
pub fn putback_isolated_lru(isolated: crate::reclaim::Isolation) -> Result<(), crate::reclaim::ReclaimError> {
    let meta = page_meta().ok_or(crate::reclaim::ReclaimError::OutOfRange)?;
    let ptr = RECLAIM_PTR.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() { return Err(crate::reclaim::ReclaimError::State); }
    // SAFETY: init_page_meta publishes the heap allocation once and PMM never frees it.
    unsafe { (&*ptr).putback(meta, isolated) }
}

/// Consume an isolated LRU token after every source PTE was converted to swap.
/// The caller still owns the page lock and must immediately drop the matched
/// PTE references; no allocator state is touched by this transition.
/// # C: O(1); # Lk: TaskList
pub fn release_isolated_lru(isolated: crate::reclaim::Isolation) -> Result<(), crate::reclaim::ReclaimError> {
    let meta = page_meta().ok_or(crate::reclaim::ReclaimError::OutOfRange)?;
    let ptr = RECLAIM_PTR.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() { return Err(crate::reclaim::ReclaimError::State); }
    // SAFETY: init_page_meta publishes the heap allocation once and PMM never frees it.
    unsafe { (&*ptr).release(meta, isolated) }
}

/// Snapshot the initialized kernel reclaim owner.  `None` means page metadata
/// has not been installed, rather than a fabricated all-zero memory state.
/// # C: O(1); # Lk: TaskList
pub fn reclaim_snapshot() -> Option<crate::reclaim::ReclaimSnapshot> {
    let ptr = RECLAIM_PTR.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() { return None; }
    // SAFETY: init_page_meta publishes the heap allocation once and PMM never frees it.
    Some(unsafe { (&*ptr).snapshot() })
}

/// Snapshot the owning cgroup for a resident page. # C: O(1)
pub fn memcg_for_pa(pa: u64) -> u64 {
    page_meta().and_then(|meta| meta.memcg(hal::Pfn(pa / hal::PAGE_SIZE_BYTES))).unwrap_or(0)
}

/// Snapshot the AnonVma stored at `pa`. Bumps the strong count so
/// the caller's clone is independent. `None` if no anon_vma is
/// bound or pre-init.
/// # C: O(1)
pub fn anon_vma_for_pa(pa: u64) -> Option<alloc::sync::Arc<vmm::AnonVma>> {
    let meta = page_meta()?;
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    let raw = meta.mapping(pfn)?;
    if raw.is_null() { return None; }
    // SAFETY: raw was installed via set_anon_rmap_for_pa's into_raw;
    // increment the strong count and reconstruct an owned Arc.
    unsafe {
        alloc::sync::Arc::increment_strong_count(raw as *const vmm::AnonVma);
        Some(alloc::sync::Arc::from_raw(raw as *const vmm::AnonVma))
    }
}

/// Snapshot the page_index stored at `pa`. 0 pre-init or out-of-range.
/// # C: O(1)
pub fn page_index_for_pa(pa: u64) -> u32 {
    page_meta()
        .and_then(|m| m.page_index(hal::Pfn(pa / hal::PAGE_SIZE_BYTES)))
        .unwrap_or(0)
}

/// Count live address spaces OTHER than `exclude_root` that still map VA `va`
/// to physical frame `pa`. Used at every free-to-zero to enforce the
/// never-free-a-mapped-page invariant AUTHORITATIVELY — a frame about to return
/// to PMM while a peer task's PTE still maps it (refcount under-counted by a
/// map-time `inc_ref` that never ran). Works for ALL backings (not just anon,
/// unlike an rmap walk) by enumerating live tasks' address spaces. `hhdm` is the
/// HHDM offset for foreign-PT reads. Production (was debug-fwm): it is the
/// backstop that turns an under-count into a survivable leak instead of a
/// free-while-mapped corruption. Each probe is one 4-level walk per AS.
/// # C: O(N_tasks) — one 4-level PT walk each
#[cfg(feature = "debug-fwm")]
pub fn fwm_peer_maps(va: u64, pa: u64, exclude_root: u64, hhdm: u64) -> usize {
    let target = pa & !(hal::PAGE_SIZE_BYTES - 1);
    let tasks = match sched::registry::try_snapshot() { Some(t) => t, None => return 0 };
    let mut count = 0usize;
    let mut seen: [u64; 96] = [0; 96];
    let mut n_seen = 0usize;
    for t in tasks.iter() {
        // SAFETY: smp=1 debug detector; no other task executes during this
        // teardown, so reading a peer task's mm root is a stable read.
        let root = match unsafe { t.mm_ref() } { Some(mm) => mm.root_pa(), None => continue };
        if root == exclude_root || root == 0 { continue; }
        if seen[..n_seen].contains(&root) { continue; } // dedup threads sharing an mm
        if n_seen < seen.len() { seen[n_seen] = root; n_seen += 1; }
        // SAFETY: read-only foreign-mm PT walk; root is a live AS root frame;
        // HHDM covers page-table memory.
        #[cfg(target_arch = "x86_64")]
        let tr = unsafe { hal::pt_walker::translate_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(root, va, hhdm) };
        #[cfg(target_arch = "aarch64")]
        let tr = unsafe { hal::pt_walker::translate_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(root, va, hhdm) };
        if let Some((mapped, _)) = tr {
            if (mapped & !(hal::PAGE_SIZE_BYTES - 1)) == target { count += 1; }
        }
    }
    count
}

/// F156-rmap: release one PTE reference while retaining the rmap edge until
/// the final mapping disappears. Wraps `dec_and_maybe_free_frame` for COW,
/// munmap, and address-space teardown.
/// # SAFETY: same as `dec_and_maybe_free_frame`.
/// # C: O(1)
pub unsafe fn rmap_aware_dec_and_maybe_free(pa: u64) {
    const FINAL_PTE_MAPCOUNT: u32 = 1;
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    let managed = page_meta().and_then(|meta| meta.get(pfn)).is_some();
    if !managed {
        // SAFETY: an unmanaged frame has no PMM metadata to serialize; this
        // is the legacy pre-init/out-of-range teardown path.
        unsafe { clear_anon_rmap_for_pa(pa); }
        // SAFETY: caller asserts the frame's leaf PTE has been removed.
        unsafe { dec_and_maybe_free_frame(pa); }
        return;
    }
    while !try_lock_page(pa) { core::hint::spin_loop(); }
    let is_final_mapping = page_meta()
        .and_then(|meta| meta.mapcount(pfn))
        == Some(FINAL_PTE_MAPCOUNT);
    if is_final_mapping {
        // SAFETY: the page lock serializes all rmap-aware PTE drops. The
        // final PTE is about to disappear, so this Arc cannot serve a peer.
        let file = page_meta().and_then(|meta| meta.flags(pfn))
            .is_some_and(|flags| flags.contains(crate::PageFlags::FILE_RMAP));
        if file { unsafe { clear_file_rmap_for_pa(pa); } }
        else { unsafe { clear_anon_rmap_for_pa(pa); } }
    }
    // SAFETY: caller has removed one PTE and the page lock serializes its
    // mapcount transition with every other rmap-aware release.
    unsafe { dec_and_maybe_free_frame(pa); }
    let _ = unlock_page(pa);
}

/// Try to acquire a PMM-managed page's migration/I/O lock. A missing metadata
/// slot is not a managed anonymous page and therefore cannot participate in
/// swap migration.
/// # C: O(1)
pub fn try_lock_page(pa: u64) -> bool {
    page_meta()
        .and_then(|meta| meta.try_lock_page(hal::Pfn(pa / hal::PAGE_SIZE_BYTES)))
        .unwrap_or(false)
}

/// Release the migration/I/O lock for a PMM-managed page. Returns `false` if
/// metadata is absent or the caller did not own the lock.
/// # C: O(1)
pub fn unlock_page(pa: u64) -> bool {
    page_meta()
        .and_then(|meta| meta.unlock_page(hal::Pfn(pa / hal::PAGE_SIZE_BYTES)))
        .unwrap_or(false)
}

/// Revoke single-mapper write reuse before a page is shared with swap.
/// # C: O(1)
pub fn clear_anon_exclusive(pa: u64) {
    if let Some(meta) = page_meta() {
        let _ = meta.clear_flags(hal::Pfn(pa / hal::PAGE_SIZE_BYTES), crate::PageFlags::ANON_EXCLUSIVE);
    }
}

/// F157: compute pfn_max from a `BootInfo`. Used by `kernel_main` to
/// size the per-page metadata array. Same walk as
/// `init_from_boot_info`; lifted here so callers don't have to
/// touch `BootMemRegion` themselves.
/// # C: O(memmap.len)
pub fn pfn_max_from_boot_info(info: &BootInfo) -> u64 {
    if info.memmap_count == 0 { return 0; }
    // SAFETY: caller passed valid memmap_ptr/count per BootInfo contract.
    let regions: &[BootMemRegion] = unsafe {
        core::slice::from_raw_parts(info.memmap_ptr, info.memmap_count as usize)
    };
    let mut pfn_max: u64 = 0;
    for r in regions {
        if r.kind != BootMemKind::Usable { continue; }
        let end_pa = r.base_pa.saturating_add(r.len);
        let end_pfn = end_pa >> PAGE_SHIFT;
        if end_pfn > pfn_max { pfn_max = end_pfn; }
    }
    pfn_max
}

/// debug-cow: identify the current task (Linux pid == kernel tid) and CPU
/// for [COW-CORRUPT] / [COW-LEAK] attribution. Returns (0,0) pre-sched.
/// # C: O(1)
#[cfg(feature = "debug-cow")]
pub(super) fn cow_dbg_who() -> (u32, u32) {
    let tid = sched::current().map(|t| t.tid).unwrap_or(0);
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    let cpu = { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() };
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    let cpu = { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() };
    #[cfg(not(target_os = "oxide-kernel"))]
    let cpu = 0u32;
    (tid, cpu)
}

/// debug-cow item 2: authoritative "who still maps this frame" report.
/// The O(1) mapcount check can itself be under-counted (the residual-bug
/// hypothesis), so on a [COW-LEAK] hit we walk the frame's anon_vma rmap
/// chain and PTE-verify each candidate, naming a concrete still-mapping
/// (AS-root, VA) pair: `[COW-LEAK]  still-mapped-by root=R va=V`.
/// # C: O(N_chain) page-table walks
#[cfg(feature = "debug-cow")]
pub(super) fn cow_dbg_rmap_report(pa: u64) {
    crate::user_as::rmap_walk_anon_pa(pa, |root, va| {
        klog::write_raw(b"[COW-LEAK]  still-mapped-by root="); klog::write_hex_u64(root);
        klog::write_raw(b" va="); klog::write_hex_u64(va);
        klog::write_raw(b"\n");
    });
}

/// Internal: snapshot the metadata array if installed.
/// debug-atexit: dec context root for [ARMED-DEC]/[FWM-FREE] attribution.
/// Set by as_teardown (the dying root); 0 = use the current task's mm root.
#[cfg(feature = "debug-atexit")]
static DEC_CTX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// # C: O(1)
#[cfg(feature = "debug-atexit")]
pub fn set_dec_ctx(root: u64) { DEC_CTX.store(root, core::sync::atomic::Ordering::Release); }

/// # C: O(1)
#[cfg(feature = "debug-atexit")]
pub(super) fn dec_ctx_root() -> u64 {
    let t = DEC_CTX.load(core::sync::atomic::Ordering::Acquire);
    if t != 0 { return t; }
    sched::live::current()
        .and_then(|c| unsafe { c.mm_ref() }.map(|m| m.root_pa()))
        .unwrap_or(0)
}

pub(crate) fn page_meta() -> Option<&'static crate::PageMetaArr> {
    let p = PAGE_META_PTR.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: PAGE_META_PTR is set exactly once via Box::leak in
    // init_page_meta; the pointee has 'static lifetime; never freed.
    Some(unsafe { &*p })
}
