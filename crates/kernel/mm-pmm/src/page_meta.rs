// Per-page metadata array per `11§8`.
//
// One `PageMeta` per physical page in `[base_pfn, base_pfn + len)`:
// `refcount` (COW + io_uring fixed-buffer pinning), `flags` (DIRTY /
// REFERENCED / LOCKED / RESERVED), and an opaque `mapping` pointer
// (file/inode owner — typed once VFS lands).
//
// Storage is supplied as a `&'static [PageMeta]`; the kernel boot path
// allocates this slab from PMM directly (`11§8` `≈ 0.4% RAM`).
// Hosted tests use `Box::leak` to manufacture the static slice.
//
// All fields are atomics — concurrent updates from any context are
// safe; no outer lock is needed for the array itself. Higher-level
// lock-ordering is the caller's concern (`06§3.6`).

use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, AtomicU64, Ordering};

use hal::Pfn;

mod reclaim;
pub use reclaim::{reclaim_state, ReclaimPageState};

bitflags::bitflags! {
    /// Per-page flag bits per `11§8`. Stored Relaxed; a flag transition
    /// implies whatever ordering the caller establishes externally
    /// (typically via the page-table or VMA write lock).
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct PageFlags: u32 {
        const DIRTY      = 1 << 0;
        const REFERENCED = 1 << 1;
        const LOCKED     = 1 << 2;
        const RESERVED   = 1 << 3;
        // F157-A1: page-class + state bits mirroring Linux `page->flags`
        // (PageAnon / PageSwapBacked / PG_uptodate) + the folio
        // `PageAnonExclusive` proxy used by the COW-reuse fast path. Only
        // 4 of 32 bits were used; these claim 6 more (26 still free).
        const ANON           = 1 << 4;
        const FILE           = 1 << 5;
        const SHMEM          = 1 << 6;
        const PFNMAP         = 1 << 7;
        const UPTODATE       = 1 << 8;
        /// Linux `PageAnonExclusive`: the page is mapped by exactly one
        /// AS and may be reused in place on a write fault (`wp_page_reuse`)
        /// instead of COW-copied. A3 will set/clear this; today it's a
        /// placeholder so the bit position is reserved.
        const ANON_EXCLUSIVE = 1 << 9;
        /// Linux `PG_lru`: this PFN has exactly one reclaim-LRU membership.
        const LRU            = 1 << 10;
        /// Linux `PG_active`: membership is on the active, not inactive LRU.
        const ACTIVE         = 1 << 11;
        /// Linux `PG_unevictable`: page is on the unevictable reclaim list.
        const UNEVICTABLE    = 1 << 12;
        /// Linux `PG_isolated`: temporarily removed from its LRU by reclaim.
        const ISOLATED       = 1 << 13;
        /// Linux `PageTable`: this managed frame is a page-table page, not a
        /// reclaimable user or page-cache folio.  Its `memcg` and `mapping`
        /// (the latter carries the root PA only while this flag is set)
        /// identify the mm that allocated it until the sole PMM free path
        /// releases the matching `memory.stat pagetables` charge.
        const PAGETABLE      = 1 << 14;
        /// Linux `PageSlab` equivalent for physical runs permanently owned by
        /// the kernel allocator.  These frames back allocator arenas, not
        /// user, page-cache, or reclaimable objects, and must never enter a
        /// generic PMM release path.
        const KHEAP          = 1 << 16;
        /// This PFN was seeded into the buddy allocator at boot (inside a
        /// `UsableRegion`) — distinguishes "buddy-managed, currently free"
        /// from "never handed to the buddy at all" (kernel image, firmware
        /// reserved, ACPI, memmap holes). Both cases otherwise carry
        /// identical all-zero `PageMeta` (`PageMeta::new()` zero-inits every
        /// slot in `[0, pfn_max)` unconditionally, gaps included), which a
        /// bare `page_meta().get(pfn)` hit cannot tell apart.
        const MANAGED        = 1 << 15;
        /// A blocking page-lock waiter has published on the corresponding
        /// bounded wait bucket. Unlock tests this before entering that bucket.
        const WAITERS        = 1 << 17;
    }
}

/// One metadata slot per PFN.  `mapping` carries the owning page-table root
/// only while `PAGETABLE` is set; it is otherwise the normal typed mapping
/// pointer. Reusing that mutually-exclusive owner field retains Linux's
/// ptdesc/mm association without a second owner pointer.
///
/// `mapping` is a Linux-style tagged raw owner pointer: its low alignment bit
/// distinguishes file rmap from anon-vma, so type and pointer cannot diverge.
/// `page_index` is the page-aligned offset within the originating VMA, used by
/// rmap walkers to compute the VA. `lru_prev`/`lru_next` are Linux's embedded
/// `struct page::lru` equivalent, so exact list deletion never searches by PFN.
///
/// F157-A1: `refcount` and `mapcount` are now SEPARATE, mirroring Linux
/// `page->_refcount` vs `page->_mapcount`:
///   * `mapcount` = count of live user PTEs pointing at this frame.
///   * `refcount` = `mapcount` + object holds (inode base pin for shmem)
///     + transient kernel pins (io_uring fixed buffers, GUP).
/// A frame is freed only when `refcount` hits 0 (`setup.rs` free path),
/// by which point `mapcount` is already 0. The split lets a future
/// `wp_page_reuse` fast path test `mapcount == 1` (sole mapper) without
/// being fooled by a transient refcount pin. `memcg` records the canonical
/// owning cgroup for anonymous memory and is carried into a swap slot.
#[repr(C)]
pub struct PageMeta {
    pub refcount:   AtomicU32,
    pub flags:      AtomicU32,
    /// Diagnostic-only holder for `LOCKED`. Zero means boot/interrupt context
    /// or no recorded task; normal lock semantics remain solely in `flags`.
    #[cfg(feature = "debug-watchdog")]
    pub lock_owner: AtomicU32,
    pub mapping:    AtomicPtr<()>,
    pub page_index: AtomicU32,
    /// Live user-PTE count (Linux `page->_mapcount`). Distinct from
    /// `refcount`; occupies the former 4-byte pad.
    pub mapcount:   AtomicU32,
    /// Owning cgroup-v2 id for anonymous memory. Zero is unowned/non-anon;
    /// the root cgroup has a nonzero identifier.
    pub memcg:      AtomicU64,
    /// Previous PFN in the current reclaim LRU, or `u64::MAX`.
    pub lru_prev:   AtomicU64,
    /// Next PFN in the current reclaim LRU, or `u64::MAX`.
    pub lru_next:   AtomicU64,
}

/// Native-driver `struct page` ABI view.  PMM owns the canonical allocator
/// state in `PageMeta`; this stable per-PFN view exists so driver arithmetic
/// maps a page descriptor back to the same physical PFN.
#[repr(C)]
pub struct NativePage {
    pub flags: AtomicU64,
    pub mapping_union: [u8; 44],
    pub refcount: AtomicI32,
    pub memcg_data: AtomicU64,
}

impl NativePage {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { flags: AtomicU64::new(0), mapping_union: [0; 44], refcount: AtomicI32::new(0), memcg_data: AtomicU64::new(0) }
    }
}

const _: () = {
    assert!(core::mem::size_of::<NativePage>() == 64);
    assert!(core::mem::offset_of!(NativePage, flags) == 0);
    assert!(core::mem::offset_of!(NativePage, refcount) == 52);
    assert!(core::mem::offset_of!(NativePage, memcg_data) == 56);
};

impl PageMeta {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            refcount:   AtomicU32::new(0),
            flags:      AtomicU32::new(0),
            #[cfg(feature = "debug-watchdog")]
            lock_owner: AtomicU32::new(0),
            mapping:    AtomicPtr::new(core::ptr::null_mut()),
            page_index: AtomicU32::new(0),
            mapcount:   AtomicU32::new(0),
            memcg:      AtomicU64::new(cgroup::NO_MEMCG),
            lru_prev:   AtomicU64::new(u64::MAX),
            lru_next:   AtomicU64::new(u64::MAX),
        }
    }
}

impl Default for PageMeta {
    fn default() -> Self { Self::new() }
}

/// Sparse-friendly view over the per-PFN array. Indexing is by raw PFN;
/// PFNs outside `[base, base + len)` return `None` rather than panic so
/// boot-time queries from arbitrary HW maps stay safe.
pub struct PageMetaArr {
    base_pfn: u64,
    table:    &'static [PageMeta],
    native:   &'static [NativePage],
}

impl PageMetaArr {
    /// # C: O(1)
    pub const fn new(base_pfn: u64, table: &'static [PageMeta]) -> Self {
        Self { base_pfn, table, native: &[] }
    }

    /// # C: O(1)
    pub const fn new_with_native(base_pfn: u64, table: &'static [PageMeta], native: &'static [NativePage]) -> Self {
        Self { base_pfn, table, native }
    }

    /// # C: O(1)
    pub fn base_pfn(&self) -> Pfn { Pfn(self.base_pfn) }

    /// # C: O(1)
    pub fn len(&self) -> usize { self.table.len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.table.is_empty() }

    /// Per-PFN slot or `None` if `pfn` is out of range.
    /// # C: O(1)
    pub fn get(&self, pfn: Pfn) -> Option<&PageMeta> {
        let idx = pfn.0.checked_sub(self.base_pfn)? as usize;
        self.table.get(idx)
    }

    /// Native-driver page descriptor for this physical PFN.
    /// # C: O(1)
    pub fn native_page(&self, pfn: Pfn) -> Option<&NativePage> {
        let idx = pfn.0.checked_sub(self.base_pfn)? as usize;
        self.native.get(idx)
    }

    /// First native-driver page descriptor, when the PMM published one.
    /// # C: O(1)
    pub fn native_base(&self) -> *const NativePage { self.native.as_ptr() }

    /// Atomic refcount increment. Returns the old value, or `None` if
    /// `pfn` is out of range.
    /// # C: O(1)
    pub fn inc_ref(&self, pfn: Pfn) -> Option<u32> {
        Some(self.get(pfn)?.refcount.fetch_add(1, Ordering::AcqRel))
    }

    /// Atomic refcount decrement. Returns the new value, or `None` if
    /// `pfn` is out of range. The caller frees the page when the new
    /// value reaches `0` per `11§7`.
    ///
    /// Underflows panic in `debug` builds; `release` wraps silently.
    /// # C: O(1)
    pub fn dec_ref(&self, pfn: Pfn) -> Option<u32> {
        let prev = self.get(pfn)?.refcount.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "PageMeta::dec_ref underflow at pfn {}", pfn.0);
        Some(prev.wrapping_sub(1))
    }

    /// Snapshot of the refcount.
    /// # C: O(1)
    pub fn refcount(&self, pfn: Pfn) -> Option<u32> {
        Some(self.get(pfn)?.refcount.load(Ordering::Acquire))
    }

    /// Atomic mapcount increment (a new user PTE now points here).
    /// Returns the old value, or `None` if `pfn` is out of range.
    /// Mirrors Linux `page_add_*_rmap` `atomic_inc(&page->_mapcount)`.
    /// # C: O(1)
    pub fn inc_map(&self, pfn: Pfn) -> Option<u32> {
        Some(self.get(pfn)?.mapcount.fetch_add(1, Ordering::AcqRel))
    }

    /// Atomic mapcount decrement (a user PTE was torn down). Returns the
    /// NEW value, or `None` if `pfn` is out of range. Underflows panic in
    /// `debug` builds; `release` wraps silently. Mirrors Linux
    /// `page_remove_rmap` `atomic_add_negative` shape.
    /// # C: O(1)
    pub fn dec_map(&self, pfn: Pfn) -> Option<u32> {
        let prev = self.get(pfn)?.mapcount.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "PageMeta::dec_map underflow at pfn {}", pfn.0);
        Some(prev.wrapping_sub(1))
    }

    /// Snapshot of the mapcount (live user-PTE count).
    /// # C: O(1)
    pub fn mapcount(&self, pfn: Pfn) -> Option<u32> {
        Some(self.get(pfn)?.mapcount.load(Ordering::Acquire))
    }

    /// Set the given flag bits. Returns the previous full flag word.
    /// # C: O(1)
    pub fn set_flags(&self, pfn: Pfn, bits: PageFlags) -> Option<PageFlags> {
        let prev = self.get(pfn)?.flags.fetch_or(bits.bits(), Ordering::AcqRel);
        Some(PageFlags::from_bits_retain(prev))
    }

    /// Clear the given flag bits. Returns the previous full flag word.
    /// # C: O(1)
    pub fn clear_flags(&self, pfn: Pfn, bits: PageFlags) -> Option<PageFlags> {
        let prev = self.get(pfn)?.flags.fetch_and(!bits.bits(), Ordering::AcqRel);
        Some(PageFlags::from_bits_retain(prev))
    }

    /// Snapshot of the flag word.
    /// # C: O(1)
    pub fn flags(&self, pfn: Pfn) -> Option<PageFlags> {
        Some(PageFlags::from_bits_retain(self.get(pfn)?.flags.load(Ordering::Acquire)))
    }

    /// Try to acquire the per-page migration/I/O lock. Exactly one caller can
    /// transition an unlocked page to `LOCKED`; the winner owns all state
    /// protected by that bit until [`Self::unlock_page`] releases it.
    /// Returns `None` for an out-of-range PFN.
    /// # C: O(1)
    pub fn try_lock_page(&self, pfn: Pfn) -> Option<bool> {
        let flags = &self.get(pfn)?.flags;
        let previous = flags.fetch_or(PageFlags::LOCKED.bits(), Ordering::AcqRel);
        Some(previous & PageFlags::LOCKED.bits() == 0)
    }

    /// Release the per-page migration/I/O lock acquired by
    /// [`Self::try_lock_page`]. Returns `false` if the page was not locked,
    /// which is a caller bug; no state other than the lock bit is changed.
    /// # C: O(1)
    pub fn unlock_page(&self, pfn: Pfn) -> Option<bool> {
        let previous = self.get(pfn)?.flags.fetch_and(!PageFlags::LOCKED.bits(), Ordering::Release);
        Some(previous & PageFlags::LOCKED.bits() != 0)
    }

    /// Publish that a blocking page-lock waiter may need a wakeup.
    /// # C: O(1)
    pub fn set_page_waiters(&self, pfn: Pfn) -> Option<()> {
        self.get(pfn)?.flags.fetch_or(PageFlags::WAITERS.bits(), Ordering::Release);
        Some(())
    }

    /// Whether the page's bounded wait bucket may contain a blocking waiter.
    /// # C: O(1)
    pub fn page_has_waiters(&self, pfn: Pfn) -> Option<bool> {
        Some(self.get(pfn)?.flags.load(Ordering::Acquire) & PageFlags::WAITERS.bits() != 0)
    }

    /// Retire a stale page-lock waiter marker after its bucket is empty.
    /// # C: O(1)
    pub fn clear_page_waiters(&self, pfn: Pfn) -> Option<()> {
        self.get(pfn)?.flags.fetch_and(!PageFlags::WAITERS.bits(), Ordering::Release);
        Some(())
    }

    /// Record the task that acquired a page lock for the debug-watchdog
    /// diagnostic path. The bit in `flags` remains the sole lock authority.
    /// # C: O(1)
    #[cfg(feature = "debug-watchdog")]
    pub fn note_page_lock_owner(&self, pfn: Pfn, tid: u32) {
        if let Some(page) = self.get(pfn) { page.lock_owner.store(tid, Ordering::Release); }
    }

    /// Clear the debug-only page-lock ownership record before publishing the
    /// unlocked bit. The record never participates in acquisition.
    /// # C: O(1)
    #[cfg(feature = "debug-watchdog")]
    pub fn clear_page_lock_owner(&self, pfn: Pfn) {
        if let Some(page) = self.get(pfn) { page.lock_owner.store(0, Ordering::Release); }
    }

    /// Read the debug-only page-lock owner, if this PFN has metadata.
    /// # C: O(1)
    #[cfg(feature = "debug-watchdog")]
    pub fn page_lock_owner(&self, pfn: Pfn) -> Option<u32> {
        Some(self.get(pfn)?.lock_owner.load(Ordering::Acquire))
    }

    /// Set the mapping pointer (typed `MappingId` once VFS lands).
    /// # C: O(1)
    pub fn set_mapping(&self, pfn: Pfn, ptr: *mut ()) -> Option<*mut ()> {
        Some(self.get(pfn)?.mapping.swap(ptr, Ordering::AcqRel))
    }

    /// Snapshot of the mapping pointer.
    /// # C: O(1)
    pub fn mapping(&self, pfn: Pfn) -> Option<*mut ()> {
        Some(self.get(pfn)?.mapping.load(Ordering::Acquire))
    }

    /// Atomic swap on the mapping pointer. Returns the previous
    /// value so the caller can decrement an Arc strong count when
    /// the slot was non-null. Linux `struct page->mapping` swap.
    /// # C: O(1)
    pub fn swap_mapping(&self, pfn: Pfn, ptr: *mut ()) -> Option<*mut ()> {
        Some(self.get(pfn)?.mapping.swap(ptr, Ordering::AcqRel))
    }

    /// Set the page_index — the page-aligned VA offset within the
    /// originating VMA. Per Linux `struct page->index`.
    /// # C: O(1)
    pub fn set_page_index(&self, pfn: Pfn, idx: u32) -> Option<()> {
        self.get(pfn)?.page_index.store(idx, Ordering::Release);
        Some(())
    }

    /// Snapshot of `page_index`.
    /// # C: O(1)
    pub fn page_index(&self, pfn: Pfn) -> Option<u32> {
        Some(self.get(pfn)?.page_index.load(Ordering::Acquire))
    }

    /// Set the owning cgroup for one anonymous page. # C: O(1)
    pub fn set_memcg(&self, pfn: Pfn, cgid: u64) -> Option<()> {
        self.get(pfn)?.memcg.store(cgid, Ordering::Release);
        Some(())
    }

    /// Snapshot the owning cgroup for one page. # C: O(1)
    pub fn memcg(&self, pfn: Pfn) -> Option<u64> {
        Some(self.get(pfn)?.memcg.load(Ordering::Acquire))
    }

}

#[cfg(test)]
#[path = "page_meta/tests.rs"]
mod tests;
