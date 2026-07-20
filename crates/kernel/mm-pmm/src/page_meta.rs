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

use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

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
        /// identify the mm that allocated it until the sole
        /// PMM free path releases the matching `memory.stat pagetables`
        /// charge.
        const PAGETABLE      = 1 << 14;
        /// `mapping` is an `Arc<vmm::FileRmap>` raw pointer, not an anon_vma.
        /// It is valid only for shared file/shmem frames and makes the owner
        /// type explicit before any raw-pointer destructor runs.
        const FILE_RMAP      = 1 << 15;
    }
}

/// One metadata slot per PFN.  `mapping` carries the owning page-table root
/// only while `PAGETABLE` is set; it is otherwise the normal typed mapping
/// pointer.  Reusing that mutually-exclusive owner field preserves the fixed
/// 32-byte struct-page layout while retaining Linux's ptdesc/mm association.
///
/// `mapping` is a type-erased pointer per Linux `struct page->mapping`:
/// for anonymous pages it's an `Arc<vmm::AnonVma>` raw pointer with
/// `Arc::into_raw` semantics (pmm doesn't depend on vmm; the kernel
/// adapter — `pmm::setup::set_anon_rmap_for_pfn` — owns the typed
/// dance). `page_index` is the page-aligned offset within the
/// originating VMA, used by `rmap_walk_anon` to compute the VA.
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
    pub mapping:    AtomicPtr<()>,
    pub page_index: AtomicU32,
    /// Live user-PTE count (Linux `page->_mapcount`). Distinct from
    /// `refcount`; occupies the former 4-byte pad.
    pub mapcount:   AtomicU32,
    /// Owning cgroup-v2 id for anonymous memory. Zero is unowned/non-anon;
    /// the root cgroup has a nonzero identifier.
    pub memcg:      AtomicU64,
}

impl PageMeta {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            refcount:   AtomicU32::new(0),
            flags:      AtomicU32::new(0),
            mapping:    AtomicPtr::new(core::ptr::null_mut()),
            page_index: AtomicU32::new(0),
            mapcount:   AtomicU32::new(0),
            memcg:      AtomicU64::new(cgroup::NO_MEMCG),
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
}

impl PageMetaArr {
    /// # C: O(1)
    pub const fn new(base_pfn: u64, table: &'static [PageMeta]) -> Self {
        Self { base_pfn, table }
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
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use std::sync::Arc;
    use std::thread;

    fn leak_arr(base_pfn: u64, count: usize) -> PageMetaArr {
        let v: Vec<PageMeta> = (0..count).map(|_| PageMeta::new()).collect();
        let s: &'static [PageMeta] = Box::leak(v.into_boxed_slice());
        PageMetaArr::new(base_pfn, s)
    }

    #[test]
    fn new_empty() {
        let a = leak_arr(0, 0);
        assert!(a.is_empty());
        assert_eq!(a.len(), 0);
        assert!(a.get(Pfn(0)).is_none());
    }

    #[test]
    fn out_of_range_pfn_returns_none() {
        let a = leak_arr(100, 16);
        assert!(a.get(Pfn(99)).is_none());
        assert!(a.get(Pfn(116)).is_none());
        assert!(a.get(Pfn(100)).is_some());
        assert!(a.get(Pfn(115)).is_some());
    }

    #[test]
    fn refcount_inc_dec_roundtrip() {
        let a = leak_arr(0, 8);
        assert_eq!(a.refcount(Pfn(3)), Some(0));
        assert_eq!(a.inc_ref(Pfn(3)), Some(0)); // returns old
        assert_eq!(a.refcount(Pfn(3)), Some(1));
        assert_eq!(a.inc_ref(Pfn(3)), Some(1));
        assert_eq!(a.refcount(Pfn(3)), Some(2));
        assert_eq!(a.dec_ref(Pfn(3)), Some(1)); // returns new
        assert_eq!(a.dec_ref(Pfn(3)), Some(0));
        assert_eq!(a.refcount(Pfn(3)), Some(0));
    }

    #[test]
    fn flag_set_clear() {
        let a = leak_arr(0, 4);
        assert_eq!(a.flags(Pfn(0)), Some(PageFlags::empty()));
        a.set_flags(Pfn(0), PageFlags::DIRTY | PageFlags::REFERENCED).unwrap();
        let f = a.flags(Pfn(0)).unwrap();
        assert!(f.contains(PageFlags::DIRTY));
        assert!(f.contains(PageFlags::REFERENCED));
        a.clear_flags(Pfn(0), PageFlags::DIRTY).unwrap();
        let f = a.flags(Pfn(0)).unwrap();
        assert!(!f.contains(PageFlags::DIRTY));
        assert!(f.contains(PageFlags::REFERENCED));
    }

    #[test]
    fn page_lock_has_one_winner_and_releases() {
        const BASE_PFN: u64 = 0;
        const PAGE_COUNT: usize = 1;
        const LOCKED_PAGE_PFN: u64 = BASE_PFN;
        let a = leak_arr(BASE_PFN, PAGE_COUNT);
        let page = Pfn(LOCKED_PAGE_PFN);
        assert_eq!(a.try_lock_page(page), Some(true));
        assert_eq!(a.try_lock_page(page), Some(false));
        assert_eq!(a.unlock_page(page), Some(true));
        assert_eq!(a.unlock_page(page), Some(false));
        assert_eq!(a.try_lock_page(page), Some(true));
    }

    #[test]
    fn mapping_pointer_swap() {
        let a = leak_arr(0, 4);
        let p1: *mut () = 0xdead_beef as *mut ();
        let p2: *mut () = 0x1234_5678 as *mut ();
        assert_eq!(a.mapping(Pfn(2)), Some(core::ptr::null_mut()));
        assert_eq!(a.set_mapping(Pfn(2), p1), Some(core::ptr::null_mut()));
        assert_eq!(a.mapping(Pfn(2)), Some(p1));
        assert_eq!(a.set_mapping(Pfn(2), p2), Some(p1));
        assert_eq!(a.mapping(Pfn(2)), Some(p2));
    }

    #[test]
    fn concurrent_inc_dec_preserves_count() {
        // 8 threads × 1000 inc/dec on the same pfn; final count must be 0.
        let a: &'static PageMetaArr = Box::leak(Box::new(leak_arr(0, 1)));
        let arc: Arc<&'static PageMetaArr> = Arc::new(a);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let arc = Arc::clone(&arc);
            handles.push(thread::spawn(move || {
                for _ in 0..1_000 {
                    arc.inc_ref(Pfn(0));
                    arc.dec_ref(Pfn(0));
                }
            }));
        }
        for h in handles { h.join().unwrap(); }
        assert_eq!(a.refcount(Pfn(0)), Some(0));
    }

    #[test]
    fn refcount_only_affects_target_pfn() {
        let a = leak_arr(0, 4);
        a.inc_ref(Pfn(1)).unwrap();
        a.inc_ref(Pfn(1)).unwrap();
        a.inc_ref(Pfn(2)).unwrap();
        assert_eq!(a.refcount(Pfn(0)), Some(0));
        assert_eq!(a.refcount(Pfn(1)), Some(2));
        assert_eq!(a.refcount(Pfn(2)), Some(1));
        assert_eq!(a.refcount(Pfn(3)), Some(0));
    }

    #[test]
    fn mapcount_inc_dec_roundtrip() {
        let a = leak_arr(0, 8);
        assert_eq!(a.mapcount(Pfn(5)), Some(0));
        assert_eq!(a.inc_map(Pfn(5)), Some(0)); // returns old
        assert_eq!(a.mapcount(Pfn(5)), Some(1));
        assert_eq!(a.inc_map(Pfn(5)), Some(1));
        assert_eq!(a.mapcount(Pfn(5)), Some(2));
        assert_eq!(a.dec_map(Pfn(5)), Some(1)); // returns new
        assert_eq!(a.dec_map(Pfn(5)), Some(0));
        assert_eq!(a.mapcount(Pfn(5)), Some(0));
        // mapcount and refcount are independent fields.
        a.inc_ref(Pfn(5)).unwrap();
        assert_eq!(a.refcount(Pfn(5)), Some(1));
        assert_eq!(a.mapcount(Pfn(5)), Some(0));
    }

    #[test]
    fn meta_size_matches_spec() {
        // `11§8`: refcount(4) + flags(4) + mapping(8) + page_index(4) +
        // mapcount(4) + memcg(8) = 32 B/page, still below the 1%-of-RAM
        // metadata budget.
        assert_eq!(core::mem::size_of::<PageMeta>(), 32);
    }

    #[test]
    fn pagetable_context_uses_mapping_slot_without_layout_growth() {
        let a = leak_arr(0, 1);
        let pfn = Pfn(0);
        let root_pa = 0x20_000u64;
        a.set_flags(pfn, PageFlags::PAGETABLE).unwrap();
        a.set_mapping(pfn, root_pa as usize as *mut ()).unwrap();
        assert!(a.flags(pfn).unwrap().contains(PageFlags::PAGETABLE));
        assert_eq!(a.mapping(pfn).unwrap() as usize as u64, root_pa);
        a.clear_flags(pfn, PageFlags::PAGETABLE).unwrap();
        a.set_mapping(pfn, core::ptr::null_mut()).unwrap();
        assert!(!a.flags(pfn).unwrap().contains(PageFlags::PAGETABLE));
        assert!(a.mapping(pfn).unwrap().is_null());
    }
}
