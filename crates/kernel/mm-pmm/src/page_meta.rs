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

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use hal::Pfn;

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
    }
}

/// One metadata slot per PFN. Layout per `11§8`: 24 bytes
/// (refcount 4 + flags 4 + mapping 8 + page_index 4 + pad 4).
///
/// `mapping` is a type-erased pointer per Linux `struct page->mapping`:
/// for anonymous pages it's an `Arc<vmm::AnonVma>` raw pointer with
/// `Arc::into_raw` semantics (pmm doesn't depend on vmm; the kernel
/// adapter — `pmm::setup::set_anon_rmap_for_pfn` — owns the typed
/// dance). `page_index` is the page-aligned offset within the
/// originating VMA, used by `rmap_walk_anon` to compute the VA.
#[repr(C)]
pub struct PageMeta {
    pub refcount:   AtomicU32,
    pub flags:      AtomicU32,
    pub mapping:    AtomicPtr<()>,
    pub page_index: AtomicU32,
    _pad:           u32,
}

impl PageMeta {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            refcount:   AtomicU32::new(0),
            flags:      AtomicU32::new(0),
            mapping:    AtomicPtr::new(core::ptr::null_mut()),
            page_index: AtomicU32::new(0),
            _pad:       0,
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
    fn meta_size_matches_spec() {
        // `11§8`: per-page metadata. 24 B = refcount(4) + flags(4) +
        // mapping(8) + page_index(4) + pad(4). Bumped from 16 to 24
        // when F156-rmap added page_index for `rmap_walk_anon`.
        // 24 B/page ≈ 0.6% RAM overhead — still well under the
        // 1%-of-RAM budget per `04§*`.
        assert_eq!(core::mem::size_of::<PageMeta>(), 24);
    }
}
