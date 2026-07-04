#[cfg(feature = "debug-cow")]
mod alloc_integrity {
    use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

    /// Data pointer to the leaked `[AtomicU64]` shadow bitmap (null until init).
    static BITS: AtomicPtr<AtomicU64> = AtomicPtr::new(core::ptr::null_mut());
    /// Word count of the bitmap (ceil(pfn_max/64)).
    static WORDS: AtomicUsize = AtomicUsize::new(0);

    /// Allocate the shadow bitmap covering [0, pfn_max). Idempotent (first
    /// caller wins). Called from `init_page_meta` once pfn_max is known.
    /// # C: O(pfn_max / 64)
    pub fn init(pfn_max: u64) {
        if pfn_max == 0 || !BITS.load(Ordering::Acquire).is_null() { return; }
        let words = ((pfn_max + 63) / 64) as usize;
        let mut v: alloc::vec::Vec<AtomicU64> = alloc::vec::Vec::with_capacity(words);
        for _ in 0..words { v.push(AtomicU64::new(0)); }
        let leaked: &'static [AtomicU64] = alloc::boxed::Box::leak(v.into_boxed_slice());
        // Publish WORDS before BITS so any reader that observes a non-null
        // BITS also observes the correct length.
        WORDS.store(words, Ordering::Release);
        BITS.store(leaked.as_ptr() as *mut AtomicU64, Ordering::Release);
    }

    /// `&AtomicU64` for `pfn`'s word, or `None` pre-init / out-of-range.
    /// # C: O(1)
    fn word(pfn: u64) -> Option<&'static AtomicU64> {
        let p = BITS.load(Ordering::Acquire);
        if p.is_null() { return None; }
        let w = (pfn >> 6) as usize;
        if w >= WORDS.load(Ordering::Acquire) { return None; }
        // SAFETY: BITS is a Box::leak'd 'static [AtomicU64] of WORDS elements;
        // `w` is bounds-checked above; a shared &AtomicU64 is sound (atomics).
        Some(unsafe { &*p.add(w) })
    }

    /// Mark `pfn` allocated; return the PRIOR bit (true ⇒ already allocated
    /// = double-alloc). No-op (returns false) pre-init / out-of-range.
    /// # C: O(1)
    pub fn test_and_set(pfn: u64) -> bool {
        let bit = 1u64 << (pfn & 63);
        match word(pfn) {
            Some(w) => (w.fetch_or(bit, Ordering::AcqRel) & bit) != 0,
            None    => false,
        }
    }

    /// Mark `pfn` free. Idempotent; no-op pre-init / out-of-range.
    /// # C: O(1)
    pub fn clear(pfn: u64) {
        let bit = 1u64 << (pfn & 63);
        if let Some(w) = word(pfn) { w.fetch_and(!bit, Ordering::AcqRel); }
    }
}
