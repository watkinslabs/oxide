// Minimal bump allocator — the rtld's heap (docs/59§5). The dynamic linker
// needs dynamic storage (the link map, `crate::dl`'s Vec/BTreeMap) before
// libc's malloc exists, so it runs its own allocator over mmap'd regions.
// Bump-only: dealloc is a no-op (glibc's __minimal_malloc is the same shape)
// — the rtld never frees during loading. When a chunk is exhausted a fresh
// region is mapped; prior allocations stay valid in their own mappings.
use core::sync::atomic::{AtomicUsize, Ordering};

/// Pure bump arena over a half-open region [base, end). Lock-free via CAS so
/// it is Sync without `static mut`; rtld startup is single-threaded anyway.
pub struct Bump {
    cur: AtomicUsize,
    end: AtomicUsize,
}

impl Bump {
    /// # C: O(1)
    pub const fn new() -> Self {
        Bump { cur: AtomicUsize::new(0), end: AtomicUsize::new(0) }
    }

    /// Install the backing region [base, base+size). Resets the arena.
    ///
    /// # C: set the bump region to [base, base+size)
    pub fn set_region(&self, base: usize, size: usize) {
        self.end.store(base + size, Ordering::Release);
        self.cur.store(base, Ordering::Release);
    }

    /// Remaining free bytes in the current region.
    /// # C: end - cur
    pub fn remaining(&self) -> usize {
        self.end.load(Ordering::Acquire).saturating_sub(self.cur.load(Ordering::Acquire))
    }

    /// Bump-allocate `size` bytes aligned to `align` (power of two). Returns
    /// None if the current region cannot satisfy it.
    ///
    /// # C: aligned bump within [cur, end); None on exhaustion
    pub fn alloc(&self, size: usize, align: usize) -> Option<*mut u8> {
        let align = align.max(1);
        loop {
            let cur = self.cur.load(Ordering::Acquire);
            let end = self.end.load(Ordering::Acquire);
            let aligned = (cur + (align - 1)) & !(align - 1);
            let next = aligned.checked_add(size)?;
            if next > end { return None; }
            if self.cur.compare_exchange(cur, next, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                return Some(aligned as *mut u8);
            }
        }
    }
}

impl Default for Bump {
    fn default() -> Self { Self::new() }
}

#[cfg(feature = "freestanding")]
mod global {
    use super::Bump;
    use crate::syscall;
    use core::alloc::{GlobalAlloc, Layout};
    use core::sync::atomic::{AtomicBool, Ordering};

    const CHUNK: usize = 8 << 20; // 8 MiB per mmap'd region

    static HEAP: Bump = Bump::new();
    static GROWING: AtomicBool = AtomicBool::new(false);

    struct G;

    // SAFETY: the bump arena is internally synchronized (CAS) and the
    // process is single-threaded during the rtld phase that allocates; grow
    // is guarded so two threads cannot map regions concurrently.
    unsafe impl GlobalAlloc for G {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let (size, align) = (layout.size(), layout.align());
            if let Some(p) = HEAP.alloc(size, align) { return p; }
            // Exhausted: map a fresh region big enough, then retry.
            let want = (size + align).max(CHUNK);
            let mapped = grow(want);
            if mapped == 0 { return core::ptr::null_mut(); }
            HEAP.set_region(mapped, want);
            HEAP.alloc(size, align).unwrap_or(core::ptr::null_mut())
        }
        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
            // bump allocator: no per-allocation free
        }
    }

    fn grow(size: usize) -> usize {
        while GROWING.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            core::hint::spin_loop();
        }
        // SAFETY: anonymous private mmap of `size` bytes RW; -1 fd, 0 off per
        // the MAP_ANONYMOUS contract. Returns the region base or 0 on failure.
        let r = unsafe {
            syscall::mmap(0, size, syscall::PROT_READ | syscall::PROT_WRITE,
                syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS, -1, 0)
        };
        GROWING.store(false, Ordering::Release);
        if r < 0 { 0 } else { r as usize }
    }

    #[global_allocator]
    static A: G = G;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_within_bounds_no_overlap() {
        let buf = std::vec![0u8; 4096];
        let base = buf.as_ptr() as usize;
        let b = Bump::new();
        b.set_region(base, 4096);

        let p1 = b.alloc(10, 16).unwrap() as usize;
        let p2 = b.alloc(32, 32).unwrap() as usize;
        let p3 = b.alloc(1, 8).unwrap() as usize;
        assert_eq!(p1 % 16, 0);
        assert_eq!(p2 % 32, 0);
        assert_eq!(p3 % 8, 0);
        assert!(p1 >= base && p3 < base + 4096);
        assert!(p2 >= p1 + 10); // no overlap with p1's 10 bytes
        assert!(p3 >= p2 + 32); // no overlap with p2's 32 bytes
    }

    #[test]
    fn exhaustion_returns_none() {
        let buf = std::vec![0u8; 64];
        let b = Bump::new();
        b.set_region(buf.as_ptr() as usize, 64);
        assert!(b.alloc(32, 8).is_some());
        assert!(b.alloc(64, 8).is_none()); // would exceed region
        assert!(b.remaining() <= 32);
    }
}
