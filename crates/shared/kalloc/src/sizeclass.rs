// Size-class free lists — the `kmalloc` front end (`docs/12§2`).
//
// The sorted hole list underneath is address-ordered: `alloc` first-fits and
// `dealloc` inserts in order, both walking the list. That is fine while the
// heap is young and fatal once it is not: measured on a 64 MiB heap, one
// alloc+free pair costs 21 ns unfragmented and 128 µs after 20 000 holes
// accumulate — a 6000× cliff that every allocation-heavy kernel path pays
// (B1475 traced systemd service start-up latency to it).
//
// Linux never asks a general-purpose allocator for a small object: `kmalloc`
// routes to a per-size `kmem_cache` whose free objects sit on an intrusive
// LIFO list (Linux's `slab_alloc_node`/`do_slab_free` pop and push
// `c->freelist`), and only a cache REFILL touches the page allocator. Same
// shape here: a class pop/push is O(1), and the O(N) hole-list walk is paid
// once per slab and amortised over every object carved from it.
//
// Class sizes are Linux's `kmalloc` caches (`kmalloc_info[]`),
// floored at this heap's 16-byte minimum block.
//
// Diagnostic builds bypass the front end entirely (see `class_index`): the
// corruption hunters (`debug-heappoison` quarantine, `debug-dealloc-diag`
// size ledger, `debug-hw-watchpoint`, `debug-efence`) all assume every live
// block is individually known to the hole list.

use core::alloc::Layout;
use core::ptr::NonNull;

/// Serviced object sizes. Linux `kmalloc_info[]` minus the
/// 8-byte cache, which is below this heap's `MIN_HOLE_SIZE`.
pub const CLASS_SIZES: [usize; 11] =
    [16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096];

/// Largest routed request. Above this, Linux leaves `kmalloc` for the page
/// allocator; here the hole list keeps large blocks. Derived from
/// [`CLASS_SIZES`] so the bound cannot drift from the table it bounds.
///
/// Read by the real `class_index` and by the class-routing tests. Diagnostic
/// builds replace `class_index` with a stub that routes nothing, so in those
/// configurations the bound has no reader.
#[allow(dead_code)]
pub const MAX_CLASS_BYTES: usize = CLASS_SIZES[CLASS_SIZES.len() - 1];

/// Alignment every slab base is carved to, and the largest alignment a routed
/// request may ask for. Linux's `kmalloc` caches guarantee `ARCH_KMALLOC_MINALIGN`
/// and size-derived alignment the same way.
pub const SLAB_ALIGN: usize = 64;

/// Preferred slab size. One O(N) hole-list carve then serves `SLAB_BYTES/obj`
/// allocations, so the walk cost per object approaches zero.
pub const SLAB_BYTES: usize = 32 * 1024;

/// Progressively smaller slab carves, tried in order, so a fragmented heap
/// still makes progress instead of reporting OOM with free space available.
pub const SLAB_FALLBACK_BYTES: [usize; 3] = [SLAB_BYTES, 4096, 0];

/// Class serving `layout`, or `None` to leave it to the hole list. The SINGLE
/// routing predicate: `dealloc` re-evaluates it on the same `Layout` Rust
/// guarantees it is given, so an object can never be pushed to a class it was
/// not carved for.
/// # C: O(NCLASS)
#[cfg(not(any(feature = "debug-heappoison", feature = "debug-dealloc-diag",
              feature = "debug-hw-watchpoint", feature = "debug-efence")))]
pub fn class_index(layout: Layout) -> Option<usize> {
    let size = layout.size();
    let align = layout.align();
    if size == 0 || size > MAX_CLASS_BYTES || align > SLAB_ALIGN { return None; }
    let i = CLASS_SIZES.iter().position(|&c| c >= size)?;
    // Objects sit at `base + k*obj` from a `SLAB_ALIGN`-aligned base, so the
    // stride must itself carry the caller's alignment.
    if CLASS_SIZES[i] % align != 0 { return None; }
    Some(i)
}

/// Diagnostic builds keep every block in the hole list where their quarantine,
/// size ledger, watchpoint and fence machinery can see it. # C: O(1)
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag",
          feature = "debug-hw-watchpoint", feature = "debug-efence"))]
pub fn class_index(_layout: Layout) -> Option<usize> { None }

/// Per-class intrusive LIFO free lists. A free object stores its successor in
/// its own first word (Linux's `freelist` pointer lives in the free object
/// too), so the lists cost no side storage.
pub struct SizeClasses {
    heads: [*mut u8; CLASS_SIZES.len()],
}

// SAFETY: every `heads` pointer addresses a block this allocator owns and is
// only reached while the caller holds `KAlloc`'s `Spinlock`, exactly like the
// `HoleList` the same lock guards.
unsafe impl Send for SizeClasses {}

impl SizeClasses {
    /// # C: O(1)
    pub const fn new() -> Self { Self { heads: [core::ptr::null_mut(); CLASS_SIZES.len()] } }

    /// Take the class head. # C: O(1)
    pub fn pop(&mut self, i: usize) -> Option<NonNull<u8>> {
        let head = self.heads[i];
        let nn = NonNull::new(head)?;
        // SAFETY: `head` is a block this allocator carved for class `i`
        // (>= 16 bytes) and pushed; its first word holds the successor link.
        self.heads[i] = unsafe { core::ptr::read(head as *const *mut u8) };
        Some(nn)
    }

    /// Return an object to its class. # C: O(1)
    /// # SAFETY: `p` was carved for class `i` by `push_slab` and is no longer
    /// borrowed by the caller.
    pub unsafe fn push(&mut self, i: usize, p: *mut u8) {
        // SAFETY: caller-asserted ownership; the object is at least
        // `CLASS_SIZES[0]` = 16 bytes, so the link word fits.
        unsafe { core::ptr::write(p as *mut *mut u8, self.heads[i]) };
        self.heads[i] = p;
    }

    /// Detach class `i`'s whole free list and return its head, for a caller
    /// that will return every object to the hole list. Linux reclaims idle slab
    /// memory the same way (`kmem_cache_shrink`, `discard_slab`) rather than
    /// letting a cache pin memory another size needs.
    /// # C: O(1)
    pub fn take_list(&mut self, i: usize) -> *mut u8 {
        core::mem::replace(&mut self.heads[i], core::ptr::null_mut())
    }

    /// Successor link of a detached free object. Read BEFORE the object is
    /// handed to the hole list, which overwrites its first bytes with a header.
    /// # SAFETY: `p` is a detached free object of some class (>= 16 bytes).
    /// # C: O(1)
    pub unsafe fn next_of(p: *mut u8) -> *mut u8 {
        // SAFETY: caller-asserted — every class object is at least 16 bytes and
        // stores its successor in its first word.
        unsafe { core::ptr::read(p as *const *mut u8) }
    }

    /// Thread `count` objects of `CLASS_SIZES[i]` starting at `base` onto the
    /// class list.
    /// # SAFETY: `[base, base + count*CLASS_SIZES[i])` is a live, exclusively
    /// owned, `SLAB_ALIGN`-aligned allocation.
    /// # C: O(count)
    pub unsafe fn push_slab(&mut self, i: usize, base: *mut u8, count: usize) {
        let obj = CLASS_SIZES[i];
        for k in 0..count {
            // SAFETY: `k < count` keeps the offset inside the caller's slab.
            unsafe { self.push(i, base.add(k * obj)) };
        }
    }
}
