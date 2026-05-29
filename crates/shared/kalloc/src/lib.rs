// Kernel heap allocator (`kalloc`).
//
// `KAlloc` is a `GlobalAlloc` implementation backed by a sorted hole-list
// (`holes::HoleList`) with a `Spinlock<HoleList, KMalloc>` guard. The
// `KMalloc` lock class is the leaf of the partial order (`06§3.6`); any
// other subsystem may hold its own lock and call into kalloc, but kalloc
// never calls back into them.
//
// Boot sets up a single fixed-size BSS heap (`STATIC_HEAP_SIZE`) and
// hands its byte range to `KAlloc::init`. Future revisions per `12§2`
// will replace the static heap with PMM-backed slab size-class routing
// once a kernel binary stage exists; the public `GlobalAlloc` surface
// stays.
//
// Hosted tests instantiate fresh `KAlloc` instances over their own
// `Vec<u8>` buffers — no global state.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sync::{KMalloc, Spinlock};

mod holes;
pub use holes::{HoleList, MIN_HOLE_ALIGN, MIN_HOLE_SIZE};

/// Heap size carved out of BSS for the kernel's static heap. 16 MiB is
/// generous for early-boot subsystems (vmm VMA tree, sched runqueues,
/// vfs dentry cache); replaced by PMM-backed slab routing per `12§2`
/// once a binary stage exists.
pub const STATIC_HEAP_SIZE: usize = 64 * MIB;

/// Bytes in 1 MiB.
pub const MIB: usize = 1024 * 1024;

/// Minimum grow-callback request size — avoid thrashing the PMM with
/// tiny grows by always pulling a 1 MiB chunk.
pub const GROW_CHUNK_MIN: usize = 1 * MIB;

/// Bump-aligned BSS storage. `align(4096)` keeps the heap page-aligned
/// so future mappings can be relaxed at page granularity.
#[repr(C, align(4096))]
struct StaticHeap(UnsafeCell<MaybeUninit<[u8; STATIC_HEAP_SIZE]>>);

// SAFETY: cross-thread access is mediated by `KAlloc`'s internal
// Spinlock; the raw bytes are uninitialized BSS and only handed out
// via `KAlloc::init_static`.
unsafe impl Sync for StaticHeap {}

static STATIC_HEAP: StaticHeap = StaticHeap(UnsafeCell::new(MaybeUninit::uninit()));

/// Heap allocator. Construct with `KAlloc::new()` (const), then call
/// `init` once at boot before any allocation.
pub struct KAlloc {
    inner: Spinlock<HoleList, KMalloc>,
    initialized: AtomicBool,
    grow_hook: AtomicU64,
}

impl KAlloc {
    /// Construct an uninitialized allocator. `init` must be called
    /// before any `alloc` / `dealloc` reaches this instance.
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            inner: Spinlock::new(HoleList::new()),
            initialized: AtomicBool::new(false),
            grow_hook: AtomicU64::new(GROW_HOOK_NONE),
        }
    }

    /// Set up the allocator over `[start, start + size)`.
    ///
    /// # SAFETY: caller asserts the byte range is exclusively owned by
    /// this allocator for the rest of program lifetime, fully writable,
    /// and not aliased by any live reference. Must be called exactly
    /// once before the first allocation.
    /// # C: O(1)
    /// # Ctx: pre-init, IRQ-off, single-CPU
    pub unsafe fn init(&self, start: usize, size: usize) {
        let mut g = self.inner.lock();
        // SAFETY: caller-asserted exclusive ownership of [start, start+size).
        unsafe { g.add_free_region(start, size) };
        drop(g);
        self.initialized.store(true, Ordering::Release);
    }

    /// Initialize from the built-in static BSS heap. Convenience wrapper
    /// over `init`; same one-shot, exclusive-ownership contract.
    ///
    /// # SAFETY: caller is the boot path; the static heap must not
    /// already be in use.
    /// # C: O(1)
    /// # Ctx: pre-init
    pub unsafe fn init_static(&self) {
        let ptr = STATIC_HEAP.0.get() as *mut u8 as usize;
        // SAFETY: caller-asserted exclusivity; STATIC_HEAP lives for the
        // process lifetime.
        unsafe { self.init(ptr, STATIC_HEAP_SIZE) };
    }

    /// True iff `init` has been called.
    /// # C: O(1)
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }
}

impl Default for KAlloc {
    fn default() -> Self { Self::new() }
}

/// T16 (F247) growable kernel heap: when the hole-list allocator can't
/// satisfy a request, fall back to a registered grow callback that
/// asks the PMM for more pages and feeds them to the hole list.
/// Linux's vmalloc equivalent; without it the kernel OOMs on any
/// single workload bigger than the static heap can hold.
///
/// Callback signature: takes the minimum extra bytes needed; returns
/// `(start_addr, size_bytes)` of a fresh region added to the hole
/// list, or `None` if no more memory is available. The callback owns
/// the lifetime of the region — it must stay valid until process
/// shutdown.
pub type GrowFn = fn(min_extra: usize) -> Option<(usize, usize)>;

/// Sentinel "no hook installed" stored in `KAlloc::grow_hook`.
const GROW_HOOK_NONE: u64 = 0;

impl KAlloc {
    /// Register a callback the alloc path invokes when the hole-list
    /// can't satisfy a request. Idempotent: a later call replaces the
    /// prior hook.
    /// # SAFETY: `f` must remain a valid fn-pointer for the lifetime
    /// of this allocator; the kernel never unloads it.
    /// # C: O(1)
    pub fn set_grow_hook(&self, f: GrowFn) {
        let raw = (f as usize) as u64;
        self.grow_hook.store(raw, Ordering::Release);
    }
}

// SAFETY: `KAlloc::alloc` returns either null or a NonNull pointing
// into the heap region the caller passed to `init`. `dealloc` accepts
// only pointers that came from `alloc`; both paths take the inner
// Spinlock so the hole list mutations are serialized.
unsafe impl GlobalAlloc for KAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !self.is_initialized() { return ptr::null_mut(); }
        let mut g = self.inner.lock();
        if let Some(p) = g.alloc(layout) {
            return p.as_ptr();
        }
        // T16: hole-list couldn't satisfy. Try the grow hook.
        let raw = self.grow_hook.load(Ordering::Acquire);
        if raw == GROW_HOOK_NONE {
            return ptr::null_mut();
        }
        drop(g);
        // SAFETY: stored only via set_grow_hook from a `GrowFn`; the
        // round-trip cast restores the fn-pointer's ABI.
        let f: GrowFn = unsafe { core::mem::transmute(raw as usize) };
        // Ask for at least the layout, with align headroom, rounded up
        // to GROW_CHUNK_MIN so we don't thrash the PMM with tiny grows.
        let need = layout.size().saturating_add(layout.align()).max(GROW_CHUNK_MIN);
        let (addr, size) = match f(need) {
            Some(p) => p,
            None    => return ptr::null_mut(),
        };
        let mut g = self.inner.lock();
        // SAFETY: caller of the GrowFn (the kernel boot path) guarantees
        // exclusive ownership of [addr, addr + size); fully writable.
        unsafe { g.add_free_region(addr, size) };
        g.alloc(layout).map_or(ptr::null_mut(), |p| p.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() { return; }
        // SAFETY: caller-asserted that `ptr` was previously returned by
        // `alloc(layout)` and is no longer borrowed.
        let nn = unsafe { core::ptr::NonNull::new_unchecked(ptr) };
        let mut g = self.inner.lock();
        // SAFETY: same as above; routed through HoleList::dealloc which
        // re-inserts the region into the sorted hole list.
        unsafe { g.dealloc(nn, layout) };
    }
}

#[cfg(test)]
mod tests;
