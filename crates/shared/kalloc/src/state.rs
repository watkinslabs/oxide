// Allocator ownership state (`AllocState`), the `KAlloc` handle itself, its
// boot-time init / hook installation, and the IRQ-atomic guard every
// alloc/dealloc runs under.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sync::{KMalloc, Spinlock, MAX_CPUS};

use crate::holes::HoleList;
use crate::limits::{GROW_HOOK_NONE, NO_MEMCG_CONTEXT, STATIC_HEAP_SIZE};
use crate::sizeclass;
use crate::static_heap::STATIC_HEAP;
#[cfg(feature = "debug-heappoison")]
use crate::limits::VALIDATE_INTERVAL;
#[cfg(feature = "debug-dealloc-diag")]
use crate::limits::DIAG_VALIDATE_INTERVAL;
#[cfg(feature = "debug-heappoison")]
use crate::poison;
#[cfg(feature = "debug-dealloc-diag")]
use crate::size_track;

pub(crate) static GLOBAL_ALLOC: AtomicU64 = AtomicU64::new(0);

/// All mutable allocator ownership state. A block lives in exactly one of the
/// hole list (free), the quarantine (debug-held), or caller ownership (live).
pub(crate) struct AllocState {
    pub(crate) holes: HoleList,
    /// `kmalloc` size-class free lists (`sizeclass.rs`). Guarded by the same
    /// lock as `holes`: a refill moves a slab from one to the other, so the two
    /// must never be observed disagreeing about who owns a block.
    pub(crate) classes: sizeclass::SizeClasses,
    #[cfg(feature = "debug-heappoison")]
    pub(crate) quarantine: poison::Quar,
    /// Bounded live-allocation size ledger (`debug-dealloc-diag`) — see
    /// `size_track.rs`. Lives here so it's protected by the same lock as
    /// `holes`, with zero extra locking.
    #[cfg(feature = "debug-dealloc-diag")]
    pub(crate) size_track: size_track::SizeTrack,
}

impl AllocState {
    const fn new() -> Self {
        Self {
            holes: HoleList::new(),
            classes: sizeclass::SizeClasses::new(),
            #[cfg(feature = "debug-heappoison")]
            quarantine: poison::Quar::new(),
            #[cfg(feature = "debug-dealloc-diag")]
            size_track: size_track::SizeTrack::new(),
        }
    }
}

/// Heap allocator. Construct with `KAlloc::new()` (const), then call
/// `init` once at boot before any allocation.
pub struct KAlloc {
    pub(crate) inner: Spinlock<AllocState, KMalloc>,
    initialized: AtomicBool,
    pub(crate) grow_hook: AtomicU64,
    /// Arch IRQ save-and-disable hook (`fn() -> u64`, returns the prior flags).
    /// `0` = not installed → no-op (early boot runs IRQ-off already).
    irq_save: AtomicU64,
    /// Arch IRQ restore hook (`fn(u64)`). Paired with `irq_save`.
    irq_restore: AtomicU64,
    context_cpu: AtomicU64,
    pub(crate) contexts: [AtomicU64; MAX_CPUS],
    pub(crate) context_required: AtomicBool,
    /// Diagnostic (`debug-heappoison`) op counter: every `VALIDATE_INTERVAL`th
    /// alloc/dealloc runs a full free-list `validate()`. Per-execve checkpoints
    /// alone leave a wide window between "corruption happened" and "a syscall
    /// boundary noticed" — this tightens detection to within one interval of
    /// ops, at the cost of O(N) work every `VALIDATE_INTERVAL` calls.
    #[cfg(feature = "debug-heappoison")]
    pub(crate) validate_countdown: AtomicU64,
    /// B1347: dealloc-diag full-free-list validation countdown (see
    /// `periodic_validate_diag`).
    #[cfg(feature = "debug-dealloc-diag")]
    pub(crate) validate_countdown_diag: AtomicU64,
    /// B1347: address of the last-reported corrupt node, to dedup repeat logs
    /// of a not-yet-overwritten bad node.
    #[cfg(feature = "debug-dealloc-diag")]
    pub(crate) last_bad_diag: AtomicU64,
}

/// RAII: IRQs are disabled for the whole enclosing alloc/dealloc and restored
/// on drop (every return path). The kernel heap is shared with IRQ-context
/// allocators — the timer-ISR deferred-wake path pushes an `Arc<Task>` to a
/// per-CPU `Vec` that can realloc → `KAlloc::alloc` inside a hard IRQ. Under the
/// plain (non-IRQ) `Spinlock` that deadlocks (the ISR spins on the lock the
/// interrupted mainline holds) or, in the grow window, re-enters and races the
/// hole list. Disabling IRQs across the ENTIRE op (not just while the hole-list
/// lock is held — the grow path drops it to call the PMM) closes both.
pub(crate) struct IrqOff {
    restore: u64,
    flags: u64,
}
impl Drop for IrqOff {
    fn drop(&mut self) {
        if self.restore != 0 {
            // SAFETY: `restore` was stored from a `fn(u64)` via set_irq_gate;
            // `flags` is the value the paired save hook returned.
            let f: fn(u64) = unsafe { core::mem::transmute(self.restore as usize) };
            f(self.flags);
        }
    }
}

impl KAlloc {
    /// Construct an uninitialized allocator. `init` must be called
    /// before any `alloc` / `dealloc` reaches this instance.
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            inner: Spinlock::new(AllocState::new()),
            initialized: AtomicBool::new(false),
            grow_hook: AtomicU64::new(GROW_HOOK_NONE),
            irq_save: AtomicU64::new(0),
            irq_restore: AtomicU64::new(0),
            context_cpu: AtomicU64::new(0),
            contexts: [const { AtomicU64::new(NO_MEMCG_CONTEXT) }; MAX_CPUS],
            context_required: AtomicBool::new(false),
            #[cfg(feature = "debug-heappoison")]
            validate_countdown: AtomicU64::new(VALIDATE_INTERVAL),
            #[cfg(feature = "debug-dealloc-diag")]
            validate_countdown_diag: AtomicU64::new(DIAG_VALIDATE_INTERVAL),
            #[cfg(feature = "debug-dealloc-diag")]
            last_bad_diag: AtomicU64::new(0),
        }
    }

    /// Install the arch IRQ save-disable / restore hooks so `alloc`/`dealloc`
    /// run IRQ-atomic (see `IrqOff`). Called once at boot after IRQs exist.
    /// # C: O(1)
    pub fn set_irq_gate(&self, save: fn() -> u64, restore: fn(u64)) {
        self.irq_save.store(save as usize as u64, Ordering::Release);
        self.irq_restore.store(restore as usize as u64, Ordering::Release);
    }

    /// Install per-CPU identity accessor used by allocation scopes. # C: O(1)
    pub fn set_context_cpu_hook(&self, current_cpu: fn() -> u16) {
        self.context_cpu.store(current_cpu as usize as u64, Ordering::Release);
    }

    /// Publish this kernel-lifetime allocator as the sole context owner.
    /// # C: O(1)
    pub fn install_global(&'static self) { GLOBAL_ALLOC.store(self as *const Self as u64, Ordering::Release); }

    /// Reject post-init heap growth with no explicit allocation context.
    /// # C: O(1)
    pub fn require_context_for_growth(&self) { self.context_required.store(true, Ordering::Release); }

    /// Disable IRQs for the caller's scope (RAII); no-op until `set_irq_gate`.
    /// # C: O(1)
    #[inline]
    pub(crate) fn irq_off(&self) -> IrqOff {
        let s = self.irq_save.load(Ordering::Acquire);
        let r = self.irq_restore.load(Ordering::Acquire);
        if s == 0 || r == 0 { return IrqOff { restore: 0, flags: 0 }; }
        // SAFETY: `s` was stored from a `fn() -> u64` via set_irq_gate.
        let save: fn() -> u64 = unsafe { core::mem::transmute(s as usize) };
        IrqOff { restore: r, flags: save() }
    }

    /// CPU index the allocation-context slots are keyed by. # C: O(1)
    pub(crate) fn context_cpu(&self) -> usize {
        let raw = self.context_cpu.load(Ordering::Acquire);
        if raw == 0 { return 0; }
        // SAFETY: set_context_cpu_hook stores only this function-pointer ABI.
        let current: fn() -> u16 = unsafe { core::mem::transmute(raw as usize) };
        let cpu = current() as usize;
        assert!(cpu < MAX_CPUS, "kalloc context cpu out of range");
        cpu
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
        assert!(unsafe { g.holes.add_region(start, size) }.is_ok(), "kalloc init region invalid");
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
