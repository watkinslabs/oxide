// Lazy allocation of a task's debug-register shadow.
//
// The state is NOT stored inline in `Task`. x86's shadow is six words and
// aarch64's is a 32-slot register file — hundreds of bytes that every task
// would carry so the vanishingly rare traced one can use them. `Task` is
// constructed on the boot stack, and the deepest aarch64 syscall path runs
// within single-digit bytes of the stack ceiling, so inline state there is a
// stack-budget regression, not just wasted memory.
//
// So a task holds ONE pointer, null until something actually arms a
// breakpoint. Reads of an unarmed task never touch memory beyond that pointer
// and answer from the architectural reset value.

use core::sync::atomic::{AtomicPtr, Ordering};

use alloc::boxed::Box;

/// A task's debug-register shadow slot: null until first use.
///
/// Publishing is a `compare_exchange`, so two racing arms cannot leak the
/// loser's allocation, and the pointer only ever transitions null -> live ->
/// (freed at task teardown). Nothing reads it after `free`.
pub struct Lazy<T> { ptr: AtomicPtr<T> }

impl<T> Lazy<T> {
    /// Empty slot — no allocation. # C: O(1)
    pub const fn new() -> Self { Self { ptr: AtomicPtr::new(core::ptr::null_mut()) } }

    /// The live state, or `None` when this task never armed anything. # C: O(1)
    pub fn get(&self) -> Option<&T> {
        let p = self.ptr.load(Ordering::Acquire);
        // SAFETY: a non-null `ptr` was published by `get_or_init` from `Box::into_raw` and is freed only by `free` at task teardown, after which nothing reads it; the borrow cannot outlive `&self`.
        if p.is_null() { None } else { Some(unsafe { &*p }) }
    }

    /// The live state, allocating the default on first use. `None` only when
    /// the allocation itself failed, which a caller reports as ENOMEM rather
    /// than pretending the breakpoint was installed.
    /// # C: O(1)
    pub fn get_or_init(&self) -> Option<&T> where T: Default {
        if let Some(v) = self.get() { return Some(v); }
        let raw = Box::into_raw(Box::new(T::default()));
        match self.ptr.compare_exchange(core::ptr::null_mut(), raw,
                                        Ordering::AcqRel, Ordering::Acquire) {
            // SAFETY: `raw` was just published by this thread's successful CAS and is freed only at task teardown.
            Ok(_) => Some(unsafe { &*raw }),
            Err(winner) => {
                // Another arm won the race; reclaim ours rather than leak it.
                // SAFETY: `raw` came from `Box::into_raw` above and lost the CAS, so it was never published and no one else can hold it.
                drop(unsafe { Box::from_raw(raw) });
                // SAFETY: `winner` is the pointer the winning CAS published, live until task teardown.
                Some(unsafe { &*winner })
            }
        }
    }

    /// Release the allocation. Called once, from `Task::drop`, when no other
    /// reference to this task exists.
    /// # C: O(1)
    pub fn free(&self) {
        let p = self.ptr.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if p.is_null() { return; }
        // SAFETY: `p` came from `Box::into_raw` in `get_or_init`; the swap claimed it exactly once, and `Task::drop` runs with no other reference to this task alive.
        drop(unsafe { Box::from_raw(p) });
    }
}

impl<T> Default for Lazy<T> {
    fn default() -> Self { Self::new() }
}

// SAFETY: the pointer is only published by an atomic CAS and only reclaimed at
// task teardown; `T` itself carries whatever interior mutability its own
// fields declare, so sharing `&Lazy<T>` across threads is exactly as sound as
// sharing `&T`.
unsafe impl<T: Send + Sync> Sync for Lazy<T> {}
// SAFETY: ownership of the allocation moves with the `Lazy`, and `T: Send` is
// required for the boxed value to cross threads with it.
unsafe impl<T: Send> Send for Lazy<T> {}

#[cfg(test)]
#[path = "slab/tests.rs"] mod tests;
