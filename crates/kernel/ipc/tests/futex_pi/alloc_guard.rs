use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

use std::alloc::System;

static VIOLATIONS: AtomicUsize = AtomicUsize::new(0);

pub struct PiCheckedAllocator;

fn record() {
    if crate::futex_pi::pi::state::pi_table_held_for_test() {
        VIOLATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

// SAFETY: every operation delegates unchanged pointer/layout arguments to the
// process System allocator; the wrapper adds only lock-state observation.
unsafe impl GlobalAlloc for PiCheckedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record();
        // SAFETY: caller supplies the GlobalAlloc layout contract unchanged.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record();
        // SAFETY: caller supplies the GlobalAlloc layout contract unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record();
        // SAFETY: pointer and layout came from this delegated System allocator.
        unsafe { System.dealloc(ptr, layout); }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record();
        // SAFETY: pointer/layout provenance is System and size is forwarded unchanged.
        unsafe { System.realloc(ptr, layout, size) }
    }
}

pub fn reset() { VIOLATIONS.store(0, Ordering::SeqCst); }
pub fn violations() -> usize { VIOLATIONS.load(Ordering::SeqCst) }
