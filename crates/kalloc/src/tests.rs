// Hosted unit tests: each test instantiates a fresh `KAlloc` over its
// own `Vec<u8>` buffer, exercises `GlobalAlloc`, and verifies pointer
// alignment, reuse after free, OOM, and coalescing.

use super::*;
use core::alloc::Layout;
use std::boxed::Box;
use std::vec;
use std::vec::Vec;

/// Allocate `size` bytes of u8-aligned scratch space, returning the
/// raw start address. Pointer is into the test's own heap-allocated
/// `Vec<u8>` and lives for the scope of the test.
fn fresh_heap(size: usize) -> (Box<[u8]>, KAlloc) {
    let buf: Vec<u8> = vec![0u8; size];
    let mut buf = buf.into_boxed_slice();
    let ka = KAlloc::new();
    let start = buf.as_mut_ptr() as usize;
    // SAFETY: we own `buf` for the lifetime of the test; nothing else
    // will read or write the region until `KAlloc` is dropped here.
    unsafe { ka.init(start, size) };
    (buf, ka)
}

fn layout(size: usize, align: usize) -> Layout {
    Layout::from_size_align(size, align).unwrap()
}

#[test]
fn init_then_alloc_returns_aligned() {
    let (_buf, ka) = fresh_heap(64 * 1024);
    let l = layout(128, 64);
    // SAFETY: layout valid; ka initialized.
    let p = unsafe { ka.alloc(l) };
    assert!(!p.is_null());
    assert_eq!(p as usize % 64, 0);
    // SAFETY: just allocated above with the same layout.
    unsafe { ka.dealloc(p, l) };
}

#[test]
fn alloc_before_init_returns_null() {
    let ka = KAlloc::new();
    let l = layout(16, 8);
    // SAFETY: layout valid; ka uninitialized so returns null.
    let p = unsafe { ka.alloc(l) };
    assert!(p.is_null());
}

#[test]
fn dealloc_then_realloc_reuses_region() {
    let (_buf, ka) = fresh_heap(64 * 1024);
    let l = layout(256, 16);
    // SAFETY: valid layout, initialized allocator.
    let p1 = unsafe { ka.alloc(l) };
    assert!(!p1.is_null());
    // SAFETY: just allocated.
    unsafe { ka.dealloc(p1, l) };
    // SAFETY: valid layout.
    let p2 = unsafe { ka.alloc(l) };
    assert!(!p2.is_null());
    assert_eq!(p1, p2, "first-fit must reuse the freed region");
    // SAFETY: just allocated.
    unsafe { ka.dealloc(p2, l) };
}

#[test]
fn many_small_allocs_then_free_all_then_one_big() {
    let (_buf, ka) = fresh_heap(64 * 1024);
    let small = layout(64, 8);
    let mut ptrs: Vec<*mut u8> = Vec::new();
    // Fill heap with small allocations.
    loop {
        // SAFETY: valid small layout.
        let p = unsafe { ka.alloc(small) };
        if p.is_null() { break; }
        ptrs.push(p);
    }
    assert!(ptrs.len() > 100, "expected many small allocations to fit");

    // Free in reverse order.
    while let Some(p) = ptrs.pop() {
        // SAFETY: every ptr came from `alloc(small)`.
        unsafe { ka.dealloc(p, small) };
    }

    // After full free + coalesce, a single big allocation should fit.
    let big = layout(32 * 1024, 64);
    // SAFETY: valid big layout.
    let p = unsafe { ka.alloc(big) };
    assert!(!p.is_null(), "coalescing must restore one large hole");
    // SAFETY: just allocated.
    unsafe { ka.dealloc(p, big) };
}

#[test]
fn oom_when_request_exceeds_heap() {
    let (_buf, ka) = fresh_heap(8 * 1024);
    let too_big = layout(64 * 1024, 8);
    // SAFETY: valid layout.
    let p = unsafe { ka.alloc(too_big) };
    assert!(p.is_null());
}

#[test]
fn oom_after_exhausting_heap_then_recovers_after_free() {
    let (_buf, ka) = fresh_heap(8 * 1024);
    let l = layout(1024, 8);
    let mut ptrs: Vec<*mut u8> = Vec::new();
    loop {
        // SAFETY: valid layout.
        let p = unsafe { ka.alloc(l) };
        if p.is_null() { break; }
        ptrs.push(p);
    }
    // SAFETY: valid layout, all heap exhausted.
    let p = unsafe { ka.alloc(l) };
    assert!(p.is_null());
    // Free one.
    let freed = ptrs.pop().unwrap();
    // SAFETY: came from alloc above.
    unsafe { ka.dealloc(freed, l) };
    // Now next alloc succeeds.
    // SAFETY: valid layout.
    let p2 = unsafe { ka.alloc(l) };
    assert!(!p2.is_null());

    // Cleanup.
    // SAFETY: came from alloc above.
    unsafe { ka.dealloc(p2, l) };
    while let Some(p) = ptrs.pop() {
        // SAFETY: each came from alloc.
        unsafe { ka.dealloc(p, l) };
    }
}

#[test]
fn high_alignment_request_satisfied() {
    let (_buf, ka) = fresh_heap(64 * 1024);
    for align_log2 in 3..=12u32 {
        let align = 1usize << align_log2;
        let l = layout(64, align);
        // SAFETY: valid layout.
        let p = unsafe { ka.alloc(l) };
        assert!(!p.is_null(), "alloc failed at align {align}");
        assert_eq!(p as usize % align, 0, "ptr {p:?} not aligned to {align}");
        // SAFETY: just allocated.
        unsafe { ka.dealloc(p, l) };
    }
}

#[test]
fn interleaved_alloc_free_pattern() {
    // Stress: deterministic pseudo-random alloc/free pattern. After the
    // run, freeing every outstanding ptr must leave the heap usable for
    // one big allocation (= coalescing works under churn).
    let (_buf, ka) = fresh_heap(128 * 1024);
    let mut state: u64 = 0xfeed_face_cafe_babe;
    let mut live: Vec<(*mut u8, Layout)> = Vec::new();
    for _ in 0..2000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let action = state & 1;
        let size = (((state >> 4) & 0x1ff) + 8) as usize; // 8..520
        let align_log2 = ((state >> 16) & 3) as u32 + 3;  // 8..64
        let align = 1usize << align_log2;
        let l = layout(size, align);
        if action == 0 || live.is_empty() {
            // SAFETY: valid layout.
            let p = unsafe { ka.alloc(l) };
            if !p.is_null() {
                assert_eq!(p as usize % align, 0);
                live.push((p, l));
            }
        } else {
            let idx = ((state >> 32) as usize) % live.len();
            let (p, l_old) = live.swap_remove(idx);
            // SAFETY: came from alloc with l_old.
            unsafe { ka.dealloc(p, l_old) };
        }
    }
    // Drain remaining.
    while let Some((p, l_old)) = live.pop() {
        // SAFETY: came from alloc.
        unsafe { ka.dealloc(p, l_old) };
    }
    // Whole heap should be reclaimable.
    let big = layout(96 * 1024, 64);
    // SAFETY: valid layout.
    let p = unsafe { ka.alloc(big) };
    assert!(!p.is_null(), "coalescing failed under churn");
    // SAFETY: just allocated.
    unsafe { ka.dealloc(p, big) };
}

#[test]
fn writes_to_allocated_memory_dont_clobber_others() {
    // Two simultaneous live allocations; writing to one must not
    // overlap the other.
    let (_buf, ka) = fresh_heap(16 * 1024);
    let l = layout(256, 16);
    // SAFETY: valid layout, initialized.
    let p1 = unsafe { ka.alloc(l) };
    let p2 = unsafe { ka.alloc(l) };
    assert!(!p1.is_null() && !p2.is_null());
    assert_ne!(p1, p2);
    // SAFETY: pointers from alloc; layout::size = 256 each, distinct
    // regions.
    unsafe {
        core::ptr::write_bytes(p1, 0xAA, 256);
        core::ptr::write_bytes(p2, 0x55, 256);
    }
    // SAFETY: just wrote AA / 55 above; reading back.
    unsafe {
        for i in 0..256 {
            assert_eq!(*p1.add(i), 0xAA);
            assert_eq!(*p2.add(i), 0x55);
        }
        ka.dealloc(p1, l);
        ka.dealloc(p2, l);
    }
}
