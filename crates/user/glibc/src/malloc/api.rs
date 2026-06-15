// malloc C ABI + Rust #[global_allocator] (docs/59§6 G5). Freestanding
// only; thin wrappers over the heap algorithm in `super::heap`.
#![cfg(feature = "freestanding")]
use super::heap;
use core::alloc::{GlobalAlloc, Layout};

const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;

// # C: void *malloc(size_t size)
#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut u8 {
    // SAFETY: heap::malloc has no precondition beyond the size argument.
    unsafe { heap::malloc(size) }
}
// # C: void free(void *ptr)
#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut u8) {
    // SAFETY: ptr is null or was returned by this allocator (C free rule).
    unsafe { heap::free(ptr) }
}
// # C: void *calloc(size_t n, size_t size)
#[no_mangle]
pub unsafe extern "C" fn calloc(n: usize, size: usize) -> *mut u8 {
    // SAFETY: heap::calloc validates the n*size overflow itself.
    unsafe { heap::calloc(n, size) }
}
// # C: void *realloc(void *ptr, size_t size)
#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut u8, size: usize) -> *mut u8 {
    // SAFETY: ptr is null or allocator-owned (C realloc rule).
    unsafe { heap::realloc(ptr, size) }
}
// # C: void *aligned_alloc(size_t align, size_t size)
#[no_mangle]
pub unsafe extern "C" fn aligned_alloc(align: usize, size: usize) -> *mut u8 {
    // SAFETY: align is a power of two (C11 contract); heap::aligned handles it.
    unsafe { heap::aligned(align, size) }
}
// # C: void *memalign(size_t align, size_t size)
#[no_mangle]
pub unsafe extern "C" fn memalign(align: usize, size: usize) -> *mut u8 {
    // SAFETY: legacy alias of aligned_alloc; same contract.
    unsafe { heap::aligned(align, size) }
}
// # C: int posix_memalign(void **memptr, size_t align, size_t size)
#[no_mangle]
pub unsafe extern "C" fn posix_memalign(memptr: *mut *mut u8, align: usize, size: usize) -> i32 {
    if align < core::mem::size_of::<usize>() || !align.is_power_of_two() { return EINVAL; }
    // SAFETY: memptr is a valid writable pointer per the C contract.
    unsafe {
        let p = heap::aligned(align, size);
        if p.is_null() { return ENOMEM; }
        *memptr = p;
    }
    0
}
// # C: size_t malloc_usable_size(void *ptr)
#[no_mangle]
pub unsafe extern "C" fn malloc_usable_size(ptr: *mut u8) -> usize {
    // SAFETY: ptr is null or allocator-owned.
    unsafe { heap::usable_size(ptr) }
}

// Rust global allocator (serves the crate's own alloc/Vec/Box in the
// shipped libc). Routes through the same heap.
struct OxideAlloc;
unsafe impl GlobalAlloc for OxideAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // SAFETY: heap::aligned honours the layout's size + power-of-two align.
        unsafe { heap::aligned(l.align(), l.size()) }
    }
    unsafe fn dealloc(&self, p: *mut u8, _l: Layout) {
        // SAFETY: p came from this allocator's alloc with the same layout.
        unsafe { heap::free(p) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, ns: usize) -> *mut u8 {
        // SAFETY: p is from a prior alloc(l); for ≤16 align the in-place
        // path applies, else we move with explicit copy honouring align.
        unsafe {
            if l.align() <= 16 { return heap::realloc(p, ns); }
            let np = heap::aligned(l.align(), ns);
            if np.is_null() { return np; }
            core::ptr::copy_nonoverlapping(p, np, l.size().min(ns));
            heap::free(p);
            np
        }
    }
}
#[global_allocator]
static GLOBAL_ALLOC: OxideAlloc = OxideAlloc;
