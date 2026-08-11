//! Guaranteed reserve allocator for native request paths.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::null_mut;
use sync::{Modules as ModulesLockClass, Spinlock};

use crate::linux_alloc::{self, LinuxKmemCache};

type AllocFn = unsafe extern "C" fn(u32, *mut c_void) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void, *mut c_void);

struct PoolState { elements: Vec<usize> }

#[repr(C)]
struct LinuxMempool {
    min_nr: usize,
    alloc: Option<AllocFn>,
    free: Option<FreeFn>,
    pool_data: *mut c_void,
    state: Spinlock<PoolState, ModulesLockClass>,
}

/// Register reserve-pool allocation entry points.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("mempool_create_node_noprof", mempool_create_node_noprof as *const () as usize),
        ("mempool_alloc_noprof", mempool_alloc_noprof as *const () as usize),
        ("mempool_free", mempool_free as *const () as usize),
        ("mempool_destroy", mempool_destroy as *const () as usize),
        ("mempool_kmalloc", mempool_kmalloc as *const () as usize),
        ("mempool_kfree", mempool_kfree as *const () as usize),
        ("mempool_alloc_slab", mempool_alloc_slab as *const () as usize),
        ("mempool_free_slab", mempool_free_slab as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn mempool_create_node_noprof(min_nr: i32, alloc: Option<AllocFn>, free: Option<FreeFn>, pool_data: *mut c_void, flags: u32, _node: i32) -> *mut LinuxMempool {
    if min_nr < 0 || alloc.is_none() || free.is_none() { return null_mut(); }
    let mut pool = Box::new(LinuxMempool { min_nr: min_nr as usize, alloc, free, pool_data, state: Spinlock::new(PoolState { elements: Vec::new() }) });
    for _ in 0..pool.min_nr {
        // SAFETY: pool creation received the module's allocation callback and its opaque pool_data.
        let element = unsafe { pool.alloc.unwrap()(flags, pool.pool_data) };
        if element.is_null() {
            release_pool(&mut pool);
            return null_mut();
        }
        pool.state.lock().elements.push(element as usize);
    }
    Box::into_raw(pool)
}

extern "C" fn mempool_alloc_noprof(pool: *mut LinuxMempool, flags: u32) -> *mut c_void {
    if pool.is_null() { return null_mut(); }
    // SAFETY: pool is a live pointer returned by mempool_create_node_noprof until mempool_destroy.
    let pool = unsafe { &*pool };
    if let Some(alloc) = pool.alloc {
        // SAFETY: allocation callback and opaque data belong to this still-live pool.
        let element = unsafe { alloc(flags, pool.pool_data) };
        if !element.is_null() { return element; }
    }
    pool.state.lock().elements.pop().map_or(null_mut(), |element| element as *mut c_void)
}

extern "C" fn mempool_free(element: *mut c_void, pool: *mut LinuxMempool) {
    if element.is_null() || pool.is_null() { return; }
    // SAFETY: pool is a live pointer returned by mempool_create_node_noprof until mempool_destroy.
    let pool = unsafe { &*pool };
    let retained = {
        let mut state = pool.state.lock();
        if state.elements.len() >= pool.min_nr { false } else { state.elements.push(element as usize); true }
    };
    if !retained {
        // SAFETY: this element came from the pool's allocation callback and is excess to the reserve.
        unsafe { pool.free.unwrap()(element, pool.pool_data); }
    }
}

extern "C" fn mempool_destroy(pool: *mut LinuxMempool) {
    if pool.is_null() { return; }
    // SAFETY: destroy consumes the unique allocation returned by mempool_create_node_noprof.
    let mut pool = unsafe { Box::from_raw(pool) };
    release_pool(&mut pool);
}

extern "C" fn mempool_kmalloc(flags: u32, pool_data: *mut c_void) -> *mut c_void {
    linux_alloc::alloc_bytes(pool_data as usize, core::mem::align_of::<usize>(), flags & 0x8000 != 0).cast()
}

extern "C" fn mempool_kfree(element: *mut c_void, _pool_data: *mut c_void) {
    // SAFETY: mempool_kfree is paired with mempool_kmalloc's allocator surface.
    unsafe { linux_alloc::free_bytes(element.cast()); }
}

extern "C" fn mempool_alloc_slab(flags: u32, pool_data: *mut c_void) -> *mut c_void {
    crate::linux_alloc::cache::kmem_cache_alloc_noprof(pool_data.cast::<LinuxKmemCache>(), flags).cast()
}

extern "C" fn mempool_free_slab(element: *mut c_void, pool_data: *mut c_void) {
    crate::linux_alloc::cache::kmem_cache_free(pool_data.cast::<LinuxKmemCache>(), element);
}

fn release_pool(pool: &mut LinuxMempool) {
    let elements = core::mem::take(&mut pool.state.lock().elements);
    for element in elements {
        // SAFETY: every retained element came from this pool's creation/allocation callback.
        unsafe { pool.free.unwrap()(element as *mut c_void, pool.pool_data); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static ALLOCS: AtomicUsize = AtomicUsize::new(0);
    static FREES: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn alloc(_flags: u32, _data: *mut c_void) -> *mut c_void {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        linux_alloc::alloc_bytes(16, 8, false).cast()
    }
    unsafe extern "C" fn free(element: *mut c_void, _data: *mut c_void) {
        FREES.fetch_add(1, Ordering::Relaxed);
        // SAFETY: test alloc returned this block through linux_alloc::alloc_bytes.
        unsafe { linux_alloc::free_bytes(element.cast()); }
    }

    #[test]
    fn reserve_is_preallocated_then_refilled_before_excess_is_freed() {
        let _modules = crate::test_serial::claim();
        ALLOCS.store(0, Ordering::Relaxed); FREES.store(0, Ordering::Relaxed);
        let pool = mempool_create_node_noprof(2, Some(alloc), Some(free), null_mut(), 0, 0);
        assert!(!pool.is_null()); assert_eq!(ALLOCS.load(Ordering::Relaxed), 2);
        let first = mempool_alloc_noprof(pool, 0); assert!(!first.is_null());
        mempool_free(first, pool);
        mempool_destroy(pool);
        assert_eq!(FREES.load(Ordering::Relaxed), ALLOCS.load(Ordering::Relaxed));
    }
}
