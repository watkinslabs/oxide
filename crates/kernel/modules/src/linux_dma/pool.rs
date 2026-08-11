//! Coherent DMA object pools with alignment and boundary guarantees.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;
use sync::{Modules as ModulesLockClass, Spinlock};

use super::{dma_alloc_coherent, dma_free_coherent, LinuxDevice};

struct Block { raw: *mut c_void, raw_dma: u64, ptr: *mut c_void, dma: u64 }
struct State { free: Vec<Block>, active: Vec<Block> }

#[repr(C)]
pub(super) struct DmaPool {
    dev: *mut LinuxDevice,
    size: usize,
    align: usize,
    boundary: usize,
    allocation: usize,
    state: Spinlock<State, ModulesLockClass>,
}

pub(super) extern "C" fn dma_pool_create_node(_name: *const c_char, dev: *mut LinuxDevice, size: usize, align: usize, boundary: usize, _node: i32) -> *mut DmaPool {
    if size == 0 || !align.is_power_of_two() || (boundary != 0 && (!boundary.is_power_of_two() || size > boundary)) { return null_mut(); }
    let align = align.max(core::mem::align_of::<usize>());
    let allocation = match size.checked_add(align).and_then(|v| v.checked_add(boundary)) { Some(v) => v, None => return null_mut() };
    Box::into_raw(Box::new(DmaPool { dev, size, align, boundary, allocation, state: Spinlock::new(State { free: Vec::new(), active: Vec::new() }) }))
}

pub(super) extern "C" fn dma_pool_alloc(pool: *mut DmaPool, flags: u32, handle: *mut u64) -> *mut c_void {
    if pool.is_null() || handle.is_null() { return null_mut(); }
    // SAFETY: pool is live until dma_pool_destroy and handle is a non-null caller out pointer.
    let pool = unsafe { &*pool };
    if let Some(block) = pool.state.lock().free.pop() {
        // SAFETY: handle is writable by the caller and records this reused coherent DMA address.
        unsafe { *handle = block.dma; }
        let ptr = block.ptr;
        pool.state.lock().active.push(block);
        return ptr;
    }
    let mut raw_dma = 0u64;
    let raw = dma_alloc_coherent(pool.dev, pool.allocation, &mut raw_dma, flags as u64);
    if raw.is_null() { return null_mut(); }
    let (ptr, dma) = match aligned_block(raw, raw_dma, pool.size, pool.align, pool.boundary) {
        Some(v) => v,
        None => { dma_free_coherent(pool.dev, pool.allocation, raw, raw_dma); return null_mut(); }
    };
    // SAFETY: handle is writable by the caller and dma corresponds exactly to ptr's coherent subrange.
    unsafe { *handle = dma; }
    pool.state.lock().active.push(Block { raw, raw_dma, ptr, dma });
    ptr
}

pub(super) extern "C" fn dma_pool_free(pool: *mut DmaPool, ptr: *mut c_void, dma: u64) {
    if pool.is_null() || ptr.is_null() { return; }
    // SAFETY: pool is live until dma_pool_destroy; each caller returns exactly one block it obtained from this pool.
    let pool = unsafe { &*pool };
    let mut state = pool.state.lock();
    let Some(index) = state.active.iter().position(|block| block.ptr == ptr && block.dma == dma) else { return; };
    let block = state.active.swap_remove(index);
    state.free.push(block);
}

pub(super) extern "C" fn dma_pool_destroy(pool: *mut DmaPool) {
    if pool.is_null() { return; }
    // SAFETY: destroy consumes the unique pool allocation after all caller blocks were returned.
    let pool = unsafe { Box::from_raw(pool) };
    let mut state = pool.state.lock();
    let mut blocks = core::mem::take(&mut state.free);
    blocks.append(&mut state.active);
    drop(state);
    for block in blocks { dma_free_coherent(pool.dev, pool.allocation, block.raw, block.raw_dma); }
}

fn aligned_block(raw: *mut c_void, raw_dma: u64, size: usize, align: usize, boundary: usize) -> Option<(*mut c_void, u64)> {
    let base = raw_dma.checked_add((align - 1) as u64)? & !(align as u64 - 1);
    let dma = if boundary != 0 && base % boundary as u64 + size as u64 > boundary as u64 {
        base.checked_add(boundary as u64 - 1)? & !(boundary as u64 - 1)
    } else { base };
    let offset = dma.checked_sub(raw_dma)? as usize;
    Some((raw.cast::<u8>().wrapping_add(offset).cast(), dma))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_returns_aligned_non_crossing_coherent_blocks() {
        let _modules = crate::test_serial::claim();
        let pool = dma_pool_create_node(core::ptr::null(), null_mut(), 96, 64, 256, 0);
        assert!(!pool.is_null());
        let mut dma = 0; let ptr = dma_pool_alloc(pool, 0, &mut dma);
        assert!(!ptr.is_null()); assert_eq!(dma & 63, 0); assert!(dma % 256 + 96 <= 256);
        let mut second_dma = 0; let second = dma_pool_alloc(pool, 0, &mut second_dma);
        assert!(!second.is_null()); assert_ne!(ptr, second);
        dma_pool_free(pool, ptr, dma); dma_pool_free(pool, second, second_dma);
        dma_pool_destroy(pool);
    }
}
