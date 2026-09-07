//! Allocation: free-block search, split, region growth, large blocks.

use crate::backend::HeapBackend;
use crate::flags::*;
use crate::heap::{Heap, Large, UserInfo};
use crate::layout::{Header, LARGE_REGION};
use crate::limits::*;

impl Heap {
    /// Serve `size` user bytes, growing the heap when no free block fits.
    /// # C: O(log N_free), amortised no address-space work
    pub fn allocate<B: HeapBackend>(&mut self, backend: &mut B, flags: u32, size: usize) -> Option<u64> {
        let block_size = block_size_for(size)?;
        if block_size >= MIN_LARGE_BLOCK_BYTES { return self.allocate_large(backend, flags, size); }
        let (index, addr, found) = self.find_free_block(backend, block_size)?;
        let ptr = self.carve(backend, index, addr, found, block_size, size, flags)?;
        self.note_user_info(ptr, flags);
        Some(ptr)
    }

    /// Take the smallest free block that fits, else reserve a new region.
    /// # C: O(log N_free)
    pub(crate) fn find_free_block<B: HeapBackend>(&mut self, backend: &mut B, block_size: usize) -> Option<(usize, u64, usize)> {
        if let Some(&(found, addr)) = self.free_by_size.range((block_size, 0)..).next() {
            let index = self.region_of(addr)?;
            if self.commit_through(backend, index, addr + (block_size + MIN_BLOCK_BYTES) as u64) {
                self.remove_free(addr);
                return Some((index, addr, found));
            }
        }
        let need = SUBHEAP_OVERHEAD + block_size + MIN_BLOCK_BYTES;
        let index = self.grow(backend, need)?;
        let addr = self.subheaps[index].base + SUBHEAP_OVERHEAD as u64;
        if !self.commit_through(backend, index, addr + (block_size + MIN_BLOCK_BYTES) as u64) { return None; }
        let found = self.remove_free(addr)?;
        Some((index, addr, found))
    }

    /// Split a taken free block, publish the used header, honour the flags.
    /// # C: O(log N_free)
    pub(crate) fn carve<B: HeapBackend>(&mut self, backend: &mut B, index: usize, addr: u64,
        found: usize, block_size: usize, size: usize, flags: u32) -> Option<u64> {
        let block_size = if found >= block_size + MIN_BLOCK_BYTES {
            if !self.insert_free(backend, index, addr + block_size as u64, found - block_size) { return None; }
            block_size
        } else { found };
        let region = self.subheaps[index].id;
        // User flags live in the heap's own user records, so an allocated
        // block's flag byte carries only the free/large bits it does not have.
        let header = Header { block_size, tail: block_size - HEADER_BYTES - size, region, kind: BLOCK_TYPE_USED, flags: 0 };
        if !backend.write(addr, &header.encode()) { return None; }
        let ptr = addr + HEADER_BYTES as u64;
        if flags & HEAP_ZERO_MEMORY != 0 && !backend.fill(ptr, size, 0) { return None; }
        Some(ptr)
    }

    /// Give an allocation its own reservation once it outgrows a block header.
    /// # C: O(N_large) plus one reserve and one commit
    pub(crate) fn allocate_large<B: HeapBackend>(&mut self, backend: &mut B, flags: u32, size: usize) -> Option<u64> {
        let mapping = round_up(SUBHEAP_OVERHEAD.checked_add(size)?, REGION_ALIGN);
        let base = backend.reserve(mapping)?;
        if !backend.commit(base, mapping) { backend.release(base, mapping); return None; }
        let addr = base + SUBHEAP_OVERHEAD as u64;
        let header = Header { block_size: 0, tail: 0, region: LARGE_REGION, kind: BLOCK_TYPE_LARGE, flags: BLOCK_FLAG_LARGE };
        if !backend.write(addr, &header.encode()) { backend.release(base, mapping); return None; }
        let ptr = addr + HEADER_BYTES as u64;
        let index = self.large.partition_point(|block| block.base < base);
        self.large.insert(index, Large { base, mapping, data_size: size });
        // Fresh reservations arrive zeroed, so `HEAP_ZERO_MEMORY` costs nothing.
        self.note_user_info(ptr, flags);
        Some(ptr)
    }

    /// Open a user record when the allocation asked for one.
    /// # C: O(1)
    pub(crate) fn note_user_info(&mut self, ptr: u64, flags: u32) {
        if flags & HEAP_ADD_USER_INFO == 0 { return; }
        self.user_info.push(UserInfo { ptr, flags: flags & HEAP_USER_FLAGS_MASK, value: 0 });
    }
}
