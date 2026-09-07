//! Release: header validation, neighbour coalescing, empty-region release.

use crate::backend::HeapBackend;
use crate::flags::*;
use crate::heap::Heap;
use crate::layout::Header;
use crate::limits::*;

impl Heap {
    /// Read and validate the header of an allocated block at `ptr`.
    /// # C: O(log N_regions)
    pub(crate) fn used_block<B: HeapBackend>(&self, backend: &B, ptr: u64) -> Option<(usize, u64, Header)> {
        if ptr < HEADER_BYTES as u64 || ptr % BLOCK_ALIGN as u64 != 0 { return None; }
        let addr = ptr - HEADER_BYTES as u64;
        let mut bytes = [0u8; 8];
        if !backend.read(addr, &mut bytes) { return None; }
        let header = Header::decode(bytes);
        if header.kind == BLOCK_TYPE_LARGE && header.flags & BLOCK_FLAG_LARGE != 0 {
            let index = self.large_of(addr)?;
            return Some((index, addr, header));
        }
        if header.kind != BLOCK_TYPE_USED || header.flags & BLOCK_FLAG_FREE != 0 { return None; }
        let index = self.region_of(addr)?;
        let region = self.subheaps[index];
        if region.id != header.region { return None; }
        if header.block_size < MIN_BLOCK_BYTES || header.block_size % BLOCK_ALIGN != 0 { return None; }
        if addr + header.block_size as u64 > region.base + region.committed as u64 { return None; }
        if header.tail + HEADER_BYTES > header.block_size { return None; }
        Some((index, addr, header))
    }

    /// Index of the large block whose header sits at `addr`.
    /// # C: O(log N_large)
    pub(crate) fn large_of(&self, addr: u64) -> Option<usize> {
        let base = addr.checked_sub(SUBHEAP_OVERHEAD as u64)?;
        self.large.binary_search_by_key(&base, |block| block.base).ok()
    }

    /// Return one allocation to the heap.
    /// # C: O(log N_free), address-space work only on an emptied region
    pub fn free<B: HeapBackend>(&mut self, backend: &mut B, ptr: u64) -> bool {
        if ptr == 0 { return true; }
        let Some((index, addr, header)) = self.used_block(backend, ptr) else { return false; };
        self.move_user_info(ptr, None);
        if header.flags & BLOCK_FLAG_LARGE != 0 {
            let block = self.large.remove(index);
            return backend.release(block.base, block.mapping);
        }
        self.free_block(backend, index, addr, header.block_size)
    }

    /// Coalesce a block with free neighbours and re-index or release it.
    /// # C: O(log N_free)
    pub(crate) fn free_block<B: HeapBackend>(&mut self, backend: &mut B, index: usize, addr: u64, block_size: usize) -> bool {
        let region = self.subheaps[index];
        let (mut addr, mut block_size) = (addr, block_size);
        if let Some(&next_size) = self.free_by_addr.get(&(addr + block_size as u64)) {
            if self.region_of(addr + block_size as u64) == Some(index) {
                self.remove_free(addr + block_size as u64);
                block_size += next_size;
            }
        }
        if let Some((&prev_addr, &prev_size)) = self.free_by_addr.range(..addr).next_back() {
            if prev_addr + prev_size as u64 == addr && self.region_of(prev_addr) == Some(index) {
                self.remove_free(prev_addr);
                addr = prev_addr;
                block_size += prev_size;
            }
        }
        let whole = addr == region.base + SUBHEAP_OVERHEAD as u64 && block_size == region.body();
        if whole && !region.primary {
            self.subheaps.remove(index);
            return backend.release(region.base, region.reserved);
        }
        self.insert_free(backend, index, addr, block_size)
    }
}
