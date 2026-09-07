//! Resize: in-place shrink, growth into a free neighbour, else move and copy.

use crate::backend::HeapBackend;
use crate::flags::*;
use crate::heap::Heap;
use crate::layout::Header;
use crate::limits::*;

/// Bounce-buffer bytes used when a resize has to move the body.
const COPY_CHUNK: usize = 512;

impl Heap {
    /// Resize one allocation, preferring the block it already occupies.
    /// # C: O(log N_free), plus O(size) when the body has to move
    pub fn reallocate<B: HeapBackend>(&mut self, backend: &mut B, flags: u32, ptr: u64, size: usize) -> Option<u64> {
        let block_size = block_size_for(size)?;
        let (index, addr, header) = self.used_block(backend, ptr)?;
        let old_size = if header.flags & BLOCK_FLAG_LARGE != 0 { self.large[index].data_size } else { header.user_size() };
        if self.resize_in_place(backend, flags, index, addr, header, block_size, size, old_size) { return Some(ptr); }
        if flags & HEAP_REALLOC_IN_PLACE_ONLY != 0 { return None; }
        let moved = self.allocate(backend, flags, size)?;
        if !self.copy_body(backend, ptr, moved, old_size.min(size)) { self.free(backend, moved); return None; }
        let user = self.user_info.iter().find(|entry| entry.ptr == ptr).map(|entry| (entry.flags, entry.value));
        self.free(backend, ptr);
        if let Some((user_flags, value)) = user {
            self.user_info.retain(|entry| entry.ptr != moved);
            self.user_info.push(crate::heap::UserInfo { ptr: moved, flags: user_flags, value });
        }
        Some(moved)
    }

    /// Keep the allocation where it is when the block can serve the new size.
    /// # C: O(log N_free)
    fn resize_in_place<B: HeapBackend>(&mut self, backend: &mut B, flags: u32, index: usize, addr: u64,
        header: Header, block_size: usize, size: usize, old_size: usize) -> bool {
        if header.flags & BLOCK_FLAG_LARGE != 0 {
            let block = self.large[index];
            if size > block.mapping - SUBHEAP_OVERHEAD - HEADER_BYTES { return false; }
            self.large[index].data_size = size;
            return self.zero_growth(backend, flags, addr + HEADER_BYTES as u64, old_size, size);
        }
        if block_size >= MIN_LARGE_BLOCK_BYTES { return false; }
        let mut total = header.block_size;
        let next = addr + total as u64;
        let neighbour = self.free_by_addr.get(&next).copied().filter(|_| self.region_of(next) == Some(index));
        if block_size > total {
            // Growth needs the next block free and large enough; the merge
            // below then happens for a shrink too, so a split remainder cannot
            // be left beside an existing free block.
            let Some(next_size) = neighbour else { return false; };
            if total + next_size < block_size { return false; }
            if !self.commit_through(backend, index, addr + (block_size + MIN_BLOCK_BYTES) as u64) { return false; }
        }
        if let Some(next_size) = neighbour { self.remove_free(next); total += next_size; }
        let kept = if total >= block_size + MIN_BLOCK_BYTES {
            if !self.insert_free(backend, index, addr + block_size as u64, total - block_size) { return false; }
            block_size
        } else { total };
        let region = self.subheaps[index].id;
        let header = Header { block_size: kept, tail: kept - HEADER_BYTES - size, region, kind: BLOCK_TYPE_USED, flags: 0 };
        if !backend.write(addr, &header.encode()) { return false; }
        self.zero_growth(backend, flags, addr + HEADER_BYTES as u64, old_size, size)
    }

    /// Zero only the bytes a growing resize added, as the flag promises.
    /// # C: O(size - old_size)
    fn zero_growth<B: HeapBackend>(&mut self, backend: &mut B, flags: u32, ptr: u64, old_size: usize, size: usize) -> bool {
        if flags & HEAP_ZERO_MEMORY == 0 || size <= old_size { return true; }
        backend.fill(ptr + old_size as u64, size - old_size, 0)
    }

    /// Move a body between two allocations through a bounded bounce buffer.
    /// # C: O(len)
    fn copy_body<B: HeapBackend>(&self, backend: &mut B, from: u64, to: u64, len: usize) -> bool {
        let mut buffer = [0u8; COPY_CHUNK];
        let mut done = 0;
        while done < len {
            let step = COPY_CHUNK.min(len - done);
            if !backend.read(from + done as u64, &mut buffer[..step]) { return false; }
            if !backend.write(to + done as u64, &buffer[..step]) { return false; }
            done += step;
        }
        true
    }
}
