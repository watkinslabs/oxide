//! Read-only heap surface: block size, pointer validation, walk, user records.

use crate::backend::HeapBackend;
use crate::flags::*;
use crate::heap::Heap;
use crate::layout::Header;
use crate::limits::*;

/// One block reported by a heap walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalkEntry { pub data: u64, pub size: usize, pub busy: bool }

impl Heap {
    /// User bytes an allocation serves, or `None` for a foreign pointer.
    /// # C: O(log N_regions)
    pub fn size<B: HeapBackend>(&self, backend: &B, ptr: u64) -> Option<usize> {
        let (index, _, header) = self.used_block(backend, ptr)?;
        if header.flags & BLOCK_FLAG_LARGE != 0 { return Some(self.large[index].data_size); }
        Some(header.user_size())
    }

    /// Whether `ptr` names a live allocation of this heap.
    /// # C: O(log N_regions)
    pub fn validate<B: HeapBackend>(&self, backend: &B, ptr: u64) -> bool { self.used_block(backend, ptr).is_some() }

    /// Header at a block address, sanity-checked against its region.
    /// # C: O(log N_regions)
    fn header_at<B: HeapBackend>(&self, backend: &B, index: usize, addr: u64) -> Option<Header> {
        let region = self.subheaps[index];
        if addr + HEADER_BYTES as u64 > region.base + region.committed as u64 { return None; }
        let mut bytes = [0u8; 8];
        if !backend.read(addr, &mut bytes) { return None; }
        let header = Header::decode(bytes);
        if header.block_size < MIN_BLOCK_BYTES || header.block_size % BLOCK_ALIGN != 0 { return None; }
        if addr + header.block_size as u64 > region.base + region.reserved as u64 { return None; }
        Some(header)
    }

    /// Next block after `cursor` in address order; `0` starts the walk.
    /// # C: O(1) amortised per step
    pub fn walk<B: HeapBackend>(&self, backend: &B, cursor: u64) -> Option<WalkEntry> {
        let mut region_index = 0;
        let mut addr = None;
        if cursor != 0 {
            if let Some(index) = self.region_of(cursor.checked_sub(HEADER_BYTES as u64)?) {
                let block = cursor - HEADER_BYTES as u64;
                let header = self.header_at(backend, index, block)?;
                region_index = index;
                addr = Some(block + header.block_size as u64);
            } else { region_index = self.subheaps.len(); }
        }
        while region_index < self.subheaps.len() {
            let region = self.subheaps[region_index];
            let start = addr.unwrap_or(region.base + SUBHEAP_OVERHEAD as u64);
            if let Some(header) = self.header_at(backend, region_index, start) {
                return Some(WalkEntry { data: start + HEADER_BYTES as u64, size: if header.flags & BLOCK_FLAG_FREE != 0 { header.block_size - HEADER_BYTES } else { header.user_size() },
                                        busy: header.flags & BLOCK_FLAG_FREE == 0 });
            }
            region_index += 1;
            addr = None;
        }
        let next = self.large.iter().map(|block| block.base + (SUBHEAP_OVERHEAD + HEADER_BYTES) as u64)
            .find(|data| *data > cursor)?;
        let block = self.large.binary_search_by_key(&(next - (SUBHEAP_OVERHEAD + HEADER_BYTES) as u64), |block| block.base).ok()?;
        Some(WalkEntry { data: next, size: self.large[block].data_size, busy: true })
    }

    /// Free blocks currently indexed; the shape a fragmentation test reads.
    /// # C: O(1)
    pub fn free_block_count(&self) -> usize { self.free_by_addr.len() }

    /// User value and flags recorded for one allocation.
    /// # C: O(N_user_info)
    pub fn user_info(&self, ptr: u64) -> Option<(u64, u32)> {
        self.user_info.iter().find(|entry| entry.ptr == ptr).map(|entry| (entry.value, entry.flags & !HEAP_ADD_USER_INFO))
    }

    /// Replace the user value of an allocation that carries a record.
    /// # C: O(N_user_info)
    pub fn set_user_value(&mut self, ptr: u64, value: u64) -> bool {
        match self.user_info.iter_mut().find(|entry| entry.ptr == ptr) { Some(entry) => { entry.value = value; true } None => false }
    }
}
