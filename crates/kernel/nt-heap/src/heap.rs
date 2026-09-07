//! Heap state: reserved regions, the free-block index, and large blocks.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use crate::backend::HeapBackend;
use crate::flags::{BLOCK_FLAG_FREE, BLOCK_TYPE_FREE};
use crate::layout::Header;
use crate::limits::*;

/// One reserved region carved into blocks; `committed` bytes from its base
/// carry backing, the rest is reservation the next growth commits.
#[derive(Clone, Copy, Debug)]
pub struct Subheap { pub id: u16, pub base: u64, pub reserved: usize, pub committed: usize, pub primary: bool }

impl Subheap {
    /// Bytes the region's blocks may span, rounded down to block alignment.
    /// # C: O(1)
    pub fn body(&self) -> usize { (self.reserved - SUBHEAP_OVERHEAD) & !(BLOCK_ALIGN - 1) }
}

/// One allocation large enough to own its reservation.
#[derive(Clone, Copy, Debug)]
pub struct Large { pub base: u64, pub mapping: usize, pub data_size: usize }

/// Per-allocation user record, kept only for allocations that asked for one.
#[derive(Clone, Copy, Debug)]
pub struct UserInfo { pub ptr: u64, pub flags: u32, pub value: u64 }

/// A process heap: reserved regions plus the size-ordered free index.
pub struct Heap {
    pub(crate) flags: u32,
    pub(crate) subheaps: Vec<Subheap>,
    pub(crate) large: Vec<Large>,
    pub(crate) free_by_addr: BTreeMap<u64, usize>,
    pub(crate) free_by_size: BTreeSet<(usize, u64)>,
    pub(crate) grow_size: usize,
    pub(crate) next_id: u16,
    pub(crate) user_info: Vec<UserInfo>,
}

impl Heap {
    /// Empty heap; the first allocation reserves the primary region.
    /// # C: O(1)
    pub fn new(flags: u32) -> Heap {
        Heap { flags, subheaps: Vec::new(), large: Vec::new(), free_by_addr: BTreeMap::new(),
               free_by_size: BTreeSet::new(), grow_size: INITIAL_GROW_SIZE, next_id: 0, user_info: Vec::new() }
    }

    /// Index of the region containing `addr`, if any.
    /// # C: O(log N_regions)
    pub(crate) fn region_of(&self, addr: u64) -> Option<usize> {
        let index = self.subheaps.partition_point(|region| region.base <= addr);
        let index = index.checked_sub(1)?;
        let region = self.subheaps[index];
        if addr < region.base + region.reserved as u64 { Some(index) } else { None }
    }

    /// Commit region backing through `end`, rounded to the region granule.
    /// # C: O(1) plus one commit call per newly backed granule
    pub(crate) fn commit_through<B: HeapBackend>(&mut self, backend: &mut B, index: usize, end: u64) -> bool {
        let region = self.subheaps[index];
        let Some(needed) = end.checked_sub(region.base) else { return false; };
        let needed = round_up(needed as usize, REGION_ALIGN).min(region.reserved);
        if needed <= region.committed { return true; }
        if !backend.commit(region.base + region.committed as u64, needed - region.committed) { return false; }
        self.subheaps[index].committed = needed;
        true
    }

    /// Publish a free block: write its header and index it by address and size.
    /// # C: O(log N_free)
    pub(crate) fn insert_free<B: HeapBackend>(&mut self, backend: &mut B, index: usize, addr: u64, block_size: usize) -> bool {
        if block_size % BLOCK_ALIGN != 0 || block_size < MIN_BLOCK_BYTES { return false; }
        let region = self.subheaps[index];
        let header = Header { block_size, tail: 0, region: region.id, kind: BLOCK_TYPE_FREE, flags: BLOCK_FLAG_FREE };
        if !backend.write(addr, &header.encode()) { return false; }
        self.free_by_addr.insert(addr, block_size);
        self.free_by_size.insert((block_size, addr));
        true
    }

    /// Drop a block from the free index.
    /// # C: O(log N_free)
    pub(crate) fn remove_free(&mut self, addr: u64) -> Option<usize> {
        let block_size = self.free_by_addr.remove(&addr)?;
        self.free_by_size.remove(&(block_size, addr));
        Some(block_size)
    }

    /// Reserve a new region and make its whole extent one free block.
    /// # C: O(log N_free) plus one reserve and one commit
    pub(crate) fn grow<B: HeapBackend>(&mut self, backend: &mut B, need: usize) -> Option<usize> {
        if !self.subheaps.is_empty() && self.flags & crate::flags::HEAP_GROWABLE == 0 { return None; }
        let want = if self.subheaps.is_empty() { INITIAL_SIZE.max(need) } else { self.grow_size.max(need) };
        let mut reserved = round_up(want, REGION_RESERVE_ALIGN).min(MAX_SUBHEAP_BYTES);
        if reserved < need { return None; }
        let base = loop {
            match backend.reserve(reserved) {
                Some(base) => break base,
                None if reserved > need && reserved > REGION_ALIGN => reserved = (reserved / 2).max(round_up(need, REGION_RESERVE_ALIGN)),
                None => return None,
            }
        };
        if self.next_id == crate::layout::LARGE_REGION { return None; }
        let id = self.next_id;
        self.next_id += 1;
        let primary = self.subheaps.is_empty();
        let index = self.subheaps.partition_point(|region| region.base < base);
        self.subheaps.insert(index, Subheap { id, base, reserved, committed: 0, primary });
        if !self.subheaps.is_empty() && !primary { self.grow_size = (self.grow_size * 2).min(MAX_GROW_SIZE); }
        let first = base + SUBHEAP_OVERHEAD as u64;
        // The region's first block spans its whole body: rounded DOWN to block
        // alignment, because the header encodes a size in whole units.
        let block_size = self.subheaps[index].body();
        if !self.commit_through(backend, index, first + MIN_BLOCK_BYTES as u64) { return None; }
        if !self.insert_free(backend, index, first, block_size) { return None; }
        Some(index)
    }

    /// Release every region and forget all state.
    /// # C: O(N_regions + N_large)
    pub fn destroy<B: HeapBackend>(&mut self, backend: &mut B) {
        for region in core::mem::take(&mut self.subheaps) { backend.release(region.base, region.reserved); }
        for block in core::mem::take(&mut self.large) { backend.release(block.base, block.mapping); }
        self.free_by_addr.clear();
        self.free_by_size.clear();
        self.user_info.clear();
        self.grow_size = INITIAL_GROW_SIZE;
    }

    /// Record, replace or drop the user record of one allocation.
    /// # C: O(N_user_info)
    pub(crate) fn move_user_info(&mut self, from: u64, to: Option<u64>) {
        match to {
            Some(to) => { if let Some(entry) = self.user_info.iter_mut().find(|entry| entry.ptr == from) { entry.ptr = to; } }
            None => self.user_info.retain(|entry| entry.ptr != from),
        }
    }
}
