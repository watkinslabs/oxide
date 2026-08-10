// A page supply backed by host memory at physical addresses the test picks.
//
// The point is control over WHICH address comes back: the staging algorithm's
// only interesting branch fires when an allocation lands exactly on another
// segment's destination, and a supply that cannot be aimed can never reach it.

extern crate alloc;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::frames::Frames;
use crate::image::SegmentSource;
use crate::uapi::PAGE_SIZE;
use crate::validate::KResult;

/// Host-backed page supply. `queue` is handed out in order; when it empties,
/// pages come from `next_free` upward.
pub struct FakeFrames {
    pub queue: Vec<u64>,
    pub next_free: u64,
    pub total_ram_pages: u64,
    pub fail_after: usize,
    handed: usize,
    live: BTreeMap<u64, Box<[u8; PAGE_SIZE as usize]>>,
    /// Pages that exist but were never handed out by the allocator — memory
    /// this kernel has promised not to use. A crash image is built entirely
    /// out of these, so a supply that could not model them could not tell a
    /// crash image that touched the allocator from one that did not.
    region: BTreeMap<u64, Box<[u8; PAGE_SIZE as usize]>>,
    pub freed: Vec<u64>,
}

impl FakeFrames {
    /// Supply that hands out `next_free`, `next_free + 4096`, … forever.
    pub fn new(next_free: u64) -> Self {
        Self { queue: Vec::new(), next_free, total_ram_pages: 1 << 20,
               fail_after: usize::MAX, handed: 0, live: BTreeMap::new(),
               region: BTreeMap::new(), freed: Vec::new() }
    }
    /// Supply that hands out `queue` first, in order.
    pub fn with_queue(queue: &[u64], next_free: u64) -> Self {
        let mut f = Self::new(next_free);
        f.queue = queue.to_vec();
        f
    }
    /// Pages allocated and not yet freed.
    pub fn live_count(&self) -> usize { self.live.len() }
    /// Make `[start, start + len)` exist without the allocator ever owning it.
    pub fn reserve_region(&mut self, start: u64, len: u64) {
        let mut pa = start;
        while pa < start + len {
            self.region.insert(pa, Box::new([0u8; PAGE_SIZE as usize]));
            pa += PAGE_SIZE;
        }
    }
    /// Fill a reserved page with `byte`, so a later stage into it has
    /// something to overwrite. Without this a region page is already zero and
    /// a missing clear looks exactly like a clear that happened.
    pub fn dirty_region(&mut self, pa: u64, byte: u8) {
        self.region.get_mut(&pa).expect("page is in the region").fill(byte);
    }
    /// Read a staged page back, to assert what the copy actually wrote.
    pub fn page(&self, pa: u64) -> &[u8] {
        &self.live.get(&pa).or_else(|| self.region.get(&pa)).expect("page exists")[..]
    }
}

impl Frames for FakeFrames {
    fn alloc(&mut self) -> Option<u64> {
        if self.handed >= self.fail_after { return None; }
        self.handed += 1;
        let pa = if self.queue.is_empty() {
            let p = self.next_free;
            self.next_free += PAGE_SIZE;
            p
        } else {
            self.queue.remove(0)
        };
        self.live.entry(pa).or_insert_with(|| Box::new([0u8; PAGE_SIZE as usize]));
        Some(pa)
    }
    unsafe fn free(&mut self, pa: u64) { self.live.remove(&pa); self.freed.push(pa); }
    fn ptr(&self, pa: u64) -> Option<*mut u8> {
        self.live.get(&pa).or_else(|| self.region.get(&pa)).map(|b| b.as_ptr() as *mut u8)
    }
    fn total_ram_pages(&self) -> u64 { self.total_ram_pages }
}

/// Segment source over a byte pattern, so a staged page's contents are
/// predictable per offset.
pub struct PatternSource {
    pub bytes: Vec<u8>,
}

impl PatternSource {
    /// `len` bytes where byte `i` is `(i % 251) as u8` — a period coprime with
    /// the page size, so a page-boundary off-by-one changes the value.
    pub fn new(len: usize) -> Self {
        Self { bytes: (0..len).map(|i| (i % 251) as u8).collect() }
    }
}

impl SegmentSource for PatternSource {
    fn read_at(&self, buf: u64, off: u64, dst: &mut [u8]) -> KResult<()> {
        let s = (buf + off) as usize;
        dst.copy_from_slice(&self.bytes[s..s + dst.len()]);
        Ok(())
    }
}

/// Source that always faults, for the EFAULT path.
pub struct FaultingSource;

impl SegmentSource for FaultingSource {
    fn read_at(&self, _buf: u64, _off: u64, _dst: &mut [u8]) -> KResult<()> {
        Err(crate::validate::Error::Fault)
    }
}
