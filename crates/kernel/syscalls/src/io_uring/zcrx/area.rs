// The receive area: pages pinned out of the caller's memory, split into
// fixed-size buffers, plus the two counts each buffer carries.
//
// The pinning is what makes the area safe to hand to a device or to copy into
// from a receive path: the frames stay put for the instance's whole life, so
// nothing the caller does to its own mappings can retarget a buffer the kernel
// has already told a device about.

use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as RingLockClass};
use syscall::errno::Errno;

use net::page_pool::NetIovArea;

use crate::io_uring_abi::zcrx::{refill, Refill, UserRefs};

use crate::io_uring::pin::PinnedRange;

/// One instance's area. There is exactly one per instance, so its id is always
/// zero — the id still travels in every offset because the ABI encodes it, and
/// a refill entry naming a different area is a malformed entry rather than a
/// silent aliasing bug.
pub struct ZcrxArea {
    mem: PinnedRange,
    /// One descriptor per buffer, shared with the page pool.
    pub nia: Arc<NetIovArea>,
    /// Bytes one buffer spans, as a shift.
    pub niov_shift: u32,
    pub area_id: u16,
    /// Buffers the instance owns outright, newest first.
    free: Spinlock<Vec<u32>, RingLockClass>,
    /// Per-buffer references the caller holds.
    urefs: UserRefs,
}

impl ZcrxArea {
    /// Split a pinned range into buffers. # C: O(N_buffers)
    pub fn new(mem: PinnedRange, niov_shift: u32) -> Result<Self, Errno> {
        let n = (mem.len >> niov_shift) as usize;
        if n == 0 { return Err(Errno::Einval); }
        let mut free: Vec<u32> = Vec::new();
        if free.try_reserve_exact(n).is_err() { return Err(Errno::Enomem); }
        let urefs = UserRefs::new(n).ok_or(Errno::Enomem)?;
        // Handed out lowest-index first, which makes a fresh instance's
        // completions walk the area in order and keeps a caller's own reads
        // sequential.
        for i in (0..n as u32).rev() { free.push(i); }
        Ok(Self {
            mem, nia: Arc::new(NetIovArea::new(n)), niov_shift, area_id: 0,
            free: Spinlock::new(free), urefs,
        })
    }

    /// # C: O(1)
    pub fn num_niovs(&self) -> u32 { self.urefs.len() as u32 }
    /// # C: O(1)
    pub fn len(&self) -> u64 { self.mem.len }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.mem.len == 0 }
    /// Bytes one buffer spans. # C: O(1)
    pub fn buf_len(&self) -> u64 { 1u64 << self.niov_shift }
    /// Byte offset of buffer `idx` inside the area. # C: O(1)
    pub fn byte_off(&self, idx: u32) -> u64 { (idx as u64) << self.niov_shift }

    /// Take a buffer the instance owns. # C: O(1)
    pub fn get_free(&self) -> Option<u32> { self.free.lock().pop() }

    /// Give a buffer back to the instance. # C: O(1)
    pub fn put_free(&self, idx: u32) {
        if idx >= self.num_niovs() { return; }
        self.nia.niovs[idx as usize].clear_bound();
        let mut g = self.free.lock();
        if g.try_reserve(1).is_ok() { g.push(idx); }
    }

    /// Buffers the instance owns right now. # C: O(1)
    pub fn free_count(&self) -> usize { self.free.lock().len() }

    /// Record that the caller has been told about a buffer. # C: O(1)
    pub fn get_uref(&self, idx: u32) { self.urefs.take(idx); }

    /// References the caller holds on a buffer. # C: O(1)
    pub fn user_refs(&self, idx: u32) -> u32 { self.urefs.get(idx) }

    /// Consume one refill entry against a buffer, spending the caller's
    /// reference before the pool's. The ordering lives in
    /// `io_uring_abi::zcrx::refill`, which is ungated so it can be tested.
    /// # C: O(1)
    pub fn refill(&self, idx: u32) -> Refill { refill(&self.nia, &self.urefs, idx) }

    /// Take back every buffer the caller was still holding, so no buffer is
    /// left charged to a caller that can no longer return it.
    ///
    /// It spends the caller's references through the same one ordering a
    /// refill entry does, rather than resetting the counts: a buffer the stack
    /// still holds must stay out of the freelist even here, or the next
    /// allocation would hand out memory that is being written into.
    /// # C: O(N_buffers × refs)
    pub fn scrub(&self) {
        for idx in 0..self.num_niovs() {
            while self.user_refs(idx) != 0 {
                if self.refill(idx) == Refill::Freed { self.put_free(idx); }
            }
        }
    }

    /// Copy `src` into buffer `idx` at `off` bytes in. # C: O(src.len())
    pub fn write_buf(&self, idx: u32, off: u64, src: &[u8]) -> Result<(), Errno> {
        if off + src.len() as u64 > self.buf_len() { return Err(Errno::Einval); }
        self.mem.write_at(self.byte_off(idx) + off, src)
    }
}
