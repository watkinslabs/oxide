// The refill queue: the ring userspace writes returned buffers into.
//
// It is a single-producer (userspace) single-consumer (kernel) ring in a
// kernel-allocated region the caller maps. The kernel keeps its own cached
// head so it can walk a batch without publishing progress until the batch is
// done — publishing per entry would let userspace refill a slot the kernel is
// still reading out of.

use sync::{Spinlock, TaskList as RingLockClass};

use crate::io_uring::region::Region;
use crate::io_uring_abi::zcrx::{
    rq_available, Rqe, RQE_BYTES, ZCRX_RQ_HEAD_OFF, ZCRX_RQ_RQES_OFF, ZCRX_RQ_TAIL_OFF,
};

pub struct ZcrxRq {
    /// The shared region. Refcounted RAM: the caller maps it as a
    /// `KernelFrame`, so a page dies only once the ring released it AND every
    /// mapping is gone.
    pub region: Region,
    /// Entries, a power of two.
    pub nr_entries: u32,
    /// How far the kernel has consumed. Behind the published head until a
    /// batch finishes.
    cached_head: Spinlock<u32, RingLockClass>,
    /// Byte offset of the notification statistics record, when the caller
    /// asked for one.
    pub stats_off: Option<u64>,
}

impl ZcrxRq {
    /// # C: O(1)
    pub fn new(region: Region, nr_entries: u32, stats_off: Option<u64>) -> Self {
        let rq = Self { region, nr_entries, cached_head: Spinlock::new(0), stats_off };
        rq.store_u32(ZCRX_RQ_HEAD_OFF, 0);
        rq.store_u32(ZCRX_RQ_TAIL_OFF, 0);
        if let Some(off) = stats_off { rq.store_u64(off, 0); rq.store_u64(off + 8, 0); }
        rq
    }

    /// # C: O(1)
    fn load_u32(&self, off: u32) -> u32 {
        // SAFETY: off is one of the region's own layout constants, inside the region this instance allocated and holds for its whole life.
        unsafe { core::ptr::read_volatile(self.region.at(off as u64) as *const u32) }
    }
    /// # C: O(1)
    fn store_u32(&self, off: u32, v: u32) {
        // SAFETY: off is one of the region's own layout constants, inside the region this instance allocated; the head is written only under `cached_head`.
        unsafe { core::ptr::write_volatile(self.region.at(off as u64) as *mut u32, v); }
    }
    /// # C: O(1)
    fn load_u64(&self, off: u64) -> u64 {
        // SAFETY: off was bounded to the region by `admit_notif_stats` before the instance was published.
        unsafe { core::ptr::read_volatile(self.region.at(off) as *const u64) }
    }
    /// # C: O(1)
    fn store_u64(&self, off: u64, v: u64) {
        // SAFETY: off was bounded to the region by `admit_notif_stats` before the instance was published.
        unsafe { core::ptr::write_volatile(self.region.at(off) as *mut u64, v); }
    }

    /// Entry `idx & mask`. # C: O(1)
    fn rqe(&self, idx: u32) -> Rqe {
        let at = self.region.at(ZCRX_RQ_RQES_OFF as u64
                                + (idx & (self.nr_entries - 1)) as u64 * RQE_BYTES);
        let mut b = [0u8; RQE_BYTES as usize];
        for (i, slot) in b.iter_mut().enumerate() {
            // SAFETY: the index is masked into the entry array, which `admit_rq_region` sized inside this region.
            *slot = unsafe { core::ptr::read_volatile((at + i as u64) as *const u8) };
        }
        Rqe::from_bytes(&b)
    }

    /// Take up to `max` entries and hand each to `f`, then publish how far the
    /// kernel got. Returns the number taken.
    ///
    /// The published head moves ONCE, after the batch: userspace refills the
    /// slots below it, so moving it per entry would open a slot the walk has
    /// not finished with. # C: O(max)
    pub fn take(&self, max: usize, mut f: impl FnMut(Rqe)) -> usize {
        let mut head = self.cached_head.lock();
        let tail = self.load_u32(ZCRX_RQ_TAIL_OFF);
        let avail = rq_available(tail, *head, self.nr_entries) as usize;
        let n = core::cmp::min(avail, max);
        for _ in 0..n {
            let rqe = self.rqe(*head);
            *head = head.wrapping_add(1);
            f(rqe);
        }
        if n != 0 { self.store_u32(ZCRX_RQ_HEAD_OFF, *head); }
        n
    }

    /// Entries waiting to be taken. # C: O(1)
    pub fn ready(&self) -> u32 {
        let head = *self.cached_head.lock();
        rq_available(self.load_u32(ZCRX_RQ_TAIL_OFF), head, self.nr_entries)
    }

    /// Add to a notification statistics counter, when the caller asked for
    /// one. `which` is 0 for the completion count and 1 for the byte count.
    /// # C: O(1)
    pub fn stat_add(&self, which: u64, v: u64) {
        let Some(base) = self.stats_off else { return };
        let at = base + which * 8;
        self.store_u64(at, self.load_u64(at).wrapping_add(v));
    }
}
