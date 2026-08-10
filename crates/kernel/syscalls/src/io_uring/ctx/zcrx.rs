// A ring's zero-copy receive instances, keyed by the id it hands the caller.
//
// The id is claimed BEFORE the instance is built, because the refill queue's
// mmap offset encodes it and the caller is told that offset as part of the
// registration. A claimed-but-unpublished slot is therefore a real state: it
// holds the id against a concurrent registration while the region and the area
// are being built, and a failure releases it.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::io_uring::zcrx::ZcrxIfq;
use crate::io_uring_abi::zcrx::ZCRX_MAX_IFQS;

use super::IoUringInode;

/// One slot of the instance table.
pub enum Slot {
    /// Nothing here.
    Empty,
    /// The id is taken; the instance is still being built.
    Claimed,
    Live(Arc<ZcrxIfq>),
}

impl IoUringInode {
    /// Take the lowest free id. # C: O(N_ifqs)
    pub fn zcrx_claim_id(&self) -> Result<u32, Errno> {
        let mut g = self.zcrx.lock();
        for (i, s) in g.iter_mut().enumerate() {
            if matches!(s, Slot::Empty) { *s = Slot::Claimed; return Ok(i as u32); }
        }
        if g.len() as u32 >= ZCRX_MAX_IFQS { return Err(Errno::Enomem); }
        if g.try_reserve(1).is_err() { return Err(Errno::Enomem); }
        g.push(Slot::Claimed);
        Ok(g.len() as u32 - 1)
    }

    /// Give a claimed or live id back. # C: O(1)
    pub fn zcrx_release_id(&self, id: u32) {
        let mut g = self.zcrx.lock();
        if let Some(s) = g.get_mut(id as usize) { *s = Slot::Empty; }
    }

    /// Publish a built instance under the id it was built for. # C: O(1)
    pub fn zcrx_publish(&self, id: u32, ifq: Arc<ZcrxIfq>) {
        let mut g = self.zcrx.lock();
        if let Some(s) = g.get_mut(id as usize) { *s = Slot::Live(ifq); }
    }

    /// The instance an id names, or `None` for an id that names none — which
    /// is what makes a control operation on an unregistered id `ENXIO` rather
    /// than a panic. # C: O(1)
    pub fn zcrx_lookup(&self, id: u32) -> Option<Arc<ZcrxIfq>> {
        let g = self.zcrx.lock();
        match g.get(id as usize) { Some(Slot::Live(i)) => Some(Arc::clone(i)), _ => None }
    }

    /// Physical backing for the refill-queue region an mmap offset selects.
    /// # C: O(1)
    pub fn zcrx_mmap_backing(&self, id: u32) -> Option<(u64, u64)> {
        let ifq = self.zcrx_lookup(id)?;
        Some((ifq.rq.region.base_pa, ifq.rq.region.map_bytes))
    }

    /// Let go of every instance this ring registered or adopted.
    ///
    /// It runs from the ring's teardown rather than from a `Drop`: a bound
    /// device queue holds the instance, and the instance holds the queue
    /// array, so nothing is dropped until the ring stops being a user here.
    ///
    /// Letting go is not the same as closing: an instance a SECOND ring
    /// adopted keeps its queue bound, because that ring is still a user of it.
    /// # C: O(N_ifqs)
    pub fn zcrx_teardown(&self) {
        let taken: Vec<Slot> = core::mem::take(&mut *self.zcrx.lock());
        for s in taken {
            if let Slot::Live(ifq) = s { ifq.put_user(); }
        }
    }
}
