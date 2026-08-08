// Completion posting: the ONE path a completion reaches userspace by.
//
// A completion is never dropped because the CQ ring is full. When there is no
// room it goes to the ring's overflow backlog and `IORING_SQ_CQ_OVERFLOW` is
// raised in the SQ flags word; the next post, the next enter and every reap
// attempt flush the backlog back into the ring in order. Losing a completion
// would strand the submitter forever waiting for it, which is why the promise
// is a reported feature bit and not an implementation detail.

use crate::io_uring_abi::enter::cq_has_room;
use crate::io_uring_abi::layout::{
    RING_CQ_HEAD, RING_CQ_OVERFLOW, RING_CQ_TAIL, RING_SQ_FLAGS,
};
use crate::io_uring_abi::uapi::IORING_SQ_CQ_OVERFLOW;

use super::ctx::IoUringInode;
use super::ring::IoUring;

/// One completion, in the order the fields sit in the CQE.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

impl Cqe {
    /// # C: O(1)
    pub fn new(user_data: u64, res: i32) -> Self { Self { user_data, res, flags: 0 } }
}

/// Write one CQE into the ring at `tail` and publish the new tail.
/// # C: O(1)
fn write_cqe(r: &IoUring, tail: u32, c: Cqe) {
    let at = r.cqe_at(tail);
    // SAFETY: cqe_at masks the index into the CQE array, which the geometry bounded inside the rings frame; the ring lock serialises kernel writers.
    unsafe {
        core::ptr::write_volatile((at + 0) as *mut u64, c.user_data);
        core::ptr::write_volatile((at + 8) as *mut i32, c.res);
        core::ptr::write_volatile((at + 12) as *mut u32, c.flags);
    }
    r.hdr_store(RING_CQ_TAIL, tail.wrapping_add(1));
}

impl IoUringInode {
    /// Move as much of the overflow backlog into the ring as fits, oldest
    /// first. Returns true when the backlog is empty afterwards.
    /// # C: O(N_flushed)
    pub fn flush_overflow(&self) -> bool {
        let r = self.ring.lock();
        let mut ovf = self.overflow.lock();
        while let Some(&c) = ovf.front() {
            let tail = r.hdr_load(RING_CQ_TAIL);
            let head = r.hdr_load(RING_CQ_HEAD);
            if !cq_has_room(tail, head, r.cq_entries) { break; }
            write_cqe(&r, tail, c);
            ovf.pop_front();
        }
        let empty = ovf.is_empty();
        let f = r.hdr_load(RING_SQ_FLAGS);
        r.hdr_store(RING_SQ_FLAGS, if empty { f & !IORING_SQ_CQ_OVERFLOW } else { f | IORING_SQ_CQ_OVERFLOW });
        empty
    }

    /// Post one completion. Never drops it: a full ring sends it to the
    /// backlog. A backlog allocation that cannot grow is the ONE case where a
    /// completion is lost, and it is counted in the ring's `cq_overflow`
    /// so the caller can see that it happened. # C: O(N_flushed)
    pub fn post_cqe(&self, c: Cqe) {
        let drained = self.flush_overflow();
        {
            let r = self.ring.lock();
            if drained {
                let tail = r.hdr_load(RING_CQ_TAIL);
                let head = r.hdr_load(RING_CQ_HEAD);
                if cq_has_room(tail, head, r.cq_entries) {
                    write_cqe(&r, tail, c);
                    drop(r);
                    self.wake_cq_waiters();
                    return;
                }
            }
        }
        let queued = {
            let mut ovf = self.overflow.lock();
            if ovf.try_reserve(1).is_ok() { ovf.push_back(c); true } else { false }
        };
        let r = self.ring.lock();
        if queued {
            r.hdr_store(RING_SQ_FLAGS, r.hdr_load(RING_SQ_FLAGS) | IORING_SQ_CQ_OVERFLOW);
        } else {
            r.hdr_store(RING_CQ_OVERFLOW, r.hdr_load(RING_CQ_OVERFLOW).wrapping_add(1));
            self.note_cqe_dropped();
        }
        drop(r);
        self.wake_cq_waiters();
    }

    /// Completions posted and not yet reaped, backlog included — the quantity
    /// a `min_complete` wait is measured against. # C: O(1)
    pub fn cq_ready(&self) -> u32 {
        let r = self.ring.lock();
        let ready = r.hdr_load(RING_CQ_TAIL).wrapping_sub(r.hdr_load(RING_CQ_HEAD));
        drop(r);
        ready.saturating_add(self.overflow.lock().len() as u32)
    }

    /// Whether the caller has anything at all to reap. # C: O(1)
    pub fn cq_nonempty(&self) -> bool { self.cq_ready() > 0 }
}
