// Completion posting: the ONE path a completion reaches userspace by.
//
// A completion is never dropped because the CQ ring is full. When there is no
// room it goes to the ring's overflow backlog and `IORING_SQ_CQ_OVERFLOW` is
// raised in the SQ flags word; the next post, the next enter and every reap
// attempt flush the backlog back into the ring in order. Losing a completion
// would strand the submitter forever waiting for it, which is why the promise
// is a reported feature bit and not an implementation detail.

use crate::io_uring_abi::cqe_slot::{marks_32, place, IORING_CQE_F_SKIP};
use crate::io_uring_abi::layout::{
    RING_CQ_HEAD, RING_CQ_OVERFLOW, RING_CQ_TAIL, RING_SQ_FLAGS,
};
use crate::io_uring_abi::ops::IORING_CQE_F_32;
use crate::io_uring_abi::uapi::IORING_SQ_CQ_OVERFLOW;

use super::ctx::IoUringInode;
use super::ring::IoUring;

/// One completion, in the order the fields sit in the CQE.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
    /// `big_cqe[2]`. Written on an `IORING_SETUP_CQE32` ring, where every CQE
    /// carries the two extra words whether or not an operation filled them,
    /// and on a mixed ring for a completion that asked to be 32 bytes. A plain
    /// 16-byte ring never has room and never writes them.
    pub big: [u64; 2],
    /// This completion carries a 32-byte payload. On a mixed ring that costs a
    /// second slot and sets `IORING_CQE_F_32`; on a 32-byte ring it is the
    /// only shape there is; on a plain ring the operation that wanted it was
    /// already refused at submission.
    pub cqe32: bool,
}

impl Cqe {
    /// # C: O(1)
    pub fn new(user_data: u64, res: i32) -> Self {
        Self { user_data, res, flags: 0, big: [0; 2], cqe32: false }
    }

    /// A completion carrying the 32-byte half. # C: O(1)
    pub fn big32(user_data: u64, res: i32, flags: u32, big: [u64; 2]) -> Self {
        Self { user_data, res, flags, big, cqe32: true }
    }

    /// The filler a mixed ring posts to reach the array's wrap: it carries
    /// nothing and the reader is required to step over it. # C: O(1)
    fn filler() -> Self {
        Self { user_data: 0, res: 0, flags: IORING_CQE_F_SKIP, big: [0; 2], cqe32: false }
    }
}

/// Write one CQE into array slot `slot`. The second half goes out too when the
/// completion is a 32-byte one — always on a 32-byte ring, and for a marked
/// completion on a mixed ring, where it occupies the slot after this one.
/// Nothing is published here: the tail moves once, in the caller, so a reader
/// that saw the tail move sees whole records.
/// # C: O(1)
fn write_slot(r: &IoUring, slot: u32, c: Cqe) {
    let at = r.cqe_at(slot);
    let wide = r.cqe_size as usize == crate::io_uring_abi::uapi::CQE32_SIZE || c.cqe32;
    // SAFETY: cqe_at masks the index into the CQE array, which the geometry bounded inside the rings frame; a wide record occupies this slot and the next, which `place` reserved contiguously; the ring lock serialises kernel writers.
    unsafe {
        core::ptr::write_volatile((at + 0) as *mut u64, c.user_data);
        core::ptr::write_volatile((at + 8) as *mut i32, c.res);
        core::ptr::write_volatile((at + 12) as *mut u32, c.flags);
        if wide {
            core::ptr::write_volatile((at + 16) as *mut u64, c.big[0]);
            core::ptr::write_volatile((at + 24) as *mut u64, c.big[1]);
        }
    }
}

/// Place one completion in the ring and publish the new tail, or report that
/// it did not fit. The filler a mixed ring needs to reach the wrap is written
/// here, before the completion itself, and is counted in the same tail move.
/// # C: O(1)
fn write_cqe(r: &IoUring, c: Cqe) -> bool {
    let tail = r.hdr_load(RING_CQ_TAIL);
    let head = r.hdr_load(RING_CQ_HEAD);
    let Some(p) = place(r.flags, tail, head, r.cq_entries, c.cqe32) else { return false };
    if let Some(f) = p.filler_at { write_slot(r, f, Cqe::filler()); }
    let mut c = c;
    // A mixed ring's reader has no other way to tell the two shapes apart.
    if c.cqe32 && marks_32(r.flags) { c.flags |= IORING_CQE_F_32; }
    write_slot(r, p.at, c);
    r.hdr_store(RING_CQ_TAIL, tail.wrapping_add(p.advance));
    true
}

impl IoUringInode {
    /// Move as much of the overflow backlog into the ring as fits, oldest
    /// first. Returns true when the backlog is empty afterwards.
    /// # C: O(N_flushed)
    pub fn flush_overflow(&self) -> bool {
        let r = self.ring.lock();
        let mut ovf = self.overflow.lock();
        while let Some(&c) = ovf.front() {
            if !write_cqe(&r, c) { break; }
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
        self.posted.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        // A completion is what a count-gated timeout is waiting for, and the
        // only thing that can notice one became due is a worker.
        if self.has_count_timers() {
            for a in crate::io_uring::iowq::WQ.acct.iter() { a.wait.wake_all(); }
        }
        let drained = self.flush_overflow();
        {
            let r = self.ring.lock();
            if drained && write_cqe(&r, c) {
                drop(r);
                self.wake_cq_waiters();
                return;
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
