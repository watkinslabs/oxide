// One io_uring instance: everything a ring owns, in one place.
//
// The regions live in `ring`; who may submit and what they may submit lives
// here; the registered resources live in `reg`. Three locks, in a fixed order
// so no path can invert them:
//
//   submit  (sleeping)  — held across a whole submission batch, so two tasks
//                         submitting to one ring cannot interleave their link
//                         chains. Dropped before any wait.
//   ring    (spin)      — the shared memory words. Short critical sections
//                         only: no op ever runs with it held, because ops
//                         sleep.
//   overflow/reg (spin) — the backlog and the registered-resource tables.
//
// Order is submit -> ring -> overflow/reg. Ops execute holding none of them.

use alloc::collections::VecDeque;
use alloc::sync::Arc;

use sync::{Spinlock, TaskList as RingLockClass};

use crate::io_uring_abi::layout::Geometry;

use super::cqe::Cqe;
use super::ring::IoUring;
use super::rsrc::IoUringReg;

pub struct IoUringInode {
    pub ring: Spinlock<IoUring, RingLockClass>,
    pub reg:  Spinlock<IoUringReg, RingLockClass>,
    /// Completions that did not fit the CQ ring, oldest first.
    pub overflow: Spinlock<VecDeque<Cqe>, RingLockClass>,
    /// Held for a whole submission batch.
    pub submit: sched::live::Mutex<()>,
    /// Tasks blocked in `io_uring_enter` waiting for completions.
    pub cq_wait: sched::live::WaitList,
    /// The setup flags this ring was built with.
    pub flags: u32,
    /// State bits — see `state`.
    pub state: core::sync::atomic::AtomicU32,
    /// For an `IORING_SETUP_SINGLE_ISSUER` ring: the one task allowed to
    /// submit to it and to register against it, claimed by whoever gets there
    /// first. `0` = unclaimed.
    pub submitter: core::sync::atomic::AtomicU32,
    /// Requests this ring still owes a completion for.
    pub inflight: Spinlock<super::req::InFlight, RingLockClass>,
    /// Completions this ring has posted, ever. A completion-count timeout is
    /// stated against this, not against the CQ tail, which userspace's reaping
    /// moves on its own.
    pub posted: core::sync::atomic::AtomicU64,
    /// The address space, descriptor table and credentials a worker borrows to
    /// run this ring's deferred work, captured at the first deferral.
    pub owner: Spinlock<Option<Arc<super::iowq::Owner>>, RingLockClass>,
    /// `IORING_REGISTER_IOWQ_MAX_WORKERS`: how many of this ring's requests may
    /// run at once, per work class.
    pub iowq_max: [core::sync::atomic::AtomicU32; super::iowq::acct::NR],
    /// How many are running right now.
    pub iowq_running: [core::sync::atomic::AtomicU32; super::iowq::acct::NR],
    /// This ring's submission-polling thread, for an `IORING_SETUP_SQPOLL`
    /// ring. `None` otherwise, which is what makes `io_uring_enter` submit
    /// inline rather than defer to a thread that does not exist.
    pub sq: Spinlock<Option<Arc<super::sqpoll::SqData>>, RingLockClass>,
    /// Armed timeouts gated on this ring's completion count. Non-zero means a
    /// completion can make one due, so posting one must rouse the pool.
    pub count_timers: core::sync::atomic::AtomicU32,
    /// `IORING_REGISTER_MEM_REGION`: the one region a ring may register.
    /// `Some` is what makes a second registration `EBUSY`.
    pub param_region: Spinlock<Option<super::mem_region::MemRegion>, RingLockClass>,
    /// Bytes of `param_region` exposed as the registered wait area, or zero
    /// for a ring that registered a region WITHOUT
    /// `IORING_MEM_REGION_REG_WAIT_ARG`. Zero is load-bearing: it is what
    /// makes every `IORING_ENTER_EXT_ARG_REG` offset fault on such a ring,
    /// with no separate "is there an area" test.
    pub cq_wait_size: core::sync::atomic::AtomicU64,
    /// Requests handed to a backend and not yet completed — Linux's
    /// `ctx->iopoll_list`, and STRONG for the reason that list is: nothing else
    /// holds a queued transfer. A timeout is held by the clock and a punted
    /// operation by its worker, but a transfer the backend owns is held only by
    /// the backend's completion, which owns the result slot and deliberately not
    /// the request. Without this the request would be dropped at the end of the
    /// submitting call and its completion would never be posted.
    pub iopoll_list: Spinlock<alloc::vec::Vec<Arc<super::req::IoReq>>, RingLockClass>,
    /// `IORING_SETUP_HYBRID_IOPOLL`: the shortest service time any transfer on
    /// this ring has been observed to take, in nanoseconds — the reference's
    /// `ctx->hybrid_poll_time`. The next transfer sleeps for half of it before
    /// it starts spinning. [`crate::io_uring_abi::iopoll::NO_ESTIMATE`] means
    /// nothing has been timed yet, which is what makes the first transfer spin
    /// outright rather than sleep against a guess.
    pub hybrid_poll_time: core::sync::atomic::AtomicU64,
}

/// `state` bits.
pub mod state {
    /// Submission is refused until `IORING_REGISTER_ENABLE_RINGS` runs.
    pub const DISABLED: u32 = 1 << 0;
    /// A completion was lost because the backlog could not grow. Reported
    /// once, to the next waiter, then cleared.
    pub const CQE_DROPPED: u32 = 1 << 1;
    /// The ring has submitted an entry asking for its success to be silent, so
    /// completion-counting barriers can no longer be honoured.
    pub const DRAIN_DISABLED: u32 = 1 << 2;
}

impl IoUringInode {
    /// Build a ring from an admitted geometry. # C: O(1)
    pub fn new(g: &Geometry) -> Option<Arc<Self>> {
        use crate::io_uring_abi::uapi::IORING_SETUP_R_DISABLED;
        let ring = IoUring::new(g)?;
        let init = if g.flags & IORING_SETUP_R_DISABLED != 0 { state::DISABLED } else { 0 };
        Some(Arc::new(Self {
            ring: Spinlock::new(ring),
            reg:  Spinlock::new(IoUringReg {
                clockid: super::rsrc::CLOCK_MONOTONIC,
                napi: crate::io_uring_abi::napi::NapiState::inactive(),
                bpf: super::register::bpf_filter::inherited_filters(),
                restrictions: super::register::task_restrict::inherited_restrictions(),
                ..IoUringReg::default()
            }),
            overflow: Spinlock::new(VecDeque::new()),
            submit: sched::live::Mutex::new(()),
            cq_wait: sched::live::WaitList::new(),
            flags: g.flags,
            state: core::sync::atomic::AtomicU32::new(init),
            submitter: core::sync::atomic::AtomicU32::new(0),
            inflight: Spinlock::new(super::req::InFlight::default()),
            posted: core::sync::atomic::AtomicU64::new(0),
            owner: Spinlock::new(None),
            iowq_max: [
                core::sync::atomic::AtomicU32::new(super::iowq::pool::DEFAULT_MAX[0]),
                core::sync::atomic::AtomicU32::new(super::iowq::pool::DEFAULT_MAX[1]),
            ],
            iowq_running: [
                core::sync::atomic::AtomicU32::new(0),
                core::sync::atomic::AtomicU32::new(0),
            ],
            sq: Spinlock::new(None),
            count_timers: core::sync::atomic::AtomicU32::new(0),
            param_region: Spinlock::new(None),
            cq_wait_size: core::sync::atomic::AtomicU64::new(0),
            iopoll_list: Spinlock::new(alloc::vec::Vec::new()),
            hybrid_poll_time: core::sync::atomic::AtomicU64::new(
                crate::io_uring_abi::iopoll::NO_ESTIMATE),
        }))
    }

    /// # C: O(1)
    pub fn test_state(&self, bit: u32) -> bool {
        use core::sync::atomic::Ordering;
        self.state.load(Ordering::Acquire) & bit != 0
    }

    /// # C: O(1)
    pub fn set_state(&self, bit: u32) {
        use core::sync::atomic::Ordering;
        self.state.fetch_or(bit, Ordering::AcqRel);
    }

    /// # C: O(1)
    pub fn clear_state(&self, bit: u32) -> bool {
        use core::sync::atomic::Ordering;
        self.state.fetch_and(!bit, Ordering::AcqRel) & bit != 0
    }

    /// Claim, or check, the single-issuer right. A ring without
    /// `IORING_SETUP_SINGLE_ISSUER` admits every task; one with it admits the
    /// first task to arrive and reports EEXIST to any other, which is what
    /// makes the flag a guarantee rather than a hint. # C: O(1)
    pub fn claim_issuer(&self) -> Result<(), syscall::errno::Errno> {
        use core::sync::atomic::Ordering;
        use crate::io_uring_abi::uapi::IORING_SETUP_SINGLE_ISSUER;
        if self.flags & IORING_SETUP_SINGLE_ISSUER == 0 { return Ok(()); }
        let Some(cur) = sched::live::current() else { return Ok(()) };
        match self.submitter.compare_exchange(0, cur.tid, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(()),
            Err(owner) if owner == cur.tid => Ok(()),
            Err(_) => Err(syscall::errno::Errno::Eexist),
        }
    }

    /// Read one `struct io_uring_reg_wait` out of the registered wait area at
    /// byte offset `argp` — the `IORING_ENTER_EXT_ARG_REG` form, where `argp`
    /// is an offset into a region the ring registered rather than a user
    /// pointer. A ring with no wait area has size zero, so every offset
    /// faults. # C: O(1)
    pub fn reg_wait(&self, argp: u64)
        -> Result<[u8; crate::io_uring_abi::enter::REG_WAIT_BYTES as usize], syscall::errno::Errno>
    {
        use crate::io_uring_abi::mem_region::ext_arg_reg_offset;
        use core::sync::atomic::Ordering;
        let off = ext_arg_reg_offset(argp, self.cq_wait_size.load(Ordering::Acquire))?;
        let mut b = [0u8; crate::io_uring_abi::enter::REG_WAIT_BYTES as usize];
        let g = self.param_region.lock();
        let r = g.as_ref().ok_or(syscall::errno::Errno::Efault)?;
        r.read_at(off, &mut b)?;
        Ok(b)
    }

    /// Record that a completion could not be delivered. # C: O(1)
    pub fn note_cqe_dropped(&self) { self.set_state(state::CQE_DROPPED); }

    /// Wake everyone blocked on completions, and signal the registered
    /// completion eventfd. # C: O(N_waiters)
    pub fn wake_cq_waiters(&self) {
        self.cq_wait.wake_all();
        self.signal_eventfd();
    }

    /// Signal the registered completion eventfd (+1), if one is registered and
    /// it is not the async-only variant. Every completion here is posted from
    /// the submitting task, so an async-only eventfd is correctly never
    /// signalled. # C: O(1)
    pub fn signal_eventfd(&self) {
        let efd = { let g = self.reg.lock(); if g.eventfd_async { None } else { g.eventfd.clone() } };
        if let Some(f) = efd {
            let one = 1u64.to_ne_bytes();
            let _ = f.inode().write(0, &one);
        }
    }
}

#[path = "ctx/async_state.rs"] mod async_state;
