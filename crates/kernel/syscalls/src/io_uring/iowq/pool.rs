// The worker pool: two queues, their threads, the per-ring worker limits, the
// processor affinity and the armed-clock list.
//
// Two queues, not one, for the reason the two accounts exist at all: work on a
// socket or a pipe can block for as long as the peer likes, and work on a
// regular file cannot. Sharing one thread set between them lets a handful of
// idle sockets starve every file operation in the system, so each class gets
// its own threads and neither can consume the other's.
//
// Worker threads are started on demand and then live for the life of the
// system, serving whichever ring has work — a thread per ring would need a way
// for a kernel thread to exit, which the scheduler does not offer. The
// per-ring `IORING_REGISTER_IOWQ_MAX_WORKERS` limit is therefore enforced on
// how many of a ring's requests may run at once rather than on how many
// threads exist, which is the property the registration actually promises.

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as WqLockClass};

use crate::io_uring::req::IoReq;

/// The two work classes.
pub mod acct {
    /// Work that cannot block indefinitely — regular files, paths, metadata.
    pub const BOUND: usize = 0;
    /// Work that can block for as long as a peer likes — sockets, pipes, ttys.
    pub const UNBOUND: usize = 1;
    /// How many classes there are.
    pub const NR: usize = 2;
}

/// Threads serving the bound queue. Bound work makes progress on its own, so a
/// small set keeps up; each thread is a kernel stack that is never reclaimed.
pub const BOUND_THREADS: u32 = 4;
/// Threads serving the unbound queue. Every one of these can be parked in a
/// peer's silence at once, so the set is larger.
pub const UNBOUND_THREADS: u32 = 8;

/// A limit of zero means "leave this class alone", so it can never be a real
/// ceiling; the default ceiling is the thread set that serves the class.
pub const DEFAULT_MAX: [u32; acct::NR] = [BOUND_THREADS, UNBOUND_THREADS];

/// Nothing is queued and nothing is armed: park this long anyway, so a wake
/// that lands between the emptiness check and the park is never the last word.
const BACKSTOP_NS: u64 = 100_000_000;

/// One work class's queue and threads.
pub struct Acct {
    pub queue: Spinlock<VecDeque<Arc<IoReq>>, WqLockClass>,
    pub wait: sched::live::WaitList,
    pub threads: AtomicU32,
}

impl Acct {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            queue: Spinlock::new(VecDeque::new()),
            wait: sched::live::WaitList::new(),
            threads: AtomicU32::new(0),
        }
    }
}

/// The pool.
pub struct IoWq {
    pub acct: [Acct; acct::NR],
    /// Requests armed on a clock, oldest arming first. Weak: a request that
    /// completed some other way must not be held alive by its own deadline.
    pub timers: Spinlock<alloc::vec::Vec<Weak<IoReq>>, WqLockClass>,
    /// Processors workers may run on; `0` = every processor.
    pub cpu_mask: AtomicU64,
    pub started: AtomicBool,
}

/// The one pool. Every ring's async work runs here.
pub static WQ: IoWq = IoWq {
    acct: [Acct::new(), Acct::new()],
    timers: Spinlock::new(alloc::vec::Vec::new()),
    cpu_mask: AtomicU64::new(0),
    started: AtomicBool::new(false),
};

/// Which class an opcode's work belongs to. Anything that talks to something
/// outside this machine can wait forever; anything else cannot.
/// # C: O(1)
pub fn class_of(opcode: u8) -> usize {
    use crate::io_uring_abi::ops::*;
    match opcode {
        IORING_OP_SEND | IORING_OP_RECV | IORING_OP_SENDMSG | IORING_OP_RECVMSG
        | IORING_OP_ACCEPT | IORING_OP_CONNECT | IORING_OP_LISTEN | IORING_OP_BIND
        | IORING_OP_SHUTDOWN | IORING_OP_SOCKET | IORING_OP_POLL_ADD
        | IORING_OP_TIMEOUT | IORING_OP_LINK_TIMEOUT => acct::UNBOUND,
        _ => acct::BOUND,
    }
}

impl IoWq {
    /// Hand a request to a worker. # C: O(1)
    pub fn queue(&'static self, req: Arc<IoReq>) {
        let class = class_of(req.opcode());
        {
            let mut q = self.acct[class].queue.lock();
            if q.try_reserve(1).is_err() {
                // Nowhere to put it: report the failure rather than dropping
                // the request, which would strand its submitter forever.
                drop(q);
                super::run::fail(&req, syscall::errno::Errno::Enomem);
                return;
            }
            q.push_back(req);
        }
        self.acct[class].wait.wake_all();
    }

    /// Take the next request this class may run. A ring already running as
    /// many requests of this class as it registered a limit for is skipped,
    /// not blocked: another ring's work must not wait behind it. # C: O(N_q)
    pub fn take(&'static self, class: usize) -> Option<Arc<IoReq>> {
        let mut q = self.acct[class].queue.lock();
        let n = q.len();
        for _ in 0..n {
            let req = q.pop_front()?;
            // A barrier entry starts only once every earlier request of its
            // ring has completed; that is the whole of what it asks for.
            let blocked = crate::io_uring_abi::link::wants_drain(req.sqe.flags)
                && req.ring.inflight_reqs().iter().any(|r| !Arc::ptr_eq(r, &req));
            if !blocked && req.ring.iowq_admits(class) { return Some(req); }
            q.push_back(req);
        }
        None
    }

    /// Arm `req` on its deadline. # C: O(1)
    pub fn arm_timer(&'static self, req: &Arc<IoReq>) {
        {
            let mut t = self.timers.lock();
            if t.try_reserve(1).is_err() { return; }
            t.push(Arc::downgrade(req));
        }
        // Both classes park on the clock, so both must re-read it.
        for a in self.acct.iter() { a.wait.wake_all(); }
    }

    /// Every armed request whose deadline has passed, dropping the entries of
    /// requests that finished some other way. Returns the earliest deadline
    /// still armed. # C: O(N_armed)
    pub fn expired(&'static self, now: u64) -> (alloc::vec::Vec<Arc<IoReq>>, u64) {
        let mut fired = alloc::vec::Vec::new();
        let mut next = 0u64;
        let mut t = self.timers.lock();
        t.retain(|w| {
            let Some(r) = w.upgrade() else { return false };
            if r.is_done() { return false; }
            if crate::io_uring::timeout::is_due(&r, now) {
                if fired.try_reserve(1).is_ok() { fired.push(r); }
                return false;
            }
            let d = r.inner.lock().deadline;
            if d == 0 { return true; }
            if next == 0 || d < next { next = d; }
            true
        });
        (fired, next)
    }

    /// Start the pool if it is not already running. # C: O(N_threads) once
    pub fn start(&'static self) {
        if self.started.swap(true, Ordering::AcqRel) { return; }
        for (class, n) in [(acct::BOUND, BOUND_THREADS), (acct::UNBOUND, UNBOUND_THREADS)] {
            for _ in 0..n {
                if super::worker::spawn(class).is_err() { break; }
                self.acct[class].threads.fetch_add(1, Ordering::AcqRel);
            }
        }
    }

    /// How long a worker may sleep before it must look at the clock again: the
    /// nearest armed deadline, or the backstop when nothing is armed.
    /// # C: O(N_armed)
    pub fn park_deadline(&'static self, now: u64) -> u64 {
        let mut soonest = 0u64;
        for w in self.timers.lock().iter() {
            let Some(r) = w.upgrade() else { continue };
            let d = r.inner.lock().deadline;
            if d != 0 && (soonest == 0 || d < soonest) { soonest = d; }
        }
        let backstop = now.saturating_add(BACKSTOP_NS);
        if soonest != 0 && soonest < backstop { soonest } else { backstop }
    }
}

/// The processors workers may run on, as a mask. `0` = every processor.
/// # C: O(1)
pub fn cpu_mask() -> u64 { WQ.cpu_mask.load(Ordering::Acquire) }

/// Restrict workers to `mask`. # C: O(1)
pub fn set_cpu_mask(mask: u64) { WQ.cpu_mask.store(mask, Ordering::Release); }
