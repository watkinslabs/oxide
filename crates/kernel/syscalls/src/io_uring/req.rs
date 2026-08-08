// One in-flight request.
//
// An entry that completes inside the submission that issued it needs no object
// at all — it is read, run and reported before the next entry is looked at.
// Everything else does: a timeout has to sit until its clock runs out, a poll
// until its description becomes ready, and a punted operation until a worker
// picks it up. All three can be cancelled while they wait, all three can be
// the head of a link chain whose remainder must run afterwards, and all three
// outlive the syscall that submitted them. That is what this object is.
//
// Ownership: the ring owns nothing here. The request holds a strong reference
// to its ring — which is what keeps a ring alive while work of its own is
// outstanding — and the ring's in-flight table holds only weak references, so
// the table can never be the thing that keeps a finished request alive.
//
// Exactly-once completion is the invariant the whole file exists to keep. A
// request can be reached at the same instant by its worker, by a cancellation
// and by its own deadline; `claim` is the single compare-exchange all three go
// through, so precisely one of them posts the completion.

use alloc::sync::{Arc, Weak};

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as ReqLockClass};

use crate::io_uring_sqe::Sqe;

use super::ctx::IoUringInode;
use super::personality::CredSnapshot;

/// Request lifetime states.
pub mod st {
    /// Waiting: queued for a worker, armed on a clock, or armed on a poll.
    pub const ARMED: u32 = 0;
    /// A worker or a callback owns it and will report its result.
    pub const RUNNING: u32 = 1;
    /// Its completion has been posted; nothing else may post another.
    pub const DONE: u32 = 2;
}

/// Why a request stopped waiting.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Wake {
    /// Run it.
    Run,
    /// Its deadline passed.
    Expired,
    /// Somebody cancelled it.
    Canceled,
}

/// The mutable half of a request, behind one lock so no two of its fields can
/// be seen mid-update against each other.
#[derive(Default)]
pub struct ReqInner {
    /// The rest of this request's link chain, started when it completes.
    pub link: Option<Arc<IoReq>>,
    /// The `IORING_OP_LINK_TIMEOUT` guarding this request.
    pub ltimeout: Option<Arc<IoReq>>,
    /// For a link timeout: the request it guards. Weak, because the guarded
    /// request holds the timeout — two strong references would be a cycle
    /// neither could ever break.
    pub guarded: Option<Weak<IoReq>>,
    /// Monotonic deadline in nanoseconds; `0` = not armed on a clock.
    pub deadline: u64,
    /// A completion-count timeout fires once the ring's completion counter
    /// reaches this. `0` = not gated on a count.
    pub target_count: u64,
    /// The interval a repeating timeout re-arms with.
    pub interval: u64,
    /// Expiries a bounded repeating timeout has left; `0` with `repeating` is
    /// unbounded.
    pub repeats: u64,
    /// The timeout re-arms after each expiry.
    pub repeating: bool,
    /// Expiry is a normal result rather than a failure.
    pub etime_success: bool,
    /// Readiness an armed poll is waiting for; `0` = not armed on a poll.
    pub poll_events: u32,
    /// The armed poll reports every readiness change, not just the first.
    pub poll_multi: bool,
    /// The description an armed poll is subscribed to.
    pub poll_subs: Option<Arc<vfs::PollSubscribers>>,
    /// The request is a punted operation being retried after its poll fired.
    pub poll_retry: bool,
    /// The description an armed poll reads its readiness from.
    pub poll_file: Option<Arc<vfs::File>>,
    /// The readiness callback registered on that description. Owned here
    /// because the description holds only a weak reference to it.
    pub poll_waker: Option<Arc<super::poll::PollWaker>>,
}

/// One request the ring is still to finish.
pub struct IoReq {
    pub ring: Arc<IoUringInode>,
    pub sqe: Sqe,
    /// The completion this request will be reported under. Held apart from
    /// the entry's wire image because `IORING_OP_POLL_REMOVE`'s update form
    /// replaces it on an already-armed request.
    user_data: AtomicU64,
    /// The credentials the operation runs under, taken at submission.
    pub creds: Option<Arc<CredSnapshot>>,
    /// The address space, descriptor table and credentials a worker borrows to
    /// run this request as the task that submitted it.
    pub owner: Arc<super::iowq::Owner>,
    state: AtomicU32,
    pub inner: Spinlock<ReqInner, ReqLockClass>,
}

impl IoReq {
    /// # C: O(1)
    pub fn new(ring: &Arc<IoUringInode>, sqe: &Sqe, creds: Option<Arc<CredSnapshot>>,
               owner: Arc<super::iowq::Owner>) -> Arc<Self>
    {
        Arc::new(Self {
            ring: Arc::clone(ring), sqe: *sqe, creds, owner,
            user_data: AtomicU64::new(sqe.user_data),
            state: AtomicU32::new(st::ARMED),
            inner: Spinlock::new(ReqInner::default()),
        })
    }

    /// # C: O(1)
    pub fn user_data(&self) -> u64 { self.user_data.load(Ordering::Acquire) }

    /// # C: O(1)
    pub fn set_user_data(&self, v: u64) { self.user_data.store(v, Ordering::Release); }

    /// # C: O(1)
    pub fn opcode(&self) -> u8 { self.sqe.opcode }

    /// # C: O(1)
    pub fn state(&self) -> u32 { self.state.load(Ordering::Acquire) }

    /// Take ownership of a waiting request. Exactly one caller wins; every
    /// later one sees it already claimed. This is what makes "a completion is
    /// posted once" true in the face of a worker, a cancellation and a
    /// deadline arriving together. # C: O(1)
    pub fn claim(&self) -> bool {
        self.state.compare_exchange(st::ARMED, st::RUNNING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Put a claimed request back into the waiting state — a repeating timeout
    /// or a re-armed multishot poll is not finished. # C: O(1)
    pub fn rearm(&self) { self.state.store(st::ARMED, Ordering::Release); }

    /// Mark a claimed request finished. # C: O(1)
    pub fn finish(&self) { self.state.store(st::DONE, Ordering::Release); }

    /// # C: O(1)
    pub fn is_done(&self) -> bool { self.state() == st::DONE }
}

/// Every request one ring still owes a completion for.
///
/// Weak on purpose: a request that has completed and been dropped must not be
/// kept alive by the table that exists to find it, and a stale entry is
/// harmless because upgrading it fails. Entries are swept whenever the table
/// is walked, so the sweep costs nothing the walk was not already paying.
#[derive(Default)]
pub struct InFlight {
    reqs: alloc::vec::Vec<Weak<IoReq>>,
}

impl InFlight {
    /// # C: O(1) amortised
    pub fn insert(&mut self, req: &Arc<IoReq>) {
        if self.reqs.try_reserve(1).is_err() { return; }
        self.reqs.push(Arc::downgrade(req));
    }

    /// Drop the entries whose requests are gone or finished. # C: O(N)
    pub fn sweep(&mut self) {
        self.reqs.retain(|w| w.upgrade().is_some_and(|r| !r.is_done()));
    }

    /// Every live request, oldest first. # C: O(N)
    pub fn live(&self) -> alloc::vec::Vec<Arc<IoReq>> {
        self.reqs.iter().filter_map(|w| w.upgrade()).filter(|r| !r.is_done()).collect()
    }

    /// # C: O(N)
    pub fn len(&self) -> usize { self.reqs.iter().filter(|w| w.strong_count() > 0).count() }
}
