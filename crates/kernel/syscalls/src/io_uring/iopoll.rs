// The runtime half of `IORING_SETUP_IOPOLL`: driving the backend's poll.
//
// Every decision here — which opcodes a polled ring takes, which files a
// polled transfer may name, when the loop stops — lives in
// [`crate::io_uring_abi::iopoll`], which carries no target gate and is unit
// tested. What is left here is the part that can only be done against a live
// ring: resolving the descriptions with outstanding polled I/O and asking each
// of them, through `FileOps::iopoll`, whether its backend has finished
// anything yet.
//
// A polled ring never sleeps for its completions. `io_uring_enter` with
// `IORING_ENTER_GETEVENTS` spins here instead of parking on the ring's wait
// list, because the completion it is waiting for is one nothing will announce:
// on a polled backend there is no interrupt to wake the waiter, which is the
// whole reason the mode exists.

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::File;

use crate::io_uring_abi::iopoll::{hybrid_runtime, hybrid_sleep_ns, observe_runtime};
use crate::io_uring_abi::uapi::{IORING_SETUP_HYBRID_IOPOLL, IORING_SETUP_IOPOLL};

pub mod queued;

use super::ctx::{state, IoUringInode};

/// Whether this ring finds its completions by polling. # C: O(1)
pub fn polled(inode: &IoUringInode) -> bool { inode.flags & IORING_SETUP_IOPOLL != 0 }

/// Whether this description's backend can be polled for completed I/O at all —
/// Linux `file->f_op->iopoll != NULL`.
///
/// Asked as a capability rather than by polling once and looking at the count:
/// a pollable backend with nothing ready reports zero, which is the same number
/// a backend with no poll would report, and admitting a transfer on that
/// evidence would leave it outstanding forever. # C: O(1)
pub fn file_pollable(file: &File) -> bool { file.can_iopoll() }

/// The description a deferred entry on a polled ring will have outstanding
/// I/O against, or `None` when there is nothing for a poll to find.
///
/// An entry that runs inline has already posted its completion by the time
/// anything could poll for it, so only deferred TRANSFERS are recorded — and
/// only against a backend that can actually be polled, since a description
/// with no poll would put a target in the loop's set that never reaps
/// anything. # C: O(1)
pub fn outstanding_file(inode: &IoUringInode, sqe: &crate::io_uring_sqe::Sqe)
    -> Option<Arc<File>>
{
    use crate::io_uring_abi::ops::*;
    if !polled(inode) { return None; }
    if !matches!(sqe.opcode,
        IORING_OP_READ | IORING_OP_WRITE | IORING_OP_READV | IORING_OP_WRITEV
        | IORING_OP_READ_FIXED | IORING_OP_WRITE_FIXED) { return None; }
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU in the submission path; sole reader of the fd_table slot, which is not mutated across this read.
    let fdt = unsafe { cur.fd_table_ref() }?;
    let file = fdt.clone().get(sqe.fd).ok()?;
    if !file_pollable(&file) { return None; }
    Some(file)
}

/// The descriptions this ring has outstanding polled I/O against — the
/// reference's `ctx->iopoll_list`, reduced to what a poll actually needs.
///
/// Read off the request lists rather than kept beside them: a request leaves
/// them exactly when its completion is posted, so there is no third list to
/// keep in step and no way for a finished request to leave a description behind
/// for the loop to keep polling. Both lists are walked because both can hold a
/// polled transfer — one the backend owns, and one a worker is still to reach.
/// # C: O(N_queued + N_inflight)
fn targets(inode: &Arc<IoUringInode>) -> Vec<Arc<File>> {
    let mut out: Vec<Arc<File>> = Vec::new();
    for req in inode.queued_reqs().into_iter().chain(inode.inflight_reqs()) {
        let Some(f) = req.inner.lock().iopoll_file.clone() else { continue };
        // Deduplicated: one backend asked twice in a pass reaps nothing extra
        // and only costs the lock.
        if out.iter().any(|e| Arc::ptr_eq(e, &f)) { continue; }
        if out.try_reserve(1).is_err() { break; }
        out.push(f);
    }
    out
}

/// One pass over every outstanding backend. Reports how many completions the
/// backends delivered. # C: O(N_targets) poll calls
fn poll_once(files: &[Arc<File>]) -> usize {
    files.iter().filter_map(|f| f.iopoll()).sum()
}

/// Whether this ring sleeps for part of a transfer's expected service time
/// before it starts spinning. # C: O(1)
fn hybrid(inode: &IoUringInode) -> bool { inode.flags & IORING_SETUP_HYBRID_IOPOLL != 0 }

/// The hybrid sleep, and the transfer it is measured against.
///
/// Charged to the OLDEST outstanding transfer that has not paid it yet, which
/// is the one the ring is most likely to be about to complete. Returns how long
/// the pass slept and when that transfer was issued, so the pass can fold its
/// observed service time back into the ring's estimate afterwards.
/// # C: O(N_inflight)
fn hybrid_sleep(inode: &Arc<IoUringInode>) -> Option<(u64, u64)> {
    use core::sync::atomic::Ordering;
    let q = inode.queued_reqs().into_iter()
        .find_map(|r| { let g = r.inner.lock(); g.iopoll_io.clone() })?;
    if !q.take_sleep_turn() { return None; }
    let ns = hybrid_sleep_ns(inode.hybrid_poll_time.load(Ordering::Acquire), false);
    if ns == 0 { return None; }
    let issued_at = q.issued_at();
    // Parked on the ring's own wait list rather than on a bare timer: a
    // completion posted by another task during the window ends the sleep early,
    // which is strictly better than sleeping through it.
    let deadline = timekeeper::monotonic_ns().saturating_add(ns);
    // SAFETY: process context in the syscall path on the running task's own CPU, holding no spinlock and no submission lock.
    unsafe {
        sched::live::wait_event(&inode.cq_wait, sched::WaitState::Interruptible,
                                deadline, timekeeper::monotonic_ns, || false);
    }
    Some((ns, issued_at))
}

/// Fold one pass's observed service time into the ring's estimate.
/// # C: O(1)
fn hybrid_observe(inode: &Arc<IoUringInode>, slept: u64, issued_at: u64) {
    use core::sync::atomic::Ordering;
    let runtime = hybrid_runtime(timekeeper::monotonic_ns(), issued_at, slept);
    let _ = inode.hybrid_poll_time.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |cur| { let n = observe_runtime(cur, runtime); if n == cur { None } else { Some(n) } });
}

/// Drive every outstanding backend once and turn what they finished into
/// completions, reporting how many were posted.
///
/// Both callers of the polled path go through this: the task spinning in
/// `io_uring_enter(IORING_ENTER_GETEVENTS)`, and the submission-polling thread
/// of a ring that is BOTH `IORING_SETUP_SQPOLL` and `IORING_SETUP_IOPOLL`,
/// whose submitter may never enter the kernel at all. # C: O(N_targets)
pub fn drive(inode: &Arc<IoUringInode>) -> usize {
    let files = targets(inode);
    if files.is_empty() { return 0; }
    poll_once(&files);
    queued::reap(inode)
}

/// Whether this ring has transfers a backend still owes a result for — the
/// reference's non-empty `ctx->iopoll_list`. What makes a polled ring work for
/// its poll thread even with an empty submission queue. # C: O(N_queued)
pub fn has_outstanding(inode: &Arc<IoUringInode>) -> bool {
    polled(inode) && inode.has_queued()
}

/// One ring's polled wait, bound to the live ring.
struct LiveWait<'a> { inode: &'a Arc<IoUringInode>, min: u32 }

impl<'a> crate::io_uring_abi::iopoll::seq::PollWait for LiveWait<'a> {
    /// # C: O(1)
    fn min_events(&self) -> u32 { self.min }
    /// # C: O(N_backlog)
    fn flush_overflow(&mut self) { self.inode.flush_overflow(); }
    /// # C: O(1)
    fn dropped(&self) -> bool { self.inode.test_state(state::CQE_DROPPED) }
    /// # C: O(1)
    fn clear_dropped(&mut self) -> bool { self.inode.clear_state(state::CQE_DROPPED) }
    /// # C: O(1)
    fn cq_ready(&mut self) -> u32 { self.inode.cq_ready() }
    /// # C: O(N_queued)
    fn targets(&mut self) -> u32 { targets(self.inode).len() as u32 }
    /// # C: O(1)
    fn hybrid_sleep(&mut self) -> Option<(u64, u64)> {
        if hybrid(self.inode) { hybrid_sleep(self.inode) } else { None }
    }
    /// `oneshot` needs no argument here: no backend in this kernel spins
    /// inside its own poll, so the forbidding is satisfied by construction and
    /// there is nothing to pass on. # C: O(N_targets)
    fn poll_targets(&mut self, _oneshot: bool) { poll_once(&targets(self.inode)); }
    /// # C: O(N_queued)
    fn reap(&mut self) -> usize { queued::reap(self.inode) }
    /// # C: O(1)
    fn hybrid_observe(&mut self, slept: u64, issued_at: u64) {
        hybrid_observe(self.inode, slept, issued_at);
    }
    /// A spinning caller must still let whatever the poll made runnable
    /// actually run — the worker that owns a request is the thing that posts
    /// its completion, and it cannot do that while this task holds the
    /// processor. # C: O(1)
    fn yield_cpu(&mut self) {
        if sched::live::global().is_some() {
            // SAFETY: process context in the syscall path on the running task's own CPU, holding no spinlock and no submission lock; the task stays runnable across the yield.
            unsafe { sched::live::sched_yield(); }
        }
    }
    /// The same predicate the sleeping wait uses to break out, so a polled ring
    /// and an ordinary one agree about what a signal is. # C: O(1)
    fn signal_pending(&mut self) -> bool {
        sched::live::current().is_some_and(|t| {
            sched::signal_pending_state(&t, sched::WaitState::Interruptible)
        })
    }
    /// # C: O(1)
    fn need_resched(&mut self) -> bool { sched::live::preempt::need_resched() }
}

/// The `IORING_ENTER_GETEVENTS` wait for a polled ring.
///
/// Returns 0, or `-EINTR`, or `-EBADR` for a completion this ring lost. It may
/// return success having reaped FEWER than `min_complete` completions, and
/// that is the contract rather than a shortfall: a request that has not
/// reached a backend yet cannot be polled for, and a caller of a polled ring
/// is expected to come back. A loop that instead span until the count was met
/// would never exit for such a request.
///
/// The loop itself — its two early exits and the order it asks its questions
/// in — is [`crate::io_uring_abi::iopoll::seq::poll_wait`].
/// # C: O(spin until min_complete or a break condition)
pub fn cq_poll(inode: &Arc<IoUringInode>, min_complete: u32) -> i64 {
    use crate::io_uring_abi::enter::wait_min_events;
    let cq_entries = { let r = inode.ring.lock(); r.cq_entries };
    let min = wait_min_events(min_complete, cq_entries);
    crate::io_uring_abi::iopoll::seq::poll_wait(&mut LiveWait { inode, min })
}
