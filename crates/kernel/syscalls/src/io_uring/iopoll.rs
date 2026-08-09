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

use syscall::errno::Errno;

use vfs::File;

use crate::io_uring_abi::iopoll::{after_poll, before_poll, hybrid_runtime, hybrid_sleep_ns,
                                  observe_runtime, precheck, Step};
use crate::io_uring_abi::uapi::{IORING_SETUP_HYBRID_IOPOLL, IORING_SETUP_IOPOLL};

pub mod queued;

use super::ctx::{state, IoUringInode};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

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

/// The `IORING_ENTER_GETEVENTS` wait for a polled ring.
///
/// Returns 0, or `-EINTR`, or `-EBADR` for a completion this ring lost. It may
/// return success having reaped FEWER than `min_complete` completions, and
/// that is the contract rather than a shortfall: a request that has not
/// reached a backend yet cannot be polled for, and a caller of a polled ring
/// is expected to come back. A loop that instead span until the count was met
/// would never exit for such a request.
/// # C: O(spin until min_complete or a break condition)
pub fn cq_poll(inode: &Arc<IoUringInode>, min_complete: u32) -> i64 {
    use crate::io_uring_abi::enter::wait_min_events;

    let cq_entries = { let r = inode.ring.lock(); r.cq_entries };
    let min = wait_min_events(min_complete, cq_entries);
    inode.flush_overflow();

    if let Some(r) = precheck(inode.test_state(state::CQE_DROPPED), inode.cq_ready()) {
        return match r { Ok(()) => 0, Err(e) => { inode.clear_state(state::CQE_DROPPED); err(e) } };
    }

    loop {
        let files = targets(inode);
        let multi = files.len() > 1;
        match before_poll(files.len() as u32, min, multi) {
            Step::Stop => break,
            Step::Interrupted => return err(Errno::Eintr),
            Step::Poll { oneshot: _ } => {
                let timed = if hybrid(inode) { hybrid_sleep(inode) } else { None };
                poll_once(&files);
                // The backends have run their completions; turn the ones that
                // finished into CQEs. This is the reference's `io_do_iopoll`
                // second pass, and it is what a polled transfer's completion
                // comes from at all — nothing else looks at it.
                queued::reap(inode);
                if let Some((slept, issued_at)) = timed { hybrid_observe(inode, slept, issued_at); }
                inode.flush_overflow();
                // A spinning caller must still let whatever the poll made
                // runnable actually run — the worker that owns the request is
                // the thing that posts its completion, and it cannot do that
                // while this task holds the processor.
                if sched::live::global().is_some() {
                    // SAFETY: process context in the syscall path on the running task's own CPU, holding no spinlock and no submission lock; the task stays runnable across the yield.
                    unsafe { sched::live::sched_yield(); }
                }
                // The same predicate the sleeping wait uses to break out, so a
                // polled ring and an ordinary one agree about what a signal is.
                let sig = sched::live::current().is_some_and(|t| {
                    sched::signal_pending_state(&t, sched::WaitState::Interruptible)
                });
                match after_poll(inode.cq_ready(), min, sig, sched::live::preempt::need_resched()) {
                    Step::Interrupted => return err(Errno::Eintr),
                    Step::Stop => break,
                    Step::Poll { .. } => continue,
                }
            }
        }
    }

    inode.flush_overflow();
    if inode.clear_state(state::CQE_DROPPED) { return err(Errno::Ebadr); }
    0
}
