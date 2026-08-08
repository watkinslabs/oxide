// Waiting for completions.
//
// `IORING_ENTER_GETEVENTS` asks for `min_complete` completions to be available
// before the call returns. Three things end the wait: enough completions, the
// caller's timeout, or a signal. A timeout reports ETIME and a signal EINTR,
// but either is downgraded to success when there is anything at all to reap —
// the caller has work to do, so telling it about the timeout would be noise.
//
// `min_wait_usec` is a batching floor, not a second timeout: the wait does not
// return early during that window unless completions actually arrived, and
// once the window passes with nothing to show, the FIRST completion ends the
// wait rather than the full `min_complete` batch.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring_abi::enter::{should_wake, wait_min_events, ExtArg};
use crate::poll::poll_common::monotonic_ns;

use super::ctx::{state, IoUringInode};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The clock the ring measures its wait timeouts against. # C: O(1)
fn clock_now(clockid: u32) -> u64 {
    use crate::io_uring::rsrc::CLOCK_BOOTTIME;
    if clockid == CLOCK_BOOTTIME { timekeeper::boottime_ns() } else { monotonic_ns() }
}

/// The wait's deadline, expressed on the monotonic clock the parking layer
/// uses. An ABSOLUTE timeout is stated on the ring's registered clock, so it
/// is rebased here rather than compared against the wrong origin.
/// # C: O(1)
fn deadline_of(ext: &ExtArg, clockid: u32) -> Option<u64> {
    let (sec, nsec) = ext.ts?;
    let total = syscall::time::timespec_to_ns(sec, nsec).ok()?;
    let mono = monotonic_ns();
    if !ext.abs { return Some(mono.saturating_add(total)); }
    let base = clock_now(clockid);
    Some(mono.saturating_add(total.saturating_sub(base)))
}

/// Park until `cond` holds, the deadline passes, or a signal arrives.
/// `deadline == 0` means no timeout. # C: O(N_wakeups)
fn park(inode: &Arc<IoUringInode>, deadline: u64, cond: impl FnMut() -> bool)
    -> sched::task::WaitOutcome
{
    // SAFETY: process context in the syscall path on the running task's own CPU, holding no spinlock and no submission lock.
    unsafe {
        sched::live::wait_event(&inode.cq_wait, sched::task::WaitState::Interruptible,
                                deadline, monotonic_ns, cond)
    }
}

/// The `min_complete` wait. Returns 0, `-ETIME`, `-EINTR` or `-EBADR`.
/// # C: O(N_wakeups)
pub fn cq_wait(inode: &Arc<IoUringInode>, min_complete: u32, ext: &ExtArg) -> i64 {
    use crate::io_uring_abi::enter::wait_result;
    use sched::task::WaitOutcome;

    let cq_entries = { let r = inode.ring.lock(); r.cq_entries };
    let min = wait_min_events(min_complete, cq_entries);
    inode.flush_overflow();
    if should_wake(inode.cq_ready(), min) { return 0; }

    let clockid = inode.reg.lock().clockid;
    let start = monotonic_ns();
    let deadline = deadline_of(ext, clockid).unwrap_or(0);
    let started_with = inode.cq_ready();

    // The batching window: hold out for the full batch until it passes.
    if ext.min_wait_ns > 0 {
        let min_deadline = start.saturating_add(ext.min_wait_ns);
        let stop = if deadline != 0 && deadline < min_deadline { deadline } else { min_deadline };
        match park(inode, stop, || should_wake(inode.cq_ready(), min)) {
            WaitOutcome::Interrupted => return finish(inode, err(Errno::Eintr)),
            WaitOutcome::Ready => return finish(inode, 0),
            WaitOutcome::TimedOut => {
                inode.flush_overflow();
                // Anything that arrived during the window ends the wait.
                if inode.cq_ready() != started_with || inode.cq_ready() > 0 { return finish(inode, 0); }
                if deadline != 0 && monotonic_ns() >= deadline {
                    return finish(inode, wait_result(err(Errno::Etime), inode.cq_nonempty()));
                }
            }
        }
        // Past the window a single completion is enough.
        return match park(inode, deadline, || inode.cq_ready() > 0) {
            WaitOutcome::Ready       => finish(inode, 0),
            WaitOutcome::Interrupted => finish(inode, wait_result(err(Errno::Eintr), inode.cq_nonempty())),
            WaitOutcome::TimedOut    => finish(inode, wait_result(err(Errno::Etime), inode.cq_nonempty())),
        };
    }

    match park(inode, deadline, || should_wake(inode.cq_ready(), min)) {
        WaitOutcome::Ready       => finish(inode, 0),
        WaitOutcome::Interrupted => finish(inode, wait_result(err(Errno::Eintr), inode.cq_nonempty())),
        WaitOutcome::TimedOut    => finish(inode, wait_result(err(Errno::Etime), inode.cq_nonempty())),
    }
}

/// Flush what the wait made room for, and report a dropped completion once.
/// # C: O(N_flushed)
fn finish(inode: &Arc<IoUringInode>, rv: i64) -> i64 {
    inode.flush_overflow();
    if inode.clear_state(state::CQE_DROPPED) { return err(Errno::Ebadr); }
    rv
}
