use alloc::sync::Arc;
use core::sync::atomic::AtomicU32;

use sched::Task;
use syscall::errno::Errno;

use super::super::core::{Key, now_monotonic_ns};
use super::lock::{grant_kind, unqueue};
use super::state::Grant;

/// Block until this task is granted ownership of a PI futex, or the wait ends.
///
/// The classification order matches the non-PI `wait_loop` and Linux's own:
/// a real grant beats everything (the handoff already wrote the user word and
/// there is no way to give it back), then an elapsed deadline, then a signal,
/// and anything else is a spurious wake that re-parks.
///
/// An interrupted `futex_lock_pi` returns `-ERESTARTNOINTR`, NOT `-EINTR` and
/// not `-ERESTARTSYS`: Linux ends `futex_lock_pi` with
/// `ret != -EINTR ? ret : -ERESTARTNOINTR`, so the lock attempt is resumed even
/// for a handler installed WITHOUT `SA_RESTART`. Surfacing `EINTR` here instead
/// would make `pthread_mutex_lock` on a `PTHREAD_PRIO_INHERIT` mutex fail
/// spuriously, which its callers do not expect and glibc does not retry.
/// # C: O(1) expected
pub(super) fn park_for_grant(me: &Arc<Task>, grant: &AtomicU32, key: Key, tid: u32, deadline_ns: u64)
    -> Result<(), i64>
{
    loop {
        if deadline_ns != 0 {
            sched::hrtimeout::arm_current(deadline_ns, sched::hrtimeout::task_slack_ns(me));
        }
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
        sched::hrtimeout::disarm_current();
        match grant_kind(grant) {
            Grant::Owner | Grant::OwnerDied => return Ok(()),
            Grant::Pending => {}
        }
        if deadline_ns != 0 && now_monotonic_ns() >= deadline_ns {
            unqueue(key, tid);
            // Re-check: the handoff may have landed between the deadline test
            // and the dequeue, and a granted mutex must never be dropped.
            if grant_kind(grant) != Grant::Pending { return Ok(()); }
            return Err(-(Errno::Etimedout.as_i32() as i64));
        }
        if sched::live::deliverable_signals_self() != 0 {
            unqueue(key, tid);
            if grant_kind(grant) != Grant::Pending { return Ok(()); }
            return Err(syscall::restart::restart_nointr());
        }
        me.set_state(sched::TaskState::Sleeping);
    }
}
