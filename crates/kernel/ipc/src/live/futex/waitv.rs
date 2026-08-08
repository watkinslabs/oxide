use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

use sched::Task;
use syscall::errno::Errno;

use super::core::{WaitvGroup, current_key, load_user_u32, now_monotonic_ns, remove_waitv_group, WAITV_GROUPS};

/// One entry of a `futex_waitv` array, after per-entry flag validation.
///
/// `private` is PER ENTRY, not per call: `struct futex_waitv` carries its own
/// flags word, so one array may mix a process-private futex with a shared one.
/// Folding them into a single call-wide flag (the previous shape here) computed
/// the wrong key for every entry that disagreed with the fold, so those wakes
/// were silently lost.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WaitvEntry {
    pub uaddr: u64,
    pub val: u32,
    pub private: bool,
}

/// Multi-futex wait: park current task on N keys; resume when ANY of them is
/// woken (returns the index that woke). Pre-flight: if any `*uaddr != val` at
/// entry, return `-EAGAIN` immediately.
///
/// `deadline_ns` is an absolute monotonic deadline (0 = none); an expired
/// deadline wakes the task through the same scanner single-futex waits use.
/// Loops on a spurious wakeup exactly as `wait::wait_loop` does — a wake that
/// is neither a real key match, an elapsed deadline, nor a deliverable signal
/// retries instead of returning a fake success.
/// # C: O(N) pre-flight + O(N) park-enqueue + O(W) timeout cleanup
pub fn dispatch_waitv_timed(entries: &[WaitvEntry], deadline_ns: u64) -> i64 {
    if entries.is_empty() { return -(Errno::Einval.as_i32() as i64); }
    let mut keys: Vec<_> = Vec::with_capacity(entries.len());
    for ent in entries {
        if ent.uaddr == 0 || ent.uaddr >= hal::USER_VA_END || (ent.uaddr & 0x3) != 0 {
            return -(Errno::Einval.as_i32() as i64);
        }
        // SAFETY: bounded user VA validated; CR3 is current's.
        let cur_val = unsafe { load_user_u32(ent.uaddr) };
        if cur_val != ent.val { return -(Errno::Eagain.as_i32() as i64); }
        let key = match current_key(ent.uaddr, ent.private) {
            Some(k) => k, None => return -(Errno::Einval.as_i32() as i64),
        };
        keys.push(key);
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    loop {
        let raw = cur as *const Task;
        // SAFETY: cur is the running task on this CPU; bump strong count is sound.
        unsafe { Arc::increment_strong_count(raw); }
        // SAFETY: matching Arc::from_raw consumes the bumped ref.
        let arc = unsafe { Arc::from_raw(raw) };
        let group = Arc::new(WaitvGroup {
            keys: keys.clone(), task: arc.clone(), woken_idx: AtomicI32::new(-1),
        });
        {
            let mut groups = WAITV_GROUPS.lock();
            for ent in entries {
                // SAFETY: bounded user VA validated above; CR3 is the caller's.
                if unsafe { load_user_u32(ent.uaddr) } != ent.val {
                    return -(Errno::Eagain.as_i32() as i64);
                }
            }
            arc.set_state(sched::TaskState::Sleeping);
            cur.futex_uaddr.store(entries[0].uaddr, core::sync::atomic::Ordering::Relaxed);
            groups.push(group.clone());
        }
        // Armed after the group is published and the task is Sleeping — same
        // order as `wait::wait_loop`, and for the same reason: an expiry
        // consumed before `claim_wake` can win is a lost timeout.
        if deadline_ns != 0 {
            sched::hrtimeout::arm_current(deadline_ns, sched::hrtimeout::task_slack_ns(cur));
        }
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
        cur.futex_uaddr.store(0, core::sync::atomic::Ordering::Relaxed);
        sched::hrtimeout::disarm_current();
        let idx = group.woken_idx.load(Ordering::Acquire);
        if idx >= 0 { return idx as i64; }
        // Not woken by a real key match: same classification order as
        // `wait::wait_loop` (Linux `futex_wait_multiple`) — elapsed deadline
        // first, then a deliverable signal, else a spurious wake retries.
        if !remove_waitv_group(&group) { return 0; }
        if deadline_ns != 0 && now_monotonic_ns() >= deadline_ns {
            return -(Errno::Etimedout.as_i32() as i64);
        }
        if sched::live::deliverable_signals_self() != 0 {
            // A pending signal returns -ERESTARTSYS, never a bare -EINTR.
            // Unlike the legacy single-futex wait, the futex2 waiters arm NO
            // restart block even with a timeout — the absolute deadline they
            // re-read on restart is still correct without one. A bare
            // `-EINTR` here would lose the SA_RESTART restart entirely.
            return syscall::restart::restart_sys();
        }
        // Spurious: loop and re-wait.
    }
}
