use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

use sched::Task;
use syscall::errno::Errno;

use super::core::{WaitvGroup, current_key, load_user_u32, now_monotonic_ns, remove_waitv_group, WAITV_GROUPS};

/// Multi-futex wait: park current task on N keys; resume when ANY
/// of them is woken (returns the index that woke). Pre-flight
/// check: if any `*uaddr != val` at entry, return -EAGAIN
/// immediately per Linux semantics. `vals` is parallel to `uaddrs`.
/// # C: O(N) pre-flight + O(N) park-enqueue + O(1) park
pub fn dispatch_waitv(uaddrs: &[u64], vals: &[u32], private: bool) -> i64 {
    dispatch_waitv_timed(uaddrs, vals, private, 0)
}

/// `dispatch_waitv` plus an absolute monotonic deadline. Linux futex waitv
/// waits may be timed; an expired deadline wakes the task through the same
/// `wakeup_deadline_ns` scanner used by single-futex waits. Loops on a
/// spurious wakeup exactly as `wait::wait_loop` / Linux `futex_wait_multiple`
/// does — a wake that is neither a real key match, an elapsed deadline, nor a
/// deliverable signal retries instead of returning a fake success.
/// # C: O(N) pre-flight + O(N) park-enqueue + O(W) timeout cleanup
pub fn dispatch_waitv_timed(uaddrs: &[u64], vals: &[u32], private: bool, deadline_ns: u64) -> i64 {
    if uaddrs.is_empty() || uaddrs.len() != vals.len() {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut keys: Vec<_> = Vec::with_capacity(uaddrs.len());
    for (i, &ua) in uaddrs.iter().enumerate() {
        if ua == 0 || ua >= hal::USER_VA_END || (ua & 0x3) != 0 {
            return -(Errno::Einval.as_i32() as i64);
        }
        // SAFETY: bounded user VA validated; CR3 is current's.
        let cur_val = unsafe { load_user_u32(ua) };
        if cur_val != vals[i] { return -(Errno::Eagain.as_i32() as i64); }
        let key = match current_key(ua, private) {
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
        if deadline_ns != 0 {
            cur.wakeup_deadline_ns.store(deadline_ns, core::sync::atomic::Ordering::Release);
        }
        {
            let mut groups = WAITV_GROUPS.lock();
            for (i, &ua) in uaddrs.iter().enumerate() {
                // SAFETY: bounded user VA validated above; CR3 is the caller's.
                if unsafe { load_user_u32(ua) } != vals[i] {
                    cur.wakeup_deadline_ns.store(0, core::sync::atomic::Ordering::Release);
                    return -(Errno::Eagain.as_i32() as i64);
                }
            }
            arc.set_state(sched::TaskState::Sleeping);
            cur.futex_uaddr.store(uaddrs[0], core::sync::atomic::Ordering::Relaxed);
            groups.push(group.clone());
        }
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
        cur.futex_uaddr.store(0, core::sync::atomic::Ordering::Relaxed);
        cur.wakeup_deadline_ns.store(0, core::sync::atomic::Ordering::Release);
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
            return -(Errno::Eintr.as_i32() as i64);
        }
        // Spurious: loop and re-wait.
    }
}
