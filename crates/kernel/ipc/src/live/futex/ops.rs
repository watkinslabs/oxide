use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use sched::TaskState;
use syscall::errno::Errno;

use super::core::{current_key, load_user_u32, store_user_u32, wake_key, WAITERS};

/// Requeue (slot 456): wake up to `nr_wake` waiters on `src_uaddr`, then move
/// up to `nr_requeue` of the REMAINING `src` waiters onto `dst_uaddr` (re-key,
/// no wake). Returns the number of waiters woken (Linux futex-requeue
/// semantics). Single-key waiters only — waitv groups are left untouched.
/// # C: O(W)
pub fn requeue(src_uaddr: u64, dst_uaddr: u64, nr_wake: usize, nr_requeue: usize, private: bool) -> i64 {
    let src = match current_key(src_uaddr, private) { Some(k) => k, None => return -(Errno::Einval.as_i32() as i64) };
    let dst = match current_key(dst_uaddr, private) { Some(k) => k, None => return -(Errno::Einval.as_i32() as i64) };
    let mut woken: Vec<Arc<sched::Task>> = Vec::new();
    {
        let mut w = WAITERS.lock();
        let mut i = 0;
        while i < w.len() && woken.len() < nr_wake {
            if w[i].key == src { woken.push(w.swap_remove(i).task); } else { i += 1; }
        }
        let mut moved = 0;
        for waiter in w.iter_mut() {
            if moved >= nr_requeue { break; }
            if waiter.key == src { waiter.key = dst; moved += 1; }
        }
    }
    if !woken.is_empty() {
        if let Some(rq) = sched::live::global() {
            let mut inner = rq.inner.lock();
            for t in &woken {
                t.set_state(TaskState::Runnable);
                t.lift_vruntime(inner.cfs.min_vruntime());
                inner.enqueue(t.clone());
            }
            rq.nr_running.store(inner.nr_running(), Ordering::Release);
            sched::live::preempt::set_need_resched();
        }
    }
    woken.len() as i64
}

/// `FUTEX_CMP_REQUEUE` (classic op 4): like `requeue`, but first verify
/// `*src_uaddr == cmpval` (the futex word the caller last saw) — if it changed,
/// return EAGAIN so the caller retries instead of requeueing stale waiters.
/// This is what glibc's pthread_cond_broadcast / older condvars use to move
/// waiters from the cond futex onto the associated mutex. # C: O(W)
pub fn cmp_requeue(src_uaddr: u64, dst_uaddr: u64, nr_wake: usize, nr_requeue: usize, cmpval: u32, private: bool) -> i64 {
    if src_uaddr == 0 || src_uaddr >= hal::USER_VA_END || (src_uaddr & 0x3) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: bounded user VA validated; CR3 is current's.
    let cur = unsafe { load_user_u32(src_uaddr) };
    if cur != cmpval { return -(Errno::Eagain.as_i32() as i64); }
    requeue(src_uaddr, dst_uaddr, nr_wake, nr_requeue, private)
}

/// `FUTEX_WAKE_OP` (classic op 5): atomically apply an op to `*uaddr2`, wake up
/// to `nr_wake` waiters on `uaddr1`, then if the OLD `*uaddr2` satisfies the
/// encoded comparison, wake up to `nr_wake2` waiters on `uaddr2`. Linux
/// `futex_wake_op` — glibc uses it in some condvar/lock fast paths. The RMW is
/// atomic by the single-CPU preempt-off syscall invariant. # C: O(W)
pub fn wake_op(uaddr1: u64, uaddr2: u64, nr_wake: usize, nr_wake2: usize, encoded: u32, private: bool) -> i64 {
    for ua in [uaddr1, uaddr2] {
        if ua == 0 || ua >= hal::USER_VA_END || (ua & 0x3) != 0 {
            return -(Errno::Einval.as_i32() as i64);
        }
    }
    let op = (encoded >> 28) & 0x7;
    let oparg_shift = (encoded >> 28) & 0x8 != 0;
    let cmp = (encoded >> 24) & 0xf;
    let mut oparg = ((encoded >> 12) & 0xfff) as i32;
    let cmparg = (encoded & 0xfff) as i32;
    if oparg_shift { oparg = 1i32 << (oparg & 0x1f); }
    // SAFETY: bounded user VA validated; CR3 is current's; preempt-off makes the
    // read-modify-write atomic vs other tasks on this UP CPU.
    let oldval = unsafe { load_user_u32(uaddr2) } as i32;
    let newval = match op {
        0 => oparg,
        1 => oldval.wrapping_add(oparg),
        2 => oldval | oparg,
        3 => oldval & !oparg,
        4 => oldval ^ oparg,
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    // SAFETY: same validated user word; CPL=0 store through the active CR3.
    unsafe { store_user_u32(uaddr2, newval as u32); }
    let k1 = match current_key(uaddr1, private) { Some(k) => k, None => return -(Errno::Einval.as_i32() as i64) };
    let mut woken = wake_key(k1, nr_wake);
    let do_wake2 = match cmp {
        0 => oldval == cmparg,
        1 => oldval != cmparg,
        2 => oldval < cmparg,
        3 => oldval <= cmparg,
        4 => oldval > cmparg,
        5 => oldval >= cmparg,
        _ => false,
    };
    if do_wake2 {
        if let Some(k2) = current_key(uaddr2, private) { woken += wake_key(k2, nr_wake2); }
    }
    woken as i64
}
