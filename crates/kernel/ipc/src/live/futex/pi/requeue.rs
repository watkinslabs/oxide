use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU32;

use sched::{Task, TaskState};
use syscall::errno::Errno;

use crate::futex_pi_rules::{PiLockStep, lock_pi_step};

use super::super::core::{cmpxchg_user_u32, current_key, load_user_u32};
use super::lock::{current_arc, read_word};
use super::state::{Grant, PI_TABLE, PiState, PiWaiter, find, grant_and_wake, reboost};

fn e(err: Errno) -> i64 { -(err.as_i32() as i64) }

/// `FUTEX_WAIT_REQUEUE_PI` — Linux `futex_wait_requeue_pi`.
///
/// Parks on the NON-PI futex `uaddr` (a condition variable) after checking
/// `*uaddr == val`, having declared up front that the only thing allowed to
/// wake it is a `FUTEX_CMP_REQUEUE_PI` moving it onto the PI futex `uaddr2`
/// (the associated mutex). It returns owning `uaddr2`.
///
/// Declaring the target is what makes the pairing safe: a plain `FUTEX_WAKE` on
/// the condvar must NOT release this waiter, because it would return to
/// userspace believing it holds a mutex nobody handed it.
/// # C: O(S) enqueue; blocks
pub fn wait_requeue_pi(uaddr: u64, val: u32, bitset: u32, uaddr2: u64, private: bool, deadline_ns: u64)
    -> i64
{
    if uaddr == uaddr2 { return e(Errno::Einval); }
    if bitset == 0 { return e(Errno::Einval); }
    for ua in [uaddr, uaddr2] {
        if ua == 0 || ua >= hal::USER_VA_END { return e(Errno::Efault); }
        if (ua & 0x3) != 0 { return e(Errno::Einval); }
    }
    let Some(me) = current_arc() else { return e(Errno::Einval) };
    let Some(key1) = current_key(uaddr, private) else { return e(Errno::Einval) };
    let Some(key2) = current_key(uaddr2, private) else { return e(Errno::Einval) };
    let grant = Arc::new(AtomicU32::new(Grant::Pending as u32));
    {
        let mut tbl = PI_TABLE.lock();
        // SAFETY: bounded, 4-aligned user word; the caller's CR3 is active.
        if unsafe { load_user_u32(uaddr) } != val { return e(Errno::Eagain); }
        let i = match find(&tbl, key1) {
            Some(i) => i,
            None => {
                // The SOURCE futex needs a parking slot even though it has no
                // PI owner: the requeue has to find this waiter by key.
                tbl.push(PiState { key: key1, uaddr, owner: None, owner_tid: 0, waiters: Vec::new() });
                tbl.len() - 1
            }
        };
        tbl[i].waiters.push(PiWaiter {
            task: me.clone(), tid: me.tid, grant: grant.clone(), requeue_target: Some(key2) });
        me.set_state(TaskState::Sleeping);
    }
    match super::park::park_for_grant(&me, &grant, key1, me.tid, deadline_ns) {
        Ok(()) => 0,
        Err(rv) => { super::lock::unqueue(key2, me.tid); rv }
    }
}

/// `FUTEX_CMP_REQUEUE_PI` — Linux `futex_requeue(..., requeue_pi = 1)`.
///
/// Moves `FUTEX_WAIT_REQUEUE_PI` waiters off the condition variable `uaddr1`
/// onto the PI mutex `uaddr2`. At most ONE waiter is woken, and only when the
/// mutex is uncontended so the requeue can acquire it on that waiter's behalf;
/// the rest are queued as PI waiters and are released by the eventual
/// `FUTEX_UNLOCK_PI`.
/// # C: O(S + N_waiters)
pub fn cmp_requeue_pi(uaddr1: u64, uaddr2: u64, nr_wake: i64, nr_requeue: i64, cmpval: u32,
                      private: bool) -> i64
{
    if uaddr1 == uaddr2 { return e(Errno::Einval); }
    if nr_wake < 0 || nr_requeue < 0 { return e(Errno::Einval); }
    // Waking more than one waiter cannot be made correct: only the waiter the
    // requeue actually acquires the mutex for may return to userspace.
    if nr_wake != 1 { return e(Errno::Einval); }
    for ua in [uaddr1, uaddr2] {
        if ua == 0 || ua >= hal::USER_VA_END { return e(Errno::Efault); }
        if (ua & 0x3) != 0 { return e(Errno::Einval); }
    }
    let Some(key1) = current_key(uaddr1, private) else { return e(Errno::Einval) };
    let Some(key2) = current_key(uaddr2, private) else { return e(Errno::Einval) };

    let mut boost: Option<(Arc<Task>, Vec<sched::SchedClass>)> = None;
    let moved;
    {
        let mut tbl = PI_TABLE.lock();
        let uval1 = match read_word(uaddr1) { Ok(v) => v, Err(err) => return e(err) };
        if uval1 != cmpval { return e(Errno::Eagain); }
        let Some(src) = find(&tbl, key1) else { return 0 };

        // Try to acquire the PI mutex on the top waiter's behalf. `set_waiters`
        // is forced so the word carries FUTEX_WAITERS even on an uncontended
        // take — a waiter is about to be attached to it.
        let uval2 = match read_word(uaddr2) { Ok(v) => v, Err(err) => return e(err) };
        let mut woken = 0i64;
        if let Some(top) = tbl[src].waiters.iter().position(|w| w.requeue_target == Some(key2)) {
            let wtid = tbl[src].waiters[top].tid;
            let have2 = find(&tbl, key2).is_some();
            if let Ok(PiLockStep::TakeUncontended { newval }) =
                lock_pi_step(uval2, wtid, have2, true)
            {
                // SAFETY: 4-aligned user word verified present+writable by
                // `read_word`; single naturally-aligned RMW under the active AS.
                if unsafe { cmpxchg_user_u32(uaddr2, uval2, newval) } == uval2 {
                    let w = tbl[src].waiters.swap_remove(top);
                    grant_and_wake(&w, Grant::Owner);
                    woken = 1;
                }
            }
        }

        // Everything still parked for key2 is requeued onto the PI futex as an
        // ordinary PI waiter; ownership now reaches it through UNLOCK_PI.
        let mut carry: Vec<PiWaiter> = Vec::new();
        let mut n = 0i64;
        let mut idx = 0;
        while idx < tbl[src].waiters.len() && n < nr_requeue {
            if tbl[src].waiters[idx].requeue_target == Some(key2) {
                let mut w = tbl[src].waiters.swap_remove(idx);
                w.requeue_target = None;
                carry.push(w);
                n += 1;
            } else { idx += 1; }
        }
        if tbl[src].waiters.is_empty() && tbl[src].owner.is_none() { tbl.swap_remove(src); }
        moved = n + woken;
        if !carry.is_empty() {
            let dst = match find(&tbl, key2) {
                Some(i) => i,
                None => {
                    let owner_tid = uval2 & crate::futex_pi_rules::FUTEX_TID_MASK;
                    let owner = sched::live::registry::lookup_by_vpid(owner_tid);
                    tbl.push(PiState { key: key2, uaddr: uaddr2, owner_tid,
                                       owner: owner.clone(), waiters: Vec::new() });
                    tbl.len() - 1
                }
            };
            tbl[dst].waiters.extend(carry);
            let classes = tbl[dst].waiter_classes();
            boost = tbl[dst].owner.clone().map(|o| (o, classes));
        }
    }
    if let Some((owner, classes)) = boost { reboost(&owner, &classes); }
    moved
}

/// True iff `key` currently holds any `FUTEX_WAIT_REQUEUE_PI` waiter. A plain
/// `FUTEX_WAKE`/`FUTEX_REQUEUE` against such a futex is `EINVAL` — Linux
/// refuses to release a requeue-pi waiter through a non-PI path because it
/// would return to userspace holding no mutex.
/// # C: O(S + N_waiters)
pub fn has_requeue_pi_waiter(uaddr: u64, private: bool) -> bool {
    let Some(key) = current_key(uaddr, private) else { return false };
    let tbl = PI_TABLE.lock();
    find(&tbl, key).is_some_and(|i| tbl[i].waiters.iter().any(|w| w.requeue_target.is_some()))
}
