use alloc::sync::Arc;
use core::sync::atomic::AtomicU32;

use syscall::errno::Errno;

use crate::futex_pi_rules::{PiLockStep, attach_owner_result, lock_pi_step};

use super::super::core::{cmpxchg_user_u32, current_key, load_user_u32};
use super::lock::{classify_owner, current_arc, fault_in_writeable_word, owner_lookup_now,
    read_word, retry_after, visible_tid};
use super::graph::{enqueue, prepare_waiter, retire_state, would_deadlock};
use super::state::{Grant, PI_TABLE, PiState, PiWaiter, find, grant, lock_for_requeue,
    lock_for_waiter_insert, new_waiter, prepare_waiter_slot, wake as wake_waiter};

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
    let Some(vpid) = visible_tid(&me) else { return e(Errno::Esrch) };
    let Some(key1) = current_key(uaddr, private) else { return e(Errno::Einval) };
    let Some(key2) = current_key(uaddr2, private) else { return e(Errno::Einval) };
    loop {
        match load_user_u32(uaddr) {
            Ok(v) if v == val => {}
            Ok(_) => return e(Errno::Eagain),
            Err(err) => return e(err),
        }
        let grant = Arc::new(AtomicU32::new(Grant::Pending as u32));
        let waiter_slot = match prepare_waiter_slot() {
            Ok(slot) => slot,
            Err(err) => return e(err),
        };
        let waiter = new_waiter(me.clone(), vpid, grant.clone(), Some(key2));
        {
            let mut tbl = match lock_for_waiter_insert(key1) {
                Ok(tbl) => tbl,
                Err(err) => return e(err),
            };
            match load_user_u32(uaddr) {
                Ok(v) if v == val => {}
                Ok(_) => return e(Errno::Eagain),
                Err(Errno::Efault) => { retry_after(tbl); continue; }
                Err(err) => return e(err),
            }
            match find(&tbl, key1) {
                Some(i) => {
                    tbl[i].push_waiter(waiter);
                }
                None => {
                    // The SOURCE futex needs a parking slot even though it has no
                    // PI owner: the requeue has to find this waiter by key.
                    assert!(waiter_slot.len() < waiter_slot.capacity(),
                        "prepared requeue waiter slot exhausted under RtMutexWait");
                    assert!(tbl.len() < tbl.capacity(),
                        "prepared requeue state slot exhausted under RtMutexWait");
                    tbl.push(PiState::new(key1, uaddr, 0, None, waiter_slot));
                    let index = tbl.len() - 1;
                    tbl[index].push_waiter(waiter);
                }
            }
            me.set_sleep_state(sched::WaitState::Interruptible);
        }
        return match super::park::park_for_grant(&me, &grant, key1, vpid, deadline_ns) {
            Ok(()) => 0,
            Err(rv) => { super::lock::unqueue(key2, vpid); rv }
        };
    }
}

/// `FUTEX_CMP_REQUEUE_PI` — Linux `futex_requeue(..., requeue_pi = 1)`.
///
/// Moves `FUTEX_WAIT_REQUEUE_PI` waiters off the condition variable `uaddr1`
/// onto the PI mutex `uaddr2`. At most ONE waiter is woken, and only when the
/// mutex is uncontended so the requeue can acquire it on that waiter's behalf;
/// the rest are queued as PI waiters and are released by the eventual
/// `FUTEX_UNLOCK_PI`.
/// # C: O(S + N_waiters^2)
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
    if key1 == key2 { return e(Errno::Einval); }

    'retry: loop {
        if let Err(err) = fault_in_writeable_word(uaddr2) { return e(err); }
        let uval1 = match read_word(uaddr1) { Ok(v) => v, Err(err) => return e(err) };
        if uval1 != cmpval { return e(Errno::Eagain); }
        let uval2 = match read_word(uaddr2) { Ok(v) => v, Err(err) => return e(err) };
        let owner_tid2 = uval2 & crate::futex_pi_rules::FUTEX_TID_MASK;
        // Pin any destination owner before RtMutexWait; registry lookup carries a
        // lower TaskList rank. Both words are revalidated once the table is held.
        let owner2 = if owner_tid2 == 0 { None } else { Some(classify_owner(owner_tid2)) };
        let mut wake: Option<PiWaiter> = None;
        let mut retired_state = None;
        let moved;
        {
        // A failed proxy acquisition transfers the mandatory wake candidate
        // in addition to `nr_requeue`; reserve that maximum before RtMutexWait.
        let limit = usize::try_from(nr_requeue).unwrap_or(usize::MAX).saturating_add(1);
        let mut tbl = match lock_for_requeue(key1, key2, limit) {
            Ok(tbl) => tbl,
            Err(err) => return e(err),
        };
        match (read_word(uaddr1), read_word(uaddr2)) {
            (Ok(a), Ok(b)) if a == uval1 && b == uval2 => {}
            (Err(Errno::Efault), _) | (_, Err(Errno::Efault)) => {
                retry_after(tbl); continue 'retry;
            }
            _ => return e(Errno::Eagain),
        }
        let Some(src) = find(&tbl, key1) else { return 0 };
        // The source queue is a non-PI condition-variable queue. Reject an
        // rtmutex owner, an ordinary PI waiter, or a waiter paired with a
        // different destination before inspecting or changing destination
        // ownership. The complete check makes the transaction all-or-error.
        if tbl[src].owner.is_some() || tbl[src].owner_tid != 0
            || tbl[src].waiters.iter().any(|w| w.requeue_target != Some(key2)) {
            return e(Errno::Einval);
        }
        let mut owner_tid = owner_tid2;
        let mut owner_task = match owner2.as_ref() {
            None => None,
            Some((lookup, owner)) => {
                if let Err(err) = attach_owner_result(owner_lookup_now(*lookup, owner.as_ref()), false) {
                    if err == Errno::Eagain { retry_after(tbl); continue 'retry; }
                    return e(err);
                }
                owner.clone()
            }
        };
        if let Some(dst) = find(&tbl, key2) {
            let Some(state_owner) = tbl[dst].owner.as_ref() else { return e(Errno::Einval) };
            if tbl[dst].owner_tid != owner_tid2 || owner_task.as_ref()
                .is_none_or(|owner| !Arc::ptr_eq(owner, state_owner)) {
                return e(Errno::Einval);
            }
        }

        // Try to acquire the PI mutex on the top waiter's behalf. An
        // uncontended take consumes the mandatory wake slot; a contended
        // result publishes WAITERS and transfers that candidate below.
        let mut woken = 0i64;
        if let Some(top) = tbl[src].source_waiter_after(None) {
            let wtid = tbl[src].waiters[top].tid;
            let have2 = find(&tbl, key2).is_some();
            match lock_pi_step(uval2, wtid, have2, nr_requeue != 0) {
                Err(err) => return e(err),
                Ok(PiLockStep::TakeUncontended { newval }) => {
                    match cmpxchg_user_u32(uaddr2, uval2, newval) {
                        Err(Errno::Eagain | Errno::Efault) => {
                            retry_after(tbl); continue 'retry;
                        }
                        Err(err) => return e(err),
                        Ok(seen) if seen == uval2 => {
                            let w = tbl[src].remove_unlinked(top);
                            owner_tid = w.tid;
                            owner_task = Some(Arc::clone(&w.task));
                            grant(&w, Grant::Owner);
                            wake = Some(w);
                            woken = 1;
                        }
                        Ok(_) => { retry_after(tbl); continue 'retry; }
                    }
                }
                Ok(PiLockStep::PublishWaitersThenAttach { newval, .. }) => {
                    match cmpxchg_user_u32(uaddr2, uval2, newval) {
                        Ok(seen) if seen == uval2 => {}
                        Ok(_) | Err(Errno::Eagain | Errno::Efault) => {
                            retry_after(tbl); continue 'retry;
                        }
                        Err(err) => return e(err),
                    }
                }
                Ok(PiLockStep::AttachExisting) => {}
            }
        }

        // Everything still parked for key2 is requeued onto the PI futex as an
        // ordinary PI waiter; ownership now reaches it through UNLOCK_PI.
        let carry_limit = nr_requeue.saturating_add(i64::from(woken == 0));
        let mut n = 0i64;
        let has_carry = carry_limit != 0 && !tbl[src].waiters.is_empty();
        let dst = if has_carry {
            if let Some(owner) = owner_task.as_ref() {
                let limit = usize::try_from(carry_limit).unwrap_or(usize::MAX);
                let mut after = None;
                for _ in 0..limit {
                    let Some(index) = tbl[src].source_waiter_after(after) else { break };
                    let task = Arc::clone(&tbl[src].waiters[index].task);
                    if would_deadlock(&mut tbl, &task, owner) { return e(Errno::Edeadlk); }
                    after = Some((tbl[src].waiters[index].key(), tbl[src].waiters[index].order()));
                }
            }
            match find(&tbl, key2) {
                Some(i) => Some(i),
                None => {
                    let waiters = tbl.take_new_waiters();
                    assert!(tbl.len() < tbl.capacity(),
                        "prepared requeue destination slot exhausted under RtMutexWait");
                    tbl.push(PiState::new(key2, uaddr2, owner_tid,
                        owner_task.clone(), waiters));
                    Some(tbl.len() - 1)
                }
            }
        } else { None };
        while n < carry_limit {
            let Some(index) = tbl[src].source_waiter_after(None) else { break };
            let mut w = tbl[src].remove_unlinked(index);
            prepare_waiter(&mut w);
            w.requeue_target = None;
            let dst = dst.expect("eligible waiter has destination");
            enqueue(&mut tbl, dst, w);
            n += 1;
        }
        if tbl[src].waiters.is_empty() && tbl[src].owner.is_none() {
            retire_state(&mut tbl, src);
            retired_state = Some(tbl.swap_remove(src));
        }
        moved = n + woken;
        }
        if let Some(w) = wake.as_ref() { wake_waiter(w); }
        drop(retired_state);
        return moved;
    }
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
