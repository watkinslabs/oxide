use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use sched::{Task, TaskState};
use syscall::errno::Errno;

use crate::futex_pi_rules::{OwnerLookup, PiLockStep, attach_owner_result, lock_pi_step};

use super::super::core::{Key, cmpxchg_user_u32, current_key, load_user_u32};
use super::graph::{enqueue, prepare_waiter, remove, would_deadlock};
use super::state::{Grant, PI_TABLE, PiState, find, lock_for_waiter_insert,
    new_waiter, prepare_waiter_slot};

fn e(err: Errno) -> i64 { -(err.as_i32() as i64) }

/// An `Arc` for the running task. `sched` exposes only a borrowed `current()`;
/// PI state holds owning references (the owner must outlive the waiters that
/// are boosting it), so the registry lookup is the supported way to obtain one.
/// # C: O(1)
pub(super) fn current_arc() -> Option<Arc<Task>> {
    sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
}

/// Classify the TID a futex word names, for `attach_to_pi_owner`.
/// # C: O(N_tasks)
pub(crate) fn classify_owner(tid: u32) -> (OwnerLookup, Option<Arc<Task>>) {
    let Some(t) = sched::live::registry::resolve_user_pid(tid) else { return (OwnerLookup::Gone, None) };
    // A task that has reached Zombie has already run its futex exit cleanup, so
    // it can no longer hand the mutex over; treat it as gone and let the
    // word-changed re-read decide between EAGAIN and ESRCH.
    if t.state() == TaskState::Zombie { return (OwnerLookup::Gone, None); }
    if t.exiting.load(Ordering::Acquire) { return (OwnerLookup::Exiting, Some(t)); }
    // Linux rejects a PF_KTHREAD owner with EPERM. A kernel thread here is a
    // task with no user address space, which by construction cannot hold a
    // userspace mutex — the word is userspace-corrupted.
    if t.clone_mm().is_none() { return (OwnerLookup::KernelThread, None); }
    (OwnerLookup::Alive, Some(t))
}

/// Refresh only lockless exit state after RtMutexWait revalidation. # C: O(1)
pub(super) fn owner_lookup_now(initial: OwnerLookup, owner: Option<&Arc<Task>>) -> OwnerLookup {
    let Some(owner) = owner else { return initial };
    if owner.state() == TaskState::Zombie { OwnerLookup::Gone }
    else if owner.exiting.load(Ordering::Acquire) { OwnerLookup::Exiting }
    else { initial }
}

/// Namespace-visible thread number stored in a PI futex word. # C: O(depth)
pub(super) fn visible_tid(task: &Task) -> Option<u32> {
    u32::try_from(sched::live::registry::display_vtid(task.tid)).ok().filter(|tid| *tid != 0)
}

/// Read the futex word through the fault-recovering user-access owner.
/// # C: O(page faults)
pub(super) fn read_word(uaddr: u64) -> Result<u32, Errno> {
    load_user_u32(uaddr)
}

/// Resolve read, write, and COW faults before entering RtMutexWait. Linux's
/// `fault_in_user_writeable()` serves the same role around in-atomic futex RMW.
/// The same-value cmpxchg is externally idempotent. # C: O(page faults)
pub(super) fn fault_in_writeable_word(uaddr: u64) -> Result<(), Errno> {
    let mut expected = read_word(uaddr)?;
    loop {
        match cmpxchg_user_u32(uaddr, expected, expected) {
            Ok(seen) if seen == expected => return Ok(()),
            Ok(seen) => expected = seen,
            Err(Errno::Eagain) => {}
            Err(err) => return Err(err),
        }
        sched::live::cond_resched();
    }
}

/// Drop a PI-table guard before yielding on a transient user-word race. # C: O(1)
pub(super) fn retry_after<T>(held: T) { drop(held); sched::live::cond_resched(); }

/// `FUTEX_LOCK_PI` / `FUTEX_LOCK_PI2` / `FUTEX_TRYLOCK_PI` — Linux
/// `futex_lock_pi`.
///
/// Returns 0 once the caller owns the mutex. The `FUTEX_OWNER_DIED` bit is left
/// in the user word for userspace to act on (glibc turns it into
/// `EOWNERDEAD`), exactly as Linux does — the kernel never reports it as an
/// errno.
/// # C: O(S + log N_waiters + log N_owned) per attempt; blocks until owned
pub fn lock_pi(uaddr: u64, private: bool, deadline_ns: u64, trylock: bool) -> i64 {
    if uaddr == 0 || uaddr >= hal::USER_VA_END { return e(Errno::Efault); }
    if (uaddr & 0x3) != 0 { return e(Errno::Einval); }
    let Some(me) = current_arc() else { return e(Errno::Einval) };
    let Some(vpid) = visible_tid(&me) else { return e(Errno::Esrch) };
    let Some(key) = current_key(uaddr, private) else { return e(Errno::Einval) };

    loop {
        if let Err(err) = fault_in_writeable_word(uaddr) { return e(err); }
        let uval = match read_word(uaddr) { Ok(v) => v, Err(err) => return e(err) };
        // Resolve and pin a first waiter's alleged owner before taking
        // RtMutexWait: registry/mm lookup is TaskList-ranked below it. The
        // successful compare-exchange below revalidates that the word still
        // names this exact TID before the pinned Arc is published.
        let owner_tid = uval & crate::futex_pi_rules::FUTEX_TID_MASK;
        let owner_pin = if owner_tid == 0 || owner_tid == vpid {
            None
        } else {
            Some(classify_owner(owner_tid))
        };
        let grant = Arc::new(AtomicU32::new(Grant::Pending as u32));
        let waiter_slot = match prepare_waiter_slot() {
            Ok(slot) => slot,
            Err(err) => return e(err),
        };
        let mut waiter = Some(new_waiter(me.clone(), vpid, grant.clone(), None));
        {
            let mut tbl = match lock_for_waiter_insert(key) {
                Ok(tbl) => tbl,
                Err(err) => return e(err),
            };
            let existing = find(&tbl, key);
            let step = match lock_pi_step(uval, vpid, existing.is_some(), false) {
                Ok(s) => s, Err(err) => return e(err),
            };
            match step {
                PiLockStep::TakeUncontended { newval } => {
                    let seen = match cmpxchg_user_u32(uaddr, uval, newval) {
                        Ok(v) => v,
                        Err(Errno::Eagain | Errno::Efault) => { retry_after(tbl); continue; }
                        Err(err) => return e(err),
                    };
                    if seen != uval { retry_after(tbl); continue; }
                    return 0;
                }
                PiLockStep::PublishWaitersThenAttach { newval, owner_tid } => {
                    let seen = match cmpxchg_user_u32(uaddr, uval, newval) {
                        Ok(v) => v,
                        Err(Errno::Eagain | Errno::Efault) => { retry_after(tbl); continue; }
                        Err(err) => return e(err),
                    };
                    if seen != uval { retry_after(tbl); continue; }
                    let Some((lookup, owner)) = owner_pin else { return e(Errno::Einval) };
                    let lookup = owner_lookup_now(lookup, owner.as_ref());
                    if let Err(err) = attach_owner_result(lookup, false) {
                        // The word keeps FUTEX_WAITERS: harmless, and Linux
                        // leaves it set on this path too — the next unlock
                        // simply takes the kernel slow path once.
                        if err == Errno::Eagain { retry_after(tbl); continue; }
                        return e(err);
                    }
                    let owner = owner.expect("Alive implies a task");
                    if would_deadlock(&mut tbl, &me, &owner) { return e(Errno::Edeadlk); }
                    prepare_waiter(waiter.as_mut().unwrap());
                    let st = PiState::new(key, uaddr, owner_tid, Some(owner), waiter_slot);
                    assert!(tbl.len() < tbl.capacity(),
                        "prepared PI state slot exhausted under RtMutexWait");
                    tbl.push(st);
                    let index = tbl.len() - 1;
                    enqueue(&mut tbl, index, waiter.take().unwrap());
                }
                PiLockStep::AttachExisting => {
                    let i = existing.expect("AttachExisting implies existing state");
                    let Some(state_owner) = tbl[i].owner.clone() else { return e(Errno::Einval) };
                    let Some((lookup, pinned)) = owner_pin else { return e(Errno::Einval) };
                    let lookup = owner_lookup_now(lookup, pinned.as_ref());
                    if let Err(err) = attach_owner_result(lookup, false) {
                        if err == Errno::Eagain { retry_after(tbl); continue; }
                        return e(err);
                    }
                    if tbl[i].owner_tid != owner_tid || pinned.as_ref()
                        .is_none_or(|owner| !Arc::ptr_eq(owner, &state_owner)) {
                        return e(Errno::Einval);
                    }
                    if would_deadlock(&mut tbl, &me, &state_owner) { return e(Errno::Edeadlk); }
                    prepare_waiter(waiter.as_mut().unwrap());
                    enqueue(&mut tbl, i, waiter.take().unwrap());
                }
            }
            if !trylock { me.set_sleep_state(sched::WaitState::Interruptible); }
        }
        if trylock {
            unqueue(key, vpid);
            // Linux fixes the failed `rt_mutex_futex_trylock` up to
            // `-EWOULDBLOCK`, which is the same value as `-EAGAIN`.
            return e(Errno::Eagain);
        }
        match super::park::park_for_grant(&me, &grant, key, vpid, deadline_ns) {
            Ok(()) => return 0,
            Err(rv) => return rv,
        }
    }
}

/// Remove this task's waiter entry from `key`'s state, dropping the state (and
/// the owner's boost) when it was the last waiter. Used by the trylock path and
/// by a wait that ended in a timeout or a signal.
/// # C: O(S + N_waiters + log N_owned)
pub(super) fn unqueue(key: Key, tid: u32) {
    let mut retired_waiter = None;
    let mut retired_state = None;
    let mut tbl = PI_TABLE.lock();
    let Some(i) = find(&tbl, key) else { return };
    if let Some(p) = tbl[i].waiters.iter().position(|w| w.tid == tid) {
        retired_waiter = Some(remove(&mut tbl, i, p));
    }
    if tbl[i].waiters.is_empty() {
        // Last waiter gone: the state itself goes, and the owner drops the
        // boost it was carrying on our behalf. `FUTEX_WAITERS` is left set
        // in the user word — the owner's unlock then takes the kernel path
        // once and clears it, which is what Linux's cleanup does too.
        retired_state = Some(tbl.swap_remove(i));
    }
    drop(tbl);
    drop(retired_waiter);
    drop(retired_state);
}

/// Reset a granted waiter's bookkeeping after it wakes owning the mutex.
/// # C: O(1)
pub(super) fn grant_kind(grant: &AtomicU32) -> Grant {
    match grant.load(Ordering::Acquire) {
        1 => Grant::Owner,
        2 => Grant::OwnerDied,
        3 => Grant::OwnerFault,
        _ => Grant::Pending,
    }
}
