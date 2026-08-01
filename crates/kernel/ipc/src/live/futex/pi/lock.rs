use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sched::{Task, TaskState};
use syscall::errno::Errno;

use crate::futex_pi_rules::{OwnerLookup, PiLockStep, attach_owner_result, lock_pi_step};

use super::super::core::{Key, cmpxchg_user_u32, current_key, load_user_u32, user_addr_accessible};
use super::state::{Grant, PI_TABLE, PiState, PiWaiter, find, reboost};

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
fn classify_owner(tid: u32) -> (OwnerLookup, Option<Arc<Task>>) {
    let Some(t) = sched::live::registry::lookup_by_vpid(tid) else { return (OwnerLookup::Gone, None) };
    // A task that has reached Zombie has already run its futex exit cleanup, so
    // it can no longer hand the mutex over; treat it as gone and let the
    // word-changed re-read decide between EAGAIN and ESRCH.
    if t.state() == TaskState::Zombie { return (OwnerLookup::Gone, None); }
    // Linux rejects a PF_KTHREAD owner with EPERM. A kernel thread here is a
    // task with no user address space, which by construction cannot hold a
    // userspace mutex — the word is userspace-corrupted.
    // SAFETY: mm slot single-mutator per `13§5`; the borrow ends with the call.
    if unsafe { t.mm_ref() }.is_none() { return (OwnerLookup::KernelThread, None); }
    (OwnerLookup::Alive, Some(t))
}

/// Read the futex word without faulting the kernel on an unmapped page.
/// # C: O(page-table depth)
pub(super) fn read_word(uaddr: u64) -> Result<u32, Errno> {
    if !user_addr_accessible(uaddr, true) { return Err(Errno::Efault); }
    // SAFETY: page verified present and writable under the active CR3/TTBR0;
    // bounded, 4-aligned user word validated by the caller.
    Ok(unsafe { load_user_u32(uaddr) })
}

/// Bound on the retry loop. Linux retries `futex_lock_pi` without a bound; each
/// pass either makes progress or re-reads a word another task just changed. The
/// bound here keeps a hostile userspace that rewrites the word in a tight loop
/// from pinning a CPU inside a syscall — on exhaustion the caller gets `EAGAIN`,
/// which is a legal `futex_lock_pi` result that glibc already retries.
pub(super) const PI_RETRY_LIMIT: usize = 64;

/// `FUTEX_LOCK_PI` / `FUTEX_LOCK_PI2` / `FUTEX_TRYLOCK_PI` — Linux
/// `futex_lock_pi`.
///
/// Returns 0 once the caller owns the mutex. The `FUTEX_OWNER_DIED` bit is left
/// in the user word for userspace to act on (glibc turns it into
/// `EOWNERDEAD`), exactly as Linux does — the kernel never reports it as an
/// errno.
/// # C: O(S + N_waiters) per attempt; blocks until owned
pub fn lock_pi(uaddr: u64, private: bool, deadline_ns: u64, trylock: bool) -> i64 {
    if uaddr == 0 || uaddr >= hal::USER_VA_END { return e(Errno::Efault); }
    if (uaddr & 0x3) != 0 { return e(Errno::Einval); }
    let Some(me) = current_arc() else { return e(Errno::Einval) };
    let vpid = me.tid;
    let Some(key) = current_key(uaddr, private) else { return e(Errno::Einval) };

    for _ in 0..PI_RETRY_LIMIT {
        let uval = match read_word(uaddr) { Ok(v) => v, Err(err) => return e(err) };
        let grant = Arc::new(AtomicU32::new(Grant::Pending as u32));
        // Owner to re-boost after the guard drops, plus its waiter classes.
        let boost: Option<(Arc<Task>, Vec<sched::SchedClass>)>;
        {
            let mut tbl = PI_TABLE.lock();
            let existing = find(&tbl, key);
            let step = match lock_pi_step(uval, vpid, existing.is_some(), false) {
                Ok(s) => s, Err(err) => return e(err),
            };
            match step {
                PiLockStep::TakeUncontended { newval } => {
                    // SAFETY: 4-aligned user word verified present+writable by
                    // `read_word`; single naturally-aligned RMW under the
                    // active address space.
                    if unsafe { cmpxchg_user_u32(uaddr, uval, newval) } != uval { continue; }
                    return 0;
                }
                PiLockStep::PublishWaitersThenAttach { newval, owner_tid } => {
                    // SAFETY: same validated word as `read_word` above.
                    if unsafe { cmpxchg_user_u32(uaddr, uval, newval) } != uval { continue; }
                    let (lookup, owner) = classify_owner(owner_tid);
                    if let Err(err) = attach_owner_result(lookup, read_word(uaddr).ok() != Some(newval)) {
                        // The word keeps FUTEX_WAITERS: harmless, and Linux
                        // leaves it set on this path too — the next unlock
                        // simply takes the kernel slow path once.
                        if err == Errno::Eagain { continue; }
                        return e(err);
                    }
                    let owner = owner.expect("Alive implies a task");
                    let mut st = PiState {
                        key, uaddr, owner_tid, owner: Some(owner.clone()), waiters: Vec::new(),
                    };
                    st.waiters.push(PiWaiter {
                        task: me.clone(), tid: vpid, grant: grant.clone(), requeue_target: None });
                    let classes = st.waiter_classes();
                    tbl.push(st);
                    boost = Some((owner, classes));
                }
                PiLockStep::AttachExisting => {
                    let i = existing.expect("AttachExisting implies existing state");
                    tbl[i].waiters.push(PiWaiter {
                        task: me.clone(), tid: vpid, grant: grant.clone(), requeue_target: None });
                    let classes = tbl[i].waiter_classes();
                    boost = tbl[i].owner.clone().map(|o| (o, classes));
                }
            }
            if !trylock { me.set_state(TaskState::Sleeping); }
        }
        if let Some((owner, classes)) = boost { reboost(&owner, &classes); }
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
    e(Errno::Eagain)
}

/// Remove this task's waiter entry from `key`'s state, dropping the state (and
/// the owner's boost) when it was the last waiter. Used by the trylock path and
/// by a wait that ended in a timeout or a signal.
/// # C: O(S + N_waiters)
pub(super) fn unqueue(key: Key, tid: u32) {
    let boost: Option<(Arc<Task>, Vec<sched::SchedClass>)>;
    {
        let mut tbl = PI_TABLE.lock();
        let Some(i) = find(&tbl, key) else { return };
        if let Some(p) = tbl[i].waiters.iter().position(|w| w.tid == tid) { tbl[i].waiters.swap_remove(p); }
        if tbl[i].waiters.is_empty() {
            // Last waiter gone: the state itself goes, and the owner drops the
            // boost it was carrying on our behalf. `FUTEX_WAITERS` is left set
            // in the user word — the owner's unlock then takes the kernel path
            // once and clears it, which is what Linux's cleanup does too.
            let st = tbl.swap_remove(i);
            boost = st.owner.map(|o| (o, Vec::new()));
        } else {
            let classes = tbl[i].waiter_classes();
            boost = tbl[i].owner.clone().map(|o| (o, classes));
        }
    }
    if let Some((owner, classes)) = boost { reboost(&owner, &classes); }
}

/// Reset a granted waiter's bookkeeping after it wakes owning the mutex.
/// # C: O(1)
pub(super) fn grant_kind(grant: &AtomicU32) -> Grant {
    match grant.load(Ordering::Acquire) {
        1 => Grant::Owner,
        2 => Grant::OwnerDied,
        _ => Grant::Pending,
    }
}
