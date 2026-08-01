use alloc::sync::Arc;
use alloc::vec::Vec;

use sched::Task;
use syscall::errno::Errno;

use crate::futex_pi_rules::{handoff_race, handoff_word, may_unlock};

use super::super::core::{cmpxchg_user_u32, current_key};
use super::lock::{PI_RETRY_LIMIT, read_word};
use super::state::{Grant, PI_TABLE, find, grant_and_wake, reboost};

fn e(err: Errno) -> i64 { -(err.as_i32() as i64) }

/// `FUTEX_UNLOCK_PI` — Linux `futex_unlock_pi`.
///
/// Userspace only reaches here when its own `TID -> 0` fast path failed, i.e.
/// the word carries `FUTEX_WAITERS`. Two outcomes: hand the mutex directly to
/// the highest-priority waiter (writing its TID into the word before waking it,
/// so it never has to race for the lock it was just given), or, with no kernel
/// waiter, clear the word.
/// # C: O(S + N_waiters)
pub fn unlock_pi(uaddr: u64, private: bool) -> i64 {
    if uaddr == 0 || uaddr >= hal::USER_VA_END { return e(Errno::Efault); }
    if (uaddr & 0x3) != 0 { return e(Errno::Einval); }
    let Some(cur) = sched::live::current() else { return e(Errno::Einval) };
    let vpid = cur.tid;
    let Some(key) = current_key(uaddr, private) else { return e(Errno::Einval) };

    for _ in 0..PI_RETRY_LIMIT {
        let uval = match read_word(uaddr) { Ok(v) => v, Err(err) => return e(err) };
        // The ownership gate runs on the RAW word before any kernel state is
        // consulted: releasing a lock this task does not hold is EPERM even
        // when the futex has no kernel state at all.
        if let Err(err) = may_unlock(uval, vpid) { return e(err); }

        // (task to wake, grant) and the deboost/reboost work, all deferred
        // until the table guard is dropped.
        let mut deboost_me = false;
        let mut reboost_new: Option<(Arc<Task>, Vec<sched::SchedClass>)> = None;
        {
            let mut tbl = PI_TABLE.lock();
            match find(&tbl, key) {
                Some(i) if tbl[i].top_waiter().is_some() => {
                    // A futex whose kernel state names a different owner than
                    // the word did means userspace wrote the word behind the
                    // kernel's back; there is no consistent recovery.
                    if tbl[i].owner_tid != vpid { return e(Errno::Einval); }
                    let top = tbl[i].top_waiter().expect("checked above");
                    let newval = handoff_word(tbl[i].waiters[top].tid);
                    // SAFETY: 4-aligned user word verified present+writable by
                    // `read_word`; single naturally-aligned RMW under the
                    // active address space.
                    let curval = unsafe { cmpxchg_user_u32(uaddr, uval, newval) };
                    if curval != uval {
                        let err = handoff_race(uval, curval);
                        if err == Errno::Eagain { continue; }
                        return e(err);
                    }
                    // Past this point the user word already names the new
                    // owner, so nothing below may fail.
                    let w = tbl[i].waiters.swap_remove(top);
                    tbl[i].owner = Some(w.task.clone());
                    tbl[i].owner_tid = w.tid;
                    grant_and_wake(&w, Grant::Owner);
                    if tbl[i].waiters.is_empty() {
                        tbl.swap_remove(i);
                    } else {
                        let classes = tbl[i].waiter_classes();
                        reboost_new = Some((w.task.clone(), classes));
                    }
                    deboost_me = true;
                }
                other => {
                    if let Some(i) = other {
                        if tbl[i].owner_tid != vpid { return e(Errno::Einval); }
                        // State with no eligible waiter (only requeue-pi
                        // waiters parked elsewhere): it holds no ownership
                        // claim once we release, so it goes with the word.
                        tbl.swap_remove(i);
                        deboost_me = true;
                    }
                    // No kernel waiter. Linux preserves NEITHER `FUTEX_WAITERS`
                    // nor `FUTEX_OWNER_DIED` here — we are the owner and the
                    // futex becomes plainly free.
                    // SAFETY: same validated word as `read_word` above.
                    let curval = unsafe { cmpxchg_user_u32(uaddr, uval, 0) };
                    if curval != uval { continue; }
                }
            }
        }
        if deboost_me {
            if let Some(me) = super::lock::current_arc() { sched::live::pi_boost::deboost(&me); }
        }
        if let Some((owner, classes)) = reboost_new { reboost(&owner, &classes); }
        return 0;
    }
    e(Errno::Eagain)
}
