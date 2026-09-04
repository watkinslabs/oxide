use syscall::errno::Errno;

use crate::futex_pi_rules::{handoff_race, handoff_word, may_unlock};

use super::super::core::{cmpxchg_user_u32, current_key};
use super::lock::{fault_in_writeable_word, read_word, retry_after, visible_tid};
use super::graph::{handoff, retire_state};
use super::state::{Grant, PI_TABLE, PiWaiter, find, grant, wake as wake_waiter};

fn e(err: Errno) -> i64 { -(err.as_i32() as i64) }

/// `FUTEX_UNLOCK_PI` — Linux `futex_unlock_pi`.
///
/// Userspace only reaches here when its own `TID -> 0` fast path failed, i.e.
/// the word carries `FUTEX_WAITERS`. Two outcomes: hand the mutex directly to
/// the highest-priority waiter (writing its TID into the word before waking it,
/// so it never has to race for the lock it was just given), or, with no kernel
/// waiter, clear the word.
/// # C: O(S + N_waiters + log N_owned)
pub fn unlock_pi(uaddr: u64, private: bool) -> i64 {
    if uaddr == 0 || uaddr >= hal::USER_VA_END { return e(Errno::Efault); }
    if (uaddr & 0x3) != 0 { return e(Errno::Einval); }
    let Some(me) = super::lock::current_arc() else { return e(Errno::Einval) };
    let Some(vpid) = visible_tid(&me) else { return e(Errno::Esrch) };
    let Some(key) = current_key(uaddr, private) else { return e(Errno::Einval) };

    loop {
        if let Err(err) = fault_in_writeable_word(uaddr) { return e(err); }
        let uval = match read_word(uaddr) { Ok(v) => v, Err(err) => return e(err) };
        // The ownership gate runs on the RAW word before any kernel state is
        // consulted: releasing a lock this task does not hold is EPERM even
        // when the futex has no kernel state at all.
        if let Err(err) = may_unlock(uval, vpid) { return e(err); }

        let mut wake: Option<PiWaiter> = None;
        let mut retired_state = None;
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
                    let curval = match cmpxchg_user_u32(uaddr, uval, newval) {
                        Ok(v) => v,
                        Err(Errno::Eagain | Errno::Efault) => { retry_after(tbl); continue; }
                        Err(err) => return e(err),
                    };
                    if curval != uval {
                        let err = handoff_race(uval, curval);
                        if err == Errno::Eagain { retry_after(tbl); continue; }
                        return e(err);
                    }
                    // Past this point the user word already names the new
                    // owner, so nothing below may fail.
                    let w = handoff(&mut tbl, i, top);
                    grant(&w, Grant::Owner);
                    if tbl[i].waiters.is_empty() {
                        retired_state = Some(tbl.swap_remove(i));
                    }
                    wake = Some(w);
                }
                other => {
                    if let Some(i) = other {
                        if tbl[i].owner_tid != vpid { return e(Errno::Einval); }
                    }
                    // No kernel waiter. Linux preserves NEITHER `FUTEX_WAITERS`
                    // nor `FUTEX_OWNER_DIED` here — we are the owner and the
                    // futex becomes plainly free.
                    let curval = match cmpxchg_user_u32(uaddr, uval, 0) {
                        Ok(v) => v,
                        Err(Errno::Eagain | Errno::Efault) => { retry_after(tbl); continue; }
                        Err(err) => return e(err),
                    };
                    if curval != uval { retry_after(tbl); continue; }
                    if let Some(i) = other {
                        // State with no eligible waiter (only requeue-pi
                        // waiters parked elsewhere): remove it only after the
                        // user-word release succeeds, then publish deboost.
                        retire_state(&mut tbl, i);
                        retired_state = Some(tbl.swap_remove(i));
                    }
                }
            }
        }
        if let Some(w) = wake.as_ref() { wake_waiter(w); }
        drop(retired_state);
        return 0;
    }
}
