use alloc::sync::Arc;
use alloc::vec::Vec;

use sched::Task;

use crate::futex_pi_rules::{dead_owner_handoff_word, owner_died_word};

use super::super::core::{cmpxchg_user_u32, load_user_u32, user_addr_accessible};
use super::state::{Grant, PI_TABLE, PiState, grant_and_wake, reboost};

/// Linux `exit_pi_state_list` — run for every dying thread, from BOTH exit
/// paths, while its address space is still mapped.
///
/// For each PI futex the thread still owns:
///   * with a waiter — write `FUTEX_OWNER_DIED | FUTEX_WAITERS | next_tid` and
///     wake that waiter as the new owner, so it returns from `pthread_mutex_lock`
///     with `EOWNERDEAD` holding a lock it can make consistent;
///   * with no waiter — write `FUTEX_OWNER_DIED` (keeping `FUTEX_WAITERS`) and
///     drop the state, so the next locker learns the previous owner died.
///
/// Without this, a thread that dies holding a `PTHREAD_PRIO_INHERIT` mutex
/// leaves the word naming a TID that no longer exists: every subsequent
/// `FUTEX_LOCK_PI` attaches to a dead owner and every waiter blocks forever.
/// The robust-list walk deliberately does NOT wake PI futexes for exactly this
/// reason — the handoff has to happen here, where the kernel owner record is.
///
/// # SAFETY: caller is the exit path with the dying task's mm active.
/// # C: O(S · N_waiters)
pub fn exit_pi_state_list(owner_tid: u32) {
    loop {
        // One state per pass: the wake and the boost recomputation must happen
        // with the table guard dropped, and the table can change in between.
        let mut promoted: Option<(Arc<Task>, Vec<sched::SchedClass>)> = None;
        {
            let mut tbl = PI_TABLE.lock();
            let Some(i) = tbl.iter().position(|s| s.owner_tid == owner_tid && s.owner.is_some())
            else { break };
            let uaddr = tbl[i].uaddr;
            match read_word_for_exit(uaddr) {
                None => {
                    // The dying task's futex page is already gone; nothing can
                    // be written, but the kernel state must still be released
                    // or a later locker attaches to a dead owner.
                    drop_state(&mut tbl, i);
                }
                Some(uval) => match tbl[i].top_waiter() {
                    Some(top) => {
                        let next_tid = tbl[i].waiters[top].tid;
                        let newval = dead_owner_handoff_word(uval, next_tid);
                        // SAFETY: word verified present+writable by
                        // `read_word_for_exit`; single naturally-aligned RMW in
                        // the dying task's still-live address space.
                        unsafe { cmpxchg_user_u32(uaddr, uval, newval) };
                        let w = tbl[i].waiters.swap_remove(top);
                        tbl[i].owner = Some(w.task.clone());
                        tbl[i].owner_tid = w.tid;
                        grant_and_wake(&w, Grant::OwnerDied);
                        if tbl[i].waiters.is_empty() {
                            tbl.swap_remove(i);
                        } else {
                            let classes = tbl[i].waiter_classes();
                            promoted = Some((w.task.clone(), classes));
                        }
                    }
                    None => {
                        // SAFETY: the same word `read_word_for_exit` just
                        // proved in-range, 4-aligned and present+writable; a
                        // single naturally-aligned RMW in the dying task's
                        // still-active address space.
                        unsafe { cmpxchg_user_u32(uaddr, uval, owner_died_word(uval)) };
                        drop_state(&mut tbl, i);
                    }
                },
            }
        }
        if let Some((owner, classes)) = promoted { reboost(&owner, &classes); }
    }
    // The dying task may still be carrying a boost lent by a waiter whose state
    // was just torn down. Clearing it keeps a recycled `Task` from starting
    // life at an inherited real-time priority.
    if let Some(t) = sched::live::registry::lookup(owner_tid) { sched::live::pi_boost::deboost(&t); }
}

/// Fault-safe read of the futex word during a thread's exit. The dying thread
/// may be exiting BECAUSE its memory is bad, so an unmapped word aborts this
/// entry rather than faulting the kernel on the exit path.
/// # C: O(page-table depth)
fn read_word_for_exit(uaddr: u64) -> Option<u32> {
    if uaddr == 0 || uaddr >= hal::USER_VA_END || (uaddr & 0x3) != 0 { return None; }
    if !user_addr_accessible(uaddr, true) { return None; }
    // SAFETY: page verified present and writable under the dying task's still
    // active address space; bounded, 4-aligned user word.
    Some(unsafe { load_user_u32(uaddr) })
}

/// Release a state whose owner died with no waiter to hand it to.
/// # C: O(1)
fn drop_state(tbl: &mut Vec<PiState>, i: usize) {
    // Any waiter still attached is a requeue-pi waiter parked on another futex;
    // it has no claim on this one and must not be granted a dead lock.
    tbl.swap_remove(i);
}
