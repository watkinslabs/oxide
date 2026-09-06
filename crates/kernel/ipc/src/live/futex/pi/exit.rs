use syscall::errno::Errno;

use crate::futex_pi_rules::{dead_owner_handoff_word, owner_died_word};

use super::super::core::{cmpxchg_user_u32, load_user_u32};
use super::lock::fault_in_writeable_word;
use super::graph::{handoff, retire_state, TaskPiIrq};
use super::state::{Grant, PI_TABLE, PiWaiter, find_id, grant, wake as wake_waiter};

#[cfg(test)]
#[path = "exit/tests/irq.rs"]
mod irq_tests;

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
/// # C: O(N_owned · (S + log N_waiters))
pub fn exit_pi_state_list(dying: &sched::Task) {
    loop {
        let Some(lock_id) = dying.pi_lock.lock_irqsave::<TaskPiIrq>().first_owned_lock() else { break };
        let uaddr = {
            let tbl = PI_TABLE.lock();
            let i = find_id(&tbl, lock_id).expect("task PI tree names no futex state");
            assert!(tbl[i].owner.as_ref()
                .is_some_and(|owner| core::ptr::eq(owner.as_ref(), dying)),
                "task PI tree names a state owned by another task");
            tbl[i].uaddr
        };
        // Demand/COW resolution is forbidden under RtMutexWait. Touch the
        // writable word first, then re-find and revalidate its PI state.
        let uval = match fault_in_writeable_word(uaddr).and_then(|()| load_user_u32(uaddr)) {
            Ok(value) => value,
            Err(_) => {
                let mut tbl = PI_TABLE.lock();
                let failed_state = if let Some(i) = find_id(&tbl, lock_id)
                    .filter(|&i| tbl[i].owner.as_ref()
                        .is_some_and(|owner| core::ptr::eq(owner.as_ref(), dying))
                        && tbl[i].uaddr == uaddr) {
                    retire_state(&mut tbl, i);
                    let state = tbl.swap_remove(i);
                    for waiter in &state.waiters { grant(waiter, Grant::OwnerFault); }
                    Some(state)
                } else { None };
                drop(tbl);
                if let Some(state) = failed_state.as_ref() {
                    for waiter in &state.waiters { wake_waiter(waiter); }
                }
                drop(failed_state);
                continue;
            }
        };
        let mut wake: Option<PiWaiter> = None;
        let mut retired_state = None;
        {
            let mut tbl = PI_TABLE.lock();
            let Some(i) = find_id(&tbl, lock_id).filter(|&i| tbl[i].owner.as_ref()
                .is_some_and(|owner| core::ptr::eq(owner.as_ref(), dying)) && tbl[i].uaddr == uaddr)
            else { continue };
            match load_user_u32(uaddr) {
                Ok(seen) if seen == uval => {}
                Ok(_) | Err(Errno::Eagain | Errno::Efault) => continue,
                Err(_) => continue,
            }
            match tbl[i].top_waiter() {
                    Some(top) => {
                        let next_tid = tbl[i].waiters[top].tid;
                        let newval = dead_owner_handoff_word(uval, next_tid);
                        match cmpxchg_user_u32(uaddr, uval, newval) {
                            Ok(seen) if seen == uval => {}
                            Ok(_) | Err(Errno::Eagain | Errno::Efault) => continue,
                            Err(_) => continue,
                        }
                        let w = handoff(&mut tbl, i, top);
                        grant(&w, Grant::OwnerDied);
                        if tbl[i].waiters.is_empty() {
                            retired_state = Some(tbl.swap_remove(i));
                        }
                        wake = Some(w);
                    }
                    None => {
                        match cmpxchg_user_u32(uaddr, uval, owner_died_word(uval)) {
                            Ok(seen) if seen == uval => {
                                retire_state(&mut tbl, i);
                                retired_state = Some(tbl.swap_remove(i));
                            }
                            Ok(_) | Err(Errno::Eagain | Errno::Efault) => continue,
                            Err(_) => continue,
                        }
                    }
            }
        }
        if let Some(w) = wake.as_ref() { wake_waiter(w); }
        drop(retired_state);
    }
}
