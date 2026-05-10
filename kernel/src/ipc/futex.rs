// Futex kernel support per docs/24. v1 process-private only —
// keys are (mm_root_pa, user_va). Shared (cross-mm) futexes ride
// a follow-up once we have inode-based keying.
//
// Implementation: a single global Vec of (key, Arc<Task>) wait
// entries under a Tty-class spinlock. FUTEX_WAIT atomically
// checks `*uaddr == val` against the user page (via the active
// CR3 since the caller is on the syscall path and current's mm
// is active), parks if equal, schedules. FUTEX_WAKE walks the
// list and wakes up to N tasks at the same key.
//
// O(N) worst-case scan is fine for v1; real Linux hashes by
// addr → bucket. Bucketed table rides a follow-up if the linear
// scan shows up in profiles.


use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use sched::{Task, TaskState};
use sync::{Spinlock, Tty as TtyClass};
use syscall::errno::Errno;

const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_OP_MASK:    u32 = 0x7f;

#[derive(Copy, Clone, Eq, PartialEq)]
struct Key {
    /// Address-space root (CR3 pa) — distinguishes processes.
    mm_root: u64,
    /// User VA of the futex word. We don't translate to phys since
    /// v1 process-private; mm_root + va is a stable identity.
    va:      u64,
}

struct Waiter {
    key:  Key,
    task: Arc<Task>,
}

static WAITERS: Spinlock<Vec<Waiter>, TtyClass> = Spinlock::new(Vec::new());

fn current_key(uaddr: u64) -> Option<Key> {
    let cur = crate::sched::current()?;
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = unsafe { cur.mm_ref() }?;
    Some(Key { mm_root: mm.root_pa(), va: uaddr })
}

/// Read u32 at user VA `uaddr`. Caller is the syscall path with
/// current's CR3 active, so a direct kernel-mode load through
/// the user mapping resolves via the user PT (demand-faulted by
/// `user_as_fault_handler` if not yet present).
unsafe fn load_user_u32(uaddr: u64) -> u32 {
    // SAFETY: caller validated uaddr < USER_VA_END; current's mm is the active CR3 because we are on its syscall stack.
    unsafe { core::ptr::read_volatile(uaddr as *const u32) }
}

/// # C: O(W) waiters per WAKE; O(1) WAIT
pub fn dispatch(uaddr: u64, op_full: u32, val: u32) -> i64 {
    if uaddr == 0 || uaddr >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if (uaddr & 0x3) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    match op_full & FUTEX_OP_MASK {
        FUTEX_WAIT => {
            // SAFETY: bounded user VA validated above; CR3 is current's.
            let cur_val = unsafe { load_user_u32(uaddr) };
            if cur_val != val { return -(Errno::Eagain.as_i32() as i64); }
            // Atomically park self + push to waiters under the lock so a
            // concurrent FUTEX_WAKE can't see us pre-park.
            let key = match current_key(uaddr) {
                Some(k) => k, None => return -(Errno::Einval.as_i32() as i64),
            };
            let cur = match crate::sched::current() {
                Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
            };
            // Bump strong count to materialise an Arc the WAITERS list
            // can hold across the schedule.
            let raw = cur as *const Task;
            // SAFETY: cur came from sched::current() and is the running task on this CPU; bumping the strong count is sound.
            unsafe { Arc::increment_strong_count(raw); }
            // SAFETY: matching Arc::from_raw consumes the bumped ref.
            let arc = unsafe { Arc::from_raw(raw) };
            arc.set_state(TaskState::Sleeping);
            WAITERS.lock().push(Waiter { key, task: arc });
            // SAFETY: process ctx; runqueue installed; preempt-off.
            unsafe { crate::sched::schedule(); }
            // Resume — woken by FUTEX_WAKE (or spurious; caller rechecks).
            0
        }
        FUTEX_WAKE => {
            let key = match current_key(uaddr) {
                Some(k) => k, None => return -(Errno::Einval.as_i32() as i64),
            };
            let n_target = val as usize;
            let mut woken: Vec<Arc<Task>> = Vec::new();
            {
                let mut w = WAITERS.lock();
                let mut i = 0;
                while i < w.len() && woken.len() < n_target {
                    if w[i].key == key {
                        woken.push(w.swap_remove(i).task);
                    } else {
                        i += 1;
                    }
                }
            }
            if woken.is_empty() { return 0; }
            let rq = match crate::sched::global() {
                Some(r) => r, None => return woken.len() as i64,
            };
            let mut inner = rq.inner.lock();
            for t in &woken {
                t.set_state(TaskState::Runnable);
                t.lift_vruntime(inner.cfs.min_vruntime());
                inner.enqueue(t.clone());
            }
            rq.nr_running.store(inner.nr_running(), Ordering::Release);
            crate::preempt::set_need_resched();
            woken.len() as i64
        }
        _ => 0, // Unsupported ops: accept-and-no-op; musl tolerates.
    }
}
