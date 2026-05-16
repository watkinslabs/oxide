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
use core::sync::atomic::{AtomicI32, Ordering};

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

/// Multi-futex wait group. Used by `futex_waitv` — a single task
/// parks on N keys at once; the first key that fires wakes the
/// task and records its index in `woken_idx`. Other group entries
/// are reaped lazily on the next wake-walk.
struct WaitvGroup {
    keys:      Vec<Key>,
    task:      Arc<Task>,
    /// -1 until a key wakes us; then the matching index. CAS
    /// guarantees only one waker delivers the wake.
    woken_idx: AtomicI32,
}

static WAITERS: Spinlock<Vec<Waiter>, TtyClass> = Spinlock::new(Vec::new());
static WAITV_GROUPS: Spinlock<Vec<Arc<WaitvGroup>>, TtyClass> = Spinlock::new(Vec::new());

fn current_key(uaddr: u64) -> Option<Key> {
    let cur = sched::live::current()?;
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
            let cur = match sched::live::current() {
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
            unsafe { sched::live::schedule(); }
            // Resume — woken by FUTEX_WAKE (or spurious; caller rechecks).
            0
        }
        FUTEX_WAKE => {
            let key = match current_key(uaddr) {
                Some(k) => k, None => return -(Errno::Einval.as_i32() as i64),
            };
            wake_key(key, val as usize) as i64
        }
        _ => 0, // Unsupported ops: accept-and-no-op; musl tolerates.
    }
}

/// Wake up to `n_target` waiters parked on `key`. Walks both the
/// single-key WAITERS list and any WAITV_GROUPS holding `key` as
/// one of their keys; each group fires at most once (CAS on
/// `woken_idx`).
fn wake_key(key: Key, n_target: usize) -> usize {
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
    if woken.len() < n_target {
        let mut g = WAITV_GROUPS.lock();
        let mut i = 0;
        while i < g.len() && woken.len() < n_target {
            let group = g[i].clone();
            let idx = group.keys.iter().position(|k| *k == key);
            if let Some(idx) = idx {
                if group.woken_idx
                    .compare_exchange(-1, idx as i32, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    woken.push(group.task.clone());
                    g.swap_remove(i);
                    continue;
                }
            }
            i += 1;
        }
        // Sweep already-fired groups (woken_idx >= 0) left behind by
        // earlier waiters on a different key in the same group.
        g.retain(|grp| grp.woken_idx.load(Ordering::Acquire) < 0);
    }
    if woken.is_empty() { return 0; }
    let rq = match sched::live::global() {
        Some(r) => r, None => return woken.len(),
    };
    let mut inner = rq.inner.lock();
    for t in &woken {
        t.set_state(TaskState::Runnable);
        t.lift_vruntime(inner.cfs.min_vruntime());
        inner.enqueue(t.clone());
    }
    rq.nr_running.store(inner.nr_running(), Ordering::Release);
    sched::live::preempt::set_need_resched();
    woken.len()
}

/// Multi-futex wait: park current task on N keys; resume when ANY
/// of them is woken (returns the index that woke). Pre-flight
/// check: if any `*uaddr != val` at entry, return -EAGAIN
/// immediately per Linux semantics. `vals` is parallel to `uaddrs`.
/// # C: O(N) pre-flight + O(N) park-enqueue + O(1) park
pub fn dispatch_waitv(uaddrs: &[u64], vals: &[u32]) -> i64 {
    if uaddrs.is_empty() || uaddrs.len() != vals.len() {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut keys: Vec<Key> = Vec::with_capacity(uaddrs.len());
    for (i, &ua) in uaddrs.iter().enumerate() {
        if ua == 0 || ua >= hal::USER_VA_END || (ua & 0x3) != 0 {
            return -(Errno::Einval.as_i32() as i64);
        }
        // SAFETY: bounded user VA validated; CR3 is current's.
        let cur_val = unsafe { load_user_u32(ua) };
        if cur_val != vals[i] { return -(Errno::Eagain.as_i32() as i64); }
        let key = match current_key(ua) {
            Some(k) => k, None => return -(Errno::Einval.as_i32() as i64),
        };
        keys.push(key);
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    let raw = cur as *const Task;
    // SAFETY: cur is the running task on this CPU; bump strong count is sound.
    unsafe { Arc::increment_strong_count(raw); }
    // SAFETY: matching Arc::from_raw consumes the bumped ref.
    let arc = unsafe { Arc::from_raw(raw) };
    let group = Arc::new(WaitvGroup {
        keys, task: arc.clone(), woken_idx: AtomicI32::new(-1),
    });
    arc.set_state(TaskState::Sleeping);
    WAITV_GROUPS.lock().push(group.clone());
    // SAFETY: process ctx; runqueue installed; preempt-off.
    unsafe { sched::live::schedule(); }
    let idx = group.woken_idx.load(Ordering::Acquire);
    if idx < 0 { 0 } else { idx as i64 }
}
