use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

use sched::{Task, TaskState};
use sync::{Spinlock, Tty as TtyClass};

pub(super) const FUTEX_WAIT: u32 = 0;
pub(super) const FUTEX_WAKE: u32 = 1;
pub(super) const FUTEX_WAIT_BITSET: u32 = 9;
pub(super) const FUTEX_WAKE_BITSET: u32 = 10;
pub(super) const FUTEX_OP_MASK: u32 = 0x7f;
/// `FUTEX_PRIVATE_FLAG` (linux/futex.h): the futex is process-private, so it is
/// keyed on `(mm, va)` rather than physical page. Same numeric value as
/// FUTEX2_PRIVATE used by the futex2 (`futex_wait`/`futex_wake`) syscalls.
pub const FUTEX_PRIVATE_FLAG: u32 = 0x80;

#[derive(Copy, Clone, Eq, PartialEq)]
pub(super) struct Key {
    /// Address-space root (CR3 pa) — distinguishes processes.
    pub(super) mm_root: u64,
    /// User VA of the futex word. We don't translate to phys since
    /// v1 process-private; mm_root + va is a stable identity.
    pub(super) va: u64,
}

pub(super) struct Waiter {
    pub(super) key: Key,
    pub(super) task: Arc<Task>,
}

/// Multi-futex wait group. Used by `futex_waitv` — a single task
/// parks on N keys at once; the first key that fires wakes the
/// task and records its index in `woken_idx`. Other group entries
/// are reaped lazily on the next wake-walk.
pub(super) struct WaitvGroup {
    pub(super) keys: Vec<Key>,
    pub(super) task: Arc<Task>,
    /// -1 until a key wakes us; then the matching index. CAS
    /// guarantees only one waker delivers the wake.
    pub(super) woken_idx: AtomicI32,
}

pub(super) static WAITERS: Spinlock<Vec<Waiter>, TtyClass> = Spinlock::new(Vec::new());
pub(super) static WAITV_GROUPS: Spinlock<Vec<Arc<WaitvGroup>>, TtyClass> = Spinlock::new(Vec::new());

/// Compute the futex key (Linux `get_futex_key`).
///
/// * `private` (FUTEX_PRIVATE_FLAG / FUTEX2_PRIVATE) → key on `(mm_root, va)`.
///   Per-process: two processes' private futexes at the same VA (e.g. a COW
///   page right after fork) must NOT alias, so we deliberately do NOT use the
///   physical page here.
/// * shared → key on the PHYSICAL PAGE of the futex word `(0, pa)`. Two
///   processes mapping the same page (different `mm_root`, possibly different
///   VA — `mmap(MAP_SHARED)`, a shared memfd, /dev/shm) then hash to the SAME
///   key, so a cross-process `FUTEX_WAKE` actually reaches the waiter. Without
///   this, shared futexes deadlocked (the documented "process-private only"
///   gap). The VA is translated under the active CR3 (we are on the caller's
///   syscall stack, so its address space is live).
/// # C: O(1) private; O(page-table depth) shared
pub(super) fn current_key(uaddr: u64, private: bool) -> Option<Key> {
    let cur = sched::live::current()?;
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = unsafe { cur.mm_ref() }?;
    if private {
        return Some(Key { mm_root: mm.root_pa(), va: uaddr });
    }
    use hal::{MmuOps, Va};
    #[cfg(target_arch = "x86_64")]
    let pa = hal_x86_64::mmu_ops::X86Mmu::translate(Va(uaddr)).map(|(p, _)| p.0);
    #[cfg(target_arch = "aarch64")]
    let pa = hal_aarch64::mmu_ops::ArmMmu::translate(Va(uaddr)).map(|(p, _)| p.0);
    match pa {
        Some(pa) => Some(Key { mm_root: 0, va: pa }),
        None => Some(Key { mm_root: mm.root_pa(), va: uaddr }),
    }
}

/// Read u32 at user VA `uaddr`. Caller is the syscall path with
/// current's CR3 active, so a direct kernel-mode load through
/// the user mapping resolves via the user PT (demand-faulted by
/// `user_as_fault_handler` if not yet present).
pub(super) unsafe fn load_user_u32(uaddr: u64) -> u32 {
    // SAFETY: caller validated uaddr < USER_VA_END; current's mm is the active CR3 because we are on its syscall stack.
    unsafe { core::ptr::read_volatile(uaddr as *const u32) }
}

/// Write u32 at user VA `uaddr`. Same active-CR3 contract as `load_user_u32`;
/// used by `FUTEX_WAKE_OP`'s atomic RMW on the second futex word.
/// # SAFETY: caller validated `uaddr` is a 4-aligned mapped user word.
pub(super) unsafe fn store_user_u32(uaddr: u64, val: u32) {
    // SAFETY: caller validated uaddr < USER_VA_END + 4-aligned; current's mm is the active CR3.
    unsafe { core::ptr::write_volatile(uaddr as *mut u32, val); }
}

/// Remove the waiter with `tid` from WAITERS; returns true if it was present
/// (i.e. NOT already removed by a FUTEX_WAKE — so the wake came from the
/// deadline tick or a signal).
/// # C: O(W)
pub(super) fn remove_waiter(tid: u32) -> bool {
    let mut w = WAITERS.lock();
    if let Some(i) = w.iter().position(|x| x.task.tid == tid) {
        w.swap_remove(i);
        true
    } else {
        false
    }
}

/// Remove a waitv group that woke without a futex wake, normally through the
/// deadline scanner. Returns true if the group was still queued.
/// # C: O(G)
pub(super) fn remove_waitv_group(target: &Arc<WaitvGroup>) -> bool {
    let mut g = WAITV_GROUPS.lock();
    if let Some(i) = g.iter().position(|x| Arc::ptr_eq(x, target)) {
        g.swap_remove(i);
        true
    } else {
        false
    }
}

/// Wake up to `n_target` waiters parked on `key`. Walks both the
/// single-key WAITERS list and any WAITV_GROUPS holding `key` as
/// one of their keys; each group fires at most once (CAS on
/// `woken_idx`).
pub(super) fn wake_key(key: Key, n_target: usize) -> usize {
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
