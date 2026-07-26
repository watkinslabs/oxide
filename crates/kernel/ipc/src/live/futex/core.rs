use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

use sched::{Task, TaskState};
use sync::{Spinlock, Tty as TtyClass};

pub(super) const FUTEX_WAIT: u32 = 0;
pub(super) const FUTEX_WAKE: u32 = 1;
// `FUTEX_REQUEUE`(3)/`FUTEX_CMP_REQUEUE`(4)/`FUTEX_WAKE_OP`(5) are intercepted
// earlier, at the syscall shim (`202_futex.rs`), which routes them straight to
// `ops::{requeue, cmp_requeue, wake_op}` — they never reach this dispatch, so
// no constant for them lives here.
pub(super) const FUTEX_FD: u32 = 2;
pub(super) const FUTEX_LOCK_PI: u32 = 6;
pub(super) const FUTEX_UNLOCK_PI: u32 = 7;
pub(super) const FUTEX_TRYLOCK_PI: u32 = 8;
pub(super) const FUTEX_WAIT_BITSET: u32 = 9;
pub(super) const FUTEX_WAKE_BITSET: u32 = 10;
pub(super) const FUTEX_WAIT_REQUEUE_PI: u32 = 11;
pub(super) const FUTEX_CMP_REQUEUE_PI: u32 = 12;
pub(super) const FUTEX_LOCK_PI2: u32 = 13;
/// `FUTEX_PRIVATE_FLAG` (linux/futex.h): the futex is process-private, so it is
/// keyed on `(mm, va)` rather than physical page. Same numeric value as
/// FUTEX2_PRIVATE used by the futex2 (`futex_wait`/`futex_wake`) syscalls.
pub const FUTEX_PRIVATE_FLAG: u32 = 0x80;
/// `FUTEX_CLOCK_REALTIME` (linux/futex.h): pair the wait's absolute deadline
/// with `CLOCK_REALTIME` instead of `CLOCK_MONOTONIC`. Linux `do_futex`
/// restricts this modifier to `FUTEX_WAIT_BITSET`/`FUTEX_WAIT_REQUEUE_PI`/
/// `FUTEX_LOCK_PI2` and returns `-ENOSYS` for any other cmd (`kernel/futex/
/// syscalls.c` `FLAGS_CLOCKRT` check) — callers must replicate that gate.
pub const FUTEX_CLOCK_REALTIME: u32 = 0x100;
/// Linux `FUTEX_CMD_MASK`: `~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)`.
/// Extracts the command from `op`, leaving any other stray high bits intact
/// so an out-of-range op number falls through to the real "unknown cmd"
/// path instead of being silently truncated into a valid low command.
pub const FUTEX_CMD_MASK: u32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
/// Linux `FUTEX_BITSET_MATCH_ANY`: the implicit bitset for plain
/// `FUTEX_WAIT`/`FUTEX_WAKE` (and any wake path — requeue, wake_op — that
/// does not carry a caller bitset), matching every waiter regardless of its
/// registered bitset.
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xffff_ffff;

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
    /// Wake bitset this waiter registered with (`FUTEX_WAIT_BITSET`'s `val3`,
    /// or `FUTEX_BITSET_MATCH_ANY` for plain `FUTEX_WAIT`). A `FUTEX_WAKE_BITSET`
    /// only wakes waiters where `waiter.bitset & wake_bitset != 0` (Linux
    /// `futex_wake`: "Check if one of the bits is set in both bitsets").
    pub(super) bitset: u32,
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
    // Linux `get_futex_key`: the physical/inode key is used ONLY for a genuinely
    // shared (VM_SHARED) mapping. A "shared" futex OP on a PRIVATE mapping (anon
    // or MAP_PRIVATE file — e.g. a glibc process-shared condvar that still lives
    // in private-anon memory) keys on `(mm, addr)`, exactly like a private op.
    // Otherwise a shared-op WAIT and a private-op WAKE on the SAME private-anon
    // word compute different keys (phys vs mm+va) and the wake is lost — the
    // journald flush hang that wedged sysinit (main thread WAITs shared, worker
    // WAKEs private on the same condvar word).
    let vm_shared = hal::UserVirtAddr::new(uaddr)
        .and_then(|u| mm.find_vma(u))
        .map(|v| v.flags.contains(vmm::VmaFlags::SHARED))
        .unwrap_or(false);
    if !vm_shared {
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

/// True iff user VA `va` resolves to a present page in the ACTIVE address
/// space, and — when `need_write` — that page is user-writable, so a CPL=0
/// load (or store) through `va` will NOT #PF. The robust-list exit walk
/// (`robust::exit_robust_list`) uses this to stay fault-safe: it runs on the
/// exit/fault path of a possibly-CRASHING task whose `robust_list_head` and
/// mutex words may be corrupt or unmapped, and a raw `read_volatile` of an
/// unmapped user VA there would #PF the kernel (→ double-fault/hang), a worse
/// regression than a stranded waiter. Translates via the SAME arch MMU walk
/// `current_key` uses for shared-futex keying (the active CR3/TTBR0). O(1) per
/// node, no lock/alloc, IRQ/exit-context safe. Mirrors Linux `get_user`
/// returning -EFAULT (the walk aborts) instead of faulting the kernel.
/// # C: O(page-table depth)
pub(super) fn user_addr_accessible(va: u64, need_write: bool) -> bool {
    use hal::{MmuOps, PageFlags, Va};
    #[cfg(target_arch = "x86_64")]
    let r = hal_x86_64::mmu_ops::X86Mmu::translate(Va(va));
    #[cfg(target_arch = "aarch64")]
    let r = hal_aarch64::mmu_ops::ArmMmu::translate(Va(va));
    match r {
        Some((_, flags)) => !need_write || flags.contains(PageFlags::WRITE),
        None => false,
    }
}

/// Current monotonic ns, arch-dispatched (same clock `202_futex.rs` uses to
/// compute the absolute deadline). `wait::dispatch_timed` uses this to decide
/// whether a woken `FUTEX_WAIT`'s deadline has genuinely elapsed (`ETIMEDOUT`)
/// versus a signal or spurious wake racing the ~100ms-cadence deadline
/// scanner (`tick_wake_expired`), which can flip a task Runnable slightly
/// before or after this read observes the deadline as past.
/// # C: O(1)
pub(super) fn now_monotonic_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    now
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

/// Wake up to `n_target` waiters parked on `key` whose registered bitset
/// intersects `bitset` (Linux `futex_wake`'s `this->bitset & bitset`). Walks
/// both the single-key WAITERS list and any WAITV_GROUPS holding `key` as
/// one of their keys — waitv groups always register as match-any (no
/// per-key bitset in `futex_waitv`), so they are never bitset-filtered.
/// Each group fires at most once (CAS on `woken_idx`).
pub(super) fn wake_key(key: Key, n_target: usize, bitset: u32) -> usize {
    let mut woken: Vec<Arc<Task>> = Vec::new();
    {
        let mut w = WAITERS.lock();
        let mut i = 0;
        while i < w.len() && woken.len() < n_target {
            if w[i].key == key && (w[i].bitset & bitset) != 0 {
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
    let n = woken.len();
    // Route each wake through the scheduler's canonical waker instead of
    // hand-rolling set_state(Runnable)+enqueue. try_to_wake_up does the atomic
    // Sleeping->Runnable CAS claim AND the on_cpu deferral (a task still
    // finishing its context-switch-off on another CPU is routed through that
    // CPU's wake-list, not enqueued live) — required on SMP, where a futex
    // wake of an on_cpu waiter otherwise runs it on two CPUs / on a half-saved
    // context. Matches Linux futex_wake -> wake_up_q -> try_to_wake_up.
    for t in &woken {
        // SAFETY: wake-site; the Arc keeps `t` alive across the call.
        unsafe { sched::live::try_to_wake_up(t.clone()); }
    }
    n
}
