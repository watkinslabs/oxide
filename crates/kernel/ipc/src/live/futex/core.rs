use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use sched::Task;
use syscall::errno::Errno;
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
/// `FUTEX_PRIVATE_FLAG` (futex UAPI): the futex is process-private, so it is
/// keyed on `(mm, va)` rather than physical page. Same numeric value as
/// FUTEX2_PRIVATE used by the futex2 (`futex_wait`/`futex_wake`) syscalls.
pub const FUTEX_PRIVATE_FLAG: u32 = 0x80;
/// `FUTEX_CLOCK_REALTIME` (futex UAPI): pair the wait's absolute deadline
/// with `CLOCK_REALTIME` instead of `CLOCK_MONOTONIC`. Linux `do_futex`
/// restricts this modifier to `FUTEX_WAIT_BITSET`/`FUTEX_WAIT_REQUEUE_PI`/
/// `FUTEX_LOCK_PI2` and returns `-ENOSYS` for any other cmd (`kernel/futex/
/// syscalls.c` `FLAGS_CLOCKRT` check) — callers must replicate that gate.
pub const FUTEX_CLOCK_REALTIME: u32 = 0x100;
/// `FUTEX_ROBUST_UNLOCK`: atomically release the futex word and clear the
/// robust-list `list_op_pending` slot supplied as `uaddr2`.
pub const FUTEX_ROBUST_UNLOCK: u32 = 0x200;
/// `FUTEX_ROBUST_LIST32`: the pending slot is a compat (32-bit) pointer.
pub const FUTEX_ROBUST_LIST32: u32 = 0x400;
/// Linux `FUTEX_CMD_MASK`: all four UAPI modifiers are outside the command.
/// Extracts the command from `op`, leaving any other stray high bits intact
/// so an out-of-range op number falls through to the real "unknown cmd"
/// path instead of being silently truncated into a valid low command.
pub const FUTEX_CMD_MASK: u32 =
    !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME | FUTEX_ROBUST_UNLOCK | FUTEX_ROBUST_LIST32);
/// Linux `FUTEX_BITSET_MATCH_ANY`: the implicit bitset for plain
/// `FUTEX_WAIT`/`FUTEX_WAKE` (and any wake path — requeue, wake_op — that
/// does not carry a caller bitset), matching every waiter regardless of its
/// registered bitset.
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xffff_ffff;

/// Which identity a [`Key`] is built from. Without the discriminant a shared
/// object's id could numerically equal a page-table root and alias a private
/// futex belonging to an unrelated process.
#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) enum KeyKind {
    /// `(mm root, user VA)` — a process-private futex.
    Private,
    /// `(object identity, offset in object)` — Linux's inode-keyed shared futex.
    SharedObject,
    /// `(0, physical address)` — a shared mapping with no stable object
    /// identity (shared anonymous memory), whose pages stay resident.
    SharedPhys,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) struct Key {
    /// What `mm_root`/`va` mean.
    pub(crate) kind: KeyKind,
    /// Address-space root (CR3 pa) — distinguishes processes.
    pub(crate) mm_root: u64,
    /// User VA of the futex word. We don't translate to phys since
    /// v1 process-private; mm_root + va is a stable identity.
    pub(crate) va: u64,
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

/// A non-task consumer of a futex wait queue. io_uring uses this form so a
/// request can remain armed without pinning an io-wq worker in `schedule()`.
pub trait WaitCallback: Send + Sync {
    /// The futex wake removed this registration. The callback must arrange
    /// the consumer's own progress; it must not sleep.
    fn wake(&self, index: usize);
}

struct CallbackWaiter {
    id: u64,
    keys: Vec<Key>,
    callback: Arc<dyn WaitCallback>,
    bitset: u32,
}

/// Registration owned by the caller. Dropping it removes an un-fired
/// callback; a callback removed by `wake_key` is already absent.
pub struct WaitRegistration { id: u64 }

static NEXT_CALLBACK_ID: AtomicU64 = AtomicU64::new(1);

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
static CALLBACKS: Spinlock<Vec<CallbackWaiter>, TtyClass> = Spinlock::new(Vec::new());

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
pub(crate) fn current_key(uaddr: u64, private: bool) -> Option<Key> {
    let cur = sched::live::current()?;
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = unsafe { cur.mm_ref() }?;
    if private {
        return Some(Key { kind: KeyKind::Private, mm_root: mm.root_pa(), va: uaddr });
    }
    // Linux `get_futex_key`: the physical/inode key is used ONLY for a genuinely
    // shared (VM_SHARED) mapping. A "shared" futex OP on a PRIVATE mapping (anon
    // or MAP_PRIVATE file — e.g. a glibc process-shared condvar that still lives
    // in private-anon memory) keys on `(mm, addr)`, exactly like a private op.
    // Otherwise a shared-op WAIT and a private-op WAKE on the SAME private-anon
    // word compute different keys (phys vs mm+va) and the wake is lost — the
    // journald flush hang that wedged sysinit (main thread WAITs shared, worker
    // WAKEs private on the same condvar word).
    let vma = hal::UserVirtAddr::new(uaddr).and_then(|u| mm.find_vma(u));
    let vm_shared = vma.as_ref().map(|v| v.flags.contains(vmm::VmaFlags::SHARED)).unwrap_or(false);
    if !vm_shared {
        return Some(Key { kind: KeyKind::Private, mm_root: mm.root_pa(), va: uaddr });
    }
    // Preferred: key on the OBJECT and the offset within it, which is what
    // Linux's `get_futex_key` does for a `VM_SHARED` file mapping. Two
    // processes mapping one file at different addresses then agree on the key,
    // and — unlike a physical-page key — it survives the page being evicted and
    // read back at a different physical address between the WAIT and the WAKE,
    // which would otherwise silently lose the wakeup.
    if let Some(v) = vma.as_ref() {
        if let vmm::VmaBacking::File { backing, off } = &v.backing {
            let obj = backing.object_id();
            if obj != 0 {
                let file_off = off.wrapping_add(uaddr - v.start.as_u64());
                return Some(Key { kind: KeyKind::SharedObject, mm_root: obj, va: file_off });
            }
        }
    }
    // Shared ANONYMOUS memory (and any backing with no stable object identity)
    // has no inode to key on. Its pages are permanently resident, so the
    // physical page IS a stable identity for as long as the mapping exists.
    use hal::{MmuOps, Va};
    #[cfg(target_arch = "x86_64")]
    let pa = hal_x86_64::mmu_ops::X86Mmu::translate(Va(uaddr)).map(|(p, _)| p.0);
    #[cfg(target_arch = "aarch64")]
    let pa = hal_aarch64::mmu_ops::ArmMmu::translate(Va(uaddr)).map(|(p, _)| p.0);
    match pa {
        Some(pa) => Some(Key { kind: KeyKind::SharedPhys, mm_root: 0, va: pa }),
        None => Some(Key { kind: KeyKind::Private, mm_root: mm.root_pa(), va: uaddr }),
    }
}

impl Drop for WaitRegistration {
    fn drop(&mut self) { CALLBACKS.lock().retain(|w| w.id != self.id); }
}

/// Register a callback after the Linux value check and the same recheck-under-
/// queue-lock that task waits use. `Err(Eagain)` means the word already
/// changed and no registration was made.
pub fn register_callback(uaddr: u64, value: u32, bitset: u32, private: bool,
                         callback: Arc<dyn WaitCallback>) -> Result<WaitRegistration, Errno> {
    if bitset == 0 { return Err(Errno::Einval); }
    if load_user_u32(uaddr)? != value { return Err(Errno::Eagain); }
    let key = current_key(uaddr, private).ok_or(Errno::Einval)?;
    let id = NEXT_CALLBACK_ID.fetch_add(1, Ordering::Relaxed);
    let mut g = CALLBACKS.lock();
    if load_user_u32(uaddr)? != value { return Err(Errno::Eagain); }
    g.push(CallbackWaiter { id, keys: alloc::vec![key], callback, bitset });
    Ok(WaitRegistration { id })
}

pub fn register_waitv_callback(entries: &[super::waitv::WaitvEntry],
                               callback: Arc<dyn WaitCallback>) -> Result<WaitRegistration, Errno> {
    if entries.is_empty() { return Err(Errno::Einval); }
    let mut keys = Vec::with_capacity(entries.len());
    for entry in entries {
        if load_user_u32(entry.uaddr)? != entry.val { return Err(Errno::Eagain); }
        keys.push(current_key(entry.uaddr, entry.private).ok_or(Errno::Einval)?);
    }
    let id = NEXT_CALLBACK_ID.fetch_add(1, Ordering::Relaxed);
    let mut g = CALLBACKS.lock();
    for entry in entries {
        if load_user_u32(entry.uaddr)? != entry.val { return Err(Errno::Eagain); }
    }
    g.push(CallbackWaiter { id, keys, callback, bitset: FUTEX_BITSET_MATCH_ANY });
    Ok(WaitRegistration { id })
}

/// Probe the futex word without sleeping. Used by an io_uring worker after a
/// callback wake; `false` is a spurious wake and must be re-armed.
pub fn callback_probe(uaddr: u64, value: u32) -> Result<bool, Errno> {
    Ok(load_user_u32(uaddr)? != value)
}

pub fn callback_probe_waitv(entries: &[super::waitv::WaitvEntry], preferred: i32)
    -> Result<Option<usize>, Errno>
{
    if preferred >= 0 {
        let i = preferred as usize;
        if i < entries.len() && load_user_u32(entries[i].uaddr)? != entries[i].val {
            return Ok(Some(i));
        }
    }
    for (i, entry) in entries.iter().enumerate() {
        if load_user_u32(entry.uaddr)? != entry.val { return Ok(Some(i)); }
    }
    Ok(None)
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

/// Read the u32 at user VA `uaddr`, Linux `futex_get_value_locked` →
/// `__get_user`. Caller is the syscall path with current's CR3 active, so a
/// not-yet-present page is demand-faulted by `user_as_fault_handler`; a page
/// that cannot be resolved at all takes the `__ex_table` fixup and answers
/// EFAULT instead of faulting the kernel. Four bytes on the stack, so the
/// hot FUTEX_WAIT path allocates nothing.
/// # C: O(1)
pub(super) fn load_user_u32(uaddr: u64) -> Result<u32, Errno> {
    crate::useraccess::read_u32(uaddr)
}

/// Write the u32 at user VA `uaddr`, Linux `put_user`. Same recovery contract
/// as `load_user_u32`; used by `FUTEX_WAKE_OP`'s RMW on the second futex word.
/// # C: O(1)
pub(super) fn store_user_u32(uaddr: u64, val: u32) -> Result<(), Errno> {
    crate::useraccess::write_u32(uaddr, val)
}

/// Atomically swap `new` into the user word if it still holds `old`, returning
/// the value seen or EFAULT through the architecture exception table.
/// # C: O(page faults)
pub(super) fn cmpxchg_user_u32(uaddr: u64, old: u32, new: u32) -> Result<u32, Errno> {
    crate::useraccess::cmpxchg_u32(uaddr, old, new)
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
    let mut callbacks = Vec::new();
    if woken.len() < n_target {
        let mut c = CALLBACKS.lock();
        let mut i = 0;
        while i < c.len() && woken.len() + callbacks.len() < n_target {
            if (c[i].bitset & bitset) != 0 {
                if let Some(index) = c[i].keys.iter().position(|k| *k == key) {
                    callbacks.push((c.swap_remove(i).callback, index));
                    continue;
                }
            }
            i += 1;
        }
    }
    let callback_count = callbacks.len();
    for (callback, index) in callbacks { callback.wake(index); }
    if woken.is_empty() { return callback_count; }
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
    n + callback_count
}
