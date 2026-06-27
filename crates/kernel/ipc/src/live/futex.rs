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
const FUTEX_WAIT_BITSET: u32 = 9;
const FUTEX_WAKE_BITSET: u32 = 10;
const FUTEX_OP_MASK:    u32 = 0x7f;
/// `FUTEX_PRIVATE_FLAG` (linux/futex.h): the futex is process-private, so it is
/// keyed on `(mm, va)` rather than physical page. Same numeric value as
/// FUTEX2_PRIVATE used by the futex2 (`futex_wait`/`futex_wake`) syscalls.
pub const FUTEX_PRIVATE_FLAG: u32 = 0x80;

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
fn current_key(uaddr: u64, private: bool) -> Option<Key> {
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
    // Fall back to the private key if the page isn't mapped yet (translate
    // None): the WAIT path already faulted it in via the value read, and a
    // same-process key is correct when no other process shares the page.
    match pa {
        Some(pa) => Some(Key { mm_root: 0, va: pa }),
        None => Some(Key { mm_root: mm.root_pa(), va: uaddr }),
    }
}

/// Read u32 at user VA `uaddr`. Caller is the syscall path with
/// current's CR3 active, so a direct kernel-mode load through
/// the user mapping resolves via the user PT (demand-faulted by
/// `user_as_fault_handler` if not yet present).
unsafe fn load_user_u32(uaddr: u64) -> u32 {
    // SAFETY: caller validated uaddr < USER_VA_END; current's mm is the active CR3 because we are on its syscall stack.
    unsafe { core::ptr::read_volatile(uaddr as *const u32) }
}

/// Write u32 at user VA `uaddr`. Same active-CR3 contract as `load_user_u32`;
/// used by `FUTEX_WAKE_OP`'s atomic RMW on the second futex word.
/// # SAFETY: caller validated `uaddr` is a 4-aligned mapped user word.
unsafe fn store_user_u32(uaddr: u64, val: u32) {
    // SAFETY: caller validated uaddr < USER_VA_END + 4-aligned; current's mm is the active CR3.
    unsafe { core::ptr::write_volatile(uaddr as *mut u32, val); }
}

/// Back-compat shim for callers without a timeout (deadline 0 = block forever).
/// # C: O(W) waiters per WAKE; O(1) WAIT
pub fn dispatch(uaddr: u64, op_full: u32, val: u32) -> i64 {
    dispatch_timed(uaddr, op_full, val, 0)
}

/// `dispatch` + absolute monotonic deadline (ns). `deadline_ns == 0` means no
/// timeout. FUTEX_WAIT/FUTEX_WAIT_BITSET park with the deadline so a timed wait
/// (glibc pthread_cond_timedwait / sem_timedwait / any timeout-only futex)
/// actually wakes on expiry and returns ETIMEDOUT instead of hanging forever.
/// # C: O(W) waiters per WAKE; O(1) WAIT
pub fn dispatch_timed(uaddr: u64, op_full: u32, val: u32, deadline_ns: u64) -> i64 {
    if uaddr == 0 || uaddr >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if (uaddr & 0x3) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let private = (op_full & FUTEX_PRIVATE_FLAG) != 0;
    match op_full & FUTEX_OP_MASK {
        // BITSET variants: v1 ignores the bitmask (treat as match-any), which
        // is correct for glibc's MATCH_ANY usage and harmless otherwise.
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            // SAFETY: bounded user VA validated above; CR3 is current's.
            let cur_val = unsafe { load_user_u32(uaddr) };
            if cur_val != val { return -(Errno::Eagain.as_i32() as i64); }
            // DIAG (debug-boot): a process about to PARK on a futex in the high
            // library region — names the lock value it sees. A single-threaded
            // process parking means the word is "contended"; if it's a fork-
            // inherited / non-zeroed-BSS garbage value, this shows it.
            #[cfg(feature = "debug-boot")]
            if uaddr >= 0x7fff_0000_0000 {
                let nm = sched::live::current()
                    .and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s| s.clone()) })
                    .unwrap_or_default();
                klog::write_raw(b"[futex park] uaddr="); klog::write_hex_u64(uaddr);
                klog::write_raw(b" val="); klog::write_dec_u64(val as u64);
                klog::write_raw(b" exe="); klog::write_raw(nm.as_bytes());
                klog::write_raw(b"\n");
            }
            // Atomically park self + push to waiters under the lock so a
            // concurrent FUTEX_WAKE can't see us pre-park.
            let key = match current_key(uaddr, private) {
                Some(k) => k, None => return -(Errno::Einval.as_i32() as i64),
            };
            let cur = match sched::live::current() {
                Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
            };
            let tid = cur.tid;
            // DIAG (debug-mount): for a no-timeout WAIT (the wedge pattern), log
            // the VMA backing of the futex word — File(page-cache) vs
            // KernelBytes(loader) vs Anonymous — and its file offset, so a stuck
            // glibc lock can be traced to the exact file+offset it lives in.
            #[cfg(feature = "debug-mount")]
            if (uaddr & !0xfff) == 0x7ffffe88d000 {
                let mut vstart: u64 = 0;
                let mut voff: u64 = 0;
                let mut vprot: u8 = 0;
                let mut vino: u64 = 0;
                let (kind, foff): (&str, u64) = match unsafe { cur.mm_ref() } {
                    None => ("NOMM", 0),
                    // SAFETY: single-mutator mm slot per 13§5.
                    Some(mm) => match hal::UserVirtAddr::new(uaddr).and_then(|u| mm.find_vma(u)) {
                        None => ("NOVMA", 0),
                        Some(v) => {
                            // Log the VMA's own start/off/prot so a mis-mapped
                            // writable segment (RW VMA pointing at a .text file
                            // offset → glibc lock inits to code bytes ≠ 0 →
                            // self-deadlock) is unambiguous.
                            vstart = v.start.as_u64();
                            vprot = v.prot.bits();
                            match &v.backing {
                                vmm::VmaBacking::File { off, backing } => { voff = *off; vino = backing.ino();
                                    ("File", off.wrapping_add(uaddr - v.start.as_u64())) }
                                vmm::VmaBacking::KernelBytes { off, .. } => { voff = *off as u64;
                                    ("KernelBytes", (*off as u64).wrapping_add(uaddr - v.start.as_u64())) }
                                vmm::VmaBacking::Anonymous => ("Anon", 0),
                                _ => ("Other", 0),
                            }
                        }
                    },
                };
                // AS root_pa: match to FFAULT-LOCK's root= to tell whether the
                // process that faulted this frame is the SAME one now stuck
                // (intra-process stray write) or a different one (cross-process
                // COW-shared frame written by a peer).
                let root = unsafe { cur.mm_ref() }.map(|m| m.root_pa()).unwrap_or(0);
                klog::write_raw(b"[mnt] FUTEXWAIT root=");
                klog::write_hex_u64(root);
                klog::write_raw(b" op=");
                klog::write_hex_u64((op_full & FUTEX_OP_MASK) as u64);
                klog::write_raw(b" dl=");
                klog::write_hex_u64(deadline_ns);
                klog::write_raw(b" uaddr=");
                klog::write_hex_u64(uaddr);
                klog::write_raw(b" val=");
                klog::write_dec_u64(val as u64);
                klog::write_raw(b" backing=");
                klog::write_raw(kind.as_bytes());
                klog::write_raw(b" foff=");
                klog::write_hex_u64(foff);
                klog::write_raw(b" vstart=");
                klog::write_hex_u64(vstart);
                klog::write_raw(b" voff=");
                klog::write_hex_u64(voff);
                klog::write_raw(b" prot=");
                klog::write_hex_u64(vprot as u64);
                klog::write_raw(b" ino=");
                klog::write_dec_u64(vino);
                // Frame PA backing uaddr right now. Compare to FFAULT-LOCK's
                // pa= for this process: SAME pa → the lock frame was written in
                // place (stray write / live share); DIFFERENT pa → the PTE was
                // remapped to another frame (a mapping/COW bug).
                klog::write_raw(b" fpa=");
                {
                    use hal::{MmuOps, Va};
                    #[cfg(target_arch = "x86_64")]
                    let fpa = hal_x86_64::mmu_ops::X86Mmu::translate(Va(uaddr)).map(|(p, _)| p.0 & !0xfff).unwrap_or(0);
                    #[cfg(target_arch = "aarch64")]
                    let fpa = hal_aarch64::mmu_ops::ArmMmu::translate(Va(uaddr)).map(|(p, _)| p.0 & !0xfff).unwrap_or(0);
                    klog::write_hex_u64(fpa);
                }
                // Dump the words SURROUNDING the futex word: if they read as
                // ASCII file bytes (e.g. "-messages.c") the .bss page still has
                // raw file content (ld.so's zero-fill never landed → memory
                // bug); if they're 0 the page IS zeroed and val=2 is a genuine
                // held lock (a real lost-wakeup, not a memory bug).
                klog::write_raw(b" ctx=");
                let base = uaddr & !0xf;
                for i in 0..8u64 {
                    // SAFETY: same page as the validated futex word; CR3 current's.
                    let w = unsafe { load_user_u32(base.wrapping_add(i * 4)) };
                    klog::write_hex_u64(w as u64);
                    klog::write_raw(b",");
                }
                klog::write_raw(b"\n");
            }
            // Arm the per-task wake deadline; tick_wake_expired rouses us at
            // `deadline_ns` (leaving us in WAITERS, so resume can tell a
            // timeout from a real FUTEX_WAKE by our list membership).
            if deadline_ns != 0 {
                cur.wakeup_deadline_ns.store(deadline_ns, core::sync::atomic::Ordering::Release);
            }
            // Bump strong count to materialise an Arc the WAITERS list
            // can hold across the schedule.
            let raw = cur as *const Task;
            // SAFETY: cur came from sched::current() and is the running task on this CPU; bumping the strong count is sound.
            unsafe { Arc::increment_strong_count(raw); }
            // SAFETY: matching Arc::from_raw consumes the bumped ref.
            let arc = unsafe { Arc::from_raw(raw) };
            // Re-check the futex word UNDER the WAITERS lock, then enqueue,
            // atomically. FUTEX_WAKE also takes WAITERS, so a wake that lands
            // after the holder released the lock either (a) runs before our
            // lock → our re-read sees the new value → EAGAIN, no park; or (b)
            // runs after our push → finds us and wakes. The earlier line-140
            // check is only a fast path: without THIS re-read under the lock a
            // wake landing between that read and the enqueue is lost → the
            // waiter parks forever (the intermittent boot wedge: glibc's
            // __exit_funcs_lock left contended=2 with no waker). Linux holds
            // the hash-bucket lock across exactly this check+enqueue.
            {
                let mut w = WAITERS.lock();
                // SAFETY: bounded user VA validated above; CR3 is the caller's.
                if unsafe { load_user_u32(uaddr) } != val {
                    drop(w);
                    // Not parking: release the Arc ref bumped above + disarm.
                    drop(arc);
                    cur.wakeup_deadline_ns.store(0, core::sync::atomic::Ordering::Release);
                    return -(Errno::Eagain.as_i32() as i64);
                }
                arc.set_state(TaskState::Sleeping);
                cur.futex_uaddr.store(uaddr, core::sync::atomic::Ordering::Relaxed);
                w.push(Waiter { key, task: arc });
            }
            // SAFETY: process ctx; runqueue installed; preempt-off.
            unsafe { sched::live::schedule(); }
            cur.futex_uaddr.store(0, core::sync::atomic::Ordering::Relaxed);
            // Resume. Clear any armed deadline. If we're still in WAITERS,
            // FUTEX_WAKE didn't remove us → the tick woke us at the deadline:
            // remove self + report ETIMEDOUT. Otherwise a real wake (or
            // spurious) → 0, caller rechecks the futex word.
            cur.wakeup_deadline_ns.store(0, core::sync::atomic::Ordering::Release);
            if remove_waiter(tid) && deadline_ns != 0 {
                return -(Errno::Etimedout.as_i32() as i64);
            }
            0
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            let key = match current_key(uaddr, private) {
                Some(k) => k, None => return -(Errno::Einval.as_i32() as i64),
            };
            let n = wake_key(key, val as usize);
            // DIAG (debug-mount): trace WAKEs on the stuck libc lock page. If a
            // WAKE for this va NEVER appears, the holder died/exited without
            // releasing (fork-inherited lock); if it appears but wakes 0, the
            // waiter's key didn't match (keying/COW bug).
            #[cfg(feature = "debug-mount")]
            if (uaddr & !0xfff) == 0x7ffffe88d000 {
                let tid = sched::live::current().map(|c| c.tid).unwrap_or(0);
                klog::write_raw(b"[mnt] FUTEXWAKE uaddr=");
                klog::write_hex_u64(uaddr);
                klog::write_raw(b" woke=");
                klog::write_dec_u64(n as u64);
                klog::write_raw(b" by_tid=");
                klog::write_dec_u64(tid as u64);
                klog::write_raw(b"\n");
            }
            n as i64
        }
        _ => 0,
    }
}

/// Remove the waiter with `tid` from WAITERS; returns true if it was present
/// (i.e. NOT already removed by a FUTEX_WAKE — so the wake came from the
/// deadline tick or a signal).
/// # C: O(W)
fn remove_waiter(tid: u32) -> bool {
    let mut w = WAITERS.lock();
    if let Some(i) = w.iter().position(|x| x.task.tid == tid) {
        w.swap_remove(i);
        true
    } else {
        false
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

/// Requeue (slot 456): wake up to `nr_wake` waiters on `src_uaddr`, then move
/// up to `nr_requeue` of the REMAINING `src` waiters onto `dst_uaddr` (re-key,
/// no wake). Returns the number of waiters woken (Linux futex-requeue
/// semantics). Single-key waiters only — waitv groups are left untouched.
/// # C: O(W)
pub fn requeue(src_uaddr: u64, dst_uaddr: u64, nr_wake: usize, nr_requeue: usize, private: bool) -> i64 {
    let src = match current_key(src_uaddr, private) { Some(k) => k, None => return -(Errno::Einval.as_i32() as i64) };
    let dst = match current_key(dst_uaddr, private) { Some(k) => k, None => return -(Errno::Einval.as_i32() as i64) };
    let mut woken: Vec<Arc<Task>> = Vec::new();
    {
        let mut w = WAITERS.lock();
        // Phase 1: collect up to nr_wake src waiters to wake.
        let mut i = 0;
        while i < w.len() && woken.len() < nr_wake {
            if w[i].key == src { woken.push(w.swap_remove(i).task); } else { i += 1; }
        }
        // Phase 2: re-key up to nr_requeue remaining src waiters → dst.
        let mut moved = 0;
        for waiter in w.iter_mut() {
            if moved >= nr_requeue { break; }
            if waiter.key == src { waiter.key = dst; moved += 1; }
        }
    }
    if !woken.is_empty() {
        if let Some(rq) = sched::live::global() {
            let mut inner = rq.inner.lock();
            for t in &woken {
                t.set_state(TaskState::Runnable);
                t.lift_vruntime(inner.cfs.min_vruntime());
                inner.enqueue(t.clone());
            }
            rq.nr_running.store(inner.nr_running(), Ordering::Release);
            sched::live::preempt::set_need_resched();
        }
    }
    woken.len() as i64
}

/// `FUTEX_CMP_REQUEUE` (classic op 4): like `requeue`, but first verify
/// `*src_uaddr == cmpval` (the futex word the caller last saw) — if it changed,
/// return EAGAIN so the caller retries instead of requeueing stale waiters.
/// This is what glibc's pthread_cond_broadcast / older condvars use to move
/// waiters from the cond futex onto the associated mutex. # C: O(W)
pub fn cmp_requeue(src_uaddr: u64, dst_uaddr: u64, nr_wake: usize, nr_requeue: usize, cmpval: u32, private: bool) -> i64 {
    if src_uaddr == 0 || src_uaddr >= hal::USER_VA_END || (src_uaddr & 0x3) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: bounded user VA validated; CR3 is current's.
    let cur = unsafe { load_user_u32(src_uaddr) };
    if cur != cmpval { return -(Errno::Eagain.as_i32() as i64); }
    requeue(src_uaddr, dst_uaddr, nr_wake, nr_requeue, private)
}

/// `FUTEX_WAKE_OP` (classic op 5): atomically apply an op to `*uaddr2`, wake up
/// to `nr_wake` waiters on `uaddr1`, then if the OLD `*uaddr2` satisfies the
/// encoded comparison, wake up to `nr_wake2` waiters on `uaddr2`. Linux
/// `futex_wake_op` — glibc uses it in some condvar/lock fast paths. The RMW is
/// atomic by the single-CPU preempt-off syscall invariant. # C: O(W)
pub fn wake_op(uaddr1: u64, uaddr2: u64, nr_wake: usize, nr_wake2: usize, encoded: u32, private: bool) -> i64 {
    for ua in [uaddr1, uaddr2] {
        if ua == 0 || ua >= hal::USER_VA_END || (ua & 0x3) != 0 {
            return -(Errno::Einval.as_i32() as i64);
        }
    }
    // Decode (linux/futex.h): bits 28..31 op (0x8 = OPARG_SHIFT), 24..27 cmp,
    // 12..23 oparg, 0..11 cmparg.
    let op = (encoded >> 28) & 0x7;
    let oparg_shift = (encoded >> 28) & 0x8 != 0;
    let cmp = (encoded >> 24) & 0xf;
    let mut oparg = ((encoded >> 12) & 0xfff) as i32;
    let cmparg = (encoded & 0xfff) as i32;
    if oparg_shift { oparg = 1i32 << (oparg & 0x1f); }
    // SAFETY: bounded user VA validated; CR3 is current's; preempt-off makes the
    // read-modify-write atomic vs other tasks on this UP CPU.
    let oldval = unsafe { load_user_u32(uaddr2) } as i32;
    let newval = match op {
        0 => oparg,              // SET
        1 => oldval.wrapping_add(oparg),
        2 => oldval | oparg,     // OR
        3 => oldval & !oparg,    // ANDN
        4 => oldval ^ oparg,     // XOR
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    // SAFETY: same validated user word; CPL=0 store through the active CR3.
    unsafe { store_user_u32(uaddr2, newval as u32); }
    let k1 = match current_key(uaddr1, private) { Some(k) => k, None => return -(Errno::Einval.as_i32() as i64) };
    let mut woken = wake_key(k1, nr_wake);
    let do_wake2 = match cmp {
        0 => oldval == cmparg,
        1 => oldval != cmparg,
        2 => oldval < cmparg,
        3 => oldval <= cmparg,
        4 => oldval > cmparg,
        5 => oldval >= cmparg,
        _ => false,
    };
    if do_wake2 {
        if let Some(k2) = current_key(uaddr2, private) { woken += wake_key(k2, nr_wake2); }
    }
    woken as i64
}

/// Robust-futex bits (linux/futex.h). glibc stores the owner's TID in the low
/// 30 bits of a robust mutex word; the kernel ORs OWNER_DIED on owner death.
const FUTEX_WAITERS:    u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK:   u32 = 0x3fff_ffff;
const ROBUST_LIST_LIMIT: usize = 2048;

/// Linux `exit_robust_list` (kernel/futex): on thread death, walk the user
/// `robust_list_head` this thread registered via set_robust_list and, for every
/// robust mutex it still owns, mark FUTEX_OWNER_DIED and wake one waiter so a
/// peer blocked on that mutex can recover (glibc's mutex lock returns
/// EOWNERDEAD). Without this, a thread that dies — crash or normal exit —
/// holding a robust mutex strands every waiter forever (the boot wedge: init
/// parks in waitid while a service hangs on a dead owner's lock).
///
/// `owner_tid` is the dying thread's userspace TID (== gettid, the value glibc
/// wrote into the word). Runs in the dying task's address space (CR3 live).
/// # SAFETY: caller is the exit/fault path with the dying task's mm active.
/// # C: O(min(list_len, ROBUST_LIST_LIMIT))
pub fn exit_robust_list(head_uaddr: u64, owner_tid: u32) {
    if head_uaddr == 0 || head_uaddr >= hal::USER_VA_END || (head_uaddr & 0x7) != 0 { return; }
    // robust_list_head { list.next @+0; long futex_offset @+8; *list_op_pending @+16 }.
    let rd = |va: u64| -> Option<u64> {
        if va == 0 || va >= hal::USER_VA_END || (va & 0x7) != 0 { return None; }
        // SAFETY: bounded, 8-aligned user VA; dying task's CR3 is active.
        Some(unsafe { core::ptr::read_volatile(va as *const u64) })
    };
    let futex_offset = match rd(head_uaddr + 8) { Some(v) => v as i64, None => return };
    let pending = rd(head_uaddr + 16).unwrap_or(0);
    let mut entry = match rd(head_uaddr) { Some(v) => v, None => return };
    let mut n = 0usize;
    // The list is circular, terminating back at &head->list. Bound the walk so a
    // corrupt list can't spin the kernel.
    while entry != head_uaddr && n < ROBUST_LIST_LIMIT {
        if entry != pending {
            handle_futex_death((entry as i64).wrapping_add(futex_offset) as u64, owner_tid);
        }
        entry = match rd(entry) { Some(v) => v, None => break };
        n += 1;
    }
    // The in-progress lock/unlock (list_op_pending) is handled last, as Linux does.
    if pending != 0 {
        handle_futex_death((pending as i64).wrapping_add(futex_offset) as u64, owner_tid);
    }
}

/// Recover one robust mutex owned by a dying thread (Linux `handle_futex_death`).
/// # C: O(W) waiters on wake
fn handle_futex_death(futex_uaddr: u64, owner_tid: u32) {
    if futex_uaddr == 0 || futex_uaddr >= hal::USER_VA_END || (futex_uaddr & 0x3) != 0 { return; }
    // SAFETY: bounded, 4-aligned user word; dying task's CR3 active.
    let val = unsafe { load_user_u32(futex_uaddr) };
    // Only recover words this thread actually owns (TID in the low 30 bits).
    if (val & FUTEX_TID_MASK) != owner_tid || (val & FUTEX_OWNER_DIED) != 0 { return; }
    // Mark owner-died, drop the owner TID, preserve the waiters bit.
    let newval = (val & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
    // SAFETY: same validated user word; CPL=0 store through the active CR3.
    unsafe { store_user_u32(futex_uaddr, newval); }
    if val & FUTEX_WAITERS != 0 {
        // Robust mutexes may be process-private or -shared; wake on BOTH keyings
        // (over-wake is harmless — a spurious wake just rechecks the word) so a
        // cross-process waiter is reached too.
        if let Some(k) = current_key(futex_uaddr, true)  { wake_key(k, 1); }
        if let Some(k) = current_key(futex_uaddr, false) { wake_key(k, 1); }
    }
}

/// Multi-futex wait: park current task on N keys; resume when ANY
/// of them is woken (returns the index that woke). Pre-flight
/// check: if any `*uaddr != val` at entry, return -EAGAIN
/// immediately per Linux semantics. `vals` is parallel to `uaddrs`.
/// # C: O(N) pre-flight + O(N) park-enqueue + O(1) park
pub fn dispatch_waitv(uaddrs: &[u64], vals: &[u32], private: bool) -> i64 {
    dispatch_waitv_timed(uaddrs, vals, private, 0)
}

/// `dispatch_waitv` plus an absolute monotonic deadline. Linux futex waitv
/// waits may be timed; an expired deadline wakes the task through the same
/// `wakeup_deadline_ns` scanner used by single-futex waits.
/// # C: O(N) pre-flight + O(N) park-enqueue + O(W) timeout cleanup
pub fn dispatch_waitv_timed(uaddrs: &[u64], vals: &[u32], private: bool, deadline_ns: u64) -> i64 {
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
        let key = match current_key(ua, private) {
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
    if deadline_ns != 0 {
        cur.wakeup_deadline_ns.store(deadline_ns, core::sync::atomic::Ordering::Release);
    }
    {
        let mut groups = WAITV_GROUPS.lock();
        for (i, &ua) in uaddrs.iter().enumerate() {
            // SAFETY: bounded user VA validated above; CR3 is the caller's.
            if unsafe { load_user_u32(ua) } != vals[i] {
                cur.wakeup_deadline_ns.store(0, core::sync::atomic::Ordering::Release);
                return -(Errno::Eagain.as_i32() as i64);
            }
        }
        arc.set_state(TaskState::Sleeping);
        cur.futex_uaddr.store(uaddrs[0], core::sync::atomic::Ordering::Relaxed);
        groups.push(group.clone());
    }
    // SAFETY: process ctx; runqueue installed; preempt-off.
    unsafe { sched::live::schedule(); }
    cur.futex_uaddr.store(0, core::sync::atomic::Ordering::Relaxed);
    cur.wakeup_deadline_ns.store(0, core::sync::atomic::Ordering::Release);
    let idx = group.woken_idx.load(Ordering::Acquire);
    if idx < 0 {
        if remove_waitv_group(&group) && deadline_ns != 0 {
            return -(Errno::Etimedout.as_i32() as i64);
        }
        0
    } else {
        idx as i64
    }
}

/// Remove a waitv group that woke without a futex wake, normally through the
/// deadline scanner. Returns true if the group was still queued.
/// # C: O(G)
fn remove_waitv_group(target: &Arc<WaitvGroup>) -> bool {
    let mut g = WAITV_GROUPS.lock();
    if let Some(i) = g.iter().position(|x| Arc::ptr_eq(x, target)) {
        g.swap_remove(i);
        true
    } else {
        false
    }
}
