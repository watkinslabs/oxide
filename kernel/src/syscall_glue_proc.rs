// P3-08 process-shaped syscalls split out of `syscall_glue.rs`
// to keep that file under the 1000-line cap per `08§7`. Houses
// `sys_sched_yield`, `sys_gettid`, `sys_set_tid_address`. Other
// task-introspection (getpid/getppid) stay in syscall_glue
// because they're tightly coupled to the dispatch trace.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_sched_yield()` — slot 24 per docs/15§5. Cooperative
/// reschedule per `13§7`: if a runqueue is installed, calls
/// `tick_yield` which picks a different runnable task and
/// switches into it. Returns 0 unconditionally per Linux ABI.
/// # C: O(log N) CFS pick + O(1) ctxsw
pub fn kernel_sys_sched_yield(_args: &SyscallArgs) -> i64 {
    if crate::sched::global().is_some() {
        // SAFETY: process ctx; runqueue installed; preempt-off through the syscall handler; tick_yield saves into current.arch_ctx + Context::switch's away.
        unsafe { crate::sched::tick_yield(); }
    }
    0
}

/// `sys_gettid()` — slot 186. Returns the current task's `tid`.
/// v1 single-thread-per-process → tgid == tid (`sys_getpid`
/// returns the same value).
/// # C: O(1)
pub fn kernel_sys_gettid(_args: &SyscallArgs) -> i64 {
    crate::sched::current().map(|c| c.tid as i64).unwrap_or(1)
}

/// `sys_set_tid_address(tidptr)` — slot 218. Linux stores
/// `tidptr` for CLONE_CHILD_CLEARTID futex wake on thread exit.
/// v1 single-thread → no-op; return current tid.
/// # C: O(1)
pub fn kernel_sys_set_tid_address(_args: &SyscallArgs) -> i64 {
    crate::sched::current().map(|c| c.tid as i64).unwrap_or(1)
}

/// `sys_futex(uaddr, op, val, ts, uaddr2, val3)` — slot 202.
/// v1 minimal: FUTEX_WAKE returns 0 (no blocked waiters since we
/// don't park), FUTEX_WAIT returns 0 (spurious wake — caller
/// rechecks). Anything else returns 0. Real wait queue per
/// docs/24 rides P3 follow-up.
/// # C: O(1)
pub fn kernel_sys_futex(_args: &SyscallArgs) -> i64 { 0 }

/// `sys_clone3(cl_args, size)` — slot 435. v1 stub: return
/// `-ENOSYS` so musl falls back to single-threaded code paths.
/// Real CLONE_VM/CLONE_FS/CLONE_FILES/CLONE_SIGHAND lands with
/// the threading subsystem.
/// # C: O(1)
pub fn kernel_sys_clone3(_args: &SyscallArgs) -> i64 {
    -(syscall::errno::Errno::Enosys.as_i32() as i64)
}

/// `sys_mprotect(addr, len, prot)` — slot 10. v1: accept and
/// no-op. Real per-page PTE prot bits + W^X enforcement rides
/// the VMA permission rewrite per docs/11§6.
/// # C: O(1)
pub fn kernel_sys_mprotect(_args: &SyscallArgs) -> i64 { 0 }

/// `sys_madvise(addr, len, advice)` — slot 28. v1: hint-only,
/// no-op. MADV_DONTNEED zero-fill rides docs/11§9.
/// # C: O(1)
pub fn kernel_sys_madvise(_args: &SyscallArgs) -> i64 { 0 }

/// `sys_prlimit64(pid, resource, new, old)` — slot 302. v1
/// returns 0 — no rlimit enforcement yet.
/// # C: O(1)
pub fn kernel_sys_prlimit64(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let pid      = args.a0 as u32;
    let resource = args.a1 as usize;
    let new_ptr  = args.a2;
    let old_ptr  = args.a3;
    if resource >= sched::rlimit::rlim::COUNT {
        return -(Errno::Einval.as_i32() as i64);
    }
    let task = if pid == 0 {
        crate::sched::current().and_then(|c| crate::sched::registry::lookup(c.tid))
    } else {
        crate::sched::registry::lookup(pid)
    };
    let task = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };

    if old_ptr != 0 && old_ptr < hal::USER_VA_END {
        // SAFETY: same single-mutator invariant as getrlimit.
        let (rcur, rmax) = unsafe { (*task.rlimits.get())[resource] };
        // SAFETY: old_ptr validated; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile( old_ptr       as *mut u64, rcur);
            core::ptr::write_volatile((old_ptr + 8)  as *mut u64, rmax);
        }
    }
    if new_ptr != 0 && new_ptr < hal::USER_VA_END {
        // SAFETY: validated; CPL=0 reads through caller's AS.
        let (nc, nm) = unsafe {
            let c = core::ptr::read_volatile( new_ptr       as *const u64);
            let m = core::ptr::read_volatile((new_ptr + 8)  as *const u64);
            (c, m)
        };
        let pair = match sched::rlimit::clamp_pair(nc, nm) {
            Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
        };
        // SAFETY: rlimits write — task may not be `current` but the slot
        // is single-mutator in v1's UP scheduler model (no preemption mid-syscall).
        unsafe { (*task.rlimits.get())[resource] = pair; }
    }
    0
}

/// `sys_rt_sigaction(sig, act, oldact, sz)` — slot 13. P3-64:
/// reads + stores the user-supplied `struct sigaction` into the
/// per-task `sigactions` array; writes the prior to `oldact` if
/// non-NULL. Layout (Linux x86_64):
///   { sa_handler: u64, sa_flags: u64, sa_restorer: u64, sa_mask: u64 }
/// = 32 bytes. v1 ignores beyond the first 4 fields.
/// # C: O(1)
pub fn kernel_sys_rt_sigaction(args: &SyscallArgs) -> i64 {
    use sched::SaHandler;
    use syscall::errno::Errno;
    let sig = args.a0 as usize;
    let act    = args.a1;
    let oldact = args.a2;
    let _sz    = args.a3;
    if sig == 0 || sig > 64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return 0,
    };
    let idx = sig - 1;
    // SAFETY: running task on this CPU; preempt-off; sole writer to sigactions slot per single-mutator invariant.
    let table = unsafe { &mut *cur.sigactions.get() };
    let prior = table[idx];
    if oldact != 0 && oldact < hal::USER_VA_END {
        // SAFETY: oldact validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile( oldact         as *mut u64, prior.handler);
            core::ptr::write_volatile((oldact +   8)  as *mut u64, prior.flags);
            core::ptr::write_volatile((oldact +  16)  as *mut u64, prior.restorer);
            core::ptr::write_volatile((oldact +  24)  as *mut u64, prior.mask);
        }
    }
    if act != 0 {
        if act >= hal::USER_VA_END {
            return -(Errno::Efault.as_i32() as i64);
        }
        // SAFETY: act validated < USER_VA_END; user page mapped via active CR3 (caller's AS); CPL=0 reads through user mapping per `15§3`; 8-byte aligned per Linux ABI.
        let (h, f, r, m) = unsafe { (
            core::ptr::read_volatile( act         as *const u64),
            core::ptr::read_volatile((act +   8)  as *const u64),
            core::ptr::read_volatile((act +  16)  as *const u64),
            core::ptr::read_volatile((act +  24)  as *const u64),
        ) };
        table[idx] = SaHandler { handler: h, flags: f, restorer: r, mask: m };
    }
    0
}

/// `sys_rt_sigprocmask(how, set, oldset, sz)` — slot 14. P3-22:
/// updates `current.sigmask` per Linux semantics:
/// - SIG_BLOCK   (0): mask |= set
/// - SIG_UNBLOCK (1): mask &= !set
/// - SIG_SETMASK (2): mask = set
/// Writes the prior mask to `oldset` if non-NULL. `sz` must be 8.
/// # C: O(1)
pub fn kernel_sys_rt_sigprocmask(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    const SIG_BLOCK:   u64 = 0;
    const SIG_UNBLOCK: u64 = 1;
    const SIG_SETMASK: u64 = 2;
    let how    = args.a0;
    let set    = args.a1;
    let oldset = args.a2;
    let sz     = args.a3;
    if sz != 8 { return -(Errno::Einval.as_i32() as i64); }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return 0,
    };
    let prior = cur.sigmask.load(Ordering::Acquire);
    if oldset != 0 && oldset < hal::USER_VA_END {
        // SAFETY: oldset validated < USER_VA_END; user page mapped via active CR3 (caller's AS); CPL=0 writes through user mapping.
        unsafe { core::ptr::write_volatile(oldset as *mut u64, prior); }
    }
    if set == 0 { return 0; }
    if set >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // SAFETY: set validated < USER_VA_END; user page mapped via active CR3 (caller's AS); CPL=0 reads through user mapping.
    let new_set = unsafe { core::ptr::read_volatile(set as *const u64) };
    let new_mask = match how {
        SIG_BLOCK   => prior | new_set,
        SIG_UNBLOCK => prior & !new_set,
        SIG_SETMASK => new_set,
        _           => return -(Errno::Einval.as_i32() as i64),
    };
    // SIGKILL (9) and SIGSTOP (19) cannot be blocked — clear those bits.
    let new_mask = new_mask & !(1u64 << 8) & !(1u64 << 18);
    cur.sigmask.store(new_mask, Ordering::Release);
    0
}

/// `sys_sigaltstack(ss, oldss)` — slot 131. v1 stub: signal
/// frames don't exist yet; accept and ignore.
/// # C: O(1)
pub fn kernel_sys_sigaltstack(_args: &SyscallArgs) -> i64 { 0 }

/// `sys_nanosleep(req, rem)` — slot 35. v1 busy-wait: spins on
/// the per-arch monotonic clock until the requested ns has
/// elapsed, yielding via `tick_yield` between checks so other
/// runnable tasks can make progress. `rem` ignored (no signal
/// interruption yet). `req` is `timespec { tv_sec: i64, tv_nsec: i64 }`.
/// # C: O(req_ns / yield_quantum)
pub fn kernel_sys_nanosleep(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    use syscall::errno::Errno;
    let req = args.a0;
    if req == 0 || req >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // SAFETY: req validated < USER_VA_END; user page mapped (caller's AS); CPL=0 reads via active CR3.
    let secs = unsafe { core::ptr::read_volatile(req as *const i64) };
    // SAFETY: same validated range; tv_nsec at +8 is 8-byte aligned per Linux ABI.
    let nsec = unsafe { core::ptr::read_volatile((req + 8) as *const i64) };
    if secs < 0 || nsec < 0 || nsec >= 1_000_000_000 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let total = (secs as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64);
    #[cfg(target_arch = "x86_64")]
    let now = || hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let now = || hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let start = now();
    let deadline = start.saturating_add(total);
    while now() < deadline {
        if crate::sched::global().is_some() {
            // SAFETY: process ctx; runqueue installed; preempt-off through the syscall handler; tick_yield saves into current.arch_ctx + Context::switch's away.
            unsafe { crate::sched::tick_yield(); }
        } else {
            core::hint::spin_loop();
        }
    }
    0
}

/// `sys_rseq(rseq, len, flags, sig)` — slot 334. Linux's
/// restartable-sequences ABI for fast cancellation. v1: musl
/// happily falls back when this returns -ENOSYS.
/// # C: O(1)
pub fn kernel_sys_rseq(_args: &SyscallArgs) -> i64 {
    -(syscall::errno::Errno::Enosys.as_i32() as i64)
}

/// `sys_getresuid(ruid, euid, suid)` / `sys_getresgid` — slots
/// 118/120. Writes (0,0,0) into all three user pointers — root
/// everywhere, no separate saved-uid concept in v1.
/// # C: O(1)
pub fn kernel_sys_getres_uid(args: &SyscallArgs) -> i64 {
    for &p in &[args.a0, args.a1, args.a2] {
        if p != 0 && p < hal::USER_VA_END {
            // SAFETY: each pointer validated < USER_VA_END; CPL=0 writes through caller's AS.
            unsafe { core::ptr::write_volatile(p as *mut u32, 0); }
        }
    }
    0
}

/// `sys_rt_sigpending(set, sz)` — slot 127. Writes
/// `current.sigpending` to user `set` (8 B). `sz` must be 8.
/// # C: O(1)
pub fn kernel_sys_rt_sigpending(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let set = args.a0;
    let sz  = args.a1;
    if sz != 8 { return -(Errno::Einval.as_i32() as i64); }
    if set == 0 || set >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match crate::sched::current() { Some(c) => c, None => return 0 };
    let p = cur.sigpending.load(Ordering::Acquire);
    // SAFETY: set validated < USER_VA_END; user page mapped via active CR3 (caller's AS); CPL=0 writes through user mapping.
    unsafe { core::ptr::write_volatile(set as *mut u64, p); }
    0
}

/// `sys_rt_sigsuspend(mask, sz)` — slot 130. Temporarily
/// replaces sigmask with `mask`. v1 has no real wait — returns
/// -EINTR immediately; `take_lowest_pending` at the dispatch
/// tail will terminate the task if any unmasked signal is
/// already pending under the new mask.
/// # C: O(1)
pub fn kernel_sys_rt_sigsuspend(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let mask = args.a0;
    let sz   = args.a1;
    if sz != 8 { return -(Errno::Einval.as_i32() as i64); }
    if mask == 0 || mask >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Eintr.as_i32() as i64),
    };
    // SAFETY: mask validated < USER_VA_END; user page mapped via active CR3 (caller's AS); CPL=0 reads through user mapping.
    let m = unsafe { core::ptr::read_volatile(mask as *const u64) };
    let m = m & !(1u64 << 8) & !(1u64 << 18); // SIGKILL/SIGSTOP unmaskable
    cur.sigmask.store(m, Ordering::Release);
    -(Errno::Eintr.as_i32() as i64)
}

/// One signal ready for delivery: number + the registered
/// sa_handler. `handler == 0` ⇒ SIG_DFL (terminate per `27§2`);
/// `handler == 1` ⇒ SIG_IGN (drop); else user fn pointer.
#[derive(Copy, Clone, Debug)]
pub struct PendingSignal {
    pub sig:      u32,
    pub handler:  u64,
    pub flags:    u64,
    pub restorer: u64,
}

/// Inspect `current.sigpending & !current.sigmask`; if non-zero,
/// clear the lowest bit and return the `PendingSignal`. The
/// caller decides delivery: SIG_DFL→terminate, SIG_IGN→drop,
/// other→build a signal frame and jump.
/// # C: O(1)
pub fn take_lowest_pending() -> Option<PendingSignal> {
    use core::sync::atomic::Ordering;
    let cur = crate::sched::current()?;
    let pending = cur.sigpending.load(Ordering::Acquire);
    let masked  = cur.sigmask.load(Ordering::Acquire);
    let deliver = pending & !masked;
    if deliver == 0 { return None; }
    let sig = deliver.trailing_zeros() + 1;
    cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
    // SAFETY: running task on this CPU; preempt-off; sole reader of sigactions slot per single-mutator invariant in `13§5`.
    let table = unsafe { &*cur.sigactions.get() };
    let h = table[(sig - 1) as usize];
    Some(PendingSignal {
        sig,
        handler:  h.handler,
        flags:    h.flags,
        restorer: h.restorer,
    })
}

/// `sys_getrlimit(res, rlim)` — slot 97. Reads the per-task
/// rlimit slot for `res` and writes `(cur, max)` to user `rlim`.
/// # C: O(1)
pub fn kernel_sys_getrlimit(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let resource = args.a0 as usize;
    let rlim = args.a1;
    if rlim == 0 || rlim >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if resource >= sched::rlimit::rlim::COUNT {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: rlimits slot single-mutator per `13§5`; current task is the running task on this CPU.
    let (rcur, rmax) = unsafe { (*cur.rlimits.get())[resource] };
    // SAFETY: rlim validated < USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile( rlim       as *mut u64, rcur);
        core::ptr::write_volatile((rlim + 8)  as *mut u64, rmax);
    }
    0
}

/// `sys_setrlimit(res, rlim)` — slot 160. Reads `(cur, max)` from
/// user `rlim`, validates `cur <= max`, writes to per-task slot.
/// # C: O(1)
pub fn kernel_sys_setrlimit(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let resource = args.a0 as usize;
    let rlim = args.a1;
    if rlim == 0 || rlim >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if resource >= sched::rlimit::rlim::COUNT {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: rlim validated < USER_VA_END; CPL=0 reads through caller's AS.
    let (new_cur, new_max) = unsafe {
        let c = core::ptr::read_volatile( rlim       as *const u64);
        let m = core::ptr::read_volatile((rlim + 8)  as *const u64);
        (c, m)
    };
    let pair = match sched::rlimit::clamp_pair(new_cur, new_max) {
        Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
    };
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: same single-mutator invariant as the getrlimit reader.
    unsafe { (*cur.rlimits.get())[resource] = pair; }
    0
}

/// `sys_getrusage(who, usage)` — slot 98. Writes a 144-byte
/// `struct rusage` of zeros. v1 has no per-task accounting.
/// # C: O(1)
pub fn kernel_sys_getrusage(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let _who = args.a0;
    let buf = args.a1;
    if buf == 0 || buf >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: validated 144-byte user buf < USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        for off in (0..144u64).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
    }
    0
}

/// `sys_times(tms)` — slot 100. Writes `struct tms { utime,
/// stime, cutime, cstime }` (4 × i64) of zeros and returns the
/// monotonic clock in CLK_TCK ticks (100 Hz).
/// # C: O(1)
pub fn kernel_sys_times(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    let buf = args.a0;
    if buf != 0 && buf < hal::USER_VA_END {
        // SAFETY: validated 32-byte user buf below USER_VA_END; CPL=0 writes through caller's AS.
        unsafe {
            for off in (0..32u64).step_by(8) {
                core::ptr::write_volatile((buf + off) as *mut u64, 0);
            }
        }
    }
    #[cfg(target_arch = "x86_64")]
    let ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    (ns / 10_000_000) as i64
}

/// `sys_sysinfo(info)` — slot 99. Writes a minimal struct
/// sysinfo (112 B) — uptime, loads, totalram, freeram, etc.
/// v1 fills uptime + zero everything else.
/// # C: O(1)
pub fn kernel_sys_sysinfo(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    use syscall::errno::Errno;
    let buf = args.a0;
    if buf == 0 || buf >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    #[cfg(target_arch = "x86_64")]
    let ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let uptime = (ns / 1_000_000_000) as i64;
    // SAFETY: 112-byte user buffer validated < USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        for off in (0..112u64).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
        core::ptr::write_volatile(buf as *mut i64, uptime);
    }
    0
}

/// `sys_mremap(old, old_sz, new_sz, flags, new_addr)` — slot 25.
/// v1: returns -ENOMEM unconditionally; libc falls back to
/// mmap+memcpy+munmap which we already support.
/// # C: O(1)
pub fn kernel_sys_mremap(_args: &SyscallArgs) -> i64 {
    -(syscall::errno::Errno::Enomem.as_i32() as i64)
}

/// `sys_msync(addr, len, flags)` — slot 26. v1 has no
/// file-backed VMAs to flush; succeed.
/// # C: O(1)
pub fn kernel_sys_msync(_args: &SyscallArgs) -> i64 { 0 }

/// `sys_mincore(addr, len, vec)` — slot 27. Reports residency
/// of pages in [addr, addr+len) into `vec`. v1 conservatively
/// reports every page resident (bit 0 set per byte).
/// # C: O(len/4096)
pub fn kernel_sys_mincore(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let _addr = args.a0;
    let len   = args.a1;
    let vec   = args.a2;
    let pages = (len + 0xfff) / 0x1000;
    if vec == 0 || vec.checked_add(pages).map_or(true, |e| e >= hal::USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: validated user range below USER_VA_END; CPL=0 writes through caller's AS; pages bytes inside the validated range.
    unsafe {
        for i in 0..pages {
            core::ptr::write_volatile((vec + i) as *mut u8, 1);
        }
    }
    0
}

/// `sys_mlock` / `sys_munlock` / `sys_mlockall` / `sys_munlockall`
/// — slots 149/150/151/152. v1 has no swap; every page is
/// effectively locked. Accept and return 0.
/// # C: O(1)
pub fn kernel_sys_mlock_family(_args: &SyscallArgs) -> i64 { 0 }

/// `sys_getpgrp` — slot 111. Returns the current task's pgid.
/// # C: O(1)
pub fn kernel_sys_getpgrp(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    crate::sched::current().map(|c| c.pgid.load(Ordering::Acquire) as i64).unwrap_or(1)
}

/// `sys_getpgid(pid)` — slot 121. `pid==0` means the current task.
/// # C: O(N_tasks) for non-self lookup
pub fn kernel_sys_getpgid(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let pid = args.a0 as u32;
    let task = if pid == 0 {
        crate::sched::current().and_then(|c| crate::sched::registry::lookup(c.tid))
    } else {
        crate::sched::registry::lookup(pid)
    };
    match task {
        Some(t) => t.pgid.load(Ordering::Acquire) as i64,
        None    => -(syscall::errno::Errno::Esrch.as_i32() as i64),
    }
}

/// `sys_getsid(pid)` — slot 124. `pid==0` means the current task.
/// # C: O(N_tasks) for non-self lookup
pub fn kernel_sys_getsid(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let pid = args.a0 as u32;
    let task = if pid == 0 {
        crate::sched::current().and_then(|c| crate::sched::registry::lookup(c.tid))
    } else {
        crate::sched::registry::lookup(pid)
    };
    match task {
        Some(t) => t.sid.load(Ordering::Acquire) as i64,
        None    => -(syscall::errno::Errno::Esrch.as_i32() as i64),
    }
}

/// `sys_setpgid(pid, pgid)` — slot 109. Sets target task's pgid.
/// `pid==0` means current; `pgid==0` means use the target's tid.
/// Returns -ESRCH if the target task isn't live.
/// # C: O(N_tasks)
pub fn kernel_sys_setpgid(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let pid  = args.a0 as u32;
    let pgid = args.a1 as u32;
    let task = if pid == 0 {
        crate::sched::current().and_then(|c| crate::sched::registry::lookup(c.tid))
    } else {
        crate::sched::registry::lookup(pid)
    };
    let t = match task { Some(t) => t, None => return -(syscall::errno::Errno::Esrch.as_i32() as i64) };
    let new_pgid = if pgid == 0 { t.tid } else { pgid };
    t.pgid.store(new_pgid, Ordering::Release);
    0
}

/// `sys_setsid()` — slot 112. Makes the caller a session leader:
/// new sid = new pgid = tid. Returns the new sid.
/// # C: O(1)
pub fn kernel_sys_setsid(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let cur = match crate::sched::current() { Some(c) => c, None => return 1 };
    cur.sid.store(cur.tid, Ordering::Release);
    cur.pgid.store(cur.tid, Ordering::Release);
    cur.tid as i64
}

/// `sys_umask(mask)` — slot 95. v1 returns 0o022 as the prior
/// mask and forgets the new one.
/// # C: O(1)
pub fn kernel_sys_umask(_args: &SyscallArgs) -> i64 { 0o022 }

/// `sys_getcpu(cpu, node, tcache)` — slot 309. v1 single-CPU UP →
/// always returns CPU 0, NUMA node 0.
/// # C: O(1)
pub fn kernel_sys_getcpu(args: &SyscallArgs) -> i64 {
    let cpu  = args.a0;
    let node = args.a1;
    if cpu  != 0 && cpu  < hal::USER_VA_END {
        // SAFETY: cpu pointer validated < USER_VA_END; CPL=0 writes through caller's AS via active CR3.
        unsafe { core::ptr::write_volatile(cpu  as *mut u32, 0); }
    }
    if node != 0 && node < hal::USER_VA_END {
        // SAFETY: node pointer validated < USER_VA_END; same AS as above.
        unsafe { core::ptr::write_volatile(node as *mut u32, 0); }
    }
    0
}

/// `sys_sched_getparam(pid, param)` — slot 143. v1: writes
/// sched_priority=0 (only meaningful for RT classes).
/// # C: O(1)
pub fn kernel_sys_sched_getparam(args: &SyscallArgs) -> i64 {
    let p = args.a1;
    if p != 0 && p < hal::USER_VA_END {
        // SAFETY: p validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe { core::ptr::write_volatile(p as *mut i32, 0); }
    }
    0
}

/// `sys_sched_setscheduler` / `sys_sched_getscheduler` —
/// slots 144/145. v1 always reports SCHED_OTHER (0); set is no-op.
/// # C: O(1)
pub fn kernel_sys_sched_getscheduler(_args: &SyscallArgs) -> i64 { 0 }

/// `sys_sched_get_priority_max(policy)` — slot 146. v1: 99 for
/// SCHED_FIFO/RR, 0 otherwise.
/// # C: O(1)
pub fn kernel_sys_sched_get_priority_max(args: &SyscallArgs) -> i64 {
    let policy = args.a0 as i32;
    match policy { 1 | 2 => 99, _ => 0 }
}

/// `sys_sched_get_priority_min(policy)` — slot 147. v1: 1 for
/// SCHED_FIFO/RR, 0 otherwise.
/// # C: O(1)
pub fn kernel_sys_sched_get_priority_min(args: &SyscallArgs) -> i64 {
    let policy = args.a0 as i32;
    match policy { 1 | 2 => 1, _ => 0 }
}

/// `sys_sched_getaffinity(pid, cpusetsize, mask)` — slot 204.
/// v1: writes a single-bit mask covering CPU 0; returns 8.
/// # C: O(1)
pub fn kernel_sys_sched_getaffinity(args: &SyscallArgs) -> i64 {
    let cpusetsize = args.a1;
    let mask = args.a2;
    if mask == 0 || mask >= hal::USER_VA_END || cpusetsize < 8 {
        return -(syscall::errno::Errno::Einval.as_i32() as i64);
    }
    // SAFETY: mask validated < USER_VA_END; cpusetsize >= 8 guarantees the 8-byte write fits; CPL=0 writes through caller's AS.
    unsafe { core::ptr::write_volatile(mask as *mut u64, 1); }
    8
}

/// `sys_sched_setaffinity` — slot 203. v1 single-CPU → no-op.
/// # C: O(1)
pub fn kernel_sys_sched_setaffinity(_args: &SyscallArgs) -> i64 { 0 }

/// `sys_prctl(option, ...)` — slot 157. v1 honours
/// PR_SET_NAME / PR_GET_NAME (no-op since name is &'static str)
/// and PR_SET_DUMPABLE / PR_GET_DUMPABLE; returns 0 elsewhere.
/// # C: O(1)
pub fn kernel_sys_prctl(args: &SyscallArgs) -> i64 {
    const PR_SET_NAME:     u64 = 15;
    const PR_GET_NAME:     u64 = 16;
    const PR_SET_DUMPABLE: u64 = 4;
    const PR_GET_DUMPABLE: u64 = 3;
    match args.a0 {
        PR_SET_NAME | PR_SET_DUMPABLE => 0,
        PR_GET_DUMPABLE              => 1,
        PR_GET_NAME => {
            let p = args.a1;
            if p != 0 && p < hal::USER_VA_END {
                let name = crate::sched::current().map(|c| c.name).unwrap_or("oxide");
                let n = name.len().min(15);
                // SAFETY: p validated < USER_VA_END; n bytes from a 'static str fit in the user 16-byte name buf.
                unsafe {
                    for i in 0..n {
                        core::ptr::write_volatile((p + i as u64) as *mut u8, name.as_bytes()[i]);
                    }
                    core::ptr::write_volatile((p + n as u64) as *mut u8, 0);
                }
            }
            0
        }
        _ => 0,
    }
}

/// `sys_membarrier(cmd, flags, cpu_id)` — slot 324. v1 single-
/// CPU UP: every memory op is already globally ordered, so any
/// MEMBARRIER_CMD_* request succeeds vacuously.
/// # C: O(1)
pub fn kernel_sys_membarrier(_args: &SyscallArgs) -> i64 { 0 }

/// `sys_clock_nanosleep(clk_id, flags, req, rem)` — slot 230.
/// v1: ignores clk_id + flags, reuses `kernel_sys_nanosleep` on
/// the req timespec. TIMER_ABSTIME would compute deadline from
/// the timespec directly; v1 treats all values as relative.
/// # C: same as nanosleep
pub fn kernel_sys_clock_nanosleep(args: &SyscallArgs) -> i64 {
    let inner = SyscallArgs { a0: args.a2, a1: args.a3, a2: 0, a3: 0, a4: 0, a5: 0 };
    kernel_sys_nanosleep(&inner)
}

/// `sys_kill(pid, sig)` — slot 62. pgrp-aware per `28§4`:
///   pid > 0 — signal that tid via the registry.
///   pid == 0 — fan to caller's pgrp.
///   pid == -1 — not implemented; -EPERM.
///   pid <  -1 — fan to pgrp `(-pid)`.
/// `sig == 0` is a permission probe.
/// # C: O(N_tasks) on pgrp fan; O(N_tasks) lookup for non-self pid
pub fn kernel_sys_kill(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let pid = args.a0 as i32;
    let sig = args.a1 as i32;
    if !(0..=64).contains(&sig) { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(syscall::errno::Errno::Esrch.as_i32() as i64),
    };
    let bit = if sig == 0 { 0 } else { 1u64 << (sig - 1) };
    if pid > 0 {
        if pid as u32 == cur.tid {
            if sig != 0 { cur.sigpending.fetch_or(bit, Ordering::Release); }
            return 0;
        }
        match crate::sched::registry::lookup(pid as u32) {
            Some(t) => {
                if sig != 0 {
                    t.sigpending.fetch_or(bit, Ordering::Release);
                    if sig == 18 { crate::sched::registry::wake_if_stopped(&t); }
                }
                0
            }
            None => -(syscall::errno::Errno::Esrch.as_i32() as i64),
        }
    } else if pid == 0 {
        let pgid = cur.pgid.load(Ordering::Acquire);
        let n = post_pgrp(pgid, bit, sig);
        if n == 0 { -(syscall::errno::Errno::Esrch.as_i32() as i64) } else { 0 }
    } else if pid == -1 {
        -(syscall::errno::Errno::Eperm.as_i32() as i64)
    } else {
        let n = post_pgrp((-pid) as u32, bit, sig);
        if n == 0 { -(syscall::errno::Errno::Esrch.as_i32() as i64) } else { 0 }
    }
}

fn post_pgrp(pgid: u32, bit: u64, sig: i32) -> usize {
    use core::sync::atomic::Ordering;
    let tasks = crate::sched::registry::tasks_in_pgrp(pgid);
    let n = tasks.len();
    if sig != 0 {
        for t in &tasks {
            t.sigpending.fetch_or(bit, Ordering::Release);
            // SIGCONT (18) wakes a Stopped target per signal(7).
            if sig == 18 { crate::sched::registry::wake_if_stopped(t); }
        }
    }
    n
}

/// `sys_tgkill(tgid, tid, sig)` — slot 234. v1: routes via
/// `kernel_sys_kill` keyed on tid.
/// # C: same as kill
pub fn kernel_sys_tgkill(args: &SyscallArgs) -> i64 {
    let kill_args = SyscallArgs { a0: args.a1, a1: args.a2, a2: 0, a3: 0, a4: 0, a5: 0 };
    kernel_sys_kill(&kill_args)
}

/// `sys_sethostname(name, len)` — slot 170. Writes the global
/// hostname slot read by uname.nodename + /proc/sys/kernel/hostname.
/// # C: O(N)
pub fn kernel_sys_sethostname(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let ptr = args.a0;
    let len = args.a1 as usize;
    if len > crate::hostname::HOST_NAME_MAX { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = crate::syscall_glue::validate_user_buf(ptr, len as u64, 1) { return rv; }
    let mut buf = [0u8; crate::hostname::HOST_NAME_MAX];
    // SAFETY: ptr range validated < USER_VA_END; CPL=0 reads through caller's AS.
    unsafe {
        for i in 0..len { buf[i] = core::ptr::read_volatile((ptr + i as u64) as *const u8); }
    }
    crate::hostname::set(&buf[..len]);
    0
}

/// `sys_getuid` / `sys_geteuid` / `sys_getgid` / `sys_getegid`
/// — slots 102/107/104/108. v1 single-user; always returns 0 (root).
/// # C: O(1)
pub fn kernel_sys_getuid_zero(_args: &SyscallArgs) -> i64 { 0 }
