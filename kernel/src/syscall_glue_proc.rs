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
pub fn kernel_sys_prlimit64(_args: &SyscallArgs) -> i64 { 0 }

/// `sys_rt_sigaction(sig, act, oldact, sz)` — slot 13. v1
/// stub: stores nothing, returns 0. Real signal-handler dispatch
/// + signal frame on user stack per docs/27 rides P3 follow-up.
/// # C: O(1)
pub fn kernel_sys_rt_sigaction(_args: &SyscallArgs) -> i64 { 0 }

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

/// Inspect `current.sigpending & !current.sigmask`; if non-zero,
/// clear the lowest bit and return its 1-based signal number for
/// the caller to deliver. v1 has no sa_handler dispatch — caller
/// terminates the task per the default-disposition table in
/// `27§2`.
/// # C: O(1)
pub fn take_lowest_pending() -> Option<u32> {
    use core::sync::atomic::Ordering;
    let cur = crate::sched::current()?;
    let pending = cur.sigpending.load(Ordering::Acquire);
    let masked  = cur.sigmask.load(Ordering::Acquire);
    let deliver = pending & !masked;
    if deliver == 0 { return None; }
    let sig = deliver.trailing_zeros() + 1;
    cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
    Some(sig)
}

/// `sys_getrlimit(res, rlim)` — slot 97. Writes (rlim_cur,
/// rlim_max) for the resource. v1: every limit is unbounded
/// (RLIM_INFINITY = u64::MAX). `rlim` is `struct rlimit { u64
/// rlim_cur; u64 rlim_max; }`.
/// # C: O(1)
pub fn kernel_sys_getrlimit(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let _resource = args.a0;
    let rlim = args.a1;
    if rlim == 0 || rlim >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: rlim validated < USER_VA_END; user page mapped via active CR3 (caller's AS); CPL=0 writes through user mapping.
    unsafe {
        core::ptr::write_volatile( rlim       as *mut u64, u64::MAX);
        core::ptr::write_volatile((rlim + 8)  as *mut u64, u64::MAX);
    }
    0
}

/// `sys_setrlimit(res, rlim)` — slot 160. v1 accepts any new
/// limit and forgets it (no enforcement yet).
/// # C: O(1)
pub fn kernel_sys_setrlimit(_args: &SyscallArgs) -> i64 { 0 }

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
