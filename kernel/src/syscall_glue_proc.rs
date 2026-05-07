// P3-08 process-shaped syscalls split out of `syscall_glue.rs`
// to keep that file under the 1000-line cap per `08§7`. Houses
// `sys_sched_yield`, `sys_gettid`, `sys_set_tid_address`. Other
// task-introspection (getpid/getppid) stay in syscall_glue
// because they're tightly coupled to the dispatch trace.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_sched_yield()` — slot 24. tick_yield + 0.
/// # C: O(log N)
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

/// `sys_set_tid_address(tidptr)` — slot 218. Stores the user
/// pointer in `Task.clear_child_tid` per CLONE_CHILD_CLEARTID
/// semantics. v1 single-thread doesn't yet wake-on-exit; the
/// storage is for musl + glibc visibility.
/// # C: O(1)
pub fn kernel_sys_set_tid_address(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let cur = match crate::sched::current() { Some(c) => c, None => return 1 };
    cur.clear_child_tid.store(args.a0, Ordering::Release);
    cur.tid as i64
}

/// `sys_futex(uaddr, op, val, ts, uaddr2, val3)` — slot 202.
/// Delegates to `crate::futex` which keeps a per-(mm_root_pa, va)
/// in-kernel wait queue. Supported ops:
///   FUTEX_WAIT (0) — atomically check `*uaddr == val`; if so park
///                    self until FUTEX_WAKE on the same key.
///   FUTEX_WAKE (1) — wake at most `val` tasks parked on this key.
/// Both ops accept `| FUTEX_PRIVATE_FLAG (128)` and `|
/// FUTEX_CLOCK_REALTIME (256)` masks (treated as no-ops since v1
/// process-private-only with monotonic clock).
/// # C: O(W) waiters per WAKE, O(1) WAIT
pub fn kernel_sys_futex(args: &SyscallArgs) -> i64 {
    crate::futex::dispatch(args.a0, args.a1 as u32, args.a2 as u32)
}

/// `sys_clone3(cl_args, size)` — slot 435. Reads the user
/// `struct clone_args` (Linux ABI; size is the user's view of the
/// struct so future fields can be detected via short-write probe)
/// and routes through the unified clone path. Returns the child
/// tid in the parent, 0 in the child (the spawn machinery wires
/// the child's rax via `ArchCtx::new_user_for_fork`).
///
/// `struct clone_args` layout (Linux v5.5+):
///   u64 flags          — CLONE_* bits, low byte = exit_signal.
///                        clone3 places exit_signal in `exit_signal`
///                        instead of the bottom byte (kernel ANDs it
///                        in at entry); we OR them back together.
///   u64 pidfd          — pidfd writeback (we currently no-op).
///   u64 child_tid      — *ctid (CLONE_CHILD_SETTID/CLEARTID).
///   u64 parent_tid     — *ptid (CLONE_PARENT_SETTID).
///   u64 exit_signal
///   u64 stack          — child stack base.
///   u64 stack_size     — for stacks-grow-down archs we use top = stack+size.
///   u64 tls            — CLONE_SETTLS payload.
///   u64 set_tid        — pid namespace tid array (ignored v1).
///   u64 set_tid_size
///   u64 cgroup         — cgroup fd (ignored v1).
///
/// # C: O(parent VMAs) | O(1) for CLONE_VM
#[cfg(target_arch = "x86_64")]
pub fn kernel_sys_clone3(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let cl_args = args.a0;
    let size    = args.a1 as usize;
    if size < 64 || size > 256 { return -(Errno::Einval.as_i32() as i64); }
    if cl_args == 0 || cl_args >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if cl_args.checked_add(size as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: cl_args range validated < USER_VA_END; CPL=0 reads
    // through caller's AS; struct fields are u64-aligned per ABI.
    unsafe {
        let p = cl_args as *const u64;
        let flags        = core::ptr::read_volatile(p.add(0));
        let _pidfd       = core::ptr::read_volatile(p.add(1));
        let child_tid    = core::ptr::read_volatile(p.add(2));
        let parent_tid   = core::ptr::read_volatile(p.add(3));
        let exit_signal  = core::ptr::read_volatile(p.add(4));
        let stack        = core::ptr::read_volatile(p.add(5));
        let stack_size   = core::ptr::read_volatile(p.add(6));
        let tls          = core::ptr::read_volatile(p.add(7));
        // Stacks grow down on x86_64: child sees its initial RSP
        // at `stack + stack_size`. clone(2) takes the top directly;
        // clone3(2) takes (base, size).
        let user_sp = stack.saturating_add(stack_size);
        let merged_flags = flags | (exit_signal & 0xff);
        // Direct call into the dispatch helper — same path as
        // clone/fork/vfork.
        crate::syscall_glue::kernel_sys_clone_dispatch_pub(
            args, merged_flags, user_sp, parent_tid, child_tid, tls,
        )
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn kernel_sys_clone3(_args: &SyscallArgs) -> i64 {
    -(syscall::errno::Errno::Enosys.as_i32() as i64)
}

/// `sys_mprotect(addr, len, prot)` — slot 10. v1: accept and
/// no-op. Real per-page PTE prot bits + W^X enforcement rides
/// the VMA permission rewrite per docs/11§6.
/// # C: O(1)
pub fn kernel_sys_mprotect(args: &SyscallArgs) -> i64 {
    use vmm::VmaProt;
    use hal::UserVirtAddr;
    use syscall::errno::Errno;
    let addr = args.a0;
    let len  = args.a1 as usize;
    let prot = args.a2 as u32;
    let cur = match crate::sched::current() { Some(c) => c, None => return 0 };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return 0 };
    let mut vp = VmaProt::empty();
    if (prot & 0x1) != 0 { vp |= VmaProt::READ;  }
    if (prot & 0x2) != 0 { vp |= VmaProt::WRITE; }
    if (prot & 0x4) != 0 { vp |= VmaProt::EXEC;  }
    let ua = match UserVirtAddr::new(addr) {
        Some(u) => u, None => return -(Errno::Einval.as_i32() as i64),
    };
    match mm.mprotect(ua, len, vp) {
        Ok(()) => 0,
        Err(_) => -(Errno::Einval.as_i32() as i64),
    }
}

/// `sys_madvise(addr, len, advice)` — slot 28.
///
/// MADV_DONTNEED (4) zeroes the affected anonymous-VMA pages by
/// unmapping them from the AS — next access faults a fresh zero
/// page. Other advice values are accepted as hints (no state change).
///
/// MADV_DONTNEED on file-backed VMAs returns 0 silently — Linux
/// treats this as drop-clean-pages, which our v1 doesn't yet have a
/// page cache to flush; behaviorally indistinguishable from no-op.
/// # C: O(len/4096)
pub fn kernel_sys_madvise(args: &SyscallArgs) -> i64 {
    use hal::UserVirtAddr;
    use syscall::errno::Errno;
    const MADV_DONTNEED: u64 = 4;
    let addr   = args.a0;
    let len    = args.a1 as usize;
    let advice = args.a2;
    if advice != MADV_DONTNEED { return 0; }
    if addr == 0 || (addr & 0xFFF) != 0 { return -(Errno::Einval.as_i32() as i64); }
    if len == 0 { return 0; }
    let cur = match crate::sched::current() { Some(c) => c, None => return 0 };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return 0 };
    let ua = match UserVirtAddr::new(addr) {
        Some(u) => u, None => return -(Errno::Einval.as_i32() as i64),
    };
    // munmap then re-add an anonymous VMA covering the same region.
    // Next page-fault on the region zero-fills via the existing
    // demand-fault handler. Cleaner than walking PTEs by hand and
    // matches Linux's "drop pages, refault zero" semantic.
    let _ = mm.munmap(ua, len);
    use vmm::{VmaProt, VmaFlags, VmaBacking};
    let _ = mm.mmap(
        Some(ua), len,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::ANONYMOUS | VmaFlags::PRIVATE,
        VmaBacking::Anonymous, /*fixed=*/ true,
    );
    0
}

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

/// `sys_sigaltstack(ss, oldss)` — slot 131. Records the
/// alternate signal stack on the current task. The stored
/// `ss_sp`/`ss_size`/`ss_flags` are honoured by `sig_dispatch`'s
/// stack-pick path when a sigaction has SA_ONSTACK set.
///
/// `ss == 0`: just write the current values into `oldss` (if non-NULL).
/// `oldss == 0`: skip the write-back. Both can be NULL — Linux uses
/// that to query (no, that's getsigaltstack, but our shape stays
/// permissive).
/// # C: O(1)
pub fn kernel_sys_sigaltstack(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let ss    = args.a0;
    let oldss = args.a1;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Eperm.as_i32() as i64),
    };
    if oldss != 0 {
        if oldss >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        let sp    = cur.sigaltstack_sp.load(Ordering::Acquire);
        let size  = cur.sigaltstack_size.load(Ordering::Acquire);
        let flags = cur.sigaltstack_flags.load(Ordering::Acquire);
        // SAFETY: oldss validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile(oldss        as *mut u64, sp);
            core::ptr::write_volatile((oldss + 8)  as *mut i32, flags as i32);
            core::ptr::write_volatile((oldss + 16) as *mut u64, size);
        }
    }
    if ss != 0 {
        if ss >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: ss validated < USER_VA_END; CPL=0 reads through caller's AS.
        let sp:    u64 = unsafe { core::ptr::read_volatile(ss as *const u64) };
        let flags: i32 = unsafe { core::ptr::read_volatile((ss + 8) as *const i32) };
        let size:  u64 = unsafe { core::ptr::read_volatile((ss + 16) as *const u64) };
        cur.sigaltstack_sp.store(sp, Ordering::Release);
        cur.sigaltstack_size.store(size, Ordering::Release);
        cur.sigaltstack_flags.store(flags as u32, Ordering::Release);
    }
    0
}

/// `sys_nanosleep(req, rem)` — slot 35. yield-loop on monotonic clock.
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
/// restartable-sequences ABI for fast cancellation + per-CPU
/// counter visibility. v1 returns 0 (registered) but doesn't
/// implement the cs-abort or migration-clear protocol since
/// we're single-CPU UP — the user-visible rseq.cpu_id == 0 is
/// stable across the process lifetime, which is exactly what
/// glibc's fast getpid path expects. Real per-CPU rseq rides
/// SMP enablement.
/// # C: O(1)
pub fn kernel_sys_rseq(_args: &SyscallArgs) -> i64 { 0 }

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

/// `sys_rt_sigsuspend(mask, sz)` — slot 130. Atomically replaces
/// sigmask with `mask`, parks the task (yield loop), and returns
/// -EINTR once any unmasked signal becomes pending. The original
/// sigmask is restored on return so the handler runs under the
/// caller's pre-suspend mask.
///
/// v1 implementation is a tick_yield loop — every other task gets
/// a chance to run, and signal-raising paths (kill, ^C, etc.) bump
/// our `sigpending` which the loop notices on the next iteration.
/// A real waitqueue + signal-arrival wakeup hook rides a follow-up.
/// # C: O(yields until signal)
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
    let new_mask = m & !(1u64 << 8) & !(1u64 << 18); // SIGKILL/SIGSTOP unmaskable
    let old_mask = cur.sigmask.swap(new_mask, Ordering::AcqRel);
    loop {
        let pending = cur.sigpending.load(Ordering::Acquire);
        if (pending & !cur.sigmask.load(Ordering::Acquire)) != 0 { break; }
        // Briefly enable IRQs so timer + signal-raising IPIs can
        // deliver. tick_yield gives every other task a slice. A
        // real signal-waitqueue wakeup primitive replaces this
        // when threading lands in PR-E.
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("sti; pause; cli", options(nomem, nostack, preserves_flags)); }
        // SAFETY: process ctx; runqueue installed.
        unsafe { crate::sched::tick_yield(); }
    }
    cur.sigmask.store(old_mask, Ordering::Release);
    -(Errno::Eintr.as_i32() as i64)
}

/// `sys_rt_sigtimedwait(set, info, timeout, sz)` — slot 128.
/// Block until any signal in `set` becomes pending, then take
/// it (clear from `sigpending`) and return the signal number.
/// On timeout returns -EAGAIN. `info` (siginfo_t writeback) is
/// zero-filled for v1 since signal-raising paths don't yet
/// preserve siginfo.
/// # C: O(yields until signal or timeout)
pub fn kernel_sys_rt_sigtimedwait(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use hal::TimerOps;
    use syscall::errno::Errno;
    let set     = args.a0;
    let info    = args.a1;
    let timeout = args.a2;
    let sz      = args.a3;
    if sz != 8 { return -(Errno::Einval.as_i32() as i64); }
    if set == 0 || set >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: set validated < USER_VA_END; CPL=0 reads via active CR3.
    let wanted = unsafe { core::ptr::read_volatile(set as *const u64) };
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Eintr.as_i32() as i64),
    };
    let deadline = if timeout != 0 && timeout < hal::USER_VA_END {
        // SAFETY: timeout validated; struct timespec at +0 is tv_sec, +8 is tv_nsec.
        let secs = unsafe { core::ptr::read_volatile(timeout as *const i64) };
        let nsec = unsafe { core::ptr::read_volatile((timeout + 8) as *const i64) };
        if secs < 0 || nsec < 0 || nsec >= 1_000_000_000 {
            return -(Errno::Einval.as_i32() as i64);
        }
        let total = (secs as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64);
        #[cfg(target_arch = "x86_64")]
        let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
        #[cfg(target_arch = "aarch64")]
        let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        Some(now.saturating_add(total))
    } else { None };
    loop {
        let pending = cur.sigpending.load(Ordering::Acquire);
        let arrived = pending & wanted;
        if arrived != 0 {
            let sig = arrived.trailing_zeros() + 1;
            // Atomically clear that bit from sigpending.
            cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
            // v1 siginfo_t writeback: zero-fill. Real siginfo
            // (si_code, si_pid, si_uid, si_status) lands when
            // signal-raising paths preserve it.
            if info != 0 && info < hal::USER_VA_END {
                unsafe {
                    for i in 0..128usize {
                        core::ptr::write_volatile((info + i as u64) as *mut u8, 0);
                    }
                    core::ptr::write_volatile(info as *mut i32, sig as i32); // si_signo
                }
            }
            return sig as i64;
        }
        if let Some(dl) = deadline {
            #[cfg(target_arch = "x86_64")]
            let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
            #[cfg(target_arch = "aarch64")]
            let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
            if now >= dl { return -(Errno::Eagain.as_i32() as i64); }
        }
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("sti; pause; cli", options(nomem, nostack, preserves_flags)); }
        unsafe { crate::sched::tick_yield(); }
    }
}

/// `sys_rt_sigqueueinfo(pid, sig, info)` — slot 129. v1 ignores
/// the siginfo extras and routes through `kernel_sys_kill`. Real
/// siginfo_t propagation rides a follow-up alongside per-signal
/// queueing.
/// # C: O(N_tasks)
pub fn kernel_sys_rt_sigqueueinfo(args: &SyscallArgs) -> i64 {
    let kill_args = SyscallArgs {
        a0: args.a0, a1: args.a1, a2: 0, a3: 0, a4: 0, a5: 0,
    };
    kernel_sys_kill(&kill_args)
}

/// `sys_rt_tgsigqueueinfo(tgid, tid, sig, info)` — slot 297.
/// v1 ignores tgid + siginfo, routes the signal to `tid` via
/// `kernel_sys_tgkill`.
/// # C: O(1)
pub fn kernel_sys_rt_tgsigqueueinfo(args: &SyscallArgs) -> i64 {
    let tgkill_args = SyscallArgs {
        a0: args.a0, a1: args.a1, a2: args.a2, a3: 0, a4: 0, a5: 0,
    };
    kernel_sys_tgkill(&tgkill_args)
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

/// `sys_getrusage(who, usage)` — slot 98. ru_utime reports
/// `monotonic_ns - spawn_ns` for the calling task; ru_stime + the
/// 14 trailing counters all zero.
/// # C: O(1)
pub fn kernel_sys_getrusage(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use hal::TimerOps;
    use syscall::errno::Errno;
    let _who = args.a0;
    let buf = args.a1;
    if buf == 0 || buf >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let now = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::X86TimerOps::monotonic_ns().0 }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    };
    let elapsed = now.saturating_sub(cur.spawn_ns.load(Ordering::Acquire));
    let (sec, usec) = sched::clock::ns_to_timeval(elapsed);
    // SAFETY: validated 144-byte user buf < USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile( buf       as *mut u64, sec);
        core::ptr::write_volatile((buf + 8)  as *mut u64, usec);
        for off in (16..144u64).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
    }
    0
}

/// `sys_times(tms)` — slot 100. tms_utime reports
/// `(monotonic_ns - spawn_ns)` in CLK_TCK (100 Hz) ticks; the rest
/// of the struct stays zero. Return value: monotonic ticks total.
/// # C: O(1)
pub fn kernel_sys_times(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use hal::TimerOps;
    let buf = args.a0;
    let now = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::X86TimerOps::monotonic_ns().0 }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    };
    let elapsed = match crate::sched::current() {
        Some(c) => now.saturating_sub(c.spawn_ns.load(Ordering::Acquire)),
        None    => 0,
    };
    let utime_ticks = sched::clock::ns_to_clk_tck(elapsed);
    if buf != 0 && buf < hal::USER_VA_END {
        // SAFETY: validated 32-byte user buf below USER_VA_END; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile( buf       as *mut u64, utime_ticks);
            core::ptr::write_volatile((buf + 8)  as *mut u64, 0); // stime
            core::ptr::write_volatile((buf + 16) as *mut u64, 0); // cutime
            core::ptr::write_volatile((buf + 24) as *mut u64, 0); // cstime
        }
    }
    sched::clock::ns_to_clk_tck(now) as i64
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
///
/// Implementation: shrink-in-place is a partial munmap. Grow-in-place
/// tries to extend the old VMA's end; if the next address is mapped
/// it falls back to mmap-new-region + munmap-old (MREMAP_MAYMOVE).
/// MREMAP_FIXED + new_addr requires the caller-supplied destination
/// be cleared first (Linux semantic).
///
/// MREMAP_MAYMOVE = 1; MREMAP_FIXED = 2; MREMAP_DONTUNMAP = 4 (unsup).
/// # C: O(K + log N) per VMA-tree op
pub fn kernel_sys_mremap(args: &SyscallArgs) -> i64 {
    use hal::UserVirtAddr;
    use syscall::errno::Errno;
    use vmm::{VmaProt, VmaFlags, VmaBacking};
    const MREMAP_MAYMOVE: u64 = 1;
    const MREMAP_FIXED:   u64 = 2;
    let old      = args.a0;
    let old_size = args.a1 as usize;
    let new_size = args.a2 as usize;
    let flags    = args.a3;
    let new_addr = args.a4;
    if old == 0 || (old & 0xFFF) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    if new_size == 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return -(Errno::Einval.as_i32() as i64) };
    let old_ua = match UserVirtAddr::new(old) {
        Some(u) => u, None => return -(Errno::Einval.as_i32() as i64),
    };

    // Shrink: drop the tail.
    if new_size < old_size {
        let drop_va = old + new_size as u64;
        if let Some(da) = UserVirtAddr::new(drop_va) {
            let _ = mm.munmap(da, old_size - new_size);
        }
        return old as i64;
    }
    // Same size: no-op.
    if new_size == old_size && (flags & MREMAP_FIXED) == 0 {
        return old as i64;
    }

    // Grow path. v1 always copies via mmap+munmap when MAYMOVE allowed
    // (in-place grow needs VMA-tree extension which would require
    // tree.extend_end semantics not yet exposed). MREMAP_FIXED forces
    // the caller-supplied address; otherwise pick a hole.
    if (flags & MREMAP_MAYMOVE) == 0 && (flags & MREMAP_FIXED) == 0 {
        return -(Errno::Enomem.as_i32() as i64);
    }
    let hint = if (flags & MREMAP_FIXED) != 0 {
        match UserVirtAddr::new(new_addr) {
            Some(u) => Some(u), None => return -(Errno::Einval.as_i32() as i64),
        }
    } else { None };

    let new_va = match mm.mmap(
        hint, new_size,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::ANONYMOUS | VmaFlags::PRIVATE,
        VmaBacking::Anonymous,
        (flags & MREMAP_FIXED) != 0,
    ) {
        Ok(v)  => v,
        Err(_) => return -(Errno::Enomem.as_i32() as i64),
    };

    // Best-effort byte copy from old to new. Both regions are user
    // mappings under the caller's AS so plain volatile reads/writes
    // suffice. Page-fault during copy aborts (caller gets the
    // partially-populated new region; matches Linux's "best-effort"
    // for the rare error case).
    let copy_len = core::cmp::min(old_size, new_size);
    let dst = new_va.as_u64();
    // SAFETY: both regions live in the caller's AS, validated by
    // mmap/lookup; CPL=0 reads/writes through caller's PT.
    unsafe {
        for i in 0..copy_len {
            let v = core::ptr::read_volatile((old + i as u64) as *const u8);
            core::ptr::write_volatile((dst + i as u64) as *mut u8, v);
        }
    }

    // Unmap the old region.
    let _ = mm.munmap(old_ua, old_size);

    new_va.as_u64() as i64
}

/// `sys_msync(addr, len, flags)` — slot 26. # C: O(1)
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
pub fn kernel_sys_umask(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let new_mask = (args.a0 as u32) & 0o777;
    let cur = match crate::sched::current() { Some(c) => c, None => return 0o022 };
    cur.umask.swap(new_mask, Ordering::AcqRel) as i64
}

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

const CLONE_NEWNS:    u64 = 0x00020000;
const CLONE_NEWCGROUP:u64 = 0x02000000;
const CLONE_NEWUTS:   u64 = 0x04000000;
const CLONE_NEWIPC:   u64 = 0x08000000;
const CLONE_NEWUSER:  u64 = 0x10000000;
const CLONE_NEWPID:   u64 = 0x20000000;
const CLONE_NEWNET:   u64 = 0x40000000;

#[inline]
fn ns_bit_for_clone(clone_flag: u64) -> Option<u32> {
    Some(match clone_flag {
        CLONE_NEWNS      => 0,
        CLONE_NEWUTS     => 1,
        CLONE_NEWIPC     => 2,
        CLONE_NEWUSER    => 3,
        CLONE_NEWPID     => 4,
        CLONE_NEWNET     => 5,
        CLONE_NEWCGROUP  => 6,
        _ => return None,
    })
}

/// `sys_unshare(flags)` — slot 272. Per Linux: detach the calling
/// task from the named namespaces, taking up its own slot. v1 honors
/// CLONE_NEWUTS by snapshotting the current global hostname into a
/// per-task UTS slot (subsequent sethostname/uname see only the
/// per-task copy). Other CLONE_NEW* bits are admitted (membership
/// bit set) but per-NS isolation isn't enforced — that requires
/// per-NS state for mount/ipc/pid/user/net/cgroup which are their
/// own subsystem rewrites tracked under the v2 phase 21 follow-ups.
///
/// Linux also lets unshare() drop CLONE_FILES / CLONE_FS / CLONE_VM /
/// CLONE_SIGHAND. v1 fork already disjoints these by default; we
/// accept the bits silently.
/// # C: O(1)
pub fn kernel_sys_unshare(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let flags = args.a0;
    let cur = match crate::sched::current() { Some(c) => c, None => return 0 };
    let mut bits: u64 = 0;
    for clone_flag in [
        CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER,
        CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWCGROUP,
    ] {
        if (flags & clone_flag) != 0 {
            if let Some(b) = ns_bit_for_clone(clone_flag) {
                bits |= 1u64 << b;
            }
        }
    }
    if bits == 0 { return 0; }
    cur.ns_membership.fetch_or(bits, Ordering::Release);
    if (bits & (1u64 << 1)) != 0 {
        // CLONE_NEWUTS: snapshot the global hostname into the per-task slot.
        let snap_bytes = crate::hostname::snapshot();
        let snap = alloc::string::String::from_utf8(snap_bytes).unwrap_or_default();
        // SAFETY: per-task slot single-mutator per `13§5`; running task
        // on this CPU is the sole writer.
        unsafe { *cur.uts_hostname.get() = snap; }
    }
    0
}

/// `sys_setns(fd, nstype)` — slot 308. Linux requires `fd` to refer
/// to a `/proc/<pid>/ns/<type>` file; v1 doesn't yet expose those.
/// We honor the syscall as a clear-the-membership-bit op so callers
/// can re-attach to the init namespace. The fd argument is currently
/// ignored.
/// # C: O(1)
pub fn kernel_sys_setns(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let _fd  = args.a0;
    let nstype = args.a1;
    let cur = match crate::sched::current() { Some(c) => c, None => return 0 };
    let mut clear: u64 = 0;
    for clone_flag in [
        CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER,
        CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWCGROUP,
    ] {
        if (nstype & clone_flag) != 0 {
            if let Some(b) = ns_bit_for_clone(clone_flag) {
                clear |= 1u64 << b;
            }
        }
    }
    if clear == 0 { return 0; }
    cur.ns_membership.fetch_and(!clear, Ordering::Release);
    if (clear & (1u64 << 1)) != 0 {
        // SAFETY: per-task slot single-mutator per `13§5`.
        unsafe { (*cur.uts_hostname.get()).clear(); }
    }
    0
}

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

/// `sys_tgkill(tgid, tid, sig)` — slot 234. Validates that the
/// target tid actually belongs to the named tgid before delivering
/// (prevents POSIX-thread races where the target thread exited and
/// the tid was reused for an unrelated process).
/// # C: O(N_tasks) lookup
pub fn kernel_sys_tgkill(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let tgid = args.a0 as i32;
    let tid  = args.a1 as i32;
    let sig  = args.a2 as i32;
    if tgid <= 0 || tid <= 0 { return -(Errno::Esrch.as_i32() as i64); }
    if !(0..=64).contains(&sig) { return -(Errno::Einval.as_i32() as i64); }
    match crate::sched::registry::lookup(tid as u32) {
        Some(t) => {
            if t.tgid.load(Ordering::Acquire) != tgid as u32 {
                return -(Errno::Esrch.as_i32() as i64);
            }
            if sig != 0 {
                t.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
                if sig == 18 { crate::sched::registry::wake_if_stopped(&t); }
            }
            0
        }
        None => -(Errno::Esrch.as_i32() as i64),
    }
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

/// `sys_getpriority(which, who)` — slot 140. v1 honours
/// PRIO_PROCESS (which=0): returns 20 - nice for matching tid
/// (Linux convention; positive == lower priority).
/// # C: O(N_tasks)
pub fn kernel_sys_getpriority(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    const PRIO_PROCESS: u64 = 0;
    let which = args.a0;
    let who   = args.a1 as u32;
    if which != PRIO_PROCESS { return 20; } // PRIO_PGRP/USER → return default 0 nice
    let task = if who == 0 {
        crate::sched::current().and_then(|c| crate::sched::registry::lookup(c.tid))
    } else {
        crate::sched::registry::lookup(who)
    };
    match task {
        Some(t) => 20 - t.nice.load(Ordering::Acquire) as i64,
        None    => -(syscall::errno::Errno::Esrch.as_i32() as i64),
    }
}

/// `sys_setpriority(which, who, prio)` — slot 141. PRIO_PROCESS only;
/// clamps to `[-20, 19]` per `sched::rlimit::clamp_nice`.
/// # C: O(N_tasks)
pub fn kernel_sys_setpriority(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    const PRIO_PROCESS: u64 = 0;
    let which = args.a0;
    let who   = args.a1 as u32;
    let prio  = args.a2 as i32;
    if which != PRIO_PROCESS { return 0; }
    let task = if who == 0 {
        crate::sched::current().and_then(|c| crate::sched::registry::lookup(c.tid))
    } else {
        crate::sched::registry::lookup(who)
    };
    match task {
        Some(t) => {
            t.nice.store(sched::rlimit::clamp_nice(prio), Ordering::Release);
            0
        }
        None => -(syscall::errno::Errno::Esrch.as_i32() as i64),
    }
}

/// `sys_alarm(seconds)` — slot 37. Sets a per-task SIGALRM
/// deadline at monotonic_ns + seconds*1e9. Returns the seconds
/// remaining on the previous alarm, or 0 if none.
/// # C: O(1)
pub fn kernel_sys_alarm(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use hal::TimerOps;
    let secs = args.a0;
    let now = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::X86TimerOps::monotonic_ns().0 }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    };
    let cur = match crate::sched::current() { Some(c) => c, None => return 0 };
    let prev = cur.alarm_ns.load(Ordering::Acquire);
    let prev_remaining = if prev > now { (prev - now) / 1_000_000_000 } else { 0 };
    let new = if secs == 0 { 0 } else { now.saturating_add(secs.saturating_mul(1_000_000_000)) };
    cur.alarm_ns.store(new, Ordering::Release);
    prev_remaining as i64
}

/// `sys_pause()` — slot 34. Yield-loops until the calling task has
/// a non-masked signal pending, then returns -EINTR.
/// # C: O(yields)
pub fn kernel_sys_pause(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Eintr.as_i32() as i64),
    };
    loop {
        let pending = cur.sigpending.load(Ordering::Acquire);
        let masked  = cur.sigmask.load(Ordering::Acquire);
        if (pending & !masked) != 0 { return -(Errno::Eintr.as_i32() as i64); }
        // SAFETY: process ctx; runqueue installed.
        unsafe { crate::sched::tick_yield(); }
    }
}

/// `sys_setitimer(which, new, old)` — slot 38. ITIMER_REAL only.
/// new = `struct itimerval { it_interval: timeval, it_value: timeval }`.
/// # C: O(1)
pub fn kernel_sys_setitimer(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use hal::TimerOps;
    const ITIMER_REAL: u64 = 0;
    let which = args.a0;
    let new = args.a1;
    let old = args.a2;
    if which != ITIMER_REAL { return 0; } // VIRTUAL/PROF accept-and-ignore
    let cur = match crate::sched::current() { Some(c) => c, None => return 0 };
    let now = {
        #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
        #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    };
    if old != 0 && old < hal::USER_VA_END {
        // Render the previous interval + remaining time into user `old`.
        let prev_int = cur.alarm_interval_ns.load(Ordering::Acquire);
        let prev_dl  = cur.alarm_ns.load(Ordering::Acquire);
        let remain   = if prev_dl > now { prev_dl - now } else { 0 };
        let (i_s, i_us) = sched::clock::ns_to_timeval(prev_int);
        let (r_s, r_us) = sched::clock::ns_to_timeval(remain);
        // SAFETY: old validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile( old        as *mut u64, i_s);
            core::ptr::write_volatile((old +  8)  as *mut u64, i_us);
            core::ptr::write_volatile((old + 16)  as *mut u64, r_s);
            core::ptr::write_volatile((old + 24)  as *mut u64, r_us);
        }
    }
    if new != 0 && new < hal::USER_VA_END {
        // SAFETY: new validated; CPL=0 reads through caller's AS.
        let (i_s, i_us, v_s, v_us) = unsafe {
            let a = core::ptr::read_volatile( new        as *const u64);
            let b = core::ptr::read_volatile((new +  8)  as *const u64);
            let c = core::ptr::read_volatile((new + 16)  as *const u64);
            let d = core::ptr::read_volatile((new + 24)  as *const u64);
            (a, b, c, d)
        };
        let interval_ns = i_s.saturating_mul(1_000_000_000).saturating_add(i_us.saturating_mul(1000));
        let value_ns    = v_s.saturating_mul(1_000_000_000).saturating_add(v_us.saturating_mul(1000));
        cur.alarm_interval_ns.store(interval_ns, Ordering::Release);
        cur.alarm_ns.store(if value_ns == 0 { 0 } else { now.saturating_add(value_ns) }, Ordering::Release);
    }
    0
}

/// `sys_getitimer(which, curr)` — slot 36. Reports remaining +
/// interval for ITIMER_REAL.
/// # C: O(1)
pub fn kernel_sys_getitimer(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use hal::TimerOps;
    const ITIMER_REAL: u64 = 0;
    let which = args.a0;
    let curr = args.a1;
    if curr == 0 || curr >= hal::USER_VA_END { return 0; }
    let cur = match crate::sched::current() { Some(c) => c, None => return 0 };
    let now = {
        #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
        #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    };
    let (interval, remain) = if which == ITIMER_REAL {
        let i = cur.alarm_interval_ns.load(Ordering::Acquire);
        let dl = cur.alarm_ns.load(Ordering::Acquire);
        (i, if dl > now { dl - now } else { 0 })
    } else { (0, 0) };
    let (i_s, i_us) = sched::clock::ns_to_timeval(interval);
    let (r_s, r_us) = sched::clock::ns_to_timeval(remain);
    // SAFETY: curr validated < USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile( curr        as *mut u64, i_s);
        core::ptr::write_volatile((curr +  8)  as *mut u64, i_us);
        core::ptr::write_volatile((curr + 16)  as *mut u64, r_s);
        core::ptr::write_volatile((curr + 24)  as *mut u64, r_us);
    }
    0
}

