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
/// PID-NS-virtualized; tasks in init NS see real tid.
/// # C: O(1)
pub fn kernel_sys_gettid(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    crate::sched::current().map(|c| {
        let v = c.vtid.load(Ordering::Acquire);
        if v != 0 { v as i64 } else { c.tid as i64 }
    }).unwrap_or(1)
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
    match cur.vtid.load(Ordering::Acquire) { 0 => cur.tid as i64, v => v as i64 }
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
        crate::syscall_glue_clone::kernel_sys_clone_dispatch(
            args, merged_flags, user_sp, parent_tid, child_tid, tls,
        )
    }
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
        Ok(()) => {
            // SAFETY: caller is the running task; mm matches active AS; per-AS UP + preempt-off serialises with fault path; mprotect_pages walks PT + flushes TLB so hardware enforces the new permissions.
            unsafe { crate::user_as::mprotect_pages(mm.root_pa(), addr, len, vp); }
            0
        }
        Err(_) => -(Errno::Einval.as_i32() as i64),
    }
}

/// `sys_madvise(addr, len, advice)` — slot 28. DONTNEED/FREE/REMOVE
/// drop pages (refault as zero); hints (NORMAL/RANDOM/SEQUENTIAL/etc)
/// no-op; HWPOISON needs CAP_SYS_ADMIN → EPERM; unknown → EINVAL.
/// # C: O(len/4096)
pub fn kernel_sys_madvise(args: &SyscallArgs) -> i64 {
    use hal::UserVirtAddr;
    use syscall::errno::Errno;
    // Drop-pages set: DONTNEED=4, FREE=8, REMOVE=9 — all observably
    // "drop and refault as zero" in v1 (no swap, no shmem hole).
    // Pure hints: NORMAL/RANDOM/SEQUENTIAL/WILLNEED/HUGEPAGE/etc.
    // HWPOISON=100 needs CAP_SYS_ADMIN → EPERM. Unknown → EINVAL.
    let addr   = args.a0;
    let len    = args.a1 as usize;
    let advice = args.a2;
    if addr == 0 || (addr & 0xFFF) != 0 { return -(Errno::Einval.as_i32() as i64); }
    if len == 0 { return 0; }
    let cur = match crate::sched::current() { Some(c) => c, None => return 0 };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return 0 };
    let ua = match UserVirtAddr::new(addr) {
        Some(u) => u, None => return -(Errno::Einval.as_i32() as i64),
    };
    match advice {
        4 | 8 | 9 => {
            let _ = mm.munmap(ua, len);
            use vmm::{VmaProt, VmaFlags, VmaBacking};
            let _ = mm.mmap(
                Some(ua), len, VmaProt::READ | VmaProt::WRITE,
                VmaFlags::ANONYMOUS | VmaFlags::PRIVATE,
                VmaBacking::Anonymous, true);
            0
        }
        0..=3 | 10..=21 => 0,                          // hints
        100 => -(Errno::Eperm.as_i32() as i64),        // MADV_HWPOISON
        _   => -(Errno::Einval.as_i32() as i64),
    }
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

// rt_sigaction / rt_sigprocmask / sigaltstack / rt_sigpending /
// rt_sigsuspend / rt_sigtimedwait / rt_sigqueueinfo /
// rt_tgsigqueueinfo / take_lowest_pending / PendingSignal moved to
// syscall_glue_signal.rs (08§7 size cap).

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

// `sys_rseq` + rseq_writeback live in `syscall_glue_rseq.rs` (F86).
pub use crate::syscall_glue_rseq::{kernel_sys_rseq, rseq_writeback};

// `sys_chroot` real impl moved to `syscall_glue_chroot.rs` (F95).

/// `sys_vhangup` — slot 153. Linux: revoke access to the calling task's
/// controlling terminal by posting SIGHUP to every task in the same
/// session. Privileged (CAP_SYS_TTY_CONFIG / root).
/// # C: O(N_tasks)
pub fn kernel_sys_vhangup(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let cur = match crate::sched::current() { Some(c) => c, None => return 0 };
    if !cur.has_cap(sched::cap::SYS_TTY_CONFIG) { return -(Errno::Eperm.as_i32() as i64); }
    let sid = cur.sid.load(Ordering::Acquire);
    for tid in crate::sched::registry::live_tids() {
        if let Some(t) = crate::sched::registry::lookup(tid) {
            if t.sid.load(Ordering::Acquire) == sid {
                t.sigpending.fetch_or(1u64 /* SIGHUP bit 0 */, Ordering::Release);
            }
        }
    }
    0
}

// `sys_syslog` moved to `syscall_glue_dmesg.rs` (F67) to keep this
// file under the 1000-line cap.

/// `sys_set_robust_list(head, len)` — slot 273. Stores per-thread
/// robust-mutex list pointer/len for `get_robust_list` readback and
/// (future) thread-exit walk to wake contending futexes. Validates
/// `head` ∈ user range; `head==0` clears.
/// # C: O(1)
pub fn kernel_sys_set_robust_list(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let head = args.a0;
    let len  = args.a1;
    if head != 0 && head >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match crate::sched::current() { Some(c) => c, None => return 0 };
    cur.robust_list_head.store(head, Ordering::Release);
    cur.robust_list_len.store(len, Ordering::Release);
    0
}

/// `sys_get_robust_list(pid, head_out, len_out)` — slot 274. `pid==0`
/// means the calling thread; non-zero pids are looked up in the
/// scheduler registry. Writes the stored head+len through the two
/// user pointers.
/// # C: O(1) | O(N_tasks) when pid != 0 (registry walk)
pub fn kernel_sys_get_robust_list(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let pid      = args.a0 as u32;
    let head_out = args.a1;
    let len_out  = args.a2;
    if head_out == 0 || head_out >= hal::USER_VA_END
        || len_out == 0 || len_out >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let (head, len) = if pid == 0 {
        let cur = match crate::sched::current() {
            Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
        };
        (cur.robust_list_head.load(Ordering::Acquire),
         cur.robust_list_len.load(Ordering::Acquire))
    } else {
        let task = match crate::sched::registry::lookup(pid) {
            Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
        };
        (task.robust_list_head.load(Ordering::Acquire),
         task.robust_list_len.load(Ordering::Acquire))
    };
    // SAFETY: head_out/len_out validated < USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile(head_out as *mut u64, head);
        core::ptr::write_volatile(len_out  as *mut u64, len);
    }
    0
}

// `sys_getresuid` / `sys_getresgid` — moved to syscall_glue_cred (F64)
// with real ruid/euid/suid writeback from Task.creds.

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
    use hal::UserVirtAddr;
    use syscall::errno::Errno;
    let addr  = args.a0;
    let len   = args.a1;
    let vec   = args.a2;
    if addr == 0 || (addr & 0xFFF) != 0 { return -(Errno::Einval.as_i32() as i64); }
    let pages = (len + 0xfff) / 0x1000;
    if vec == 0 || vec.checked_add(pages).map_or(true, |e| e >= hal::USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match crate::sched::current() { Some(c) => c, None => return -(Errno::Einval.as_i32() as i64) };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return -(Errno::Einval.as_i32() as i64) };
    for i in 0..pages {
        let p = match addr.checked_add(i * 0x1000).and_then(UserVirtAddr::new) {
            Some(u) => u, None => return -(Errno::Enomem.as_i32() as i64),
        };
        if mm.find_vma(p).is_none() { return -(Errno::Enomem.as_i32() as i64); }
    }
    // SAFETY: validated user range below USER_VA_END; CPL=0 writes through caller's AS.
    unsafe { for i in 0..pages { core::ptr::write_volatile((vec + i) as *mut u8, 1); } }
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

// `sys_prctl` real impl moved to `syscall_glue_prctl.rs` (F72).

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

/// `sys_sethostname(name, len)` — slot 170. Updates the hostname
/// visible via uname.nodename. Per F97: when the task carries
/// CLONE_NEWUTS, writes go to the per-task `uts_hostname` slot
/// (private to the namespace); else they update the global.
/// Requires CAP_SYS_ADMIN.
/// # C: O(N)
pub fn kernel_sys_sethostname(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let ptr = args.a0;
    let len = args.a1 as usize;
    if len > crate::hostname::HOST_NAME_MAX { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = crate::syscall_glue::validate_user_buf(ptr, len as u64, 1) { return rv; }
    let cur = match crate::sched::current() { Some(c) => c, None => return 0 };
    if !cur.has_cap(sched::cap::SYS_ADMIN) { return -(Errno::Eperm.as_i32() as i64); }
    let mut buf = [0u8; crate::hostname::HOST_NAME_MAX];
    // SAFETY: ptr range validated < USER_VA_END; CPL=0 reads through caller's AS.
    unsafe {
        for i in 0..len { buf[i] = core::ptr::read_volatile((ptr + i as u64) as *const u8); }
    }
    if (cur.ns_membership.load(Ordering::Acquire) & (1u64 << 1)) != 0 {
        let s = match core::str::from_utf8(&buf[..len]) {
            Ok(s) => alloc::string::String::from(s),
            Err(_) => return -(Errno::Einval.as_i32() as i64),
        };
        // SAFETY: per-task uts_hostname slot single-mutator per `13§5`; running task on this CPU is the sole writer.
        unsafe { *cur.uts_hostname.get() = s; }
    } else {
        crate::hostname::set(&buf[..len]);
    }
    0
}

// `sys_setdomainname` lives in `hostname.rs` alongside the slot.

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
        core::ptr::write_volatile( curr       as *mut u64, i_s);
        core::ptr::write_volatile((curr +  8) as *mut u64, i_us);
        core::ptr::write_volatile((curr + 16) as *mut u64, r_s);
        core::ptr::write_volatile((curr + 24) as *mut u64, r_us);
    }
    0
}

