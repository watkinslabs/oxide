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

/// `sys_rt_sigprocmask(how, set, oldset, sz)` — slot 14. v1
/// stub: signal mask is implicit-block-all; returns 0.
/// # C: O(1)
pub fn kernel_sys_rt_sigprocmask(_args: &SyscallArgs) -> i64 { 0 }

/// `sys_sigaltstack(ss, oldss)` — slot 131. v1 stub: signal
/// frames don't exist yet; accept and ignore.
/// # C: O(1)
pub fn kernel_sys_sigaltstack(_args: &SyscallArgs) -> i64 { 0 }
