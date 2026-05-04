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
