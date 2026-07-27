// 218 set_tid_address — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_set_tid_address(tidptr)` — slot 218. Linux `kernel/fork.c`:
///     current->clear_child_tid = tidptr;
///     return task_pid_vnr(current);
///
/// Unconditional store (a NULL `tidptr` disarms), no user-pointer validation —
/// Linux validates nothing here because the exit-time write is a best-effort
/// `put_user` whose fault is swallowed. `060_exit.rs` performs that write and
/// the CLONE_CHILD_CLEARTID `FUTEX_WAKE|PRIVATE` that pthread_join blocks on,
/// so a stored address is genuinely used.
///
/// Returns the caller's tid in ITS pid namespace (`task_pid_vnr`), not a
/// global id — the same value `gettid(2)` reports.
/// # C: O(1)
pub fn sys_set_tid_address(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let cur = match sched::live::current() { Some(c) => c, None => return 1 };
    cur.clear_child_tid.store(args.a0, Ordering::Release);
    match cur.vtid.load(Ordering::Acquire) { 0 => cur.tid as i64, v => v as i64 }
}
