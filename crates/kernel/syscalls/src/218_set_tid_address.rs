// 218 set_tid_address — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_set_tid_address(tidptr)` — slot 218. Stores the user
/// pointer in `Task.clear_child_tid` per CLONE_CHILD_CLEARTID
/// semantics. v1 single-thread doesn't yet wake-on-exit; the
/// storage is for musl + glibc visibility.
/// # C: O(1)
pub fn sys_set_tid_address(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let cur = match sched::live::current() { Some(c) => c, None => return 1 };
    cur.clear_child_tid.store(args.a0, Ordering::Release);
    match cur.vtid.load(Ordering::Acquire) { 0 => cur.tid as i64, v => v as i64 }
}
