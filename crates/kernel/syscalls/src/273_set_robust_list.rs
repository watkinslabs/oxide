// 273 set_robust_list — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_set_robust_list(head, len)` — slot 273. Stores per-thread
/// robust-mutex list pointer/len for `get_robust_list` readback and
/// (future) thread-exit walk to wake contending futexes. Validates
/// `head` ∈ user range; `head==0` clears.
/// # C: O(1)
pub fn sys_set_robust_list(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let head = args.a0;
    let len  = args.a1;
    if head != 0 && head >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    cur.robust_list_head.store(head, Ordering::Release);
    cur.robust_list_len.store(len, Ordering::Release);
    0
}
