// 095 umask — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_umask(mask)` — slot 95. Swaps per-task `umask` and returns
/// the previous mask. New mask is clamped to 9 bits per POSIX.
/// # C: O(1)
pub fn sys_umask(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let new_mask = (args.a0 as u32) & 0o777;
    let cur = match sched::live::current() { Some(c) => c, None => return 0o022 };
    cur.umask.swap(new_mask, Ordering::AcqRel) as i64
}
