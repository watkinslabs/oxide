// 097 getrlimit — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::validate_user_buf_writable;

/// `sys_getrlimit(res, rlim)` — slot 97. Reads the per-task
/// rlimit slot for `res` and writes `(cur, max)` to user `rlim`.
/// # C: O(1)
pub fn sys_getrlimit(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let resource = args.a0 as usize;
    let rlim = args.a1;
    if resource >= sched::rlimit::rlim::COUNT {
        return -(Errno::Einval.as_i32() as i64);
    }
    if let Err(rv) = validate_user_buf_writable(rlim, 16, 1) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let (rcur, rmax) = cur.rlimit(resource);
    // SAFETY: rlim validated writable for the 16-byte rlimit result.
    unsafe {
        core::ptr::write_unaligned( rlim       as *mut u64, rcur);
        core::ptr::write_unaligned((rlim + 8)  as *mut u64, rmax);
    }
    0
}
