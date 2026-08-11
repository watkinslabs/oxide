// 201 time — one syscall, one file (docs/53 §0). Moved verbatim from time.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::userbuf::validate_user_buf_writable;
use crate::time_common::{NS_PER_SEC, realtime_ns};
use crate::user_mem as um;

/// `sys_time(tloc)` — slot 201. Returns wall-clock seconds since
/// epoch (monotonic_ns + REALTIME_OFFSET_NS); writes *tloc.
/// # C: O(1)
pub fn kernel_time(args: &SyscallArgs) -> i64 {
    let sec = (realtime_ns() / NS_PER_SEC) as i64;
    let tloc = args.a0;
    if tloc != 0 {
        if let Err(rv) = validate_user_buf_writable(tloc, 8, 1) { return rv; }
        // Linux `sys_time`: `put_user` failure reports EFAULT in place of the seconds value.
        if um::put_i64(tloc, sec).is_err() { return um::EFAULT; }
    }
    sec
}
