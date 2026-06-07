// 201 time — one syscall, one file (docs/53 §0). Moved verbatim from time.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::time_common::{NS_PER_SEC, realtime_ns};

/// `sys_time(tloc)` — slot 201. Returns wall-clock seconds since
/// epoch (monotonic_ns + REALTIME_OFFSET_NS); writes *tloc.
/// # C: O(1)
pub fn kernel_time(args: &SyscallArgs) -> i64 {
    let sec = (realtime_ns() / NS_PER_SEC) as i64;
    let tloc = args.a0;
    if tloc != 0 && tloc < hal::USER_VA_END {
        // SAFETY: tloc validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe { core::ptr::write_volatile(tloc as *mut i64, sec); }
    }
    sec
}
