// 228 clock_gettime — one syscall, one file (docs/53 §0). Moved verbatim from time.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf_writable;
use crate::time_common::{NS_PER_SEC, clock_id_known, current_ns_for_clock};

/// `sys_clock_gettime(clk_id, tp)` — slot 228. Writes
/// `{tv_sec, tv_nsec}` for the given clock per `28§4`.
/// # C: O(1)
pub fn kernel_clock_gettime(args: &SyscallArgs) -> i64 {
    let clk_id = args.a0;
    let tp = args.a1;
    if !clock_id_known(clk_id) { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_user_buf_writable(tp, 16, 1) { return rv; }
    let ns = match current_ns_for_clock(clk_id) {
        Ok(ns) => ns,
        Err(_) => return -(Errno::Eio.as_i32() as i64),
    };
    let tv_sec  = ns / NS_PER_SEC;
    let tv_nsec = ns % NS_PER_SEC;
    // SAFETY: tp validated writable for one 16-byte timespec result.
    unsafe {
        core::ptr::write_unaligned(tp as *mut u64,         tv_sec);
        core::ptr::write_unaligned((tp + 8) as *mut u64,   tv_nsec);
    }
    0
}
