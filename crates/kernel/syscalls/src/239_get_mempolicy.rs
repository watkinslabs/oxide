// 239 get_mempolicy — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::misc::misc_common::MPOL_DEFAULT;
use crate::userbuf::validate_user_buf_writable;

/// get_mempolicy(mode_out, nodemask_out, maxnode, addr, flags).
/// # C: O(1)
pub fn sys_get_mempolicy(args: &SyscallArgs) -> i64 {
    let mode_out = args.a0;
    if mode_out != 0 {
        if let Err(rv) = validate_user_buf_writable(mode_out, 4, 1) { return rv; }
        // SAFETY: mode_out validated writable for one i32 mode word.
        unsafe { core::ptr::write_unaligned(mode_out as *mut u32, MPOL_DEFAULT); }
    }
    0
}
