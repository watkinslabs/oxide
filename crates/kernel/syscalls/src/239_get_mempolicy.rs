// 239 get_mempolicy — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::{errno, MPOL_DEFAULT};

/// get_mempolicy(mode_out, nodemask_out, maxnode, addr, flags).
/// # C: O(1)
pub fn sys_get_mempolicy(args: &SyscallArgs) -> i64 {
    let mode_out = args.a0;
    if mode_out != 0 {
        if mode_out >= hal::USER_VA_END { return errno(Errno::Efault); }
        // SAFETY: validated < USER_VA_END; aligned u32 store.
        unsafe { core::ptr::write_volatile(mode_out as *mut u32, MPOL_DEFAULT); }
    }
    0
}
