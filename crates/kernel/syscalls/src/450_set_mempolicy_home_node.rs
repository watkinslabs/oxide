// 450 set_mempolicy_home_node — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

/// set_mempolicy_home_node(start, len, home_node, flags).
/// # C: O(1)
pub fn sys_set_mempolicy_home_node(args: &SyscallArgs) -> i64 {
    let home = args.a2 as i32;
    if home != 0 && home != -1 { return errno(Errno::Einval); }
    0
}
