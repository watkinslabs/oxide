// 238 set_mempolicy — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::{errno, MPOL_LOCAL};

/// set_mempolicy(mode, nodemask, maxnode).
/// # C: O(1)
pub fn sys_set_mempolicy(args: &SyscallArgs) -> i64 {
    let mode = args.a0 as u32;
    if mode > MPOL_LOCAL { return errno(Errno::Einval); }
    0
}
