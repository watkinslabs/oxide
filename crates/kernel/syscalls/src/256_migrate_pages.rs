// 256 migrate_pages — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

/// migrate_pages(pid, maxnode, old, new).
/// # C: O(1)
pub fn sys_migrate_pages(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as u32;
    if pid != 0 && sched::live::registry::lookup(pid).is_none() {
        return errno(Errno::Esrch);
    }
    0
}
