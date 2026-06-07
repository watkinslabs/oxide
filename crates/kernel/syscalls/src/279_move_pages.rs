// 279 move_pages — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

/// move_pages(pid, count, pages, nodes, status, flags).
/// # C: O(N=count, capped 4096)
pub fn sys_move_pages(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as u32;
    if pid != 0 && sched::live::registry::lookup(pid).is_none() {
        return errno(Errno::Esrch);
    }
    let count = args.a1 as usize;
    let status = args.a4;
    if status != 0 && count > 0 {
        if status >= hal::USER_VA_END { return errno(Errno::Efault); }
        // Each page is "on node 0" in our single-node world.
        for i in 0..count.min(4096) {
            // SAFETY: status validated < USER_VA_END; bounded count loop; aligned i32 store into caller's AS.
            unsafe {
                core::ptr::write_volatile((status + (i*4) as u64) as *mut i32, 0);
            }
        }
    }
    0
}
