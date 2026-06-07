// 316 renameat2 — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// # C: O(1)
pub fn sys_renameat2(args: &SyscallArgs) -> i64 {
    crate::s082_rename::rename_impl(args.a0 as i32, args.a1, args.a2 as i32, args.a3)
}
