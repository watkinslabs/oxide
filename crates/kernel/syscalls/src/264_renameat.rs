// 264 renameat — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// # C: O(1)
pub fn sys_renameat(args: &SyscallArgs) -> i64 {
    // renameat(olddirfd, from, newdirfd, to): resolve each against its dirfd.
    crate::s082_rename::rename_impl(args.a0 as i32, args.a1, args.a2 as i32, args.a3)
}
