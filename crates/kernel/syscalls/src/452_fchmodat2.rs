// 452 fchmodat2 — one syscall, one file (docs/53 §0).
//
// fchmodat2(dirfd, path, mode, flags): the modern fchmodat whose `flags`
// (AT_SYMLINK_NOFOLLOW=0x100, AT_EMPTY_PATH=0x1000) are honored by the kernel
// rather than emulated in the libc wrapper. `perms::sys_fchmodat` already
// reads a4-style flags via resolve_at_target's nofollow bit, so the work is
// identical — this routes the new number to that handler.

use syscall::SyscallArgs;

/// `sys_fchmodat2(dirfd, path, mode, flags)` — slot 452.
/// # C: O(N_path)
pub fn sys_fchmodat2(args: &SyscallArgs) -> i64 {
    crate::perms::sys_fchmodat(args)
}
