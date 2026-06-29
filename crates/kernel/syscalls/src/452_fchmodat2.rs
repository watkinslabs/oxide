// 452 fchmodat2 — one syscall, one file (docs/53 §0).
//
// fchmodat2(dirfd, path, mode, flags): the modern fchmodat whose `flags`
// (AT_SYMLINK_NOFOLLOW=0x100, AT_EMPTY_PATH=0x1000) are honored by the kernel
// rather than emulated in the libc wrapper. `perms::sys_fchmodat` already
// reads a4-style flags via resolve_at_target's nofollow bit, so the work is
// identical — this routes the new number to that handler.

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_fchmodat2(dirfd, path, mode, flags)` — slot 452. Unlike the legacy
/// fchmodat (whose `flags` are emulated in libc), the kernel validates them
/// here: only AT_SYMLINK_NOFOLLOW (0x100) and AT_EMPTY_PATH (0x1000) are
/// accepted — any other bit → EINVAL (Linux do_fchmodat2) (D40).
/// # C: O(N_path)
pub fn sys_fchmodat2(args: &SyscallArgs) -> i64 {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EMPTY_PATH:       u64 = 0x1000;
    if args.a3 & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    crate::s268_fchmodat::sys_fchmodat(args)
}
