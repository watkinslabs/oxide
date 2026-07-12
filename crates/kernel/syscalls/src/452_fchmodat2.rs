// 452 fchmodat2 — one syscall, one file (docs/53 §0).
//
// fchmodat2(dirfd, path, mode, flags): the modern fchmodat whose `flags`
// (AT_SYMLINK_NOFOLLOW=0x100, AT_EMPTY_PATH=0x1000) are honored by the kernel
// rather than emulated in the libc wrapper. The old fchmodat slot passes flags
// 0; this slot validates and passes the real flags to the shared core.

use syscall::SyscallArgs;
use crate::perms_common::validate_chmod_chown_flags;

/// `sys_fchmodat2(dirfd, path, mode, flags)` — slot 452. Unlike the legacy
/// fchmodat (whose `flags` are emulated in libc), the kernel validates them
/// here: only AT_SYMLINK_NOFOLLOW (0x100) and AT_EMPTY_PATH (0x1000) are
/// accepted — any other bit → EINVAL (Linux do_fchmodat2) (D40).
/// # C: O(N_path)
pub fn sys_fchmodat2(args: &SyscallArgs) -> i64 {
    let flags = args.a3 as u32;
    if let Err(rv) = validate_chmod_chown_flags(flags) { return rv; }
    crate::s268_fchmodat::sys_fchmodat_flags(args, flags)
}
