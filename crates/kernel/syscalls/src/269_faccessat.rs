// faccessat(2) / faccessat2(2) shim — slot 269 (+ 439). Split out
// per `08§7` / `53§0`; work belongs in vfs per `53` (tracked sweep).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::fs_access_common::do_access;

/// `sys_faccessat(dirfd, path, mode)` — slot 269. The raw `faccessat(2)`
/// syscall takes NO flags (glibc emulates AT_EACCESS via faccessat2); a3 is
/// undefined here, so flags are forced to 0 (real-uid check).
/// # C: O(N_path)
pub fn sys_faccessat(args: &SyscallArgs) -> i64 {
    do_access(args.a0 as i32, args.a1, args.a2 as u32, 0)
}

/// `sys_faccessat2(dirfd, path, mode, flags)` — slot 439. Honors AT_EACCESS
/// (effective-id check) / AT_SYMLINK_NOFOLLOW; bad flags → EINVAL.
/// # C: O(N_path)
pub fn sys_faccessat2(args: &SyscallArgs) -> i64 {
    do_access(args.a0 as i32, args.a1, args.a2 as u32, args.a3 as u32)
}
