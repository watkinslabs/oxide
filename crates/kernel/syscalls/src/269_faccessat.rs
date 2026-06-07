// faccessat(2) / faccessat2(2) shim — slot 269 (+ 439). Split out
// per `08§7` / `53§0`; work belongs in vfs per `53` (tracked sweep).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::fs_access_common::do_access;

/// `sys_faccessat(dirfd, path, mode, flags)` — slot 269 (+ faccessat2 326).
/// Resolves `path` against `dirfd`.
/// # C: O(N_path)
pub fn sys_faccessat(args: &SyscallArgs) -> i64 {
    do_access(args.a0 as i32, args.a1)
}
