// access(2) shim — slot 21. Split out per `08§7` / `53§0`; work
// belongs in vfs per `53` (tracked sweep).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::fs_access_common::do_access;

/// `sys_access(path, mode)` — slot 21. Existence check (mode honoured by
/// the path-walk's perm gate). No dirfd → resolve against cwd.
/// # C: O(N_path)
pub fn sys_access(args: &SyscallArgs) -> i64 {
    do_access(-100, args.a0)
}
