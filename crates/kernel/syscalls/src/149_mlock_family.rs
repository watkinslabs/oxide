// 149 mlock_family — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
// Covers slots 149 (mlock) / 150 (munlock) / 151 (mlockall) / 152 (munlockall).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_mlock` / `sys_munlock` / `sys_mlockall` / `sys_munlockall`
/// — slots 149/150/151/152. v1 has no swap; every page is
/// effectively locked. Accept and return 0.
/// # C: O(1)
pub fn sys_mlock_family(_args: &SyscallArgs) -> i64 { 0 }
