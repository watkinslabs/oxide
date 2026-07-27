// 329 pkey_mprotect — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;
use crate::pkey::pkey_mprotect_allows;

/// `pkey_mprotect(addr, len, prot, pkey)` — slot 329.
///
/// Linux `do_mprotect_pkey`: `pkey != -1 && !mm_pkey_is_allocated(mm, pkey)`
/// -> EINVAL, checked before any VMA walk. Without `X86_FEATURE_OSPKE` the
/// only allocated key is the implicit default 0, so -1 ("keep current") and 0
/// are plain mprotect and every other key is EINVAL — the same answer Linux
/// gives on that CPU (see slot 330 for why this is not ENOSYS).
/// # C: O(1) + mprotect cost
pub fn sys_pkey_mprotect(args: &SyscallArgs) -> i64 {
    if pkey_mprotect_allows(args.a3 as i32) { crate::s010_mprotect::sys_mprotect(args) }
    else { errno(Errno::Einval) }
}
