// 329 pkey_mprotect — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

/// `pkey_mprotect(addr, len, prot, pkey)` — slot 329. pkey -1 ("keep current")
/// and 0 (the default key) are plain mprotect. Any other key cannot exist —
/// pkey_alloc returns ENOSYS without PKU — so it is invalid.
/// # C: O(1) + mprotect cost
pub fn sys_pkey_mprotect(args: &SyscallArgs) -> i64 {
    let key = args.a3 as i32;
    if key <= 0 { crate::s010_mprotect::sys_mprotect(args) }
    else        { errno(Errno::Einval) }
}
