// 329 pkey_mprotect — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::{errno, PKEY_BITMAP};

/// # C: O(1) + mprotect cost
pub fn sys_pkey_mprotect(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let key = args.a3 as i32;
    if key < 0 || key >= 16 { return errno(Errno::Einval); }
    if PKEY_BITMAP.load(Ordering::Acquire) & (1u16 << key) == 0 {
        return errno(Errno::Einval);
    }
    crate::s010_mprotect::sys_mprotect(args)
}
