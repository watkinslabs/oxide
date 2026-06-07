// 331 pkey_free — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::{errno, PKEY_BITMAP};

/// # C: O(1)
pub fn sys_pkey_free(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let key = args.a0 as i32;
    if !(1..16).contains(&key) { return errno(Errno::Einval); }
    let mut cur = PKEY_BITMAP.load(Ordering::Acquire);
    loop {
        if cur & (1u16 << key) == 0 { return errno(Errno::Einval); }
        let next = cur & !(1u16 << key);
        match PKEY_BITMAP.compare_exchange(cur, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_)    => return 0,
            Err(now) => cur = now,
        }
    }
}
