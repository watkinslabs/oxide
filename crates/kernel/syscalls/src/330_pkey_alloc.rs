// 330 pkey_alloc — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::{errno, PKEY_BITMAP};

/// # C: O(1)
pub fn sys_pkey_alloc(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let mut cur = PKEY_BITMAP.load(Ordering::Acquire);
    loop {
        let i = match (1..16).find(|i| cur & (1u16 << i) == 0) {
            Some(i) => i, None => return errno(Errno::Enospc),
        };
        let next = cur | (1u16 << i);
        match PKEY_BITMAP.compare_exchange(cur, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_)    => return i as i64,
            Err(now) => cur = now,
        }
    }
}
