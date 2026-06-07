// 440 process_madvise — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

/// process_madvise(pidfd, iov, iovcnt, advice, flags).
/// # C: O(N=iovcnt, capped 64)
pub fn sys_process_madvise(args: &SyscallArgs) -> i64 {
    let iov = args.a1;
    let cnt = args.a2 as usize;
    if cnt == 0 { return 0; }
    if iov == 0 || iov >= hal::USER_VA_END { return errno(Errno::Efault); }
    // Validate first iovec entry's pointer falls in user range; same
    // advise-only semantics as madvise once validated.
    for i in 0..cnt.min(64) {
        let p = iov + (i as u64) * 16;
        if p >= hal::USER_VA_END { return errno(Errno::Efault); }
        // SAFETY: validated p < USER_VA_END; 8-byte aligned read of iovec.iov_base from caller's AS.
        let base = unsafe { core::ptr::read_volatile(p as *const u64) };
        if base != 0 && base >= hal::USER_VA_END { return errno(Errno::Efault); }
    }
    0
}
