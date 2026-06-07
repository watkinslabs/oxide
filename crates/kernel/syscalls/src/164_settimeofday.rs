// 164 settimeofday — one syscall, one file (docs/53 §0). Moved verbatim from time.rs.
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;

use crate::time_common::{NS_PER_SEC, REALTIME_OFFSET_NS, monotonic_ns};

/// `sys_settimeofday(tv, tz)` — slot 164. Writes REALTIME_OFFSET_NS
/// from `tv` so subsequent gettimeofday/time return wall-clock.
/// # C: O(1)
pub fn kernel_settimeofday(args: &SyscallArgs) -> i64 {
    let tv = args.a0;
    if tv == 0 || tv >= hal::USER_VA_END { return 0; }
    // SAFETY: tv validated 16-byte range; CPL=0 reads through caller's AS.
    let (sec, usec) = unsafe {
        let s = core::ptr::read_volatile(tv as *const u64);
        let u = core::ptr::read_volatile((tv + 8) as *const u64);
        (s, u)
    };
    let target = sec.saturating_mul(NS_PER_SEC).saturating_add(usec.saturating_mul(1000));
    REALTIME_OFFSET_NS.store(sched::clock::settimeofday_offset(monotonic_ns(), target), Ordering::Release);
    0
}
