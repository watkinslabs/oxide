// 454 futex_wake — one syscall, one file (docs/53 §0).
//
// futex2 wake: wake up to `nr` waiters on `uaddr`. Maps onto the shared futex
// queue (the same FUTEX_WAKE path as the classic NR_FUTEX). Only 32-bit
// futexes are supported (FUTEX2_SIZE_U32), matching the classic path.

use syscall::{errno::Errno, SyscallArgs};
use ipc::futex2_flags::{FUTEX2_PRIVATE, validate_futex2_flags, validate_futex2_input};

const FUTEX_WAKE: u32 = 1;

/// `sys_futex_wake(uaddr, mask, nr, flags)` — slot 454.
///
/// `mask` is an `unsigned long`, so a 64-bit caller can hand a value wider than
/// the 32-bit futex word; that is `EINVAL`, never a truncation (a truncated
/// mask of `0` would then trip the separate `mask == 0` rejection and report
/// the wrong reason, or worse, alias a real bitset).
/// # C: O(waiters)
pub fn sys_futex_wake(args: &SyscallArgs) -> i64 {
    let uaddr = args.a0;
    let mask  = args.a1;
    let nr    = args.a2 as u32;
    let flags = args.a3 as u32;
    let f = match validate_futex2_flags(flags) {
        Ok(f) => f, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    if !validate_futex2_input(f.size_bytes, mask) { return -(Errno::Einval.as_i32() as i64); }
    // `mask` is the futex2 wake bitset (identical to classic FUTEX_WAKE_BITSET's
    // val3) — only waiters whose registered bitset intersects `mask` wake.
    // `dispatch_timed` rejects `mask == 0` with -EINVAL (Linux `futex_wake`).
    ::ipc::live::futex::dispatch_timed(
        uaddr, FUTEX_WAKE | (flags & FUTEX2_PRIVATE), nr, mask as u32, 0)
}
