// 454 futex_wake — one syscall, one file (docs/53 §0).
//
// futex2 wake: wake up to `nr` waiters on `uaddr`. Maps onto the shared futex
// queue (the same FUTEX_WAKE path as the classic NR_FUTEX). Only 32-bit
// futexes are supported (FUTEX2_SIZE_U32), matching the classic path.

use syscall::{errno::Errno, SyscallArgs};

const FUTEX2_SIZE_U32:  u32 = 0x02; // flags bits[1:0] = size class
const FUTEX2_SIZE_MASK: u32 = 0x03;
const FUTEX2_PRIVATE:   u32 = 0x80;
const FUTEX_WAKE:       u32 = 1;

/// `sys_futex_wake(uaddr, mask, nr, flags)` — slot 454.
/// # C: O(waiters)
pub fn sys_futex_wake(args: &SyscallArgs) -> i64 {
    let uaddr = args.a0;
    let mask  = args.a1 as u32;
    let nr    = args.a2 as u32;
    let flags = args.a3 as u32;
    if (flags & FUTEX2_SIZE_MASK) != FUTEX2_SIZE_U32
        || (flags & !(FUTEX2_SIZE_MASK | FUTEX2_PRIVATE)) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    // `mask` is the futex2 wake bitset (identical to classic FUTEX_WAKE_BITSET's
    // val3) — only waiters whose registered bitset intersects `mask` wake.
    // `dispatch_timed` rejects `mask == 0` with -EINVAL (Linux `futex_wake`).
    ::ipc::live::futex::dispatch_timed(uaddr, FUTEX_WAKE | (flags & FUTEX2_PRIVATE), nr, mask, 0)
}
