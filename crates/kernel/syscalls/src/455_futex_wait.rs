// 455 futex_wait — one syscall, one file (docs/53 §0).
//
// futex2 wait: park if *uaddr == val. Maps onto the shared futex queue (same
// FUTEX_WAIT path as the classic NR_FUTEX). 32-bit futexes only. The absolute
// timeout (a4/clockid) is not yet honored — the futex queue has no timed park
// for EITHER the classic or futex2 path; that is a shared follow-up, not a
// futex2-specific gap. Callers loop on a wake (glibc's low-level locks do).

use syscall::{errno::Errno, SyscallArgs};

const FUTEX2_SIZE_U32:  u32 = 0x02;
const FUTEX2_SIZE_MASK: u32 = 0x03;
const FUTEX2_PRIVATE:   u32 = 0x80;
const FUTEX_WAIT:       u32 = 0;

/// `sys_futex_wait(uaddr, val, mask, flags, timeout, clockid)` — slot 455.
/// # C: O(1) park
pub fn sys_futex_wait(args: &SyscallArgs) -> i64 {
    let uaddr = args.a0;
    let val   = args.a1 as u32;
    let flags = args.a3 as u32;
    if (flags & FUTEX2_SIZE_MASK) != FUTEX2_SIZE_U32
        || (flags & !(FUTEX2_SIZE_MASK | FUTEX2_PRIVATE)) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    ::ipc::live::futex::dispatch(uaddr, FUTEX_WAIT, val)
}
