// 455 futex_wait — one syscall, one file (docs/53 §0).
//
// futex2 wait: park if *uaddr == val. Maps onto the shared futex queue (same
// FUTEX_WAIT path as the classic NR_FUTEX). 32-bit futexes only.

use syscall::{errno::Errno, SyscallArgs};
use ipc::futex2_flags::{FUTEX2_PRIVATE, validate_futex2_flags, validate_futex2_input};

const FUTEX_WAIT: u32 = 0;

fn absolute_deadline_ns(timeout: u64, clockid: u64) -> Result<u64, i64> {
    if timeout == 0 { return Ok(0); }
    // Only these two clocks; checked BEFORE the timespec read so a bogus
    // clockid with an unreadable timespec is EINVAL, not EFAULT.
    if clockid != crate::time_common::CLOCK_REALTIME && clockid != crate::time_common::CLOCK_MONOTONIC {
        return Err(-(Errno::Einval.as_i32() as i64));
    }
    crate::userbuf::validate_user_buf(timeout, 16, 1)?;
    // SAFETY: timeout was validated as a readable 16-byte timespec; scalar loads permit unaligned user storage.
    let secs = unsafe { core::ptr::read_unaligned(timeout as *const i64) };
    // SAFETY: timeout+8 is inside the validated timespec and unaligned loads match user ABI copyin.
    let nsec = unsafe { core::ptr::read_unaligned((timeout + 8) as *const i64) };
    // `ktime_set`-clamped decode: a huge-but-valid tv_sec clamps to
    // KTIME_MAX_NS instead of an unbounded absolute deadline.
    let abs = ::syscall::time::timespec_to_ns(secs, nsec)
        .map_err(|_| -(Errno::Einval.as_i32() as i64))?;
    let host_abs = if clockid == crate::time_common::CLOCK_MONOTONIC {
        crate::time_common::current_sleep_target_to_host(clockid, true, abs)
            .map_err(|_| -(Errno::Eio.as_i32() as i64))?
    } else {
        abs
    };
    let now = crate::time_common::ns_for_clock(clockid);
    Ok(crate::time_common::monotonic_ns().saturating_add(host_abs.saturating_sub(now)).max(1))
}

/// `sys_futex_wait(uaddr, val, mask, flags, timeout, clockid)` — slot 455.
/// # C: O(1) park
pub fn sys_futex_wait(args: &SyscallArgs) -> i64 {
    let uaddr = args.a0;
    let val   = args.a1;
    let mask  = args.a2;
    let flags = args.a3 as u32;
    let f = match validate_futex2_flags(flags) {
        Ok(f) => f, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    // `val` and `mask` are `unsigned long`; a value wider than the 32-bit futex
    // word is EINVAL. Truncating instead (the previous shape) let a caller's
    // mismatched compare-value alias a real word value and park forever.
    if !validate_futex2_input(f.size_bytes, val) || !validate_futex2_input(f.size_bytes, mask) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let deadline_ns = match absolute_deadline_ns(args.a4, args.a5) {
        Ok(dl) => dl,
        Err(e) => return e,
    };
    // `mask` is the futex2 wait bitset (identical to classic FUTEX_WAIT_BITSET's
    // val3) — `dispatch_timed` rejects `mask == 0` with -EINVAL (Linux
    // `__futex_wait`) and only a FUTEX_WAKE_BITSET matching one of these bits
    // wakes this waiter.
    ::ipc::live::futex::dispatch_timed(
        uaddr, FUTEX_WAIT | (flags & FUTEX2_PRIVATE), val as u32, mask as u32, deadline_ns)
}
