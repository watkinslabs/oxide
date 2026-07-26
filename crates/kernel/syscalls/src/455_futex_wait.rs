// 455 futex_wait — one syscall, one file (docs/53 §0).
//
// futex2 wait: park if *uaddr == val. Maps onto the shared futex queue (same
// FUTEX_WAIT path as the classic NR_FUTEX). 32-bit futexes only.

use syscall::{errno::Errno, SyscallArgs};

const FUTEX2_SIZE_U32:  u32 = 0x02;
const FUTEX2_SIZE_MASK: u32 = 0x03;
const FUTEX2_PRIVATE:   u32 = 0x80;
const FUTEX_WAIT:       u32 = 0;

fn absolute_deadline_ns(timeout: u64, clockid: u64) -> Result<u64, i64> {
    if timeout == 0 { return Ok(0); }
    crate::userbuf::validate_user_buf(timeout, 16, 1)?;
    if !crate::time_common::clock_id_known(clockid) {
        return Err(-(Errno::Einval.as_i32() as i64));
    }
    // SAFETY: timeout was validated as a readable 16-byte timespec; scalar loads permit unaligned user storage.
    let secs = unsafe { core::ptr::read_unaligned(timeout as *const i64) };
    // SAFETY: timeout+8 is inside the validated timespec and unaligned loads match user ABI copyin.
    let nsec = unsafe { core::ptr::read_unaligned((timeout + 8) as *const i64) };
    if secs < 0 || nsec < 0 || nsec >= 1_000_000_000 {
        return Err(-(Errno::Einval.as_i32() as i64));
    }
    let abs = (secs as u64)
        .saturating_mul(crate::time_common::NS_PER_SEC)
        .saturating_add(nsec as u64);
    let host_abs = if clockid == crate::time_common::CLOCK_MONOTONIC {
        crate::time_common::current_sleep_target_to_host(clockid, true, abs)
            .map_err(|_| -(Errno::Eio.as_i32() as i64))?
    } else {
        abs
    };
    let now = crate::time_common::ns_for_clock(clockid);
    if host_abs <= now { return Err(-(Errno::Etimedout.as_i32() as i64)); }
    Ok(host_abs.saturating_sub(now)
        .saturating_add(crate::time_common::monotonic_ns()).max(1))
}

/// `sys_futex_wait(uaddr, val, mask, flags, timeout, clockid)` — slot 455.
/// # C: O(1) park
pub fn sys_futex_wait(args: &SyscallArgs) -> i64 {
    let uaddr = args.a0;
    let val   = args.a1 as u32;
    let mask  = args.a2 as u32;
    let flags = args.a3 as u32;
    if (flags & FUTEX2_SIZE_MASK) != FUTEX2_SIZE_U32
        || (flags & !(FUTEX2_SIZE_MASK | FUTEX2_PRIVATE)) != 0 {
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
    ::ipc::live::futex::dispatch_timed(uaddr, FUTEX_WAIT | (flags & FUTEX2_PRIVATE), val, mask, deadline_ns)
}
