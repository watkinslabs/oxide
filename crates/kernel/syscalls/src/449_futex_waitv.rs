// futex_waitv (slot 449) — multi-key wait split out of proc.rs to
// keep that file under the 1000-line cap. Delegates to
// `::ipc::live::futex::dispatch_waitv` which holds the wait group.

use ::syscall::SyscallArgs;
use ::syscall::errno::Errno;

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
    if host_abs <= now { return Err(-(Errno::Etimedout.as_i32() as i64)); }
    Ok(host_abs.saturating_sub(now)
        .saturating_add(crate::time_common::monotonic_ns()).max(1))
}

/// `sys_futex_waitv(waiters, nr_futexes, flags, timeout, clockid)`.
/// Reads N `struct futex_waitv { u64 val; u64 uaddr; u32 flags;
/// u32 _rsvd }` from a0, parks until ANY key is woken, returns
/// the index.
/// # C: O(N) pre-flight + O(N) park-enqueue
pub fn sys_futex_waitv(args: &SyscallArgs) -> i64 {
    const FUTEX_WAITV_MAX: u64 = 128;
    const ENTRY_BYTES: u64 = 24;
    let (ptr, n) = (args.a0, args.a1);
    if ptr == 0 || n == 0 || n > FUTEX_WAITV_MAX {
        return -(Errno::Einval.as_i32() as i64);
    }
    let deadline_ns = match absolute_deadline_ns(args.a3, args.a4) {
        Ok(dl) => dl,
        Err(e) => return e,
    };
    if let Err(rv) = crate::userbuf::validate_user_buf(ptr, n * ENTRY_BYTES, 1) { return rv; }
    let mut uaddrs: ::alloc::vec::Vec<u64> = ::alloc::vec::Vec::with_capacity(n as usize);
    let mut vals:   ::alloc::vec::Vec<u32> = ::alloc::vec::Vec::with_capacity(n as usize);
    let mut private = true; // FUTEX2_PRIVATE per-waiter; AND across the set.
    for i in 0..n {
        let base = ptr + i * ENTRY_BYTES;
        // SAFETY: the full wait-vector byte span was validated; scalar loads permit unaligned user storage.
        let val   = unsafe { core::ptr::read_unaligned(base as *const u64) };
        // SAFETY: uaddr lies within the validated wait-vector entry.
        let uaddr = unsafe { core::ptr::read_unaligned((base + 8) as *const u64) };
        // SAFETY: flags lies within the validated wait-vector entry.
        let flags = unsafe { core::ptr::read_unaligned((base + 16) as *const u32) };
        if (flags & ::ipc::live::futex::FUTEX_PRIVATE_FLAG) == 0 { private = false; }
        if val > u32::MAX as u64 { return -(Errno::Einval.as_i32() as i64); }
        uaddrs.push(uaddr);
        vals.push(val as u32);
    }
    ::ipc::live::futex::dispatch_waitv_timed(&uaddrs, &vals, private, deadline_ns)
}
