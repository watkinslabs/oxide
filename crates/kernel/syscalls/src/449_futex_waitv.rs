// 449 futex_waitv — one syscall, one file (docs/53 §0). Multi-key wait;
// delegates to `::ipc::live::futex::dispatch_waitv_timed`, which owns the
// wait group.

use ::syscall::SyscallArgs;
use ::syscall::errno::Errno;
use ::ipc::futex2_flags::{validate_futex2_flags, validate_futex2_input};
use ::ipc::live::futex::WaitvEntry;

/// `struct futex_waitv { __u64 val; __u64 uaddr; __u32 flags; __u32 __reserved; }`
/// — 24 bytes, identical on x86_64 and aarch64.
const ENTRY_BYTES: u64 = 24;
const OFF_UADDR: u64 = 8;
const OFF_FLAGS: u64 = 16;
const OFF_RESERVED: u64 = 20;
/// `FUTEX_WAITV_MAX`.
const FUTEX_WAITV_MAX: u64 = 128;

/// Convert `futex_waitv`'s ABSOLUTE timeout to the kernel's monotonic deadline.
///
/// Only `CLOCK_REALTIME` and `CLOCK_MONOTONIC` are accepted, and that check runs
/// BEFORE the timespec is read: a bogus clockid with an unreadable timespec is
/// `EINVAL`, not `EFAULT`.
///
/// A deadline already in the past is NOT reported as `ETIMEDOUT` here. Linux
/// arms an already-expired timer and still runs the wait, so a `*uaddr != val`
/// mismatch reports `EAGAIN` — returning `ETIMEDOUT` from the setup would have
/// hidden that and told a caller its futex value matched when it did not.
fn absolute_deadline_ns(timeout: u64, clockid: u64) -> Result<u64, i64> {
    if timeout == 0 { return Ok(0); }
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
    let mono = crate::time_common::monotonic_ns();
    Ok(mono.saturating_add(host_abs.saturating_sub(now)).max(1))
}

/// `sys_futex_waitv(waiters, nr_futexes, flags, timeout, clockid)`.
///
/// Parks until ANY listed futex is woken and returns that entry's index.
/// # C: O(N) pre-flight + O(N) park-enqueue
pub fn sys_futex_waitv(args: &SyscallArgs) -> i64 {
    let (ptr, n) = (args.a0, args.a1 as u32 as u64);
    // The syscall-level `flags` argument is reserved — no bit is defined and
    // the per-futex flags live in each array entry. Ignoring it (the previous
    // shape) silently accepted a caller asking for unimplemented behaviour.
    if args.a2 != 0 { return -(Errno::Einval.as_i32() as i64); }
    if ptr == 0 || n == 0 || n > FUTEX_WAITV_MAX { return -(Errno::Einval.as_i32() as i64); }
    let deadline_ns = match absolute_deadline_ns(args.a3, args.a4) {
        Ok(dl) => dl,
        Err(e) => return e,
    };
    if let Err(rv) = crate::userbuf::validate_user_buf(ptr, n * ENTRY_BYTES, 1) { return rv; }
    let mut entries: ::alloc::vec::Vec<WaitvEntry> = ::alloc::vec::Vec::with_capacity(n as usize);
    for i in 0..n {
        let base = ptr + i * ENTRY_BYTES;
        // SAFETY: the full wait-vector byte span was validated; scalar loads permit unaligned user storage.
        let val   = unsafe { core::ptr::read_unaligned(base as *const u64) };
        // SAFETY: uaddr lies within the validated wait-vector entry.
        let uaddr = unsafe { core::ptr::read_unaligned((base + OFF_UADDR) as *const u64) };
        // SAFETY: flags lies within the validated wait-vector entry.
        let flags = unsafe { core::ptr::read_unaligned((base + OFF_FLAGS) as *const u32) };
        // SAFETY: __reserved lies within the validated wait-vector entry.
        let rsvd  = unsafe { core::ptr::read_unaligned((base + OFF_RESERVED) as *const u32) };
        // A non-zero `__reserved` is EINVAL: it is the extension point, and
        // accepting garbage there would make a future meaning unusable.
        if rsvd != 0 { return -(Errno::Einval.as_i32() as i64); }
        let f = match validate_futex2_flags(flags) {
            Ok(f) => f, Err(_) => return -(Errno::Einval.as_i32() as i64),
        };
        // `val` is `__u64`; a value wider than the futex word is EINVAL, not a
        // truncation that would make a mismatched compare-value look equal and
        // park the caller forever.
        if !validate_futex2_input(f.size_bytes, val) { return -(Errno::Einval.as_i32() as i64); }
        entries.push(WaitvEntry { uaddr, val: val as u32, private: f.private });
    }
    ::ipc::live::futex::dispatch_waitv_timed(&entries, deadline_ns)
}
