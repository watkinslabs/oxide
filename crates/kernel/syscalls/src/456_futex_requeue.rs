// 456 futex_requeue — one syscall, one file (docs/53 §0).
//
// futex2 `futex_requeue(struct futex_waitv *waiters, unsigned int flags,
// int nr_wake, int nr_requeue)`: waiters[0] = source, waiters[1] = destination.
// Wake `nr_wake` on the source futex, then requeue `nr_requeue` waiters to the
// destination.
//
// This is the futex2 spelling of `FUTEX_CMP_REQUEUE`, NOT of the bare
// `FUTEX_REQUEUE`: `waiters[0].val` is a COMPARE value, and the requeue must
// fail with EAGAIN when the source word no longer holds it. Dropping that
// comparison (the previous shape here) is exactly the race `FUTEX_REQUEUE` was
// deprecated for — a condvar broadcast that lost a race would move waiters onto
// a mutex the signaller had already released, and they would never be woken.

use syscall::{errno::Errno, SyscallArgs};
use ipc::futex2_flags::{validate_futex2_flags, validate_futex2_input};

/// `sizeof(struct futex_waitv)`; `val@0`, `uaddr@8`, `flags@16`, `__reserved@20`.
const WAITV_SZ: u64 = 24;
const OFF_UADDR: u64 = 8;
const OFF_FLAGS: u64 = 16;
const OFF_RESERVED: u64 = 20;

struct Parsed { uaddr: u64, val: u64, flags: u32, private: bool }

/// Read and validate one `struct futex_waitv` from an already-validated span.
fn parse(base: u64) -> Result<Parsed, i64> {
    let einval = -(Errno::Einval.as_i32() as i64);
    // SAFETY: `base` lies inside a span validated as readable by the caller; scalar loads permit unaligned user storage.
    let val = unsafe { core::ptr::read_unaligned(base as *const u64) };
    // SAFETY: uaddr lies within the same validated 24-byte entry.
    let uaddr = unsafe { core::ptr::read_unaligned((base + OFF_UADDR) as *const u64) };
    // SAFETY: flags lies within the same validated 24-byte entry.
    let flags = unsafe { core::ptr::read_unaligned((base + OFF_FLAGS) as *const u32) };
    // SAFETY: __reserved lies within the same validated 24-byte entry.
    let rsvd = unsafe { core::ptr::read_unaligned((base + OFF_RESERVED) as *const u32) };
    if rsvd != 0 { return Err(einval); }
    let f = validate_futex2_flags(flags).map_err(|_| einval)?;
    if !validate_futex2_input(f.size_bytes, val) { return Err(einval); }
    Ok(Parsed { uaddr, val, flags, private: f.private })
}

/// `sys_futex_requeue(waiters, flags, nr_wake, nr_requeue)` — slot 456.
/// # C: O(W)
pub fn sys_futex_requeue(args: &SyscallArgs) -> i64 {
    let einval = -(Errno::Einval.as_i32() as i64);
    let waiters = args.a0;
    if args.a1 != 0 { return einval; } // flags reserved
    if waiters == 0 { return einval; }
    let nr_wake    = args.a2 as i32 as i64;
    let nr_requeue = args.a3 as i32 as i64;
    if let Err(rv) = crate::userbuf::validate_user_buf(waiters, WAITV_SZ * 2, 1) { return rv; }
    let src = match parse(waiters)            { Ok(p) => p, Err(rv) => return rv };
    let dst = match parse(waiters + WAITV_SZ) { Ok(p) => p, Err(rv) => return rv };
    // Both entries must agree on size class AND private/shared: one requeue
    // cannot span two key derivations, and a mismatch is a caller bug rather
    // than something to silently resolve in one direction.
    if src.flags != dst.flags { return einval; }
    ::ipc::live::futex::cmp_requeue(
        src.uaddr, dst.uaddr, nr_wake, nr_requeue, src.val as u32, src.private)
}
