// 202 futex — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_futex(uaddr, op, val, ts, uaddr2, val3)` — slot 202.
/// Delegates to `::ipc::live::futex` which keeps a per-(mm_root_pa, va)
/// in-kernel wait queue. Supported ops:
///   FUTEX_WAIT (0) — atomically check `*uaddr == val`; if so park
///                    self until FUTEX_WAKE on the same key.
///   FUTEX_WAKE (1) — wake at most `val` tasks parked on this key.
/// Both ops accept `| FUTEX_PRIVATE_FLAG (128)` and `|
/// FUTEX_CLOCK_REALTIME (256)` masks (treated as no-ops since v1
/// process-private-only with monotonic clock).
/// # C: O(W) waiters per WAKE, O(1) WAIT
pub fn sys_futex(args: &SyscallArgs) -> i64 {
    ::ipc::live::futex::dispatch(args.a0, args.a1 as u32, args.a2 as u32)
}
