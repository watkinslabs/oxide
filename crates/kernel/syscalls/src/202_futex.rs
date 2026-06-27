// 202 futex — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_futex(uaddr, op, val, ts, uaddr2, val3)` — slot 202.
/// Delegates to `::ipc::live::futex` which keeps a per-(mm_root_pa, va)
/// in-kernel wait queue. Supported ops: FUTEX_WAIT/FUTEX_WAIT_BITSET (park
/// until FUTEX_WAKE or the timeout), FUTEX_WAKE/FUTEX_WAKE_BITSET.
///
/// `ts` (a3) is the timeout: RELATIVE for FUTEX_WAIT, ABSOLUTE for
/// FUTEX_WAIT_BITSET. Honored here as a monotonic deadline so timeout-only
/// waits (pthread_cond_timedwait, sem_timedwait) wake on expiry with
/// ETIMEDOUT instead of hanging forever — the bug that wedged early systemd
/// services. `FUTEX_PRIVATE_FLAG`/`FUTEX_CLOCK_REALTIME` masks are accepted
/// (v1 process-private + monotonic clock).
/// # C: O(W) waiters per WAKE, O(1) WAIT
pub fn sys_futex(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    use syscall::errno::Errno;
    const FUTEX_WAIT: u32 = 0;
    const FUTEX_WAIT_BITSET: u32 = 9;
    let op = args.a1 as u32;
    let op_base = op & 0x7f;

    // REQUEUE/CMP_REQUEUE/WAKE_OP operate on TWO futex words and carry their
    // operands in a3/a4/a5 (uaddr2 = a4). Previously these fell through the
    // futex dispatch's `_ => 0` no-op, so glibc condvar broadcast / requeue and
    // WAKE_OP fast paths silently did nothing → waiters never moved/woken
    // (deadlock). Wire them to the real implementations (Linux semantics).
    const FUTEX_REQUEUE: u32 = 3;
    const FUTEX_CMP_REQUEUE: u32 = 4;
    const FUTEX_WAKE_OP: u32 = 5;
    let private = (op & ::ipc::live::futex::FUTEX_PRIVATE_FLAG) != 0;
    match op_base {
        FUTEX_REQUEUE => {
            return ::ipc::live::futex::requeue(args.a0, args.a4, args.a2 as usize, args.a3 as usize, private);
        }
        FUTEX_CMP_REQUEUE => {
            return ::ipc::live::futex::cmp_requeue(
                args.a0, args.a4, args.a2 as usize, args.a3 as usize, args.a5 as u32, private);
        }
        FUTEX_WAKE_OP => {
            return ::ipc::live::futex::wake_op(
                args.a0, args.a4, args.a2 as usize, args.a3 as usize, args.a5 as u32, private);
        }
        _ => {}
    }

    let ts = args.a3;
    let deadline_ns = if (op_base == FUTEX_WAIT || op_base == FUTEX_WAIT_BITSET)
        && ts != 0 && ts < hal::USER_VA_END
    {
        // SAFETY: ts validated < USER_VA_END; timespec is 2×i64 at +0/+8 in
        // the caller's AS; CPL=0 reads via active CR3.
        let secs = unsafe { core::ptr::read_volatile(ts as *const i64) };
        // SAFETY: same validated range; tv_nsec at +8.
        let nsec = unsafe { core::ptr::read_volatile((ts + 8) as *const i64) };
        if secs < 0 || nsec < 0 || nsec >= 1_000_000_000 {
            return -(Errno::Einval.as_i32() as i64);
        }
        let t = (secs as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64);
        #[cfg(target_arch = "x86_64")]
        let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
        #[cfg(target_arch = "aarch64")]
        let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        // FUTEX_WAIT timeout is relative; FUTEX_WAIT_BITSET is absolute.
        // `.max(1)` keeps 0 reserved for "no timeout".
        if op_base == FUTEX_WAIT { now.saturating_add(t).max(1) } else { t.max(1) }
    } else {
        0
    };
    ::ipc::live::futex::dispatch_timed(args.a0, op, args.a2 as u32, deadline_ns)
}
