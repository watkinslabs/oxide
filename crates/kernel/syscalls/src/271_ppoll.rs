// 271 ppoll — one syscall, one file (docs/53 §0). Moved verbatim from poll.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::poll::s007_poll::sys_poll_timeout;
use crate::userbuf::validate_user_buf;

/// `sys_ppoll(fds, nfds, ts, sigmask, sigsz)` — slot 271. Timeout
/// from timespec (16 B { sec, nsec }); sigmask honored as a
/// best-effort block-mask swap is a follow-up.
/// # C: O(nfds × N_loop)
pub fn sys_ppoll(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let ts_ptr      = args.a2;
    let sigmask_ptr = args.a3;
    let sigsz       = args.a4;
    // NULL timespec = block forever (poll timeout = -1). {0,0} = single-pass.
    let timeout_ns = if ts_ptr == 0 {
        None
    } else {
        if let Err(rv) = validate_user_buf(ts_ptr, 16, 1) { return rv; }
        // SAFETY: ts_ptr validated as a readable 16-byte user timespec.
        let (s, n) = unsafe {
            (
                core::ptr::read_unaligned(ts_ptr as *const i64),
                core::ptr::read_unaligned((ts_ptr + 8) as *const i64),
            )
        };
        // `ktime_set`-clamped decode: a huge-but-valid tv_sec clamps to
        // KTIME_MAX_NS instead of an unbounded relative timeout.
        match ::syscall::time::timespec_to_ns(s, n) {
            Ok(ns) => Some(ns),
            Err(_) => return -(Errno::Einval.as_i32() as i64),
        }
    };
    // B17 (T11 close): honor the ppoll sigmask. The whole point of
    // ppoll over poll is the atomic sigmask swap — sshd-session uses
    // it to keep SIGCHLD blocked outside the wait and unblock it
    // exactly during the wait. Without this, SIGCHLD never makes the
    // poll loop's pending-signal check fire, sshd-session waits
    // forever for a child that already died, and accept'd TCP
    // sockets leak in CLOSE_WAIT.
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    let saved_mask = cur.sigmask.load(Ordering::Acquire);
    let swapped = if sigmask_ptr != 0 {
        if sigsz != 8 { return -(Errno::Einval.as_i32() as i64); }
        if let Err(rv) = validate_user_buf(sigmask_ptr, 8, 1) { return rv; }
        // SAFETY: sigmask_ptr validated as a readable 8-byte user sigset_t.
        let new_mask = unsafe { core::ptr::read_unaligned(sigmask_ptr as *const u64) };
        let new_mask = new_mask
            & !(sched::live::sigpend::Signum::Sigkill.bit()
              | sched::live::sigpend::Signum::Sigstop.bit());
        cur.sigmask.store(new_mask, Ordering::Release);
        true
    } else { false };
    let rv = sys_poll_timeout(args.a0, args.a1, timeout_ns);
    // Restore the caller's original sigmask (Linux ppoll semantic).
    if swapped {
        cur.sigmask.store(saved_mask, Ordering::Release);
    }
    rv
}
