// 271 ppoll — one syscall, one file (docs/53 §0). Moved verbatim from poll.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::poll::s007_poll::sys_poll;

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
    let timeout_arg: u64 = if ts_ptr == 0 {
        (-1i32) as u32 as u64
    } else if ts_ptr >= USER_VA_END {
        0
    } else {
        // SAFETY: ts_ptr validated < USER_VA_END; struct timespec is 16 B; CPL=0 reads.
        unsafe {
            let s = core::ptr::read_volatile(ts_ptr as *const i64);
            let n = core::ptr::read_volatile((ts_ptr + 8) as *const i64);
            if s < 0 || n < 0 { 0 }
            else { (s as u64) * 1000 + (n as u64) / 1_000_000 }
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
    if sigmask_ptr != 0 && sigmask_ptr < USER_VA_END && sigsz == 8 {
        // SAFETY: ptr validated < USER_VA_END; sigset_t = 8 B on Linux x86_64/aarch64.
        let new_mask = unsafe { core::ptr::read_volatile(sigmask_ptr as *const u64) };
        cur.sigmask.store(new_mask, Ordering::Release);
    }
    let inner = SyscallArgs { a0: args.a0, a1: args.a1, a2: timeout_arg, a3: 0, a4: 0, a5: 0 };
    let rv = sys_poll(&inner);
    // Restore the caller's original sigmask (Linux ppoll semantic).
    if sigmask_ptr != 0 && sigmask_ptr < USER_VA_END && sigsz == 8 {
        cur.sigmask.store(saved_mask, Ordering::Release);
    }
    rv
}
