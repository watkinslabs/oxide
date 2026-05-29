// sys_poll / sys_ppoll per `15§5`. Extracted from fs.rs to keep
// that file under the 1000-line cap. Timeout-aware: -1 = block,
// 0 = single-pass, >0 = block up to `ms` milliseconds.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

const POLLIN:  i16 = 0x0001;
const POLLOUT: i16 = 0x0004;
/// B17 (T11): POSIX poll(2) — these are unconditionally reported in
/// `revents` regardless of whether the caller requested them in
/// `events`. Without this, sshd-session's poll(POLLIN) never sees
/// POLLHUP when the TCP peer closes, sshd waits forever for a
/// session that's already gone, and the accept'd socket leaks in
/// CLOSE_WAIT.
const POLLERR:  i16 = 0x0008;
const POLLHUP:  i16 = 0x0010;
const POLLNVAL: i16 = 0x0020;
const POLL_ALWAYS: i16 = POLLERR | POLLHUP | POLLNVAL;
const NFDS_MAX: u64 = 4096;

/// `sys_poll(fds, nfds, timeout)` — slot 7. Honors per-fd
/// readiness via PTY-pair `master_readable`/`slave_readable`;
/// non-pty CharDev defaults to always-ready (POLLIN | POLLOUT).
/// # C: O(nfds × N_loop)
pub fn sys_poll(args: &SyscallArgs) -> i64 {
    let fds_ptr = args.a0;
    let nfds    = args.a1;
    let timeout = args.a2 as i32;
    if nfds == 0 {
        if timeout > 0 { yield_sleep_ms(timeout as u64); }
        return 0;
    }
    if nfds > NFDS_MAX { return -(Errno::Einval.as_i32() as i64); }
    let bytes = match nfds.checked_mul(8) {
        Some(v) => v, None => return -(Errno::Efault.as_i32() as i64),
    };
    if let Err(rv) = crate::syscalls::validate_user_buf(fds_ptr, bytes, 4) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot per `13§5` single-mutator.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let deadline = if timeout > 0 { Some(monotonic_ns().saturating_add((timeout as u64) * 1_000_000)) } else { None };
    loop {
        let mut ready: i64 = 0;
        for i in 0..nfds {
            let p = fds_ptr + i * 8;
            // SAFETY: pollfd[i] inside validated nfds*8-byte range; 4-byte aligned read.
            let fd     = unsafe { core::ptr::read_volatile( p        as *const i32) };
            // SAFETY: same validated range; events at +4 is 2-byte aligned.
            let events = unsafe { core::ptr::read_volatile((p + 4)   as *const i16) };
            let mut revents: i16 = 0;
            if let Ok(file) = fdt.get(fd) {
                if file.inode().file_type() == vfs::FileType::CharDev {
                    let ino = file.inode().ino();
                    let pty_readable = if (ino & 0xFFFF_0000) == 0x6000_0000 {
                        let is_master = (ino & 0x8000) == 0;
                        crate::dev::pty::pair_for((ino & 0x7FFF) as u32).map(|pair| {
                            pair.with_pair(|p| if is_master { p.master_readable() } else { p.slave_readable() })
                        })
                    } else { None };
                    let inb = match pty_readable {
                        Some(true)  => POLLIN,
                        Some(false) => 0,
                        None        => POLLIN,
                    };
                    revents = events & (inb | POLLOUT);
                } else {
                    // F146: delegate to inode.poll() for sockets, pipes,
                    // ext4 regulars etc. The inode-side mask is bits
                    // POLL_IN(1) / POLL_OUT(4) / POLL_HUP(0x10) — same
                    // numeric layout as POLLIN/POLLOUT/POLLHUP so we
                    // can intersect against `events` directly.
                    // POSIX: POLLHUP/POLLERR/POLLNVAL are always
                    // reported regardless of `events` (see POLL_ALWAYS).
                    let mask = file.inode().poll() as i16;
                    revents = mask & (events | POLL_ALWAYS);
                }
            }
            // SAFETY: revents at p+6 inside validated range; 2-byte aligned.
            unsafe { core::ptr::write_volatile((p + 6) as *mut i16, revents); }
            if revents != 0 { ready += 1; }
        }
        if ready > 0 || timeout == 0 { return ready; }
        if let Some(dl) = deadline { if monotonic_ns() >= dl { return 0; } }
        // B17 (T11 close): break out of the poll loop on any unblocked
        // pending signal so the dispatch tail can deliver the signal
        // (and run its default action / handler). Without this, a task
        // parked in poll(-1) never sees SIGCHLD when a child exits, so
        // sshd-session waits forever for its slave that already died
        // and the accept'd TCP socket leaks in CLOSE_WAIT. Mirrors the
        // pselect6 EINTR check.
        use core::sync::atomic::Ordering;
        let pending = cur.sigpending.load(Ordering::Acquire);
        let mask    = cur.sigmask.load(Ordering::Acquire);
        if pending & !mask != 0 {
            return -(Errno::Eintr.as_i32() as i64);
        }
        // SAFETY: process ctx; runqueue installed; preempt-off; tick_yield returns to loop recheck.
        unsafe { sched::live::tick_yield(); }
    }
}

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

#[inline]
fn monotonic_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

fn yield_sleep_ms(ms: u64) {
    let dl = monotonic_ns().saturating_add(ms * 1_000_000);
    while monotonic_ns() < dl {
        // SAFETY: process ctx; runqueue installed; tick_yield reschedules.
        unsafe { sched::live::tick_yield(); }
    }
}
