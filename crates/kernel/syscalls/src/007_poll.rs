// 007 poll — one syscall, one file (docs/53 §0). Moved verbatim from poll.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::poll::poll_common::monotonic_ns;

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
    if let Err(rv) = crate::userbuf::validate_user_buf(fds_ptr, bytes, 4) { return rv; }
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
                if file.inode().file_type() == vfs::FileType::CharDev
                    && (file.inode().ino() & 0xFFFF_0000) == 0x6000_0000
                {
                    // PTY: readability from the pair state (master/slave).
                    let ino = file.inode().ino();
                    let is_master = (ino & 0x8000) == 0;
                    let pty_readable = devpts::pair_for((ino & 0x7FFF) as u32).map(|pair| {
                        pair.with_pair(|p| if is_master { p.master_readable() } else { p.slave_readable() })
                    });
                    let inb = match pty_readable {
                        Some(true)  => POLLIN,
                        Some(false) => 0,
                        None        => POLLIN,
                    };
                    revents = events & (inb | POLLOUT);
                } else {
                    // Non-pty chardevs (e.g. /dev/console) + sockets / pipes /
                    // ext4 regulars: delegate to inode.poll() so POLLIN
                    // reflects real input readiness. Hardcoding POLLIN for
                    // console made systemd's DSR `ppoll(POLLIN)` loop spin on
                    // EAGAIN forever instead of timing out (it never reached
                    // the timeout→fallback path). ConsoleInode::poll() returns
                    // POLLIN only when its VT ring holds bytes. (F146: same
                    // POLL_IN/OUT/HUP bit layout as POLLIN/OUT/HUP; POSIX
                    // POLLHUP/ERR/NVAL always reported — see POLL_ALWAYS.)
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
        // B57: sleep on the poll wait queue (Linux way) instead of busy-
        // yield. Woken by `notify_poll_waiters`; bounded re-scan caps
        // worst-case latency for not-yet-wired ready-sites.
        const RESCAN_NS: u64 = 20_000_000;
        let rescan_at = monotonic_ns().saturating_add(RESCAN_NS);
        let park_dl = match deadline {
            Some(d) => core::cmp::min(d, rescan_at),
            None    => rescan_at,
        };
        // SAFETY: process ctx; preempt-off across the syscall; park marks Sleeping + stamps deadline; tick_yield yields; re-scan on wake.
        unsafe {
            sched::live::POLL_WAIT.park_with_deadline(park_dl);
            sched::live::tick_yield();
        }
    }
}

fn yield_sleep_ms(ms: u64) {
    let dl = monotonic_ns().saturating_add(ms * 1_000_000);
    while monotonic_ns() < dl {
        // SAFETY: process ctx; runqueue installed; tick_yield reschedules.
        unsafe { sched::live::tick_yield(); }
    }
}
