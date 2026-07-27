// 007 poll — one syscall, one file (docs/53 §0). Moved verbatim from poll.rs.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use syscall::SyscallArgs;
use syscall::errno::Errno;

#[cfg(not(test))]
use crate::poll::poll_common::{monotonic_ns, PollWaiter};
#[cfg(test)]
use super::poll::poll_common::{monotonic_ns, PollWaiter};
use crate::pselect_ppoll::wait_verdict;

/// `poll(2)`'s `int timeout` is milliseconds; Linux `do_sys_poll`'s caller
/// folds it into `end_time` through `poll_select_set_timeout(…, ms / MSEC_PER_SEC,
/// NSEC_PER_MSEC * (ms % MSEC_PER_SEC))`. `ppoll(2)` supplies nanoseconds
/// directly, so this scale belongs to slot 7 alone.
const NSEC_PER_MSEC: u64 = 1_000_000;

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

#[derive(Clone, Copy)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

/// Running task, shared with slot 271 so `ppoll` resolves `current` exactly as
/// the poll engine it hands off to does. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) fn current_task() -> Option<&'static sched::Task> {
    #[cfg(test)]
    {
        let p = TEST_CURRENT.load(core::sync::atomic::Ordering::Acquire);
        if p != 0 {
            // SAFETY: ownership tests leak the Task and clear this pointer only after the syscall returns.
            let task = unsafe { &*(p as *const sched::Task) };
            return Some(task);
        }
    }
    sched::current()
}

#[cfg(test)]
static TEST_CURRENT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static POST_SNAPSHOT_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
pub(super) fn set_test_current(task: Option<&'static sched::Task>) {
    TEST_CURRENT.store(task.map_or(0, |t| t as *const sched::Task as usize), core::sync::atomic::Ordering::Release);
}

#[cfg(test)]
pub(super) fn set_post_snapshot_hook(hook: Option<fn()>) {
    POST_SNAPSHOT_HOOK.store(hook.map_or(0, |f| f as usize), core::sync::atomic::Ordering::Release);
}

#[cfg(test)]
fn run_post_snapshot_hook() {
    let p = POST_SNAPSHOT_HOOK.swap(0, core::sync::atomic::Ordering::AcqRel);
    if p != 0 {
        // SAFETY: set_post_snapshot_hook stores only a `fn()` pointer and swap gives this call sole use.
        let hook: fn() = unsafe { core::mem::transmute(p) };
        hook();
    }
}

fn pollfd_bytes(nfds: u64) -> Result<u64, i64> {
    nfds.checked_mul(8).ok_or(-(Errno::Efault.as_i32() as i64))
}

fn copy_pollfds_from_user(fds_ptr: u64, nfds: u64) -> Result<Vec<PollFd>, i64> {
    let bytes = pollfd_bytes(nfds)?;
    #[cfg(not(test))]
    if let Err(rv) = crate::userbuf::validate_user_buf_readable(fds_ptr, bytes, 1) { return Err(rv); }
    #[cfg(test)]
    if let Err(rv) = super::userbuf::validate_user_buf_readable(fds_ptr, bytes, 1) { return Err(rv); }
    let mut out = Vec::new();
    let mut i = 0;
    while i < nfds {
        let p = fds_ptr + i * 8;
        // SAFETY: pollfd[i].fd/events lie inside the readable validated nfds*8-byte range.
        let fd = unsafe { core::ptr::read_unaligned(p as *const i32) };
        // SAFETY: pollfd[i].events lie inside the readable validated nfds*8-byte range.
        let events = unsafe { core::ptr::read_unaligned((p + 4) as *const i16) };
        out.push(PollFd { fd, events, revents: 0 });
        i += 1;
    }
    Ok(out)
}

fn copy_pollfds_revents_to_user(fds_ptr: u64, fds: &[PollFd]) -> Result<(), i64> {
    let bytes = pollfd_bytes(fds.len() as u64)?;
    #[cfg(not(test))]
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(fds_ptr, bytes, 1) { return Err(rv); }
    #[cfg(test)]
    if let Err(rv) = super::userbuf::validate_user_buf_writable(fds_ptr, bytes, 1) { return Err(rv); }
    for (i, pfd) in fds.iter().enumerate() {
        let p = fds_ptr + (i as u64) * 8 + 6;
        // SAFETY: pollfd[i].revents lies inside the writable validated nfds*8-byte range.
        unsafe { core::ptr::write_unaligned(p as *mut i16, pfd.revents); }
    }
    Ok(())
}

fn snapshot_poll_files(fdt: &vfs::FdTable, pfds: &[PollFd]) -> Vec<Option<Arc<vfs::File>>> {
    pfds.iter().map(|pfd| {
        if pfd.fd < 0 { None } else { fdt.get(pfd.fd).ok() }
    }).collect()
}

#[cfg(target_os = "oxide-kernel")]
fn pty_poll_in_bit(ino: u64) -> i16 {
    let is_master = (ino & 0x8000) == 0;
    let pty_readable = devpts::pair_for((ino & 0x7FFF) as u32).map(|pair| {
        pair.with_pair(|p| if is_master { p.master_readable() } else { p.slave_readable() })
    });
    match pty_readable {
        Some(true)  => POLLIN,
        Some(false) => 0,
        None        => POLLIN,
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn pty_poll_in_bit(_ino: u64) -> i16 { POLLIN }

/// `sys_poll(fds, nfds, timeout)` — slot 7. Honors per-fd
/// readiness via PTY-pair `master_readable`/`slave_readable`;
/// non-pty CharDev defaults to always-ready (POLLIN | POLLOUT).
/// # C: O(nfds × N_loop)
pub fn sys_poll(args: &SyscallArgs) -> i64 {
    let timeout = args.a2 as i32;
    // Linux `poll_select_set_timeout`: a negative ms waits indefinitely, and
    // `0` is a single non-blocking pass whose `end_time` is already reached.
    let deadline_ns = if timeout < 0 { None } else {
        Some(monotonic_ns().saturating_add((timeout as u64).saturating_mul(NSEC_PER_MSEC)))
    };
    sys_poll_deadline(args.a0, args.a1, deadline_ns)
}

/// Shared poll engine (Linux `do_sys_poll`) on an absolute monotonic
/// `end_time`. `poll(2)` folds its millisecond argument into one; `ppoll(2)`
/// folds its `timespec` into one, so a sub-millisecond wait never becomes an
/// early timeout. `None` = wait indefinitely.
/// # C: O(nfds × N_loop)
pub(crate) fn sys_poll_deadline(fds_ptr: u64, nfds: u64, deadline_ns: Option<u64>) -> i64 {
    let cur = match current_task() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if nfds > cur.nofile_soft() as u64 { return -(Errno::Einval.as_i32() as i64); }
    if nfds == 0 { return poll_no_fds(cur, deadline_ns); }
    let mut pfds = match copy_pollfds_from_user(fds_ptr, nfds) {
        Ok(v)  => v,
        Err(e) => return e,
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot per `13§5` single-mutator.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // Snapshot Oxide's requested open-file descriptions once. Every later
    // readiness operation uses this snapshot, so close/reuse cannot retarget
    // an active syscall and an initially invalid fd remains POLLNVAL.
    let files = snapshot_poll_files(&fdt, &pfds);
    #[cfg(test)]
    run_post_snapshot_hook();
    // Linux `->poll`: register this call's waiter on each polled fd's OWN
    // wait queue (PollSubscribers). The fd's readiness transition `notify()`s
    // only its subscribers — no global broadcast. Subscribe once, up front,
    // so a transition between scans still wakes us.
    let waiter = PollWaiter::new();
    let mut subbed: Vec<Arc<vfs::PollSubscribers>> = Vec::new();
    for file in files.iter().flatten() {
        if let Some(s) = file.poll_subscribers() {
            waiter.subscribe(&s);
            subbed.push(s);
        }
    }
    // debug-syscost: dump polkitd's polled fd set (fd/events/ino/readiness) +
    // timeout on entry, so the stuck ~45s ppoll's fds are visible (which fd it
    // waits on, whether it's already ready, infinite vs timed).
    #[cfg(feature = "debug-syscost")]
    {
        let is_pol = sched::live::current()
            .map(|c| c.with_exe_path(|p| p.map(|s| s.contains("polkit")).unwrap_or(false)))
            .unwrap_or(false);
        if is_pol {
            klog::write_raw(b"[POLLFDS tid="); klog::write_dec_u64(cur.tid as u64);
            klog::write_raw(b" nfds="); klog::write_dec_u64(nfds);
            klog::write_raw(b" deadline_ns="); klog::write_dec_u64(deadline_ns.unwrap_or(u64::MAX));
            let mut i = 0u64;
            while i < nfds && i < 12 {
                let pfd = pfds[i as usize];
                klog::write_raw(b" fd="); klog::write_dec_u64(pfd.fd as u64);
                klog::write_raw(b"/ev="); klog::write_hex_u64(pfd.events as u16 as u64);
                if let Some(file) = files[i as usize].as_ref() {
                    klog::write_raw(b"/ino="); klog::write_hex_u64(file.inode().ino());
                    klog::write_raw(b"/rdy="); klog::write_hex_u64(file.poll() as u64);
                }
                i += 1;
            }
            klog::write_raw(b"\n");
        }
    }
    let rv: i64 = loop {
        let observed = waiter.generation();
        let mut ready: i64 = 0;
        for (pfd, file) in pfds.iter_mut().zip(files.iter()) {
            let mut revents: i16 = 0;
            if let Some(file) = file.as_ref() {
                if file.inode().file_type() == vfs::FileType::CharDev
                    && (file.inode().ino() & 0xFFFF_0000) == 0x6000_0000
                {
                    // PTY: readability from the pair state (master/slave).
                    let inb = pty_poll_in_bit(file.inode().ino());
                    revents = (pfd.events & (inb | POLLOUT)) | ((file.poll() as i16) & POLL_ALWAYS);
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
                    let mask = file.poll() as i16;
                    revents = mask & (pfd.events | POLL_ALWAYS);
                }
            } else if pfd.fd >= 0 {
                revents = POLLNVAL;
            }
            pfd.revents = revents;
            if revents != 0 { ready += 1; }
        }
        // Linux `do_poll`'s break order (`crate::pselect_ppoll::wait_verdict`):
        // readiness, then a deliverable signal, then the expired deadline —
        // so a zero-timeout poll with a pending signal is EINTR, not 0.
        // B17 (T11 close): without the signal arm, a task parked in poll(-1)
        // never sees SIGCHLD when a child exits, so sshd-session waits forever
        // for a slave that already died and the accept'd TCP socket leaks in
        // CLOSE_WAIT.
        let timed_out = deadline_ns.map(|dl| monotonic_ns() >= dl).unwrap_or(false);
        if let Some(out) = wait_verdict(ready, timed_out, deliverable_signal_pending(cur)) {
            break out;
        }
        let source_deadline = files.iter().filter_map(|file| {
            file.as_ref().and_then(|file| file.poll_deadline_ns())
        }).min();
        let park_dl = min_deadline(deadline_ns, source_deadline).unwrap_or(0);
        // SAFETY: process ctx; preempt-off across the syscall; park+yield per `13§8`.
        unsafe { waiter.park_until(observed, park_dl); }
    };
    // Drop our registration from every fd we subscribed to.
    for s in &subbed { waiter.unsubscribe(s); }
    // Linux `do_sys_poll` copies `revents` out UNCONDITIONALLY, after
    // `do_poll` returns — an interrupted poll still zeroes the caller's
    // `revents` rather than leaving the previous call's values in place.
    if let Err(e) = copy_pollfds_revents_to_user(fds_ptr, &pfds) { return e; }
    rv
}

fn poll_no_fds(cur: &sched::Task, deadline_ns: Option<u64>) -> i64 {
    let waiter = PollWaiter::new();
    loop {
        let observed = waiter.generation();
        let timed_out = deadline_ns.map(|dl| monotonic_ns() >= dl).unwrap_or(false);
        if let Some(out) = wait_verdict(0, timed_out, deliverable_signal_pending(cur)) {
            return out;
        }
        let park_dl = deadline_ns.unwrap_or(0);
        // SAFETY: process ctx; preempt-off across the syscall; park+yield per `13§8`.
        unsafe { waiter.park_until(observed, park_dl); }
    }
}

fn min_deadline(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(core::cmp::min(x, y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

/// Linux `signal_pending(current)`: only signals the return path will act on.
/// Linux drops SIG_IGN and default-ignore dispositions at SEND time
/// (`sig_ignored`), so they must not turn a blocking poll into EINTR here
/// either — a raw `sigpending & !sigmask` makes e.g. a SIGWINCH resize
/// spuriously interrupt every event loop. Same helper every other blocking
/// path uses, so there is one definition of "deliverable".
/// # C: O(N_sig)
fn deliverable_signal_pending(cur: &sched::Task) -> bool {
    cur.deliverable_signals() != 0
}
