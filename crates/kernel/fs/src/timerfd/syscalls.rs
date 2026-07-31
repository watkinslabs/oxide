//! Linux timerfd syscall transactions and error ordering.

use alloc::sync::Arc;

use super::model::{
    TimerfdData, make_timerfd_inode, monotonic_deadline_from_value, monotonic_ns,
    timerfd_alarm_clock, timerfd_clock_known, timerfd_namespace_clock,
    timerfd_realtime_clock,
};
use super::uapi::{
    self, TFD_CLOEXEC, TFD_NONBLOCK, TFD_SETTIME_FLAGS, TFD_TIMER_ABSTIME,
    TFD_TIMER_CANCEL_ON_SET,
};

/// `sys_timerfd_create(clockid, flags)`. # C: O(N_fds)
pub fn sys_timerfd_create(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    use vfs::{File, OpenFlags};

    let clockid = args.a0 as u32 as u64;
    let flags = args.a1 as u32 as u64;
    if !timerfd_clock_known(clockid) || flags & !(TFD_NONBLOCK | TFD_CLOEXEC) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    if timerfd_alarm_clock(clockid) && !cur_has_cap(sched::cap::WAKE_ALARM) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = make_timerfd_inode(clockid);
    #[cfg(any(feature = "debug-desktop", feature = "debug-mutter-timer-verbose"))]
    if let Some(d) = inode.private::<TimerfdData>() {
        super::debug::event(b"create", d.id, clockid, flags, 0, monotonic_ns());
    }
    let dentry = vfs::dcache::d_alloc_pseudo(
        "[timerfd]",
        Arc::clone(&inode),
        &crate::anon_dname::ANON_INODE_OPS,
    );
    let mut fl = OpenFlags::O_RDWR;
    if (flags & TFD_NONBLOCK) != 0 { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode, dentry, fl);
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => {
            if (flags & TFD_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}

/// Import and atomically replace one timerfd's complete state.
/// # C: O(1), excluding namespace snapshot internals
pub fn sys_timerfd_settime(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;

    let error = |errno: Errno| -(errno.as_i32() as i64);
    let fd = args.a0 as i32;
    let flags = args.a1 as u32 as u64;
    let new = args.a2;
    let old = args.a3;
    let raw = match uapi::read_itimerspec(new) {
        Ok(raw) => raw,
        Err(errno) => return error(errno),
    };
    let prepared = match uapi::prepare_itimerspec(flags, raw) {
        Ok(prepared) => prepared,
        Err(errno) => {
            #[cfg(feature = "debug-mutter-timer-verbose")]
            super::debug::rejected(fd, flags, raw.interval_sec, raw.interval_nsec,
                raw.value_sec, raw.value_nsec);
            return error(errno);
        }
    };
    let cur = match sched::current() {
        Some(c) => c, None => return error(Errno::Ebadf),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return error(Errno::Ebadf),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return error(Errno::Ebadf),
    };
    let timerfd = match file.inode().private::<TimerfdData>() {
        Some(timerfd) => timerfd,
        None => return error(Errno::Einval),
    };
    if timerfd_alarm_clock(timerfd.clockid) && !cur.has_cap(sched::cap::WAKE_ALARM) {
        return error(Errno::Eperm);
    }
    #[cfg(any(feature = "debug-desktop", feature = "debug-mutter-timer-verbose"))]
    super::debug::spec(timerfd.id, timerfd.clockid, flags, raw.interval_sec,
        raw.interval_nsec, raw.value_sec, raw.value_nsec);

    let cancel_enabled = (flags & (TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET))
        == (TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET)
        && timerfd_realtime_clock(timerfd.clockid);
    let (old_spec, canceled, _projected_expiry, _now_mono) = {
        let mut state = timerfd.state.lock();
        let host_value = if (flags & TFD_TIMER_ABSTIME) != 0 && prepared.value_ns != 0 {
            match timerfd_namespace_clock(timerfd.clockid) {
                Some(clock) => {
                    let owner = match cur.namespace_snapshot() {
                        Some(snapshot) => snapshot.time,
                        None => return error(Errno::Eio),
                    };
                    match nscg::time_ns::absolute_to_host(&owner, clock, prepared.value_ns) {
                        Ok(value) => value,
                        Err(_) => return error(Errno::Eio),
                    }
                }
                None => prepared.value_ns,
            }
        } else { prepared.value_ns };
        let now_mono = monotonic_ns();
        let now_real = vfs::inode_times::realtime_now_ns();
        let realtime_absolute = host_value != 0
            && (flags & TFD_TIMER_ABSTIME) != 0
            && timerfd_realtime_clock(timerfd.clockid);
        let expiry = if realtime_absolute {
            host_value
        } else {
            monotonic_deadline_from_value(flags, host_value, now_mono)
        };
        let (old_spec, canceled) = state.install(now_mono, now_real, expiry,
            prepared.interval_ns, cancel_enabled, realtime_absolute,
            (flags & TFD_SETTIME_FLAGS) as u16);
        let projected_expiry = state.projected_expiry(now_mono, now_real);
        (old_spec, canceled, projected_expiry, now_mono)
    };
    timerfd.read_waiters.wake_all();
    timerfd.poll_subscribers.notify_mask(vfs::POLL_IN);
    #[cfg(any(feature = "debug-desktop", feature = "debug-mutter-timer-verbose"))]
    super::debug::event(b"arm", timerfd.id, timerfd.clockid, flags,
        _projected_expiry, _now_mono);
    if canceled { return error(Errno::Ecanceled); }
    if old != 0 {
        if let Err(errno) = uapi::write_itimerspec(old, old_spec) { return error(errno); }
    }
    0
}

/// Report one timerfd's remaining time and interval. # C: O(1)
pub fn sys_timerfd_gettime(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;

    let error = |errno: Errno| -(errno.as_i32() as i64);
    let fd = args.a0 as i32;
    let value = args.a1;
    let cur = match sched::current() {
        Some(c) => c, None => return error(Errno::Ebadf),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return error(Errno::Ebadf),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return error(Errno::Ebadf),
    };
    let timerfd = match file.inode().private::<TimerfdData>() {
        Some(timerfd) => timerfd,
        None => return error(Errno::Einval),
    };
    let now_mono = monotonic_ns();
    let now_real = vfs::inode_times::realtime_now_ns();
    let spec = {
        let mut state = timerfd.state.lock();
        state.snapshot(now_mono, now_real)
    };
    match uapi::write_itimerspec(value, spec) {
        Ok(()) => 0,
        Err(errno) => error(errno),
    }
}

/// Test the current task's effective capability set. # C: O(1)
fn cur_has_cap(cap: u32) -> bool {
    sched::current().map(|c| c.has_cap(cap)).unwrap_or(false)
}
