use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::{
    epoll_inode_of, make_epoll_inode, EpItem, EPOLLEXCLUSIVE, EPOLL_CTL_ADD,
    EPOLL_CTL_DEL, EPOLL_CTL_MOD, EPOLL_DATA_OFF, EPOLL_EVENT_SIZE, EPOLLET,
    EPOLLWAKEUP,
    NEXT_SUB_ID,
};
use super::scan::{scan_once, validate_events_out};
use crate::userbuf::validate_user_buf;

#[cfg(all(target_os = "oxide-kernel", feature = "debug-fdlife"))]
fn trace_ebadf(cur: &sched::Task, fdt: &vfs::FdTable, epfd: i32, op: i32, fd: i32, missing: &'static [u8]) {
    klog::write_raw(b"[EPBADF pid="); klog::write_dec_u64(cur.vtgid.load(Ordering::Acquire) as u64);
    klog::write_raw(b" table="); klog::write_hex_u64(fdt as *const vfs::FdTable as u64);
    klog::write_raw(b" epfd="); klog::write_dec_u64(epfd as u32 as u64);
    klog::write_raw(b" op="); klog::write_dec_u64(op as u32 as u64);
    klog::write_raw(b" fd="); klog::write_dec_u64(fd as u32 as u64);
    klog::write_raw(b" missing="); klog::write_raw(missing);
    klog::write_raw(b" live=");
    for live in fdt.live_fds() { klog::write_dec_u64(live as u64); klog::write_raw(b","); }
    klog::write_raw(b"]\n");
    vfs::fdtable::debug::dump(fdt);
}

/// `sys_epoll_create(size)`. # C: O(N_fds)
pub fn sys_epoll_create(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let size = args.a0 as i32;
    if size <= 0 { return -(Errno::Einval.as_i32() as i64); }
    sys_epoll_create_common(0)
}

/// `sys_epoll_create1(flags)`. # C: O(N_fds)
pub fn sys_epoll_create1(args: &syscall::SyscallArgs) -> i64 {
    sys_epoll_create_common(args.a0)
}

fn sys_epoll_create_common(flags: u64) -> i64 {
    use syscall::errno::Errno;
    use vfs::{File, OpenFlags};
    const EPOLL_CLOEXEC: u64 = OpenFlags::O_CLOEXEC.bits() as u64;
    if flags & !EPOLL_CLOEXEC != 0 { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = make_epoll_inode();
    let dentry = vfs::dcache::d_alloc_pseudo("[eventpoll]", Arc::clone(&inode), &crate::anon_dname::ANON_INODE_OPS);
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => {
            if (flags & EPOLL_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}

/// `sys_epoll_ctl(epfd, op, fd, event*)`. # C: O(N_entries)
pub fn sys_epoll_ctl(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let epfd = args.a0 as i32;
    let op   = args.a1 as i32;
    let fd   = args.a2 as i32;
    let evp  = args.a3;
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let epfile = match fdt.get(epfd) {
        Ok(f) => f,
        Err(_) => {
            #[cfg(all(target_os = "oxide-kernel", feature = "debug-fdlife"))]
            trace_ebadf(cur, &fdt, epfd, op, fd, b"epfd");
            return -(Errno::Ebadf.as_i32() as i64);
        }
    };
    let ep = match epoll_inode_of(&epfile) {
        Some(i) => i, None => return -(Errno::Einval.as_i32() as i64),
    };
    let (events, data) = if op == EPOLL_CTL_DEL {
        (0u32, 0u64)
    } else {
        if let Err(rv) = validate_user_buf(evp, EPOLL_EVENT_SIZE as u64, 1) { return rv; }
        // SAFETY: evp validated readable for one epoll_event object.
        unsafe {
            let ev = core::ptr::read_unaligned(evp as *const u32);
            let da = core::ptr::read_unaligned((evp + EPOLL_DATA_OFF as u64) as *const u64);
            (ev, da)
        }
    };
    let target_file = match fdt.get(fd) {
        Ok(f) => f,
        Err(_) => {
            #[cfg(all(target_os = "oxide-kernel", feature = "debug-fdlife"))]
            trace_ebadf(cur, &fdt, epfd, op, fd, b"target");
            return -(Errno::Ebadf.as_i32() as i64);
        }
    };
    if op != EPOLL_CTL_DEL {
        if Arc::ptr_eq(&target_file, &epfile) { return -(Errno::Einval.as_i32() as i64); }
    }
    if events & EPOLLEXCLUSIVE != 0 {
        const EXCLUSIVE_EVENTS: u32 = vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_PRI
            | vfs::POLL_ERR | vfs::POLL_HUP | EPOLLET | EPOLLWAKEUP | EPOLLEXCLUSIVE;
        if op != EPOLL_CTL_ADD || events & !EXCLUSIVE_EVENTS != 0 {
            return -(Errno::Einval.as_i32() as i64);
        }
    }
    match op {
        EPOLL_CTL_ADD => {
            if let Some(child) = epoll_inode_of(&target_file) {
                if nested_reaches(&child, ep.id, 0).is_err() {
                    return -(Errno::Eloop.as_i32() as i64);
                }
            }
            let mut entries = ep.entries.lock();
            if entries.iter().any(|e| e.fd == fd && e.file_is(&target_file)) {
                return -(Errno::Eexist.as_i32() as i64);
            }
            #[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
            {
                let target = sched::current().map(|c| {
                    c.creds.euid.load(Ordering::Acquire) == 1000
                        || unsafe { (*c.exe_path.get()).as_ref().map(|s| s.contains("dbus-broker")).unwrap_or(false) }
                }).unwrap_or(false);
                if target {
                    klog::write_raw(b"[EPADD tid=");
                    klog::write_dec_u64(sched::current().map(|c| c.tid as u64).unwrap_or(0));
                    klog::write_raw(b" fd="); klog::write_dec_u64(fd as u64);
                    klog::write_raw(b" ino="); klog::write_hex_u64(target_file.inode().ino());
                    klog::write_raw(b" ev="); klog::write_hex_u64(events as u64);
                    klog::write_raw(b"]\n");
                }
            }
            let sub_id = NEXT_SUB_ID.fetch_add(1, Ordering::Relaxed);
            let poll_source = target_file.poll_subscribers();
            let item = EpItem::new(&ep, fd, sub_id, events, data, target_file.clone(), poll_source);
            entries.push(Arc::clone(&item));
            target_file.epoll_link(sub_id, item.file_link());
            if let Some(subs) = item.poll_source.as_ref() {
                if events & EPOLLEXCLUSIVE != 0 { subs.subscribe_exclusive(sub_id, item.callback(), events); }
                else { subs.subscribe_mask(sub_id, item.callback(), events); }
            }
            if item.ready(events) != 0 { EpItem::queue(&item, true); }
            0
        }
        EPOLL_CTL_MOD => {
            let entries = ep.entries.lock();
            let item = entries.iter()
                .find(|e| e.fd == fd && e.file_is(&target_file)).cloned();
            let Some(item) = item else { return -(Errno::Enoent.as_i32() as i64); };
            {
                let mut state = item.state.lock();
                if state.events & EPOLLEXCLUSIVE != 0 {
                    return -(Errno::Einval.as_i32() as i64);
                }
                state.events = events;
                state.data = data;
                state.armed = true;
            }
            if let Some(subs) = item.poll_source.as_ref() {
                if events & EPOLLEXCLUSIVE != 0 { subs.subscribe_exclusive(item.sub_id, item.callback(), events); }
                else { subs.subscribe_mask(item.sub_id, item.callback(), events); }
            }
            if item.ready(events) != 0 { EpItem::queue(&item, true); }
            0
        }
        EPOLL_CTL_DEL => {
            let entries = ep.entries.lock();
            let item = entries.iter()
                .find(|e| e.fd == fd && e.file_is(&target_file)).cloned();
            let Some(item) = item else { return -(Errno::Enoent.as_i32() as i64); };
            drop(entries);
            EpItem::detach(&item);
            0
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}

const EP_MAX_NESTS: usize = 4;

/// Reject epoll cycles and Linux-excessive nesting before publishing an item.
/// # C: O(N_epoll_graph)
fn nested_reaches(start: &Arc<super::EpollData>, needle: u32, depth: usize) -> Result<(), ()> {
    if start.id == needle { return Err(()); }
    if depth >= EP_MAX_NESTS { return Err(()); }
    let entries = start.entries.lock().clone();
    for item in entries {
        let Some(file) = item.file.upgrade() else { continue; };
        let Some(child) = epoll_inode_of(&file) else { continue; };
        if child.id == needle { return Err(()); }
        nested_reaches(&child, needle, depth + 1)?;
    }
    Ok(())
}

/// `sys_epoll_wait(epfd, events*, maxevents, timeout)`. # C: O(N_entries)
pub fn sys_epoll_wait(args: &syscall::SyscallArgs) -> i64 {
    let timeout = args.a3 as i32;
    let timeout_ns = if timeout < 0 { None } else { Some((timeout as u64).saturating_mul(1_000_000)) };
    sys_epoll_wait_timeout(args, timeout_ns)
}

/// `sys_epoll_pwait(epfd, events*, maxevents, timeout_ms, sigmask, sigsetsize)`.
pub fn sys_epoll_pwait(args: &syscall::SyscallArgs) -> i64 {
    let timeout = args.a3 as i32;
    let timeout_ns = if timeout < 0 { None } else { Some((timeout as u64).saturating_mul(1_000_000)) };
    sys_epoll_wait_sigmask(args, timeout_ns, args.a4, args.a5)
}

/// `sys_epoll_pwait2(epfd, events*, maxevents, timeout*, sigmask, sigsetsize)`.
pub fn sys_epoll_pwait2(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let timeout_ns = if args.a3 == 0 {
        None
    } else {
        if let Err(rv) = validate_user_buf(args.a3, 16, 1) { return rv; }
        // SAFETY: timeout pointer validated readable for one timespec.
        let (sec, nsec) = unsafe {
            (
                core::ptr::read_unaligned(args.a3 as *const i64),
                core::ptr::read_unaligned((args.a3 + 8) as *const i64),
            )
        };
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return -(Errno::Einval.as_i32() as i64);
        }
        Some((sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64))
    };
    sys_epoll_wait_sigmask(args, timeout_ns, args.a4, args.a5)
}

fn sys_epoll_wait_sigmask(args: &syscall::SyscallArgs, timeout_ns: Option<u64>, sigmask_ptr: u64, sigsetsize: u64) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    if sigmask_ptr == 0 { return sys_epoll_wait_timeout(args, timeout_ns); }
    if sigsetsize != 8 { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_user_buf(sigmask_ptr, 8, 1) { return rv; }
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: sigmask_ptr validated as a readable 8-byte kernel_sigset_t.
    let new_mask = unsafe { core::ptr::read_unaligned(sigmask_ptr as *const u64) }
        & !(sched::signum::Signum::Sigkill.bit()
          | sched::signum::Signum::Sigstop.bit());
    let saved = cur.sigmask.swap(new_mask, Ordering::AcqRel);
    let rv = sys_epoll_wait_timeout(args, timeout_ns);
    cur.sigmask.store(saved, Ordering::Release);
    rv
}

fn sys_epoll_wait_timeout(args: &syscall::SyscallArgs, timeout_ns: Option<u64>) -> i64 {
    use syscall::errno::Errno;
    let epfd = args.a0 as i32;
    let evp  = args.a1;
    let maxevents = args.a2 as i32;
    if maxevents <= 0 { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_events_out(evp, maxevents) { return rv; }
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let epfile = match fdt.get(epfd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let ep = match epoll_inode_of(&epfile) {
        Some(i) => i, None => return -(Errno::Einval.as_i32() as i64),
    };
    ep.rescan_levels();
    let out = scan_once(&ep, evp, maxevents);
    if out > 0 || timeout_ns == Some(0) { return out as i64; }
    #[cfg(target_os = "oxide-kernel")]
    {
        use hal::TimerOps;
        let now = || {
            #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
            #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
        };
        let deadline_ns = timeout_ns.map(|ns| now().saturating_add(ns));
        #[cfg(feature = "debug-wakelat")]
        let wl_start = now();
        #[cfg(feature = "debug-wakelat")]
        let wl_tid = sched::current().map(|c| c.tid).unwrap_or(0);
        loop {
            let observed_global = super::GLOBAL_EPOLL_GEN.load(Ordering::Acquire);
            let current_ns = now();
            ep.queue_expired_deadlines(current_ns);
            ep.rescan_levels();
            let out2 = scan_once(&ep, evp, maxevents);
            if out2 > 0 {
                #[cfg(feature = "debug-wakelat")]
                sched::live::wakelat::note_blocked(
                    wl_tid, sched::live::wakelat::KIND_EPOLL,
                    now().saturating_sub(wl_start), out2 as u64);
                return out2 as i64;
            }
            if let Some(d) = deadline_ns {
                if current_ns >= d { return 0; }
            }
            if has_unmasked_signal() { return -(Errno::Eintr.as_i32() as i64); }
            #[cfg(feature = "debug-wakelat")]
            sched::live::wakelat::note_wait(wl_tid, sched::live::wakelat::KIND_EPOLL);
            let park_dl = match (deadline_ns, ep.next_poll_deadline()) {
                (Some(a), Some(b)) => core::cmp::min(a, b),
                (Some(a), None) | (None, Some(a)) => a,
                (None, None) => 0,
            };
            // SAFETY: process context; prepare_park marks current Sleeping while
            // holding the ready lock shared with source callbacks and broadcasts.
            if unsafe { ep.prepare_park(observed_global, park_dl) } {
                // Catch a signal published just before Sleeping was installed;
                // later signals observe Sleeping and wake through the scheduler.
                if has_unmasked_signal() { ep.waiters.wake_all(); }
                // SAFETY: prepare_park installed this task on ep.waiters.
                unsafe { sched::live::park_yield(); }
            }
        }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
        0
    }
}

#[cfg(target_os = "oxide-kernel")]
fn has_unmasked_signal() -> bool {
    let Some(cur) = sched::current() else { return false; };
    const FORCED: u64 = (1u64 << 8) | (1u64 << 18);
    let pending = cur.sigpending.load(Ordering::Acquire);
    let masked = cur.sigmask.load(Ordering::Acquire);
    (pending & !masked) | (pending & FORCED) != 0
}
