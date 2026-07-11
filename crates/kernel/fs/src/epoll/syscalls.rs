use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::{
    epoll_inode_of, make_epoll_inode, EpollEntry, EPOLL_CTL_ADD, EPOLL_CTL_DEL,
    EPOLL_CTL_MOD, EPOLL_DATA_OFF, EPOLL_EVENT_SIZE, NEXT_SUB_ID,
};
use super::scan::{scan_once, validate_events_out};
use crate::userbuf::validate_user_buf;

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
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
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
    let target_inode = fdt.get(fd).ok().map(|f| f.inode().clone());
    let mut list = ep.entries.lock();
    match op {
        EPOLL_CTL_ADD => {
            if list.iter().any(|e| e.fd == fd) {
                return -(Errno::Eexist.as_i32() as i64);
            }
            #[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
            {
                let is_db = sched::current().and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s| s.contains("dbus-broker")) }).unwrap_or(false);
                if is_db {
                    klog::write_raw(b"[EPADD fd="); klog::write_dec_u64(fd as u64);
                    klog::write_raw(b" ino="); klog::write_hex_u64(target_inode.as_ref().map(|i| i.ino()).unwrap_or(0));
                    klog::write_raw(b" ev="); klog::write_hex_u64(events as u64);
                    klog::write_raw(b"]\n");
                }
            }
            let sub_id = NEXT_SUB_ID.fetch_add(1, Ordering::Relaxed);
            list.push(EpollEntry { fd, sub_id, events, data, et_seen: 0, last_gen: 0, last_ggen: 0,
                inode: target_inode.as_ref().map(Arc::downgrade) });
            #[cfg(target_os = "oxide-kernel")]
            if let Some(inode) = target_inode.as_ref() {
                if let Some(subs) = inode.poll_subscribers() {
                    let weak: alloc::sync::Weak<dyn vfs::EpollNotify> =
                        alloc::sync::Arc::downgrade(&(Arc::clone(&ep) as Arc<dyn vfs::EpollNotify>));
                    subs.subscribe(sub_id, weak);
                }
            }
            0
        }
        EPOLL_CTL_MOD => {
            let mut sub_id = None;
            for e in list.iter_mut() {
                if e.fd == fd { e.events = events; e.data = data; e.et_seen = 0; sub_id = Some(e.sub_id); break; }
            }
            let Some(sub_id) = sub_id else { return -(Errno::Enoent.as_i32() as i64); };
            #[cfg(target_os = "oxide-kernel")]
            if let Some(inode) = target_inode.as_ref() {
                if let Some(subs) = inode.poll_subscribers() {
                    let weak: alloc::sync::Weak<dyn vfs::EpollNotify> =
                        alloc::sync::Arc::downgrade(&(Arc::clone(&ep) as Arc<dyn vfs::EpollNotify>));
                    subs.subscribe(sub_id, weak);
                }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            let _ = sub_id;
            0
        }
        EPOLL_CTL_DEL => {
            let sub_id = list.iter().find(|e| e.fd == fd).map(|e| e.sub_id);
            let Some(sub_id) = sub_id else { return -(Errno::Enoent.as_i32() as i64); };
            list.retain(|e| e.fd != fd);
            #[cfg(target_os = "oxide-kernel")]
            if let Some(inode) = target_inode.as_ref() {
                if let Some(subs) = inode.poll_subscribers() {
                    subs.unsubscribe(sub_id);
                }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            let _ = sub_id;
            0
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
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
        & !(sched::live::sigpend::Signum::Sigkill.bit()
          | sched::live::sigpend::Signum::Sigstop.bit());
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
    let out = scan_once(&ep, &fdt, evp, maxevents);
    if out > 0 || timeout_ns == Some(0) { return out as i64; }
    #[cfg(target_os = "oxide-kernel")]
    {
        use hal::TimerOps;
        let now = || {
            #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
            #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
        };
        let deadline_ns = timeout_ns.map(|ns| now().saturating_add(ns));
        const RESCAN_NS: u64 = 20_000_000;
        #[cfg(feature = "debug-wakelat")]
        let wl_start = now();
        #[cfg(feature = "debug-wakelat")]
        let wl_tid = sched::current().map(|c| c.tid).unwrap_or(0);
        loop {
            let rescan_at = now().saturating_add(RESCAN_NS);
            let park_dl = match deadline_ns {
                Some(d) => core::cmp::min(d, rescan_at),
                None => rescan_at,
            };
            #[cfg(feature = "debug-wakelat")]
            sched::live::wakelat::note_wait(wl_tid, sched::live::wakelat::KIND_EPOLL);
            // SAFETY: process context; park state belongs to current task until scheduler yields.
            unsafe {
                ep.waiters.park_with_deadline(park_dl);
                sched::live::park_yield();
            }
            let out2 = scan_once(&ep, &fdt, evp, maxevents);
            if out2 > 0 {
                #[cfg(feature = "debug-wakelat")]
                sched::live::wakelat::note_blocked(
                    wl_tid, sched::live::wakelat::KIND_EPOLL,
                    now().saturating_sub(wl_start), out2 as u64);
                return out2 as i64;
            }
            if let Some(d) = deadline_ns {
                if now() >= d { return 0; }
            }
            if let Some(cur) = sched::current() {
                const FORCED: u64 = (1u64 << 8) | (1u64 << 18);
                let pending = cur.sigpending.load(Ordering::Acquire);
                let masked  = cur.sigmask.load(Ordering::Acquire);
                if (pending & !masked) | (pending & FORCED) != 0 {
                    return -(syscall::errno::Errno::Eintr.as_i32() as i64);
                }
            }
        }
    }
}
