// sys_waitid — extracted from syscalls/mod.rs per docs/08§7 cap.
// Linux idtype P_ALL/P_PID/P_PGID/P_PIDFD maps to wait4; populates a
// canonical siginfo_t in user memory (si_signo / si_code /
// si_pid / si_status) from the wait4-encoded wstat.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::wait::{
    waitid_code_status_from_wstat, waitid_options_valid, P_ALL, P_PGID, P_PID, P_PIDFD,
    WCONTINUED, WEXITED, WNOHANG, WNOWAIT, WSTAT_CONTINUED, WSTOPPED,
};


const SIGINFO_BYTES: u64 = 128;
const SIGINFO_OFF_SIGNO:  u64 = 0;
const SIGINFO_OFF_CODE:   u64 = 8;
const SIGINFO_OFF_PID:    u64 = 16;
const SIGINFO_OFF_UID:    u64 = 20;
const SIGINFO_OFF_STATUS: u64 = 24;

/// # C: same as wait4 — bounded by zombie poll
pub fn sys_waitid(args: &SyscallArgs) -> i64 {
    let idtype  = args.a0;
    let id      = args.a1 as i32;
    let infop   = args.a2;
    let options = args.a3;
    let rusage  = args.a4;
    if !waitid_options_valid(options) { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    #[cfg(feature = "debug-displaystack")]
    {
        if let Some(cur) = sched::live::current() {
            if cur.name == "fork-child" {
                klog::write_raw(b"[waitid entry] tid=");
                klog::write_dec_u64(cur.tid as u64);
                klog::write_raw(b" vpid=");
                klog::write_dec_u64(cur.vtgid.load(core::sync::atomic::Ordering::Acquire) as u64);
                klog::write_raw(b" idtype=");
                klog::write_dec_u64(idtype);
                klog::write_raw(b" id=");
                klog::write_dec_u64(id as i64 as u64);
                klog::write_raw(b" options=");
                klog::write_hex_u64(options);
                klog::write_raw(b"\n");
            }
        }
    }
    let mut effective_options = options;
    let mut pidfd_forced_nonblock = false;
    let pid_for_wait4: i32 = match idtype {
        P_ALL  => -1,
        P_PID  => {
            if id <= 0 { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
            id
        }
        P_PGID => {
            if id < 0 { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
            -id
        }
        P_PIDFD => {
            if id < 0 { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
            let current = match sched::live::current() {
                Some(current) => current,
                None => return -(syscall::errno::Errno::Ebadf.as_i32() as i64),
            };
            let (target, flags) = match pidfd::task_and_flags_from_fd(current, id) {
                Ok(v) => v,
                Err(pidfd::ResolveError::Released) => {
                    return -(syscall::errno::Errno::Echild.as_i32() as i64);
                }
                Err(pidfd::ResolveError::BadFd | pidfd::ResolveError::NotPidfd) => {
                    return -(syscall::errno::Errno::Ebadf.as_i32() as i64);
                }
            };
            if !target.pid.is_group_leader() {
                return -(syscall::errno::Errno::Echild.as_i32() as i64);
            }
            if flags.contains(vfs::OpenFlags::O_NONBLOCK) && (options & WNOHANG) == 0 {
                effective_options |= WNOHANG;
                pidfd_forced_nonblock = true;
            }
            sched::live::registry::display_vpid(target.tid) as i32
        }
        _ => return -(syscall::errno::Errno::Einval.as_i32() as i64),
    };
    #[cfg(feature = "debug-displaystack")]
    let debug_waitid_parent = sched::live::current().and_then(|cur| {
        if cur.name == "fork-child" {
            Some((
                cur.tid,
                cur.vtgid.load(core::sync::atomic::Ordering::Acquire),
                sched::live::registry::has_children(cur.tid),
            ))
        } else {
            None
        }
    });
    #[cfg(not(feature = "debug-displaystack"))]
    let debug_waitid_parent: Option<(u32, u32, bool)> = None;
    // DIAG (debug-watchdog): a garbage pid_for_wait4 distinguishes systemd
    // memory corruption (P_PID/P_PGID with a garbage id) from a kernel
    // pidfd-conversion bug (P_PIDFD → display_vpid returns garbage).
    #[cfg(feature = "debug-watchdog")]
    if pid_for_wait4 > 100_000 || pid_for_wait4 < -100_000 {
        klog::write_raw(b"[waitid GARBAGE] idtype="); klog::write_dec_u64(idtype);
        klog::write_raw(b" id="); klog::write_hex_u64(id as u32 as u64);
        klog::write_raw(b" pid_for_wait4="); klog::write_hex_u64(pid_for_wait4 as u32 as u64);
        klog::write_raw(b"\n");
    }
    let mut local_wstat: i32 = 0;
    let mut local_uid: u32 = 0;
    // WNOWAIT: observe the matching event without consuming it. Linux checks
    // zombie/exited first, then stopped, then continued.
    let rv = if effective_options & WNOWAIT != 0 {
        let (parent_tid, parent_tgid, parent_pgid) = match sched::live::current() {
            Some(c) => (
                c.tid,
                c.tgid.load(core::sync::atomic::Ordering::Acquire),
                c.pgid.load(core::sync::atomic::Ordering::Acquire),
            ),
            None    => (0, 0, 0),
        };
        let want_exit = (effective_options & WEXITED) != 0;
        let want_stop = (effective_options & WSTOPPED) != 0;
        let want_cont = (effective_options & WCONTINUED) != 0;
        let event = if want_exit {
            sched::live::peek_one(parent_tid, parent_tgid, pid_for_wait4, parent_pgid, effective_options)
                .map(|(child, code)| (child, if code & 0x100 != 0 { code & 0x7f } else { (code & 0xff) << 8 }))
        } else { None }
        .or_else(|| sched::live::registry::peek_child_stop_event(parent_tid, parent_tgid, pid_for_wait4, parent_pgid, effective_options, want_stop, want_cont)
            .map(|(child, kind, sig)| (child, if kind == 1 { ((sig as i32) << 8) | 0x7f } else { WSTAT_CONTINUED })));
        match event {
            Some((child, wstat)) => {
                local_wstat = wstat;
                local_uid = child.uid;
                if let Err(e) = crate::wait::write_rusage(rusage, child) { return e; }
                child.vpid as i64
            }
            None => {
                if !sched::live::registry::has_wait_children(parent_tid, parent_tgid, pid_for_wait4, parent_pgid, effective_options) {
                    -(syscall::errno::Errno::Echild.as_i32() as i64)
                } else if effective_options & WNOHANG != 0 {
                    0
                } else {
                    // Blocking WNOWAIT without WNOHANG: park until a child
                    // exits/stops/continues, then re-peek.
                    // Interruptible like sys_wait4: a deliverable signal —
                    // and ALWAYS unblockable SIGKILL/SIGSTOP — aborts with
                    // -EINTR so the dispatch tail can terminate a SIGKILL'd
                    // task instead of re-parking it forever (see 061_wait4).
                    if let Some(cur) = sched::live::current() {
                        use core::sync::atomic::Ordering;
                        use sched::live::sigpend::Signum;
                        let forced  = Signum::Sigkill.bit() | Signum::Sigstop.bit();
                        let pending = cur.sigpending.load(Ordering::Acquire);
                        let masked  = cur.sigmask.load(Ordering::Acquire);
                        let deliver = (pending & !masked) | (pending & forced);
                        if deliver != 0 { return syscall::restart::restart_sys(); }
                    }
                    // SAFETY: process ctx; runqueue installed; preempt-off; park+reschedule per `13§8`.
                    unsafe { sched::live::park_for_wait4(); sched::live::schedule(); }
                    let event = if want_exit {
                        sched::live::peek_one(parent_tid, parent_tgid, pid_for_wait4, parent_pgid, effective_options)
                            .map(|(child, code)| (child, if code & 0x100 != 0 { code & 0x7f } else { (code & 0xff) << 8 }))
                    } else { None }
                    .or_else(|| sched::live::registry::peek_child_stop_event(parent_tid, parent_tgid, pid_for_wait4, parent_pgid, effective_options, want_stop, want_cont)
                        .map(|(child, kind, sig)| (child, if kind == 1 { ((sig as i32) << 8) | 0x7f } else { WSTAT_CONTINUED })));
                    match event {
                        Some((child, wstat)) => {
                            local_wstat = wstat;
                            local_uid = child.uid;
                            if let Err(e) = crate::wait::write_rusage(rusage, child) { return e; }
                            child.vpid as i64
                        }
                        None => 0,
                    }
                }
            }
        }
    } else {
        let wait4_options = effective_options & !WEXITED;
        crate::wait::wait4_with_status_sink(pid_for_wait4, wait4_options, |wstat| {
            local_wstat = wstat;
            Ok(())
        }, |child| {
            local_uid = child.uid;
            crate::wait::write_rusage(rusage, child)
        })
    };
    if infop != 0 {
        if let Err(e) = crate::userbuf::validate_user_buf_writable(infop, SIGINFO_BYTES, 1) { return e; }
        let (si_code, si_status): (i32, i32) = if rv > 0 {
            waitid_code_status_from_wstat(local_wstat)
        } else { (0, 0) };
        // Retained, feature-gated waitid provenance. systemd's safe_fork
        // deliberately maps a child signal/nonzero status to -EPROTO; retain
        // the kernel-produced wait status so that wrapper diagnosis names the
        // real child outcome instead of attributing its synthetic errno to a
        // syscall failure.
        debug_ssh! {
            if rv > 0 {
                let tid = sched::live::current().map(|task| task.tid).unwrap_or(0);
                klog::write_raw(b"[INFO] ssh-trace: waitid tid=");
                klog::write_dec_u64(tid as u64);
                klog::write_raw(b" idtype="); klog::write_dec_u64(idtype);
                klog::write_raw(b" id="); klog::write_dec_u64(id as u64);
                klog::write_raw(b" child="); klog::write_dec_u64(rv as u64);
                klog::write_raw(b" wstat="); klog::write_hex_u64(local_wstat as u32 as u64);
                klog::write_raw(b" si_code="); klog::write_dec_u64(si_code as u64);
                klog::write_raw(b" si_status="); klog::write_dec_u64(si_status as u64);
                klog::write_raw(b" infop="); klog::write_hex_u64(infop);
                klog::write_raw(b"\n");
            }
        }
        // SAFETY: full siginfo byte range validated writable; Linux copyout accepts this fixed layout.
        unsafe {
            for i in 0..SIGINFO_BYTES as usize {
                core::ptr::write_volatile((infop + i as u64) as *mut u8, 0);
            }
            if rv > 0 {
                core::ptr::write_volatile((infop + SIGINFO_OFF_SIGNO)  as *mut i32, sched::signum::Signum::Sigchld.as_u8() as i32);
                core::ptr::write_volatile((infop + SIGINFO_OFF_CODE)   as *mut i32, si_code);
                core::ptr::write_volatile((infop + SIGINFO_OFF_PID)    as *mut i32, rv as i32);
                core::ptr::write_volatile((infop + SIGINFO_OFF_UID)    as *mut u32, local_uid);
                core::ptr::write_volatile((infop + SIGINFO_OFF_STATUS) as *mut i32, si_status);
            }
        }
    }
    if let Some((tid, vpid, has_children)) = debug_waitid_parent {
        if rv < 0 {
            klog::write_raw(b"[waitid exit] tid=");
            klog::write_dec_u64(tid as u64);
            klog::write_raw(b" vpid=");
            klog::write_dec_u64(vpid as u64);
            klog::write_raw(b" rv=-");
            klog::write_dec_u64((-rv) as u64);
            klog::write_raw(b" has_children=");
            klog::write_dec_u64(if has_children { 1 } else { 0 });
            klog::write_raw(b" pid_for_wait4=");
            klog::write_dec_u64(pid_for_wait4 as i64 as u64);
            klog::write_raw(b"\n");
        }
    }
    if rv < 0 {
        #[cfg(feature = "debug-displaystack")]
        if let Some(cur) = sched::live::current() {
            use core::sync::atomic::Ordering;
            let pending = cur.sigpending.load(Ordering::Acquire);
            let mask = cur.sigmask.load(Ordering::Acquire);
            klog::write_raw(b"[waitid signal] tid=");
            klog::write_dec_u64(cur.tid as u64);
            klog::write_raw(b" rv=");
            klog::write_dec_u64((-rv) as u64);
            klog::write_raw(b" pending=");
            klog::write_hex_u64(pending);
            klog::write_raw(b" mask=");
            klog::write_hex_u64(mask);
            klog::write_raw(b" deliver=");
            klog::write_hex_u64(pending & !mask);
            klog::write_raw(b"\n");
        }
        rv
    } else if rv == 0 && pidfd_forced_nonblock {
        -(syscall::errno::Errno::Eagain.as_i32() as i64)
    } else { 0 }
}
