// sys_waitid — ABI shim over the shared wait engine in `061_wait4.rs`.
// idtype→pid-form mapping, per-class event gating, and the wstatus→siginfo
// decode are pure and live in `syscall::wait`; this file resolves a pidfd,
// drives the engine, and copies out `siginfo_t` + `rusage`.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::SyscallArgs;
use syscall::wait::{
    int_arg_from_reg, siginfo_from_event, waitid_options_valid, waitid_target, WaitEventKind,
    WaitEvents, WaitTarget, WNOHANG, WNOWAIT,
};

use crate::wait::WaitRequest;

const SIGINFO_BYTES: u64 = 128;
const SIGINFO_OFF_SIGNO:  u64 = 0;
const SIGINFO_OFF_ERRNO:  u64 = 4;
const SIGINFO_OFF_CODE:   u64 = 8;
const SIGINFO_OFF_PID:    u64 = 16;
const SIGINFO_OFF_UID:    u64 = 20;
const SIGINFO_OFF_STATUS: u64 = 24;

/// `sys_waitid(idtype, id, infop, options, rusage)`.
/// # C: same as wait4 — bounded by the child-event scan
pub fn sys_waitid(args: &SyscallArgs) -> i64 {
    let idtype  = int_arg_from_reg(args.a0);
    let id      = args.a1 as i32;
    let infop   = args.a2;
    let options = int_arg_from_reg(args.a3);
    let rusage  = args.a4;
    if !waitid_options_valid(options) { return -(Errno::Einval.as_i32() as i64); }

    let mut effective_options = options;
    let mut pidfd_forced_nonblock = false;
    let pid_for_wait4: i32 = match waitid_target(idtype, id) {
        WaitTarget::Invalid     => return -(Errno::Einval.as_i32() as i64),
        WaitTarget::Wait4Pid(p) => p,
        WaitTarget::Pidfd(fd)   => match resolve_pidfd(fd, options) {
            Err(e) => return -(e.as_i32() as i64),
            Ok((vpid, forced)) => {
                if forced { effective_options |= WNOHANG; pidfd_forced_nonblock = true; }
                vpid
            }
        },
    };

    let mut local_wstat: i32 = 0;
    let mut local_uid: u32 = 0;
    let mut local_kind = WaitEventKind::Exited;
    let req = WaitRequest {
        pid:     pid_for_wait4,
        options: effective_options,
        events:  WaitEvents::for_waitid(effective_options),
        consume: (effective_options & WNOWAIT) == 0,
    };
    let rv = crate::wait::wait_engine(req, |kind, wstat| {
        local_kind  = kind;
        local_wstat = wstat;
        Ok(())
    }, |child| {
        local_uid = child.uid;
        crate::wait::write_rusage(rusage, child)
    });

    if infop != 0 {
        if let Err(e) = crate::userbuf::validate_user_buf_writable(infop, SIGINFO_BYTES, 1) { return e; }
        // No event (WNOHANG miss, or an error) leaves the whole siginfo zero,
        // including si_signo — that is how userspace tells "nothing happened"
        // apart from a real SIGCHLD report.
        let (si_code, si_status) = if rv > 0 { siginfo_from_event(local_kind, local_wstat) } else { (0, 0) };
        // SAFETY: full siginfo byte range validated writable in the caller's AS; fields stored at the fixed Linux siginfo_t offsets, remainder zeroed.
        unsafe {
            core::ptr::write_bytes(infop as *mut u8, 0, SIGINFO_BYTES as usize);
            if rv > 0 {
                core::ptr::write_unaligned((infop + SIGINFO_OFF_SIGNO)  as *mut i32, sched::signum::Signum::Sigchld.as_u8() as i32);
                core::ptr::write_unaligned((infop + SIGINFO_OFF_ERRNO)  as *mut i32, 0);
                core::ptr::write_unaligned((infop + SIGINFO_OFF_CODE)   as *mut i32, si_code);
                core::ptr::write_unaligned((infop + SIGINFO_OFF_PID)    as *mut i32, rv as i32);
                core::ptr::write_unaligned((infop + SIGINFO_OFF_UID)    as *mut u32, local_uid);
                core::ptr::write_unaligned((infop + SIGINFO_OFF_STATUS) as *mut i32, si_status);
            }
        }
    }
    // A reported event returns 0, not the pid — waitid's whole result is the
    // siginfo. A pidfd whose O_NONBLOCK forced WNOHANG reports EAGAIN rather
    // than the "no children ready" 0 the caller never asked for.
    if rv < 0 { rv }
    else if rv == 0 && pidfd_forced_nonblock { -(Errno::Eagain.as_i32() as i64) }
    else { 0 }
}

/// `P_PIDFD`: resolve the fd to the target's VPID. Returns the VPID and
/// whether the pidfd's `O_NONBLOCK` must force `WNOHANG`.
/// # C: O(1)
fn resolve_pidfd(fd: i32, options: u64) -> Result<(i32, bool), Errno> {
    let current = sched::live::current().ok_or(Errno::Ebadf)?;
    let (target, flags) = match pidfd::task_and_flags_from_fd(current, fd) {
        Ok(v) => v,
        Err(pidfd::ResolveError::Released) => return Err(Errno::Echild),
        Err(pidfd::ResolveError::BadFd | pidfd::ResolveError::NotPidfd) => return Err(Errno::Ebadf),
    };
    // A thread pidfd resolves to PIDTYPE_PID, which no untraced thread-group
    // wait can match — the observable result is ECHILD.
    if !target.pid.is_group_leader() { return Err(Errno::Echild); }
    let forced = flags.contains(vfs::OpenFlags::O_NONBLOCK) && (options & WNOHANG) == 0;
    Ok((sched::live::registry::display_vpid(target.tid) as i32, forced))
}
