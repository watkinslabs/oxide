// sys_waitid — ABI shim over the shared wait engine in `061_wait4.rs`. The
// option decode, the idtype ladder, the pidfd errno ladder, the forced-WNOHANG
// rule, the siginfo image and the return-value tail are all pure and live in
// `syscall::wait::{prepare, siginfo}`; this file resolves a pidfd through the
// fd table, drives the engine, and copies out.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::wait::{
    pidfd_bind, siginfo_bytes, waitid_prepare, waitid_result, PidfdTarget, WaitEventKind,
    WaitReport, WaitidPrepare, SIGINFO_BYTES,
};

/// `sys_waitid(idtype, id, infop, options, rusage)`.
/// # C: same as wait4 — bounded by the child-event scan
pub fn sys_waitid(args: &SyscallArgs) -> i64 {
    let infop  = args.a2;
    let rusage = args.a4;

    let (plan, forced_nonblock) = match waitid_prepare(args.a0, args.a1 as i32, args.a3) {
        Err(e) => return -(e.as_i32() as i64),
        Ok(WaitidPrepare::Ready(p)) => (p, false),
        Ok(WaitidPrepare::Pidfd { fd, options }) => match pidfd_bind(options, resolve_pidfd(fd)) {
            Err(e) => return -(e.as_i32() as i64),
            Ok(v)  => v,
        },
    };

    let mut local_wstat: i32 = 0;
    let mut local_uid: u32 = 0;
    let mut local_kind = WaitEventKind::Exited;
    let rv = crate::wait::wait_engine(plan, |kind, wstat| {
        local_kind  = kind;
        local_wstat = wstat;
        Ok(())
    }, |child| {
        local_uid = child.uid;
        crate::wait::write_rusage(rusage, child)
    });

    if infop != 0 {
        if let Err(e) = crate::userbuf::validate_user_buf_writable(infop, SIGINFO_BYTES as u64, 1) { return e; }
        // The structure is written on every non-null `infop`, error returns
        // included. No event leaves it entirely zero, `si_signo` included —
        // that zero is how userspace tells "nothing happened" from a report.
        let report = (rv > 0).then(|| WaitReport {
            kind: local_kind, wstat: local_wstat, pid: rv as i32, uid: local_uid,
        });
        let bytes = siginfo_bytes(sched::signum::Signum::Sigchld.as_u8() as i32, report);
        if crate::user_mem::put_bytes(infop, &bytes).is_err() { return crate::user_mem::EFAULT; }
    }
    waitid_result(rv, forced_nonblock)
}

/// `P_PIDFD`: look the descriptor up in the caller's fd table. The errno
/// ladder over the outcome is `syscall::wait::pidfd_bind`'s.
/// # C: O(1)
fn resolve_pidfd(fd: i32) -> PidfdTarget {
    let Some(current) = sched::live::current() else { return PidfdTarget::BadFd };
    let (target, flags) = match pidfd::task_and_flags_from_fd(current, fd) {
        Ok(v) => v,
        Err(pidfd::ResolveError::Released) => return PidfdTarget::Released,
        Err(pidfd::ResolveError::BadFd | pidfd::ResolveError::NotPidfd) => return PidfdTarget::BadFd,
    };
    // A pidfd naming a THREAD (producible via CLONE_THREAD|CLONE_PIDFD) is a
    // thread-level pid. A wait keyed on it looks the target up as a thread
    // GROUP, finds nothing for a non-leader, and falls through to "no eligible
    // child". Only a tracer of that exact thread could match it, and a pidfd is
    // never how a tracer reaches its tracee.
    if !target.pid.is_group_leader() { return PidfdTarget::NonLeader; }
    PidfdTarget::Leader {
        vpid:     sched::live::registry::display_vpid(target.tid) as i32,
        nonblock: flags.contains(vfs::OpenFlags::O_NONBLOCK),
    }
}
