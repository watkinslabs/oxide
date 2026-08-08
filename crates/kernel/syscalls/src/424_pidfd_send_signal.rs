// 424 pidfd_send_signal — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use sched::sigsend::{SigSource, SigTarget};

use crate::pidfd_signal_policy::{
    classify_target, scope_for, siginfo_forgery_rejected, validate_flags, Scope, Target,
};
use crate::signal_common::{read_user_siginfo, KERNEL_SIGINFO_BYTES, SI_SIGNO};

/// `sys_pidfd_send_signal(pidfd, sig, info, flags)` — slot 424.
///
/// Linux order:
///   1. unknown flag bits → EINVAL; more than one scope flag → EINVAL.
///   2. `PIDFD_SELF_THREAD` / `PIDFD_SELF_THREAD_GROUP` short-circuit the fd
///      table entirely; anything else is looked up (EBADF) and must be a pidfd
///      (EBADF from `pidfd_to_pid`).
///   3. scope: an explicit flag wins, else a `PIDFD_THREAD` pidfd is
///      thread-scoped and every other pidfd is process-scoped.
///   4. with `info`: copy it in (EFAULT), `sig != si_signo` → EINVAL, and a
///      kernel-origin `si_code` aimed anywhere but yourself → EPERM.
///      Without `info`: synthesise `SI_USER` + the sender's identity.
///   5. deliver, or ESRCH when the pidfd's process has already been reaped.
/// # C: O(N_tasks) for a process-group send; O(log N) otherwise
pub fn sys_pidfd_send_signal(args: &syscall::SyscallArgs) -> i64 {
    let fd    = args.a0 as i32;
    let sig   = args.a1 as i32;
    let info  = args.a2;
    let flags = args.a3 as u32;
    if !(0..=64).contains(&sig) { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_flags(flags) { return rv; }
    let Some(cur) = sched::live::current() else { return -(Errno::Esrch.as_i32() as i64) };
    let (task, default_scope) = match classify_target(fd) {
        // `PIDFD_SELF*` needs no fd at all — a process that has exhausted its
        // fd table can still signal itself, which is the whole point.
        Target::SelfTask(scope) => {
            let Some(t) = sched::registry::lookup(cur.tid) else {
                return -(Errno::Esrch.as_i32() as i64);
            };
            (t, scope)
        }
        Target::Fd(fd) => match resolve_pidfd(cur, fd) {
            Ok(pair) => pair,
            Err(rv) => return rv,
        },
    };
    if task.reaped.load(Ordering::Acquire) { return -(Errno::Esrch.as_i32() as i64); }
    let scope = scope_for(flags, default_scope);
    let targets_self = task.tid == cur.tid
        || task.tgid.load(Ordering::Acquire) == cur.tgid.load(Ordering::Acquire);
    let src = match build_source(cur, sig, info, targets_self, scope) {
        Ok(src) => src,
        Err(rv) => return rv,
    };
    if !crate::signal::sig_perm_check(cur, &task, sig) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    // `sig == 0` is the permission probe: everything above ran, nothing is sent.
    if sig == 0 { return 0; }
    match scope {
        Scope::Thread => send_one(&task, sig, src, SigTarget::Thread),
        Scope::ThreadGroup => send_one(&task, sig, src, SigTarget::Process),
        Scope::ProcessGroup => send_pgrp(cur, &task, sig, src),
    }
}

/// Resolve a real pidfd to its task plus the scope its own kind implies.
/// # C: O(log N)
fn resolve_pidfd(cur: &sched::Task, fd: i32) -> Result<(Arc<sched::Task>, Scope), i64> {
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return Err(-(Errno::Ebadf.as_i32() as i64)),
    };
    let file = fdt.get(fd).map_err(|_| -(Errno::Ebadf.as_i32() as i64))?;
    // Linux `pidfd_to_pid` returns `-EBADF` for a non-pidfd file, not EINVAL:
    // the fd is open but is not the kind of object this call accepts.
    let Some(identity) = pidfd::identity_from_inode(&file.inode()) else {
        return Err(-(Errno::Ebadf.as_i32() as i64));
    };
    let Some(task) = identity.task() else { return Err(-(Errno::Esrch.as_i32() as i64)) };
    // `PIDFD_THREAD` is `O_EXCL` on the pidfd.
    let scope = if file.flags().contains(vfs::OpenFlags::O_EXCL) { Scope::Thread }
                else { Scope::ThreadGroup };
    Ok((task, scope))
}

/// Linux's `if (info) { copy_siginfo_from_user_any(...) } else {
/// prepare_kill_siginfo(...) }` arm, including the forgery gate.
/// # C: O(1)
fn build_source(cur: &sched::Task, sig: i32, info: u64, targets_self: bool, scope: Scope)
    -> Result<SigSource, i64>
{
    if info == 0 {
        return Ok(SigSource::User {
            pid: cur.vtgid.load(Ordering::Acquire),
            uid: cur.creds.ruid.load(Ordering::Acquire),
        });
    }
    crate::userbuf::validate_user_buf(info, KERNEL_SIGINFO_BYTES, 1)?;
    // SAFETY: info validated readable for KERNEL_SIGINFO_BYTES; si_signo is the leading i32.
    let signo = unsafe { core::ptr::read_unaligned((info + SI_SIGNO) as *const i32) };
    if signo != sig { return Err(-(Errno::Einval.as_i32() as i64)); }
    let rec = read_user_siginfo(info, sig as u32);
    if siginfo_forgery_rejected(rec.code, targets_self, scope) {
        return Err(-(Errno::Eperm.as_i32() as i64));
    }
    Ok(SigSource::Info(rec))
}

/// # C: O(N_threads)
fn send_one(t: &Arc<sched::Task>, sig: i32, src: SigSource, target: SigTarget) -> i64 {
    match sched::live::send_signal(t, sig as u32, src, target) {
        Ok(()) => 0,
        Err(sched::live::SendErr::Again) => -(Errno::Eagain.as_i32() as i64),
    }
}

/// `PIDFD_SIGNAL_PROCESS_GROUP` — Linux `kill_pgrp_info`, which folds exactly
/// like `kill(2)`'s process-group arm.
/// # C: O(N_tasks)
fn send_pgrp(cur: &sched::Task, task: &Arc<sched::Task>, sig: i32, src: SigSource) -> i64 {
    let mut fold = crate::kill_policy::PgrpFold::new();
    for t in &sched::live::registry::tasks_in_pgrp(task.pgid()) {
        if t.tid != t.tgid.load(Ordering::Acquire) { continue; }
        if !crate::signal::sig_perm_check(cur, t, sig) {
            fold.visit(-(Errno::Eperm.as_i32() as i64));
            continue;
        }
        fold.visit(if sig == 0 { 0 } else { send_one(t, sig, src, SigTarget::Process) });
    }
    fold.finish()
}
