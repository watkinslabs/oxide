// 129 rt_sigqueueinfo — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::signal_common::*;
use crate::userbuf::validate_user_buf;

/// `sys_rt_sigqueueinfo(pid, sig, info)` — slot 129.
///
/// Linux `SYSCALL_DEFINE3(rt_sigqueueinfo)` → `__copy_siginfo_from_user` →
/// `do_rt_sigqueueinfo` → `kill_proc_info`, in that order:
///   1. copy `sizeof(kernel_siginfo)` from `uinfo` → EFAULT.
///   2. si_signo is FORCED to `sig`; the sender cannot disagree with it.
///   3. Forgery guard — EPERM if `si_code >= 0 || si_code == SI_TKILL` and the
///      caller's own vpid is not `pid`. This is a SECURITY check: `si_code`
///      values at or above `SI_USER`, plus `SI_TKILL`, are stamped by the
///      kernel or by `tkill`/`tgkill`; letting an app forge them at another
///      process makes a `SI_KERNEL` "sent by the kernel" siginfo (or a
///      counterfeit `tgkill` origin) that a privileged handler will trust.
///      Compared against the pid ARGUMENT, exactly as `task_pid_vnr(current)
///      != pid` does — not against the resolved task.
///   4. EINVAL for an out-of-range signal, ESRCH for an unknown pid, EPERM
///      from the `kill(2)` permission rule — all inside `sigqueue_to`.
///
/// EVERY signal number carries its siginfo, standard as well as real-time:
/// `sigqueue(3)` on SIGUSR1 must deliver its `sival_ptr`, and glibc's
/// SIGCANCEL/SIGSETXID handlers reject a delivery whose si_code is missing.
/// # C: O(1) after the registry lookup
pub fn sys_rt_sigqueueinfo(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let pid = args.a0 as i32;
    let sig = args.a1 as i32;
    let info_ptr = args.a2;
    if let Err(rv) = validate_user_buf(info_ptr, KERNEL_SIGINFO_BYTES, 1) { return rv; }
    let info = read_user_siginfo(info_ptr, sig as u32);
    if forgery_rejected(info.code, pid) { return -(Errno::Eperm.as_i32() as i64); }
    if sig < 0 { return -(Errno::Einval.as_i32() as i64); }
    sigqueue_to(pid as u32, sig as u32, info)
}

/// Bind the hosted-tested `do_rt_sigqueueinfo` gate to the running task's own
/// vpid (Linux `task_pid_vnr(current)`).
/// # C: O(1)
pub(crate) fn forgery_rejected(si_code: i32, pid_arg: i32) -> bool {
    use core::sync::atomic::Ordering;
    let caller = match sched::live::current() {
        Some(c) => c.vtid.load(Ordering::Acquire),
        // No current task means no identity to match; a forged code cannot be
        // excused, so keep the strict answer.
        None    => u32::MAX,
    };
    sched::signum::sigqueueinfo_forgery_rejected(si_code, caller, pid_arg)
}
