// 157 prctl — one syscall, one file (docs/53 §0). ABI shim only.
//
// Linux `SYSCALL_DEFINE5(prctl)` opens with
//   error = security_task_prctl(option, arg2, arg3, arg4, arg5);
//   if (error != -ENOSYS) return error;
// i.e. the security-module hook gets first refusal, and the big
// switch runs only for the options it declined. `PR_SET_SECCOMP` is this
// port's one such option: seccomp lives in the `security` crate, which
// depends on `sched`, so `sched::prctl` cannot reach it.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `PR_SET_SECCOMP`.
const PR_SET_SECCOMP: u64 = 22;

/// `prctl(option, arg2, arg3, arg4, arg5)` — slot 157.
///
/// `PR_SET_SECCOMP` is the legacy front door onto `do_seccomp`
/// (Linux's `prctl_set_seccomp`). Both modes reach it: STRICT maps to
/// `SECCOMP_SET_MODE_STRICT` and FILTER to `SECCOMP_SET_MODE_FILTER`, with the
/// mode ladder owned by `security::seccomp::prctl_seccomp_op`. The door
/// libseccomp actually uses is `seccomp(2)` (slot 317); this one exists for
/// the pre-3.17 callers that still take it.
/// # C: see `sched::prctl::sys_prctl`
pub fn sys_prctl(args: &SyscallArgs) -> i64 {
    if args.a0 == PR_SET_SECCOMP {
        return security::seccomp::prctl_set_seccomp(args.a1, args.a2);
    }
    sched::prctl::sys_prctl(args)
}
