// 129 rt_sigqueueinfo — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::signal_common::*;

/// `sys_rt_sigqueueinfo(pid, sig, info)` — slot 129. RT signals
/// (33..=64) push the user-supplied siginfo_t onto the target's
/// per-signal RT queue; standard signals fall through to sys_kill
/// (which collapses to the bitmap).
/// # C: O(N_tasks)
pub fn sys_rt_sigqueueinfo(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as u32;
    let sig = args.a1 as u32;
    let info_ptr = args.a2;
    if sig < 33 || sig > 64 {
        let kill_args = SyscallArgs {
            a0: args.a0, a1: args.a1, a2: 0, a3: 0, a4: 0, a5: 0,
        };
        return crate::s062_kill::sys_kill(&kill_args);
    }
    rt_sigqueue_to(pid, sig, info_ptr)
}
