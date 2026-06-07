// 297 rt_tgsigqueueinfo — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::signal_common::*;

/// `sys_rt_tgsigqueueinfo(tgid, tid, sig, info)` — slot 297.
/// # C: O(1)
pub fn sys_rt_tgsigqueueinfo(args: &SyscallArgs) -> i64 {
    let _tgid = args.a0 as u32;
    let tid   = args.a1 as u32;
    let sig   = args.a2 as u32;
    let info_ptr = args.a3;
    if sig < 33 || sig > 64 {
        let tgkill_args = SyscallArgs {
            a0: args.a0, a1: args.a1, a2: args.a2, a3: 0, a4: 0, a5: 0,
        };
        return crate::s234_tgkill::sys_tgkill(&tgkill_args);
    }
    rt_sigqueue_to(tid, sig, info_ptr)
}
