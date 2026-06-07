// 140 getpriority — one syscall, one file (docs/53 §0).
//
// getpriority(which, who): PRIO_PROCESS (0) / PRIO_PGRP (1) / PRIO_USER
// (2). Returns `20 - nice` of the lowest-nice matching task; -ESRCH if
// none. Shared target resolution lives in priority_common.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use super::priority_common::for_each_target;

/// `sys_getpriority(which, who)` — slot 140. PRIO_PROCESS/PGRP/USER.
/// Returns `20 - nice` of the lowest-nice matching task; -ESRCH if none.
/// # C: O(N_tasks)
pub fn sys_getpriority(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let (which, who) = (args.a0, args.a1 as u32);
    if which > 2 { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    let mut best: Option<i32> = None;
    for_each_target(which, who, |t| {
        let n = t.nice.load(Ordering::Acquire) as i32;
        best = Some(match best { Some(b) => b.min(n), None => n });
    });
    match best { Some(n) => 20 - n as i64, None => -(syscall::errno::Errno::Esrch.as_i32() as i64) }
}
