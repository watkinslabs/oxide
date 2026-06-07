// 141 setpriority — one syscall, one file (docs/53 §0).
//
// setpriority(which, who, prio): PRIO_PROCESS (0) / PRIO_PGRP (1) /
// PRIO_USER (2). Clamps nice to [-20,19] and rewrites the live CFS
// weight so the change shifts CPU shares. Shared target resolution
// lives in priority_common.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use super::priority_common::for_each_target;

/// `sys_setpriority(which, who, prio)` — slot 141. Clamps nice to [-20,19].
/// # C: O(N_tasks)
pub fn sys_setpriority(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let (which, who, prio) = (args.a0, args.a1 as u32, args.a2 as i32);
    if which > 2 { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    let n = sched::rlimit::clamp_nice(prio);
    let mut touched = false;
    // Store the nice value AND rewrite the live CFS weight so the change
    // actually shifts CPU shares (`13§3`): nice<0 → heavier → more CPU.
    let w = sched::cputime::nice_to_weight(n);
    for_each_target(which, who, |t| {
        t.nice.store(n, Ordering::Release);
        t.load_weight.store(w, Ordering::Release);
        touched = true;
    });
    if touched { 0 } else { -(syscall::errno::Errno::Esrch.as_i32() as i64) }
}
