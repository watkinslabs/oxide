// 140 getpriority — one syscall, one file (docs/53 §0).
//
// getpriority(which, who): PRIO_PROCESS (0) / PRIO_PGRP (1) / PRIO_USER
// (2). Returns `20 - nice` of the lowest-nice matching task; -ESRCH if
// none. Shared target resolution lives in priority_common.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use super::priority_common::for_each_target;

/// `sys_getpriority(which, who)` — slot 140. PRIO_PROCESS/PGRP/USER.
///
/// The return value is BIASED: Linux reports `nice_to_rlimit(nice)` =
/// `MAX_NICE - nice + 1`, i.e. `20 - nice`, so the result lies in `[1, 40]` and
/// a high-priority (negative-nice) task can never produce a return the libc
/// wrapper would mistake for `-errno`. glibc subtracts the bias again.
///
/// Linux seeds `retval = -ESRCH` and keeps the LARGEST `nice_to_rlimit` seen
/// (`if (niceval > retval) retval = niceval`) — the highest priority, i.e. the
/// LOWEST nice, among the matching tasks. -ESRCH when nothing matches, EINVAL
/// for a `which` outside PRIO_PROCESS..PRIO_USER.
/// # C: O(N_tasks)
pub fn sys_getpriority(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use sched::rlimit::{nice_to_rlimit, prio_which};
    let (which, who) = (args.a0, args.a1 as u32);
    // `which` arrives as a sign-extended int: a negative value (Linux's
    // `which < PRIO_PROCESS`) becomes a huge u64 and fails this same bound.
    if which > prio_which::USER { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    let mut best: Option<i32> = None;
    for_each_target(which, who, |t| {
        let n = t.nice.load(Ordering::Acquire) as i32;
        best = Some(match best { Some(b) => b.min(n), None => n });
    });
    match best {
        Some(n) => nice_to_rlimit(n) as i64,
        None => -(syscall::errno::Errno::Esrch.as_i32() as i64),
    }
}
