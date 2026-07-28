// 252 ioprio_get — one syscall, one file (docs/53 §0).
// `ioprio_get(which, who)`: Linux `block/ioprio.c:180`. Thin shim over
// `crate::ioprio`.
//
// The two arms differ on purpose in Linux and here: IOPRIO_WHO_PROCESS reports
// the RAW stored value (`get_task_raw_ioprio`) so userspace can distinguish
// "never set" from an explicit priority, while PGRP/USER report the EFFECTIVE
// value (`__get_task_ioprio`, class+level derived from nice when unset) and
// fold the set with `ioprio_best`.
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use syscall::errno::Errno;
use syscall::SyscallArgs;
use crate::ioprio;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Linux `__get_task_ioprio()` applied to one live task.
/// # C: O(1)
fn effective(t: &sched::Task) -> i32 {
    let policy = crate::sched_policy::task_policy(t);
    ioprio::effective(t.ioprio.load(Ordering::Acquire) as i32,
                      t.nice.load(Ordering::Acquire) as i32,
                      crate::sched_policy::idle_policy(policy),
                      crate::sched_policy::rt_policy(policy) || crate::sched_policy::dl_policy(policy))
}

/// `sys_ioprio_get(which, who)` — slot 252.
/// # C: O(N_tasks) for PGRP/USER
pub fn sys_ioprio_get(args: &SyscallArgs) -> i64 {
    let which = args.a0 as i32;
    let who   = args.a1 as u32;
    let base = match ioprio::who_base(which) { Ok(b) => b, Err(rv) => return rv };
    let raw = which == ioprio::WHO_PROCESS;
    let mut best: Option<i32> = None;
    crate::priority::priority_common::for_each_target(base, who, |t| {
        let v = if raw { t.ioprio.load(Ordering::Acquire) as i32 } else { effective(t) };
        best = Some(match best { None => v, Some(b) => ioprio::best(b, v) });
    });
    // The return is an `int`, so a raw value with the sign bit set comes back
    // negative exactly as it does on Linux.
    match best { Some(v) => v as i64, None => err(Errno::Esrch) }
}
