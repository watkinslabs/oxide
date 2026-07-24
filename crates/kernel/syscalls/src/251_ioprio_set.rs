// 251 ioprio_set — one syscall, one file (docs/53 §0).
//
// ioprio_set(which, who, ioprio): set per-task I/O priority. which is
// IOPRIO_WHO_PROCESS=1 / PGRP=2 / USER=3 (same target resolution as
// getpriority(2), shifted by 1). ioprio packs class (bits[15:13]: 1=RT,
// 2=BE, 3=IDLE) + level (low 13 bits). RT class needs privilege (euid 0).
// Real per-task state (stored, inherited on fork, queried by ionice).

use core::sync::atomic::Ordering;
use syscall::errno::Errno;
use syscall::SyscallArgs;

const CLASS_RT:   u16 = 1;
const CLASS_IDLE: u16 = 3;

/// `sys_ioprio_set(which, who, ioprio)` — slot 251.
/// # C: O(N_tasks) for PGRP/USER
pub fn sys_ioprio_set(args: &SyscallArgs) -> i64 {
    let which  = args.a0;
    let who    = args.a1 as u32;
    let ioprio = args.a2 as u16;
    if !(1..=3).contains(&which) { return -(Errno::Einval.as_i32() as i64); }
    let class = ioprio >> 13;
    if class > CLASS_IDLE { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64) };
    let has_nice = cur.has_cap(sched::cap::SYS_NICE);
    // Linux `ioprio_check_cap`: the RT class needs CAP_SYS_ADMIN or CAP_SYS_NICE
    // (not merely euid 0).
    if class == CLASS_RT && !cur.has_cap(sched::cap::SYS_ADMIN) && !has_nice {
        return -(Errno::Eperm.as_i32() as i64);
    }
    let euid = cur.creds.euid.load(Ordering::Acquire);
    let ruid = cur.creds.ruid.load(Ordering::Acquire);
    // Linux `set_task_ioprio` per-target owner check: the target's real uid must
    // match the caller's euid or ruid, or the caller holds CAP_SYS_NICE.
    let mut error: i64 = -(Errno::Esrch.as_i32() as i64);
    crate::priority::priority_common::for_each_target(which - 1, who, |t| {
        let target_ruid = t.creds.ruid.load(Ordering::Acquire);
        let owner_ok = has_nice || target_ruid == euid || target_ruid == ruid;
        if !owner_ok { error = -(Errno::Eperm.as_i32() as i64); return; }
        t.ioprio.store(ioprio, Ordering::Release);
        if error == -(Errno::Esrch.as_i32() as i64) { error = 0; }
    });
    error
}
