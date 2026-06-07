// 145 sched_getscheduler — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_sched_getscheduler(pid)` — slot 145. Returns the target's
/// scheduling policy: SCHED_OTHER=0, SCHED_FIFO=1, SCHED_RR=2.
/// `pid==0` = caller. SCHED_SETSCHEDULER (slot 144) shares this
/// path as a no-op (move-between-runqueues integration is
/// follow-up; honest 0 return matches "no-op-but-ok").
/// # C: O(N_tasks) on non-self lookup
pub fn sys_sched_getscheduler(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as u32;
    sched_lookup_policy(pid) as i64
}

/// Look up the target task and return its policy code per Linux
/// constants (0=OTHER, 1=FIFO, 2=RR, 5=IDLE).
/// # C: O(N_tasks) on non-self lookup
fn sched_lookup_policy(pid: u32) -> i32 {
    use sched::{SchedClass, SchedPolicy};
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        sched::live::registry::lookup(pid)
    };
    match task.map(|t| t.sched_class()) {
        Some(SchedClass::Rt { policy: SchedPolicy::Fifo, .. }) => 1,
        Some(SchedClass::Rt { policy: SchedPolicy::Rr,   .. }) => 2,
        Some(SchedClass::Idle) => 5,
        _ => 0,
    }
}
