// 143 sched_getparam — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::userbuf::validate_user_buf_writable;

/// `sys_sched_getparam(pid, param)` — slot 143. Writes the
/// target task's RT priority (1..=99 for FIFO/RR; 0 for Normal/Idle).
/// `pid==0` means the calling task.
/// # C: O(N_tasks) on non-self lookup
pub fn sys_sched_getparam(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as u32;
    let p   = args.a1;
    if let Err(rv) = validate_user_buf_writable(p, 4, 1) { return rv; }
    let prio = match sched_lookup_prio(pid) { Some(v) => v, None => return -(Errno::Esrch.as_i32() as i64) };
    // SAFETY: p validated writable for struct sched_param.sched_priority.
    unsafe { core::ptr::write_unaligned(p as *mut i32, prio); }
    0
}

/// Look up the target task and return its RT priority, or 0 for
/// Normal/Idle tasks.
/// # C: O(N_tasks) on non-self lookup
fn sched_lookup_prio(pid: u32) -> Option<i32> {
    use sched::SchedClass;
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        sched::live::registry::resolve_user_pid(pid)
    };
    match task.map(|t| t.sched_class()) {
        Some(SchedClass::Rt { prio, .. }) => Some(prio as i32),
        Some(_) => Some(0),
        None => None,
    }
}
