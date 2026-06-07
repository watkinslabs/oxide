// 143 sched_getparam — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_sched_getparam(pid, param)` — slot 143. Writes the
/// target task's RT priority (1..=99 for FIFO/RR; 0 for Normal/Idle).
/// `pid==0` means the calling task.
/// # C: O(N_tasks) on non-self lookup
pub fn sys_sched_getparam(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as u32;
    let p   = args.a1;
    let prio = sched_lookup_prio(pid);
    if p != 0 && p < hal::USER_VA_END {
        // SAFETY: p validated < USER_VA_END; aligned i32 store of sched_priority into caller's AS.
        unsafe { core::ptr::write_volatile(p as *mut i32, prio); }
    }
    0
}

/// Look up the target task and return its RT priority, or 0 for
/// Normal/Idle tasks.
/// # C: O(N_tasks) on non-self lookup
fn sched_lookup_prio(pid: u32) -> i32 {
    use sched::SchedClass;
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        sched::live::registry::lookup(pid)
    };
    match task.map(|t| t.sched_class()) {
        Some(SchedClass::Rt { prio, .. }) => prio as i32,
        _ => 0,
    }
}
